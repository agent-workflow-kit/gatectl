"""``gatectl export``: print ``audit.jsonl`` (or ``log.jsonl``) records as JSON lines.

The files are public contracts but hold untrusted text, and a same-user process can edit them, so
the reader is defensive and streams:

* The file is opened without following a link and judged by ``fstat``: only a regular file owned
  by the user is read (a FIFO, directory or link is refused, never waited on). A missing file is
  an empty export. Nothing is created, locked or written.
* Memory is bounded by one line: a line is read with a cap of ``audit.LINE_CAP`` bytes and a longer
  one is skipped without being held (its rest is read in small pieces and dropped). Only the bytes
  present when the file was opened are read, so a writer that keeps appending cannot hold the
  command open.
* A line is a record when it is a UTF-8 JSON object (no ``NaN``, no number that does not
  serialize) with a ``ts`` in the fixed timestamp form; a blank line is skipped silently, any other
  line is skipped and counted, and the count is reported on stderr after the output (``--quiet``
  does not silence it: a skipped line is lost data). ``--since`` keeps the records whose ``ts``
  is not older than it.
* What is printed is the parsed record re-serialized as ASCII JSON with every string sanitized
  (non-printable code points become the marker) and nesting beyond 32 levels cut, so a tampered
  file cannot put control sequences or bidi text on a terminal.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from gatectl import audit
from gatectl.clock import format_ts, parse_since, parse_ts
from gatectl.context import Context, Result
from gatectl.errors import InternalError
from gatectl.sanitize import MARKER, sanitize

_CHUNK = 64 * 1024
_DEPTH = 32
_PIECE = 64 * 1024


class _Skipped:
    def __init__(self) -> None:
        self.count = 0

    def report(self) -> str | None:
        if not self.count:
            return None
        noun = "line" if self.count == 1 else "lines"
        return f"gatectl: warning export: {self.count} {noun} skipped (not valid records)"


def _reject_constant(_: str) -> Any:
    raise ValueError("not a JSON number")


def _scrub(value: Any, depth: int = 0) -> Any:
    if isinstance(value, str):
        return sanitize(value, audit.LINE_CAP)
    if isinstance(value, dict | list):
        if depth >= _DEPTH:
            return MARKER
        if isinstance(value, list):
            return [_scrub(v, depth + 1) for v in value]
        out: dict[str, Any] = {}
        for key, item in value.items():
            clean = sanitize(key, audit.LINE_CAP)
            base, n = clean, 1
            while clean in out:
                n += 1
                clean = f"{base}~{n}"
            out[clean] = _scrub(item, depth + 1)
        return out
    return value


def _record(body: bytes, since: str | None) -> str | None | bool:
    """The output line of one stored line; None when it is older than ``since``; False when it
    is not a valid record."""
    try:
        value = json.loads(body.decode("utf-8"), parse_constant=_reject_constant)
        if not isinstance(value, dict):
            return False
        when = value.get("ts")
        if not isinstance(when, str):
            return False
        parse_ts(when)
        if since is not None and when < since:
            return None
        text = json.dumps(_scrub(value), ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    except (ValueError, RecursionError):  # UnicodeDecodeError is a ValueError
        return False
    return text + "\n"


def _open(path: Path) -> tuple[int, int] | None:
    """The descriptor and the size the file has now (the bytes this export will read)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError:
        raise InternalError(f"{path.name} cannot be opened") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise InternalError(f"{path.name} is not a regular file")
        if info.st_uid != os.geteuid():
            raise InternalError(f"{path.name} is not owned by the current user")
    except BaseException:
        os.close(fd)
        raise
    return fd, info.st_size


def _lines(path: Path, since: str | None, skipped: _Skipped) -> Iterator[str]:
    opened = _open(path)
    if opened is None:
        return
    fd, budget = opened
    limit = audit.LINE_CAP + 2  # a record, its newline and one byte to tell "too long"
    pending: list[str] = []
    size = 0
    with os.fdopen(fd, "rb") as handle:
        while budget > 0:
            chunk = handle.readline(min(limit, budget))
            if not chunk:
                break
            budget -= len(chunk)
            if not chunk.endswith(b"\n") and len(chunk) >= limit:
                while budget > 0:  # too long: drop the rest of the line, piece by piece
                    piece = handle.readline(min(_PIECE, budget))
                    if not piece:
                        break
                    budget -= len(piece)
                    if piece.endswith(b"\n"):
                        break
                skipped.count += 1
                continue
            body = chunk[:-1] if chunk.endswith(b"\n") else chunk
            if len(body) > audit.LINE_CAP:
                skipped.count += 1
                continue
            if not body.strip():
                continue  # a blank line is skipped, not an invalid record
            line = _record(body, since)
            if line is False:
                skipped.count += 1
            elif isinstance(line, str):
                pending.append(line)
                size += len(line)
                if size >= _CHUNK:
                    yield "".join(pending)
                    pending, size = [], 0
    if pending:
        yield "".join(pending)


def handle(ctx: Context) -> Result:
    since = None
    if ctx.args.since is not None:
        since = format_ts(parse_since(ctx.args.since, datetime.now(UTC)))
    name = "log.jsonl" if ctx.args.log else "audit.jsonl"
    skipped = _Skipped()
    return Result(
        stream=_lines(audit.state_dir() / name, since, skipped), stderr_after=skipped.report
    )
