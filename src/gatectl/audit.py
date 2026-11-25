"""Append-only writers for ``audit.jsonl`` and ``log.jsonl`` (interface.md, Audit and log).

Every line is written with a single ``write`` on a descriptor opened with ``O_APPEND``, so
concurrent writers (threads or processes) never interleave. A line is capped at 64 KiB
(newline included) by shortening its free-text fields before it is written. A short or failed
write is never truncated back: another writer's line may already follow it, so the partial line
stays and the caller fails (a consumer skips a line that does not parse). Files are created
with mode 0600, set explicitly rather than through the umask.

Lines are ASCII JSON (``ensure_ascii``): no raw U+2028, NEL or other separator can ever split a
line in a reader that splits on more than ``\\n``, and sizes are measured on the bytes written.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from gatectl.clock import now_ts
from gatectl.sanitize import MARKER, sanitize

LINE_CAP = 64 * 1024
MESSAGE_CAP = 2048  # schemas/log.json: message maxLength
REASON_CAP = 1024  # schemas/audit.json: state_change result.reason maxLength
_MAX_DEPTH = 16  # nesting kept in free-text objects; deeper values collapse to the marker

AUDIT_ACTIONS = frozenset({"decision", "outcome", "state_change", "prune"})
LOG_LEVELS = ("debug", "info", "warn", "error")
LOG_EVENTS = frozenset(
    {
        "check_off",
        "shadow_failure",
        "hook_skipped",
        "hook_failed",
        "reconcile",
        "drop_skipped",
        "terminated",
        "cron",
        "warning",
    }
)

# Seams the tests replace (the module ``os`` itself is never patched).
_open = os.open
_write = os.write


class ShortWriteError(OSError):
    """The single ``write`` stored fewer bytes than the line. Nothing is truncated back."""


class RecordTooLargeError(ValueError):
    """The record is over the cap even with all its free text removed. Nothing is written."""


# --- paths -------------------------------------------------------------------------------


def state_dir() -> Path:
    """``$XDG_STATE_HOME/gatectl``, else ``~/.local/state/gatectl``; no other override exists."""
    xdg = os.environ.get("XDG_STATE_HOME", "")
    base = Path(xdg) if xdg and os.path.isabs(xdg) else Path.home() / ".local" / "state"
    return base / "gatectl"


def _ensure_dir(path: Path) -> None:
    """Create the state directory with mode 0700 (set explicitly). An existing one is kept."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        return
    os.chmod(path, 0o700)


def _open_append(path: Path) -> int:
    flags = os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW
    for _ in range(3):
        try:
            fd = _open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            try:
                return _open(path, flags)
            except FileNotFoundError:
                continue  # removed between the two opens: try to create it again
        try:
            os.fchmod(fd, 0o600)
        except BaseException:
            os.close(fd)
            raise
        return fd
    raise FileNotFoundError(f"cannot open {path.name} for append")


# --- encoding ----------------------------------------------------------------------------


def _clean(value: Any, sanitize_text: bool, depth: int = 0) -> Any:
    """A copy of a free-text value: strings sanitized (256 characters) and depth bounded."""
    if depth >= _MAX_DEPTH and isinstance(value, Mapping | list | tuple):
        return MARKER
    if isinstance(value, str):
        return sanitize(value) if sanitize_text else value
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("free-text object keys must be strings")
            out[sanitize(key) if sanitize_text else key] = _clean(item, sanitize_text, depth + 1)
        return out
    if isinstance(value, list | tuple):
        return [_clean(item, sanitize_text, depth + 1) for item in value]
    return value


def _dump(record: Mapping[str, Any]) -> bytes:
    text = json.dumps(record, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    return text.encode("ascii") + b"\n"


def _leaves(node: Any, out: list[tuple[Any, Any]]) -> None:
    """Collect ``(container, key)`` for every string value inside ``node``."""
    items = node.items() if isinstance(node, dict) else enumerate(node)
    for key, item in items:
        if isinstance(item, str):
            out.append((node, key))
        elif isinstance(item, dict | list):
            _leaves(item, out)


def _shorten(rec: dict[str, Any]) -> bytes:
    """Shorten free text until the line fits: one common length for every string, the largest
    that fits (so short fields survive and long ones are trimmed evenly)."""
    leaves: list[tuple[Any, Any]] = []
    if isinstance(rec.get("message"), str):
        leaves.append((rec, "message"))
    if isinstance(rec.get("data"), dict | list):
        _leaves(rec["data"], leaves)
    result = rec.get("result")
    if isinstance(result, dict) and isinstance(result.get("reason"), str):
        leaves.append((result, "reason"))
    originals = [(c, k, c[k]) for c, k in leaves]

    def apply(limit: int) -> bytes:
        for container, key, text in originals:
            container[key] = text[:limit]
        return _dump(rec)

    longest = max((len(text) for _, _, text in originals), default=0)
    if originals and len(apply(0)) <= LINE_CAP:
        low, high = 0, longest  # apply(low) fits; find the largest limit that fits
        while low < high:
            mid = (low + high + 1) // 2
            if len(apply(mid)) <= LINE_CAP:
                low = mid
            else:
                high = mid - 1
        return apply(low)
    # Even with every string emptied it does not fit: drop the optional free-text containers.
    for container, key, text in originals:
        container[key] = text
    if "data" in rec:
        rec["data"] = None
    if isinstance(result, dict) and isinstance(result.get("reason"), str):
        result["reason"] = None
    if isinstance(rec.get("message"), str):
        rec["message"] = ""
    line = _dump(rec)
    if len(line) > LINE_CAP:
        raise RecordTooLargeError("record exceeds 64 KiB without its free text")
    return line


def encode_line(record: Mapping[str, Any], *, sanitize_text: bool = True) -> bytes:
    """The bytes of one line (newline included), at most 64 KiB; the input is not modified.

    Free-text fields are the schemas' ``x-untrusted`` ones: a log record's ``message`` (2048
    characters) and ``data``, and an audit record's ``result.reason`` (1024). With
    ``sanitize_text`` they pass through the sanitizer, so no raw control character reaches a
    file even from a caller that forgot to sanitize at the source.
    """
    rec: dict[str, Any] = dict(record)
    if isinstance(rec.get("message"), str):
        rec["message"] = sanitize(rec["message"], MESSAGE_CAP) if sanitize_text else rec["message"]
    if "data" in rec:
        rec["data"] = _clean(rec["data"], sanitize_text)
    if isinstance(rec.get("result"), Mapping):
        result = dict(rec["result"])
        if isinstance(result.get("reason"), str):
            result["reason"] = (
                sanitize(result["reason"], REASON_CAP) if sanitize_text else result["reason"]
            )
        rec["result"] = result
    line = _dump(rec)
    if len(line) <= LINE_CAP:
        return line
    return _shorten(rec)


# --- appending ---------------------------------------------------------------------------


def _append(name: str, record: Mapping[str, Any], directory: Path | None, sanitize_text: bool):
    line = encode_line(record, sanitize_text=sanitize_text)  # nothing is opened if this fails
    target = directory if directory is not None else state_dir()
    _ensure_dir(target)
    fd = _open_append(target / name)
    try:
        written = _write(fd, line)
    finally:
        os.close(fd)
    if written != len(line):
        raise ShortWriteError(f"short write to {name}: {written} of {len(line)} bytes")


def append_audit(
    record: Mapping[str, Any], *, state_dir: Path | None = None, sanitize_text: bool = True
) -> None:
    """Append one record to ``audit.jsonl``. Raises ``OSError`` (``ShortWriteError`` included)."""
    _append("audit.jsonl", record, state_dir, sanitize_text)


def append_log(
    record: Mapping[str, Any], *, state_dir: Path | None = None, sanitize_text: bool = True
) -> None:
    """Append one record to ``log.jsonl``."""
    _append("log.jsonl", record, state_dir, sanitize_text)


# --- record builders ---------------------------------------------------------------------


def audit_record(
    *,
    action: str,
    target: str,
    decision_id: str | Sequence[str],
    actor: str,
    stdin_tty: bool,
    actor_source: str,
    inputs: Mapping[str, Any],
    result: Mapping[str, Any],
    caller_decision_ids: Sequence[str] = (),
    ts: str | None = None,
    now: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """One ``audit.jsonl`` record. ``inputs`` gets the caller's ids and ``actor_source``.

    ``decision_id`` is the decision's own id for ``decision`` and ``outcome`` records, else the
    caller's ``--decision-id`` values (a list). The shapes of ``inputs`` and ``result`` per
    action are checked by ``schemas/audit.json``, not here.
    """
    if action not in AUDIT_ACTIONS:
        raise ValueError(f"unknown audit action: {action!r}")
    if len(caller_decision_ids) > 16:
        raise ValueError("at most 16 caller decision_ids")
    return {
        "ts": ts if ts is not None else now_ts(now),
        "actor": actor,
        "stdin_tty": stdin_tty,
        "decision_id": decision_id if isinstance(decision_id, str) else list(decision_id),
        "action": action,
        "target": target,
        "inputs": {
            **inputs,
            "decision_ids": list(caller_decision_ids),
            "actor_source": actor_source,
        },
        "result": dict(result),
    }


def log_record(
    *,
    level: str,
    event: str,
    message: str | None = None,
    policy: str | None = None,
    scope: str | None = None,
    decision_id: str | None = None,
    hook: str | None = None,
    data: Mapping[str, Any] | None = None,
    ts: str | None = None,
    now: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """One ``log.jsonl`` record; fields left as ``None`` are omitted."""
    if level not in LOG_LEVELS:
        raise ValueError(f"unknown log level: {level!r}")
    if event not in LOG_EVENTS:
        raise ValueError(f"unknown log event: {event!r}")
    record: dict[str, Any] = {"ts": ts if ts is not None else now_ts(now), "level": level}
    record["event"] = event
    optional = {
        "message": message,
        "policy": policy,
        "scope": scope,
        "decision_id": decision_id,
        "hook": hook,
        "data": data,
    }
    record.update({k: v for k, v in optional.items() if v is not None})
    return record
