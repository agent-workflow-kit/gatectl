"""Reading, strict parsing and declaration of a check's input (interface.md, Input declaration).

The input of ``check`` is hostile by default. This module reads it bounded and without blocking,
parses it as strict JSON, validates the policy's declaration against it and captures the
declared fields and identity strings for recording. Nothing here echoes input: every
``InputInvalid`` carries a closed ``kind`` and a fixed message, and a declared key name (which
comes from the config, not from the input) only in ``key``. The caller maps ``InputInvalid`` to
the reason ``input_invalid`` and a ``UsageError`` to exit 2. A ``UsageError`` is raised only for
a terminal stdin with no ``--input`` and for a problem with a ``--input`` file; any stdin that
cannot be read (closed, a directory, not open for reading, a read error) is an unusable input
(``RawInput`` status ``unreadable``), never a usage error.

Judgment calls (conservative readings of the interface):

* Nesting: the top-level object is depth 1; depth 64 is accepted, 65 is refused.
* Numbers: an integer literal longer than ``MAX_NUMBER_CHARS`` is refused whatever the
  interpreter's integer-digit limit is set to (640 is the lowest value that limit can take);
  a float is refused only when it is not finite (``float()`` has no digit limit).
* A UTF-8 byte order mark is refused, not skipped.
* A stdin that is a terminal is a usage error only when ``--input`` is absent; ``-`` reads it
  like any stdin (polled, bound by the deadline).
"""

from __future__ import annotations

import fcntl
import json
import math
import os
import re
import select
import stat
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from gatectl.config_models import InputDecl
from gatectl.errors import UsageError
from gatectl.inputhash import canonical_input

MAX_DEPTH = 64
MAX_NUMBER_CHARS = 640
FIELD_CAP = 256  # characters of a declared string or an identity string
VALUE_CAP = 1024  # bytes of a declared non-string value's canonical JSON
IDENTITY_KEYS = ("tool", "hook", "object_type", "object_id")

_CHUNK = 64 * 1024

_MESSAGES = {
    "not_utf8": "the input is not valid UTF-8",
    "bom": "the input starts with a byte order mark",
    "depth": "the input is nested too deeply",
    "syntax": "the input is not valid JSON",
    "constant": "the input has a NaN or Infinity token",
    "number": "the input has a number that is too large or not finite",
    "surrogate": "the input has an unpaired surrogate",
    "duplicate_key": "the input has a duplicate object key",
    "not_object": "the input is not a JSON object",
    "missing": "a required input key is missing or null",
    "type": "an input key has the wrong type",
    "unrecordable": "an input value cannot be recorded",
}


class InputInvalid(Exception):
    """The input is unusable or fails the declaration; the decision is ``escalate input_invalid``.

    ``kind`` is a closed code; ``key`` is the declared key at fault (from the config) or None.
    """

    def __init__(self, kind: str, key: str | None = None) -> None:
        super().__init__(_MESSAGES[kind])
        self.kind = kind
        self.key = key


# ---- reading ----------------------------------------------------------------------------------


@dataclass(frozen=True)
class RawInput:
    """Bytes read (at most ``max_bytes + 1``) and how the read ended.

    ``complete``: end of file within the cap. ``too_large``: more than ``max_bytes`` exist.
    ``timeout``: the read budget ran out first. ``unreadable``: stdin is closed, a directory,
    not open for reading, or a read failed. ``data`` is what was read in every case (empty
    when nothing was); its SHA-256 is the ``input_sha256`` of an input that was not parsed.
    """

    data: bytes
    status: Literal["complete", "too_large", "timeout", "unreadable"]


def _stdin_readable(fd: int) -> bool:
    try:
        mode = os.fstat(fd).st_mode
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    except OSError:
        return False
    return not stat.S_ISDIR(mode) and (flags & os.O_ACCMODE) != os.O_WRONLY


def _is_tty(fd: int) -> bool:
    try:
        return os.isatty(fd)
    except OSError:
        return False


def _open_regular(path: str) -> int:
    fd = -1
    if path and "\x00" not in path:
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC)
        except (OSError, ValueError):
            fd = -1
    if fd < 0:
        raise UsageError("the input file is missing or unreadable") from None
    try:
        regular = stat.S_ISREG(os.fstat(fd).st_mode)
    except OSError:
        regular = False
    if not regular:
        os.close(fd)
        raise UsageError("the input file is not a regular file") from None
    return fd


def read_input(
    source: str | None,
    *,
    max_bytes: int,
    stdin_fd: int = 0,
    deadline: float | None = None,
    reserve: float = 0.0,
    monotonic: Callable[[], float] = time.monotonic,
) -> RawInput:
    """Read the input from the file ``source``, or from ``stdin_fd`` when it is None or ``-``.

    Reads at most ``max_bytes + 1`` bytes and stops there (``too_large``); stops with
    ``timeout`` when ``deadline - now - reserve`` (``monotonic`` seconds) reaches 0, so the
    reserve is left for recording. A file must be regular and is opened without blocking; a
    FIFO or device is never read. stdin is polled and never switched to non-blocking mode
    (the open file description is shared with whoever started us). A missing or unreadable
    file and a non-regular file raise ``UsageError`` (exit 2), as does a terminal stdin when
    ``source`` is None. Any other stdin that cannot be read returns status ``unreadable``.
    """
    if max_bytes < 1:
        raise ValueError("max_bytes must be at least 1")
    stdin = source is None or source == "-"
    if stdin:
        if source is None and _is_tty(stdin_fd):
            raise UsageError("stdin is a terminal: pass --input or pipe the input")
        if not _stdin_readable(stdin_fd):
            return RawInput(b"", "unreadable")
        fd = stdin_fd
    else:
        assert source is not None
        fd = _open_regular(source)
    try:
        return _drain(fd, max_bytes + 1, stdin, deadline, reserve, monotonic)
    finally:
        if not stdin:
            os.close(fd)


def _drain(
    fd: int,
    limit: int,
    wait: bool,
    deadline: float | None,
    reserve: float,
    monotonic: Callable[[], float],
) -> RawInput:
    buf = bytearray()
    poller = select.poll() if wait else None
    if poller is not None:
        poller.register(fd, select.POLLIN)
    while True:
        if len(buf) >= limit:
            return RawInput(bytes(buf), "too_large")
        remaining = None if deadline is None else deadline - monotonic() - reserve
        if remaining is not None and remaining <= 0:
            return RawInput(bytes(buf), "timeout")
        if poller is not None:
            ms = None if remaining is None else max(1, min(math.ceil(remaining * 1000), 60_000))
            if not poller.poll(ms):
                continue  # nothing yet; the loop re-checks the budget
        try:
            chunk = os.read(fd, min(_CHUNK, limit - len(buf)))
        except BlockingIOError:
            continue
        except OSError:
            return RawInput(bytes(buf), "unreadable")
        if not chunk:
            return RawInput(bytes(buf), "complete")
        buf += chunk


# ---- strict parsing ---------------------------------------------------------------------------


class _Reject(Exception):
    """Raised by a parse hook; never leaves this module."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


_STRUCT = re.compile(r'["\[\]{}]')
_STRING_PART = re.compile(r'["\\]')
_SURROGATE = re.compile("[\ud800-\udfff]")


def _nesting_ok(text: str) -> bool:
    """True when brackets nest at most ``MAX_DEPTH`` deep. A loop, never recursion.

    Strings are skipped (a bracket inside one does not count). Mismatched or unterminated
    input is left for the parser to refuse; the scan only measures depth and is linear.
    """
    depth = 0
    pos = 0
    while (m := _STRUCT.search(text, pos)) is not None:
        ch = text[m.start()]
        pos = m.end()
        if ch == '"':
            while (s := _STRING_PART.search(text, pos)) is not None:
                pos = s.end()
                if text[s.start()] == "\\":
                    pos += 1  # the escaped character, which may be a quote
                else:
                    break
            else:
                return True  # unterminated: the parser refuses it
        elif ch in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                return False
        elif depth:
            depth -= 1
    return True


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in items:
        if key in out:
            raise _Reject("duplicate_key")
        out[key] = value
    return out


def _constant(_name: str) -> Any:
    raise _Reject("constant")


def _int(text: str) -> int:
    if len(text) > MAX_NUMBER_CHARS:
        raise _Reject("number")
    return int(text)


def _float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise _Reject("number")
    return value


def _decode(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _loads(text: str) -> tuple[Any, str | None]:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_constant=_constant,
            parse_int=_int,
            parse_float=_float,
        )
    except _Reject as rejected:
        return None, rejected.kind
    except RecursionError:
        return None, "depth"
    except (ValueError, OverflowError):
        return None, "syntax"
    return value, None


def _walk(value: Any) -> Any:
    """Yield every node of a parsed value, iteratively (object keys included)."""
    stack = [value]
    while stack:
        node = stack.pop()
        yield node
        if isinstance(node, dict):
            stack.extend(node.keys())
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)


def _has_surrogate(value: Any) -> bool:
    return any(isinstance(n, str) and _SURROGATE.search(n) for n in _walk(value))


def parse_input(data: bytes) -> dict[str, Any]:
    """Parse ``data`` as one strict JSON object or raise ``InputInvalid``.

    UTF-8 without a byte order mark; nesting at most 64 (a non-recursive pre-scan before the
    decoder runs); no ``NaN``/``Infinity``; every number finite and every integer literal at
    most 640 characters; no duplicate key at any depth; no unpaired surrogate; no trailing
    data; an object at the top.
    """
    kind: str | None = None
    value: Any = None
    if data.startswith(b"\xef\xbb\xbf"):
        kind = "bom"
    elif (text := _decode(data)) is None:
        kind = "not_utf8"
    elif not _nesting_ok(text):
        kind = "depth"
    else:
        value, kind = _loads(text)
        if kind is None and not isinstance(value, dict):
            kind = "not_object"
        elif kind is None and _has_surrogate(value):
            kind = "surrogate"
    if kind is not None:
        raise InputInvalid(kind) from None
    assert isinstance(value, dict)
    return value


# ---- declaration ------------------------------------------------------------------------------


def _matches(kind: str, value: Any) -> bool:
    base = kind.removesuffix("?")
    if value is None:
        return kind.endswith("?")
    if base == "string":
        return isinstance(value, str)
    if base == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if base == "number":
        return isinstance(value, int | float) and not isinstance(value, bool)
    if base == "boolean":
        return isinstance(value, bool)
    if base == "object":
        return isinstance(value, dict)
    if base == "array":
        return isinstance(value, list)
    return False  # an unknown type name never matches


def check_declaration(decl: InputDecl | None, obj: Mapping[str, Any]) -> None:
    """Raise ``InputInvalid`` (``missing`` or ``type``, with the declared key) on a mismatch.

    ``require`` keys must be present and not null unless typed nullable (``?``); a key in
    ``types`` must match when present, absent is fine unless it is also required. The first
    violation in declaration order is reported (``require`` first, then ``types``).
    """
    if decl is None:
        return
    for key in decl.require:
        if key not in obj or (obj[key] is None and not decl.types.get(key, "").endswith("?")):
            raise InputInvalid("missing", key) from None
    for key, kind in decl.types.items():
        if key in obj and not _matches(kind, obj[key]):
            raise InputInvalid("type", key) from None


def without_ignored(decl: InputDecl | None, obj: Mapping[str, Any]) -> dict[str, Any]:
    """A copy of ``obj`` without the top-level keys of ``input.ignore`` (the cache-key view)."""
    skip = set(decl.ignore) if decl is not None else set()
    return {k: v for k, v in obj.items() if k not in skip}


# ---- capture for recording --------------------------------------------------------------------


def canonical_bytes(value: Any) -> bytes:
    """The UTF-8 bytes of the canonical serialization (the size that ``VALUE_CAP`` limits)."""
    return canonical_input(value).encode("utf-8")


def _ensure_recordable(value: Any) -> None:
    """Raise ``InputInvalid("unrecordable")`` unless every part is finite and UTF-8 encodable."""
    bad = False
    for node in _walk(value):
        if isinstance(node, str):
            bad = _SURROGATE.search(node) is not None
        elif isinstance(node, float):
            bad = not math.isfinite(node)
        if bad:
            raise InputInvalid("unrecordable") from None


def _capture(value: Any) -> Any:
    _ensure_recordable(value)
    if isinstance(value, str):
        return value[:FIELD_CAP]
    size = -1
    try:
        size = len(canonical_bytes(value))
    except (ValueError, TypeError, RecursionError):
        pass
    if size < 0:
        raise InputInvalid("unrecordable") from None
    if size > VALUE_CAP:
        return f"[truncated: {size} bytes]"
    return value


def declared_fields(decl: InputDecl | None, obj: Mapping[str, Any]) -> dict[str, Any]:
    """The values of the keys in ``require`` and ``types`` that are present, ready to record.

    A string is cut to 256 characters; any other value whose canonical JSON exceeds 1 KiB
    becomes ``[truncated: <n> bytes]``. A value that is not finite or not UTF-8 encodable
    raises ``InputInvalid("unrecordable")`` (checked before capping, so a bad value past the cap
    is still found). A declared key that is absent is left out.
    """
    if decl is None:
        return {}
    out: dict[str, Any] = {}
    for key in (*decl.require, *decl.types):
        if key in obj and key not in out:
            out[key] = _capture(obj[key])
    return out


@dataclass(frozen=True)
class Identity:
    """The identity strings recorded with a decision; each is a capped string or None."""

    tool: str | None
    hook: str | None
    object_type: str | None
    object_id: str | None


NO_IDENTITY = Identity(None, None, None, None)


def identity(obj: Mapping[str, Any]) -> Identity:
    """``tool``, ``hook``, ``object_type`` and ``object_id`` of the input, capped at 256
    characters; a value that is absent or not a string is None."""
    values: list[str | None] = []
    for key in IDENTITY_KEYS:
        value = obj.get(key)
        if isinstance(value, str):
            _ensure_recordable(value)
            values.append(value[:FIELD_CAP])
        else:
            values.append(None)
    return Identity(*values)
