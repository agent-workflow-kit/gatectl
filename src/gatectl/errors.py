"""Errors that carry an exit code and an envelope ``code``.

See interface.md, Exit codes and Error envelope.

Messages are fixed text naming the kind of problem. They never include the offending value:
every error ``message`` is untrusted-text-safe by construction (interface.md, Untrusted text).
``envelope`` still runs the message and details through the sanitizer as a second line of defense.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, ClassVar

from gatectl.sanitize import sanitize

# The closed ``code`` list of the error envelope (schemas/defs.json, error_code).
ERROR_CODES = (
    "usage",
    "config_invalid",
    "not_found",
    "ambiguous",
    "refused",
    "failed",
    "internal",
)
MESSAGE_CAP = 2048  # schemas/defs.json: error.message maxLength
_DETAIL_STRING_CAP = 256
_DETAIL_DEPTH = 8


class GatectlError(Exception):
    """Base class: a failure with a documented exit code. The base is an internal error (exit 1)."""

    exit_code: ClassVar[int] = 1
    code: ClassVar[str] = "internal"
    # The ``reason`` values this class may carry, and the one it carries by default.
    reasons: ClassVar[frozenset[str]] = frozenset()
    default_reason: ClassVar[str | None] = None

    def __init__(
        self,
        message: str,
        *,
        reason: str | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        if reason is None:
            reason = self.default_reason
        elif reason not in self.reasons:
            raise ValueError(f"{type(self).__name__} takes no such reason")
        self.message = message
        self.reason = reason
        self.details = details


class UsageError(GatectlError):
    """Bad flags or values (exit 2)."""

    exit_code = 2
    code = "usage"


class ConfigInvalidError(GatectlError):
    """A config error (exit 2)."""

    exit_code = 2
    code = "config_invalid"


class NotFoundError(GatectlError):
    """A decision id that does not exist (exit 10)."""

    exit_code = 10
    code = "not_found"


class AmbiguousError(GatectlError):
    """A decision-id prefix that matches more than one decision (exit 21)."""

    exit_code = 21
    code = "ambiguous"


class RefusedError(GatectlError):
    """``set ... enforced`` without a human (exit 20)."""

    exit_code = 20
    code = "refused"
    reasons = frozenset({"human_required"})
    default_reason = "human_required"


class FailedError(GatectlError):
    """The requested operation failed for an expected reason (exit 12)."""

    exit_code = 12
    code = "failed"


class InternalError(GatectlError):
    """An internal failure (exit 1); ``reason`` names a documented cause when there is one."""

    reasons = frozenset({"schema_newer", "state_db_missing"})


ALL_ERRORS: tuple[type[GatectlError], ...] = (
    UsageError,
    ConfigInvalidError,
    NotFoundError,
    AmbiguousError,
    RefusedError,
    FailedError,
    InternalError,
)

_FALLBACK_MESSAGE = "internal error"


def exit_code_of(exc: BaseException) -> int:
    """The exit code of ``exc``: its own for a gatectl error, 1 for anything else."""
    return exc.exit_code if isinstance(exc, GatectlError) else 1


def _clean(value: Any, depth: int = 0) -> Any:
    if isinstance(value, str):
        return sanitize(value, _DETAIL_STRING_CAP)
    if isinstance(value, bool) or value is None or isinstance(value, int | float):
        return value
    if depth >= _DETAIL_DEPTH:
        return None
    if isinstance(value, Mapping):
        return {sanitize(str(k), 64): _clean(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_clean(v, depth + 1) for v in value]
    return None


def envelope(exc: BaseException) -> dict[str, Any]:
    """The error envelope for ``exc``. A non-gatectl exception never leaks its text."""
    if not isinstance(exc, GatectlError):
        exc = InternalError(_FALLBACK_MESSAGE)
    details = None if exc.details is None else _clean(exc.details)
    return {
        "error": {
            "code": exc.code,
            "message": sanitize(exc.message, MESSAGE_CAP),
            "reason": exc.reason,
            "details": details,
        }
    }
