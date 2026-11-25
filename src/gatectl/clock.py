"""Fixed-width UTC timestamps and ``--since`` parsing (interface.md, Identifiers: Time).

Every stored and printed timestamp is ``YYYY-MM-DDTHH:MM:SS.ffffffZ``, so two of them compare
correctly as strings.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone

from gatectl.errors import UsageError
from gatectl.ids import parse_duration

_TS = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{6})Z")
_RFC3339 = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.([0-9]{1,9}))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))"
)


def _require_aware(moment: datetime) -> datetime:
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("naive datetime: a timezone is required")
    return moment.astimezone(UTC)


def format_ts(moment: datetime) -> str:
    """Format an aware datetime as UTC in the fixed 27-character form."""
    try:
        m = _require_aware(moment)
    except OverflowError:
        raise ValueError("datetime out of range after conversion to UTC") from None
    return (
        f"{m.year:04d}-{m.month:02d}-{m.day:02d}T"
        f"{m.hour:02d}:{m.minute:02d}:{m.second:02d}.{m.microsecond:06d}Z"
    )


def now_ts(now: Callable[[], datetime] | None = None) -> str:
    return format_ts(now() if now is not None else datetime.now(UTC))


def parse_ts(text: str) -> datetime:
    """Parse the fixed stored form only (never user input; see ``parse_since``)."""
    match = _TS.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        raise ValueError("not a fixed-width timestamp")
    year, month, day, hour, minute, second, micro = (int(g) for g in match.groups())
    return datetime(year, month, day, hour, minute, second, micro, tzinfo=UTC)


def parse_since(text: str, now: datetime) -> datetime:
    """``--since``: an RFC 3339 time with ``Z`` or an offset (never naive), or a duration.

    A duration means "now minus". Conservative reading: only the upper-case ``T`` and ``Z`` and
    a ``+hh:mm`` or ``-hh:mm`` offset are accepted. The result is an aware UTC datetime.
    """
    now_utc = _require_aware(now)
    if not isinstance(text, str):
        raise UsageError("invalid --since")
    match = _RFC3339.fullmatch(text)
    if match is None:
        try:
            delta = parse_duration(text)
        except UsageError:
            raise UsageError(
                "invalid --since: expected an RFC 3339 time with Z or an offset, or a duration"
            ) from None
        try:
            return now_utc - delta
        except OverflowError:
            raise UsageError("invalid --since: too far in the past") from None
    year, month, day, hour, minute, second = (int(g) for g in match.groups()[:6])
    fraction = (match.group(7) or "").ljust(6, "0")[:6]
    sign, off_h, off_m = match.group(8), match.group(9), match.group(10)
    try:
        if sign is None:
            tz = UTC
        else:
            if int(off_m) > 59:
                raise ValueError("offset minutes")
            offset = timedelta(hours=int(off_h), minutes=int(off_m))
            tz = timezone(-offset if sign == "-" else offset)
        moment = datetime(year, month, day, hour, minute, second, int(fraction), tzinfo=tz)
        return moment.astimezone(UTC)
    except (ValueError, OverflowError):
        raise UsageError("invalid --since: not a valid RFC 3339 time") from None
