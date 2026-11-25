"""Fixed-width UTC timestamps and --since parsing (interface.md, Time)."""

from __future__ import annotations

import random
import re
from datetime import UTC, datetime, timedelta, timezone

import pytest

from gatectl import clock
from gatectl.errors import UsageError

TS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z")
NOW = datetime(2026, 11, 24, 12, 0, 0, 123456, tzinfo=UTC)


def test_format_is_fixed_width() -> None:
    assert clock.format_ts(NOW) == "2026-11-24T12:00:00.123456Z"
    assert clock.format_ts(datetime(2026, 1, 2, 3, 4, 5, 0, tzinfo=UTC)) == (
        "2026-01-02T03:04:05.000000Z"
    )
    assert len(clock.format_ts(NOW)) == 27


def test_small_years_are_zero_padded() -> None:
    assert clock.format_ts(datetime(1, 1, 1, tzinfo=UTC)) == "0001-01-01T00:00:00.000000Z"
    assert clock.format_ts(datetime(999, 12, 31, tzinfo=UTC)).startswith("0999-")


def test_offset_times_are_converted_to_utc() -> None:
    plus5 = timezone(timedelta(hours=5, minutes=30))
    assert clock.format_ts(datetime(2026, 1, 1, 5, 30, tzinfo=plus5)) == (
        "2026-01-01T00:00:00.000000Z"
    )


def test_format_overflow_at_the_datetime_edge_is_a_value_error() -> None:
    with pytest.raises(ValueError):
        clock.format_ts(datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=5))))


def test_naive_datetime_rejected_for_format() -> None:
    with pytest.raises(ValueError, match="naive"):
        clock.format_ts(datetime(2026, 1, 1))


def test_now_ts_shape() -> None:
    assert TS.fullmatch(clock.now_ts())


def test_now_ts_uses_injected_clock() -> None:
    assert clock.now_ts(lambda: NOW) == "2026-11-24T12:00:00.123456Z"


def test_strings_sort_like_instants() -> None:
    rng = random.Random(7)
    base = datetime(2000, 1, 1, tzinfo=UTC)
    instants = [
        base + timedelta(seconds=rng.randrange(0, 10**9), microseconds=rng.randrange(0, 10**6))
        for _ in range(500)
    ]
    # Include edge shapes: whole seconds, sub-second only, year rollovers.
    instants += [
        datetime(2026, 12, 31, 23, 59, 59, 999999, tzinfo=UTC),
        datetime(2027, 1, 1, tzinfo=UTC),
        datetime(2027, 1, 1, 0, 0, 0, 1, tzinfo=UTC),
        datetime(999, 1, 1, tzinfo=UTC),
        datetime(10, 1, 1, tzinfo=UTC),
    ]
    by_instant = sorted(instants)
    by_string = sorted(instants, key=clock.format_ts)
    assert by_instant == by_string


def test_parse_ts_roundtrip() -> None:
    assert clock.parse_ts(clock.format_ts(NOW)) == NOW


@pytest.mark.parametrize(
    "bad",
    ["2026-11-24T12:00:00Z", "2026-11-24T12:00:00.123Z", "2026-11-24 12:00:00.123456Z", ""],
)
def test_parse_ts_requires_fixed_form(bad: str) -> None:
    with pytest.raises(ValueError, match="timestamp"):
        clock.parse_ts(bad)


class TestSince:
    def test_rfc3339_z(self) -> None:
        assert clock.parse_since("2026-11-24T10:00:00Z", NOW) == datetime(
            2026, 11, 24, 10, tzinfo=UTC
        )

    def test_rfc3339_offset_normalized_to_utc(self) -> None:
        got = clock.parse_since("2026-11-24T10:00:00+02:00", NOW)
        assert got == datetime(2026, 11, 24, 8, tzinfo=UTC)
        assert got.utcoffset() == timedelta(0)

    def test_negative_offset(self) -> None:
        assert clock.parse_since("2026-11-24T10:00:00-05:30", NOW) == datetime(
            2026, 11, 24, 15, 30, tzinfo=UTC
        )

    def test_fractional_seconds(self) -> None:
        got = clock.parse_since("2026-11-24T10:00:00.5Z", NOW)
        assert got == datetime(2026, 11, 24, 10, 0, 0, 500000, tzinfo=UTC)
        got = clock.parse_since("2026-11-24T10:00:00.123456789Z", NOW)
        assert got.microsecond == 123456

    @pytest.mark.parametrize(
        "naive",
        [
            "2026-11-24T10:00:00",
            "2026-11-24T10:00:00.123",
            "2026-11-24",
            "2026-11-24T10:00",
            "2026-11-24 10:00:00",
            "20261124T100000",
            "2026-11-24T10:00:00 ",
        ],
    )
    def test_naive_times_rejected(self, naive: str) -> None:
        with pytest.raises(UsageError):
            clock.parse_since(naive, NOW)

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "yesterday",
            "2026-13-01T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2026-11-24T24:00:00Z",
            "2026-11-24T10:00:60Z",
            "2026-11-24T10:00:00+24:00",
            "2026-11-24T10:00:00+0200",
            "2026-11-24T10:00:00z",
            "2026-11-24t10:00:00Z",
            "2026-11-24T10:00:00Z\n",
            "2026-11-24T10:00:00.Z",
            "0001-01-01T00:00:00+05:00",  # before the UTC epoch of datetime
            "9999-12-31T23:59:59-05:00",
            "٢026-11-24T10:00:00Z",
            "1" * 5000,
        ],
    )
    def test_malformed_rejected(self, bad: str) -> None:
        with pytest.raises(UsageError):
            clock.parse_since(bad, NOW)

    def test_duration_means_now_minus(self) -> None:
        assert clock.parse_since("10m", NOW) == NOW - timedelta(minutes=10)
        assert clock.parse_since("7d", NOW) == NOW - timedelta(days=7)
        assert clock.parse_since("0", NOW) == NOW

    def test_duration_too_far_back_is_usage_error(self) -> None:
        with pytest.raises(UsageError):
            clock.parse_since("99999999999d", datetime(2026, 1, 1, tzinfo=UTC))

    def test_naive_now_rejected(self) -> None:
        with pytest.raises(ValueError, match="naive"):
            clock.parse_since("1h", datetime(2026, 1, 1))

    def test_error_does_not_echo_input(self) -> None:
        with pytest.raises(UsageError) as exc:
            clock.parse_since("\x1b[31mbad", NOW)
        assert "\x1b" not in str(exc.value)

    def test_since_compares_correctly_against_stored_strings(self) -> None:
        cutoff = clock.format_ts(clock.parse_since("2026-11-24T12:00:00+00:00", NOW))
        assert clock.format_ts(NOW) > cutoff
        assert "2026-11-24T11:59:59.999999Z" < cutoff
