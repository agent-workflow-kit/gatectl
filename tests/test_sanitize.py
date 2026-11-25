"""Untrusted-text sanitizer (interface.md, Untrusted text)."""

from __future__ import annotations

import unicodedata

import pytest

from gatectl.sanitize import MARKER, sanitize, sanitize_bytes

# One representative per replaced category; the category is asserted so a wrong sample fails.
SAMPLES = {
    "Cc": ["\x00", "\n", "\t", "\x1b", "\x7f", "\x85", "\x9b"],
    "Cf": ["\u200b", "\u202e", "\u2066", "\ufeff", "\u00ad", "\U000e0041"],
    "Zl": ["\u2028"],
    "Zp": ["\u2029"],
    "Cs": ["\ud800", "\udfff"],
    "Co": ["\ue000", "\U000f0000"],
    "Cn": ["\u0378", "\U0010ffff", "\ufdd0"],
}


@pytest.mark.parametrize(
    ("category", "char"), [(c, ch) for c, chars in SAMPLES.items() for ch in chars]
)
def test_replaced_category(category: str, char: str) -> None:
    assert unicodedata.category(char) == category
    assert sanitize(f"a{char}b") == f"a{MARKER}b"


def test_marker_is_replacement_character() -> None:
    assert MARKER == "�"


def test_space_is_kept() -> None:
    assert sanitize("a b  c") == "a b  c"


@pytest.mark.parametrize("char", [" ", " ", "　", " "])
def test_other_non_printable_separators_replaced(char: str) -> None:
    # Zs other than the space is non-printable: replaced too.
    assert sanitize(f"a{char}b") == f"a{MARKER}b"


def test_printable_unicode_kept() -> None:
    assert sanitize("héllo wörld 日本語 \U0001f600") == "héllo wörld 日本語 \U0001f600"


def test_ansi_escape_sequence_defanged() -> None:
    out = sanitize("\x1b[31mred\x1b[0m")
    assert "\x1b" not in out
    assert out == f"{MARKER}[31mred{MARKER}[0m"


def test_newline_injection_cannot_forge_a_line() -> None:
    assert "\n" not in sanitize('x"}\n{"action":"decision"}')


def test_marker_itself_passes_through() -> None:
    assert sanitize(MARKER) == MARKER


def test_default_cap_is_256_characters() -> None:
    assert sanitize("a" * 1000) == "a" * 256
    assert sanitize("a" * 256) == "a" * 256


def test_custom_cap() -> None:
    assert sanitize("abcdef", max_len=3) == "abc"
    assert sanitize("abcdef", max_len=0) == ""


def test_cap_counts_characters_not_bytes() -> None:
    assert sanitize("é" * 300) == "é" * 256
    assert sanitize("\U0001f600" * 300) == "\U0001f600" * 256


def test_replacement_counts_toward_cap() -> None:
    assert sanitize("\n" * 300) == MARKER * 256


def test_huge_value_is_cheap_and_capped() -> None:
    out = sanitize("\x00" * 50_000_000)
    assert out == MARKER * 256


def test_negative_cap_rejected() -> None:
    with pytest.raises(ValueError, match="max_len"):
        sanitize("a", max_len=-1)


def test_non_str_rejected() -> None:
    with pytest.raises(TypeError):
        sanitize(b"bytes")  # type: ignore[arg-type]


def test_empty() -> None:
    assert sanitize("") == ""


def test_invalid_utf8_bytes_become_marker() -> None:
    assert sanitize_bytes(b"ok\xff\xfe\x80bad") == f"ok{MARKER}{MARKER}{MARKER}bad"


def test_bytes_with_control_chars_and_cap() -> None:
    assert sanitize_bytes(b"a\x00b") == f"a{MARKER}b"
    assert sanitize_bytes(b"x" * 1000) == "x" * 256
    assert sanitize_bytes(b"x" * 1000, max_len=10) == "x" * 10


def test_bytes_overlong_and_surrogate_encodings_replaced() -> None:
    # Overlong NUL and an encoded surrogate are invalid UTF-8.
    out = sanitize_bytes(b"\xc0\x80\xed\xa0\x80")
    assert set(out) == {MARKER}


def test_truncated_multibyte_at_cap_boundary_is_marker() -> None:
    data = b"a" * 10 + "é".encode()[:1]
    assert sanitize_bytes(data) == "a" * 10 + MARKER


def test_output_is_always_printable_or_space() -> None:
    every = "".join(chr(c) for c in range(0x3000)) + "\ud800\U0010ffff"
    for start in range(0, len(every), 256):
        out = sanitize(every[start : start + 256])
        assert all(ch == " " or ch.isprintable() for ch in out)
