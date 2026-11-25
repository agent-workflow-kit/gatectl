"""The untrusted-text sanitizer (interface.md, Untrusted text).

Every code point whose Unicode category is ``Cc``, ``Cf``, ``Zl``, ``Zp``, ``Cs``, ``Co`` or
``Cn``, and any other non-printable character except the space, becomes the marker, one for
one, and the result is cut to a character cap. ``str.isprintable`` is false for exactly those
categories plus the separators ``Zs`` other than the space, so it is the whole rule.
"""

from __future__ import annotations

MARKER = "�"
DEFAULT_MAX_LEN = 256


def sanitize(text: str, max_len: int = DEFAULT_MAX_LEN) -> str:
    """Return ``text`` cut to ``max_len`` characters with every non-printable one replaced.

    The cut comes first (replacement is one for one, so the result is the same) and keeps the
    cost bounded by the cap, not by the size of the input.
    """
    if not isinstance(text, str):
        raise TypeError("sanitize takes str; use sanitize_bytes for bytes")
    if max_len < 0:
        raise ValueError("max_len must not be negative")
    return "".join(ch if ch == " " or ch.isprintable() else MARKER for ch in text[:max_len])


def sanitize_bytes(data: bytes, max_len: int = DEFAULT_MAX_LEN) -> str:
    """Decode untrusted bytes as UTF-8 (each invalid byte becomes the marker) and sanitize."""
    if not isinstance(data, bytes | bytearray | memoryview):
        raise TypeError("sanitize_bytes takes bytes")
    if max_len < 0:
        raise ValueError("max_len must not be negative")
    # A UTF-8 character is at most 4 bytes and an invalid byte yields one marker, so the first
    # ``max_len`` characters come from the first ``4 * max_len`` bytes.
    head = bytes(data[: 4 * max_len])
    return sanitize(head.decode("utf-8", errors="replace"), max_len)
