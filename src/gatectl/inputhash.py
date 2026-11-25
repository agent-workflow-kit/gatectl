"""Canonical input serialization and ``input_sha256`` (interface.md, Identifiers: Input hash)."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_input(value: Any) -> str:
    """Serialize a parsed JSON value: keys sorted by code point, no whitespace, characters kept.

    ``allow_nan=False``: NaN and the infinities are not JSON, and the engine's strict parser
    rejects them before a value gets here; reaching this function with one is a bug.
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def input_sha256(value: Any) -> str:
    """SHA-256 (hex) of the canonical serialization of a parsed input.

    A lone surrogate (strict JSON allows ``"\\ud800"``) cannot be written as UTF-8; it is
    encoded with ``surrogatepass`` so the hash is defined and stable instead of crashing.
    """
    return hashlib.sha256(
        canonical_input(value).encode("utf-8", errors="surrogatepass")
    ).hexdigest()


def input_sha256_raw(data: bytes) -> str:
    """SHA-256 (hex) of the raw bytes read, used when no object was parsed."""
    if not isinstance(data, bytes | bytearray | memoryview):
        raise TypeError("input_sha256_raw takes bytes")
    return hashlib.sha256(data).hexdigest()
