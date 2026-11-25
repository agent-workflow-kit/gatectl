"""Canonical input serialization and input_sha256 (interface.md, Identifiers: Input hash)."""

from __future__ import annotations

import hashlib
import json

import pytest

from gatectl import inputhash


def test_vector_unicode_and_sorting() -> None:
    value = {"b": 1, "a": "é", "c": [1.5, True, None]}
    assert inputhash.canonical_input(value) == '{"a":"é","b":1,"c":[1.5,true,null]}'
    assert inputhash.input_sha256(value) == (
        "2332fe002293e35042867b9afd7a8a2a470df3cc466fe44903a5b44f99d16b92"
    )


def test_vector_repo_and_head() -> None:
    value = {"repo": "github.com/org/repo", "head_sha": "0123abcd"}
    assert inputhash.input_sha256(value) == (
        "82ad1dd601d033fddc136731fab553afa585dd3ad0f9f3745b42708aea02a855"
    )


def test_vector_raw_bytes() -> None:
    assert inputhash.input_sha256_raw(b"not json") == (
        "7ccfa1fbf3940e6f0c0375d87c0f9235a50514e14cb427bdfaf5077987b26ccf"
    )


def test_key_order_does_not_matter() -> None:
    assert inputhash.input_sha256({"a": 1, "b": 2}) == inputhash.input_sha256({"b": 2, "a": 1})


def test_sorted_by_code_point_not_utf16() -> None:
    # U+FF5E sorts before U+10000 by code point; UTF-16 order would put it after.
    value = {"\U00010000": 1, "～": 2}
    assert inputhash.canonical_input(value) == '{"～":2,"\U00010000":1}'


def test_nested_sorted_and_compact() -> None:
    assert inputhash.canonical_input({"z": {"b": [], "a": {}}}) == '{"z":{"a":{},"b":[]}}'


def test_characters_kept_except_required_escapes() -> None:
    assert inputhash.canonical_input({"k": 'a"b\\c\n\x01 /'}) == ('{"k":"a\\"b\\\\c\\n\\u0001 /"}')


def test_numbers() -> None:
    assert inputhash.canonical_input([1, 10**30, -0, 0.1, 1e16, 1.0, 1e-7]) == (
        "[1," + str(10**30) + ",0,0.1,1e+16,1.0,1e-07]"
    )


def test_whitespace_in_source_is_irrelevant() -> None:
    a = json.loads('{ "a" : 1 ,\n "b" : [ 1 , 2 ] }')
    b = json.loads('{"b":[1,2],"a":1}')
    assert inputhash.input_sha256(a) == inputhash.input_sha256(b)


def test_hash_is_sha256_of_utf8_of_canonical() -> None:
    value = {"x": "日本語"}
    assert (
        inputhash.input_sha256(value)
        == hashlib.sha256(inputhash.canonical_input(value).encode("utf-8")).hexdigest()
    )


def test_lone_surrogate_does_not_crash() -> None:
    value = json.loads('{"a":"\\ud800"}')
    digest = inputhash.input_sha256(value)
    assert len(digest) == 64
    assert digest == inputhash.input_sha256(json.loads('{"a":"\\ud800"}'))
    assert digest != inputhash.input_sha256({"a": "\ud801"})


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_numbers_rejected(bad: float) -> None:
    with pytest.raises(ValueError, match="finite|JSON"):
        inputhash.canonical_input({"a": bad})


def test_non_json_types_rejected() -> None:
    with pytest.raises(TypeError):
        inputhash.canonical_input({"a": {1, 2}})


def test_raw_hash_accepts_empty_and_binary() -> None:
    assert inputhash.input_sha256_raw(b"") == hashlib.sha256(b"").hexdigest()
    assert (
        inputhash.input_sha256_raw(b"\xff\xfe\x00") == hashlib.sha256(b"\xff\xfe\x00").hexdigest()
    )


def test_raw_hash_rejects_str() -> None:
    with pytest.raises(TypeError):
        inputhash.input_sha256_raw("text")  # type: ignore[arg-type]


def test_deeply_nested_value_is_an_error_not_a_crash() -> None:
    value: list = []
    for _ in range(100_000):
        value = [value]
    with pytest.raises((RecursionError, ValueError)):
        inputhash.canonical_input(value)
