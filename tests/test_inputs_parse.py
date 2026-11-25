"""Strict JSON parsing of a check's input (interface.md, Input declaration)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from gatectl import inputs
from gatectl.inputs import InputInvalid

MARK = "SECRETMARK"


def parse_kind(data: bytes) -> str:
    with pytest.raises(InputInvalid) as info:
        inputs.parse_input(data)
    return info.value.kind


# ---- valid inputs -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        (b"{}", {}),
        (b' \t\r\n{"a": 1}\n ', {"a": 1}),
        (b'{"a":[1,2.5,true,null,"x"],"b":{"c":{}}}', {"a": [1, 2.5, True, None, "x"], "b": {"c": {}}}),
        ('{"é":"日本語"}'.encode(), {"é": "日本語"}),
        (b'{"a":"\\ud83d\\ude00"}', {"a": "\U0001f600"}),  # a valid surrogate pair
        (b'{"a":"\\u0000\\n\\"\\\\"}', {"a": '\x00\n"\\'}),
        (b'{"a":-0,"b":1E2,"c":1e-999,"d":0.5}', {"a": 0, "b": 100.0, "c": 0.0, "d": 0.5}),
    ],
)
def test_valid(data: bytes, expected: dict[str, Any]) -> None:
    assert inputs.parse_input(data) == expected


def test_integer_and_float_stay_distinct() -> None:
    obj = inputs.parse_input(b'{"a":1,"b":1.0,"c":1e2,"d":true}')
    assert type(obj["a"]) is int
    assert type(obj["b"]) is float
    assert type(obj["c"]) is float
    assert obj["d"] is True


def test_key_order_is_kept() -> None:
    assert list(inputs.parse_input(b'{"b":1,"a":2}')) == ["b", "a"]


def test_one_mib_object_parses() -> None:
    body = json.dumps({"k": "x" * (1024 * 1024 - 20)}).encode()
    assert len(body) <= 1024 * 1024
    assert len(inputs.parse_input(body)["k"]) == 1024 * 1024 - 20


# ---- encoding ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [
        b'{"a":"\xff"}',
        b'{"a":"\xc0\xaf"}',  # overlong
        b'{"a":"\xed\xa0\x80"}',  # a surrogate encoded as UTF-8
        b'{"a":"\xe6\x97"}',  # truncated multi-byte sequence
        b'{"a":"\xf4\x90\x80\x80"}',  # above U+10FFFF
        b'\xff{"a":1}',
    ],
)
def test_bad_utf8(data: bytes) -> None:
    assert parse_kind(data) == "not_utf8"


def test_utf16_is_not_utf8() -> None:
    assert parse_kind('{"a":1}'.encode("utf-16")) in {"not_utf8", "bom"}
    assert parse_kind('{"a":1}'.encode("utf-16-le")) == "not_utf8"


def test_bom_rejected() -> None:
    assert parse_kind(b'\xef\xbb\xbf{"a":1}') == "bom"


# ---- constants and numbers --------------------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [b'{"a":NaN}', b'{"a":Infinity}', b'{"a":-Infinity}', b'{"a":[NaN]}', b"NaN"],
)
def test_non_finite_tokens(data: bytes) -> None:
    assert parse_kind(data) == "constant"


@pytest.mark.parametrize(
    "data",
    [b'{"a":1e999}', b'{"a":-1e999}', b'{"a":[1E400]}', b'{"a":1e99999999999}'],
)
def test_overflowing_float(data: bytes) -> None:
    assert parse_kind(data) == "number"


def test_integer_digit_limit() -> None:
    assert inputs.parse_input(b'{"a":' + b"9" * inputs.MAX_NUMBER_CHARS + b"}")["a"] > 0
    assert parse_kind(b'{"a":' + b"9" * (inputs.MAX_NUMBER_CHARS + 1) + b"}") == "number"
    assert parse_kind(b'{"a":' + b"9" * 5000 + b"}") == "number"
    assert parse_kind(b'{"a":-' + b"9" * 5000 + b"}") == "number"


def test_huge_integer_does_not_depend_on_interpreter_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    old = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(0)  # unlimited: the parser must still refuse
    try:
        assert parse_kind(b'{"a":' + b"9" * 100_000 + b"}") == "number"
    finally:
        sys.set_int_max_str_digits(old)


def test_long_float_literal() -> None:
    assert parse_kind(b'{"a":0.' + b"0" * 5000 + b"1}") == "number"
    assert parse_kind(b'{"a":1e' + b"0" * 5000 + b"1}") == "number"


@pytest.mark.parametrize(
    "data", [b'{"a":01}', b'{"a":+1}', b'{"a":.5}', b'{"a":1.}', b'{"a":0x10}', b'{"a":1_0}']
)
def test_non_json_numbers(data: bytes) -> None:
    assert parse_kind(data) == "syntax"


# ---- strings ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [
        b'{"a":"\\ud800"}',
        b'{"a":"\\udc00"}',
        b'{"a":"\\ud800x"}',
        b'{"a":"\\ud800\\u0041"}',
        b'{"a":"\\udc00\\ud800"}',  # reversed pair
        b'{"\\ud800":1}',  # a key
        b'{"a":["ok","\\udfff"]}',
        b'{"a":{"b":"\\ud83d"}}',
    ],
)
def test_unpaired_surrogate(data: bytes) -> None:
    assert parse_kind(data) == "surrogate"


@pytest.mark.parametrize(
    "data",
    [b'{"a":"x\ny"}', b'{"a":"x\ty"}', b'{"a":"x\x00y"}', b'{"a":"\x1f"}', b'{"a":"\\x41"}'],
)
def test_bad_string_content(data: bytes) -> None:
    assert parse_kind(data) == "syntax"


# ---- duplicate keys ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data",
    [
        b'{"a":1,"a":2}',
        b'{"a":1,"a":1}',
        b'{"a":{"b":1,"b":2}}',
        b'{"a":[{"x":1},{"y":1,"y":2}]}',
        b'{"a":1,"\\u0061":2}',  # the same key spelled with an escape
        b'{"":1,"":2}',
        b'{"a":{"b":{"c":{"d":1,"d":2}}}}',
    ],
)
def test_duplicate_keys(data: bytes) -> None:
    assert parse_kind(data) == "duplicate_key"


def test_same_key_in_different_objects_is_fine() -> None:
    assert inputs.parse_input(b'{"a":{"k":1},"b":{"k":2},"c":[{"k":1},{"k":2}]}')


def test_case_differs_is_not_duplicate() -> None:
    assert inputs.parse_input(b'{"a":1,"A":2}') == {"a": 1, "A": 2}


# ---- nesting ----------------------------------------------------------------------------------


def _nest(depth: int, *, array: bool = True) -> bytes:
    if array:
        return b"[" * depth + b"]" * depth
    return b'{"a":' * depth + b"1" + b"}" * depth


def test_depth_64_is_allowed_and_65_is_not() -> None:
    # The top-level object counts as depth 1.
    ok = b'{"a":' + _nest(63) + b"}"
    assert inputs.parse_input(ok)
    assert parse_kind(b'{"a":' + _nest(64) + b"}") == "depth"
    assert inputs.parse_input(_nest(64, array=False))
    assert parse_kind(_nest(65, array=False)) == "depth"


@pytest.mark.parametrize("depth", [100_000, 500_000])
def test_deep_arrays_are_refused_without_recursion(depth: int) -> None:
    assert parse_kind(b"[" * depth) == "depth"
    assert parse_kind(_nest(depth)) == "depth"
    assert parse_kind(b'{"a":' + b"[" * depth) == "depth"
    assert parse_kind(b'{"a":' * depth) == "depth"


def test_brackets_inside_strings_do_not_count() -> None:
    body = b'{"a":"' + b"[" * 5000 + b'","b":"\\"' + b"{" * 5000 + b'\\\\","c":"]]]"}'
    assert inputs.parse_input(body)["a"] == "[" * 5000


def test_escaped_backslash_before_quote_ends_the_string() -> None:
    # "\\" is a complete string; the next [ is real structure.
    body = b'{"a":"\\\\","b":' + b"[" * 70 + b"]" * 70 + b"}"
    assert parse_kind(body) == "depth"


def test_unterminated_string_with_escaped_quotes_is_fast_and_invalid() -> None:
    assert parse_kind(b'{"a":"' + b'\\"' * 500_000) == "syntax"


# ---- shape ------------------------------------------------------------------------------------


@pytest.mark.parametrize("data", [b"[]", b'"s"', b"1", b"1.5", b"null", b"true", b"[{}]"])
def test_top_level_must_be_an_object(data: bytes) -> None:
    assert parse_kind(data) == "not_object"


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"   ",
        b"\n",
        b"{",
        b"}",
        b'{"a"}',
        b'{"a":}',
        b'{"a":1,}',
        b"{'a':1}",
        b'{a:1}',
        b'{"a":1}}',
        b'{"a":1} x',
        b'{"a":1}{"b":2}',
        b'{"a":1},',
        b'{"a":1}\x00',
        b'{"a":1} // c',
        b'/* c */{"a":1}',
        b'\x0b{"a":1}',
        b'\xc2\xa0{"a":1}',  # no-break space is not JSON whitespace
        b'\x0c{"a":1}',
        b'{"a" 1}',
        b'{"a":tru}',
        b'{"a":True}',
        b'{"a":nul}',
        b'{"a":"unterminated}',
        b'{"a":[1,2}',
    ],
)
def test_syntax_errors(data: bytes) -> None:
    assert parse_kind(data) == "syntax"


def test_null_bytes_in_the_middle() -> None:
    assert parse_kind(b'{"a"\x00:1}') == "syntax"


# ---- errors never echo input ------------------------------------------------------------------


HOSTILE = [
    f'{{"a":"{MARK}\\ud800"}}'.encode(),
    f'{{"{MARK}":1,"{MARK}":2}}'.encode(),
    f'{{"a":"{MARK}"'.encode(),
    f'{{"a":{MARK}}}'.encode(),
    f'{{"a":1}} {MARK}'.encode(),
    f'["{MARK}"]'.encode(),
    f'{{"a":"{MARK}\xff"}}'.encode("latin-1"),
    f'{{"a":NaN,"{MARK}":1}}'.encode(),
    b'{"a":' + MARK.encode() + b"9" * 5000 + b"}",
    MARK.encode() + b"[" * 1000,
    f'{{"{MARK}":1e999}}'.encode(),
    b"\xef\xbb\xbf" + MARK.encode(),
]


@pytest.mark.parametrize("data", HOSTILE)
def test_error_does_not_echo_input(data: bytes) -> None:
    with pytest.raises(InputInvalid) as info:
        inputs.parse_input(data)
    exc = info.value
    assert MARK not in str(exc)
    assert MARK not in repr(exc)
    assert all(MARK not in str(a) for a in exc.args)
    assert exc.__cause__ is None
    assert exc.__context__ is None
    assert exc.__suppress_context__
    assert MARK not in exc.kind
    assert exc.key is None


def test_non_bytes_is_a_type_error() -> None:
    with pytest.raises(TypeError):
        inputs.parse_input('{"a":1}')  # type: ignore[arg-type]


def test_every_invalid_parse_is_input_invalid_never_another_exception() -> None:
    # A catalogue of nasty byte strings: whatever happens, the one exception type comes out.
    nasty = [bytes([b]) * n for b in (0, 0x22, 0x5C, 0x7B, 0x5B, 0xFF, 0x80) for n in (1, 3, 1000)]
    nasty += [b'{"a":' + b"-" * 10_000 + b"}", b'{"a":' + b"1" * 10_000 + b".5}"]
    for data in nasty:
        with pytest.raises(InputInvalid):
            inputs.parse_input(data)
