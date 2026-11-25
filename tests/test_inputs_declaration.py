"""Declaration validation and declared-field capture (interface.md, Input declaration)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from gatectl import inputs, scope
from gatectl.config_models import InputDecl
from gatectl.inputhash import input_sha256, input_sha256_raw
from gatectl.inputs import InputInvalid


def decl(**kw: Any) -> InputDecl:
    return InputDecl(**kw)


def kind_of(d: InputDecl | None, obj: dict[str, Any]) -> tuple[str, str | None] | None:
    try:
        inputs.check_declaration(d, obj)
    except InputInvalid as exc:
        return exc.kind, exc.key
    return None


# ---- require and types ------------------------------------------------------------------------


def test_no_declaration_accepts_any_object() -> None:
    assert kind_of(None, {"a": 1}) is None
    assert kind_of(decl(), {}) is None


def test_require_present_and_non_null() -> None:
    d = decl(require=["repo"])
    assert kind_of(d, {"repo": "x"}) is None
    assert kind_of(d, {}) == ("missing", "repo")
    assert kind_of(d, {"repo": None}) == ("missing", "repo")


def test_require_with_nullable_type_allows_null_but_not_absence() -> None:
    d = decl(require=["a"], types={"a": "string?"})
    assert kind_of(d, {"a": None}) is None
    assert kind_of(d, {"a": "x"}) is None
    assert kind_of(d, {}) == ("missing", "a")
    assert kind_of(d, {"a": 1}) == ("type", "a")


def test_key_in_types_but_not_required_may_be_absent_but_must_match() -> None:
    d = decl(types={"n": "integer"})
    assert kind_of(d, {}) is None
    assert kind_of(d, {"n": 3}) is None
    assert kind_of(d, {"n": "3"}) == ("type", "n")
    assert kind_of(d, {"n": None}) == ("type", "n")  # null only with ?


def test_optional_nullable() -> None:
    d = decl(types={"n": "integer?"})
    assert kind_of(d, {}) is None
    assert kind_of(d, {"n": None}) is None
    assert kind_of(d, {"n": 1.5}) == ("type", "n")


@pytest.mark.parametrize(
    ("kind", "good", "bad"),
    [
        ("string", ["", "x", "é"], [1, 1.5, True, None, [], {}]),
        ("integer", [0, -5, 10**30], [1.0, 1.5, True, False, "1", None, [], {}]),
        ("number", [0, 1, 1.5, -2.5e10, 1.0], [True, False, "1", None, [], {}]),
        ("boolean", [True, False], [0, 1, "true", None, [], {}]),
        ("object", [{}, {"a": 1}], [[], "x", 1, True, None]),
        ("array", [[], [1]], [{}, "x", 1, True, None]),
    ],
)
def test_type_rules(kind: str, good: list[Any], bad: list[Any]) -> None:
    d = decl(types={"k": kind})
    for value in good:
        assert kind_of(d, {"k": value}) is None, value
    for value in bad:
        assert kind_of(d, {"k": value}) == ("type", "k"), value
    nullable = decl(types={"k": kind + "?"})
    assert kind_of(nullable, {"k": None}) is None


def test_integer_rejects_one_point_zero_from_the_parser() -> None:
    d = decl(types={"n": "integer"})
    assert kind_of(d, inputs.parse_input(b'{"n":1.0}')) == ("type", "n")
    assert kind_of(d, inputs.parse_input(b'{"n":1e0}')) == ("type", "n")
    assert kind_of(d, inputs.parse_input(b'{"n":1}')) is None
    assert kind_of(d, inputs.parse_input(b'{"n":-0}')) is None


def test_booleans_are_never_numbers() -> None:
    assert kind_of(decl(types={"n": "number"}), {"n": True}) == ("type", "n")
    assert kind_of(decl(types={"n": "integer"}), {"n": True}) == ("type", "n")


def test_required_key_without_type_just_needs_a_value() -> None:
    d = decl(require=["a"])
    assert kind_of(d, {"a": 0}) is None
    assert kind_of(d, {"a": False}) is None
    assert kind_of(d, {"a": ""}) is None
    assert kind_of(d, {"a": []}) is None


def test_first_violation_in_declaration_order_is_reported() -> None:
    d = decl(require=["a", "b"], types={"c": "integer"})
    assert kind_of(d, {"c": "x"}) == ("missing", "a")


def test_error_never_carries_the_value() -> None:
    d = decl(types={"k": "integer"})
    with pytest.raises(InputInvalid) as info:
        inputs.check_declaration(d, {"k": "SECRETMARK"})
    assert "SECRETMARK" not in str(info.value) + repr(info.value)
    assert info.value.__cause__ is None


def test_similar_keys_are_not_confused() -> None:
    d = decl(require=["repo"])
    assert kind_of(d, {"Repo": "x", "repo ": "x", "repos": "x"}) == ("missing", "repo")


# ---- ignore -----------------------------------------------------------------------------------


def test_without_ignored_drops_only_top_level_listed_keys() -> None:
    obj = {"ts": 1, "keep": {"ts": 2}, "other": 3}
    assert inputs.without_ignored(decl(ignore=["ts"]), obj) == {"keep": {"ts": 2}, "other": 3}
    assert obj["ts"] == 1  # the input itself is untouched
    assert inputs.without_ignored(None, obj) == obj
    assert inputs.without_ignored(decl(ignore=["absent"]), obj) == obj


def test_ignored_keys_still_change_the_input_hash() -> None:
    a = {"ts": 1, "x": 1}
    b = {"ts": 2, "x": 1}
    assert input_sha256(a) != input_sha256(b)
    d = decl(ignore=["ts"])
    assert input_sha256(inputs.without_ignored(d, a)) == input_sha256(inputs.without_ignored(d, b))


def test_ignored_keys_are_still_validated() -> None:
    d = decl(require=["ts"], ignore=["ts"])
    assert kind_of(d, {}) == ("missing", "ts")


# ---- declared fields --------------------------------------------------------------------------


def test_declared_fields_cover_require_and_types_only() -> None:
    d = decl(require=["a"], types={"a": "string", "b": "integer?", "c": "string"})
    obj = {"a": "x", "b": None, "extra": "no", "d": 1}
    assert inputs.declared_fields(d, obj) == {"a": "x", "b": None}


def test_declared_fields_none_declaration() -> None:
    assert inputs.declared_fields(None, {"a": 1}) == {}


def test_declared_string_cap_is_256_characters() -> None:
    d = decl(require=["s"])
    assert inputs.declared_fields(d, {"s": "a" * 256})["s"] == "a" * 256
    assert inputs.declared_fields(d, {"s": "a" * 257})["s"] == "a" * 256
    assert inputs.declared_fields(d, {"s": "é" * 1000})["s"] == "é" * 256
    assert inputs.declared_fields(d, {"s": "\U0001f600" * 300})["s"] == "\U0001f600" * 256


def test_declared_non_string_over_1kib_is_replaced_by_a_marker() -> None:
    d = decl(require=["o"])
    small = {"k": "x" * (1024 - len('{"k":""}'))}
    assert len(inputs.canonical_bytes(small)) == 1024
    assert inputs.declared_fields(d, {"o": small})["o"] == small
    big = {"k": "x" * (1024 - len('{"k":""}') + 1)}
    assert inputs.declared_fields(d, {"o": big})["o"] == "[truncated: 1025 bytes]"


def test_truncation_counts_utf8_bytes_of_the_canonical_form() -> None:
    d = decl(require=["o"])
    value = ["é"] * 600  # 600 * (2 + 2 quotes + 1 comma) - 1 + 2 brackets = 3001 bytes
    expected = len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode())
    assert inputs.declared_fields(d, {"o": value})["o"] == f"[truncated: {expected} bytes]"


def test_truncated_marker_is_a_string_even_for_a_declared_array() -> None:
    d = decl(types={"a": "array"})
    out = inputs.declared_fields(d, {"a": list(range(2000))})["a"]
    assert isinstance(out, str) and out.startswith("[truncated: ")


def test_huge_declared_value_is_marked_without_blowup() -> None:
    d = decl(require=["a"])
    obj = inputs.parse_input(b'{"a":[' + b"1," * 300_000 + b"1]}")
    assert inputs.declared_fields(d, obj)["a"] == f"[truncated: {300_000 * 2 + 1 + 2} bytes]"


def test_declared_numbers_and_booleans_are_kept() -> None:
    d = decl(types={"i": "integer", "f": "number", "b": "boolean"})
    obj = {"i": 10**20, "f": 1.5, "b": False}
    assert inputs.declared_fields(d, obj) == obj


def test_unrecordable_declared_values_are_refused_before_recording() -> None:
    d = decl(require=["a"])
    for bad in (float("nan"), float("inf"), "\ud800", ["x", {"k": "\udfff"}], {"\ud800": 1}):
        with pytest.raises(InputInvalid) as info:
            inputs.declared_fields(d, {"a": bad})
        assert info.value.kind == "unrecordable"
        assert info.value.__cause__ is None


def test_unrecordable_is_found_before_it_is_capped_or_truncated() -> None:
    d = decl(require=["a"])
    with pytest.raises(InputInvalid):
        inputs.declared_fields(d, {"a": "x" * 300 + "\ud800"})  # past the 256 cap
    with pytest.raises(InputInvalid):
        inputs.declared_fields(d, {"a": [0] * 5000 + [float("nan")]})  # inside a truncated value


# ---- identity strings -------------------------------------------------------------------------


def test_identity_strings() -> None:
    obj = {"tool": "Bash", "hook": "pre", "object_type": "pr", "object_id": "42"}
    ident = inputs.identity(obj)
    assert (ident.tool, ident.hook, ident.object_type, ident.object_id) == (
        "Bash",
        "pre",
        "pr",
        "42",
    )


def test_identity_absent_and_non_string_are_null() -> None:
    ident = inputs.identity({"object_id": 42, "tool": None, "hook": ["x"], "object_type": {}})
    assert (ident.tool, ident.hook, ident.object_type, ident.object_id) == (None, None, None, None)
    assert inputs.identity({}) == inputs.Identity(None, None, None, None)
    assert inputs.identity({"object_id": True}).object_id is None
    assert inputs.identity({"object_id": 1.5}).object_id is None


def test_identity_is_capped_at_256_characters() -> None:
    assert inputs.identity({"tool": "t" * 1000}).tool == "t" * 256
    assert inputs.identity({"tool": "é" * 257}).tool == "é" * 256


def test_identity_refuses_unencodable_strings() -> None:
    with pytest.raises(InputInvalid) as info:
        inputs.identity({"tool": "\ud800"})
    assert info.value.kind == "unrecordable"
    # a non-string is recorded as null, so its content is never looked at
    assert inputs.identity({"tool": ["\ud800"]}).tool is None


def test_identity_null_form() -> None:
    assert inputs.NO_IDENTITY == inputs.Identity(None, None, None, None)


# ---- the acceptance cases end to end ----------------------------------------------------------


def _record(data: bytes) -> str:
    """What the engine does after reading: parse, scope, capture, hash. Nothing may fail."""
    d = decl(require=["repo"], types={"repo": "string"})
    try:
        obj = inputs.parse_input(data)
    except InputInvalid:
        assert input_sha256_raw(data)  # an unparsed input is hashed as the raw bytes
        assert scope.resolve_scope(None, None).indeterminate
        return "invalid"
    sc = scope.resolve_scope(None, obj)
    try:
        inputs.check_declaration(d, obj)
        inputs.declared_fields(d, obj)
        inputs.identity(obj)
    except InputInvalid:
        return "declaration"
    input_sha256(obj)
    return "indeterminate" if sc.indeterminate else "ok"


@pytest.mark.parametrize(
    ("data", "outcome"),
    [
        (b'{"repo":"github.com/o/r","n":1e999}', "invalid"),
        (b'{"repo":"\\ud800"}', "invalid"),
        (b"[" * 100_000 + b"]" * 100_000, "invalid"),
        (b'{"repo":"github.com/o/r","n":' + b"9" * 5000 + b"}", "invalid"),
        (b'{"repo":"github.com/o/r","repo":"github.com/o/r"}', "invalid"),
        (b'{"repo":"\xff"}', "invalid"),
        (b'{"repo":"' + b"a" * (1024 * 1024 - 20) + b'"}', "indeterminate"),
        (b'{"repo":"github.com/o/r","object_id":42,"tool":"t"}', "ok"),
        (b'{"repo":"github.com/o/r","object_id":1e5}', "ok"),
        (b"{}", "declaration"),
        (b'{"repo":5}', "declaration"),
    ],
)
def test_nothing_fails_while_recording(data: bytes, outcome: str) -> None:
    assert _record(data) == outcome


def test_numeric_object_id_is_recorded_as_null() -> None:
    obj = inputs.parse_input(b'{"repo":"github.com/o/r","object_id":42}')
    assert inputs.identity(obj).object_id is None
