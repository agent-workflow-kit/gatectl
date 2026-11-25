from __future__ import annotations

import json
from pathlib import Path

import pytest

from gatectl import errors
from gatectl.sanitize import MARKER
from tests import schema_util

DEFS = json.loads(
    (Path(__file__).resolve().parent.parent / "schemas" / "defs.json").read_text(encoding="utf-8")
)["$defs"]

# The documented table: error envelope code -> exit code (interface.md, Error envelope).
DOCUMENTED = {
    "usage": 2,
    "config_invalid": 2,
    "not_found": 10,
    "ambiguous": 21,
    "refused": 20,
    "failed": 12,
    "internal": 1,
}


def test_the_code_list_is_exactly_the_documented_and_schema_list() -> None:
    assert set(errors.ERROR_CODES) == set(DOCUMENTED)
    assert set(errors.ERROR_CODES) == set(DEFS["error_code"]["enum"])
    assert len(errors.ERROR_CODES) == len(set(errors.ERROR_CODES))


@pytest.mark.parametrize(
    ("cls", "code"),
    [
        (errors.UsageError, "usage"),
        (errors.ConfigInvalidError, "config_invalid"),
        (errors.NotFoundError, "not_found"),
        (errors.AmbiguousError, "ambiguous"),
        (errors.RefusedError, "refused"),
        (errors.FailedError, "failed"),
        (errors.InternalError, "internal"),
    ],
)
def test_each_class_has_its_documented_code_and_exit_code(
    cls: type[errors.GatectlError], code: str
) -> None:
    assert cls.code == code
    assert cls.exit_code == DOCUMENTED[code]
    assert cls.exit_code in DEFS["exit_code"]["enum"]


def test_the_base_class_is_an_internal_error() -> None:
    assert errors.GatectlError.code == "internal"
    assert errors.GatectlError.exit_code == 1


def test_a_refused_error_defaults_to_human_required() -> None:
    assert errors.RefusedError("needs a human").reason == "human_required"


def test_an_internal_error_accepts_only_the_documented_reasons() -> None:
    assert errors.InternalError("x", reason="schema_newer").reason == "schema_newer"
    assert errors.InternalError("x", reason="state_db_missing").reason == "state_db_missing"
    assert errors.InternalError("x").reason is None
    with pytest.raises(ValueError):
        errors.InternalError("x", reason="because")


def test_other_classes_take_no_reason() -> None:
    with pytest.raises(ValueError):
        errors.UsageError("x", reason="human_required")


def test_the_envelope_has_the_documented_shape_and_validates() -> None:
    envelope = errors.envelope(errors.UsageError("bad flag", details={"kind": "unknown_policy"}))
    assert envelope == {
        "error": {
            "code": "usage",
            "message": "bad flag",
            "reason": None,
            "details": {"kind": "unknown_policy"},
        }
    }
    schema_util.assert_valid("cli/error", envelope)


@pytest.mark.parametrize("cls", errors.ALL_ERRORS)
def test_every_class_yields_a_schema_valid_envelope(cls: type[errors.GatectlError]) -> None:
    schema_util.assert_valid("cli/error", errors.envelope(cls("message")))


def test_the_envelope_sanitizes_message_and_details() -> None:
    err = errors.UsageError("a\x1b[31mb‮c", details={"ids": ["x\x00y"], "n": 3})
    body = errors.envelope(err)["error"]
    assert body["message"] == f"a{MARKER}[31mb{MARKER}c"
    assert body["details"] == {"ids": [f"x{MARKER}y"], "n": 3}


def test_the_envelope_caps_the_message_at_the_schema_limit() -> None:
    body = errors.envelope(errors.UsageError("m" * 5000))["error"]
    assert len(body["message"]) == 2048
    schema_util.assert_valid("cli/error", {"error": body})


def test_an_unknown_exception_becomes_a_fixed_internal_envelope() -> None:
    body = errors.envelope(RuntimeError("secret /home/user/token"))["error"]
    assert body["code"] == "internal"
    assert "secret" not in json.dumps(body)
    assert errors.exit_code_of(RuntimeError("x")) == 1


def test_exit_code_of_a_gatectl_error_is_its_own() -> None:
    assert errors.exit_code_of(errors.AmbiguousError("x")) == 21
