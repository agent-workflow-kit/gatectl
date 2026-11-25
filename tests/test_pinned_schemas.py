"""The pinned claude-session schemas: version header, ability to fail, never used by ``src/``."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from tests import pinned_schemas as pinned

SRC = Path(__file__).resolve().parent.parent / "src"


@pytest.mark.parametrize("name", pinned.NAMES)
def test_every_pinned_file_records_the_pinned_version_in_its_header(name: str) -> None:
    document = json.loads((pinned.PINNED_DIR / f"{name}.json").read_text(encoding="utf-8"))
    assert next(iter(document)) == "$comment"  # the header comes first
    assert f"v{pinned.PINNED_VERSION}" in document["$comment"]
    assert pinned.PINNED_COMMIT in document["$comment"]
    assert f"schemas/cli/{name}.json" in document["$comment"]


def test_the_directory_name_carries_the_version() -> None:
    assert pinned.PINNED_DIR.name == f"claude-session-{pinned.PINNED_VERSION}"
    assert {p.stem for p in pinned.PINNED_DIR.glob("*.json")} == set(pinned.NAMES)


def test_the_task_schemas_are_present() -> None:
    assert {"outcome", "status", "start"} <= set(pinned.NAMES)


@pytest.mark.parametrize("name", pinned.NAMES)
def test_every_pinned_schema_is_itself_valid(name: str) -> None:
    pinned.validator(name).check_schema(pinned.validator(name).schema)


def test_the_validator_can_fail_on_a_bad_start_object() -> None:
    good = pinned.sample("start")
    assert pinned.errors("start", good) == []
    assert pinned.errors("start", {**good, "run": 0})
    assert pinned.errors("start", {k: v for k, v in good.items() if k != "argv"})
    assert pinned.errors("start", {**good, "extra": 1})


def test_the_validator_follows_cross_file_references() -> None:
    # exec.json is only a $ref to outcome.json: an outcome with an unknown end reason must fail.
    sample = pinned.sample("outcome_unreported")
    assert pinned.errors("exec", sample) == []
    assert pinned.errors("exec", {**sample, "end_reason": "made_up"})
    # outcome_rules: exit code 14 belongs to exited-unreported only.
    assert pinned.errors("exec", {**sample, "exit_code": 0})


@pytest.mark.parametrize(
    ("name", "sample"),
    [
        ("start", "start"),
        ("status", "status_pending"),
        ("status", "status_final"),
        ("list", "list"),
        ("stop", "stop_cancel"),
        ("stop", "stop_final"),
        ("forget", "forget_ok"),
        ("error", "launch_failed"),
        ("exec", "outcome_unreported"),
    ],
)
def test_recorded_real_output_validates_against_the_pinned_schema(name: str, sample: str) -> None:
    assert pinned.errors(name, pinned.sample(sample)) == []


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            found.append(node.module or "")
    return found


def test_nothing_in_src_imports_or_names_the_pinned_schemas_or_the_fake() -> None:
    files = sorted(SRC.rglob("*.py"))
    assert files, "no source files found: the test would be vacuous"
    for path in files:
        text = path.read_text(encoding="utf-8")
        for name in ("pinned_schemas", "fake_session", "fakebin", "claude-session-0."):
            assert name not in text, f"{path} mentions {name}"
        for module in _imports(path):
            assert module.split(".")[0] not in ("tests", "claude_session", "jsonschema"), (
                f"{path} imports {module}"
            )


def test_the_src_scan_can_fail(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text("from tests import pinned_schemas\nimport claude_session\n", encoding="utf-8")
    assert _imports(bad) == ["tests", "claude_session"]
