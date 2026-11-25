from __future__ import annotations

import json
from pathlib import Path

import pytest

from gatectl import commands
from gatectl.cli import main
from gatectl.commands import Context, Result
from tests import golden
from tests.command_util import isolate
from tests.test_cli import MIN_ARGV

SCHEMAS = Path(__file__).resolve().parent.parent / "schemas"

# golden stem -> the command whose stdout it is. The handlers are stubs until each command lands:
# the owner issue replaces the stub with the real command output (see the todo on each entry).
COMMAND_OF = {
    # todo(#18): replace the stub with the real check output
    "check-shadow-allow": "check",
    "check-enforced-deny": "check",
    "check-not-applicable": "check",
    "check-off": "check",
    "check-shadow-error": "check",
    # check-dry-run is real (#11): see tests/test_dry_run.py::test_the_plan_is_golden
    # todo(#28): replace the stub with the real outcome output
    "outcome": "outcome",
    # decisions and show are real (#15): see tests/test_decisions.py and tests/test_show.py
    # todo(#29): replace the stub with the real stats output
    "stats": "stats",
    # set is real (#14): see tests/test_set.py::test_set_shadow_prints_the_golden_output
    # policies-static is real (#11): see tests/test_policies.py::test_the_output_is_golden.
    # policies (stored view) is real (#15): see tests/test_policies_stored.py; its records are
    # todo(#29) until stats lands
    # validate is real (#10): see test_validate_prints_its_golden_files_byte_for_byte
    # todo(#32): replace the stub with the real reconcile output
    "reconcile": "reconcile",
    # todo(#33): replace the stub with the real prune output
    "prune": "prune",
    # todo(#34): replace the stub with the real cron output
    "cron": "cron",
}


def test_every_cli_schema_has_a_golden_sample() -> None:
    documented = {f"cli/{p.stem}" for p in (SCHEMAS / "cli").glob("*.json")}
    assert documented <= set(golden.SHAPES.values())


def test_every_golden_file_is_listed_and_every_listing_exists() -> None:
    on_disk = {p.stem for p in golden.GOLDEN_DIR.glob("*.json")}
    assert on_disk == set(golden.SHAPES)


@pytest.mark.parametrize("name", sorted(golden.SHAPES))
def test_each_golden_file_is_canonical_and_matches_its_schema(name: str) -> None:
    golden.load(name)


@pytest.mark.parametrize("name", sorted(COMMAND_OF))
def test_each_golden_document_survives_the_printer_unchanged(
    name: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A stub handler returns the parsed golden document; the CLI must print the same bytes.

    This checks ``render_json`` (canonical form) and the dispatch path, and the golden file's
    schema through ``golden.load``. It cannot catch a wrong command output: the stub supplies the
    content. Each real command replaces its stub (the todo on its ``COMMAND_OF`` entry).
    """
    _, document = golden.load(name)
    command = COMMAND_OF[name]

    def handler(ctx: Context) -> Result:
        return Result(payload=document)

    monkeypatch.setattr(commands, "HANDLERS", {command: handler})
    assert main([*MIN_ARGV[command], "--json"]) == 0
    golden.assert_output(name, capsys.readouterr().out)


def _validate_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], review: dict[str, object]
) -> tuple[int, str]:
    session = tmp_path / "claude-session"
    session.write_text("#!/bin/sh\n")
    session.chmod(0o755)
    config = tmp_path / "config.yaml"
    config.write_text(json.dumps({"session_cmd": [str(session)], "policies": {"review": review}}))
    code = main(["validate", "--json", "--config", str(config)])
    return code, capsys.readouterr().out


def test_validate_prints_its_golden_files_byte_for_byte(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    agent = {"name": "judge", "type": "agent", "instruction": "Be careful."}
    code, out = _validate_output(tmp_path, capsys, {"checks": [agent]})
    assert code == 0
    golden.assert_output("validate", out)
    code, out = _validate_output(tmp_path, capsys, {"timeout": "0s", "checks": [agent]})
    assert code == 2
    golden.assert_output("validate-invalid", out)


def test_the_error_envelope_prints_its_golden_file_byte_for_byte(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["stats", "--json", "--decision-id", "bad id"]) == 2
    golden.assert_output("error-usage", capsys.readouterr().out)


def test_the_refused_envelope_prints_its_golden_file_byte_for_byte(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    isolate(monkeypatch, tmp_path)
    assert (
        main(["set", "pol", "enforced", "--actor", "auto:t", "--json"]) == 20
    )  # the real set, no human
    golden.assert_output("error-refused", capsys.readouterr().out)


# --- the harness itself can fail ----------------------------------------------------------


def _write(directory: Path, name: str, text: str) -> None:
    (directory / f"{name}.json").write_text(text, encoding="utf-8")


def test_the_harness_rejects_a_file_that_breaks_its_schema(tmp_path: Path) -> None:
    _, document = golden.load("set")
    document["state"] = "paused"
    _write(tmp_path, "set", json.dumps(document, separators=(",", ":")) + "\n")
    with pytest.raises(AssertionError):
        golden.load("set", directory=tmp_path)


def test_the_harness_rejects_a_file_with_an_extra_key(tmp_path: Path) -> None:
    _, document = golden.load("set")
    document["extra"] = 1
    _write(tmp_path, "set", json.dumps(document, separators=(",", ":")) + "\n")
    with pytest.raises(AssertionError):
        golden.load("set", directory=tmp_path)


def test_the_harness_rejects_a_non_canonical_file(tmp_path: Path) -> None:
    raw, _ = golden.load("set")
    _write(tmp_path, "set", raw.decode().replace(",", ", "))
    with pytest.raises(AssertionError):
        golden.load("set", directory=tmp_path)
    _write(tmp_path, "set", raw.decode().rstrip("\n"))
    with pytest.raises(AssertionError):
        golden.load("set", directory=tmp_path)


def test_the_harness_detects_a_one_byte_output_difference() -> None:
    raw, _ = golden.load("set")
    golden.assert_output("set", raw.decode())
    with pytest.raises(AssertionError):
        golden.assert_output("set", raw.decode().replace("shadow", "shadoW", 1))
    with pytest.raises(AssertionError):
        golden.assert_output("set", raw.decode() + "\n")


def test_a_schema_valid_output_that_differs_from_the_golden_file_fails() -> None:
    # Same shape, one valid value changed: schema validation alone would not notice.
    raw, _ = golden.load("set")
    with pytest.raises(AssertionError):
        golden.assert_output("set", raw.decode().replace('"changed":true', '"changed":false'))
