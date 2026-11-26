"""Hostile stored rows and arguments for ``stats``: fixed text, exit 1, never a traceback."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from gatectl.cli import main
from tests import schema_util
from tests.command_util import CANARY, config_file, isolate, rule
from tests.history_util import check_entry, did, put_decision, put_outcome, sql, ts

EVIL = f"{CANARY}\x1b[31m\x00‮" + "x" * 300
ID = did(1)


@pytest.fixture(autouse=True)
def state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


@pytest.fixture
def config(tmp_path: Path) -> str:
    return config_file(tmp_path, {"policies": {"p": {"checks": [rule()]}}})


def run_json(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main([*argv, "--json"])
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _cases() -> list[tuple[str, dict[str, Any]]]:
    return [
        ("bad-policy", {"policy": EVIL}),
        ("huge-policy", {"policy": "a" * 100_000}),
        ("bad-scope", {"scope": EVIL}),
        ("blob-scope", {"scope": b"\x00\x01"}),
        ("null-byte-scope", {"scope": "*\x00x"}),
        ("bad-time", {"time": EVIL}),
        ("short-time", {"time": "2026-11-24T12:00:00Z"}),
        ("int-time", {"time": 5}),
        ("bad-decision", {"decision": "maybe"}),
        ("bad-fingerprint", {"fingerprint": EVIL}),
        ("short-fingerprint", {"fingerprint": "sha256:abc"}),
        ("int-fingerprint", {"fingerprint": 7}),
        ("bad-case-key", {"case_key": EVIL}),
        ("upper-case-key", {"case_key": "A" * 64}),
        ("int-case-key", {"case_key": 5}),
        ("checks-not-json", {"checks_json": EVIL}),
        ("checks-object", {"checks_json": "{}"}),
        ("checks-scalars", {"checks_json": "[1, 2]"}),
        ("checks-deep", {"checks_json": "[" * 400 + "]" * 400}),
        ("checks-huge", {"checks_json": json.dumps([{"detail": "x" * 100_000}])}),
        ("checks-too-many", {"checks_json": json.dumps([{"reason": None}] * 300)}),
        ("checks-blob", {"checks_json": b"[]"}),
        ("checks-bad-reason", {"checks_json": json.dumps([{"reason": EVIL}])}),
        ("checks-int-reason", {"checks_json": json.dumps([{"reason": 5}])}),
        ("checks-object-reason", {"checks_json": json.dumps([{"reason": {"a": 1}}])}),
        ("bad-own-reason", {"reason": "because"}),
    ]


@pytest.mark.parametrize(("label", "raw"), _cases(), ids=[c[0] for c in _cases()])
def test_a_tampered_decision_row_exits_1_with_fixed_text(
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
    label: str,
    raw: dict[str, Any],
) -> None:
    put_decision(state_dir, ID, raw=raw)
    for extra in ([], ["--since", "2000-01-01T00:00:00Z"]):
        code, out, err = run_json(capsys, "stats", "--config", config, *extra)
        if code == 0:
            # the row was excluded by --since (a non-text time sorts below any text)
            assert extra and label in {"int-time"}
            continue
        assert code == 1, label
        doc = json.loads(out)
        assert doc["error"]["code"] == "internal"
        assert doc["error"]["message"] == "state.db holds an invalid decision row"
        assert CANARY not in out + err and "\x1b" not in out + err and "Traceback" not in err
        schema_util.assert_valid("cli/error", doc)
        code, out, err = run_json(capsys, "stats", "--config", config)
    code = main(["stats", "--config", config])
    captured = capsys.readouterr()
    assert code == 1 and CANARY not in captured.out + captured.err


@pytest.mark.parametrize(
    "raw",
    [
        {"signal": EVIL},
        {"signal": "Bad Signal"},
        {"actor_kind": "root"},
        {"actor_kind": EVIL},
    ],
)
def test_a_tampered_outcome_row_exits_1(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, raw: dict[str, str]
) -> None:
    put_decision(state_dir, ID)
    put_outcome(state_dir, ID, "agree")
    ((column, value),) = raw.items()
    sql(state_dir, f"UPDATE outcomes SET {column} = ?", value)  # noqa: S608  (a fixed test column)
    code, out, err = run_json(capsys, "stats", "--config", config)
    assert code == 1 and CANARY not in out + err
    assert json.loads(out)["error"]["message"] == "state.db holds an invalid decision row"


def test_an_orphan_outcome_is_ignored(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    put_outcome(state_dir, did(99), "disagree")
    code, out, _ = run_json(capsys, "stats", "--config", config)
    assert code == 0 and json.loads(out)["records"][0]["signals"] == {}


def test_nulls_in_unused_optional_columns_are_fine(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(
        state_dir,
        ID,
        raw={"tool": None, "hook": None, "object_id": None, "checks_json": None, "case_key": None},
    )
    code, out, _ = run_json(capsys, "stats", "--config", config)
    doc = json.loads(out)
    assert code == 0 and doc["records"][0]["reason_counts"][0]["reason"] == "all_passed"


def test_many_outcomes_on_one_decision_count_as_records_but_one_effective_outcome(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID, checks=[check_entry()])
    for i in range(200):
        put_outcome(state_dir, ID, "agree" if i % 2 else "disagree", when=ts(i % 50))
    code, out, _ = run_json(capsys, "stats", "--config", config)
    r = json.loads(out)["records"][0]
    assert code == 0 and r["decisions"]["allow"] == 1 and r["signals"] == {"human": 200}
    assert r["outcomes"]["agree"] == 1 and r["unsafe_miss_cases"] == 0  # the last counting one


def test_one_resolved_case_has_the_bound_of_one_case(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID, raw={"case_key": "0" * 64})
    put_outcome(state_dir, ID, "agree")
    code, out, _ = run_json(capsys, "stats", "--config", config)
    assert code == 0 and json.loads(out)["records"][0]["upper_bound"] == pytest.approx(0.95)


def test_hostile_flags_are_bound_parameters_never_sql(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    for flag in (["--policy", "p' OR 1=1 --"], ["--repo", "x'; DROP TABLE decisions; --"]):
        code, out, _ = run_json(capsys, "stats", "--config", config, *flag)
        assert code == 2 and "DROP" not in out
    code, _, _ = run_json(capsys, "stats", "--config", config)
    assert code == 0  # the table is still there
