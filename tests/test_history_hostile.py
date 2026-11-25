"""Hostile stored rows and hostile arguments for ``decisions`` and ``show``.

Everything these commands print is untrusted stored text: it is sanitized and capped in JSON and
in text, a tampered row is refused with fixed text (exit 1, never the stored value), the reader
never writes, and no argument reaches SQL as anything but a bound parameter.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from gatectl.cli import main
from tests import schema_util
from tests.command_util import CANARY, config_file, isolate, rule
from tests.history_util import (
    check_entry,
    did,
    put_decision,
    put_outcome,
    sql,
    ts,
)

ID = did(1)
EVIL = f"{CANARY}\x1b[31m\x00\x07‮⁦x﻿ y"


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


def run_text(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def assert_inert(*streams: str) -> None:
    for text in streams:
        for ch in text:
            assert ch == "\n" or ch.isprintable(), repr(ch)


# --- hostile stored text is sanitized and capped --------------------------------------------


def test_hostile_text_columns_are_sanitized_in_json_and_text(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(
        state_dir,
        ID,
        tool=EVIL,
        hook=EVIL,
        object_type=EVIL,
        object_id=EVIL,
        declared={EVIL: EVIL, "nested": [EVIL, {"k": EVIL}]},
        checks=[check_entry(detail=EVIL)],
    )
    put_outcome(state_dir, ID, "agree", reason=EVIL)
    for argv in (("decisions",), ("show", ID)):
        code, out, err = run_json(capsys, *argv, "--config", config)
        assert code == 0 and err == ""
        doc = json.loads(out)
        assert out.isascii() and "\\u001b" not in out and "\\u202e" not in out
        assert "\\u0000" not in out and "\\ufeff" not in out and "\\u2028" not in out
        assert CANARY in out  # the text is kept, only its dangerous characters are replaced
        schema_util.assert_valid(f"cli/{argv[0]}", doc)
        code, out, err = run_text(capsys, *argv, "--config", config)
        assert code == 0
        assert_inert(out, err)


def test_huge_values_are_cut_to_their_caps(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    huge = "A" * 200_000
    big = "A" * 5000
    put_decision(
        state_dir,
        ID,
        tool=huge,
        object_id=huge,
        checks=[check_entry(detail=big)],
        declared={"k": big},
    )
    put_outcome(state_dir, ID, "agree", reason=huge)
    _, out, _ = run_json(capsys, "show", ID, "--config", config)
    doc = json.loads(out)
    assert len(doc["tool"]) == 256 and len(doc["object_id"]) == 256
    assert len(doc["checks"][0]["detail"]) == 1024
    assert len(doc["outcomes"][0]["reason"]) == 1024
    assert len(doc["declared"]["k"]) == 256
    assert len(out) < 20_000
    schema_util.assert_valid("cli/show", doc)


def test_an_unconfigured_policy_name_in_a_row_is_just_a_name(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID, policy="legacy-policy_1")
    code, out, _ = run_json(capsys, "decisions", "--config", config)
    assert code == 0 and json.loads(out)["decisions"][0]["configured"] is False


# --- tampered rows are refused with fixed text -------------------------------------------------


def _row_cases() -> list[tuple[str, dict[str, Any]]]:
    return [
        ("bad-state", {"state": "paused"}),
        ("canary-state", {"state": EVIL}),
        ("canary-policy", {"policy": EVIL}),
        ("huge-policy", {"policy": "a" * 100_000}),
        ("bad-scope", {"scope": EVIL}),
        ("canary-id", {"id": EVIL}),
        ("bad-time", {"time": EVIL}),
        ("short-time", {"time": "2026-11-24T12:00:00Z"}),
        ("bad-decision", {"decision": "maybe"}),
        ("bad-reason", {"reason": EVIL}),
        ("free-text-reason", {"reason": "because I said so"}),
        ("bad-fingerprint", {"fingerprint": EVIL}),
        ("marker-ok-but-short", {"fingerprint": "sha256:abc"}),
        ("bad-actor", {"actor": EVIL}),
        ("bad-repo", {"repo": EVIL}),
        ("blob-hook", {"hook": b"\x00\x01"}),
        ("no-hash", {"input_sha256": None}),
        ("bad-hash", {"input_sha256": EVIL}),
        ("bad-case-key", {"case_key": EVIL}),
        ("negative-rev", {"state_rev": -1}),
        ("declared-not-json", {"declared_json": EVIL}),
        ("declared-array", {"declared_json": "[1]"}),
        ("declared-nan", {"declared_json": '{"a": NaN}'}),
        ("declared-deep", {"declared_json": '{"a":' * 500 + "1" + "}" * 500}),
        ("declared-huge", {"declared_json": json.dumps({"a": "x" * 100_000})}),
        ("declared-int", {"declared_json": 5}),
    ]


@pytest.mark.parametrize(("label", "raw"), _row_cases(), ids=[c[0] for c in _row_cases()])
@pytest.mark.parametrize("command", ["decisions", "show"])
def test_a_tampered_decision_row_exits_1_with_fixed_text(
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
    command: str,
    label: str,
    raw: dict[str, Any],
) -> None:
    if "id" in raw:
        pytest.skip("an invalid id is not addressable by show; decisions covers it")
    put_decision(state_dir, ID, raw=raw)
    argv = ["decisions"] if command == "decisions" else ["show", ID]
    code, out, err = run_json(capsys, *argv, "--config", config)
    assert code == 1, label
    doc = json.loads(out)
    assert doc["error"]["code"] == "internal"
    assert CANARY not in out + err
    assert_inert(err)


def test_a_row_with_an_invalid_id_makes_the_list_refuse(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, EVIL)
    code, out, err = run_json(capsys, "decisions", "--config", config)
    assert code == 1 and CANARY not in out + err


@pytest.mark.parametrize(
    "checks",
    [
        "not json",
        "{}",
        '[{"name": "x"}]',
        json.dumps([check_entry(verdict="maybe")]),
        json.dumps([check_entry(name="Bad Name")]),
        json.dumps([check_entry(reason="free text")]),
        json.dumps([check_entry(verdict="deny", reason=None)]),
        json.dumps([check_entry(duration_ms=-1)]),
        json.dumps([check_entry(detail=5)]),
        json.dumps([check_entry(confidence=0.5)]),  # confidence belongs to agent checks only
        json.dumps([check_entry(type="agent", confidence=2, reused=False)]),
        json.dumps([check_entry(type="agent", confidence=0.5)]),  # reused missing
        json.dumps([check_entry()] * 1000),
        "[" * 1000,
        json.dumps([check_entry(detail="x" * 70_000)]),
    ],
)
def test_tampered_checks_json_is_refused_by_show(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, checks: str
) -> None:
    put_decision(state_dir, ID, raw={"checks_json": checks})
    code, out, err = run_json(capsys, "show", ID, "--config", config)
    assert code == 1 and json.loads(out)["error"]["code"] == "internal"
    assert CANARY not in out + err


def test_a_tampered_outcome_row_is_refused_by_show(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    put_outcome(state_dir, ID, "agree", actor=EVIL)
    code, out, err = run_json(capsys, "show", ID, "--config", config)
    assert code == 1 and CANARY not in out + err


def test_outcome_history_is_bounded(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    for _ in range(3):
        put_outcome(state_dir, ID, "agree")
    sql(
        state_dir,
        "INSERT INTO outcomes(decision_id, time, outcome, signal, actor, actor_kind)"
        " SELECT decision_id, time, outcome, signal, actor, actor_kind FROM outcomes,"
        " (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 1500)"
        " SELECT x FROM c)",
    )
    code, out, _ = run_json(capsys, "show", ID, "--config", config)
    assert code == 0 and len(json.loads(out)["outcomes"]) == 1000


def test_a_database_that_is_not_a_database_exits_1_with_fixed_text(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    state_dir.mkdir(parents=True)
    (state_dir / "state.db").write_bytes(EVIL.encode() * 50)
    for argv in (("decisions",), ("show", ID)):
        code, out, err = run_json(capsys, *argv, "--config", config)
        assert code == 1 and CANARY not in out + err


# --- the reader never writes -----------------------------------------------------------------


def snapshot(state_dir: Path) -> dict[str, str]:
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(state_dir.iterdir())
        if p.is_file() and p.name != "state.db-shm" and p.stat().st_size > 0
    }


def test_decisions_and_show_never_write_anything(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    put_outcome(state_dir, ID, "agree")
    before = snapshot(state_dir)
    for argv in (
        ("decisions",),
        ("decisions", "--outcome", "agree", "--policy", "p"),
        ("show", ID),
        ("show", "gd-zzzzzz"),
    ):
        run_json(capsys, *argv, "--config", config)
    assert snapshot(state_dir) == before
    con = sqlite3.connect(state_dir / "state.db")
    try:
        assert con.execute("SELECT COUNT(*) FROM decisions").fetchone() == (1,)
        assert con.execute("SELECT COUNT(*) FROM policy_state").fetchone() == (0,)
    finally:
        con.close()


def test_a_missing_state_dir_stays_missing(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    for argv in (("decisions",), ("show", ID), ("export",), ("export", "--log")):
        run_json(capsys, *argv, "--config", config)
    assert not state_dir.exists()


# --- hostile arguments are bound parameters ----------------------------------------------------

INJECTIONS = [
    "x' OR '1'='1",
    "'; DROP TABLE decisions; --",
    '" OR 1=1 --',
    "%",
    "_",
    "\\",
    "x\\' OR 1=1 --",
    "$.a') OR 1=1 --",
    "a%b_c",
]


@pytest.mark.parametrize("hostile", INJECTIONS)
def test_free_text_filters_match_literally_and_never_inject(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, hostile: str
) -> None:
    put_decision(state_dir, did(1), when=ts(1), object_id="42", declared={"k": "v"})
    put_decision(state_dir, did(2), when=ts(2), object_id=hostile, declared={"k": hostile})
    code, out, _ = run_json(capsys, "decisions", "--config", config, "--object-id", hostile)
    assert code == 0
    assert [d["decision_id"] for d in json.loads(out)["decisions"]] == [did(2)]
    code, out, _ = run_json(capsys, "decisions", "--config", config, "--declared", f"k={hostile}")
    assert code == 0
    assert [d["decision_id"] for d in json.loads(out)["decisions"]] == [did(2)]
    code, out, _ = run_json(capsys, "decisions", "--config", config, "--declared", f"{hostile}=v")
    assert code == 0 and json.loads(out)["decisions"] == []
    con = sqlite3.connect(state_dir / "state.db")
    try:
        assert con.execute("SELECT COUNT(*) FROM decisions").fetchone() == (2,)
    finally:
        con.close()


@pytest.mark.parametrize("hostile", INJECTIONS)
@pytest.mark.parametrize("flag", ["--policy", "--repo", "--since", "--limit", "--decision"])
def test_structured_filters_reject_hostile_values_with_exit_2(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, hostile: str, flag: str
) -> None:
    put_decision(state_dir, did(1))
    code, out, err = run_json(capsys, "decisions", "--config", config, flag, hostile)
    assert code == 2, (flag, hostile)
    assert hostile not in out + err


@pytest.mark.parametrize("hostile", INJECTIONS)
def test_hostile_decision_id_prefixes_are_usage_errors(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, hostile: str
) -> None:
    put_decision(state_dir, did(1))
    code, out, err = run_json(capsys, "show", f"gd-{hostile}abcdef", "--config", config)
    assert code == 2 and hostile not in out + err
    sql(state_dir, "SELECT 1")


# --- a NUL does not hide from the caps or the grammar (round 1) --------------------------------

NUL_TAIL = "\x00junk"


@pytest.mark.parametrize(
    "column",
    [
        "time",
        "policy",
        "scope",
        "state",
        "decision",
        "reason",
        "fingerprint",
        "actor",
        "input_sha256",
        "case_key",
    ],
)
def test_a_nul_after_a_valid_closed_value_is_refused_not_cut(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, column: str
) -> None:
    """SQLite's substr() would hand back ``p`` for ``p<NUL>junk``; the NUL must not vanish."""
    from tests.history_util import FP, HASH, T0

    valid = {
        "time": T0,
        "policy": "p",
        "scope": "*",
        "state": "shadow",
        "decision": "allow",
        "reason": "all_passed",
        "fingerprint": FP,
        "actor": "auto:unknown",
        "input_sha256": HASH,
        "case_key": HASH,
    }[column]
    put_decision(state_dir, ID, raw={column: valid + NUL_TAIL})
    for argv in (("decisions",), ("show", ID)):
        code, out, err = run_json(capsys, *argv, "--config", config)
        assert code == 1, (column, argv)
        assert json.loads(out)["error"]["message"] == "state.db holds an invalid decision row"
        assert "junk" not in out + err


def test_a_nul_after_a_valid_id_is_refused_in_the_list_and_ignored_by_resolve(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID + NUL_TAIL)
    code, out, _ = run_json(capsys, "decisions", "--config", config)
    assert code == 1 and "junk" not in out
    code, out, _ = run_json(capsys, "show", ID, "--config", config)
    assert code == 10


@pytest.mark.parametrize("column", ["tool", "hook", "object_type", "object_id"])
def test_a_nul_in_free_text_becomes_the_marker_and_keeps_the_rest(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, column: str
) -> None:
    put_decision(state_dir, ID, raw={column: "ab\x00cd"})
    _, out, _ = run_json(capsys, "show", ID, "--config", config)
    assert json.loads(out)[column] == "ab�cd"


@pytest.mark.parametrize("column", ["declared_json", "checks_json"])
def test_a_nul_does_not_bypass_the_read_caps(state_dir: Path, column: str) -> None:
    """``length(text)`` stops at the NUL: a 5 MB value would pass a character-count cap."""
    from gatectl import history, store

    put_decision(state_dir, ID)
    sql(state_dir, f"UPDATE decisions SET {column} = ?", "{}\x00" + "x" * 5_000_000)  # noqa: S608
    cap = history.DECLARED_MAX_BYTES if column == "declared_json" else history.CHECKS_MAX_BYTES
    s = store.open_store(state_dir, create=False)
    assert s is not None
    with s:
        ((value,),) = s.query(
            f"SELECT {history._bounded(f'd.{column}', cap)} FROM decisions d"  # noqa: S608, SLF001
        )
    assert value == b""


@pytest.mark.parametrize("column", ["declared_json", "checks_json"])
def test_a_nul_in_stored_json_is_a_tamper(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, column: str
) -> None:
    good = "{}" if column == "declared_json" else "[]"
    put_decision(state_dir, ID, raw={column: good + NUL_TAIL})
    code, _, _ = run_json(capsys, "show", ID, "--config", config)
    assert code == 1


def test_a_nul_in_an_outcome_actor_never_counts_as_a_human_agree(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    put_outcome(state_dir, ID, "agree", actor="human:ann" + NUL_TAIL)
    code, out, _ = run_json(capsys, "decisions", "--config", config, "--outcome", "agree")
    assert code == 0 and json.loads(out)["decisions"] == []
