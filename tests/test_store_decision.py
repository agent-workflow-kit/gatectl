"""``Store.insert_decision``: the decision row of a check, written inside one transaction."""

from __future__ import annotations

import dataclasses
import sqlite3
from pathlib import Path

import pytest

from gatectl import store
from gatectl.errors import InternalError

FP = "sha256:" + "a" * 64
ID = "gd-abcdefghijkl"


def row(**over: object) -> store.DecisionRow:
    fields: dict[str, object] = {
        "id": ID,
        "time": "2026-11-25T01:02:03.000004Z",
        "policy": "p",
        "scope": "github.com/org/repo",
        "fingerprint": FP,
        "state": "shadow",
        "decision": "allow",
        "reason": "all_passed",
        "tool": "t",
        "hook": None,
        "object_type": None,
        "object_id": "o",
        "repo": "github.com/org/repo",
        "input_sha256": "0" * 64,
        "case_key": "1" * 64,
        "state_rev": 7,
        "declared_json": '{"a":1}',
        "checks_json": "[]",
        "actor": "auto:unknown",
        "input_json": None,
    }
    fields.update(over)
    return store.DecisionRow(**fields)  # type: ignore[arg-type]


def test_a_decision_row_round_trips_every_column(tmp_path: Path) -> None:
    sdir = tmp_path / "gatectl"
    with store.open_store(sdir, create=True) as s:
        assert s is not None
        with s.write():
            s.insert_decision(row())
        cols = (
            "id, time, policy, scope, fingerprint, state, decision, reason, tool, hook,"
            " object_type, object_id, repo, input_sha256, case_key, state_rev, declared_json,"
            " checks_json, actor, input_json"
        )
        found = s.con.execute(f"SELECT {cols} FROM decisions").fetchall()  # noqa: S608
    assert found == [dataclasses.astuple(row())]


def test_the_same_id_twice_fails_with_fixed_text(tmp_path: Path) -> None:
    sdir = tmp_path / "gatectl"
    with store.open_store(sdir, create=True) as s:
        assert s is not None
        with s.write():
            s.insert_decision(row())
        with pytest.raises(InternalError) as info, s.write():
            s.insert_decision(row())
        assert ID not in str(info.value)


def test_a_bad_decision_value_is_refused_by_the_schema_not_stored(tmp_path: Path) -> None:
    sdir = tmp_path / "gatectl"
    with store.open_store(sdir, create=True) as s:
        assert s is not None
        with pytest.raises(InternalError), s.write():
            s.insert_decision(row(decision="maybe"))
        assert s.con.execute("SELECT count(*) FROM decisions").fetchone()[0] == 0


def test_insert_needs_a_write_transaction(tmp_path: Path) -> None:
    sdir = tmp_path / "gatectl"
    with store.open_store(sdir, create=True) as s:
        assert s is not None
        with pytest.raises(RuntimeError):
            s.insert_decision(row())
        assert isinstance(s.con, sqlite3.Connection)
