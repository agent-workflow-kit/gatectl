"""Helpers for the read-only history tests: seed decisions, outcomes and cache rows in a store."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from gatectl import store
from tests.command_util import payload, run

FP = "sha256:" + "ab" * 32
HASH = "0" * 64
REPO = "github.com/org/repo"
OTHER = "github.com/org/other"
T0 = "2026-11-24T12:00:00.000000Z"


def ts(n: int) -> str:
    """The n-th second of 2026-11-24 12:00 UTC, in the fixed timestamp form."""
    minutes, seconds = divmod(n, 60)
    return f"2026-11-24T12:{minutes:02d}:{seconds:02d}.000000Z"


def did(n: int) -> str:
    """A valid decision id (12 base32 characters) that differs from the others in its start."""
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    return "gd-" + alphabet[(n // 32) % 32] + alphabet[n % 32] + "kkkkkkkkkk"


def check_entry(name: str = "ci-green", **extra: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "name": name,
        "type": "rule",
        "verdict": "allow",
        "reason": None,
        "detail": None,
        "duration_ms": 1,
    }
    entry.update(extra)
    return entry


def put_decision(
    state_dir: Path,
    decision_id: str,
    *,
    when: str = T0,
    policy: str = "p",
    scope: str = "*",
    repo: str | None = None,
    state: str = "shadow",
    decision: str = "allow",
    reason: str = "all_passed",
    fingerprint: str = FP,
    actor: str = "auto:unknown",
    tool: str | None = None,
    hook: str | None = "pre-merge",
    object_type: str | None = "pr",
    object_id: str | None = "42",
    input_sha256: str | None = HASH,
    case_key: str | None = HASH,
    state_rev: int | None = None,
    declared: Any = None,
    checks: Any = None,
    raw: Mapping[str, Any] | None = None,
) -> None:
    """Insert one decision row. ``raw`` overrides any column with the exact stored value."""
    values: dict[str, Any] = {
        "id": decision_id,
        "time": when,
        "policy": policy,
        "scope": scope,
        "fingerprint": fingerprint,
        "state": state,
        "decision": decision,
        "reason": reason,
        "tool": tool,
        "hook": hook,
        "object_type": object_type,
        "object_id": object_id,
        "repo": repo,
        "input_sha256": input_sha256,
        "case_key": case_key,
        "state_rev": state_rev,
        "declared_json": json.dumps(declared if declared is not None else {}),
        "checks_json": json.dumps(checks if checks is not None else [check_entry()]),
        "actor": actor,
        "input_json": None,
    }
    values.update(raw or {})
    s = store.open_store(state_dir, create=True)
    assert s is not None
    with s:
        with s.write():
            # a tampered row may break a CHECK constraint: the test inserts it anyway
            s.con.execute("PRAGMA ignore_check_constraints = ON")
            columns = ", ".join(values)
            marks = ", ".join("?" for _ in values)
            s.con.execute(
                f"INSERT INTO decisions({columns}) VALUES({marks})",  # noqa: S608
                list(values.values()),
            )


def put_outcome(
    state_dir: Path,
    decision_id: str,
    outcome: str,
    *,
    actor: str = "human:ann",
    signal: str = "human",
    kind: str = "human",
    reason: str | None = None,
    when: str = T0,
) -> None:
    s = store.open_store(state_dir, create=True)
    assert s is not None
    with s:
        with s.write():
            s.con.execute(
                "INSERT INTO outcomes(decision_id, time, outcome, signal, actor, actor_kind,"
                " reason) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (decision_id, when, outcome, signal, actor, kind, reason),
            )


def put_cache(
    state_dir: Path,
    key: str,
    decision_id: str | None,
    *,
    when: str = T0,
    expires_at: str = "2099-01-01T00:00:00.000000Z",
) -> None:
    s = store.open_store(state_dir, create=True)
    assert s is not None
    with s:
        with s.write():
            s.con.execute(
                "INSERT INTO agent_cache(key, time, expires_at, artifact_json, decision_id)"
                " VALUES(?, ?, ?, '{}', ?)",
                (key, when, expires_at, decision_id),
            )


def sql(state_dir: Path, statement: str, *args: Any) -> None:
    """Run a raw statement (a tamper): the one place a test writes outside the store API."""
    con = sqlite3.connect(state_dir / "state.db")
    try:
        con.execute(statement, args)
        con.commit()
    finally:
        con.close()


def call(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict[str, Any], str]:
    """Run a command with ``--json``: (exit code, parsed stdout or {}, stderr)."""
    code, out, err = run(capsys, [*argv, "--json"])
    return code, (payload(out) if out else {}), err


__all__ = [
    "FP",
    "HASH",
    "OTHER",
    "REPO",
    "T0",
    "call",
    "check_entry",
    "did",
    "put_cache",
    "put_decision",
    "put_outcome",
    "sql",
    "ts",
]
