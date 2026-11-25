"""Helpers for the ``set`` tests: a config, stored rows, audit lines and fingerprints."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from gatectl import fingerprint, store
from gatectl.config import load_config
from gatectl.scope import Scope
from tests.command_util import agent, config_file, isolate, payload, rule, run, script

REPO = "github.com/org/repo"
OTHER = "github.com/org/other"
STALE = "sha256:" + "c" * 64
ALIEN = "sha256:" + "d" * 64
HUMAN = ["--actor", "human:ann"]

RULE_POLICY: dict[str, Any] = {"state": "off", "checks": [rule("r")]}
SCRIPT_POLICY: dict[str, Any] = {"checks": [script("s")]}
AGENT_ONLY: dict[str, Any] = {"checks": [agent("a")]}


def make_config(tmp_path: Path, policies: dict[str, Any] | None = None, **top: Any) -> str:
    body = policies if policies is not None else {"p": RULE_POLICY}
    return config_file(tmp_path, {"policies": body, **top})


def do_set(
    capsys: pytest.CaptureFixture[str], config: str, *args: str
) -> tuple[int, dict[str, Any], str]:
    """Run ``set`` and return (exit code, parsed stdout JSON or {}, stderr)."""
    code, out, err = run(capsys, ["set", *args, "--config", config, "--json"])
    return code, (payload(out) if out else {}), err


def audit_lines(state_dir: Path) -> list[dict[str, Any]]:
    path = state_dir / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


def log_lines(state_dir: Path) -> list[dict[str, Any]]:
    path = state_dir / "log.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()]


def row(state_dir: Path, policy: str, scope: str) -> store.StateRow | None:
    s = store.open_store(state_dir, create=False)
    if s is None:
        return None
    with s:
        return s.get_row(policy, scope)


def rows(state_dir: Path, policy: str) -> dict[str, store.StateRow]:
    s = store.open_store(state_dir, create=False)
    if s is None:
        return {}
    with s:
        return {r.scope: r for r in s.rows(policy)}


def seed(
    state_dir: Path,
    policy: str,
    scope: str,
    state: str,
    *,
    fingerprint_: str = STALE,
    set_by: str = "human:bob",
    cause: str = "set",
) -> store.StateRow:
    s = store.open_store(state_dir, create=True)
    assert s is not None
    with s:
        with s.write():
            return s.write_state_row(
                policy,
                scope,
                state,
                set_by=set_by,
                set_at="2026-01-01T00:00:00.000000Z",
                cause=cause,
                fingerprint=fingerprint_,
            )


def seed_decision(state_dir: Path, policy: str, scope: str) -> None:
    s = store.open_store(state_dir, create=True)
    assert s is not None
    with s:
        with s.write():
            s.con.execute(
                "INSERT INTO decisions(id, time, policy, scope, fingerprint, state, decision,"
                " reason, actor) VALUES(?, ?, ?, ?, ?, 'shadow', 'allow', 'all_passed', 'auto:t')",
                (
                    "gd-aaaaaaaaaaaa",
                    "2026-01-01T00:00:00.000000Z",
                    policy,
                    scope,
                    STALE,
                ),
            )


def set_meta(state_dir: Path, key: str, value: str) -> None:
    s = store.open_store(state_dir, create=True)
    assert s is not None
    with s:
        with s.write():
            s.con.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )


def current_fingerprint(config: str, policy: str, scope: str = "*") -> str:
    return fingerprint.fingerprint_for(load_config(config), policy, Scope(scope, False, ()))


def count_rows(state_dir: Path) -> int:
    con = sqlite3.connect(f"file:{state_dir / 'state.db'}?mode=ro", uri=True)
    try:
        return int(con.execute("SELECT COUNT(*) FROM policy_state").fetchone()[0])
    finally:
        con.close()


__all__ = [
    "AGENT_ONLY",
    "ALIEN",
    "HUMAN",
    "OTHER",
    "REPO",
    "RULE_POLICY",
    "SCRIPT_POLICY",
    "STALE",
    "agent",
    "audit_lines",
    "count_rows",
    "current_fingerprint",
    "do_set",
    "isolate",
    "log_lines",
    "make_config",
    "row",
    "rows",
    "rule",
    "seed",
    "seed_decision",
    "set_meta",
    "script",
]
