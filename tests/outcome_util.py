"""Helpers for the ``outcome`` tests: a config, seeded decisions and the stored outcome rows."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tests.command_util import config_file, rule
from tests.history_util import call, put_decision

ID = "gd-4k2m7q5x3a2b"
REPO = "github.com/org/repo"
OTHER = "github.com/org/other"
HUMAN = ["--actor", "human:ann"]
AUTO = ["--actor", "auto:bot"]


def make_config(tmp_path: Path, policies: dict[str, Any] | None = None, **top: Any) -> str:
    body = policies if policies is not None else {"p": {"checks": [rule()]}}
    return config_file(tmp_path, {"policies": body, **top})


def outcome(
    capsys: pytest.CaptureFixture[str], config: str, ref: str, verdict: str, *extra: str
) -> tuple[int, dict[str, Any], str]:
    return call(capsys, "outcome", ref, verdict, "--config", config, *extra)


def stored(state_dir: Path, decision_id: str | None = None) -> list[dict[str, Any]]:
    """The outcome rows in sequence order."""
    con = sqlite3.connect(f"file:{state_dir / 'state.db'}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        sql = "SELECT * FROM outcomes"
        args: tuple[str, ...] = ()
        if decision_id is not None:
            sql += " WHERE decision_id = ?"
            args = (decision_id,)
        return [dict(r) for r in con.execute(sql + " ORDER BY seq", args)]
    finally:
        con.close()


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


__all__ = [
    "AUTO",
    "HUMAN",
    "ID",
    "OTHER",
    "REPO",
    "audit_lines",
    "log_lines",
    "make_config",
    "outcome",
    "put_decision",
    "stored",
]
