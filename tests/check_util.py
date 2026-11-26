"""Helpers for the ``check`` engine tests: run a check, read what it recorded."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from tests import schema_util
from tests.command_util import isolate, payload, run

REPO = "github.com/org/repo"
OTHER = "github.com/org/other"
HUMAN = ["--actor", "human:ann"]
__all__ = ["isolate"]


def write_input(tmp_path: Path, content: Any, name: str = "in.json") -> str:
    path = tmp_path / name
    path.write_bytes(content if isinstance(content, bytes) else json.dumps(content).encode())
    return str(path)


def do_check(
    capsys: pytest.CaptureFixture[str],
    config: str,
    policy: str = "p",
    *extra: str,
    validate: bool = True,
) -> tuple[int, dict[str, Any], str]:
    """Run ``check`` and return (exit code, parsed stdout, stderr). Stdout is one JSON line that
    validates against ``schemas/cli/check.json`` (a result) or ``cli/error.json``."""
    code, out, err = run(capsys, ["check", policy, "--config", config, *extra])
    doc = payload(out) if out else {}
    if validate and doc:
        schema_util.assert_valid(
            "cli/error" if "error" in doc and "policy" not in doc else "cli/check", doc
        )
    return code, doc, err


def do_set(
    capsys: pytest.CaptureFixture[str], config: str, policy: str, state: str, *args: str
) -> None:
    code, _, err = run(
        capsys, ["set", policy, state, "--config", config, "--actor", "human:ann", *args]
    )
    assert code == 0, err


def rows(state_dir: Path, sql: str, *args: Any) -> list[tuple[Any, ...]]:
    path = state_dir / "state.db"
    if not path.exists():
        return []
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


def decisions(state_dir: Path) -> list[dict[str, Any]]:
    cols = (
        "id time policy scope fingerprint state decision reason tool hook object_type object_id"
        " repo input_sha256 case_key state_rev declared_json checks_json actor input_json"
    ).split()
    found = rows(state_dir, f"SELECT {', '.join(cols)} FROM decisions ORDER BY time")  # noqa: S608
    return [dict(zip(cols, r, strict=True)) for r in found]


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
