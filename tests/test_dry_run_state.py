"""``check --dry-run`` reads the stored state read-only; ``off`` still skips every check."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from gatectl import store
from tests.command_util import CANARY, isolate, payload, rule, run
from tests.test_dry_run import MIXED, cfg, input_file, would_run

REPO = "github.com/org/repo"
FP = "sha256:" + "b" * 64


@pytest.fixture(autouse=True)
def state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def seed(state_dir: Path, rows: list[tuple[str, str, str]]) -> None:
    s = store.open_store(state_dir, create=True)
    assert s is not None
    for policy, scope, state in rows:
        with s.write():
            s.write_state_row(
                policy,
                scope,
                state,
                set_by="human:a",
                set_at="2026-01-01T00:00:00Z",
                cause="set",
                fingerprint=FP,
            )
    s.close()


def dry(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, content: Any, *extra: str
) -> tuple[int, dict[str, Any], str]:
    config = cfg(tmp_path, {"p": {"state": "shadow", **MIXED}})
    args = ["check", "p", "--dry-run", "--config", config, "--input", input_file(tmp_path, content)]
    code, out, err = run(capsys, [*args, *extra])
    return code, (payload(out) if out else {}), err


def test_the_star_row_overrides_the_initial_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    seed(state_dir, [("p", "*", "enforced")])
    code, doc, _ = dry(capsys, tmp_path, {})
    assert code == 0 and doc["state"] == "enforced"
    assert doc["scope"] == "*"


def test_a_repo_row_beats_the_star_row_and_other_repos_inherit_star(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    seed(state_dir, [("p", "*", "enforced"), ("p", REPO, "shadow")])
    _, doc, _ = dry(capsys, tmp_path, {}, "--repo", REPO)
    assert doc["state"] == "shadow"
    _, doc, _ = dry(capsys, tmp_path, {}, "--repo", "github.com/org/other")
    assert doc["state"] == "enforced"


def test_an_off_row_skips_every_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    seed(state_dir, [("p", "*", "off")])
    code, doc, _ = dry(capsys, tmp_path, b"not json")
    assert code == 0 and doc["state"] == "off"
    assert would_run(doc) == [False, False, False]
    assert doc["input_valid"] is True


def test_an_indeterminate_scope_takes_the_strictest_stored_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    seed(state_dir, [("p", "*", "off"), ("p", REPO, "enforced")])
    code, doc, _ = dry(capsys, tmp_path, {"repo": 5})
    assert code == 0 and doc["state"] == "enforced"
    assert doc["input_valid"] is False


def test_rows_of_another_policy_are_ignored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    seed(state_dir, [("other", "*", "off")])
    _, doc, _ = dry(capsys, tmp_path, {})
    assert doc["state"] == "shadow"


def test_a_missing_database_without_history_is_the_initial_state_and_stays_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    _, doc, _ = dry(capsys, tmp_path, {})
    assert doc["state"] == "shadow"
    assert not state_dir.exists()


def error_of(out: str) -> dict[str, Any]:
    return json.loads(out)["error"]


def test_a_missing_database_over_an_audit_history_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    state_dir.mkdir(parents=True, mode=0o700)
    (state_dir / "audit.jsonl").write_bytes(b'{"x":1}\n')
    config = cfg(tmp_path, {"p": MIXED})
    code, out, _ = run(
        capsys,
        ["check", "p", "--dry-run", "--config", config, "--input", input_file(tmp_path, {})],
    )
    assert code == 1
    assert error_of(out)["reason"] == "state_db_missing"
    assert not (state_dir / "state.db").exists()


def test_a_newer_schema_exits_1_and_the_file_is_untouched(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    state_dir.mkdir(parents=True, mode=0o700)
    con = sqlite3.connect(state_dir / "state.db")
    con.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")
    con.execute("INSERT INTO meta VALUES('schema_version', '999')")
    con.commit()
    con.close()
    (state_dir / "state.db").chmod(0o600)
    before = (state_dir / "state.db").read_bytes()
    code, out, _ = run(
        capsys,
        [
            "check",
            "p",
            "--dry-run",
            "--config",
            cfg(tmp_path, {"p": MIXED}),
            "--input",
            input_file(tmp_path, {}),
        ],
    )
    assert code == 1 and error_of(out)["reason"] == "schema_newer"
    assert (state_dir / "state.db").read_bytes() == before


def test_a_tampered_database_never_echoes_its_text(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    state_dir.mkdir(parents=True, mode=0o700)
    (state_dir / "state.db").write_bytes((CANARY * 200).encode())
    (state_dir / "state.db").chmod(0o600)
    code, out, err = run(
        capsys,
        [
            "check",
            "p",
            "--dry-run",
            "--config",
            cfg(tmp_path, {"p": MIXED}),
            "--input",
            input_file(tmp_path, {}),
        ],
    )
    assert code == 1
    assert CANARY not in out and CANARY not in err
    _ = rule  # imported for parity with the other dry-run tests
