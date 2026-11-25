"""``validate`` judges ``state_db_missing`` exactly as the state store does (issue #59).

The store (``open_store(create=False)``) is the reference: for every audit-history state against
every database state, ``validate`` reports a ``state_db_missing`` problem exactly when the store
refuses, except ``schema_newer`` (a different refusal that ``validate`` leaves to ``check``).
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from gatectl import store
from gatectl.cli import main
from gatectl.errors import InternalError
from tests import schema_util
from tests.config_util import write
from tests.test_validate import make_executable

CANARY = "CANARY-59b1d4"


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("GATECTL_"):
            monkeypatch.delenv(name)


def _state() -> Path:
    return Path(os.environ["XDG_STATE_HOME"]) / "gatectl"


def _fresh_state() -> Path:
    state = _state()
    state.parent.mkdir(parents=True, exist_ok=True)
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    return state


# --- database kinds ---------------------------------------------------------------------------


def _db_absent(state: Path) -> None:
    pass


def _db_empty(state: Path) -> None:
    (state / "state.db").write_bytes(b"")


def _db_junk(state: Path) -> None:
    (state / "state.db").write_bytes((CANARY + "\n").encode() * 100)


def _db_foreign(state: Path) -> None:
    con = sqlite3.connect(state / "state.db")
    con.execute("CREATE TABLE other (x TEXT)")
    con.execute("INSERT INTO other VALUES (?)", (CANARY,))
    con.commit()
    con.close()


def _db_valid(state: Path) -> None:
    opened = store.open_store(state, create=True)
    assert opened is not None
    opened.close()


def _db_schema_newer(state: Path) -> None:
    _db_valid(state)
    con = sqlite3.connect(state / "state.db")
    con.execute("UPDATE meta SET value = '999999' WHERE key = 'schema_version'")
    con.commit()
    con.close()


DBS: dict[str, Callable[[Path], None]] = {
    "absent": _db_absent,
    "empty": _db_empty,
    "junk": _db_junk,
    "foreign": _db_foreign,
    "schema_newer": _db_schema_newer,
    "valid": _db_valid,
}


# --- audit kinds ------------------------------------------------------------------------------


def _audit_absent(state: Path) -> None:
    pass


def _audit_empty(state: Path) -> None:
    (state / "audit.jsonl").write_bytes(b"")


def _audit_regular(state: Path) -> None:
    (state / "audit.jsonl").write_text('{"x":1}\n')


def _audit_fifo(state: Path) -> None:
    os.mkfifo(state / "audit.jsonl")


def _audit_directory(state: Path) -> None:
    (state / "audit.jsonl").mkdir()


def _audit_symlink(state: Path) -> None:
    (state / "target").write_bytes(b"")
    (state / "audit.jsonl").symlink_to(state / "target")


def _audit_unreadable(state: Path) -> None:
    (state / "audit.jsonl").write_bytes(b"")  # lstat is made to fail in the test


AUDITS: dict[str, Callable[[Path], None]] = {
    "absent": _audit_absent,
    "empty": _audit_empty,
    "regular": _audit_regular,
    "fifo": _audit_fifo,
    "directory": _audit_directory,
    "symlink": _audit_symlink,
    "unreadable": _audit_unreadable,
}


def _store_refuses(state: Path) -> str | None:
    """The store's verdict: None (it opens, or finds nothing), else the refusal's reason."""
    try:
        opened = store.open_store(state, create=False)
    except InternalError as exc:
        return exc.reason or "internal"
    if opened is not None:
        opened.close()
    return None


def _run_validate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, Any]]:
    session = make_executable(tmp_path / "bin" / "claude-session")
    path = write(tmp_path / "cfg" / "config.yaml", {"session_cmd": [session]})
    code = main(["validate", "--json", "--config", str(path)])
    out = capsys.readouterr().out
    assert CANARY not in out
    payload = json.loads(out)
    schema_util.assert_valid("cli/validate", payload)
    return code, payload


def _codes(payload: dict[str, Any]) -> set[str]:
    return {p["code"] for p in payload["problems"]}


@pytest.mark.parametrize("db", list(DBS))
@pytest.mark.parametrize("audit", list(AUDITS))
def test_validate_agrees_with_the_store_on_state_db_missing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    audit: str,
    db: str,
) -> None:
    state = _fresh_state()
    DBS[db](state)  # the database first: the store would refuse to create one over a history
    AUDITS[audit](state)
    if audit == "unreadable":
        real_lstat = os.lstat

        def lstat(path: Any, *args: Any, **kwargs: Any) -> os.stat_result:
            if str(path) == str(state / "audit.jsonl"):
                raise PermissionError(13, "denied")
            return real_lstat(path, *args, **kwargs)

        monkeypatch.setattr(os, "lstat", lstat)
    verdict = _store_refuses(state)
    # The store itself is the reference, but pin its verdict on the corners the issue names.
    history = audit not in ("absent", "empty")
    if db == "schema_newer":
        assert verdict == "schema_newer"
    elif db == "valid":
        assert verdict is None
    elif db in ("absent", "empty"):
        assert verdict == ("state_db_missing" if history else None)
    else:  # junk and foreign: refused with or without a history
        assert verdict == ("state_db_missing" if history else "internal")

    code, payload = _run_validate(tmp_path, capsys)

    expected = verdict is not None and verdict != "schema_newer"
    assert ("state_db_missing" in _codes(payload)) == expected
    assert code == (2 if expected else 0)
    assert _codes(payload) <= {"state_db_missing"}


def test_validate_never_writes_state_for_any_judgment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state = _fresh_state()
    _db_foreign(state)
    _audit_regular(state)
    before = {p.name: (p.stat().st_size, p.stat().st_mtime_ns) for p in state.iterdir()}
    mtime = state.stat().st_mtime_ns
    _run_validate(tmp_path, capsys)
    after = {p.name: (p.stat().st_size, p.stat().st_mtime_ns) for p in state.iterdir()}
    assert after == before
    assert state.stat().st_mtime_ns == mtime
