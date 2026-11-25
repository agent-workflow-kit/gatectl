"""``validate`` reports ``state_db_missing`` only where the store refuses so (#59).

The store (``open_store(create=False)``) is the reference for the history states. ``validate``
reports a ``state_db_missing`` problem wherever the store refuses with the reason
``state_db_missing``, plus one deliberate addition: a foreign or junk (non-gatectl) ``state.db``
with no history, which the store refuses with a plain exit 1 (the code is reused because a new
one needs a schema change). Everywhere else the store refuses without a reason (``schema_newer``
is its own reason; a damaged database, an unusable ``schema_version``, a symlink, FIFO or
directory ``state.db``, a bad state directory, a permission problem) ``validate`` is silent,
and it never writes next to the database.
"""

from __future__ import annotations

import hashlib
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


def _set_version(state: Path, value: str) -> None:
    _db_valid(state)
    con = sqlite3.connect(state / "state.db")
    con.execute("UPDATE meta SET value = ? WHERE key = 'schema_version'", (value,))
    con.commit()
    con.close()


def _db_version_abc(state: Path) -> None:
    _set_version(state, "abc")


def _db_version_zero(state: Path) -> None:
    _set_version(state, "0")


def _db_meta_wrong_columns(state: Path) -> None:
    con = sqlite3.connect(state / "state.db")
    con.execute("CREATE TABLE meta (a TEXT, b TEXT)")
    con.commit()
    con.close()


def _db_corrupt_tree(state: Path) -> None:
    _db_valid(state)
    path = state / "state.db"
    data = bytearray(path.read_bytes())
    data[100:400] = b"\xff" * 300  # a valid header over a corrupt sqlite_master page
    path.write_bytes(bytes(data))


def _db_fifo(state: Path) -> None:
    os.mkfifo(state / "state.db")


def _db_directory(state: Path) -> None:
    (state / "state.db").mkdir()


def _db_symlink_valid(state: Path) -> None:
    other = state.parent / "elsewhere"
    other.mkdir(mode=0o700)
    _db_valid(other)
    (state / "state.db").symlink_to(other / "state.db")


def _fake_wal(state: Path, shm: bool) -> None:
    (state / "state.db-wal").write_bytes(b"\x00" * 100)
    if shm:
        (state / "state.db-shm").write_bytes(b"")


def _db_valid_live_wal(state: Path) -> None:
    _db_valid(state)
    _fake_wal(state, True)


def _db_junk_live_wal(state: Path) -> None:
    _db_junk(state)
    _fake_wal(state, True)


def _db_junk_live_wal_no_shm(state: Path) -> None:
    _db_junk(state)
    _fake_wal(state, False)


def _db_empty_live_wal(state: Path) -> None:
    _db_empty(state)
    _fake_wal(state, True)


DBS: dict[str, Callable[[Path], None]] = {
    "absent": _db_absent,
    "empty": _db_empty,
    "junk": _db_junk,
    "foreign": _db_foreign,
    "schema_newer": _db_schema_newer,
    "valid": _db_valid,
    "version_abc": _db_version_abc,
    "version_zero": _db_version_zero,
    "meta_wrong_columns": _db_meta_wrong_columns,
    "corrupt_tree": _db_corrupt_tree,
    "fifo": _db_fifo,
    "directory": _db_directory,
    "symlink_valid": _db_symlink_valid,
    "valid_live_wal": _db_valid_live_wal,
    "junk_live_wal": _db_junk_live_wal,
    "junk_live_wal_no_shm": _db_junk_live_wal_no_shm,
    "empty_live_wal": _db_empty_live_wal,
}

# state_db_missing for these with a history (the store's reason) ...
MISSING_WITH_HISTORY = {"absent", "empty"}
# ... and with or without one (the foreign/junk rule: a non-empty non-gatectl file)
FOREIGN = {"junk", "foreign", "junk_live_wal", "junk_live_wal_no_shm"}
MSG_HISTORY = "state.db is missing, empty or has no schema_version but audit.jsonl has records"
MSG_FOREIGN = "state.db is not a gatectl database (it has no schema_version)"


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


AUDITS: dict[str, Callable[[Path], None]] = {
    "absent": _audit_absent,
    "empty": _audit_empty,
    "regular": _audit_regular,
    "fifo": _audit_fifo,
    "directory": _audit_directory,
    "symlink": _audit_symlink,
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


def _assert_silent(code: int, payload: dict[str, Any]) -> None:
    assert payload["problems"] == []
    assert code == 0


@pytest.mark.parametrize("db", list(DBS))
@pytest.mark.parametrize("audit", list(AUDITS))
def test_validate_flags_state_db_missing_only_where_the_store_does_or_foreign(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    audit: str,
    db: str,
) -> None:
    state = _fresh_state()
    DBS[db](state)  # the database first: the store would refuse to create one over a history
    AUDITS[audit](state)
    history = audit not in ("absent", "empty")
    code, payload = _run_validate(tmp_path, capsys)  # first: the store may tidy a stale WAL
    verdict = _store_refuses(state)
    if db in ("absent", "empty"):
        assert verdict == ("state_db_missing" if history else None)
    if db == "schema_newer":
        assert verdict == "schema_newer"

    if db in MISSING_WITH_HISTORY:
        expected = MSG_HISTORY if history else None
    elif db in FOREIGN:
        expected = MSG_HISTORY if history else MSG_FOREIGN
    else:
        expected = None
    if verdict == "state_db_missing" and db != "empty_live_wal":
        # wherever the store gives the reason, validate does too; the one exception is a
        # zero-length file with a live WAL, which validate never opens (it would write the -shm)
        assert expected is not None
    if expected is None:
        _assert_silent(code, payload)
    else:
        assert code == 2
        assert [(p["code"], p["message"]) for p in payload["problems"]] == [
            ("state_db_missing", expected)
        ]


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


def _snapshot(state: Path) -> dict[str, tuple[str, int]]:
    return {
        p.name: (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns)
        for p in sorted(state.iterdir())
    }


def test_validate_does_not_touch_the_wal_or_shm_of_a_live_database(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state = _fresh_state()
    _db_valid(state)
    writer = sqlite3.connect(state / "state.db", isolation_level=None)
    try:
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("INSERT INTO meta(key, value) VALUES('x', 'y')")
        assert (state / "state.db-wal").stat().st_size > 32
        assert (state / "state.db-shm").exists()
        before = _snapshot(state)
        code, payload = _run_validate(tmp_path, capsys)
        assert _snapshot(state) == before
        _assert_silent(code, payload)
    finally:
        writer.close()


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores modes")
def test_validate_is_silent_when_the_state_directory_is_not_searchable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state = _fresh_state()
    _db_valid(state)
    state.chmod(0)
    try:
        code, payload = _run_validate(tmp_path, capsys)
    finally:
        state.chmod(0o700)
    _assert_silent(code, payload)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores modes")
def test_validate_is_silent_when_state_db_is_unreadable_even_with_history(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    state = _fresh_state()
    _db_valid(state)
    _audit_regular(state)
    (state / "state.db").chmod(0)
    code, payload = _run_validate(tmp_path, capsys)
    _assert_silent(code, payload)


def test_a_symlinked_state_directory_is_silent_even_with_a_valid_db_and_history(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    _db_valid(real)
    _audit_regular(real)
    _state().parent.mkdir(parents=True, exist_ok=True)
    _state().symlink_to(real)
    code, payload = _run_validate(tmp_path, capsys)
    _assert_silent(code, payload)


def test_a_file_as_the_state_directory_is_silent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _state().parent.mkdir(parents=True, exist_ok=True)
    _state().write_text("x")
    code, payload = _run_validate(tmp_path, capsys)
    _assert_silent(code, payload)


def test_a_state_directory_under_a_file_is_silent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    blocker = _state().parent
    blocker.parent.mkdir(parents=True, exist_ok=True)
    blocker.write_text("x")
    code, payload = _run_validate(tmp_path, capsys)
    _assert_silent(code, payload)
