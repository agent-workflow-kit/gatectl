"""The state store: schema, additive migrations, file safety, state rows and resolution."""

from __future__ import annotations

import hashlib
import multiprocessing
import os
import sqlite3
import stat
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from gatectl import store, validate
from gatectl.errors import InternalError

CANARY = "CANARY-7f3a9c"
FP = "sha256:" + "a" * 64
TS = "2026-01-02T03:04:05Z"


@pytest.fixture
def sdir(tmp_path: Path) -> Path:
    return tmp_path / "state" / "gatectl"


def audit_line(sdir: Path) -> None:
    sdir.mkdir(parents=True, exist_ok=True)
    (sdir / "audit.jsonl").write_bytes(b'{"ts":"x"}\n')


def listing(sdir: Path) -> list[str]:
    return sorted(p.name for p in sdir.iterdir())


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def put(
    s: store.Store,
    policy: str = "p",
    scope: str = "*",
    state: str = "shadow",
    *,
    fingerprint: str = FP,
    cause: str = "set",
    set_by: str = "human:alice",
) -> store.StateRow:
    with s.write():
        return s.write_state_row(
            policy, scope, state, set_by=set_by, set_at=TS, cause=cause, fingerprint=fingerprint
        )


def opened(sdir: Path, **kw: Any) -> store.Store:
    s = store.open_store(sdir, create=True, **kw)
    assert s is not None
    return s


def make_db(sdir: Path, version: int | None, *, wal: bool = True) -> Path:
    sdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = sdir / "state.db"
    con = sqlite3.connect(path)
    if wal:
        con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")
    if version is not None:
        con.execute("INSERT INTO meta VALUES('schema_version', ?)", (str(version),))
    con.commit()
    con.close()
    os.chmod(path, 0o600)
    return path


# --- creation, modes -----------------------------------------------------------------------------


def test_create_makes_private_dir_and_files_with_the_schema(sdir: Path) -> None:
    s = opened(sdir)
    put(s)
    assert stat.S_IMODE(sdir.stat().st_mode) == 0o700
    for name in ("state.db", "state.db-wal", "state.db-shm"):
        assert stat.S_IMODE((sdir / name).stat().st_mode) == 0o600, name
    con = sqlite3.connect(f"file:{sdir / 'state.db'}?mode=ro", uri=True)
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"meta", "policy_state", "decisions", "outcomes", "agent_cache", "agent_slots"} <= tables
    assert con.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    version = con.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0]
    assert version == str(store.latest_version())
    con.close()
    s.close()


def test_modes_are_set_explicitly_not_through_the_umask(sdir: Path) -> None:
    old = os.umask(0)
    try:
        s = opened(sdir)
        put(s)
        s.close()
    finally:
        os.umask(old)
    assert stat.S_IMODE((sdir / "state.db").stat().st_mode) == 0o600
    assert stat.S_IMODE(sdir.stat().st_mode) == 0o700


def test_existing_loose_modes_are_tightened(sdir: Path) -> None:
    opened(sdir).close()
    os.chmod(sdir, 0o755)
    os.chmod(sdir / "state.db", 0o644)
    s = opened(sdir)
    put(s)
    os.chmod(sdir / "state.db-wal", 0o666)
    s.close()
    s = opened(sdir)
    assert stat.S_IMODE(sdir.stat().st_mode) == 0o700
    assert stat.S_IMODE((sdir / "state.db").stat().st_mode) == 0o600
    s.close()


def test_a_missing_database_is_created_empty_only_when_asked(sdir: Path) -> None:
    assert store.open_store(sdir, create=False) is None
    assert not sdir.exists()
    sdir.mkdir(parents=True)
    assert store.open_store(sdir, create=False) is None
    assert listing(sdir) == []


# --- hostile files -------------------------------------------------------------------------------


@pytest.mark.parametrize("create", [True, False])
def test_symlinked_database_is_refused(sdir: Path, tmp_path: Path, create: bool) -> None:
    sdir.mkdir(parents=True, mode=0o700)
    target = tmp_path / "elsewhere.db"
    target.write_bytes(b"")
    (sdir / "state.db").symlink_to(target)
    with pytest.raises(InternalError):
        store.open_store(sdir, create=create)
    assert target.read_bytes() == b""


@pytest.mark.parametrize("create", [True, False])
def test_fifo_database_is_refused_without_blocking(sdir: Path, create: bool) -> None:
    sdir.mkdir(parents=True, mode=0o700)
    os.mkfifo(sdir / "state.db")
    with pytest.raises(InternalError):
        store.open_store(sdir, create=create)


def test_database_owned_by_someone_else_is_refused(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened(sdir).close()
    monkeypatch.setattr(store, "_geteuid", lambda: os.geteuid() + 1)
    with pytest.raises(InternalError):
        store.open_store(sdir, create=True)


def test_state_directory_that_is_a_symlink_is_refused(sdir: Path, tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    sdir.parent.mkdir(parents=True)
    sdir.symlink_to(real)
    with pytest.raises(Exception):  # noqa: B017,PT011
        store.open_store(sdir, create=True)
    assert listing(real) == []
    with pytest.raises(InternalError):
        store.open_store(sdir, create=False)


@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
def test_symlinked_sidecar_is_refused(sdir: Path, tmp_path: Path, suffix: str) -> None:
    opened(sdir).close()
    target = tmp_path / "victim"
    target.write_bytes(b"keep")
    (sdir / f"state.db{suffix}").symlink_to(target)
    with pytest.raises(InternalError):
        store.open_store(sdir, create=True)
    assert target.read_bytes() == b"keep"


def test_non_sqlite_file_is_refused_untouched_and_not_echoed(sdir: Path) -> None:
    sdir.mkdir(parents=True, mode=0o700)
    path = sdir / "state.db"
    path.write_bytes((CANARY + "\n").encode() * 1000)
    os.chmod(path, 0o600)
    before = digest(path)
    for create in (True, False):
        with pytest.raises(InternalError) as info:
            store.open_store(sdir, create=create)
        assert CANARY not in info.value.message
        assert CANARY not in repr(info.value.details)
    assert digest(path) == before
    assert listing(sdir) == ["state.db"]


def test_corrupt_database_is_refused_untouched(sdir: Path) -> None:
    s = opened(sdir)
    put(s)
    s.close()
    path = sdir / "state.db"
    raw = bytearray(path.read_bytes())
    for i in range(100, len(raw), 997):
        raw[i] ^= 0xFF
    path.write_bytes(bytes(raw))
    before = digest(path)
    with pytest.raises(InternalError):
        s2 = store.open_store(sdir, create=True)
        assert s2 is not None
        try:
            s2.rows("p")
            s2.effective("p", "*", "off")
        finally:
            s2.close()
    assert digest(path) == before


def test_huge_non_database_file_is_refused_quickly(sdir: Path) -> None:
    sdir.mkdir(parents=True, mode=0o700)
    path = sdir / "state.db"
    with open(path, "wb") as f:
        f.truncate(2 * 1024**3)
    os.chmod(path, 0o600)
    start = time.monotonic()
    with pytest.raises(InternalError):
        store.open_store(sdir, create=True)
    assert time.monotonic() - start < 5
    assert path.stat().st_size == 2 * 1024**3


def test_foreign_database_without_meta_is_refused_untouched(sdir: Path) -> None:
    sdir.mkdir(parents=True, mode=0o700)
    path = sdir / "state.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE secrets(x)")
    con.commit()
    con.close()
    os.chmod(path, 0o600)
    before = digest(path)
    with pytest.raises(InternalError):
        store.open_store(sdir, create=True)
    assert digest(path) == before


# --- schema_newer ---------------------------------------------------------------------------------


@pytest.mark.parametrize("create", [True, False])
def test_newer_schema_is_refused_and_the_file_is_unchanged(sdir: Path, create: bool) -> None:
    path = make_db(sdir, store.latest_version() + 1)
    before, names = digest(path), listing(sdir)
    with pytest.raises(InternalError) as info:
        store.open_store(sdir, create=create)
    assert info.value.reason == "schema_newer"
    assert info.value.exit_code == 1
    assert digest(path) == before
    assert listing(sdir) == names


def test_newer_schema_with_a_live_wal_is_not_checkpointed(sdir: Path) -> None:
    path = make_db(sdir, store.latest_version() + 5)
    holder = sqlite3.connect(path)
    holder.execute("PRAGMA wal_autocheckpoint=0")
    holder.execute("INSERT INTO meta VALUES('x', '1')")
    holder.commit()
    before = digest(path)
    try:
        with pytest.raises(InternalError) as info:
            store.open_store(sdir, create=True)
        assert info.value.reason == "schema_newer"
        assert digest(path) == before
    finally:
        holder.close()


@pytest.mark.parametrize("junk", ["abc", "", "1.5", "-1", "0", "9" * 40, "١"])
def test_unparseable_schema_version_is_refused_untouched(sdir: Path, junk: str) -> None:
    path = make_db(sdir, None)
    con = sqlite3.connect(path)
    con.execute("INSERT INTO meta VALUES('schema_version', ?)", (junk,))
    con.commit()
    con.close()
    before = digest(path)
    with pytest.raises(InternalError) as info:
        store.open_store(sdir, create=True)
    assert info.value.reason in (None, "schema_newer")
    assert digest(path) == before


# --- state_db_missing ----------------------------------------------------------------------------


@pytest.mark.parametrize("create", [True, False])
def test_missing_database_over_an_audit_history_is_refused(sdir: Path, create: bool) -> None:
    audit_line(sdir)
    with pytest.raises(InternalError) as info:
        store.open_store(sdir, create=create)
    assert info.value.reason == "state_db_missing"
    assert not (sdir / "state.db").exists()


@pytest.mark.parametrize("create", [True, False])
def test_empty_database_over_an_audit_history_is_refused(sdir: Path, create: bool) -> None:
    audit_line(sdir)
    (sdir / "state.db").write_bytes(b"")
    os.chmod(sdir / "state.db", 0o600)
    with pytest.raises(InternalError) as info:
        store.open_store(sdir, create=create)
    assert info.value.reason == "state_db_missing"
    assert (sdir / "state.db").stat().st_size == 0


@pytest.mark.parametrize("create", [True, False])
def test_schemaless_database_over_an_audit_history_is_refused(sdir: Path, create: bool) -> None:
    audit_line(sdir)
    path = make_db(sdir, None)
    before = digest(path)
    with pytest.raises(InternalError) as info:
        store.open_store(sdir, create=create)
    assert info.value.reason == "state_db_missing"
    assert digest(path) == before


def test_database_is_created_when_the_audit_log_is_absent_or_empty(sdir: Path) -> None:
    sdir.mkdir(parents=True, mode=0o700)
    (sdir / "audit.jsonl").write_bytes(b"")
    opened(sdir).close()
    assert (sdir / "state.db").exists()


def test_existing_database_with_audit_history_opens(sdir: Path) -> None:
    opened(sdir).close()
    audit_line(sdir)
    s = store.open_store(sdir, create=False)
    assert s is not None
    s.close()


def test_audit_log_that_is_not_a_regular_file_counts_as_history(sdir: Path) -> None:
    sdir.mkdir(parents=True, mode=0o700)
    os.mkfifo(sdir / "audit.jsonl")
    with pytest.raises(InternalError) as info:
        store.open_store(sdir, create=True)
    assert info.value.reason == "state_db_missing"


# --- migrations ----------------------------------------------------------------------------------


def test_migrations_are_additive_only() -> None:
    allowed = (
        "CREATE TABLE IF NOT EXISTS ",
        "CREATE INDEX IF NOT EXISTS ",
        "CREATE UNIQUE INDEX IF NOT EXISTS ",
        "ALTER TABLE ",
        "INSERT OR IGNORE INTO meta",
    )
    versions = [v for v, _ in store.MIGRATIONS]
    assert versions == list(range(1, len(versions) + 1))
    for _, statements in store.MIGRATIONS:
        for sql in statements:
            text = " ".join(sql.split())
            assert text.startswith(allowed), text
            upper = text.upper()
            for banned in ("DROP ", "DELETE ", "UPDATE ", "RENAME ", "REPLACE ", "TRUNCATE"):
                assert banned not in upper, text
            if upper.startswith("ALTER TABLE"):
                assert " ADD COLUMN " in upper, text


V2 = (
    2,
    (
        "ALTER TABLE policy_state ADD COLUMN note TEXT",
        "CREATE INDEX IF NOT EXISTS policy_state_by_state ON policy_state(state)",
    ),
)


def test_a_later_migration_applies_once_and_keeps_every_row(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = opened(sdir)
    put(s, "p", "*", "enforced")
    put(s, "p", "github.com/o/r", "shadow")
    s.close()
    monkeypatch.setattr(store, "MIGRATIONS", (*store.MIGRATIONS, V2))
    s = opened(sdir)
    assert s.schema_version() == 2
    assert {(r.scope, r.state) for r in s.rows("p")} == {
        ("*", "enforced"),
        ("github.com/o/r", "shadow"),
    }
    cols = {r[1] for r in s.con.execute("PRAGMA table_info(policy_state)")}
    assert "note" in cols
    s.close()
    opened(sdir).close()  # idempotent: the column already exists and is not added again


def test_a_failing_migration_rolls_back_whole(sdir: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    s = opened(sdir)
    put(s)
    s.close()
    bad = (
        2,
        ("ALTER TABLE policy_state ADD COLUMN note TEXT", "ALTER TABLE nosuch ADD COLUMN x TEXT"),
    )
    monkeypatch.setattr(store, "MIGRATIONS", (*store.MIGRATIONS, bad))
    with pytest.raises(InternalError):
        store.open_store(sdir, create=True)
    monkeypatch.undo()
    s = opened(sdir)
    assert s.schema_version() == store.latest_version()
    assert "note" not in {r[1] for r in s.con.execute("PRAGMA table_info(policy_state)")}
    assert len(s.rows("p")) == 1
    s.close()


def test_a_database_from_a_newer_gatectl_is_refused_after_a_downgrade(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with monkeypatch.context() as m:
        m.setattr(store, "MIGRATIONS", (*store.MIGRATIONS, V2))
        opened(sdir).close()
    before = digest(sdir / "state.db")
    with pytest.raises(InternalError) as info:
        store.open_store(sdir, create=True)
    assert info.value.reason == "schema_newer"
    assert digest(sdir / "state.db") == before


# --- state rows ----------------------------------------------------------------------------------


def test_rev_increases_with_every_write_and_never_repeats(sdir: Path) -> None:
    s = opened(sdir)
    revs = [put(s, "p", "*", "shadow").rev]
    revs.append(put(s, "p", "*", "shadow").rev)  # the same key rewritten
    revs.append(put(s, "p", "github.com/o/r", "enforced").rev)
    revs.append(put(s, "q", "*", "off").rev)
    assert revs == sorted(revs)
    assert len(set(revs)) == len(revs)
    assert revs[0] >= 1
    s.close()
    s = opened(sdir)  # the counter is persistent
    assert put(s, "p", "*", "off").rev > revs[-1]
    s.close()


def test_rolled_back_write_leaves_no_row_and_no_committed_rev_repeats(sdir: Path) -> None:
    s = opened(sdir)
    first = put(s)
    with pytest.raises(RuntimeError), s.write():
        s.write_state_row("p", "x/y", "off", set_by="a", set_at=TS, cause="set", fingerprint=FP)
        raise RuntimeError
    assert [r.scope for r in s.rows("p")] == ["*"]
    assert put(s, "p", "other/repo", "off").rev > first.rev
    s.close()


def test_row_fields_round_trip(sdir: Path) -> None:
    s = opened(sdir)
    put(s, "p", "github.com/o/r", "enforced", fingerprint=FP, cause="miss", set_by="auto:gatectl")
    row = s.get_row("p", "github.com/o/r")
    assert row is not None
    assert (row.policy, row.scope, row.state, row.cause) == (
        "p",
        "github.com/o/r",
        "enforced",
        "miss",
    )
    assert (row.set_by, row.set_at, row.fingerprint) == ("auto:gatectl", TS, FP)
    assert s.get_row("p", "nope/none") is None
    s.close()


def test_write_outside_a_transaction_is_refused(sdir: Path) -> None:
    s = opened(sdir)
    with pytest.raises(RuntimeError):
        s.write_state_row("p", "*", "off", set_by="a", set_at=TS, cause="set", fingerprint=FP)
    assert s.rows("p") == []
    s.close()


def test_execute_outside_a_transaction_is_refused(sdir: Path) -> None:
    s = opened(sdir)
    with pytest.raises(RuntimeError):
        s.execute("DELETE FROM agent_cache")
    s.close()


def test_execute_with_a_lone_surrogate_is_a_fixed_text_error_without_echo(sdir: Path) -> None:
    s = opened(sdir)
    with s.write(), pytest.raises(InternalError) as info:
        s.execute("DELETE FROM agent_cache WHERE key = ?", ("\ud800CANARY-7f3a9c",))
    assert "CANARY" not in str(info.value) and "CANARY" not in repr(info.value)
    assert "\ud800" not in str(info.value)
    s.close()


@pytest.mark.parametrize(
    "kw",
    [
        {"state": "bogus"},
        {"state": ""},
        {"cause": "other"},
        {"state": "ENFORCED"},
    ],
)
def test_invalid_state_or_cause_is_refused(sdir: Path, kw: dict[str, str]) -> None:
    s = opened(sdir)
    args: dict[str, Any] = {"state": "shadow", "cause": "set"} | kw
    with pytest.raises(ValueError), s.write():
        s.write_state_row(
            "p",
            "*",
            args["state"],
            set_by="a",
            set_at=TS,
            cause=args["cause"],
            fingerprint=FP,
        )
    assert s.rows("p") == []
    s.close()


def test_injection_shaped_text_is_stored_as_data(sdir: Path) -> None:
    s = opened(sdir)
    evil = "x'); DROP TABLE policy_state;--"
    put(s, "p", "*", "shadow", set_by=evil)
    row = s.get_row("p", "*")
    assert row is not None
    assert row.set_by == evil
    assert len(s.rows("p")) == 1
    s.close()


# --- effective state -----------------------------------------------------------------------------

R = "github.com/o/r"
OTHER = "github.com/o/other"


@pytest.mark.parametrize(
    ("rows", "scope", "initial", "want", "want_scope"),
    [
        ([], "*", "shadow", "shadow", None),
        ([], R, "off", "off", None),
        ([("*", "enforced")], "*", "off", "enforced", "*"),
        ([("*", "enforced")], R, "off", "enforced", "*"),
        ([("*", "enforced"), (R, "shadow")], R, "off", "shadow", R),
        ([("*", "shadow"), (R, "enforced")], R, "off", "enforced", R),
        ([("*", "shadow"), (R, "enforced")], "*", "off", "shadow", "*"),
        ([("*", "shadow"), (R, "enforced")], OTHER, "off", "shadow", "*"),
        ([(R, "enforced")], OTHER, "shadow", "shadow", None),
        ([(R, "enforced")], "*", "shadow", "shadow", None),
        ([("*", "off")], R, "enforced", "off", "*"),
    ],
)
def test_effective_state_is_repo_row_then_star_row_then_initial(
    sdir: Path,
    rows: list[tuple[str, str]],
    scope: str,
    initial: str,
    want: str,
    want_scope: str | None,
) -> None:
    s = opened(sdir)
    revs = {sc: put(s, "p", sc, st).rev for sc, st in rows}
    put(s, "other", "*", "enforced")  # another policy's row never leaks in
    res = s.effective("p", scope, initial)
    assert res.state == want
    assert res.rev == (revs[want_scope] if want_scope is not None else None)
    assert (res.row.scope if res.row else None) == want_scope
    s.close()


@pytest.mark.parametrize(
    ("states", "initial", "want"),
    [
        ([], "shadow", "shadow"),
        ([], "off", "off"),
        (["off"], "enforced", "off"),
        (["off", "shadow"], "off", "shadow"),
        (["shadow", "enforced", "off"], "off", "enforced"),
        (["enforced"], "off", "enforced"),
        (["shadow", "shadow"], "enforced", "shadow"),
    ],
)
def test_indeterminate_scope_takes_the_strictest_stored_state(
    sdir: Path, states: list[str], initial: str, want: str
) -> None:
    s = opened(sdir)
    for i, st in enumerate(states):
        put(s, "p", "*" if i == 0 else f"github.com/o/r{i}", st)
    put(s, "other", "*", "enforced")
    res = s.effective("p", "*", initial, indeterminate=True)
    assert res.state == want
    assert res.rev is None  # an indeterminate scope has no state_rev
    s.close()


def test_a_check_style_read_never_creates_a_row(sdir: Path) -> None:
    s = opened(sdir)
    s.effective("p", R, "shadow")
    s.effective("p", "*", "shadow", indeterminate=True)
    assert s.rows("p") == []
    assert s.con.execute("SELECT COUNT(*) FROM policy_state").fetchone()[0] == 0
    s.close()


def test_removed_policy_keeps_rows_and_readding_the_name_resumes_them(sdir: Path) -> None:
    s = opened(sdir)
    put(s, "gone", "*", "enforced")
    put(s, "gone", R, "shadow")
    s.close()
    # the store never learns about the config: nothing prunes rows of an unconfigured policy
    s = opened(sdir)
    assert {(r.scope, r.state) for r in s.rows("gone")} == {("*", "enforced"), (R, "shadow")}
    assert s.effective("gone", OTHER, "off").state == "enforced"
    s.close()


def test_tampered_row_state_is_refused_without_echo(sdir: Path) -> None:
    s = opened(sdir)
    put(s)
    s.close()
    con = sqlite3.connect(sdir / "state.db")
    con.execute("PRAGMA ignore_check_constraints=ON")
    con.execute("UPDATE policy_state SET state=?", (CANARY,))
    con.commit()
    con.close()
    s = opened(sdir)
    with pytest.raises(InternalError) as info:
        s.effective("p", "*", "off")
    assert CANARY not in info.value.message
    with pytest.raises(InternalError):
        s.rows("p")
    s.close()


@pytest.mark.parametrize("column", ["set_by", "set_at", "fingerprint"])
@pytest.mark.parametrize("value", [b"blob", b""])  # TEXT affinity turns numbers into text
def test_a_non_text_value_in_a_text_column_is_refused(
    sdir: Path, column: str, value: object
) -> None:
    s = opened(sdir)
    put(s)
    s.close()
    con = sqlite3.connect(sdir / "state.db")
    con.execute(f"UPDATE policy_state SET {column}=?", (value,))  # noqa: S608
    con.commit()
    con.close()
    s = opened(sdir)
    with pytest.raises(InternalError):
        s.rows("p")
    s.close()


def test_untrusted_row_text_is_sanitized_when_read(sdir: Path) -> None:
    s = opened(sdir)
    put(s)
    s.close()
    con = sqlite3.connect(sdir / "state.db")
    con.execute("UPDATE policy_state SET set_by=?", ("human:\x1b[31mred‮\n" + "z" * 5000,))
    con.commit()
    con.close()
    s = opened(sdir)
    row = s.get_row("p", "*")
    assert row is not None
    assert "\x1b" not in row.set_by and "‮" not in row.set_by and "\n" not in row.set_by
    assert len(row.set_by) <= 512
    s.close()


def test_a_reader_sees_rows_that_live_only_in_the_wal(sdir: Path) -> None:
    s = opened(sdir)
    s.con.execute("PRAGMA wal_autocheckpoint=0")
    put(s, "p", "*", "enforced")
    assert (sdir / "state.db-wal").stat().st_size > 0
    reader = store.open_store(sdir, create=False)
    assert reader is not None
    assert reader.effective("p", "*", "off").state == "enforced"
    reader.close()
    s.close()


def test_a_reader_never_writes(sdir: Path) -> None:
    s = opened(sdir)
    put(s)
    s.close()
    path = sdir / "state.db"
    before, names = digest(path), listing(sdir)
    reader = store.open_store(sdir, create=False)
    assert reader is not None
    assert reader.effective("p", "*", "off").state == "shadow"
    with pytest.raises(sqlite3.Error):
        reader.con.execute("DELETE FROM policy_state")
    reader.close()
    assert digest(path) == before
    # a WAL reader needs its -shm and -wal; they stay empty of data and private
    assert set(listing(sdir)) <= {*names, "state.db-wal", "state.db-shm"}
    for extra in set(listing(sdir)) - set(names):
        assert stat.S_IMODE((sdir / extra).stat().st_mode) == 0o600


# --- validate reads the same names ---------------------------------------------------------------


def test_validate_queries_work_against_a_real_store(sdir: Path) -> None:
    s = opened(sdir)
    put(s, "alpha", "*", "shadow")
    put(s, "beta", R, "enforced")
    with s.write():
        s.con.execute(
            "INSERT INTO decisions(id, time, policy, scope, fingerprint, state, decision, "
            "reason, actor) VALUES('gd-1', ?, 'gamma', '*', ?, 'shadow', 'allow', "
            "'all_passed', 'auto:x')",
            (TS, FP),
        )
    # an open store may hold frames only in the WAL: validate does not read it (never writes)
    assert validate._read_db(sdir / "state.db").version is validate._SKIP
    s.close()
    assert validate._read_db(sdir / "state.db").names == {"alpha", "beta", "gamma"}
    assert validate._read_db(sdir / "state.db").version == 1  # schema_version row is found


def test_fresh_store_is_usable_for_validate_and_has_no_orphans(sdir: Path) -> None:
    opened(sdir).close()
    audit_line(sdir)
    found = validate._read_db(sdir / "state.db")
    assert found.names == set() and found.version == 1


# --- real processes ------------------------------------------------------------------------------


def _writer(directory: str, worker: int, count: int, out: Any) -> None:
    s = store.open_store(Path(directory), create=True, busy_timeout=30.0)
    assert s is not None
    revs = []
    for i in range(count):
        with s.write():
            row = s.write_state_row(
                f"p{worker}",
                f"github.com/o/r{i}",
                "shadow",
                set_by="auto:t",
                set_at=TS,
                cause="set",
                fingerprint=FP,
            )
        revs.append(row.rev)
    s.close()
    out.put(revs)


def _holder(directory: str, held: Any, release: Any) -> None:
    s = store.open_store(Path(directory), create=True)
    assert s is not None
    with s.write():
        held.set()
        release.wait(30)
    s.close()


def _reap(procs: list[Any]) -> None:
    for p in procs:
        if p.is_alive():
            p.terminate()  # exactly the Process objects this test started
        p.join(10)


def test_eight_concurrent_writers_lose_and_tear_nothing(sdir: Path) -> None:
    opened(sdir).close()
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    workers, count = 8, 12
    procs = [ctx.Process(target=_writer, args=(str(sdir), w, count, out)) for w in range(workers)]
    try:
        for p in procs:
            p.start()
        results = [out.get(timeout=120) for _ in procs]
        for p in procs:
            p.join(30)
    finally:
        _reap(procs)
    assert [p.exitcode for p in procs] == [0] * workers
    revs = sorted(r for rs in results for r in rs)
    assert revs == list(range(1, workers * count + 1))  # unique and gapless
    s = opened(sdir)
    assert s.con.execute("SELECT COUNT(*) FROM policy_state").fetchone()[0] == workers * count
    assert s.con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    s.close()


def test_a_busy_write_lock_fails_after_the_bounded_wait_not_forever(sdir: Path) -> None:
    opened(sdir).close()
    ctx = multiprocessing.get_context("spawn")
    held, release = ctx.Event(), ctx.Event()
    proc = ctx.Process(target=_holder, args=(str(sdir), held, release))
    try:
        proc.start()
        assert held.wait(60)
        s = store.open_store(sdir, create=True, busy_timeout=0.2)
        assert s is not None
        start = time.monotonic()
        with pytest.raises(store.StoreBusyError):
            with s.write():
                pytest.fail("must not get the lock")
        elapsed = time.monotonic() - start
        assert 0.1 <= elapsed < 1.0  # one wait of busy_timeout, not repeated
        # a reader never waits for the writer
        reader = store.open_store(sdir, create=False, busy_timeout=0.2)
        assert reader is not None
        t = time.monotonic()
        assert reader.rows("p") == []
        assert time.monotonic() - t < 1
        reader.close()
        s.close()
    finally:
        release.set()
        proc.join(30)
        _reap([proc])


def test_store_busy_error_is_an_internal_error_without_reason() -> None:
    err = store.StoreBusyError("busy")
    assert isinstance(err, InternalError)
    assert err.exit_code == 1


# --- round 1 review fixes -----------------------------------------------------------------------


def _loop_writer(directory: str, seconds: float, out: Any) -> None:
    errors: list[str] = []
    try:
        s = store.open_store(Path(directory), create=True)
        assert s is not None
        end = time.monotonic() + seconds
        n = 0
        while time.monotonic() < end:
            try:
                with s.write():
                    s.write_state_row(
                        "p", f"github.com/o/r{n % 5}", "shadow", set_by="auto:t", set_at=TS,
                        cause="set", fingerprint=FP,
                    )  # fmt: skip
            except store.StoreBusyError:
                pass  # writers may starve each other under load; only readers must see no error
            n += 1
            time.sleep(0.001)
        s.close()
    except Exception as exc:  # reported to the parent
        errors.append(f"{type(exc).__name__}: {exc} {getattr(exc, 'reason', None)}")
    out.put(errors)


def _loop_reader(directory: str, seconds: float, out: Any) -> None:
    errors: list[str] = []
    end = time.monotonic() + seconds
    try:
        while time.monotonic() < end:
            s = store.open_store(Path(directory), create=False)
            assert s is not None
            s.rows("p")
            s.close()
    except Exception as exc:  # reported to the parent
        errors.append(f"{type(exc).__name__}: {exc} {getattr(exc, 'reason', None)}")
    out.put(errors)


def test_readers_racing_writers_never_see_a_spurious_error(sdir: Path) -> None:
    """R1: extended busy codes (261 and kin) are busy, never 'not usable' or state_db_missing."""
    opened(sdir).close()
    audit_line(sdir)
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    procs = [ctx.Process(target=_loop_writer, args=(str(sdir), 2.0, out)) for _ in range(2)]
    procs += [ctx.Process(target=_loop_reader, args=(str(sdir), 2.0, out)) for _ in range(2)]
    try:
        for p in procs:
            p.start()
        results = [out.get(timeout=120) for _ in procs]
        for p in procs:
            p.join(30)
    finally:
        _reap(procs)
    assert [e for errs in results for e in errs] == []


@pytest.mark.parametrize("code", [261, 5, 6, 15, 517])
def test_extended_busy_codes_translate_to_busy(code: int) -> None:
    exc = sqlite3.OperationalError("x")
    exc.sqlite_errorcode = code  # type: ignore[attr-defined]
    assert isinstance(store._translate(exc), store.StoreBusyError)


def test_extended_busy_code_in_read_version_is_raised_not_a_foreign_database() -> None:
    class Con:
        calls = 0

        def execute(self, sql: str) -> Any:
            self.calls += 1
            if "sqlite_master" in sql:
                return self
            exc = sqlite3.OperationalError("database is locked")
            exc.sqlite_errorcode = 261  # type: ignore[attr-defined]
            raise exc

        def fetchone(self) -> tuple[int]:
            return (1,)

    with pytest.raises(sqlite3.OperationalError):
        store._read_version(Con())  # type: ignore[arg-type]


def _creator(directory: str, start_at: float, out: Any) -> None:
    while time.time() < start_at:
        pass
    try:
        s = store.open_store(Path(directory), create=True)
        assert s is not None
        s.close()
        out.put("ok")
    except Exception as exc:  # reported to the parent
        out.put(f"{type(exc).__name__}: {exc}")


def test_simultaneous_first_creators_all_succeed(tmp_path: Path) -> None:
    """R4: losing the O_EXCL race re-vets the file; the WAL switch waits out a racing creator."""
    ctx = multiprocessing.get_context("spawn")
    for rnd in range(5):
        directory = tmp_path / f"r{rnd}" / "g"
        out = ctx.Queue()
        start_at = time.time() + 1.5
        args = (str(directory), start_at, out)
        procs = [ctx.Process(target=_creator, args=args) for _ in range(4)]
        try:
            for p in procs:
                p.start()
            results = [out.get(timeout=120) for _ in procs]
            for p in procs:
                p.join(30)
        finally:
            _reap(procs)
        assert results == ["ok"] * 4, results


def test_a_file_that_appears_between_the_vet_and_the_create_is_vetted_not_refused(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdir.mkdir(parents=True, mode=0o700)
    real = store._vet_file
    calls = {"n": 0}

    def racing(path: Path) -> Any:
        if path.name == "state.db" and calls["n"] == 0:
            calls["n"] += 1
            result = real(path)  # absent
            path.write_bytes(b"")  # another creator wins here
            os.chmod(path, 0o600)
            return result
        return real(path)

    monkeypatch.setattr(store, "_vet_file", racing)
    opened(sdir).close()
    assert (sdir / "state.db").exists()


def test_a_creation_race_that_leaves_a_non_regular_file_is_refused(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sdir.mkdir(parents=True, mode=0o700)
    real = store._vet_file

    def racing(path: Path) -> Any:
        result = real(path)
        if path.name == "state.db" and result is None and not path.exists():
            os.mkfifo(path)
        return result

    monkeypatch.setattr(store, "_vet_file", racing)
    with pytest.raises(InternalError):
        store.open_store(sdir, create=True)


def test_a_huge_numeric_schema_version_is_schema_newer_and_untouched(sdir: Path) -> None:
    """R3: no 18-digit cap."""
    path = make_db(sdir, None)
    con = sqlite3.connect(path)
    con.execute("INSERT INTO meta VALUES('schema_version', ?)", ("9" * 30,))
    con.commit()
    con.close()
    before = digest(path)
    for create in (True, False):
        with pytest.raises(InternalError) as info:
            store.open_store(sdir, create=create)
        assert info.value.reason == "schema_newer"
    assert digest(path) == before


@pytest.mark.parametrize("history", [True, False])
@pytest.mark.parametrize("create", [True, False])
def _junk(path: Path) -> None:
    path.write_bytes((CANARY + "\n").encode() * 100)


def _damaged_page_size(path: Path) -> None:
    """A valid ``SQLite format 3`` magic with an invalid page size (offset 16)."""
    raw = bytearray(path.read_bytes())
    raw[16:18] = b"\x00\x03"
    path.write_bytes(bytes(raw))


@pytest.mark.parametrize("history", [True, False])
@pytest.mark.parametrize("create", [True, False])
@pytest.mark.parametrize("damage", [_junk, _damaged_page_size])
def test_a_not_a_database_file_is_state_db_missing_only_over_a_history(
    sdir: Path, create: bool, history: bool, damage: Callable[[Path], None]
) -> None:
    """R5: a file SQLite reports as not a database (invalid or damaged header) has no row."""
    sdir.mkdir(parents=True, mode=0o700)
    path = sdir / "state.db"
    if damage is _damaged_page_size:
        s = opened(sdir)
        put(s)
        s.close()
        (sdir / "state.db-wal").unlink(missing_ok=True)
        (sdir / "state.db-shm").unlink(missing_ok=True)
    if history:
        audit_line(sdir)
    if damage is _junk:
        _junk(path)
    else:
        _damaged_page_size(path)
    os.chmod(path, 0o600)
    before = digest(path)
    with pytest.raises(InternalError) as info:
        store.open_store(sdir, create=create)
    assert info.value.reason == ("state_db_missing" if history else None)
    assert CANARY not in info.value.message
    assert digest(path) == before


def test_a_valid_header_with_a_corrupt_tree_over_a_history_is_a_plain_error(sdir: Path) -> None:
    s = opened(sdir)
    put(s)
    s.close()
    audit_line(sdir)
    path = sdir / "state.db"
    raw = bytearray(path.read_bytes())
    for i in range(100, len(raw), 997):
        raw[i] ^= 0xFF
    path.write_bytes(bytes(raw))
    with pytest.raises(InternalError) as info:
        s2 = store.open_store(sdir, create=True)
        assert s2 is not None
        try:
            s2.rows("p")
        finally:
            s2.close()
    assert info.value.reason is None


def test_the_revision_counter_cannot_overflow(sdir: Path) -> None:
    """R8: a tampered row with rev 2**63-1 is a fixed-text internal error, not OverflowError."""
    s = opened(sdir)
    put(s)
    with s.write():
        s.con.execute("UPDATE policy_state SET rev = ?", (2**63 - 1,))
    with pytest.raises(InternalError) as info:
        put(s, "q")
    assert "exhausted" in info.value.message
    s.close()


def test_a_huge_tampered_text_value_is_capped_when_read(sdir: Path) -> None:
    """R9: the text columns are cut in SQL, not after fetching them whole."""
    s = opened(sdir)
    put(s)
    big = "x" * (2 * 1024 * 1024)
    with s.write():
        s.con.execute("UPDATE policy_state SET set_by = ?, fingerprint = ?", (big, big))
    for row in (s.get_row("p", "*"), s.rows("p")[0], s.effective("p", "*", "off").row):
        assert row is not None
        assert len(row.set_by) <= 512 and len(row.fingerprint) <= 512
    s.close()


def test_the_select_statements_cut_text_columns() -> None:
    assert "substr(CAST(set_by AS BLOB)" in store.Store._COLUMNS  # by bytes: a NUL does not hide


def test_a_nul_in_a_state_row_value_is_kept_for_the_sanitizer(sdir: Path) -> None:
    """substr() of text stops at a NUL and would hand back ``human:ann``."""
    s = opened(sdir)
    put(s)
    with s.write():
        s.con.execute("UPDATE policy_state SET set_by = ?", ("human:ann\x00junk",))
    row = s.get_row("p", "*")
    assert row is not None and row.set_by == "human:ann\ufffdjunk"
    s.close()


@pytest.mark.parametrize("kind", ["fifo", "dir", "symlink", "empty_regular"])
@pytest.mark.parametrize("create", [True, False])
def test_the_store_judges_an_audit_log_by_lstat_and_fails_closed(
    sdir: Path, tmp_path: Path, kind: str, create: bool
) -> None:
    """R11: a FIFO, directory or symlink audit.jsonl is history; no hang, no database made."""
    sdir.mkdir(parents=True, mode=0o700)
    target = sdir / "audit.jsonl"
    if kind == "fifo":
        os.mkfifo(target)
    elif kind == "dir":
        target.mkdir()
    elif kind == "symlink":
        (tmp_path / "elsewhere").write_bytes(b"")
        target.symlink_to(tmp_path / "elsewhere")
    else:
        target.write_bytes(b"")
    if kind == "empty_regular":
        s = store.open_store(sdir, create=create)
        assert (s is None) == (not create)
        if s:
            s.close()
        return
    start = time.monotonic()
    with pytest.raises(InternalError) as info:
        store.open_store(sdir, create=create)
    assert info.value.reason == "state_db_missing"
    assert time.monotonic() - start < 5
    assert not (sdir / "state.db").exists()


def _iter_unused() -> Iterator[None]:  # keeps the import of Iterator meaningful for pyright
    yield None


def test_a_state_directory_under_a_file_is_a_plain_refusal_not_a_traceback(tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    with pytest.raises(InternalError, match="not a real directory") as caught:
        store.open_store(blocker / "gatectl", create=False)
    assert caught.value.reason is None
