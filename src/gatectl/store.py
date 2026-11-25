"""The state store: ``state.db``, its schema, additive migrations and the state rows.

``state.db`` is SQLite in WAL mode inside the private state directory (interface.md, Files and
Upgrades). This module owns how it is opened and what is in it:

* The directory is a real directory owned by the user (0700); ``state.db`` and its ``-wal``,
  ``-shm`` and ``-journal`` files are regular files owned by the user (0600), opened with
  ``O_NOFOLLOW | O_NONBLOCK`` so a link or a FIFO is refused and never followed or waited on.
* Migrations are additive only and run in one ``BEGIN IMMEDIATE`` transaction each. A database
  from a newer gatectl is refused (``schema_newer``) before anything is written to it.
* A missing, empty or schema-less ``state.db`` next to a non-empty ``audit.jsonl`` is refused
  (``state_db_missing``): gatectl never starts a fresh database over an existing history.
* Text read from the database is untrusted: it is validated and sanitized, and error messages
  are fixed text that never echo it.
* A write waits at most ``busy_timeout`` for the lock and retries the transaction once; a
  reader opens the database read-only and never waits for a writer (WAL).

``validate.py`` reads ``state.db`` with raw read-only SQLite and depends on the names
``meta(key, value)`` with a ``schema_version`` row, ``policy_state.policy`` and
``decisions.policy``; ``tests/test_store.py`` pins that against a real store.
"""

from __future__ import annotations

import os
import re
import sqlite3
import stat
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from gatectl import audit, ids
from gatectl.errors import InternalError
from gatectl.sanitize import sanitize

STATES = ("off", "shadow", "enforced")
CAUSES = ("set", "miss")
STAR = "*"
DEFAULT_BUSY_TIMEOUT = 2.0  # defaults.record_reserve
_TEXT_CAP = 512
_ROW_LIMIT = 10000  # rows of one policy a read returns (a tampered database stays bounded)
_STRICTNESS = {"enforced": 0, "shadow": 1, "off": 2}
_VERSION = re.compile(r"[0-9]{1,18}", re.ASCII)
_SQLITE_BUSY = (5, 6, 15)  # SQLITE_BUSY, SQLITE_LOCKED, SQLITE_PROTOCOL (WAL lock race)
_SIDECARS = ("-wal", "-shm", "-journal")

# Seam the tests replace (the module ``os`` itself is never patched).
_geteuid = os.geteuid

# Each migration is a version and the statements that bring the schema to it. They are additive
# only (tests/test_store.py lints this): new tables, new indexes, new columns, new meta rows.
# Never drop, rename, rewrite or delete anything: an older database must keep every row.
MIGRATIONS: tuple[tuple[int, tuple[str, ...]], ...] = (
    (
        1,
        (
            """CREATE TABLE IF NOT EXISTS meta(
                key TEXT PRIMARY KEY,
                value TEXT
            )""",
            "INSERT OR IGNORE INTO meta(key, value) VALUES('state_rev', '0')",
            """CREATE TABLE IF NOT EXISTS policy_state(
                policy TEXT NOT NULL,
                scope TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('off', 'shadow', 'enforced')),
                set_by TEXT NOT NULL,
                set_at TEXT NOT NULL,
                cause TEXT NOT NULL CHECK (cause IN ('set', 'miss')),
                fingerprint TEXT NOT NULL,
                rev INTEGER NOT NULL,
                PRIMARY KEY (policy, scope)
            ) WITHOUT ROWID""",
            "CREATE UNIQUE INDEX IF NOT EXISTS policy_state_rev ON policy_state(rev)",
            """CREATE TABLE IF NOT EXISTS decisions(
                id TEXT PRIMARY KEY,
                time TEXT NOT NULL,
                policy TEXT NOT NULL,
                scope TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                state TEXT NOT NULL,
                decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny', 'escalate')),
                reason TEXT NOT NULL,
                tool TEXT,
                hook TEXT,
                object_type TEXT,
                object_id TEXT,
                repo TEXT,
                input_sha256 TEXT,
                case_key TEXT,
                state_rev INTEGER,
                declared_json TEXT,
                checks_json TEXT,
                actor TEXT NOT NULL,
                input_json TEXT
            ) WITHOUT ROWID""",
            "CREATE INDEX IF NOT EXISTS decisions_by_policy ON decisions(policy, scope, time)",
            "CREATE INDEX IF NOT EXISTS decisions_by_time ON decisions(time)",
            "CREATE INDEX IF NOT EXISTS decisions_by_case ON decisions(policy, case_key)",
            """CREATE TABLE IF NOT EXISTS outcomes(
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                decision_id TEXT NOT NULL,
                time TEXT NOT NULL,
                outcome TEXT NOT NULL CHECK (outcome IN ('agree', 'disagree')),
                signal TEXT NOT NULL,
                actor TEXT NOT NULL,
                actor_kind TEXT NOT NULL,
                reason TEXT
            )""",
            "CREATE INDEX IF NOT EXISTS outcomes_by_decision ON outcomes(decision_id, seq)",
            """CREATE TABLE IF NOT EXISTS agent_cache(
                key TEXT PRIMARY KEY,
                time TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                artifact_json TEXT NOT NULL,
                decision_id TEXT
            ) WITHOUT ROWID""",
            "CREATE INDEX IF NOT EXISTS agent_cache_by_expiry ON agent_cache(expires_at)",
            """CREATE TABLE IF NOT EXISTS agent_slots(
                holder_pid INTEGER NOT NULL,
                holder_start TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                decision_id TEXT NOT NULL,
                csession_id TEXT,
                started_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )""",
        ),
    ),
)


def latest_version() -> int:
    return MIGRATIONS[-1][0]


class StoreBusyError(InternalError):
    """The write lock was not obtained within the bounded wait (exit 1; a retry was made)."""


@dataclass(frozen=True)
class StateRow:
    policy: str
    scope: str
    state: str
    set_by: str
    set_at: str
    cause: str
    fingerprint: str
    rev: int


@dataclass(frozen=True)
class Resolved:
    """The effective state of a policy in a scope.

    ``row`` is the stored row that supplied it (None for the initial state, and for an
    indeterminate scope, which has no single supplier). ``rev`` is the decision's ``state_rev``:
    the row's revision, or None when there is no row or the scope is indeterminate.
    """

    state: str
    rev: int | None
    row: StateRow | None


def _fail(message: str, reason: str | None = None) -> InternalError:
    return InternalError(message, reason=reason)


_UNUSABLE = "state.db is not a usable database"


def _translate(exc: sqlite3.Error) -> InternalError:
    """A fixed-text error for a SQLite failure: never the driver's text (it can echo content)."""
    if getattr(exc, "sqlite_errorcode", None) in _SQLITE_BUSY:
        return StoreBusyError("state.db is busy")
    return _fail(_UNUSABLE)


# --- the directory and the files -------------------------------------------------------------------


def _vet_dir(path: Path, create: bool) -> bool:
    """True when the state directory exists and is safe; False when it is missing (not created)."""
    if create:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if not stat.S_ISDIR(info.st_mode):
        raise _fail("the state directory is not a real directory")
    if info.st_uid != _geteuid():
        raise _fail("the state directory is not owned by the current user")
    if stat.S_IMODE(info.st_mode) != 0o700:
        os.chmod(path, 0o700)
    return True


def _vet_file(path: Path) -> tuple[int, int] | None:
    """(device, inode) of a regular file owned by this user, set to 0600; None when absent.

    Judged with ``lstat`` (a link, a FIFO or a device is refused, never opened) and tightened
    with ``chmod`` by path. The file is deliberately never opened here: closing any descriptor
    of a file drops every POSIX lock the process holds on it, which would silently release
    SQLite's own locks on the database and its ``-shm`` and corrupt a concurrent writer.
    """
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise _fail(f"{path.name} cannot be examined") from None
    if not stat.S_ISREG(info.st_mode):
        raise _fail(f"{path.name} is not a regular file")
    if info.st_uid != _geteuid():
        raise _fail(f"{path.name} is not owned by the current user")
    if stat.S_IMODE(info.st_mode) != 0o600:
        try:
            os.chmod(path, 0o600)
        except OSError:
            raise _fail(f"{path.name} cannot be made private") from None
    return (info.st_dev, info.st_ino)


def _vet_sidecars(db: Path) -> None:
    for suffix in _SIDECARS:
        _vet_file(db.with_name(db.name + suffix))


def _has_history(directory: Path) -> bool:
    """Whether ``audit.jsonl`` holds anything. Anything but an empty regular file counts."""
    try:
        info = os.lstat(directory / "audit.jsonl")
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return info.st_size > 0 if stat.S_ISREG(info.st_mode) else True


def _same_file(path: Path, ident: tuple[int, int]) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == ident


# --- reading the schema ------------------------------------------------------------------------------


def _uri(path: Path, query: str) -> str:
    return f"file:{quote(str(path))}?{query}"


def _first(con: sqlite3.Connection, sql: str) -> tuple[object, ...] | None:
    """One row of ``sql``. SQLite answers SQLITE_PROTOCOL ("locking protocol") to a reader that
    races the first use of a WAL by a writer; that is transient and is retried a few times."""
    for attempt in range(20):
        try:
            return con.execute(sql).fetchone()
        except sqlite3.OperationalError as exc:
            if getattr(exc, "sqlite_errorcode", None) != 15 or attempt == 19:
                raise
            time.sleep(0.01 * (attempt + 1))
    raise AssertionError("unreachable")


def _read_version(con: sqlite3.Connection) -> int | None | bool:
    """The ``schema_version``; None when the database has no tables; False when it has tables
    but no usable schema_version row (a foreign or damaged database)."""
    if _first(con, "SELECT 1 FROM sqlite_master LIMIT 1") is None:
        return None
    try:
        row = con.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    except sqlite3.OperationalError as exc:
        if getattr(exc, "sqlite_errorcode", None) in _SQLITE_BUSY:
            raise
        return False  # no such table: meta
    if row is None:
        return False
    value = row[0]
    if not isinstance(value, str) or _VERSION.fullmatch(value) is None or int(value) < 1:
        raise _fail("state.db has an unusable schema_version")
    return int(value)


def _peek(path: Path) -> int | None | bool:
    """Read the version without any chance of writing: ``immutable`` opens take no lock and
    create no sidecar. With frames in the WAL the committed rows may live only there, so then a
    read-only open (which never checkpoints) is used. The version is verified again on the
    working connection, so a stale answer here only decides whether to open at all."""
    wal = path.with_name(path.name + "-wal")
    try:
        live = os.lstat(wal).st_size > 32
    except OSError:
        live = False
    query = "mode=ro" if live else "immutable=1"
    try:
        con = sqlite3.connect(_uri(path, query), uri=True, timeout=0)
    except sqlite3.Error as exc:
        raise _translate(exc) from None
    try:
        con.execute("PRAGMA trusted_schema=OFF")
        return _read_version(con)
    except sqlite3.Error as exc:
        raise _translate(exc) from None
    finally:
        con.close()


# --- the store -----------------------------------------------------------------------------------------


class Store:
    """An open ``state.db``. Use ``open_store``; close it when done."""

    def __init__(self, con: sqlite3.Connection, path: Path, *, readonly: bool) -> None:
        self.con = con
        self.path = path
        self.readonly = readonly

    def close(self) -> None:
        try:
            self.con.close()
        except sqlite3.Error:
            pass

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def schema_version(self) -> int:
        try:
            version = _read_version(self.con)
        except sqlite3.Error as exc:
            raise _translate(exc) from None
        if not isinstance(version, int) or isinstance(version, bool):
            raise _fail(_UNUSABLE)
        return version

    # -- transactions --

    def _begin(self) -> None:
        for attempt in (1, 2):  # the bounded wait, then one retry
            try:
                self.con.execute("BEGIN IMMEDIATE")
                return
            except sqlite3.Error as exc:
                err = _translate(exc)
                if attempt == 2 or not isinstance(err, StoreBusyError):
                    raise err from None

    @contextmanager
    def write(self) -> Iterator[Store]:
        """One ``BEGIN IMMEDIATE`` transaction: committed on success, rolled back on any error."""
        if self.readonly:
            raise RuntimeError("the store was opened read-only")
        if self.con.in_transaction:
            raise RuntimeError("a transaction is already open")
        self._begin()
        try:
            yield self
        except BaseException:
            self._rollback()
            raise
        try:
            self.con.execute("COMMIT")
        except sqlite3.Error as exc:
            self._rollback()
            raise _translate(exc) from None

    def _rollback(self) -> None:
        try:
            if self.con.in_transaction:
                self.con.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    # -- revisions and rows --

    def next_rev(self) -> int:
        """The next store-wide revision. Only inside ``write()``; a rolled-back write returns it."""
        if not self.con.in_transaction:
            raise RuntimeError("a revision is taken inside a write transaction")
        try:
            self.con.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('state_rev', '0')")
            raw = self.con.execute("SELECT value FROM meta WHERE key = 'state_rev'").fetchone()[0]
            counter = int(raw) if isinstance(raw, str) and _VERSION.fullmatch(raw) else 0
            top = self.con.execute("SELECT COALESCE(MAX(rev), 0) FROM policy_state").fetchone()[0]
            rev = max(counter, top if isinstance(top, int) else 0) + 1
            self.con.execute("UPDATE meta SET value = ? WHERE key = 'state_rev'", (str(rev),))
        except sqlite3.Error as exc:
            raise _translate(exc) from None
        return rev

    def write_state_row(
        self,
        policy: str,
        scope: str,
        state: str,
        *,
        set_by: str,
        set_at: str,
        cause: str,
        fingerprint: str,
    ) -> StateRow:
        """Insert or replace the row of ``(policy, scope)`` with a fresh ``rev``. In ``write()``."""
        if state not in STATES:
            raise ValueError("invalid state")
        if cause not in CAUSES:
            raise ValueError("invalid cause")
        rev = self.next_rev()
        try:
            self.con.execute(
                "INSERT INTO policy_state(policy, scope, state, set_by, set_at, cause,"
                " fingerprint, rev) VALUES(?, ?, ?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(policy, scope) DO UPDATE SET state = excluded.state,"
                " set_by = excluded.set_by, set_at = excluded.set_at, cause = excluded.cause,"
                " fingerprint = excluded.fingerprint, rev = excluded.rev",
                (policy, scope, state, set_by, set_at, cause, fingerprint, rev),
            )
        except sqlite3.Error as exc:
            raise _translate(exc) from None
        return StateRow(policy, scope, state, set_by, set_at, cause, fingerprint, rev)

    def _select(self, sql: str, args: Sequence[object]) -> list[StateRow]:
        try:
            raw = self.con.execute(sql, args).fetchall()
        except sqlite3.Error as exc:
            raise _translate(exc) from None
        return [_row(r) for r in raw]

    _COLUMNS = "policy, scope, state, set_by, set_at, cause, fingerprint, rev FROM policy_state"

    def rows(self, policy: str) -> list[StateRow]:
        """Every stored row of ``policy`` (configured or not), by scope."""
        return self._select(
            f"SELECT {self._COLUMNS} WHERE policy = ? ORDER BY scope LIMIT {_ROW_LIMIT}",  # noqa: S608
            (policy,),
        )

    def get_row(self, policy: str, scope: str) -> StateRow | None:
        found = self._select(
            f"SELECT {self._COLUMNS} WHERE policy = ? AND scope = ?",  # noqa: S608
            (policy, scope),
        )
        return found[0] if found else None

    def effective(
        self, policy: str, scope: str, initial: str, *, indeterminate: bool = False
    ) -> Resolved:
        """The effective state: the repo row, else the ``*`` row, else ``initial``.

        An indeterminate scope takes the strictest state over the policy's stored rows
        (enforced over shadow over off), else ``initial``. Never creates a row.
        """
        if indeterminate:
            found = self._select(
                f"SELECT {self._COLUMNS} WHERE policy = ?"  # noqa: S608
                " ORDER BY CASE state WHEN 'enforced' THEN 0 WHEN 'shadow' THEN 1 ELSE 2 END,"
                " rev DESC LIMIT 1",
                (policy,),
            )
            return Resolved(found[0].state, None, None) if found else Resolved(initial, None, None)
        found = self._select(
            f"SELECT {self._COLUMNS} WHERE policy = ? AND scope IN (?, ?)",  # noqa: S608
            (policy, scope, STAR),
        )
        by_scope = {r.scope: r for r in found}
        for key in (scope, STAR):
            row = by_scope.get(key)
            if row is not None:
                return Resolved(row.state, row.rev, row)
        return Resolved(initial, None, None)


def _row(raw: Sequence[object]) -> StateRow:
    """A validated row. Anything unexpected in a tampered database is refused, never echoed."""
    policy, scope, state, set_by, set_at, cause, fingerprint, rev = raw
    if not (
        isinstance(policy, str)
        and ids.is_policy_name(policy)
        and isinstance(scope, str)
        and (scope == STAR or ids.is_repo_id(scope))
        and isinstance(state, str)
        and state in STATES
        and isinstance(cause, str)
        and cause in CAUSES
        and isinstance(set_by, str)
        and isinstance(set_at, str)
        and isinstance(fingerprint, str)
        and isinstance(rev, int)
        and not isinstance(rev, bool)
        and rev >= 1
    ):
        raise _fail("state.db holds an invalid state row")
    return StateRow(
        policy,
        scope,
        state,
        sanitize(set_by, _TEXT_CAP),
        sanitize(set_at, _TEXT_CAP),
        cause,
        sanitize(fingerprint, _TEXT_CAP),
        rev,
    )


# --- opening -----------------------------------------------------------------------------------------------


def _configure(con: sqlite3.Connection, busy_timeout: float) -> None:
    con.execute(f"PRAGMA busy_timeout={int(busy_timeout * 1000)}")
    con.execute("PRAGMA trusted_schema=OFF")
    con.execute("PRAGMA foreign_keys=ON")


def _migrate(con: sqlite3.Connection, store: Store) -> None:
    """Apply the missing migrations, each in its own ``BEGIN IMMEDIATE`` transaction.

    The version is read again under the lock: another process may have migrated, or a newer
    gatectl may have taken over, since the first look.
    """
    for version, statements in MIGRATIONS:
        with store.write():
            try:
                current = _read_version(con)
                if current is False:
                    raise _fail(_UNUSABLE)
                if current is not None and current > latest_version():
                    raise _fail("state.db is from a newer gatectl", "schema_newer")
                if current is not None and current >= version:
                    continue
                for sql in statements:
                    con.execute(sql)
                con.execute(
                    "INSERT INTO meta(key, value) VALUES('schema_version', ?)"
                    " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (str(version),),
                )
            except sqlite3.Error as exc:
                raise _translate(exc) from None


def _refuse_missing(history: bool) -> None:
    if history:
        raise _fail(
            "state.db is missing, empty or has no schema, but audit.jsonl has records",
            "state_db_missing",
        )


def open_store(
    directory: Path | None = None,
    *,
    create: bool,
    busy_timeout: float = DEFAULT_BUSY_TIMEOUT,
) -> Store | None:
    """Open ``state.db`` in ``directory`` (default: the state directory).

    ``create=True`` is for writers: it creates the directory and the database when there is no
    audit history, and migrates. ``create=False`` is for readers: it opens read-only and returns
    None when there is no database and no history; it never creates or migrates anything.
    Raises ``InternalError`` (reason ``schema_newer`` or ``state_db_missing`` where documented;
    ``StoreBusyError`` when the write lock is not obtained in time).
    """
    base = directory if directory is not None else audit.state_dir()
    if not _vet_dir(base, create):
        return None
    path = base / "state.db"
    history = _has_history(base)
    ident = _vet_file(path)
    if ident is None:
        _refuse_missing(history)
        if not create:
            return None
        try:
            fd = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
            )
        except OSError:
            raise _fail("state.db cannot be created safely") from None
        os.close(fd)
        ident = _vet_file(path)
        if ident is None:
            raise _fail(_UNUSABLE)
    _vet_sidecars(path)

    found = _peek(path)
    if found is None or found is False:
        _refuse_missing(history)
        if found is False:
            raise _fail("state.db is not a gatectl database")
        if not create:
            return None  # an empty file and no history: nothing stored yet
    elif found > latest_version():
        raise _fail("state.db is from a newer gatectl", "schema_newer")

    mode = "mode=rw" if create else "mode=ro"
    try:
        con = sqlite3.connect(_uri(path, mode), uri=True, timeout=busy_timeout, isolation_level=None)
    except sqlite3.Error as exc:
        raise _translate(exc) from None
    store = Store(con, path, readonly=not create)
    try:
        _configure(con, busy_timeout)
        if not create:
            con.execute("PRAGMA query_only=ON")
        version = _read_version(con)
        if not _same_file(path, ident):
            raise _fail("state.db changed while it was being opened")
        if isinstance(version, int) and not isinstance(version, bool):
            if version > latest_version():
                raise _fail("state.db is from a newer gatectl", "schema_newer")
        elif not create:
            raise _fail(_UNUSABLE)  # it changed under us between the peek and the open
        if create:
            # Query first: setting the mode on a database that is already WAL needs locks that a
            # busy writer holds.
            mode_now = con.execute("PRAGMA journal_mode").fetchone()[0].lower()
            if mode_now != "wal" and con.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
                raise _fail("state.db cannot use the WAL journal here")
            if version is None or version < latest_version():  # type: ignore[operator]
                _migrate(con, store)
        _vet_sidecars(path)
    except sqlite3.Error as exc:
        store.close()
        raise _translate(exc) from None
    except BaseException:
        store.close()
        raise
    return store


def read_effective(
    policy: str,
    scope: str,
    initial: str,
    *,
    indeterminate: bool = False,
    directory: Path | None = None,
) -> Resolved:
    """The effective state for a read-only command: no database (and no history) is ``initial``."""
    store = open_store(directory, create=False)
    if store is None:
        return Resolved(initial, None, None)
    with store:
        return store.effective(policy, scope, initial, indeterminate=indeterminate)
