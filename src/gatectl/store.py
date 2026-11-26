"""The state store: ``state.db``, its schema, additive migrations and the state rows.

``state.db`` is SQLite in WAL mode inside the private state directory (interface.md, Files and
Upgrades). This module owns how it is opened and what is in it:

* The directory is a real directory owned by the user (0700); ``state.db`` and its ``-wal``,
  ``-shm`` and ``-journal`` files are regular files owned by the user (0600). They are judged
  with ``lstat`` and tightened with ``chmod`` by path, never opened to inspect them, so a link or
  a FIFO is refused and never followed or waited on.
* Migrations are additive only and run in one ``BEGIN IMMEDIATE`` transaction each. A database
  from a newer gatectl is refused (``schema_newer``) before anything is written to it.
* A missing, empty or schema-less ``state.db`` next to a non-empty ``audit.jsonl`` is refused
  (``state_db_missing``): gatectl never starts a fresh database over an existing history.
* Text read from the database is untrusted: it is validated and sanitized, and error messages
  are fixed text that never echo it.
* A write waits at most ``busy_timeout`` for the lock; ``transact`` retries the whole transaction
  once when the lock was never obtained (a busy error later, at the commit included, is not
  retried); a reader opens the database read-only and never waits for a writer
  (WAL). Busy-class errors are recognised by their primary code (``code & 0xFF``): Python
  reports SQLite's extended codes (261 is ``SQLITE_BUSY_RECOVERY``).

``validate.py`` reads ``state.db`` with raw read-only SQLite and depends on the names
``meta(key, value)`` with a ``schema_version`` row, ``policy_state.policy`` and
``decisions.policy``; ``tests/test_store.py`` pins that against a real store.
"""

from __future__ import annotations

import dataclasses
import os
import re
import sqlite3
import stat
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar
from urllib.parse import quote

from gatectl import audit, ids
from gatectl.errors import InternalError
from gatectl.sanitize import sanitize

T = TypeVar("T")

STATES = ("off", "shadow", "enforced")
CAUSES = ("set", "miss")
STAR = "*"
DEFAULT_BUSY_TIMEOUT = 2.0  # defaults.record_reserve
_TEXT_CAP = 512
_ROW_LIMIT = 10000  # rows of one policy a read returns (a tampered database stays bounded)
_STRICTNESS = {"enforced": 0, "shadow": 1, "off": 2}
_DIGITS = re.compile(r"[0-9]{1,1000}", re.ASCII)
_MAX_REV = 2**63 - 1
_TEXT_SQL = 513  # text columns are cut in SQL to a little over the cap
_SQLITE_BUSY = (5, 6, 15)  # SQLITE_BUSY, SQLITE_LOCKED, SQLITE_PROTOCOL (WAL lock race)
_SQLITE_ERROR = 1
_SQLITE_NOTADB = 26
_BUSY_WAIT = 2.0  # total bound of the short retries of a busy-class read error
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
    """The write lock was not obtained within the bounded wait, or a commit found the database busy
    (exit 1). ``transact`` retries only a lock that was never obtained."""


class AuditWriteError(InternalError):
    """``audit.jsonl`` could not be written (full disk, read-only file, record too large).

    Fixed text, no reason code: the caller's transaction is rolled back and the state is unknown
    (exit 1). A partial line this may have left stays in the file (it is never truncated back).
    """


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
class DecisionRow:
    """One ``decisions`` row as ``check`` records it (interface.md, Check order step 8).

    ``declared_json`` and ``checks_json`` are compact JSON text; ``repo`` is None for scope ``*``;
    ``state_rev`` is the ``rev`` of the row that supplied the state (None for the initial state
    and for an indeterminate scope); ``input_json`` is only set for a policy with
    ``record_input``.
    """

    id: str
    time: str
    policy: str
    scope: str
    fingerprint: str
    state: str
    decision: str
    reason: str
    tool: str | None
    hook: str | None
    object_type: str | None
    object_id: str | None
    repo: str | None
    input_sha256: str
    case_key: str | None
    state_rev: int | None
    declared_json: str | None
    checks_json: str | None
    actor: str
    input_json: str | None


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


def cut_sql(column: str, chars: int = _TEXT_SQL) -> str:
    """SQL that reads a text column cut to the bytes that hold its first ``chars`` characters
    (4 per character, UTF-8), hex-encoded behind a ``T`` (``uncut`` decodes it); any other type
    is returned as it is.

    SQLite's ``substr()`` and ``length()`` stop at a NUL, which would hide it (and the rest of the
    value) from the cap and from the sanitizer; the byte cut does not.
    """
    return (
        f"CASE WHEN typeof({column}) = 'text'"
        f" THEN 'T' || hex(substr(CAST({column} AS BLOB), 1, {4 * chars})) ELSE {column} END"
    )


def uncut(value: object, chars: int = _TEXT_SQL) -> object:
    """The value ``cut_sql`` read: text cut to ``chars`` characters (a NUL stays in it, for
    the sanitizer or the grammar check to deal with); anything that is not text as it is."""
    if isinstance(value, str):
        return bytes.fromhex(value[1:]).decode("utf-8", errors="replace")[:chars]
    return value


def _fail(message: str, reason: str | None = None) -> InternalError:
    return InternalError(message, reason=reason)


_UNUSABLE = "state.db is not a usable database"


def _primary(exc: sqlite3.Error) -> int | None:
    """The primary result code: Python reports extended codes (261 = 5 | 1 << 8)."""
    code = getattr(exc, "sqlite_errorcode", None)
    return code & 0xFF if isinstance(code, int) else None


def _is_busy(exc: sqlite3.Error) -> bool:
    return _primary(exc) in _SQLITE_BUSY


def _parse_int(value: object) -> int | None:
    """A non-negative decimal integer of any size up to 1000 digits, else None."""
    if isinstance(value, str) and _DIGITS.fullmatch(value) is not None:
        return int(value)
    return None


def _translate(exc: sqlite3.Error) -> InternalError:
    """A fixed-text error for a SQLite failure: never the driver's text (it can echo content)."""
    if _is_busy(exc):
        return StoreBusyError("state.db is busy")
    return _fail(_UNUSABLE)


# --- the directory and the files ------------------------------


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
    except NotADirectoryError:  # a parent of the state directory is a file
        raise _fail("the state directory is not a real directory") from None
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


def has_history(directory: Path) -> bool:
    """Whether ``audit.jsonl`` holds anything. Anything but an empty regular file counts.

    Judged with ``lstat`` and never opened, so a FIFO cannot hang it; ``validate`` uses this same
    function, so the two commands cannot disagree about the history.
    """
    try:
        info = os.lstat(directory / "audit.jsonl")
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return info.st_size > 0 if stat.S_ISREG(info.st_mode) else True


def _same_file(path: Path, ident: tuple[int, int]) -> bool:
    """Best-effort detection that ``path`` is still the file that was vetted. It does not prove
    which inode the connection holds and a swap-and-restore passes it; it is not a defence (the
    state directory is 0700, and whoever can write there as this user can edit the database)."""
    try:
        info = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == ident


# --- reading the schema ------------------------------


def _uri(path: Path, query: str) -> str:
    return f"file:{quote(str(path))}?{query}"


def _first(
    con: sqlite3.Connection, sql: str, deadline: float | None = None
) -> tuple[object, ...] | None:
    """One row of ``sql``. A reader that races a writer (the first use of a WAL, a checkpoint,
    recovery) is answered with a busy-class code, SQLITE_PROTOCOL or an extended busy code such
    as 261; that is transient and is retried with short sleeps, bounded by ``deadline``
    (default: ``_BUSY_WAIT`` from now)."""
    if deadline is None:
        deadline = time.monotonic() + _BUSY_WAIT
    attempt = 0
    while True:
        try:
            return con.execute(sql).fetchone()
        except sqlite3.OperationalError as exc:
            if not _is_busy(exc) or time.monotonic() >= deadline:
                raise
            attempt += 1
            time.sleep(min(0.005 * attempt, 0.05))


def _read_version(con: sqlite3.Connection) -> int | None | bool:
    """The ``schema_version``; None when the database has no tables; False when it has tables
    but no usable schema_version row (a foreign or damaged database)."""
    deadline = time.monotonic() + _BUSY_WAIT  # one bound for both reads
    if _first(con, "SELECT 1 FROM sqlite_master LIMIT 1", deadline) is None:
        return None
    try:
        row = _first(con, "SELECT value FROM meta WHERE key = 'schema_version'", deadline)
    except sqlite3.OperationalError as exc:
        if _primary(exc) == _SQLITE_ERROR and "no such table: meta" in str(exc):
            return False
        raise  # busy past the bound, corrupt, not a database: the caller decides
    if row is None:
        return False
    number = parse_schema_version(row[0])
    if number is None:
        raise _fail("state.db has an unusable schema_version")
    return number


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
        if is_not_a_database(exc):
            return False  # "not a database" (bad header): no schema_version row
        raise _translate(exc) from None
    finally:
        con.close()


# --- the store ------------------------------


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
        """One attempt: SQLite waits ``busy_timeout`` for the lock inside it. Retrying the whole
        step-8 transaction (state re-read included) belongs to the caller."""
        try:
            self.con.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise _translate(exc) from None

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
            self._commit()
        except sqlite3.Error as exc:
            self._rollback()
            raise _translate(exc) from None
        except BaseException:
            self._rollback()
            raise

    def _commit(self) -> None:
        self.con.execute("COMMIT")

    def insert_decision(self, row: DecisionRow) -> None:
        """Insert one decision row. Only inside ``write()``; an id that exists, or a value the
        schema refuses, is a fixed-text ``InternalError`` (never the driver's text)."""
        if self.readonly:
            raise RuntimeError("the store was opened read-only")
        if not self.con.in_transaction:
            raise RuntimeError("a decision is inserted inside a write transaction")
        try:
            self.con.execute(
                "INSERT INTO decisions(id, time, policy, scope, fingerprint, state, decision,"
                " reason, tool, hook, object_type, object_id, repo, input_sha256, case_key,"
                " state_rev, declared_json, checks_json, actor, input_json)"
                " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                dataclasses.astuple(row),
            )
        except sqlite3.Error as exc:
            raise _translate(exc) from None

    def append_audit(self, record: Mapping[str, Any]) -> None:
        """Append one record to ``audit.jsonl`` inside the open write transaction, before the
        commit (interface.md, Audit and log). A failed append raises ``AuditWriteError`` and the
        ``write()`` block rolls back; the line (or a partial line) may stay, a row never outlives
        a failed append."""
        if self.readonly:
            raise RuntimeError("the store was opened read-only")
        if not self.con.in_transaction:
            raise RuntimeError("an audit line is appended inside a write transaction")
        try:
            audit.append_audit(record, state_dir=self.path.parent)
        except (OSError, audit.RecordTooLargeError, TypeError, ValueError):
            raise AuditWriteError("audit.jsonl cannot be written") from None

    def append_audit_many(self, records: Sequence[Mapping[str, Any]]) -> None:
        """Like ``append_audit`` for several records, written with one ``write`` after every
        record encodes. Residual window: a short write of the combined buffer can leave complete
        leading lines on disk while the caller's transaction rolls back (see
        ``audit._append_lines``)."""
        if self.readonly:
            raise RuntimeError("the store was opened read-only")
        if not self.con.in_transaction:
            raise RuntimeError("an audit line is appended inside a write transaction")
        try:
            audit.append_audit_many(records, state_dir=self.path.parent)
        except (OSError, audit.RecordTooLargeError, TypeError, ValueError):
            raise AuditWriteError("audit.jsonl cannot be written") from None

    def transact(self, body: Callable[[], T]) -> T:
        """Run ``body`` in one ``write()`` transaction; if the write lock is not obtained within
        ``busy_timeout``, try the whole transaction once more (worst case 2 x ``busy_timeout``).

        Only a lock timeout at the start is retried: nothing has run or been appended yet, so
        ``body`` (which re-reads the state) runs once. A busy error raised later, at the commit
        included, is not retried: the audit line may already be written and a second run would
        append a second line for the same decision.
        """
        started = False

        def run() -> T:
            nonlocal started
            started = True
            return body()

        try:
            with self.write():
                return run()
        except StoreBusyError:
            if started:
                raise
        with self.write():
            return run()

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
            counter = _parse_int(raw) or 0
            top = self.con.execute("SELECT COALESCE(MAX(rev), 0) FROM policy_state").fetchone()[0]
            rev = max(counter, top if isinstance(top, int) else 0) + 1
            if rev > _MAX_REV:
                raise _fail("state.db revision counter is exhausted")
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
        return [_row([*(uncut(v) for v in r[:7]), r[7]]) for r in raw]

    # Text columns are cut in SQL so a huge tampered value is never read whole.
    _COLUMNS = (
        ", ".join(
            cut_sql(c)
            for c in ("policy", "scope", "state", "set_by", "set_at", "cause", "fingerprint")
        )
        + ", rev FROM policy_state"
    )

    def rows(self, policy: str, *, limit: int = _ROW_LIMIT) -> list[StateRow]:
        """Stored rows of ``policy`` (configured or not), by scope, at most ``limit`` (default the
        row cap; a caller that must tell "more than the cap" asks for one more)."""
        return self._select(
            f"SELECT {self._COLUMNS} WHERE policy = ? ORDER BY scope LIMIT {int(limit)}",  # noqa: S608
            (policy,),
        )

    def get_row(self, policy: str, scope: str) -> StateRow | None:
        found = self._select(
            f"SELECT {self._COLUMNS} WHERE policy = ? AND scope = ?",  # noqa: S608
            (policy, scope),
        )
        return found[0] if found else None

    def query(self, sql: str, args: Sequence[object] = ()) -> list[tuple[Any, ...]]:
        """Run one read statement and return its rows. For the read-only history commands: the
        caller passes only fixed SQL text and bound parameters; a SQLite failure is a fixed-text
        error (never the driver's text, which can echo content)."""
        try:
            return self.con.execute(sql, args).fetchall()
        except sqlite3.Error as exc:
            raise _translate(exc) from None

    def execute(self, sql: str, args: Sequence[object] = ()) -> int:
        """Run one write statement inside ``write()`` and return the rows it changed. Fixed SQL
        text and bound parameters only. Outside a transaction it raises ``RuntimeError`` (the
        connection autocommits, so the statement would escape the caller's atomicity); a SQLite
        failure, or a parameter that cannot be encoded (a lone surrogate), is a fixed-text
        error that never echoes the value."""
        if not self.con.in_transaction:
            raise RuntimeError("a statement is executed inside a write transaction")
        try:
            return self.con.execute(sql, args).rowcount
        except sqlite3.Error as exc:
            raise _translate(exc) from None
        except (UnicodeError, ValueError, OverflowError):
            raise _fail(_UNUSABLE) from None

    @contextmanager
    def snapshot(self) -> Iterator[None]:
        """One read transaction: every ``query`` inside sees the database as of the first one
        (WAL), so a writer between two reads can neither make a row vanish nor make two reads
        disagree. Only for a read-only store."""
        try:
            self.con.execute("BEGIN")
        except sqlite3.Error as exc:
            raise _translate(exc) from None
        try:
            yield
        finally:
            try:
                self.con.execute("ROLLBACK")
            except sqlite3.Error:
                pass  # a read transaction holds nothing to undo; the connection closes next

    def has_policy(self, policy: str) -> bool:
        """Whether ``policy`` has a stored row or a recorded decision (a removed policy is known
        to ``set`` only through this)."""
        try:
            found = self.con.execute(
                "SELECT 1 FROM policy_state WHERE policy = ? UNION ALL"
                " SELECT 1 FROM decisions WHERE policy = ? LIMIT 1",
                (policy, policy),
            ).fetchone()
        except sqlite3.Error as exc:
            raise _translate(exc) from None
        return found is not None

    def has_decision(self, policy: str, scope: str) -> bool:
        """Whether a decision of ``policy`` was recorded for exactly ``scope``."""
        try:
            found = self.con.execute(
                "SELECT 1 FROM decisions WHERE policy = ? AND scope = ? LIMIT 1", (policy, scope)
            ).fetchone()
        except sqlite3.Error as exc:
            raise _translate(exc) from None
        return found is not None

    def meta(self, key: str) -> str | None:
        """A ``meta`` value as text (cut to the text cap), or None when absent or not text."""
        try:
            found = self.con.execute(
                f"SELECT {cut_sql('value')} FROM meta"  # noqa: S608
                " WHERE key = ? AND typeof(value) = 'text'",
                (key,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise _translate(exc) from None
        return sanitize(str(uncut(found[0])), _TEXT_CAP) if found is not None else None

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


# --- opening ------------------------------


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


def _ensure_wal(con: sqlite3.Connection, busy_timeout: float) -> None:
    """Switch to WAL. Concurrent first creators answer each other "database is locked" at once
    (the switch does not use the busy handler), so a busy-class error is retried, re-querying the
    mode each time, within ``busy_timeout``."""
    deadline = time.monotonic() + busy_timeout
    attempt = 0
    busy = False
    while True:
        try:
            mode = str(con.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            if mode != "wal":
                mode = str(con.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
            if mode == "wal":
                return
        except sqlite3.OperationalError as exc:
            if not _is_busy(exc):
                raise
            busy = True
        if time.monotonic() >= deadline:
            if busy:
                raise StoreBusyError("state.db is busy")
            raise _fail("state.db cannot use the WAL journal here")
        attempt += 1
        time.sleep(min(0.005 * attempt, 0.05))


def is_not_a_database(exc: sqlite3.Error) -> bool:
    """Whether SQLite reported ``file is not a database`` (an invalid or damaged header)."""
    return _primary(exc) == _SQLITE_NOTADB


def parse_schema_version(value: object) -> int | None:
    """The stored ``schema_version`` as a number, or None when it is not a usable one (< 1)."""
    number = _parse_int(value)
    return number if number is not None and number >= 1 else None


def db_verdict(history: bool, version: int | None | bool) -> str | None:
    """How the store judges a ``state.db`` whose schema version is ``version`` (``None`` for a
    missing or empty file, ``False`` for one with no ``meta.schema_version`` row or not SQLite's)
    next to an audit history: ``"state_db_missing"`` (a history and no usable schema),
    ``"not_gatectl"`` (a foreign or damaged file, history or not), or None (nothing to refuse
    here). ``open_store`` and ``validate`` both decide through this function."""
    if isinstance(version, int) and not isinstance(version, bool):
        return None
    if history:
        return "state_db_missing"
    return "not_gatectl" if version is False else None


def _refuse_missing(history: bool) -> None:
    if db_verdict(history, None) == "state_db_missing":
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
    history = has_history(base)
    ident = _vet_file(path)
    if ident is None:
        _refuse_missing(history)
        if not create:
            return None
        try:
            fd = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
            )
        except FileExistsError:
            pass  # another creator won the race: vet the file that is there now
        except OSError:
            raise _fail("state.db cannot be created safely") from None
        else:
            os.close(fd)
        ident = _vet_file(path)
        if ident is None:
            raise _fail("state.db cannot be created safely")
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
        con = sqlite3.connect(
            _uri(path, mode), uri=True, timeout=busy_timeout, isolation_level=None
        )
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
            _ensure_wal(con, busy_timeout)
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
