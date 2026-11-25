"""The audit line inside the decision's transaction, and the store under real concurrency.

interface.md, Audit and log: the record is appended inside the transaction that inserts the
decision, before the commit, so a returned decision always has an audit line; a crash (or a failed
commit) can leave a line for a decision that did not commit, never the reverse.
"""

from __future__ import annotations

import errno
import json
import multiprocessing
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

from gatectl import audit, ids, store
from gatectl.errors import InternalError

FP = "sha256:" + "a" * 64
TS = "2026-01-02T03:04:05Z"


@pytest.fixture
def sdir(tmp_path: Path) -> Path:
    return tmp_path / "state" / "gatectl"


def opened(sdir: Path, **kw: Any) -> store.Store:
    s = store.open_store(sdir, create=True, **kw)
    assert s is not None
    return s


def record(
    decision_id: str, reason: str = "all_passed", target: str = "p@*", pad: int = 0
) -> dict[str, Any]:
    return audit.audit_record(
        action="decision",
        target=target,
        decision_id=decision_id,
        actor="auto:t",
        stdin_tty=False,
        actor_source="default",
        inputs={"policy": "p", "fingerprint": FP, "pad": "x" * pad},
        result={"decision": "allow", "reason": reason, "state": "shadow"},
        ts=TS,
    )


def insert(s: store.Store, decision_id: str) -> None:
    s.con.execute(
        "INSERT INTO decisions(id, time, policy, scope, fingerprint, state, decision, reason,"
        " actor) VALUES(?, ?, 'p', '*', ?, 'shadow', 'allow', 'all_passed', 'auto:t')",
        (decision_id, TS, FP),
    )


def decide(s: store.Store, decision_id: str, reason: str = "all_passed", pad: int = 0) -> None:
    """What step 8 does: insert the row, append the audit line (the commit is ``transact``'s)."""

    def body() -> None:
        insert(s, decision_id)
        s.append_audit(record(decision_id, reason, pad=pad))

    s.transact(body)


def lines(sdir: Path) -> list[bytes]:
    path = sdir / "audit.jsonl"
    return path.read_bytes().splitlines(keepends=True) if path.exists() else []


def line_ids(sdir: Path) -> list[str]:
    return [json.loads(x)["decision_id"] for x in lines(sdir)]


def row_ids(sdir: Path) -> list[str]:
    reader = store.open_store(sdir, create=False)
    assert reader is not None
    with reader:
        return [r[0] for r in reader.con.execute("SELECT id FROM decisions ORDER BY id")]


def assert_no_line_without_row_only_the_other_way(sdir: Path) -> None:
    """Every committed row has its line (the reverse is allowed: a crash can leave a line)."""
    assert set(row_ids(sdir)) <= set(line_ids(sdir))


# --- ordering ------------------------------------------------------------------------------------


def test_the_audit_line_is_on_disk_before_the_commit(sdir: Path) -> None:
    s = opened(sdir)
    did = ids.new_decision_id()
    seen: dict[str, Any] = {}

    def body() -> None:
        insert(s, did)
        s.append_audit(record(did))
        seen["lines_before_commit"] = line_ids(sdir)
        seen["rows_before_commit"] = row_ids(sdir)  # an independent reader connection

    s.transact(body)
    assert seen["lines_before_commit"] == [did]
    assert seen["rows_before_commit"] == []
    assert row_ids(sdir) == [did]
    assert line_ids(sdir) == [did]
    s.close()


def test_a_rolled_back_transaction_can_leave_a_line_never_the_reverse(sdir: Path) -> None:
    s = opened(sdir)
    did = ids.new_decision_id()

    def body() -> None:
        insert(s, did)
        s.append_audit(record(did))
        raise RuntimeError("the caller failed after the audit append")

    with pytest.raises(RuntimeError):
        s.transact(body)
    assert line_ids(sdir) == [did]  # the line stays
    assert row_ids(sdir) == []  # the row never committed
    assert not s.con.in_transaction
    s.close()


def test_a_commit_that_fails_after_the_line_leaves_the_line_and_no_row(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = opened(sdir)
    did = ids.new_decision_id()

    def failing_commit(self: store.Store) -> None:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(store.Store, "_commit", failing_commit)
    with pytest.raises(InternalError) as info:
        decide(s, did)
    assert info.value.exit_code == 1
    assert "disk I/O" not in str(info.value)  # fixed text, never the driver's
    monkeypatch.undo()
    assert line_ids(sdir) == [did]
    assert row_ids(sdir) == []
    assert not s.con.in_transaction
    # the store is still usable afterwards
    later = ids.new_decision_id()
    decide(s, later)
    assert row_ids(sdir) == [later]
    assert_no_line_without_row_only_the_other_way(sdir)
    s.close()


def test_a_busy_commit_is_not_retried_so_a_decision_is_never_audited_twice(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = opened(sdir)
    calls: list[str] = []

    def busy_commit(self: store.Store) -> None:
        exc = sqlite3.OperationalError("database is locked")
        exc.sqlite_errorcode = sqlite3.SQLITE_BUSY
        raise exc

    monkeypatch.setattr(store.Store, "_commit", busy_commit)
    did = ids.new_decision_id()

    def body() -> None:
        calls.append("body")
        insert(s, did)
        s.append_audit(record(did))

    with pytest.raises(store.StoreBusyError):
        s.transact(body)
    assert calls == ["body"]
    assert line_ids(sdir) == [did]
    s.close()


def test_the_first_transaction_finds_the_schema_already_committed(sdir: Path) -> None:
    """Schema creation commits before any audit line is appended (so state_db_missing can only
    come from outside gatectl)."""
    s = opened(sdir)
    assert not (sdir / "audit.jsonl").exists()
    assert s.schema_version() == store.latest_version()
    assert not s.con.in_transaction
    s.close()


def test_a_failed_first_audit_append_keeps_the_schema_and_no_history(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = opened(sdir)

    def full(fd: int, data: bytes) -> int:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(audit, "_write", full)
    with pytest.raises(InternalError):
        decide(s, ids.new_decision_id())
    s.close()
    monkeypatch.undo()
    assert lines(sdir) == [] or (sdir / "audit.jsonl").stat().st_size == 0
    again = opened(sdir)  # a schema and no history: opens, no state_db_missing
    assert again.schema_version() == store.latest_version()
    again.close()


# --- a failed audit append -----------------------------------------------------------------------


def test_a_full_disk_fails_the_transaction_and_writes_nothing(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = opened(sdir)
    first = ids.new_decision_id()
    decide(s, first)
    before = (sdir / "audit.jsonl").read_bytes()

    def full(fd: int, data: bytes) -> int:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(audit, "_write", full)
    with pytest.raises(store.AuditWriteError) as info:
        decide(s, ids.new_decision_id())
    assert isinstance(info.value, InternalError)
    assert info.value.exit_code == 1
    assert "space" not in str(info.value).lower()
    monkeypatch.undo()
    assert (sdir / "audit.jsonl").read_bytes() == before
    assert row_ids(sdir) == [first]
    assert not s.con.in_transaction
    s.close()


def test_a_short_write_keeps_the_partial_line_and_fails_the_transaction(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = opened(sdir)
    first = ids.new_decision_id()
    decide(s, first)
    good = (sdir / "audit.jsonl").read_bytes()
    real = os.write

    def half(fd: int, data: bytes) -> int:
        return real(fd, data[: len(data) // 2])

    monkeypatch.setattr(audit, "_write", half)
    with pytest.raises(store.AuditWriteError):
        decide(s, ids.new_decision_id())
    monkeypatch.undo()
    after = (sdir / "audit.jsonl").read_bytes()
    assert after.startswith(good)  # never truncated, earlier lines intact and parseable
    assert len(after) > len(good)  # the partial line stays
    assert [json.loads(x)["decision_id"] for x in good.splitlines()] == [first]
    assert row_ids(sdir) == [first]
    s.close()


def test_a_read_only_audit_file_fails_the_transaction(sdir: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores file modes")
    s = opened(sdir)
    first = ids.new_decision_id()
    decide(s, first)
    path = sdir / "audit.jsonl"
    before = path.read_bytes()
    os.chmod(path, 0o400)
    try:
        with pytest.raises(store.AuditWriteError):
            decide(s, ids.new_decision_id())
    finally:
        os.chmod(path, 0o600)
    assert path.read_bytes() == before
    assert row_ids(sdir) == [first]
    s.close()


def test_an_audit_file_that_is_a_directory_fails_the_transaction(
    sdir: Path,
) -> None:
    """``audit.jsonl`` is a directory: the append is refused and the row never commits."""
    s = opened(sdir)
    (sdir / "audit.jsonl").mkdir()
    with pytest.raises(store.AuditWriteError):
        decide(s, ids.new_decision_id())
    assert row_ids(sdir) == []
    s.close()


def test_a_record_too_large_even_without_free_text_writes_nothing(sdir: Path) -> None:
    s = opened(sdir)
    did = ids.new_decision_id()
    huge = record(did, target="p@" + "x" * (audit.LINE_CAP + 10))
    insert_then = []

    def body() -> None:
        insert(s, did)
        insert_then.append(1)
        s.append_audit(huge)

    with pytest.raises(store.AuditWriteError):
        s.transact(body)
    assert not (sdir / "audit.jsonl").exists() or (sdir / "audit.jsonl").stat().st_size == 0
    assert row_ids(sdir) == []
    s.close()


def test_append_audit_outside_a_transaction_or_on_a_reader_is_refused(sdir: Path) -> None:
    s = opened(sdir)
    with pytest.raises(RuntimeError):
        s.append_audit(record(ids.new_decision_id()))
    s.close()
    reader = store.open_store(sdir, create=False)
    assert reader is not None
    with pytest.raises(RuntimeError):
        reader.append_audit(record(ids.new_decision_id()))
    reader.close()
    assert lines(sdir) == []


# --- the lock wait and the single retry ----------------------------------------------------------


def test_a_lock_timeout_retries_the_whole_transaction_once(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = opened(sdir)
    real = store.Store._begin
    attempts: list[int] = []
    bodies: list[int] = []

    def flaky(self: store.Store) -> None:
        attempts.append(1)
        if len(attempts) == 1:
            raise store.StoreBusyError("state.db is busy")
        real(self)

    monkeypatch.setattr(store.Store, "_begin", flaky)

    def body() -> str:
        bodies.append(1)
        return "done"

    assert s.transact(body) == "done"
    assert len(attempts) == 2 and len(bodies) == 1
    s.close()


def test_two_lock_timeouts_fail_and_the_body_never_runs(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = opened(sdir)
    attempts: list[int] = []

    def never(self: store.Store) -> None:
        attempts.append(1)
        raise store.StoreBusyError("state.db is busy")

    monkeypatch.setattr(store.Store, "_begin", never)
    with pytest.raises(store.StoreBusyError):
        s.transact(lambda: pytest.fail("the body must not run without the lock"))
    assert len(attempts) == 2  # one retry, no more
    s.close()


def test_a_busy_error_inside_the_body_is_not_retried(sdir: Path) -> None:
    s = opened(sdir)
    bodies: list[int] = []

    def body() -> None:
        bodies.append(1)
        raise store.StoreBusyError("state.db is busy")

    with pytest.raises(store.StoreBusyError):
        s.transact(body)
    assert bodies == [1]
    s.close()


def test_the_retry_re_reads_state_by_running_the_body_again(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The body of the second attempt starts a fresh transaction (nothing carried over)."""
    s = opened(sdir)
    real = store.Store._begin
    n = {"begin": 0}

    def flaky(self: store.Store) -> None:
        n["begin"] += 1
        if n["begin"] == 1:
            raise store.StoreBusyError("state.db is busy")
        real(self)

    monkeypatch.setattr(store.Store, "_begin", flaky)
    seen: list[bool] = []
    s.transact(lambda: seen.append(s.con.in_transaction))
    assert seen == [True]
    s.close()


def _holder(directory: str, held: Any, release: Any) -> None:
    s = store.open_store(Path(directory), create=True)
    assert s is not None
    with s.write():
        held.set()
        release.wait(60)
    s.close()


def _reap(procs: list[Any]) -> None:
    for p in procs:
        if p.is_alive():
            p.kill()  # exactly the Process objects this test started
        p.join(10)


def test_a_held_lock_costs_at_most_two_bounded_waits(sdir: Path) -> None:
    opened(sdir).close()
    ctx = multiprocessing.get_context("spawn")
    held, release = ctx.Event(), ctx.Event()
    proc = ctx.Process(target=_holder, args=(str(sdir), held, release))
    try:
        proc.start()
        assert held.wait(60)
        s = opened(sdir, busy_timeout=0.3)
        start = time.monotonic()
        with pytest.raises(store.StoreBusyError):
            s.transact(lambda: pytest.fail("no lock"))
        elapsed = time.monotonic() - start
        assert 0.5 <= elapsed < 5.0  # about 2 x 0.3; the holder lasts up to 60 s, so not unbounded
        s.close()
    finally:
        release.set()
        proc.join(30)
        _reap([proc])


_LOCK_WAIT = 1.0  # busy_timeout of the waiting store
_RELEASE_AFTER = 1.5  # the holder releases mid-way through the second wait window (1.0 .. 2.0)


def _release_later(directory: str, held: Any, delay: float) -> None:
    s = store.open_store(Path(directory), create=True)
    assert s is not None
    with s.write():
        held.set()
        time.sleep(delay)
    s.close()


def test_a_lock_freed_during_the_second_attempt_lets_the_transaction_succeed(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened(sdir).close()
    ctx = multiprocessing.get_context("spawn")
    held = ctx.Event()
    proc = ctx.Process(target=_release_later, args=(str(sdir), held, _RELEASE_AFTER))
    try:
        proc.start()
        assert held.wait(60)
        s = opened(sdir, busy_timeout=_LOCK_WAIT)
        real = store.Store._begin
        begins: list[int] = []

        def counting(self: store.Store) -> None:
            begins.append(1)
            real(self)

        monkeypatch.setattr(store.Store, "_begin", counting)
        did = ids.new_decision_id()
        decide(s, did)
        assert len(begins) == 2  # the first wait timed out; the success is the retry's
        assert row_ids(sdir) == [did]
        s.close()
    finally:
        proc.join(30)
        _reap([proc])


# --- real processes ------------------------------------------------------------------------------


def _decider(
    directory: str, worker: int, count: int, pad: int, busy: float, out: Any, barrier: Any
) -> None:
    errors: list[str] = []
    made: list[str] = []
    try:
        barrier.wait(60)  # every caller starts together
        s = store.open_store(Path(directory), create=True, busy_timeout=busy)
        assert s is not None
        for _ in range(count):
            did = ids.new_decision_id()
            reason = chr(0x4E00 + worker) * 1000  # non-ASCII: escaped, six bytes a character
            try:
                decide(s, did, reason, pad=pad)
                made.append(did)
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
        s.close()
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    out.put((worker, made, errors))


def _run_deciders(
    sdir: Path, workers: int, count: int, pad: int, busy: float
) -> tuple[list[str], list[str]]:
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    barrier = ctx.Barrier(workers)
    procs = [
        ctx.Process(target=_decider, args=(str(sdir), w, count, pad, busy, out, barrier))
        for w in range(workers)
    ]
    try:
        for p in procs:
            p.start()
        results = [out.get(timeout=240) for _ in procs]
        for p in procs:
            p.join(30)
    finally:
        _reap(procs)
    assert [p.exitcode for p in procs] == [0] * workers
    made = [d for _, ds, _ in results for d in ds]
    errors = [e for _, _, es in results for e in es]
    return made, errors


def test_eight_concurrent_writers_lose_and_tear_no_audit_lines_up_to_64k(sdir: Path) -> None:
    opened(sdir).close()
    workers, count = 8, 6
    made, errors = _run_deciders(sdir, workers, count, pad=50_000, busy=60.0)
    assert errors == []
    raw = lines(sdir)
    assert len(raw) == workers * count
    assert all(x.endswith(b"\n") for x in raw)
    assert all(len(x) <= audit.LINE_CAP for x in raw)
    assert max(len(x) for x in raw) > 55_000  # the lines really were near the cap
    parsed = [json.loads(x) for x in raw]  # every line is whole
    assert sorted(p["decision_id"] for p in parsed) == sorted(made)
    assert sorted(row_ids(sdir)) == sorted(made)
    s = opened(sdir)
    assert s.con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    s.close()


def _appender(directory: str, worker: int, count: int, out: Any, barrier: Any) -> None:
    """Append audit lines directly, with no database lock to serialize the writers."""
    made: list[str] = []
    errors: list[str] = []
    try:
        barrier.wait(60)
        for i in range(count):
            did = ids.new_decision_id()
            pad = (worker * count + i) * 6_000 % 52_000 + 100  # sizes spread up to ~64 KiB
            audit.append_audit(record(did, pad=pad), state_dir=Path(directory))
            made.append(did)
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
    out.put((worker, made, errors))


def test_eight_processes_appending_without_a_lock_lose_and_tear_no_lines(sdir: Path) -> None:
    sdir.mkdir(parents=True, mode=0o700)
    workers, count = 8, 12
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    barrier = ctx.Barrier(workers)
    procs = [
        ctx.Process(target=_appender, args=(str(sdir), w, count, out, barrier))
        for w in range(workers)
    ]
    try:
        for p in procs:
            p.start()
        results = [out.get(timeout=240) for _ in procs]
        for p in procs:
            p.join(30)
    finally:
        _reap(procs)
    assert [p.exitcode for p in procs] == [0] * workers
    assert [e for _, _, es in results for e in es] == []
    made = [d for _, ds, _ in results for d in ds]
    raw = lines(sdir)
    assert len(raw) == workers * count
    assert all(x.endswith(b"\n") and len(x) <= audit.LINE_CAP for x in raw)
    assert max(len(x) for x in raw) > 50_000
    assert sorted(json.loads(x)["decision_id"] for x in raw) == sorted(made)


def test_sixteen_concurrent_first_callers_never_leak_database_is_locked(sdir: Path) -> None:
    # no state directory at all: the callers also race to create it
    made, errors = _run_deciders(sdir, 16, 3, pad=200, busy=60.0)
    assert errors == []
    assert not any("locked" in e for e in errors)
    assert sorted(row_ids(sdir)) == sorted(made)
    assert sorted(line_ids(sdir)) == sorted(made)
    assert len(made) == 48


def test_sixteen_callers_with_the_default_wait_fail_only_as_busy_never_as_locked(
    sdir: Path,
) -> None:
    opened(sdir).close()
    made, errors = _run_deciders(sdir, 16, 3, pad=200, busy=store.DEFAULT_BUSY_TIMEOUT)
    assert all("locked" not in e for e in errors)
    assert all(e.startswith("StoreBusyError: state.db is busy") for e in errors)
    # every committed row has its line; a busy failure wrote nothing
    assert sorted(row_ids(sdir)) == sorted(made)
    assert set(made) <= set(line_ids(sdir))


def _crash_between_audit_and_commit(directory: str, did: str, code: int) -> None:
    """A writer that dies (``os._exit``) exactly between the audit append and the commit."""
    s = store.open_store(Path(directory), create=True)
    assert s is not None

    def die(self: store.Store) -> None:
        os._exit(code)

    store.Store._commit = die  # type: ignore[method-assign]  # this child process only
    decide(s, did)


def test_a_writer_that_dies_between_the_audit_append_and_the_commit(sdir: Path) -> None:
    survivor = ids.new_decision_id()
    s = opened(sdir)
    decide(s, survivor)
    s.close()
    victim = ids.new_decision_id()
    ctx = multiprocessing.get_context("spawn")
    proc = ctx.Process(target=_crash_between_audit_and_commit, args=(str(sdir), victim, 77))
    try:
        proc.start()
        proc.join(60)
    finally:
        _reap([proc])
    assert proc.exitcode == 77
    assert victim in line_ids(sdir)  # a line for a decision that did not commit
    assert row_ids(sdir) == [survivor]  # never the reverse
    # the dead writer's lock is gone: the next writer proceeds at once
    again = opened(sdir, busy_timeout=2.0)
    later = ids.new_decision_id()
    decide(again, later)
    assert row_ids(sdir) == sorted([survivor, later])
    assert again.con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    again.close()
    assert_no_line_without_row_only_the_other_way(sdir)


def _hold_uncommitted(directory: str, held: Any) -> None:
    s = store.open_store(Path(directory), create=True)
    assert s is not None
    with s.write():
        insert(s, "gd-aaaaaaaaaaaa")
        s.append_audit(record("gd-aaaaaaaaaaaa"))
        held.set()
        time.sleep(120)


def test_a_stale_lock_of_a_killed_writer_is_released_and_its_work_discarded(sdir: Path) -> None:
    opened(sdir).close()
    ctx = multiprocessing.get_context("spawn")
    held = ctx.Event()
    proc = ctx.Process(target=_hold_uncommitted, args=(str(sdir), held))
    try:
        proc.start()
        assert held.wait(60)
        # while it lives, a second writer waits out its bound and fails as busy
        blocked = opened(sdir, busy_timeout=0.2)
        with pytest.raises(store.StoreBusyError):
            blocked.transact(lambda: None)
        blocked.close()
        proc.kill()  # exactly the process this test started
        proc.join(30)
    finally:
        _reap([proc])
    assert proc.exitcode is not None and proc.exitcode < 0
    s = opened(sdir, busy_timeout=2.0)
    did = ids.new_decision_id()
    decide(s, did)
    assert row_ids(sdir) == [did]  # the killed writer's uncommitted row is gone
    assert "gd-aaaaaaaaaaaa" in line_ids(sdir)  # its line remains
    s.close()


# --- hardening -----------------------------------------------------------------------------------


@pytest.mark.parametrize("bad", [{(1, 2): "tuple key"}, float("nan")], ids=["non_str_key", "nan"])
def test_a_record_the_encoder_rejects_fails_as_an_audit_write_error(sdir: Path, bad: Any) -> None:
    s = opened(sdir)
    did = ids.new_decision_id()
    rec = record(did)
    rec["inputs"]["pad"] = bad

    def body() -> None:
        insert(s, did)
        s.append_audit(rec)

    with pytest.raises(store.AuditWriteError) as info:
        s.transact(body)
    assert info.value.exit_code == 1
    assert info.value.__cause__ is None and info.value.__suppress_context__
    assert str(info.value) == "audit.jsonl cannot be written"
    assert row_ids(sdir) == []
    assert lines(sdir) == []
    assert not s.con.in_transaction
    s.close()


def test_an_interrupt_during_the_commit_rolls_back_and_leaves_the_store_usable(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = opened(sdir)

    def interrupted(self: store.Store) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(store.Store, "_commit", interrupted)
    with pytest.raises(KeyboardInterrupt):
        decide(s, ids.new_decision_id())
    monkeypatch.undo()
    assert not s.con.in_transaction
    did = ids.new_decision_id()
    decide(s, did)  # no "a transaction is already open"
    assert row_ids(sdir) == [did]
    s.close()


def test_a_nested_transact_is_refused_not_retried_and_the_outer_one_rolls_back(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    s = opened(sdir)
    real = store.Store._begin
    begins: list[int] = []

    def counting(self: store.Store) -> None:
        begins.append(1)
        real(self)

    monkeypatch.setattr(store.Store, "_begin", counting)
    did = ids.new_decision_id()

    def body() -> None:
        insert(s, did)
        s.transact(lambda: None)

    with pytest.raises(RuntimeError, match="already open"):
        s.transact(body)
    assert len(begins) == 1
    assert row_ids(sdir) == []
    assert not s.con.in_transaction
    later = ids.new_decision_id()
    decide(s, later)
    assert row_ids(sdir) == [later]
    s.close()


def test_the_line_after_a_partial_line_is_concatenated_onto_it_known_behavior(
    sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Documented known behavior pending a maintainer decision on audit line framing.

    A short write leaves a partial line without a newline; the next writer appends with
    ``O_APPEND`` right after it, so that decision's line is fused onto the partial one and is lost
    to a reader together with it. Earlier lines stay parseable and nothing is truncated. This test
    pins the current behavior; it does not endorse it.
    """
    s = opened(sdir)
    first, failed, third = (ids.new_decision_id() for _ in range(3))
    decide(s, first)
    good = (sdir / "audit.jsonl").read_bytes()
    real = os.write

    def half(fd: int, data: bytes) -> int:
        return real(fd, data[: len(data) // 2])

    monkeypatch.setattr(audit, "_write", half)
    with pytest.raises(store.AuditWriteError):
        decide(s, failed)
    monkeypatch.undo()
    partial = (sdir / "audit.jsonl").read_bytes()[len(good) :]
    assert partial and not partial.endswith(b"\n")
    decide(s, third)
    raw = lines(sdir)
    assert len(raw) == 2  # the third decision's line shares a physical line with the partial one
    assert (sdir / "audit.jsonl").read_bytes().startswith(good + partial)  # nothing truncated
    assert json.loads(raw[0])["decision_id"] == first
    with pytest.raises(ValueError):
        json.loads(raw[1])
    assert row_ids(sdir) == sorted([first, third])  # the decision itself committed
    s.close()


# --- state_db_missing creates nothing ------------------------------------------------------------


def _history(sdir: Path) -> None:
    sdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    (sdir / "audit.jsonl").write_bytes(b'{"ts":"x"}\n')


@pytest.mark.parametrize("state", ["missing", "empty", "schemaless"])
def test_state_db_missing_is_exit_1_and_creates_nothing(sdir: Path, state: str) -> None:
    _history(sdir)
    if state == "empty":
        (sdir / "state.db").write_bytes(b"")
        os.chmod(sdir / "state.db", 0o600)
    elif state == "schemaless":
        con = sqlite3.connect(sdir / "state.db")
        con.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")
        con.commit()
        con.close()
        os.chmod(sdir / "state.db", 0o600)
    before = {p.name: p.stat().st_size for p in sdir.iterdir()}
    for create in (True, False):
        with pytest.raises(InternalError) as info:
            store.open_store(sdir, create=create)
        assert info.value.exit_code == 1
        assert info.value.code == "internal"
        assert info.value.reason == "state_db_missing"
    assert {p.name: p.stat().st_size for p in sdir.iterdir()} == before
