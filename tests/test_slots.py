"""Agent slot leases (interface.md, Agent checks: Slots; Deadline step 3)."""

from __future__ import annotations

import multiprocessing
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from gatectl import clock, procinfo, slots, store
from tests.proc_util import Tracker

NOW = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
LATER = NOW + timedelta(seconds=90)
D1 = "gd-aaaaaaaaaaaa"
D2 = "gd-bbbbbbbbbbbb"
D3 = "gd-cccccccccccc"
D4 = "gd-dddddddddddd"


@pytest.fixture
def sdir(tmp_path: Path) -> Path:
    return tmp_path / "state" / "gatectl"


@pytest.fixture
def st(sdir: Path) -> Iterator[store.Store]:
    s = store.open_store(sdir, create=True)
    assert s is not None
    yield s
    s.close()


def insert_raw(
    s: store.Store,
    *,
    pid: Any,
    start: Any,
    boot: Any,
    decision: Any = D1,
    csession: Any = None,
    started: Any = "2026-03-04T05:06:07.000000Z",
    expires: Any = "2026-03-04T05:08:07.000000Z",
) -> None:
    with s.write():
        s.con.execute(
            "INSERT INTO agent_slots(holder_pid, holder_start, boot_id, decision_id, csession_id,"
            " started_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (pid, start, boot, decision, csession, started, expires),
        )


def count(s: store.Store) -> int:
    return int(s.con.execute("SELECT COUNT(*) FROM agent_slots").fetchone()[0])


def me() -> tuple[int, str, str]:
    start = procinfo.start_time(os.getpid())
    assert start is not None
    return os.getpid(), start, procinfo.boot_id()


def acquire(s: store.Store, decision: str = D1, cap: int = 3) -> slots.Slot | None:
    return slots.try_acquire(s, decision_id=decision, max_parallel=cap, expires_at=LATER, now=NOW)


def dead_pid() -> int:
    """The pid of a child that has exited and been reaped (no process has it now, barring reuse)."""
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


# --- procinfo -------------------------------------------------------------------------------


def test_proc_state_of_this_process_is_running_or_sleeping() -> None:
    assert procinfo.proc_state(os.getpid()) in {"R", "S"}
    assert procinfo.is_zombie(os.getpid()) is False


def test_proc_state_of_a_missing_pid_is_none() -> None:
    assert procinfo.proc_state(dead_pid()) is None
    assert procinfo.is_zombie(dead_pid()) is False


def test_proc_state_survives_a_command_name_with_parentheses_and_spaces(tmp_path: Path) -> None:
    # /proc/<pid>/stat holds the name between the first "(" and the LAST ")"
    script = tmp_path / "x"
    script.write_text("import time\ntime.sleep(30)\n")
    link = tmp_path / "a) Z 1 (b"
    os.symlink(sys.executable, link)
    child = subprocess.Popen([str(link), str(script)])
    try:
        deadline = time.monotonic() + 10
        while procinfo.start_time(child.pid) is None and time.monotonic() < deadline:
            time.sleep(0.01)
        assert procinfo.proc_state(child.pid) in {"R", "S"}
        assert procinfo.start_time(child.pid) is not None
    finally:
        child.kill()
        child.wait()


# --- liveness -------------------------------------------------------------------------------


def test_the_current_process_is_a_live_holder() -> None:
    pid, start, boot = me()
    assert slots.holder_alive(pid, start, boot)


def test_a_dead_pid_is_not_alive() -> None:
    _, start, boot = me()
    assert not slots.holder_alive(dead_pid(), start, boot)


def test_a_changed_start_time_is_not_alive() -> None:
    pid, start, boot = me()
    assert not slots.holder_alive(pid, str(int(start) + 1), boot)


def test_a_changed_boot_id_is_not_alive() -> None:
    pid, start, _ = me()
    assert not slots.holder_alive(pid, start, "00000000-0000-0000-0000-000000000000")


def test_an_empty_recorded_boot_id_or_start_is_never_alive() -> None:
    pid, start, boot = me()
    assert not slots.holder_alive(pid, start, "")
    assert not slots.holder_alive(pid, "", boot)


@pytest.mark.parametrize("pid", [0, -1, True, "1", None, 2**70])
def test_a_nonsense_pid_is_not_alive(pid: Any) -> None:
    _, start, boot = me()
    assert not slots.holder_alive(pid, start, boot)


def test_a_zombie_holder_is_not_alive() -> None:
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    try:
        deadline = time.monotonic() + 10
        while procinfo.proc_state(child.pid) != "Z" and time.monotonic() < deadline:
            time.sleep(0.01)  # exited, not yet reaped: a zombie
        assert procinfo.is_zombie(child.pid)
        start = procinfo.start_time(child.pid)
        assert start is not None  # the stat file is still readable
        assert not slots.holder_alive(child.pid, start, procinfo.boot_id())
    finally:
        child.wait()


# --- acquire --------------------------------------------------------------------------------


def test_acquire_inserts_a_row_with_this_process_as_holder(st: store.Store) -> None:
    slot = acquire(st)
    assert slot is not None
    pid, start, boot = me()
    assert (slot.pid, slot.start, slot.boot_id, slot.decision_id) == (pid, start, boot, D1)
    row = st.con.execute(
        "SELECT holder_pid, holder_start, boot_id, decision_id, csession_id, started_at,"
        " expires_at FROM agent_slots"
    ).fetchall()
    assert row == [
        (pid, start, boot, D1, None, "2026-03-04T05:06:07.000000Z", "2026-03-04T05:07:37.000000Z")
    ]


def test_acquire_fails_when_max_parallel_live_holders_exist(st: store.Store) -> None:
    pid, start, boot = me()
    for i in range(2):
        insert_raw(st, pid=pid, start=start, boot=boot, decision=f"gd-{'a' * 11}{'xy'[i]}")
    assert acquire(st, D3, cap=2) is None
    assert count(st) == 2
    assert acquire(st, D3, cap=3) is not None
    assert count(st) == 3


def test_the_cap_is_the_acquiring_processs_own(st: store.Store) -> None:
    pid, start, boot = me()
    insert_raw(st, pid=pid, start=start, boot=boot)
    assert acquire(st, D2, cap=1) is None
    assert acquire(st, D2, cap=2) is not None


@pytest.mark.parametrize("cap", [0, -1, 33, True, 2.0, "3", None])
def test_a_bad_cap_is_refused(st: store.Store, cap: Any) -> None:
    with pytest.raises(ValueError):
        slots.try_acquire(st, decision_id=D1, max_parallel=cap, expires_at=LATER, now=NOW)
    assert count(st) == 0


@pytest.mark.parametrize(
    "decision", ["", "gd-AAAAAAAAAAAA", "gd-aaaa", "x" * 500, "gd-aaaaaaaaaaaa\n"]
)
def test_a_bad_decision_id_is_refused(st: store.Store, decision: str) -> None:
    with pytest.raises(ValueError):
        acquire(st, decision)
    assert count(st) == 0


def test_a_dead_pid_row_frees_the_slot(st: store.Store) -> None:
    _, start, boot = me()
    insert_raw(st, pid=dead_pid(), start=start, boot=boot)
    assert acquire(st, D2, cap=1) is not None
    assert count(st) == 1  # the dead row was deleted, the new one inserted


def test_a_zombie_row_frees_the_slot(st: store.Store) -> None:
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    try:
        deadline = time.monotonic() + 10
        while procinfo.proc_state(child.pid) != "Z" and time.monotonic() < deadline:
            time.sleep(0.01)
        start = procinfo.start_time(child.pid)
        assert start is not None
        insert_raw(st, pid=child.pid, start=start, boot=procinfo.boot_id())
        assert acquire(st, D2, cap=1) is not None
        assert count(st) == 1
    finally:
        child.wait()


def test_a_changed_start_time_row_frees_the_slot(st: store.Store) -> None:
    pid, start, boot = me()
    insert_raw(st, pid=pid, start=str(int(start) - 5), boot=boot)  # a reused pid
    assert acquire(st, D2, cap=1) is not None
    assert count(st) == 1


def test_a_changed_boot_id_row_frees_the_slot(st: store.Store) -> None:
    pid, start, _ = me()
    insert_raw(st, pid=pid, start=start, boot="11111111-1111-1111-1111-111111111111")
    assert acquire(st, D2, cap=1) is not None
    assert count(st) == 1


def test_a_live_holder_past_expires_at_is_never_freed(st: store.Store) -> None:
    pid, start, boot = me()
    insert_raw(st, pid=pid, start=start, boot=boot, expires="2001-01-01T00:00:00.000000Z")
    far = NOW + timedelta(days=3650)
    assert slots.try_acquire(st, decision_id=D2, max_parallel=1, expires_at=far, now=far) is None
    assert count(st) == 1


def test_a_clock_step_backwards_or_forwards_never_frees_a_live_holder(st: store.Store) -> None:
    pid, start, boot = me()
    insert_raw(st, pid=pid, start=start, boot=boot)
    for moment in (NOW - timedelta(days=400), NOW + timedelta(days=400)):
        assert (
            slots.try_acquire(st, decision_id=D2, max_parallel=1, expires_at=moment, now=moment)
            is None
        )
    assert count(st) == 1


@pytest.mark.parametrize(
    "bad",
    [
        {"pid": "12", "start": "1", "boot": "b"},  # pid stored as text
        {"pid": 1.5, "start": "1", "boot": "b"},
        {"pid": -4, "start": "1", "boot": "b"},
        {"pid": 0, "start": "1", "boot": "b"},
        {"pid": 1, "start": b"1", "boot": "b"},  # blob
        {"pid": 1, "start": "1" * 5000, "boot": "b" * 5000},
        {"pid": 1, "start": "1", "boot": "b", "decision": "not-a-decision-id"},
    ],
)
def test_a_tampered_row_never_counts_and_is_removed(st: store.Store, bad: dict[str, Any]) -> None:
    # A row nobody can recognise is not a live holder; it is dropped, not trusted, and the text
    # of it is never echoed anywhere.
    with st.write():
        st.con.execute(
            "INSERT INTO agent_slots(holder_pid, holder_start, boot_id, decision_id, started_at,"
            " expires_at) VALUES (?, ?, ?, ?, 'x', 'y')",
            (
                bad["pid"],
                bad["start"],
                bad["boot"],
                bad.get("decision", D1) if "decision" in bad else D1,
            ),
        )
    assert acquire(st, D2, cap=1) is not None
    assert count(st) == 1


def test_a_row_with_bad_timestamps_but_a_live_holder_still_counts(st: store.Store) -> None:
    # expires_at is informational: garbage in it must not free a live holder (the count is
    # what bounds the agent runs)
    pid, start, boot = me()
    insert_raw(st, pid=pid, start=start, boot=boot, expires="garbage", started="also garbage")
    assert acquire(st, D2, cap=1) is None
    assert count(st) == 1


def test_dead_rows_are_deleted_even_when_the_acquire_fails(st: store.Store) -> None:
    pid, start, boot = me()
    insert_raw(st, pid=pid, start=start, boot=boot)
    insert_raw(st, pid=dead_pid(), start="1", boot=boot, decision=D3)
    assert acquire(st, D2, cap=1) is None
    assert count(st) == 1


def test_acquire_works_in_a_store_with_the_slot_table_full_of_dead_rows(st: store.Store) -> None:
    _, _, boot = me()
    for i in range(200):
        insert_raw(st, pid=2**22 + i, start="1", boot=boot)
    assert acquire(st, D2, cap=1) is not None
    assert count(st) == 1


# --- csession, renew, release ---------------------------------------------------------------


def test_set_csession_updates_only_the_own_row(st: store.Store) -> None:
    pid, start, boot = me()
    insert_raw(st, pid=pid, start=start, boot=boot, decision=D3)  # another run of this process
    slot = acquire(st, D1)
    assert slot is not None
    assert slots.set_csession(st, slot, "cs-abc123") is True
    got = dict(st.con.execute("SELECT decision_id, csession_id FROM agent_slots").fetchall())
    assert got == {D1: "cs-abc123", D3: None}


@pytest.mark.parametrize("value", ["", "a b", "x" * 129, "a\nb", "a'; DROP TABLE agent_slots;--"])
def test_set_csession_refuses_an_unusable_id(st: store.Store, value: str) -> None:
    slot = acquire(st)
    assert slot is not None
    with pytest.raises(ValueError):
        slots.set_csession(st, slot, value)
    assert st.con.execute("SELECT csession_id FROM agent_slots").fetchone() == (None,)


def test_set_csession_on_a_released_slot_is_false(st: store.Store) -> None:
    slot = acquire(st)
    assert slot is not None
    assert slots.release(st, slot) is True
    assert slots.set_csession(st, slot, "cs-1") is False


def test_renew_moves_expires_at_of_the_own_row_only(st: store.Store) -> None:
    pid, start, boot = me()
    insert_raw(
        st, pid=pid, start=start, boot=boot, decision=D3, expires="2000-01-01T00:00:00.000000Z"
    )
    slot = acquire(st, D1)
    assert slot is not None
    later = LATER + timedelta(minutes=5)
    assert slots.renew(st, slot, later) is True
    got = dict(st.con.execute("SELECT decision_id, expires_at FROM agent_slots").fetchall())
    assert got[D1] == clock.format_ts(later)
    assert got[D3] == "2000-01-01T00:00:00.000000Z"


def test_renew_after_release_is_false_and_inserts_nothing(st: store.Store) -> None:
    slot = acquire(st)
    assert slot is not None
    slots.release(st, slot)
    assert slots.renew(st, slot, LATER) is False
    assert count(st) == 0


def test_release_removes_only_the_own_row_and_is_idempotent(st: store.Store) -> None:
    pid, start, boot = me()
    insert_raw(st, pid=pid, start=start, boot=boot, decision=D3)
    slot = acquire(st, D1)
    assert slot is not None
    assert slots.release(st, slot) is True
    assert slots.release(st, slot) is False
    assert st.con.execute("SELECT decision_id FROM agent_slots").fetchall() == [(D3,)]


def test_release_never_removes_another_processs_row_of_the_same_decision(st: store.Store) -> None:
    _, start, boot = me()
    other = slots.Slot(pid=os.getpid() + 1, start=start, boot_id=boot, decision_id=D1)
    insert_raw(st, pid=other.pid, start=other.start, boot=boot, decision=D1)
    mine = slots.Slot(pid=os.getpid(), start=start, boot_id=boot, decision_id=D1)
    assert slots.release(st, mine) is False
    assert count(st) == 1


def test_release_swallows_a_busy_store_and_reports_false(sdir: Path, st: store.Store) -> None:
    slot = acquire(st)
    assert slot is not None
    blocker = store.open_store(sdir, create=True, busy_timeout=0.05)
    assert blocker is not None
    short = store.open_store(sdir, create=True, busy_timeout=0.05)
    assert short is not None
    try:
        with blocker.write():
            assert slots.release(short, slot) is False  # never raises: the row dies with us
    finally:
        blocker.close()
        short.close()
    assert count(st) == 1


def test_held_releases_on_an_exception(st: store.Store) -> None:
    slot = acquire(st)
    assert slot is not None
    with pytest.raises(RuntimeError):
        with slots.held(st, slot):
            raise RuntimeError("boom")
    assert count(st) == 0


def test_held_releases_on_a_normal_exit_and_on_a_keyboard_interrupt(st: store.Store) -> None:
    slot = acquire(st)
    assert slot is not None
    with slots.held(st, slot):
        assert count(st) == 1
    assert count(st) == 0
    slot = acquire(st)
    assert slot is not None
    with pytest.raises(KeyboardInterrupt):
        with slots.held(st, slot):
            raise KeyboardInterrupt
    assert count(st) == 0


# --- listing for reconcile ------------------------------------------------------------------


def test_list_slots_reports_liveness_and_overdue(st: store.Store) -> None:
    pid, start, boot = me()
    insert_raw(
        st, pid=pid, start=start, boot=boot, decision=D1, expires="2000-01-01T00:00:00.000000Z"
    )
    insert_raw(st, pid=pid, start=start, boot=boot, decision=D2, csession="cs-9")
    insert_raw(st, pid=dead_pid(), start="1", boot=boot, decision=D3)
    infos = {i.decision_id: i for i in slots.list_slots(st, now=NOW)}
    assert (infos[D1].alive, infos[D1].overdue) == (True, True)
    assert (infos[D2].alive, infos[D2].overdue, infos[D2].csession_id) == (True, False, "cs-9")
    assert (infos[D3].alive, infos[D3].overdue) == (False, False)  # dead is not "overdue"
    assert count(st) == 3  # listing never deletes


def test_list_slots_works_on_a_read_only_store(sdir: Path, st: store.Store) -> None:
    acquire(st)
    reader = store.open_store(sdir, create=False)
    assert reader is not None
    with reader:
        assert [i.decision_id for i in slots.list_slots(reader, now=NOW)] == [D1]


def test_list_slots_skips_tampered_rows_without_echoing_them(st: store.Store) -> None:
    with st.write():
        st.con.execute(
            "INSERT INTO agent_slots(holder_pid, holder_start, boot_id, decision_id, started_at,"
            " expires_at) VALUES ('CANARY', 'CANARY', 'CANARY', 'CANARY', 'CANARY', 'CANARY')"
        )
    assert slots.list_slots(st, now=NOW) == []


def test_purge_dead_deletes_only_dead_and_invalid_rows(st: store.Store) -> None:
    pid, start, boot = me()
    insert_raw(st, pid=pid, start=start, boot=boot, decision=D1)
    insert_raw(st, pid=dead_pid(), start="1", boot=boot, decision=D2)
    assert slots.purge_dead(st) == 1
    assert st.con.execute("SELECT decision_id FROM agent_slots").fetchall() == [(D1,)]


# --- waiting --------------------------------------------------------------------------------


class FakeTime:
    def __init__(self, budget: float) -> None:
        self.budget = budget
        self.sleeps: list[float] = []

    def window(self) -> float:
        return self.budget

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.budget -= seconds


def wait(st: store.Store, ft: FakeTime, **kw: Any) -> slots.Slot | None:
    return slots.wait_for_slot(
        st,
        decision_id=D2,
        max_parallel=kw.pop("cap", 1),
        expires_at=LATER,
        launch_window=ft.window,
        min_start_budget=kw.pop("min_start", 30.0),
        sleep=ft.sleep,
        now=lambda: NOW,
        **kw,
    )


def test_wait_returns_at_once_when_a_slot_is_free(st: store.Store) -> None:
    ft = FakeTime(100)
    assert wait(st, ft) is not None
    assert ft.sleeps == []


def test_wait_polls_every_250_ms_and_ends_busy_when_the_window_falls_below_the_minimum(
    st: store.Store,
) -> None:
    pid, start, boot = me()
    insert_raw(st, pid=pid, start=start, boot=boot)
    ft = FakeTime(31.0)  # 1 s above the minimum
    assert wait(st, ft) is None
    assert ft.sleeps[:4] == [0.25, 0.25, 0.25, 0.25]
    assert sum(ft.sleeps) <= 1.0 + 0.25  # woke by the time L reached the minimum
    assert ft.budget >= 29.5  # it did not keep waiting far past
    assert count(st) == 1


def test_wait_at_once_busy_when_already_below_the_minimum_and_full(st: store.Store) -> None:
    pid, start, boot = me()
    insert_raw(st, pid=pid, start=start, boot=boot)
    ft = FakeTime(10.0)
    assert wait(st, ft) is None
    assert ft.sleeps == []


def test_wait_takes_a_slot_that_frees_while_waiting(st: store.Store) -> None:
    pid, start, boot = me()
    insert_raw(st, pid=pid, start=start, boot=boot, decision=D3)
    ft = FakeTime(100)

    def sleep(seconds: float) -> None:
        ft.sleep(seconds)
        with st.write():
            st.con.execute("DELETE FROM agent_slots WHERE decision_id = ?", (D3,))

    got = slots.wait_for_slot(
        st,
        decision_id=D2,
        max_parallel=1,
        expires_at=LATER,
        launch_window=ft.window,
        min_start_budget=30.0,
        sleep=sleep,
        now=lambda: NOW,
    )
    assert got is not None and got.decision_id == D2


def test_wait_is_bounded_even_when_the_window_never_shrinks(st: store.Store) -> None:
    pid, start, boot = me()
    insert_raw(st, pid=pid, start=start, boot=boot)
    ticks = iter(range(10_000))
    slept: list[float] = []
    got = slots.wait_for_slot(
        st,
        decision_id=D2,
        max_parallel=1,
        expires_at=LATER,
        launch_window=lambda: 1e9,
        min_start_budget=30.0,
        sleep=slept.append,
        monotonic=lambda: float(next(ticks)),
        max_wait=5.0,
        now=lambda: NOW,
    )
    assert got is None
    assert len(slept) <= 10


def test_wait_treats_a_busy_store_as_no_slot_yet_and_ends_busy(sdir: Path, st: store.Store) -> None:
    blocker = store.open_store(sdir, create=True)
    assert blocker is not None
    short = store.open_store(sdir, create=True, busy_timeout=0.05)
    assert short is not None
    ft = FakeTime(30.6)
    try:
        with blocker.write():
            assert wait(short, ft) is None
    finally:
        blocker.close()
        short.close()
    assert ft.sleeps[:2] == [0.25, 0.25]
    assert count(st) == 0


def test_wait_takes_the_slot_once_a_busy_store_frees_up(sdir: Path, st: store.Store) -> None:
    blocker = store.open_store(sdir, create=True)
    assert blocker is not None
    short = store.open_store(sdir, create=True, busy_timeout=0.05)
    assert short is not None
    ft = FakeTime(100.0)
    real_sleep = ft.sleep
    held_by_blocker = blocker.write()
    held_by_blocker.__enter__()

    def sleep(seconds: float) -> None:
        nonlocal held_by_blocker
        if held_by_blocker is not None:
            held_by_blocker.__exit__(None, None, None)
            held_by_blocker = None  # type: ignore[assignment]
        real_sleep(seconds)

    try:
        got = slots.wait_for_slot(
            short,
            decision_id=D2,
            max_parallel=1,
            expires_at=LATER,
            launch_window=ft.window,
            min_start_budget=30.0,
            sleep=sleep,
            now=lambda: NOW,
        )
    finally:
        blocker.close()
        short.close()
    assert got is not None
    assert count(st) == 1


def test_liveness_is_not_evaluated_inside_the_write_transaction_for_known_rows(
    st: store.Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid, start, boot = me()
    for decision in (D1, D3, D4):
        insert_raw(st, pid=pid, start=start, boot=boot, decision=decision)
    real = slots.holder_alive
    inside: list[bool] = []

    def spy(*args: Any) -> bool:
        inside.append(st.con.in_transaction)
        return real(*args)

    monkeypatch.setattr(slots, "holder_alive", spy)
    assert acquire(st, D2, cap=5) is not None
    assert inside and not any(inside)


def test_a_row_added_after_the_snapshot_is_still_judged_inside_the_transaction(
    st: store.Store, monkeypatch: pytest.MonkeyPatch
) -> None:
    pid, start, boot = me()
    real = slots.holder_alive
    state = {"added": False}

    def spy(*args: Any) -> bool:
        if not state["added"]:
            state["added"] = True
            insert_raw(st, pid=dead_pid(), start="1", boot=boot, decision=D3)
        return real(*args)

    insert_raw(st, pid=pid, start=start, boot=boot, decision=D1)
    monkeypatch.setattr(slots, "holder_alive", spy)
    assert acquire(st, D2, cap=2) is not None
    monkeypatch.undo()
    assert count(st) == 2  # the dead late row was deleted, the live one kept, the new one added


def test_wait_does_not_hold_a_row_when_it_ends_busy(st: store.Store) -> None:
    pid, start, boot = me()
    insert_raw(st, pid=pid, start=start, boot=boot)
    wait(st, FakeTime(30.5))
    assert count(st) == 1


# --- concurrency across processes -----------------------------------------------------------


def _hold_worker(directory: str, index: int, cap: int, hold: float, out: Any) -> None:
    s = store.open_store(Path(directory), create=True, busy_timeout=20.0)
    assert s is not None
    # decision ids are base32 [a-z2-7]: map the index onto letters
    decision = "gd-" + "f" * 10 + "abcdefghij"[index // 10 % 10] + "abcdefghij"[index % 10]
    deadline = time.monotonic() + 60
    acquired = 0
    while time.monotonic() < deadline and acquired < 2:
        slot = slots.try_acquire(
            s,
            decision_id=decision,
            max_parallel=cap,
            expires_at=datetime.now(UTC) + timedelta(seconds=90),
        )
        if slot is None:
            time.sleep(0.01)
            continue
        live = s.con.execute("SELECT COUNT(*) FROM agent_slots").fetchone()[0]
        out.put(("live", index, live))
        time.sleep(hold)
        slots.release(s, slot)
        acquired += 1
    out.put(("done", index, acquired))
    s.close()


def _reap(procs: list[Any]) -> None:
    for p in procs:
        if p.is_alive():
            p.terminate()  # exactly the Process objects this test started
        p.join(10)


def test_many_processes_never_hold_more_than_max_parallel_slots(sdir: Path) -> None:
    s = store.open_store(sdir, create=True)
    assert s is not None
    s.close()
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    workers, cap = 5, 2
    procs = [
        ctx.Process(target=_hold_worker, args=(str(sdir), i, cap, 0.05, out))
        for i in range(workers)
    ]
    try:
        for p in procs:
            p.start()
        events = []
        done = 0
        while done < workers:
            event = out.get(timeout=120)
            events.append(event)
            done += event[0] == "done"
        for p in procs:
            p.join(30)
    finally:
        _reap(procs)
    assert [p.exitcode for p in procs] == [0] * workers
    lives = [e[2] for e in events if e[0] == "live"]
    assert lives and max(lives) <= cap  # the count seen right after taking a slot
    assert [e[2] for e in events if e[0] == "done"] == [2] * workers  # everybody got turns


def _crash_holder(directory: str, started: Any) -> None:
    s = store.open_store(Path(directory), create=True)
    assert s is not None
    slot = slots.try_acquire(
        s,
        decision_id=D1,
        max_parallel=1,
        expires_at=datetime.now(UTC) + timedelta(seconds=90),
    )
    assert slot is not None
    started.set()
    time.sleep(120)


def test_a_holder_that_dies_without_releasing_frees_its_slot(sdir: Path, tracker: Tracker) -> None:
    s = store.open_store(sdir, create=True)
    assert s is not None
    ctx = multiprocessing.get_context("spawn")
    started = ctx.Event()
    proc = ctx.Process(target=_crash_holder, args=(str(sdir), started))
    try:
        proc.start()
        assert started.wait(60)
        assert acquire(s, D2, cap=1) is None  # the holder is live
        proc.kill()  # exactly the Process object this test started
        proc.join(30)
        assert acquire(s, D2, cap=1) is not None
    finally:
        _reap([proc])
        s.close()
