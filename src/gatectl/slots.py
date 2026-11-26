"""Agent slot leases in ``state.db`` (interface.md, Agent checks: Slots; Deadline, step 3).

A slot is a row of ``agent_slots``: holder PID, holder start time, boot id, decision id,
``csession_id``, run start and ``expires_at``. There is no slot number. At most the acquiring
process's ``agent.max_parallel`` rows are *live* at once, across all gatectl processes.

* A holder is **live** when its PID exists, is not a zombie, and still has the recorded process
  start time and boot id (a reused PID has another start time; a reboot another boot id).
  ``expires_at`` is informational: it is never read to decide liveness, so a clock step (or a
  slow but live run) can never free a live holder.
* ``try_acquire`` is one ``BEGIN IMMEDIATE`` transaction: delete the rows whose holder is dead
  (or that make no sense: a tampered row is never trusted as a holder), count the live ones, and
  insert the new row when fewer than ``max_parallel`` are live.
* Waiting (``wait_for_slot``) polls every 250 ms and ends with ``None`` (the caller escalates
  ``busy``) when the launch window ``L`` falls below ``agent.min_start_budget``. It also has a
  wall bound of its own, so a window that never shrinks cannot hold it forever.
* ``release`` is best effort and never raises for a store problem: a row that stays behind
  belongs to a process that is about to end, and the next acquire deletes it as dead.

The run sequence that calls these is ``engine._agent_entry``; ``reconcile``'s use of
``list_slots`` (overdue live holders, rows to sweep) and ``purge_dead`` is #32. Nothing here
starts a process.
"""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime

from gatectl import clock, ids, procinfo
from gatectl.errors import InternalError
from gatectl.store import Store, StoreBusyError, cut_sql, uncut

MAX_PARALLEL_LIMIT = 32  # the config bound of ``agent.max_parallel``
POLL_SECONDS = 0.25
MAX_WAIT_SECONDS = 86400.0  # the longest deadline there is
_ROW_LIMIT = 10000  # rows one acquire looks at; more than that is treated as full
_PID_MAX = 2**31 - 1
_START = re.compile(r"[0-9]{1,20}", re.ASCII)
_BOOT = re.compile(r"[0-9A-Za-z._-]{1,64}", re.ASCII)
_CHARS = 140
# TODO(#37): where the start time is unknown (no /proc, e.g. macOS) the placeholders below make
# every row, this process's own included, read as dead, so ``max_parallel`` is NOT enforced there;
# deferred until the macOS start-time method lands (non-blocking: Linux is the supported target).
_UNKNOWN_START = "0"
_UNKNOWN_BOOT = "unknown"

_SELECT = (
    "SELECT rowid, typeof(holder_pid), holder_pid, "
    f"{cut_sql('holder_start', _CHARS)}, {cut_sql('boot_id', _CHARS)}, "
    f"{cut_sql('decision_id', _CHARS)}, {cut_sql('csession_id', _CHARS)}, "
    f"{cut_sql('started_at', _CHARS)}, {cut_sql('expires_at', _CHARS)} "
    "FROM agent_slots ORDER BY rowid LIMIT ?"
)


@dataclass(frozen=True)
class Slot:
    """The identity of a held slot: what ``release``, ``renew`` and ``set_csession`` match on."""

    pid: int
    start: str
    boot_id: str
    decision_id: str


@dataclass(frozen=True)
class SlotInfo:
    """One well-formed slot row as ``reconcile`` sees it. ``overdue`` is a live holder past its
    ``expires_at``; it is a report, never a reason to free the slot."""

    pid: int
    start: str
    boot_id: str
    decision_id: str
    csession_id: str | None
    started_at: str | None
    expires_at: str | None
    alive: bool
    overdue: bool


def holder_alive(pid: object, start: object, boot_id: object) -> bool:
    """Whether the recorded holder is still the live process that took the slot."""
    if not (isinstance(pid, int) and not isinstance(pid, bool) and 0 < pid <= _PID_MAX):
        return False
    if not (isinstance(start, str) and start and isinstance(boot_id, str) and boot_id):
        return False
    current_boot = procinfo.boot_id()
    if not current_boot or boot_id != current_boot:
        return False
    if procinfo.start_time(pid) != start:
        return False
    return not procinfo.is_zombie(pid)


def current_holder(decision_id: str) -> Slot:
    # TODO(#37): with no start time the placeholder row below is judged dead by holder_alive, so
    # the slot cap is not enforced on a platform without /proc (see _UNKNOWN_START).
    start = procinfo.start_time(os.getpid())
    return Slot(
        pid=os.getpid(),
        start=start if start else _UNKNOWN_START,
        boot_id=procinfo.boot_id() or _UNKNOWN_BOOT,
        decision_id=decision_id,
    )


def _check_cap(max_parallel: object) -> int:
    if (
        not isinstance(max_parallel, int)
        or isinstance(max_parallel, bool)
        or not 1 <= max_parallel <= MAX_PARALLEL_LIMIT
    ):
        raise ValueError("max_parallel must be an integer from 1 to 32")
    return max_parallel


def _check_decision(decision_id: object) -> str:
    if not isinstance(decision_id, str) or not ids.is_decision_id(decision_id):
        raise ValueError("decision_id must be a gd- decision id")
    return decision_id


def _ts(moment: datetime) -> str:
    return clock.format_ts(moment)


def _text(value: object, pattern: re.Pattern[str]) -> str | None:
    text = uncut(value, _CHARS)
    if isinstance(text, str) and pattern.fullmatch(text) is not None:
        return text
    return None


@dataclass(frozen=True)
class _Row:
    rowid: int
    info: SlotInfo | None  # None: a row nobody can recognise


def _ts_or_none(value: object) -> str | None:
    text = uncut(value, _CHARS)
    if isinstance(text, str):
        try:
            clock.parse_ts(text)
        except ValueError:
            return None
        return text
    return None


_Identity = tuple[int, str, str]  # (pid, start time, boot id): unique to one process


def _read(
    store: Store,
    now_ts: str,
    limit: int,
    known: dict[_Identity, bool] | None = None,
) -> list[_Row]:
    """The rows with their liveness. ``known`` holds verdicts already reached for an exact
    identity (see ``_snapshot``); only identities not in it are looked up in ``/proc``."""
    rows: list[_Row] = []
    for raw in store.query(_SELECT, (limit,)):
        rowid, kind, pid, start, boot, decision, csession, started, expires = raw
        start_t = _text(start, _START)
        boot_t = _text(boot, _BOOT)
        decision_t = _text(decision, ids._DECISION_ID)
        if (
            kind != "integer"
            or not isinstance(pid, int)
            or isinstance(pid, bool)
            or not 0 < pid <= _PID_MAX
            or start_t is None
            or boot_t is None
            or decision_t is None
        ):
            rows.append(_Row(rowid, None))
            continue
        cs = uncut(csession, _CHARS)
        cs_t = cs if isinstance(cs, str) and ids.is_caller_decision_id(cs) else None
        identity = (pid, start_t, boot_t)
        if known is not None and identity in known:
            alive = known[identity]
        else:
            alive = holder_alive(pid, start_t, boot_t)
        expires_t = _ts_or_none(expires)
        rows.append(
            _Row(
                rowid,
                SlotInfo(
                    pid=pid,
                    start=start_t,
                    boot_id=boot_t,
                    decision_id=decision_t,
                    csession_id=cs_t,
                    started_at=_ts_or_none(started),
                    expires_at=expires_t,
                    alive=alive,
                    overdue=alive and expires_t is not None and expires_t < now_ts,
                ),
            )
        )
    return rows


def _snapshot(store: Store, now_ts: str, limit: int = _ROW_LIMIT + 1) -> dict[_Identity, bool]:
    """Liveness of the rows as read now, outside any write transaction, so the ``/proc`` reads
    do not hold the write lock. The identity (pid, start time, boot id) is unique to one
    process, so a row judged dead stays dead; one judged alive that has died since is kept by
    the sweep that uses this and freed by the next."""
    return {
        (r.info.pid, r.info.start, r.info.boot_id): r.info.alive
        for r in _read(store, now_ts, limit)
        if r.info is not None
    }


def _sweep(
    store: Store,
    now_ts: str,
    limit: int = _ROW_LIMIT + 1,
    known: dict[_Identity, bool] | None = None,
) -> tuple[int, int]:
    """Delete the dead and unrecognisable rows; return (live rows seen, rows deleted)."""
    live = deleted = 0
    for row in _read(store, now_ts, limit, known):
        if row.info is not None and row.info.alive:
            live += 1
        else:
            deleted += store.execute("DELETE FROM agent_slots WHERE rowid = ?", (row.rowid,))
    return live, deleted


def try_acquire(
    store: Store,
    *,
    decision_id: str,
    max_parallel: int,
    expires_at: datetime,
    now: datetime | None = None,
) -> Slot | None:
    """One attempt: a ``Slot``, or ``None`` when ``max_parallel`` holders are live.

    ``expires_at`` is the check's deadline plus 60 s (informational). Raises ``ValueError`` for
    arguments that are not what the callers pass and ``InternalError`` when the store fails.
    """
    cap = _check_cap(max_parallel)
    decision = _check_decision(decision_id)
    moment = now if now is not None else datetime.now(UTC)
    now_ts, expires_ts = _ts(moment), _ts(expires_at)
    slot = current_holder(decision)
    known = _snapshot(store, now_ts)  # /proc is read here, not under the write lock

    def body() -> Slot | None:
        live, _ = _sweep(store, now_ts, known=known)
        if live >= cap:
            return None
        store.execute(
            "INSERT INTO agent_slots(holder_pid, holder_start, boot_id, decision_id, csession_id,"
            " started_at, expires_at) VALUES (?, ?, ?, ?, NULL, ?, ?)",
            (slot.pid, slot.start, slot.boot_id, slot.decision_id, now_ts, expires_ts),
        )
        return slot

    return store.transact(body)


def wait_for_slot(
    store: Store,
    *,
    decision_id: str,
    max_parallel: int,
    expires_at: datetime,
    launch_window: Callable[[], float],
    min_start_budget: float,
    poll: float = POLL_SECONDS,
    max_wait: float = MAX_WAIT_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
    monotonic: Callable[[], float] = time.monotonic,
    now: Callable[[], datetime] | None = None,
) -> Slot | None:
    """Poll for a slot (Deadline, step 3). ``None`` means busy: the launch window ``L`` fell
    below ``min_start_budget`` (or ``max_wait`` elapsed) with every slot still live."""
    started = monotonic()
    while True:
        try:
            slot = try_acquire(
                store,
                decision_id=decision_id,
                max_parallel=max_parallel,
                expires_at=expires_at,
                now=now() if now is not None else None,
            )
        except StoreBusyError:
            slot = None  # the write lock is held by someone else: no slot yet, keep polling
        if slot is not None:
            return slot
        slack = launch_window() - min_start_budget
        if slack < 0 or monotonic() - started >= max_wait:
            return None
        sleep(min(poll, max(slack, 0.001)))


def _own(slot: Slot) -> tuple[object, ...]:
    return (slot.pid, slot.start, slot.boot_id, slot.decision_id)


_OWN = "holder_pid = ? AND holder_start = ? AND boot_id = ? AND decision_id = ?"


def set_csession(store: Store, slot: Slot, csession_id: str) -> bool:
    """Record the claude-session id of the run (Run sequence, step 2); False if the row is gone."""
    if not isinstance(csession_id, str) or not ids.is_caller_decision_id(csession_id):
        raise ValueError("csession_id has an unusable form")
    return bool(
        store.transact(
            lambda: store.execute(
                f"UPDATE agent_slots SET csession_id = ? WHERE {_OWN}",  # noqa: S608
                (csession_id, *_own(slot)),
            )
        )
    )


def renew(store: Store, slot: Slot, expires_at: datetime) -> bool:
    """Move the informational ``expires_at`` of the own row; False if the row is gone."""
    expires_ts = _ts(expires_at)
    return bool(
        store.transact(
            lambda: store.execute(
                f"UPDATE agent_slots SET expires_at = ? WHERE {_OWN}",  # noqa: S608
                (expires_ts, *_own(slot)),
            )
        )
    )


def release(store: Store, slot: Slot) -> bool:
    """Delete the own row. True when a row was removed. Never raises for a store failure: the
    row of a process that ends is deleted as dead by the next acquire."""
    try:
        return bool(
            store.transact(
                lambda: store.execute(
                    f"DELETE FROM agent_slots WHERE {_OWN}",  # noqa: S608
                    _own(slot),
                )
            )
        )
    except InternalError:
        return False


@contextmanager
def held(store: Store, slot: Slot) -> Iterator[Slot]:
    """Release the slot on every way out (normal, exception, interrupt)."""
    try:
        yield slot
    finally:
        release(store, slot)


def list_slots(store: Store, *, now: datetime | None = None) -> list[SlotInfo]:
    """Every well-formed row with its liveness (for ``reconcile``); deletes nothing, works on a
    read-only store. Unrecognisable rows are left out and never echoed."""
    now_ts = _ts(now if now is not None else datetime.now(UTC))
    return [r.info for r in _read(store, now_ts, _ROW_LIMIT) if r.info is not None]


def purge_dead(store: Store) -> int:
    """Delete the dead and unrecognisable rows in one transaction; returns how many."""
    now_ts = _ts(datetime.now(UTC))
    known = _snapshot(store, now_ts)
    return store.transact(lambda: _sweep(store, now_ts, known=known)[1])
