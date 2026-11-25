"""Process-test helpers: record every process a test starts and kill exactly those on teardown.

Nothing here kills by pattern. A process is signalled only through a handle taken when it was
recorded: a ``pidfd`` where the kernel has one (immune to pid reuse), else its pid after its
``/proc`` start time still matches the recorded one, else (a direct child that is still
unreaped, so its pid cannot be reused) its pid.
"""

from __future__ import annotations

import os
import select
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path

from gatectl.gateway import Child, ChildSpec, SubprocessGateway


def _start_of(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read()
    except OSError:
        return None
    return data[data.rindex(b")") + 2 :].split()[19].decode()


def _cmdline_of(pid: int) -> bytes | None:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read()
    except OSError:
        return None


def _settled_cmdline(pid: int) -> bytes | None:
    """The command line, re-read briefly while empty: a zombie's stays empty, but a process
    that has only just exec'd can read empty for an instant."""
    line = _cmdline_of(pid)
    for _ in range(5):
        if line:
            break
        time.sleep(0.01)
        line = _cmdline_of(pid)
    return line


def _state_of(pid: int) -> bytes | None:
    """The one-letter ``/proc`` state (``Z`` for a zombie), or ``None`` when the pid is gone."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read()
    except OSError:
        return None
    return data[data.rindex(b")") + 2 :][:1]


@dataclass
class _Tracked:
    pid: int
    pidfd: int | None
    start: str | None
    direct_child: bool
    survivor_ok: bool = False
    reaped: bool = False


@dataclass
class Tracker:
    """``use_pidfd`` selects the handle: ``True`` takes a pidfd where the kernel has one (the
    default), ``False`` forces the start-time fallback so both modes can be tested."""

    items: list[_Tracked] = field(default_factory=list)
    use_pidfd: bool = True

    # -- recording ---------------------------------------------------------------------

    def _record(self, pid: int, direct_child: bool) -> _Tracked:
        pidfd: int | None = None
        if self.use_pidfd and hasattr(os, "pidfd_open"):
            try:
                pidfd = os.pidfd_open(pid)
            except OSError:
                pidfd = None
        start = _start_of(pid)
        for known in self.items:
            if known.pid == pid and known.start == start and start is not None:
                if pidfd is not None:
                    os.close(pidfd)
                return known  # the same process recorded twice is one item
        item = _Tracked(pid, pidfd, start, direct_child)
        self.items.append(item)
        return item

    def track_child(self, pid: int) -> None:
        """Record a process this test started itself (a direct child)."""
        self._record(pid, True)

    def track_pid(self, pid: int, cmdline_contains: bytes | None = None) -> None:
        """Record a descendant a hostile script reported. ``cmdline_contains`` guards reuse."""
        if cmdline_contains is not None:
            line = _settled_cmdline(pid)
            # A just-spawned child can still show its parent's command line for an instant
            # after the spawn returns; re-read for a short bound before calling it a mismatch.
            for _ in range(50):
                if not line or cmdline_contains in line:
                    break
                time.sleep(0.01)
                line = _cmdline_of(pid)
            if line is not None and line and cmdline_contains not in line:
                raise AssertionError(f"pid {pid} is not the expected process: {line!r}")
            if not line and _state_of(pid) in (None, b"Z"):
                # Already gone: unreadable, or a zombie (its cmdline reads as empty). Record it
                # as dead, with no handle to signal. A live process with an empty cmdline is
                # recorded normally below, so it is killed and waited for.
                self.items.append(_Tracked(pid, None, None, False))
                return
        self._record(pid, False)

    def expect_survivor(self, pid: int) -> None:
        """Mark a recorded process that is meant to outlive the test body (killed on teardown)."""
        self._item(pid).survivor_ok = True

    def gateway(self) -> TrackingGateway:
        return TrackingGateway(self)

    # -- liveness ----------------------------------------------------------------------

    def _item(self, pid: int) -> _Tracked:
        """The most recently recorded process with this pid (a pid can be recorded again once
        its first holder is gone; ``teardown`` still treats every record on its own)."""
        for item in reversed(self.items):
            if item.pid == pid:
                return item
        raise AssertionError(f"pid {pid} was never recorded")

    def alive(self, pid: int) -> bool:
        """True while the recorded process runs (a zombie, awaiting its reaper, is dead)."""
        return self._alive(self._item(pid))

    def _alive(self, item: _Tracked) -> bool:
        pid = item.pid
        if item.pidfd is not None:
            poller = select.poll()
            poller.register(item.pidfd, select.POLLIN)
            return not poller.poll(0)
        stat = _start_of(pid)
        if item.start is not None:
            if stat != item.start:
                return False
            try:
                with open(f"/proc/{pid}/stat", "rb") as f:
                    data = f.read()
            except OSError:
                return False
            return data[data.rindex(b")") + 2 :][:1] != b"Z"
        if item.direct_child and not item.reaped:
            try:
                return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None
            except ChildProcessError:
                item.reaped = True
                return False
        return False

    def wait_dead(self, pid: int, timeout: float = 5.0) -> bool:
        """Bounded wait (no busy loop) until the recorded process is gone."""
        return self._wait_item_dead(self._item(pid), timeout)

    def _wait_item_dead(self, item: _Tracked, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while self._alive(item):
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.02)
        return True

    # -- teardown ----------------------------------------------------------------------

    def _kill(self, item: _Tracked) -> None:
        """Signal exactly this record's process, never one that merely has the same pid."""
        if item.pidfd is not None:
            try:
                signal.pidfd_send_signal(item.pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            return
        if item.start is not None and _start_of(item.pid) != item.start:
            return
        if item.start is None and (not item.direct_child or item.reaped):
            return  # no safe handle: never guess
        try:
            os.kill(item.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def teardown(self) -> list[int]:
        """Kill every recorded process still running; return those that were not allowed to be."""
        leaked: list[int] = []
        for item in self.items:
            if self._alive(item):
                if not item.survivor_ok:
                    leaked.append(item.pid)
                self._kill(item)
        for item in self.items:
            if not self._wait_item_dead(item, 5.0):
                leaked.append(item.pid)
            if item.pidfd is not None:
                os.close(item.pidfd)
        self.items.clear()
        return leaked


class TrackingGateway:
    """The real gateway, recording the pid of every child it starts."""

    def __init__(self, tracker: Tracker) -> None:
        self._tracker = tracker
        self._real = SubprocessGateway()
        self.specs: list[ChildSpec] = []

    def start(self, spec: ChildSpec) -> Child:
        self.specs.append(spec)
        child = self._real.start(spec)
        self._tracker.track_child(child.pid)
        return child


def read_pid(path: Path, timeout: float = 10.0) -> int:
    """Wait (bounded) for a script to write its pid to ``path``."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return int(path.read_text())
        except (OSError, ValueError):
            if time.monotonic() >= deadline:
                raise AssertionError(f"{path} never got a pid") from None
            time.sleep(0.02)
