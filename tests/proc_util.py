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
    items: list[_Tracked] = field(default_factory=list)

    # -- recording ---------------------------------------------------------------------

    def _record(self, pid: int, direct_child: bool) -> _Tracked:
        pidfd: int | None = None
        if hasattr(os, "pidfd_open"):
            try:
                pidfd = os.pidfd_open(pid)
            except OSError:
                pidfd = None
        item = _Tracked(pid, pidfd, _start_of(pid), direct_child)
        self.items.append(item)
        return item

    def track_child(self, pid: int) -> None:
        """Record a process this test started itself (a direct child)."""
        self._record(pid, True)

    def track_pid(self, pid: int, cmdline_contains: bytes | None = None) -> None:
        """Record a descendant a hostile script reported. ``cmdline_contains`` guards reuse."""
        if cmdline_contains is not None:
            line = _cmdline_of(pid)
            if line is not None and cmdline_contains not in line:
                raise AssertionError(f"pid {pid} is not the expected process: {line!r}")
            if line is None:
                # Already gone (the runner is fast): record it as dead, with no handle to signal.
                self.items.append(_Tracked(pid, None, None, False))
                return
        self._record(pid, False)

    def expect_survivor(self, pid: int) -> None:
        """Mark a recorded process that is meant to outlive the test body (killed on teardown)."""
        for item in self.items:
            if item.pid == pid:
                item.survivor_ok = True
                return
        raise AssertionError(f"pid {pid} was never recorded")

    def gateway(self) -> TrackingGateway:
        return TrackingGateway(self)

    # -- liveness ----------------------------------------------------------------------

    def _item(self, pid: int) -> _Tracked:
        for item in self.items:
            if item.pid == pid:
                return item
        raise AssertionError(f"pid {pid} was never recorded")

    def alive(self, pid: int) -> bool:
        """True while the recorded process runs (a zombie, awaiting its reaper, is dead)."""
        item = self._item(pid)
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
                return False
        return False

    def wait_dead(self, pid: int, timeout: float = 5.0) -> bool:
        """Bounded wait (no busy loop) until the recorded process is gone."""
        deadline = time.monotonic() + timeout
        while self.alive(pid):
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.02)
        return True

    # -- teardown ----------------------------------------------------------------------

    def _kill(self, item: _Tracked) -> None:
        if item.pidfd is not None:
            try:
                signal.pidfd_send_signal(item.pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            return
        if item.start is not None and _start_of(item.pid) != item.start:
            return
        if item.start is None and not item.direct_child:
            return  # no safe handle: never guess
        try:
            os.kill(item.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def teardown(self) -> list[int]:
        """Kill every recorded process still running; return those that were not allowed to be."""
        leaked: list[int] = []
        for item in self.items:
            if self.alive(item.pid):
                if not item.survivor_ok:
                    leaked.append(item.pid)
                self._kill(item)
        for item in self.items:
            if not self.wait_dead(item.pid, 5.0):
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
