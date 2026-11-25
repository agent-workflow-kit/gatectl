"""Teardown edge cases of the runner: an unkillable leader, a dead watchdog, an interrupt.

The unkillable leader is a fake ``Child`` whose ``wait_exited`` is always false. It stands on
a real, harmless process (its own group, recorded by the tracker) so that a watchdog told about
it can never signal anything else.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from typing import IO

import pytest

from gatectl import runner
from gatectl.gateway import Child, ChildSpec, Stdio
from gatectl.runner import RunSpec, run_process, run_script
from tests.proc_util import Tracker

PY = sys.executable


class StuckChild:
    """A leader that never exits, whatever it is sent, and must never be waited for."""

    own_group = True

    def __init__(self, tracker: Tracker) -> None:
        self._proc = subprocess.Popen(
            [PY, "-c", "import time; time.sleep(60)"],
            process_group=0,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        tracker.track_child(self._proc.pid)
        tracker.expect_survivor(self._proc.pid)
        self.pid = self._proc.pid
        self.stdin: IO[bytes] | None = None
        self.stdout: IO[bytes] | None = self._eof()
        self.stderr: IO[bytes] | None = self._eof()
        self.signals: list[int] = []
        self.wait_calls = 0
        self.wait_exited_calls = 0
        self.wait_exited_timeouts: list[float | None] = []

    @staticmethod
    def _eof() -> IO[bytes]:
        r, w = os.pipe()
        os.close(w)
        return os.fdopen(r, "rb")

    def poll(self) -> int | None:
        return None

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        raise AssertionError("an unkillable leader must never be waited for")

    def wait_exited(self, timeout: float | None = None) -> bool:
        self.wait_exited_calls += 1
        self.wait_exited_timeouts.append(timeout)
        return False

    def signal_group(self, sig: int) -> None:
        self.signals.append(sig)


class StuckGateway:
    """The watchdog is real; the check is a ``StuckChild``."""

    def __init__(self, tracker: Tracker) -> None:
        self._tracker = tracker
        self._real = tracker.gateway()
        self._starts = 0
        self.child: StuckChild | None = None

    def start(self, spec: ChildSpec) -> Child:
        self._starts += 1
        if self._starts == 1:
            return self._real.start(spec)
        self.child = StuckChild(self._tracker)
        return self.child  # type: ignore[return-value]


def stuck_spec(**kw: object) -> RunSpec:
    fields: dict[str, object] = {
        "argv": (PY, "-c", "pass"),
        "env": {},
        "cwd": "/",
        "timeout": 0.2,
        "kill_grace": 0.1,
    }
    fields.update(kw)
    return RunSpec(**fields)  # type: ignore[arg-type]


def test_an_unkillable_leader_is_never_reaped_and_its_watchdog_is_parked(
    tracker: Tracker, monkeypatch: pytest.MonkeyPatch
) -> None:
    parked: list[Child] = []
    monkeypatch.setattr(runner, "_PARKED", parked)
    monkeypatch.setattr(runner, "_KILL_WAIT", 0.3)
    gw = StuckGateway(tracker)
    phases: list[str] = []
    r = run_process(gw, stuck_spec(), on_phase=lambda p, c, w: phases.append(p))
    assert gw.child is not None
    assert r.leader_unkilled and r.status == "timeout"
    assert gw.child.wait_calls == 0  # an unreaped leader keeps its group id
    assert phases == ["started"]  # no sweep, no ``done``, no reap
    assert len(parked) == 1
    wd = parked[0]
    assert wd.stdin is not None and not wd.stdin.closed  # the lifeline stays open
    tracker.expect_survivor(wd.pid)
    time.sleep(0.2)
    assert tracker.alive(wd.pid)  # it was not told ``done`` and was not released


def test_an_unkillable_leader_is_waited_for_once_not_twice(
    tracker: Tracker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "_PARKED", [])
    monkeypatch.setattr(runner, "_KILL_WAIT", 1.0)
    gw = StuckGateway(tracker)
    t0 = time.monotonic()
    r = run_process(gw, stuck_spec())
    took = time.monotonic() - t0
    assert gw.child is not None and r.leader_unkilled
    assert gw.child.signals == [signal.SIGTERM, signal.SIGKILL]  # no third signal in teardown
    # Deterministic check: the loop only polls (timeout 0); teardown adds no blocking wait.
    assert gw.child.wait_exited_calls > 0
    assert all(not t for t in gw.child.wait_exited_timeouts)
    # Generous bound: timeout 0.2 + grace 0.1 + one kill wait 1.0 is about 1.3 s; a second
    # wait would make it about 2.3 s.
    assert took < 1.8
    tracker.expect_survivor(runner._PARKED[0].pid)


# --- a watchdog that is gone -------------------------------------------------------------------


class _SwapWatchdogGateway:
    """Replaces the watchdog program (the first child) with another one."""

    def __init__(self, tracker: Tracker, code: str) -> None:
        self._real = tracker.gateway()
        self._code = code
        self._first = True

    def start(self, spec: ChildSpec) -> Child:
        if self._first:
            self._first = False
            spec = ChildSpec(
                (PY, "-c", self._code),
                stdin=Stdio.PIPE,
                stdout=Stdio.DEVNULL,
                stderr=Stdio.DEVNULL,
                own_group=True,
                cwd="/",
                env={},
            )
        return self._real.start(spec)


@pytest.mark.parametrize("watchdog", ["pass", "import sys; sys.stdin.readline()"])
@pytest.mark.parametrize("check", ["import time; time.sleep(0.5)", "import time; time.sleep(60)"])
def test_a_watchdog_that_dies_never_leaves_a_check_running_or_allowed(
    tracker: Tracker, watchdog: str, check: str
) -> None:
    gw = _SwapWatchdogGateway(tracker, watchdog)
    t0 = time.monotonic()
    o = run_script(
        gw,
        argv=(PY, "-c", check),
        payload=None,
        timeout=20.0,
        env={},
        cwd="/",
        kill_grace=0.3,
        drain_grace=0.3,
    )
    assert time.monotonic() - t0 < 10
    assert (o.verdict, o.reason) == ("escalate", "check_error")
    assert o.detail in ("not started", "lifeline lost")
    assert all(not tracker.alive(item.pid) for item in tracker.items)


# --- an interrupt right after the child started -----------------------------------------------


def test_an_interrupt_while_registering_still_kills_and_reaps_everything(
    tracker: Tracker, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(pid: int) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(runner.procinfo, "start_time", interrupted)
    with pytest.raises(KeyboardInterrupt):
        run_process(
            tracker.gateway(),
            RunSpec(argv=(PY, "-c", "import time; time.sleep(60)"), env={}, cwd="/", timeout=10.0),
        )
    assert tracker.items and all(not tracker.alive(item.pid) for item in tracker.items)
