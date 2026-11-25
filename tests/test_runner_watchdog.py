"""The lifeline watchdog and its ``done`` handshake, with real processes.

The driver (``tests/runner_driver.py``) plays gatectl and SIGKILLs itself at a chosen phase of
the runner, so each test shows what the watchdog does when gatectl dies exactly there. Nothing
is killed by pattern: every pid is recorded when it is learned, and teardown signals only
those.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from gatectl.gateway import Stdio, watchdog_spec
from gatectl.runner import RunSpec, run_process
from tests.proc_util import Tracker, read_pid

PY = sys.executable
DRIVER = str(Path(__file__).with_name("runner_driver.py"))


def start_driver(tracker: Tracker, directory: Path, phase: str, leader: str) -> int:
    env = {"PATH": "/usr/bin:/bin", "HOME": str(directory)}
    p = subprocess.Popen(
        [PY, DRIVER, str(directory), phase, leader],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        env=env,
        cwd=str(directory),
    )
    tracker.track_child(p.pid)
    return p.pid


def learn(tracker: Tracker, directory: Path, name: str, marker: bytes | None = None) -> int:
    pid = read_pid(directory / name)
    tracker.track_pid(pid, cmdline_contains=marker)
    return pid


def wait_for(path: Path, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        assert time.monotonic() < deadline, f"{path.name} never appeared"
        time.sleep(0.02)


def test_sigkill_of_gatectl_during_a_check_kills_the_checks_group(
    tracker: Tracker, tmp_path: Path
) -> None:
    driver = start_driver(tracker, tmp_path, "started", "sleep")
    gc = learn(tracker, tmp_path, "gc", str(tmp_path).encode())
    leader = learn(tracker, tmp_path, "leader", str(tmp_path).encode())
    wd = learn(tracker, tmp_path, "watchdog.pid")
    assert tracker.wait_dead(driver, 10)
    assert tracker.wait_dead(leader, 10), "the check leader outlived gatectl"
    assert tracker.wait_dead(gc, 10), "the check's grandchild outlived gatectl"
    assert tracker.wait_dead(wd, 10), "the watchdog outlived its work"


def test_sigkill_between_the_sweep_and_done_still_kills_the_group(
    tracker: Tracker, tmp_path: Path
) -> None:
    start_driver(tracker, tmp_path, "swept", "straggler")
    wait_for(tmp_path / "decoy")
    decoy = learn(tracker, tmp_path, "decoy", f"decoy{tmp_path}".encode())
    wd = learn(tracker, tmp_path, "watchdog.pid")
    # gatectl died before it said ``done``: the group is the watchdog's to kill, the late
    # arrival in it included.
    assert tracker.wait_dead(decoy, 10)
    assert tracker.wait_dead(wd, 10)


def test_sigkill_between_done_and_the_reap_signals_nothing(
    tracker: Tracker, tmp_path: Path
) -> None:
    start_driver(tracker, tmp_path, "done_sent", "straggler")
    wait_for(tmp_path / "decoy")
    decoy = learn(tracker, tmp_path, "decoy", f"decoy{tmp_path}".encode())
    tracker.expect_survivor(decoy)
    wd = learn(tracker, tmp_path, "watchdog.pid")
    # ``done`` was sent: the group was already swept and its id may be reused any moment, so
    # the watchdog must exit without a signal even though the pipe now reaches EOF.
    assert tracker.wait_dead(wd, 10)
    time.sleep(0.3)
    assert tracker.alive(decoy)


def test_a_driver_that_finishes_normally_leaves_no_watchdog(
    tracker: Tracker, tmp_path: Path
) -> None:
    driver = start_driver(tracker, tmp_path, "never", "straggler")
    wait_for(tmp_path / "finished")
    gc = learn(tracker, tmp_path, "gc", str(tmp_path).encode())
    wd = learn(tracker, tmp_path, "watchdog.pid")
    assert tracker.wait_dead(driver, 10)
    assert tracker.wait_dead(gc, 5)
    assert tracker.wait_dead(wd, 5)


def test_run_process_reaps_its_watchdog(tracker: Tracker) -> None:
    pids: list[int] = []
    run_process(
        tracker.gateway(),
        RunSpec(argv=(PY, "-c", "pass"), env={}, cwd="/", timeout=10.0),
        on_phase=lambda phase, check_pid, wd_pid: pids.append(wd_pid),
    )
    assert pids and not tracker.alive(pids[0])
    with pytest.raises(ChildProcessError):  # reaped: nothing left for anyone to wait for
        os.waitid(os.P_PID, pids[0], os.WEXITED | os.WNOHANG)


def test_phases_come_in_the_documented_order(tracker: Tracker) -> None:
    seen: list[str] = []
    run_process(
        tracker.gateway(),
        RunSpec(argv=(PY, "-c", "pass"), env={}, cwd="/", timeout=10.0),
        on_phase=lambda phase, c, w: seen.append(phase),
    )
    assert seen == ["started", "swept", "done_sent", "reaped"]


def test_done_is_sent_before_the_leader_is_reaped(tracker: Tracker) -> None:
    # At ``done_sent`` the leader must still be an unreaped zombie (its pgid cannot be reused);
    # at ``reaped`` it is gone.
    states: dict[str, bool] = {}

    def hook(phase: str, check_pid: int, wd_pid: int) -> None:
        try:
            os.waitid(os.P_PID, check_pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            states[phase] = True  # still waitable
        except ChildProcessError:
            states[phase] = False

    run_process(
        tracker.gateway(),
        RunSpec(argv=(PY, "-c", "pass"), env={}, cwd="/", timeout=10.0),
        on_phase=hook,
    )
    assert states["swept"] and states["done_sent"]
    assert not states["reaped"]


# --- the watchdog program on its own -----------------------------------------------------


def decoy_group(tracker: Tracker) -> tuple[int, str]:
    p = subprocess.Popen(
        [PY, "-c", "import time; time.sleep(60)", "watchdog-decoy"],
        process_group=0,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
    )
    tracker.track_child(p.pid)
    stat = Path(f"/proc/{p.pid}/stat").read_bytes()
    return p.pid, stat[stat.rindex(b")") + 2 :].split()[19].decode()


def run_watchdog(tracker: Tracker, lines: list[bytes]) -> int:
    child = tracker.gateway().start(watchdog_spec())
    assert child.stdin is not None
    for line in lines:
        child.stdin.write(line)
    child.stdin.close()  # EOF: gatectl is gone
    return child.wait(timeout=10)


needs_proc = pytest.mark.skipif(not os.path.exists("/proc/self/stat"), reason="needs /proc")


def test_watchdog_spec_is_isolated_and_explicit() -> None:
    s = watchdog_spec()
    assert s.own_group
    assert (s.stdin, s.stdout, s.stderr) == (Stdio.PIPE, Stdio.DEVNULL, Stdio.DEVNULL)
    assert dict(s.env or {}) == {}  # never inherits gatectl's environment


@needs_proc
def test_watchdog_kills_the_registered_group_on_eof(tracker: Tracker) -> None:
    pid, start = decoy_group(tracker)
    assert run_watchdog(tracker, [f"G {pid} {start}\n".encode()]) == 0
    assert tracker.wait_dead(pid, 5)


@needs_proc
def test_watchdog_on_done_exits_without_signalling(tracker: Tracker) -> None:
    pid, start = decoy_group(tracker)
    assert run_watchdog(tracker, [f"G {pid} {start}\n".encode(), b"done\n"]) == 0
    time.sleep(0.2)
    assert tracker.alive(pid)


def test_watchdog_with_nothing_registered_signals_nothing(tracker: Tracker) -> None:
    pid, _ = decoy_group(tracker)
    assert run_watchdog(tracker, []) == 0
    assert tracker.alive(pid)


@needs_proc
def test_watchdog_refuses_a_group_whose_leader_is_a_different_process(tracker: Tracker) -> None:
    # The recorded start time does not match: the pid was reused. Never signal it.
    pid, start = decoy_group(tracker)
    assert run_watchdog(tracker, [f"G {pid} {int(start) + 1}\n".encode()]) == 0
    time.sleep(0.2)
    assert tracker.alive(pid)


@pytest.mark.parametrize("target", ["0", "1", "-1", "-5", "abc", "", "9" * 30, "1.5"])
def test_watchdog_never_signals_a_nonsense_group(tracker: Tracker, target: str) -> None:
    pid, _ = decoy_group(tracker)
    assert run_watchdog(tracker, [f"G {target} -\n".encode()]) == 0
    assert tracker.alive(pid)


@pytest.mark.parametrize("line", [b"garbage\n", b"G\n", b"G 5\n", b"g 5 -\n", b"\n", b"done"])
def test_watchdog_ignores_malformed_lines(tracker: Tracker, line: bytes) -> None:
    pid, _ = decoy_group(tracker)
    assert run_watchdog(tracker, [line]) == 0
    assert tracker.alive(pid)


def test_watchdog_survives_a_flood_of_input_without_growing(tracker: Tracker) -> None:
    pid, _ = decoy_group(tracker)
    assert run_watchdog(tracker, [b"x" * 200_000]) == 0
    assert tracker.alive(pid)
