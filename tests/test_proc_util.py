"""The process tracker itself: it kills exactly the processes recorded, in both handle modes."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Iterator

import pytest

from tests.proc_util import Tracker

PY = sys.executable
SLEEP = [PY, "-c", "import time; time.sleep(60)", "tracker-test"]


@pytest.fixture(params=[True, False], ids=["pidfd", "start-time"])
def own(request: pytest.FixtureRequest) -> Iterator[Tracker]:
    if request.param and not hasattr(os, "pidfd_open"):
        pytest.skip("no pidfd here")
    t = Tracker(use_pidfd=request.param)
    yield t
    t.teardown()


@pytest.fixture
def bystanders() -> Iterator[list[subprocess.Popen[bytes]]]:
    procs: list[subprocess.Popen[bytes]] = []
    yield procs
    for p in procs:  # exact handles this test itself started
        p.kill()
        p.wait()


def sleeper(procs: list[subprocess.Popen[bytes]]) -> subprocess.Popen[bytes]:
    p = subprocess.Popen(SLEEP, stdin=subprocess.DEVNULL, close_fds=True)
    procs.append(p)
    return p


def test_the_selected_mode_decides_the_handle(own: Tracker) -> None:
    p = subprocess.Popen(SLEEP)
    try:
        own.track_child(p.pid)
        assert (own.items[0].pidfd is not None) == own.use_pidfd
    finally:
        own.teardown()
        p.wait()


def test_teardown_kills_exactly_the_recorded_pids(
    own: Tracker, bystanders: list[subprocess.Popen[bytes]]
) -> None:
    mine, other = sleeper(bystanders), sleeper(bystanders)
    own.track_child(mine.pid)
    own.expect_survivor(mine.pid)
    assert own.teardown() == []
    assert mine.wait(timeout=5) == -9
    assert other.poll() is None  # never recorded, never signalled


def test_a_survivor_that_was_not_expected_is_reported(
    own: Tracker, bystanders: list[subprocess.Popen[bytes]]
) -> None:
    p = sleeper(bystanders)
    own.track_child(p.pid)
    assert own.teardown() == [p.pid]
    p.wait(timeout=5)


def test_a_pid_whose_identity_changed_is_not_signalled(
    bystanders: list[subprocess.Popen[bytes]],
) -> None:
    t = Tracker(use_pidfd=False)
    p = sleeper(bystanders)
    t.track_pid(p.pid)
    t.items[0].start = "0"  # as if the pid now belonged to a newer process
    assert not t.alive(p.pid)
    assert t.teardown() == []
    assert p.poll() is None


def test_a_reaped_direct_child_with_no_start_time_is_never_signalled() -> None:
    t = Tracker(use_pidfd=False)
    p = subprocess.Popen([PY, "-c", "pass"])
    t.track_child(p.pid)
    t.items[0].start = None
    p.wait()
    assert not t.alive(p.pid)  # waitid reports it reaped
    assert t.items[0].reaped
    t._kill(t.items[0])  # would signal a recycled pid if it guessed
    t.teardown()


def test_a_marker_that_does_not_match_is_refused(
    own: Tracker, bystanders: list[subprocess.Popen[bytes]]
) -> None:
    p = sleeper(bystanders)
    with pytest.raises(AssertionError, match="not the expected process"):
        own.track_pid(p.pid, cmdline_contains=b"definitely-not-there")
    assert own.items == []


def test_a_marker_that_matches_is_recorded(
    own: Tracker, bystanders: list[subprocess.Popen[bytes]]
) -> None:
    p = sleeper(bystanders)
    own.track_pid(p.pid, cmdline_contains=b"tracker-test")
    assert own.alive(p.pid)
    own.expect_survivor(p.pid)


def test_a_zombie_is_recorded_as_dead_not_refused() -> None:
    # A zombie's /proc/<pid>/cmdline is empty, not missing: it is dead, not "another process".
    t = Tracker()
    p = subprocess.Popen([PY, "-c", "pass"])
    try:
        os.waitid(os.P_PID, p.pid, os.WEXITED | os.WNOWAIT)
        t.track_pid(p.pid, cmdline_contains=b"anything")
        assert not t.alive(p.pid)
        assert t.teardown() == []
    finally:
        p.wait()


def test_the_same_process_recorded_twice_is_one_record(
    own: Tracker, bystanders: list[subprocess.Popen[bytes]]
) -> None:
    p = sleeper(bystanders)
    own.track_pid(p.pid)
    own.track_pid(p.pid)
    assert len(own.items) == 1
    own.expect_survivor(p.pid)


def test_a_pid_recorded_again_for_a_new_process_is_a_separate_record(
    bystanders: list[subprocess.Popen[bytes]],
) -> None:
    t = Tracker(use_pidfd=False)
    p = sleeper(bystanders)
    t.track_pid(p.pid)
    t.items[0].start = "0"  # the first holder is gone; a different process now has this pid
    t.track_pid(p.pid)
    assert len(t.items) == 2
    assert t.alive(p.pid)  # the latest record answers
    t.expect_survivor(p.pid)
    assert t.teardown() == []
    assert p.wait(timeout=5) == -9
