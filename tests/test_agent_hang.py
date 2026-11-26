"""An agent run that hangs, ignores SIGTERM or is killed: the check ends as a timeout inside its
bounds, with every process of the run gone and the session stopped and forgotten as far as the
budget allowed. Run against the fake claude-session's hang scenarios (issue #24, Bounds).

``exec_margin`` is negative in these tests: the fake never outlives its own ``--timeout``, so the
overdue path is reached by making gatectl's guard (``n`` plus the margin) shorter than the run.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from gatectl import agent
from tests.agent_util import Fake, agent_check, config, limits_env, tmp_entries
from tests.check_util import REPO, do_check, isolate, rows, write_input
from tests.command_util import config_file
from tests.proc_util import Tracker

INPUT = {"ci": "ok", "repo": REPO}
# n = 3 s, the guard 1 s: the run is overdue after one second of a three second hang.
SHORT = agent.Limits(call_timeout=1.5, exec_margin=-2.0, cleanup_budget=6.0, kill_grace=0.5)


@pytest.fixture
def sdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def run_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], cfg: dict[str, Any]
) -> tuple[dict[str, Any], float]:
    config_path = config_file(tmp_path, cfg)
    began = time.monotonic()
    _, doc, _ = do_check(capsys, config_path, "p", "--input", write_input(tmp_path, INPUT))
    return doc, time.monotonic() - began


def cfg_for(fake: Fake) -> dict[str, Any]:
    return config(fake, checks=[agent_check(timeout="3s")])


def stops(fake: Fake) -> list[list[str]]:
    return [a for a in fake.argvs() if a[0] == "stop"]


@pytest.mark.parametrize("scenario", ["hang", "hang_ignore_term", "hang_ignore_term_wrapper"])
def test_an_overdue_exec_is_stopped_then_signalled_and_ends_as_a_timeout(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
    scenario: str,
) -> None:
    fake = Fake(tmp_path, scenario, FAKE_CS_HANG_MAX="30")
    limits_env(monkeypatch, tracker, SHORT)
    doc, elapsed = run_check(tmp_path, capsys, cfg_for(fake))
    entry = doc["checks"][0]
    assert (entry["verdict"], entry["reason"]) == ("escalate", "timeout")
    assert doc["decision"] == "escalate" and doc["reason"] == "timeout"
    verbs = fake.verbs()
    # step 3 of the sequence: a stop before the signals; then the clean-up's list (a second stop
    # only for a session whose run is still not final by then)
    assert verbs[:3] == ["start", "exec", "stop"]
    assert "list" in verbs and verbs.count("stop") in (1, 2)
    for call in stops(fake):
        assert call[2:] == ["--grace", "2s", "--actor", "auto:gatectl"]
    assert verbs.count("forget") == 1  # forget runs on this path too
    assert elapsed < 20
    assert tmp_entries(sdir) == []
    assert rows(sdir, "SELECT * FROM agent_slots") == []


def test_a_wrapper_that_ignores_sigterm_with_a_hanging_stop_leaks_nothing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(
        tmp_path,
        "hang_ignore_term_wrapper",
        FAKE_CS_HANG_MAX="30",
        FAKE_CS_BEHAVIOR_STOP="hang",
    )
    limits_env(monkeypatch, tracker, SHORT)
    doc, elapsed = run_check(tmp_path, capsys, cfg_for(fake))
    entry = doc["checks"][0]
    assert (entry["verdict"], entry["reason"]) == ("escalate", "timeout")
    assert elapsed < 25
    # every process gatectl started is gone (the tracker fixture fails the test on a leak), and
    # so is the wrapper the fake recorded
    wrapper = fake.records()[0]["wrapper_pid"]
    assert wrapper is not None
    tracker.track_pid(wrapper, cmdline_contains=b"claude-session")
    assert tracker.wait_dead(wrapper, 5.0)
    assert tmp_entries(sdir) == []
    assert rows(sdir, "SELECT * FROM agent_slots") == []


def test_a_child_that_ignores_sigterm_dies_with_the_run_group(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path, "hang_ignore_term", FAKE_CS_HANG_MAX="30")
    limits_env(monkeypatch, tracker, SHORT)
    run_check(tmp_path, capsys, cfg_for(fake))
    child = fake.records()[0]["child_pid"]
    assert child is not None
    tracker.track_pid(child)
    assert tracker.wait_dead(child, 5.0)


def test_a_hung_exec_and_stop_end_within_the_documented_bound(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    """Deadline plus 20 s plus the reserve at the real limits is 22 s; with the short limits the
    same sequence is bounded by guard + cleanup budget + one signal grace."""
    fake = Fake(
        tmp_path,
        "hang_ignore_term_wrapper",
        FAKE_CS_HANG_MAX="30",
        FAKE_CS_BEHAVIOR_STOP="hang",
        FAKE_CS_BEHAVIOR_LIST="hang",
        FAKE_CS_BEHAVIOR_FORGET="hang",
    )
    limits_env(monkeypatch, tracker, SHORT)
    doc, elapsed = run_check(tmp_path, capsys, cfg_for(fake))
    assert doc["checks"][0]["reason"] == "timeout"
    bound = 1.0 + SHORT.cleanup_budget + 2 * SHORT.kill_grace + SHORT.call_timeout + 3.0
    assert elapsed < bound + 4.0  # + start/status process start-up on a slow machine
    assert tracker.items  # a leak is failed by the tracker fixture itself


def test_an_exhausted_cleanup_budget_leaves_the_rest_to_reconcile(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path, "hang", FAKE_CS_HANG_MAX="30", FAKE_CS_BEHAVIOR_STOP="hang")
    spent = agent.Limits(call_timeout=1.5, exec_margin=-2.0, cleanup_budget=1.0, kill_grace=0.5)
    limits_env(monkeypatch, tracker, spent)
    doc, _ = run_check(tmp_path, capsys, cfg_for(fake))
    assert doc["checks"][0]["reason"] == "timeout"
    # the first stop hung and ate the whole budget: no list, no second stop, no forget
    assert fake.verbs().count("stop") == 1
    assert "forget" not in fake.verbs()
    assert tmp_entries(sdir) == []  # our own files and slot are still released
    assert rows(sdir, "SELECT * FROM agent_slots") == []


def test_a_hung_status_is_abandoned_and_the_session_is_still_forgotten(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path, FAKE_CS_BEHAVIOR_STATUS="hang_ignore_term", FAKE_CS_HANG_MAX="30")
    limits_env(monkeypatch, tracker)
    doc, elapsed = run_check(tmp_path, capsys, config(fake))
    assert doc["checks"][0]["reason"] == "check_error"
    assert fake.verbs().count("forget") == 1
    assert elapsed < 20


# --- gatectl itself is killed ---------------------------------------------------------------


def test_a_sigkilled_gatectl_leaves_a_session_a_reconcile_sweep_can_find_by_label(
    tmp_path: Path, tracker: Tracker
) -> None:
    """The run's wrapper is killed by the lifeline watchdog; the session, the slot row and the
    directory stay, and the session carries the labels ``reconcile`` selects on."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    fake = Fake(tmp_path, FAKE_CS_DELAY_EXEC="60")
    cfg = config_file(tmp_path, config(fake))
    data = write_input(tmp_path, INPUT)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "config"),
        "XDG_STATE_HOME": str(home / "state"),
        "LC_ALL": "C",
    }
    proc = subprocess.Popen(  # noqa: S603 - our own interpreter and module
        [sys.executable, "-m", "gatectl", "check", "p", "--input", data, "--config", cfg],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    tracker.track_child(proc.pid)
    wrapper: int | None = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and wrapper is None:
        found = fake.records()
        wrapper = found[0]["wrapper_pid"] if found else None
        time.sleep(0.05)
    assert wrapper is not None, "the run never reached exec"
    tracker.track_pid(wrapper, cmdline_contains=b"claude-session")
    os.kill(proc.pid, signal.SIGKILL)  # the exact pid we started
    proc.wait(timeout=10)
    assert tracker.wait_dead(wrapper, 10.0)  # the watchdog killed the run's group
    [record] = fake.records()
    decision = next(label[9:] for label in record["labels"] if label.startswith("decision="))
    assert sorted(label.split("=")[0] for label in record["labels"]) == [
        "decision", "kind", "owner", "policy", "state",
    ]  # fmt: skip
    assert "owner=gatectl" in record["labels"] and "policy=p" in record["labels"]
    assert record["forgotten"] is False  # left for reconcile
    state = home / "state" / "gatectl"
    slot = rows(state, "SELECT decision_id, csession_id FROM agent_slots")
    assert slot == [(decision, record["id"])]
    assert (state / "tmp" / decision).is_dir()
    assert json.loads(json.dumps(record["labels"])) == record["labels"]
