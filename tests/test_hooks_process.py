"""Detached post-decision hooks as real processes: the caller-EOF tests, session and descriptor
isolation, the supervisor's signals, the payload, timeouts and the failure paths.

Every pid is recorded by the ``tracker`` fixture (the hook, the supervisor and the lifeline
watchdog, found read-only through /proc parentage) and killed by its recorded handle on
teardown; nothing is killed by pattern.
"""

from __future__ import annotations

import json
import os
import signal
import time
from pathlib import Path

from tests import schema_util
from tests.command_util import config_file
from tests.hook_util import (
    Caller,
    Hooked,
    fd_links,
    hook,
    hook_config,
    hook_dirs,
    hooked,
    log_events,
    read_json_file,
    state_dir,
    wait_exists,
    wait_for_event,
)
from tests.proc_util import Tracker, read_pid
from tests.test_check_process import gatectl


def sleeper(pid_file: Path, seconds: int = 20) -> str:
    return f"echo $$ > {pid_file}; exec sleep {seconds}"


def test_a_caller_reading_to_eof_is_not_held_by_a_sync_and_an_async_hook(
    tmp_path: Path, tracker: Tracker
) -> None:
    first, second = tmp_path / "a.pid", tmp_path / "b.started"
    config = hook_config(
        tmp_path,
        hook(sleeper(first)),
        hook(f"touch {second}; exec sleep 20", async_=True),
    )
    caller = Caller(tmp_path, config)
    try:
        out, err, to_eof = caller.read_to_eof()
        assert caller.proc.wait(timeout=1) == 0
    finally:
        caller.close()
    assert to_eof < 1.0 and err == b""
    doc = json.loads(out)
    schema_util.assert_valid("cli/check", doc)
    running = hooked(tracker, first)
    assert all(tracker.alive(p) for p in running.all())  # the hook outlives the check
    assert not second.exists()  # hooks of one event run one after the other


def test_the_supervisor_and_hook_hold_no_descriptor_of_the_caller_and_have_own_groups(
    tmp_path: Path, tracker: Tracker
) -> None:
    pid_file = tmp_path / "pid"
    caller = Caller(tmp_path, hook_config(tmp_path, hook(sleeper(pid_file))))
    try:
        caller.read_to_eof()
        caller.proc.wait(timeout=5)
        running = hooked(tracker, pid_file)
        for pid in running.all():
            assert not (fd_links(pid) & caller.pipe_links), pid
        sup = running.supervisor
        assert os.getsid(sup) == sup == os.getpgid(sup)  # its own session and group
        assert os.getpgid(running.hook) == running.hook != sup  # the hook's own group
        for pid in running.watchdog:
            assert os.getpgid(pid) == pid
        assert os.getsid(running.hook) == sup
    finally:
        caller.close()


def test_the_hook_outlives_the_caller_closing_its_pipes_and_finishing(
    tmp_path: Path, tracker: Tracker
) -> None:
    marker = tmp_path / "done"
    config = hook_config(tmp_path, hook(f"sleep 1; touch {marker}"))
    caller = Caller(tmp_path, config)
    caller.read_to_eof()
    assert caller.proc.wait(timeout=5) == 0
    caller.close()  # the caller closes everything and goes away
    wait_exists(marker, 10)
    deadline = time.monotonic() + 10
    while hook_dirs(tmp_path) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert hook_dirs(tmp_path) == []  # the directory is removed when the hook ends


def test_a_failing_and_a_hanging_hook_never_change_the_check_result(
    tmp_path: Path, tracker: Tracker
) -> None:
    pid_file = tmp_path / "pid"
    config = hook_config(tmp_path, hook("exit 9"), hook(sleeper(pid_file, 20)))
    assert (
        gatectl(tmp_path, "set", "p", "enforced", "--actor", "human:ann", config=config).returncode
        == 0
    )
    caller = Caller(tmp_path, config, stdin=b'{"ci": "bad"}')
    try:
        out, err, to_eof = caller.read_to_eof()
        code = caller.proc.wait(timeout=2)
    finally:
        caller.close()
    doc = json.loads(out)
    schema_util.assert_valid("cli/check", doc)
    assert to_eof < 1.0 and code == 11
    assert err.decode() == f"gatectl: deny p@*: check_denied (r) {doc['decision_id']}\n"
    assert out.count(b"\n") == 1
    ev = wait_for_event(tmp_path, "hook_failed")
    assert ev["data"] == {"index": 0, "reason": "exit", "exit_code": 9}
    hooked(tracker, pid_file)  # the second hook is running (and is cleaned up by the tracker)


def test_the_payload_validates_against_the_schema_and_carries_no_input_text(
    tmp_path: Path,
) -> None:
    out_file = tmp_path / "payload.out"
    config = hook_config(tmp_path, hook(f"cat > {out_file}"))
    canary = "INPUT-CANARY-8841"
    caller = Caller(tmp_path, config, stdin=json.dumps({"ci": "ok", "note": canary}).encode())
    try:
        result, _, _ = caller.read_to_eof()
        caller.proc.wait(timeout=5)
    finally:
        caller.close()
    doc = json.loads(result)
    payload = read_json_file(out_file)
    schema_util.assert_valid("hooks/post-decision", payload)
    assert payload["object_id"] == doc["decision_id"]
    assert payload["decision"] == doc["decision"] and payload["scope"] == "*"
    assert payload["repo"] is None and "labels" not in payload
    assert canary not in json.dumps(payload)
    assert [c["name"] for c in payload["checks"]] == ["r"]


def test_a_hook_timeout_is_logged_and_its_group_killed(tmp_path: Path, tracker: Tracker) -> None:
    pid_file = tmp_path / "pid"
    config = hook_config(tmp_path, hook(sleeper(pid_file, 30), timeout="1s"))
    caller = Caller(tmp_path, config)
    try:
        caller.read_to_eof()
        caller.proc.wait(timeout=5)
    finally:
        caller.close()
    running = hooked(tracker, pid_file)
    ev = wait_for_event(tmp_path, "hook_failed", 15)
    assert ev["data"]["reason"] == "timeout" and ev["hook"] == "post-decision"
    assert tracker.wait_dead(running.hook, 5.0)
    assert tracker.wait_dead(running.supervisor, 10.0)
    assert hook_dirs(tmp_path) == []


def test_sigterm_to_the_supervisor_kills_the_hook_group_and_removes_the_directory(
    tmp_path: Path, tracker: Tracker
) -> None:
    pid_file = tmp_path / "pid"
    caller = Caller(tmp_path, hook_config(tmp_path, hook(sleeper(pid_file, 60))))
    try:
        caller.read_to_eof()
        caller.proc.wait(timeout=5)
    finally:
        caller.close()
    running = hooked(tracker, pid_file)
    assert len(hook_dirs(tmp_path)) == 1
    os.kill(running.supervisor, signal.SIGTERM)  # the recorded, verified supervisor pid
    assert tracker.wait_dead(running.hook, 10.0)
    assert tracker.wait_dead(running.supervisor, 10.0)
    assert hook_dirs(tmp_path) == []
    assert wait_for_event(tmp_path, "hook_failed")["data"]["reason"] == "terminated"


def test_a_sigkilled_supervisor_leaves_its_directory_and_the_watchdog_kills_the_hook(
    tmp_path: Path, tracker: Tracker
) -> None:
    pid_file = tmp_path / "pid"
    caller = Caller(tmp_path, hook_config(tmp_path, hook(sleeper(pid_file, 60))))
    try:
        caller.read_to_eof()
        caller.proc.wait(timeout=5)
    finally:
        caller.close()
    running: Hooked = hooked(tracker, pid_file)
    (directory,) = hook_dirs(tmp_path)
    os.kill(running.supervisor, signal.SIGKILL)
    assert tracker.wait_dead(running.hook, 10.0)  # the lifeline watchdog killed the group
    assert directory.is_dir() and (directory / "payload.json").exists()
    assert json.loads((directory / "owner").read_text())["pid"] == running.supervisor
    time.sleep(0)  # nothing removes it: that is reconcile's
    assert directory.is_dir()
    assert log_events(tmp_path) == []


def test_a_hook_that_cannot_write_to_the_callers_streams_and_stays_silent(
    tmp_path: Path,
) -> None:
    done = tmp_path / "done"
    config = hook_config(
        tmp_path, hook(f"echo LOUD; echo LOUD >&2; echo LOUD > /dev/tty; touch {done}")
    )
    caller = Caller(tmp_path, config)
    try:
        out, err, _ = caller.read_to_eof()
        caller.proc.wait(timeout=5)
    finally:
        caller.close()
    wait_exists(done)
    assert b"LOUD" not in out and b"LOUD" not in err
    assert out.count(b"\n") == 1


def test_the_state_directory_of_a_run_holds_no_leftovers_after_a_clean_hook(
    tmp_path: Path,
) -> None:
    done = tmp_path / "done"
    caller = Caller(tmp_path, hook_config(tmp_path, hook(f"touch {done}")))
    try:
        caller.read_to_eof()
        caller.proc.wait(timeout=5)
    finally:
        caller.close()
    wait_exists(done)
    deadline = time.monotonic() + 10
    while hook_dirs(tmp_path) and time.monotonic() < deadline:
        time.sleep(0.02)
    assert hook_dirs(tmp_path) == []
    assert log_events(tmp_path) == []
    assert state_dir(tmp_path).is_dir()


def test_a_check_killed_with_sigkill_leaves_no_process_holding_the_callers_pipes(
    tmp_path: Path, tracker: Tracker
) -> None:
    script_pid, marker = tmp_path / "script.pid", tmp_path / "hook.ran"
    slow = {
        "name": "s",
        "type": "script",
        "argv": ["/bin/sh", "-c", f"echo $$ > {script_pid}; exec sleep 60"],
        "timeout": "60s",
    }
    config = config_file(
        tmp_path,
        {
            "policies": {"p": {"checks": [slow]}},
            "hooks": {"post-decision": [hook(f"touch {marker}")]},
        },
    )
    caller = Caller(tmp_path, config)
    try:
        pid = read_pid(script_pid)
        tracker.track_pid(pid, cmdline_contains=b"sleep")
        caller.proc.kill()  # SIGKILL to the check, by its own Popen handle
        started = time.monotonic()
        out, err, _ = caller.read_to_eof()  # EOF: nothing else holds the caller's pipes
        assert time.monotonic() - started < 3.0
        caller.proc.wait(timeout=5)
    finally:
        caller.close()
    assert out == b"" and err == b""
    assert tracker.wait_dead(pid, 5.0)  # the lifeline watchdog killed the script's group
    time.sleep(0.5)
    assert not marker.exists() and hook_dirs(tmp_path) == []  # no decision, no hook
