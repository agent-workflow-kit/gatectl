"""The hook runner (``gatectl.hooks``) against real ``sh -c`` hooks: order, payload file, timeout,
environment, log events and clean-up. Every process is recorded by the ``tracker`` fixture and
killed by its recorded handle; nothing is killed by pattern."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

from gatectl import hooks
from gatectl.hooks import HookCommand, HookEvent
from tests.proc_util import Tracker, read_pid

BASE_ENV = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}


def event(*cmds: tuple[str, float], payload: dict[str, Any] | None = None, **kw: Any) -> HookEvent:
    fields: dict[str, Any] = {
        "hook": "post-decision",
        "object_type": "decision",
        "object_id": "gd-abcdefghijkl",
        "payload": payload if payload is not None else {"tool": "gatectl", "k": "v"},
        "commands": tuple(HookCommand(c, t) for c, t in cmds),
        "policy": "p",
        "scope": "*",
        "decision_id": "gd-abcdefghijkl",
    }
    fields.update(kw)
    return HookEvent(**fields)


def log_events(state: Path) -> list[dict[str, Any]]:
    path = state / "log.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def run(tracker: Tracker, state: Path, ev: HookEvent, **kw: Any) -> list[hooks.HookReport]:
    kw.setdefault("environ", BASE_ENV)
    kw.setdefault("kill_grace", 0.3)
    return hooks.run_hooks(tracker.gateway(), ev, state_dir=state, **kw)


def test_the_payload_file_is_the_hooks_stdin_and_its_directory_is_removed(
    tracker: Tracker, tmp_path: Path
) -> None:
    state = tmp_path / "state"
    out = tmp_path / "out"
    seen = tmp_path / "seen"
    cmd = f"cat > {out}; ls -l /proc/$$/fd/0 > {seen}; readlink /proc/$$/fd/0 >> {seen}"
    reports = run(tracker, state, event((cmd, 10)))
    assert [r.status for r in reports] == ["exited"]
    assert json.loads(out.read_text()) == {"tool": "gatectl", "k": "v"}
    inside = seen.read_text().splitlines()[-1]
    assert inside.startswith(str(state / "tmp" / "hook-")) and inside.endswith("/payload.json")
    assert list((state / "tmp").iterdir()) == []
    assert log_events(state) == []  # a clean exit writes nothing


def test_hooks_of_one_event_run_one_after_the_other_in_config_order(
    tracker: Tracker, tmp_path: Path
) -> None:
    trace = tmp_path / "trace"
    cmds = [
        (f"echo start{i} >> {trace}; sleep 0.2; echo end{i} >> {trace}", 10.0) for i in range(3)
    ]
    run(tracker, tmp_path / "state", event(*cmds))
    assert trace.read_text().split() == [f"{w}{i}" for i in range(3) for w in ("start", "end")]


def test_output_is_discarded_and_no_descriptor_above_2_is_held(
    tracker: Tracker, tmp_path: Path
) -> None:
    seen = tmp_path / "seen"
    script = tmp_path / "probe.py"
    script.write_text(
        "import json, os, sys\n"
        "print('noise'); sys.stderr.write('noise')\n"
        "names = os.listdir('/proc/self/fd')\n"
        "links = {}\n"
        "for n in names:\n"
        "    try:\n"
        "        links[n] = os.readlink('/proc/self/fd/' + n)\n"
        "    except OSError:\n"
        "        pass\n"
        f"open({str(seen)!r}, 'w').write(json.dumps(links))\n"
    )
    run(tracker, tmp_path / "state", event((f"{sys.executable} {script}", 10)))
    fds = json.loads(seen.read_text())
    assert fds["0"].endswith("/payload.json")
    assert (fds["1"], fds["2"]) == ("/dev/null", "/dev/null")
    # Whatever else the probe's interpreter holds (its listing handle, a runtime file), nothing of
    # gatectl's: no pipe, no socket, no file of the state tree or the test's directory.
    for n, target in fds.items():
        if int(n) > 2:
            assert not target.startswith(("pipe:", "socket:", "anon_inode:")), (n, target)
            assert str(tmp_path) not in target, (n, target)


def test_the_environment_is_gatectls_plus_the_three_reserved_names(
    tracker: Tracker, tmp_path: Path
) -> None:
    out = tmp_path / "env"
    env = {
        **BASE_ENV,
        "GATECTL_HOOK": "spoofed",
        "GATECTL_ID": "spoofed",
        "GATECTL_OBJECT_TYPE": "spoofed",
        "KEEP_ME": "yes",
    }
    run(tracker, tmp_path / "state", event((f"env > {out}", 10)), environ=env)
    got = dict(line.split("=", 1) for line in out.read_text().splitlines() if "=" in line)
    assert got["GATECTL_HOOK"] == "post-decision"
    assert got["GATECTL_ID"] == "gd-abcdefghijkl"
    assert got["GATECTL_OBJECT_TYPE"] == "decision"
    assert got["KEEP_ME"] == "yes"
    assert not any("payload" in v or "k=v" in v for v in got.values())


def test_the_payload_never_reaches_the_environment_or_argv(
    tracker: Tracker, tmp_path: Path
) -> None:
    out = tmp_path / "dump"
    secret = "PAYLOAD-CANARY-31337"
    cmd = f"(env; cat /proc/$$/cmdline | tr '\\0' ' ') > {out}"
    run(tracker, tmp_path / "state", event((cmd, 10), payload={"canary": secret}))
    assert secret not in out.read_text()


def test_no_substitution_is_done_in_the_command(tracker: Tracker, tmp_path: Path) -> None:
    out = tmp_path / "out"
    run(tracker, tmp_path / "state", event((f"printf '%s' '{{object_id}}{{policy}}' > {out}", 10)))
    assert out.read_text() == "{object_id}{policy}"


def test_a_nonzero_exit_is_a_hook_failed_event_and_the_next_hook_still_runs(
    tracker: Tracker, tmp_path: Path
) -> None:
    state = tmp_path / "state"
    marker = tmp_path / "second"
    reports = run(tracker, state, event(("exit 3", 10), (f"touch {marker}", 10)))
    assert [(r.status, r.code) for r in reports] == [("exited", 3), ("exited", 0)]
    assert marker.exists()
    (rec,) = log_events(state)
    assert (rec["event"], rec["level"], rec["hook"]) == ("hook_failed", "warn", "post-decision")
    assert rec["decision_id"] == "gd-abcdefghijkl" and rec["policy"] == "p"
    assert rec["data"] == {"index": 0, "reason": "exit", "exit_code": 3}
    assert "exit 3" not in json.dumps(rec)  # the command text is never logged


def test_a_hook_that_ignores_term_is_killed_at_its_timeout_with_its_whole_group(
    tracker: Tracker, tmp_path: Path
) -> None:
    state = tmp_path / "state"
    pids = tmp_path / "pids"
    cmd = (
        f"trap '' TERM; (trap '' TERM; echo $$ > {pids}.child; sleep 60) & "
        f"echo $$ > {pids}.leader; sleep 60"
    )
    reports = run(tracker, state, event((cmd, 0.5)))
    assert reports[0].status == "timeout"
    for name in ("leader", "child"):
        pid = read_pid(Path(f"{pids}.{name}"))
        tracker.track_pid(pid)
        assert tracker.wait_dead(pid, 5.0)
    (rec,) = log_events(state)
    assert (rec["event"], rec["data"]["reason"]) == ("hook_failed", "timeout")
    assert list((state / "tmp").iterdir()) == []


def test_background_children_are_swept_when_the_hook_exits(
    tracker: Tracker, tmp_path: Path
) -> None:
    pid_file = tmp_path / "bg"
    run(tracker, tmp_path / "state", event((f"sleep 60 & echo $! > {pid_file}", 10)))
    pid = read_pid(pid_file)
    tracker.track_pid(pid)
    assert tracker.wait_dead(pid, 5.0)


def test_a_missing_shell_command_is_a_failed_hook_not_a_crash(
    tracker: Tracker, tmp_path: Path
) -> None:
    state = tmp_path / "state"
    reports = run(tracker, state, event(("/nonexistent/hook-tool", 10)))
    assert reports[0].status == "exited" and reports[0].code == 127
    assert log_events(state)[0]["event"] == "hook_failed"


def test_cancel_kills_the_running_hook_skips_the_rest_and_removes_the_directory(
    tracker: Tracker, tmp_path: Path
) -> None:
    state = tmp_path / "state"
    pid_file = tmp_path / "pid"
    flag = {"on": False}

    def cancel() -> bool:
        if pid_file.exists():
            flag["on"] = True
        return flag["on"]

    reports = run(
        tracker, state, event((f"echo $$ > {pid_file}; sleep 60", 30), ("true", 5)), cancel=cancel
    )
    assert [r.status for r in reports] == ["cancelled", "skipped"]
    pid = read_pid(pid_file)
    tracker.track_pid(pid)
    assert tracker.wait_dead(pid, 5.0)
    assert list((state / "tmp").iterdir()) == []
    events = [(e["event"], e["data"]["reason"]) for e in log_events(state)]
    assert events == [("hook_failed", "terminated"), ("hook_skipped", "terminated")]


def test_an_uncreatable_directory_skips_the_hook_and_never_raises(
    tracker: Tracker, tmp_path: Path
) -> None:
    blocker = tmp_path / "state"
    blocker.write_text("a file where the state directory should be")
    reports = run(tracker, blocker, event(("true", 5)))
    assert [r.status for r in reports] == ["skipped"]


def test_too_many_hooks_for_one_event_are_capped(tracker: Tracker, tmp_path: Path) -> None:
    n = hooks.MAX_HOOKS + 3
    reports = run(tracker, tmp_path / "state", event(*[("true", 5.0)] * n))
    assert [r.status for r in reports].count("skipped") == 3
    events = log_events(tmp_path / "state")
    assert [e["event"] for e in events] == ["hook_skipped"] * 3
    assert events[0]["data"]["reason"] == "too_many_hooks"


def test_hostile_values_are_refused_before_anything_starts(
    tracker: Tracker, tmp_path: Path
) -> None:
    for bad in ("a\x00b", ""):
        reports = run(tracker, tmp_path / "state", event((bad, 5)))
        assert [r.status for r in reports] == ["skipped"]
    reports = run(
        tracker, tmp_path / "state", event(("true", 5), object_id="x\x00y"), environ=BASE_ENV
    )
    assert [r.status for r in reports] == ["skipped"]
    assert {e["event"] for e in log_events(tmp_path / "state")} == {"hook_skipped"}


def test_a_failing_log_never_raises(tracker: Tracker, tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir()
    (state / "log.jsonl").mkdir()  # not appendable
    reports = run(tracker, state, event(("exit 1", 5)))
    assert reports[0].code == 1


def test_directory_and_payload_modes_while_the_hook_runs(tracker: Tracker, tmp_path: Path) -> None:
    state = tmp_path / "state"
    out = tmp_path / "modes"
    cmd = f"stat -c '%a' $(dirname $(readlink /proc/$$/fd/0)) $(readlink /proc/$$/fd/0) > {out}"
    run(tracker, state, event((cmd, 10)))
    assert out.read_text().split() == ["700", "600"]
    assert stat.S_IMODE(os.stat(state).st_mode) == 0o700
