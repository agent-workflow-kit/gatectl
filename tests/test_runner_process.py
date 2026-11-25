"""The script runner against real (tiny Python) children: groups, caps, deadlines, stragglers.

Every process is recorded by the ``tracker`` fixture and killed by its recorded handle on
teardown; a test that leaves one running fails. Nothing is killed by pattern.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

import pytest

from gatectl.gateway import ChildSpec, Stdio
from gatectl.runner import RunResult, RunSpec, run_process
from tests.proc_util import Tracker, read_pid

PY = sys.executable


def spec(code: str, *args: str, **kw: object) -> RunSpec:
    fields: dict[str, object] = {
        "argv": (PY, "-c", code, *args),
        "env": {},
        "cwd": "/",
        "timeout": 10.0,
        "kill_grace": 0.3,
        "drain_grace": 0.3,
    }
    fields.update(kw)
    return RunSpec(**fields)  # type: ignore[arg-type]


def run(tracker: Tracker, s: RunSpec, **kw: object) -> RunResult:
    return run_process(tracker.gateway(), s, **kw)  # type: ignore[arg-type]


# --- plain exits, signals, output ----------------------------------------------------------


def test_exit_zero_with_output(tracker: Tracker) -> None:
    r = run(tracker, spec("import sys; sys.stdout.write('hi'); sys.stderr.write('err')"))
    assert (r.status, r.code, r.signal) == ("exited", 0, None)
    assert r.stdout == b"hi"
    assert not r.stdout_truncated and not r.stderr_truncated


@pytest.mark.parametrize("code", [1, 2, 11, 13, 126, 127, 255])
def test_exit_codes_pass_through(tracker: Tracker, code: int) -> None:
    r = run(tracker, spec(f"import sys; sys.exit({code})"))
    assert (r.status, r.code) == ("exited", code)


def test_child_killed_by_a_signal_is_reported_as_one(tracker: Tracker) -> None:
    r = run(tracker, spec("import os, signal; os.kill(os.getpid(), signal.SIGKILL)"))
    assert (r.status, r.code, r.signal) == ("signaled", None, 9)


def test_zero_bytes_of_output(tracker: Tracker) -> None:
    r = run(tracker, spec("pass"))
    assert r.stdout == b"" and not r.stdout_truncated


def test_stdout_cap_keeps_the_first_bytes_of_100_mb(tracker: Tracker) -> None:
    code = (
        "import sys\n"
        "block = bytes(range(256)) * 4096\n"  # 1 MiB
        "for _ in range(100): sys.stdout.buffer.write(block)\n"
    )
    r = run(tracker, spec(code, timeout=60.0))
    assert r.status == "exited" and r.code == 0
    assert r.stdout_truncated
    assert r.stdout == (bytes(range(256)) * 4096)[:65536]


def test_output_exactly_at_the_cap_is_not_truncated(tracker: Tracker) -> None:
    r = run(tracker, spec("import sys; sys.stdout.buffer.write(b'x' * 65536)"))
    assert len(r.stdout) == 65536 and not r.stdout_truncated


def test_one_byte_over_the_cap_is_truncated(tracker: Tracker) -> None:
    r = run(tracker, spec("import sys; sys.stdout.buffer.write(b'x' * 65537)"))
    assert len(r.stdout) == 65536 and r.stdout_truncated


def test_custom_cap(tracker: Tracker) -> None:
    r = run(tracker, spec("import sys; sys.stdout.buffer.write(b'x' * 100)", stdout_cap=10))
    assert r.stdout == b"x" * 10 and r.stdout_truncated


def test_stderr_is_capped_and_never_returned(tracker: Tracker) -> None:
    r = run(tracker, spec("import sys; sys.stderr.buffer.write(b'e' * 200000)"))
    assert r.stderr_truncated and not r.stdout_truncated
    assert not hasattr(r, "stderr")


def test_both_pipes_flooded_at_once_do_not_deadlock(tracker: Tracker) -> None:
    # Reading one pipe to EOF before the other would deadlock this child on a full stderr pipe.
    code = (
        "import os\n"
        "chunk = b'z' * 65536\n"
        "for _ in range(80):\n"
        "    os.write(2, chunk)\n"
        "    os.write(1, chunk)\n"
    )
    r = run(tracker, spec(code, timeout=30.0))
    assert (r.status, r.code) == ("exited", 0)
    assert r.stdout_truncated and r.stderr_truncated


def test_binary_and_non_utf8_output_is_returned_as_raw_bytes(tracker: Tracker) -> None:
    r = run(
        tracker,
        spec("import sys; sys.stdout.buffer.write(b'\\xff\\xfe\\x00bad\\xed\\xa0\\x80')"),
    )
    assert r.stdout == b"\xff\xfe\x00bad\xed\xa0\x80"


def test_closed_stdout_still_exits_cleanly(tracker: Tracker) -> None:
    r = run(tracker, spec("import os, time; os.close(1); time.sleep(0.1)"))
    assert (r.status, r.code, r.stdout) == ("exited", 0, b"")


def test_both_output_streams_closed_while_the_child_keeps_running(tracker: Tracker) -> None:
    r = run(tracker, spec("import os, time; os.close(1); os.close(2); time.sleep(60)", timeout=0.4))
    assert r.status == "timeout"


# --- stdin ---------------------------------------------------------------------------------


def test_no_payload_means_devnull(tracker: Tracker) -> None:
    r = run(tracker, spec("import sys; sys.stdout.buffer.write(sys.stdin.buffer.read() + b'|')"))
    assert r.stdout == b"|"


def test_payload_is_delivered_in_full(tracker: Tracker) -> None:
    payload = os.urandom(300_000)
    code = (
        "import hashlib, sys\n"
        "d = sys.stdin.buffer.read()\n"
        "sys.stdout.write(hashlib.sha256(d).hexdigest() + ' ' + str(len(d)))\n"
    )
    r = run(tracker, spec(code, stdin_data=payload))
    assert r.stdout.decode() == f"{hashlib.sha256(payload).hexdigest()} {len(payload)}"


def test_empty_payload_is_an_empty_stdin_not_devnull_inheritance(tracker: Tracker) -> None:
    code = "import os, stat, sys; sys.stdout.write(str(stat.S_ISFIFO(os.fstat(0).st_mode)))"
    assert run(tracker, spec(code, stdin_data=b"")).stdout == b"True"
    assert run(tracker, spec(code)).stdout == b"False"


def test_child_that_exits_without_reading_a_huge_stdin_does_not_hang(tracker: Tracker) -> None:
    started = time.monotonic()
    r = run(tracker, spec("pass", stdin_data=b"x" * 5_000_000))
    assert (r.status, r.code) == ("exited", 0)
    assert time.monotonic() - started < 5


def test_child_that_closes_stdin_early_is_not_an_error(tracker: Tracker) -> None:
    code = "import os, time; os.close(0); time.sleep(0.2)"
    r = run(tracker, spec(code, stdin_data=b"x" * 5_000_000))
    assert (r.status, r.code) == ("exited", 0)


def test_child_that_never_reads_a_5_mb_stdin_times_out(tracker: Tracker) -> None:
    started = time.monotonic()
    r = run(tracker, spec("import time; time.sleep(60)", stdin_data=b"x" * 5_000_000, timeout=0.5))
    assert r.status == "timeout"
    assert time.monotonic() - started < 5


# --- timeouts and the kill sequence --------------------------------------------------------


def test_timeout_terminates_a_child_that_honours_sigterm_without_waiting_the_grace(
    tracker: Tracker,
) -> None:
    started = time.monotonic()
    r = run(tracker, spec("import time; time.sleep(60)", timeout=0.3, kill_grace=30.0))
    assert r.status == "timeout"
    assert r.signal == 15
    assert time.monotonic() - started < 10


def test_timeout_kills_a_child_that_ignores_sigterm_after_the_grace(tracker: Tracker) -> None:
    code = "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
    started = time.monotonic()
    r = run(tracker, spec(code, timeout=0.3, kill_grace=0.5))
    elapsed = time.monotonic() - started
    assert (r.status, r.signal) == ("timeout", 9)
    assert 0.8 <= elapsed < 10  # timeout + grace, not earlier


def test_timeout_leaves_no_process_behind_including_a_grandchild_ignoring_sigterm(
    tracker: Tracker, tmp_path: Path
) -> None:
    code = (
        "import os, signal, sys, time\n"
        "d = sys.argv[1]\n"
        "if os.fork() == 0:\n"
        "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "    open(d + '/gc', 'w').write(str(os.getpid()))\n"
        "    time.sleep(60)\n"
        "    os._exit(0)\n"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "open(d + '/leader', 'w').write(str(os.getpid()))\n"
        "time.sleep(60)\n"
    )
    marker = f"{tmp_path}"
    result: list[RunResult] = []

    def go() -> None:
        result.append(run(tracker, spec(code, marker, timeout=1.0, kill_grace=0.4)))

    import threading

    t = threading.Thread(target=go)
    t.start()
    gc = read_pid(tmp_path / "gc")
    tracker.track_pid(gc, cmdline_contains=marker.encode())
    t.join(30)
    assert not t.is_alive()
    assert result[0].status == "timeout"
    assert tracker.wait_dead(gc, 5), "the grandchild survived the group kill"


def test_leader_exit_sweeps_a_straggler_that_holds_the_pipes(
    tracker: Tracker, tmp_path: Path
) -> None:
    code = (
        "import os, sys, time\n"
        "if os.fork() == 0:\n"
        "    open(sys.argv[1] + '/gc', 'w').write(str(os.getpid()))\n"
        "    time.sleep(60)\n"
        "    os._exit(0)\n"
        "sys.stdout.write('done')\n"
    )
    started = time.monotonic()
    import threading

    result: list[RunResult] = []
    t = threading.Thread(target=lambda: result.append(run(tracker, spec(code, str(tmp_path)))))
    t.start()
    gc = read_pid(tmp_path / "gc")
    tracker.track_pid(gc, cmdline_contains=str(tmp_path).encode())
    t.join(30)
    assert not t.is_alive()
    assert time.monotonic() - started < 8
    r = result[0]
    assert (r.status, r.code, r.stdout) == ("exited", 0, b"done")
    assert not r.pipes_held
    assert tracker.wait_dead(gc, 5)


def test_a_child_that_forks_and_exits_immediately(tracker: Tracker) -> None:
    r = run(tracker, spec("import os; os._exit(0) if os.fork() else os._exit(0)"))
    assert (r.status, r.code) == ("exited", 0)


def test_straggler_that_left_the_group_cannot_hang_the_runner(
    tracker: Tracker, tmp_path: Path
) -> None:
    # A setsid process leaves the group and keeps the pipe open (a documented residual risk):
    # the runner must still return, after its drain deadline, and say the pipes were held.
    code = (
        "import os, sys, time\n"
        "if os.fork() == 0:\n"
        "    os.setsid()\n"
        "    open(sys.argv[1] + '/gc', 'w').write(str(os.getpid()))\n"
        "    time.sleep(60)\n"
        "    os._exit(0)\n"
        "sys.stdout.write('out')\n"
    )
    import threading

    result: list[RunResult] = []
    t = threading.Thread(target=lambda: result.append(run(tracker, spec(code, str(tmp_path)))))
    t.start()
    gc = read_pid(tmp_path / "gc")
    tracker.track_pid(gc, cmdline_contains=str(tmp_path).encode())
    tracker.expect_survivor(gc)
    t.join(30)
    assert not t.is_alive()
    r = result[0]
    assert (r.status, r.code, r.stdout) == ("exited", 0, b"out")
    assert r.pipes_held


def test_cancel_callback_runs_the_kill_sequence(tracker: Tracker) -> None:
    calls = {"n": 0}

    def cancel() -> bool:
        calls["n"] += 1
        return calls["n"] > 5

    r = run(tracker, spec("import time; time.sleep(60)"), cancel=cancel)
    assert r.status == "cancelled"
    assert r.signal == 15


def test_a_leader_that_exits_on_its_own_just_before_the_deadline_is_not_a_timeout(
    tracker: Tracker,
) -> None:
    r = run(tracker, spec("import time; time.sleep(0.1)", timeout=5.0))
    assert r.status == "exited"


# --- groups, descriptors, environment, cwd ----------------------------------------------


def test_child_runs_in_its_own_process_group_and_never_ours(tracker: Tracker) -> None:
    r = run(
        tracker,
        spec("import os; print(os.getpid(), os.getpgrp(), os.getsid(0), sep=',')"),
    )
    pid, pgrp, _sid = (int(x) for x in r.stdout.decode().split(","))
    assert pgrp == pid
    assert pgrp != os.getpgrp()


def test_every_child_is_started_in_its_own_group_with_explicit_streams(tracker: Tracker) -> None:
    gw = tracker.gateway()
    run_process(gw, spec("pass"))
    assert len(gw.specs) == 2  # the watchdog and the check
    for s in gw.specs:
        assert isinstance(s, ChildSpec)
        assert s.own_group
        assert Stdio.DEVNULL in (s.stdin, s.stdout, s.stderr) or s.stdin is Stdio.PIPE
    assert gw.specs[1].stdin is Stdio.DEVNULL
    assert gw.specs[1].stdout is Stdio.PIPE and gw.specs[1].stderr is Stdio.PIPE


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="needs /proc")
def test_callers_descriptors_are_never_inherited(tracker: Tracker, tmp_path: Path) -> None:
    f = open(tmp_path / "held", "w")  # noqa: SIM115
    os.set_inheritable(f.fileno(), True)
    try:
        code = (
            "import json, os\n"
            "fds = os.listdir('/proc/self/fd')\n"
            "print(json.dumps({int(f): os.path.realpath('/proc/self/fd/' + f) for f in fds}))"
        )
        r = run(tracker, spec(code))
    finally:
        f.close()
    fds = json.loads(r.stdout.decode())
    # (Some interpreters keep an fd of their own open, so the test names the file, not a count.)
    assert os.path.realpath(tmp_path / "held") not in fds.values()


def test_environment_is_exactly_what_was_given(tracker: Tracker) -> None:
    code = "import os, json; print(json.dumps(dict(os.environ), sort_keys=True))"
    r = run(tracker, spec(code, env={"A": "1", "B": "two words"}))
    seen = json.loads(r.stdout)
    # Python itself may add LC_CTYPE coercion on some builds; nothing of ours is inherited.
    assert seen["A"] == "1" and seen["B"] == "two words"
    assert "HOME" not in seen and "PATH" not in seen and "XDG_STATE_HOME" not in seen


def test_secrets_in_gatectls_environment_never_reach_the_child(
    tracker: Tracker, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "hunter2")
    r = run(tracker, spec("import os; print(os.environ.get('GITHUB_TOKEN'))"))
    assert r.stdout.strip() == b"None"


def test_cwd_is_honoured(tracker: Tracker, tmp_path: Path) -> None:
    r = run(tracker, spec("import os; print(os.getcwd())", cwd=str(tmp_path)))
    assert r.stdout.decode().strip() == str(tmp_path.resolve())


def test_missing_cwd_is_not_started_not_tool_missing(tracker: Tracker, tmp_path: Path) -> None:
    r = run(tracker, spec("pass", cwd=str(tmp_path / "gone")))
    assert r.status == "not_started"


# --- argv0 ---------------------------------------------------------------------------------


def test_missing_executable_is_tool_missing(tracker: Tracker, tmp_path: Path) -> None:
    r = run(tracker, spec("", argv=(str(tmp_path / "nope"),)))
    assert r.status == "tool_missing"


def test_non_executable_file_is_tool_missing(tracker: Tracker, tmp_path: Path) -> None:
    f = tmp_path / "plain"
    f.write_text("#!/bin/sh\n")
    f.chmod(0o644)
    assert run(tracker, spec("", argv=(str(f),))).status == "tool_missing"


def test_directory_is_tool_missing(tracker: Tracker, tmp_path: Path) -> None:
    assert run(tracker, spec("", argv=(str(tmp_path),))).status == "tool_missing"


def test_executable_without_shebang_or_format_is_tool_missing(
    tracker: Tracker, tmp_path: Path
) -> None:
    f = tmp_path / "junk"
    f.write_bytes(b"\x00\x01 not a program")
    f.chmod(0o755)
    assert run(tracker, spec("", argv=(str(f),))).status == "tool_missing"


def test_shebang_to_a_missing_interpreter_is_tool_missing(tracker: Tracker, tmp_path: Path) -> None:
    f = tmp_path / "s"
    f.write_text("#!/nonexistent/interp\n")
    f.chmod(0o755)
    assert run(tracker, spec("", argv=(str(f),))).status == "tool_missing"


@pytest.mark.parametrize("argv0", ["sh", "./x", "bin/x", ""])
def test_relative_argv0_is_refused_and_never_searched_on_path(tracker: Tracker, argv0: str) -> None:
    gw = tracker.gateway()
    with pytest.raises(ValueError, match="absolute"):
        run_process(gw, spec("", argv=(argv0, "a")))
    assert gw.specs == []  # nothing was started


def test_relative_later_argv_elements_are_passed_through_untouched(tracker: Tracker) -> None:
    r = run(tracker, spec("import sys; print(sys.argv[1:])", "./rel", "../x", "a b"))
    assert r.stdout.decode().strip() == "['./rel', '../x', 'a b']"


def test_executable_script_runs_with_its_shebang(tracker: Tracker, tmp_path: Path) -> None:
    f = tmp_path / "ok"
    f.write_text(f"#!{PY}\nprint('hi')\n")
    f.chmod(0o755)
    r = run(tracker, spec("", argv=(str(f),)))
    assert (r.status, r.stdout) == ("exited", b"hi\n")


# --- argument validation -------------------------------------------------------------------


@pytest.mark.parametrize("t", [0, -1, float("nan"), float("inf")])
def test_timeout_must_be_a_positive_finite_number(t: float) -> None:
    with pytest.raises(ValueError, match="timeout"):
        spec("pass", timeout=t)


def test_negative_caps_and_graces_are_refused() -> None:
    for key in ("stdout_cap", "stderr_cap"):
        with pytest.raises(ValueError, match=key):
            spec("pass", **{key: -1})
    for key in ("kill_grace", "drain_grace"):
        with pytest.raises(ValueError, match=key):
            spec("pass", **{key: -0.1})


def test_env_must_be_a_string_mapping() -> None:
    with pytest.raises(ValueError, match="env"):
        spec("pass", env={"A": 1})


# --- no descriptor or process leaks across runs --------------------------------------------


@pytest.mark.skipif(not os.path.isdir("/proc/self/fd"), reason="needs /proc")
def test_runs_do_not_leak_descriptors(tracker: Tracker) -> None:
    run(tracker, spec("pass"))  # warm up
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(3):
        run(tracker, spec("import sys; sys.stdout.write('x')", stdin_data=b"y"))
        run(tracker, spec("import time; time.sleep(30)", timeout=0.2))
    assert len(os.listdir("/proc/self/fd")) == before
