"""The exit-code contract and strict stdout JSON, then the hostile-script cases end to end."""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest

from gatectl.runner import RunResult, ScriptOutcome, interpret, run_script
from tests.proc_util import Tracker, read_pid

PY = sys.executable
ARGV0 = "/opt/checks/scope"


def rr(**kw: object) -> RunResult:
    fields: dict[str, object] = {"status": "exited", "code": 0, "signal": None, "stdout": b""}
    fields.update(kw)
    return RunResult(**fields)  # type: ignore[arg-type]


def out(result: RunResult) -> ScriptOutcome:
    return interpret(ARGV0, result)


# --- the exit code decides -----------------------------------------------------------------


def test_exit_0_allows() -> None:
    o = out(rr())
    assert (o.verdict, o.reason, o.detail, o.warnings) == ("allow", None, None, ())


def test_exit_11_denies() -> None:
    o = out(rr(code=11))
    assert (o.verdict, o.reason, o.detail) == ("deny", "check_denied", "exit 11")


def test_exit_13_escalates_by_its_own_verdict() -> None:
    o = out(rr(code=13))
    assert (o.verdict, o.reason, o.detail) == ("escalate", "check_escalated", "exit 13")


@pytest.mark.parametrize("code", [1, 2, 10, 12, 14, 126, 127, 128, 137, 143, 255])
def test_any_other_exit_is_check_error(code: int) -> None:
    o = out(rr(code=code))
    assert (o.verdict, o.reason, o.detail) == ("escalate", "check_error", f"exit {code}")


def test_a_signal_is_check_error() -> None:
    o = out(rr(status="signaled", code=None, signal=11))
    assert (o.verdict, o.reason, o.detail) == ("escalate", "check_error", "signal 11")


def test_timeout() -> None:
    o = out(rr(status="timeout", code=None, signal=9))
    assert (o.verdict, o.reason, o.detail) == ("escalate", "timeout", "timeout")


def test_a_timeout_never_allows_even_if_the_child_said_so() -> None:
    o = out(rr(status="timeout", code=0, stdout=b'{"decision": "allow"}'))
    assert o.verdict == "escalate" and o.reason == "timeout"


def test_cancelled_is_check_error() -> None:
    o = out(rr(status="cancelled", code=None, signal=15))
    assert (o.verdict, o.reason, o.detail) == ("escalate", "check_error", "cancelled")


def test_tool_missing_names_the_command() -> None:
    o = out(rr(status="tool_missing", code=None))
    assert (o.verdict, o.reason, o.detail) == ("escalate", "tool_missing", ARGV0)


def test_tool_missing_detail_is_sanitized() -> None:
    o = interpret("/x/\x1b[31mevil\n", rr(status="tool_missing", code=None))
    assert o.detail is not None and "\x1b" not in o.detail and "\n" not in o.detail


def test_not_started() -> None:
    o = out(rr(status="not_started", code=None))
    assert (o.verdict, o.reason, o.detail) == ("escalate", "check_error", "not started")


# --- stdout JSON ---------------------------------------------------------------------------


def j(**obj: object) -> bytes:
    return json.dumps(obj).encode()


def test_reason_becomes_the_detail_of_a_check_that_did_not_allow() -> None:
    o = out(rr(code=11, stdout=j(reason="touches secrets/")))
    assert (o.verdict, o.detail) == ("deny", "touches secrets/")


def test_reason_is_used_for_errors_and_timeouts_too() -> None:
    assert out(rr(code=2, stdout=j(reason="boom"))).detail == "boom"
    assert out(rr(status="timeout", code=None, stdout=j(reason="slow"))).detail == "slow"


def test_an_allow_has_no_detail_even_with_a_reason() -> None:
    assert out(rr(stdout=j(reason="all good"))).detail is None


def test_a_long_reason_is_truncated_not_dropped() -> None:
    o = out(rr(code=11, stdout=j(reason="x" * 5000)))
    assert o.detail == "x" * 1024


def test_reason_is_sanitized() -> None:
    o = out(rr(code=11, stdout=j(reason="a\x1b[31mb‮c\x00d")))
    assert o.detail is not None
    assert all(ch.isprintable() for ch in o.detail)
    assert o.detail.startswith("a")


@pytest.mark.parametrize("reason", [5, None, ["x"], {"a": 1}, True])
def test_a_reason_of_the_wrong_type_drops_only_the_detail(reason: object) -> None:
    o = out(rr(code=11, stdout=j(reason=reason)))
    assert (o.verdict, o.reason, o.detail) == ("deny", "check_denied", "exit 11")


def test_an_empty_reason_falls_back_to_the_exit_form() -> None:
    assert out(rr(code=11, stdout=j(reason=""))).detail == "exit 11"


def test_unknown_keys_are_ignored() -> None:
    o = out(rr(code=11, stdout=j(reason="r", extra=[1, 2], other={"a": None})))
    assert (o.verdict, o.detail) == ("deny", "r")


@pytest.mark.parametrize(("code", "decision"), [(0, "allow"), (11, "deny"), (13, "escalate")])
def test_a_decision_that_agrees_changes_nothing(code: int, decision: str) -> None:
    o = out(rr(code=code, stdout=j(decision=decision)))
    assert o.reason in (None, "check_denied", "check_escalated")
    assert o.verdict == decision


@pytest.mark.parametrize(
    ("code", "decision"),
    [(0, "deny"), (0, "escalate"), (11, "allow"), (11, "escalate"), (13, "allow"), (13, "deny")],
)
def test_a_decision_that_disagrees_is_check_error(code: int, decision: str) -> None:
    o = out(rr(code=code, stdout=j(decision=decision, reason="why")))
    assert (o.verdict, o.reason) == ("escalate", "check_error")
    assert o.detail == "why"


@pytest.mark.parametrize("decision", ["maybe", "ALLOW", "", 0, None, ["allow"], True])
def test_a_decision_that_is_not_one_of_the_three_is_check_error(decision: object) -> None:
    o = out(rr(code=0, stdout=j(decision=decision)))
    assert (o.verdict, o.reason) == ("escalate", "check_error")


def test_a_decision_on_a_crash_changes_nothing() -> None:
    o = out(rr(code=2, stdout=j(decision="allow")))
    assert (o.verdict, o.reason) == ("escalate", "check_error")


@pytest.mark.parametrize(
    "stdout",
    [
        b"",
        b"not json",
        b"[1, 2]",
        b'"str"',
        b"12",
        b'{"reason": "a", "reason": "b"}',  # duplicate keys
        b'{"reason": "x"} trailing',
        b'{"reason": NaN}',
        b'{"reason": "\\ud800"}',  # lone surrogate
        b"\xef\xbb\xbf" + b'{"reason": "bom"}',
        b'{"reason": "\xff\xfe"}',  # bad UTF-8
        b"[" * 200 + b"]" * 200,  # deep nesting
        b'{"a":' * 200 + b"1" + b"}" * 200,
        b'{"reason": "cut',
    ],
)
def test_unparseable_output_drops_only_the_detail_never_the_verdict(stdout: bytes) -> None:
    o = out(rr(code=11, stdout=stdout))
    assert (o.verdict, o.reason, o.detail) == ("deny", "check_denied", "exit 11")
    assert out(rr(code=0, stdout=stdout)).verdict == "allow"
    assert out(rr(code=13, stdout=stdout)).verdict == "escalate"


def test_a_decision_inside_unparseable_output_is_not_trusted() -> None:
    o = out(rr(code=0, stdout=b'{"decision": "deny", "decision": "deny"}'))
    assert o.verdict == "allow"


def test_control_characters_in_output_cannot_reach_the_detail() -> None:
    o = out(rr(code=11, stdout=b'{"reason": "line\\nbreak\\u0000nul\\u001b[2Jesc"}'))
    assert o.detail is not None
    assert all(ch.isprintable() for ch in o.detail)


def test_truncated_stdout_warns_and_keeps_the_verdict() -> None:
    o = out(rr(code=11, stdout=j(reason="r"), stdout_truncated=True))
    assert o.warnings == ("output_truncated",) and o.verdict == "deny"


def test_truncated_stderr_warns_too_and_once() -> None:
    o = out(rr(code=0, stdout_truncated=True, stderr_truncated=True))
    assert o.warnings == ("output_truncated",)
    assert out(rr(stderr_truncated=True)).warnings == ("output_truncated",)


def test_duration_is_reported_in_milliseconds() -> None:
    assert out(rr(elapsed=1.2345)).duration_ms == 1234


# --- end to end: the hostile cases from the spike ------------------------------------------


def go(tracker: Tracker, code: str, *args: str, **kw: object) -> ScriptOutcome:
    params: dict[str, object] = {
        "argv": (PY, "-c", code, *args),
        "payload": b"{}",
        "timeout": 10.0,
        "env": {},
        "cwd": "/",
        "kill_grace": 0.3,
        "drain_grace": 0.3,
    }
    params.update(kw)
    return run_script(tracker.gateway(), **params)  # type: ignore[arg-type]


def test_exit_256_reads_as_0_documented_residual_risk(tracker: Tracker) -> None:
    # Residual risk (interface.md, Residual risks): the kernel keeps only the low 8 bits of an
    # exit status, so ``exit(256)`` is indistinguishable from a clean 0 and is an allow.
    # This test pins that behavior so a change to it is deliberate, not accidental.
    o = go(tracker, "import os; os._exit(256)")
    assert (o.verdict, o.reason) == ("allow", None)


def test_hostile_100_mb_of_output_with_a_crash_exit(tracker: Tracker) -> None:
    code = "import sys\nfor _ in range(100): sys.stdout.buffer.write(b'A' * 1048576)\nsys.exit(2)"
    o = go(tracker, code, timeout=60.0)
    assert (o.verdict, o.reason) == ("escalate", "check_error")
    assert o.warnings == ("output_truncated",)


def test_hostile_closed_stdout_then_escalate(tracker: Tracker) -> None:
    o = go(tracker, "import os; os.close(1); os.close(2); os._exit(13)")
    assert (o.verdict, o.reason) == ("escalate", "check_escalated")


def test_hostile_never_reads_a_5_mb_stdin(tracker: Tracker) -> None:
    o = go(tracker, "import time; time.sleep(60)", payload=b"x" * 5_000_000, timeout=0.5)
    assert (o.verdict, o.reason, o.detail) == ("escalate", "timeout", "timeout")


def test_hostile_early_exit_with_a_big_stdin(tracker: Tracker) -> None:
    o = go(tracker, "import sys; sys.exit(11)", payload=b"x" * 5_000_000)
    assert (o.verdict, o.reason) == ("deny", "check_denied")


@pytest.mark.parametrize(
    "stdout_code",
    [
        "sys.stdout.buffer.write(b'\\xff\\xfe{\"reason\": 1}')",
        'sys.stdout.write(\'{"reason": "a", "reason": "b"}\')',
        "sys.stdout.write('[' * 100000)",
        'sys.stdout.write(\'{"reason": "x\\\\u0000\\\\u001b[0m"}\')',
    ],
)
def test_hostile_stdout_shapes_still_follow_the_exit_code(
    tracker: Tracker, stdout_code: str
) -> None:
    o = go(tracker, f"import sys\n{stdout_code}\nsys.exit(11)")
    assert (o.verdict, o.reason) == ("deny", "check_denied")
    assert o.detail is None or all(ch.isprintable() for ch in o.detail)


def test_hostile_grandchild_ignoring_sigterm_escalates_and_leaves_nothing(
    tracker: Tracker, tmp_path: Path
) -> None:
    code = (
        "import os, signal, sys, time\n"
        "if os.fork() == 0:\n"
        "    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
        "    open(sys.argv[1] + '/gc', 'w').write(str(os.getpid()))\n"
        "    time.sleep(60)\n"
        "    os._exit(0)\n"
        "time.sleep(60)\n"
    )
    result: list[ScriptOutcome] = []
    t = threading.Thread(
        target=lambda: result.append(go(tracker, code, str(tmp_path), timeout=0.8))
    )
    t.start()
    gc = read_pid(tmp_path / "gc")
    tracker.track_pid(gc, cmdline_contains=str(tmp_path).encode())
    t.join(30)
    assert not t.is_alive()
    assert (result[0].verdict, result[0].reason) == ("escalate", "timeout")
    assert tracker.wait_dead(gc, 5)


def test_environment_reaches_the_check_exactly(tracker: Tracker) -> None:
    code = (
        "import json, os, sys\n"
        "names = sorted(k for k in os.environ if k != 'LC_CTYPE')\n"
        "print(json.dumps({'reason': json.dumps(names)}))\n"
        "sys.exit(11)"
    )
    # (Python itself adds LC_CTYPE when it coerces a C locale; it is not inherited from us.)
    o = go(tracker, code, env={"ONLY": "this"})
    assert o.detail is not None and json.loads(o.detail) == ["ONLY"]
