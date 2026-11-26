"""``gatectl check`` as a real process: stdin, descriptors, exit codes, concurrent checks."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from itertools import product
from pathlib import Path
from typing import Any

import pytest

from gatectl import cli, engine
from tests import schema_util
from tests.check_util import audit_lines, decisions
from tests.command_util import config_file

RULE = {
    "name": "r",
    "type": "rule",
    "when": [{"path": "ci", "op": "ne", "value": "ok"}],
    "then": "deny",
}


def env_for(tmp_path: Path) -> dict[str, str]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / "config"),
        "XDG_STATE_HOME": str(home / "state"),
        "LC_ALL": "C",
    }


def gatectl(
    tmp_path: Path, *args: str, stdin: bytes | None = b"", config: str | None = None
) -> subprocess.CompletedProcess[bytes]:
    cmd = [sys.executable, "-m", "gatectl", *args]
    if config is not None:
        cmd += ["--config", config]
    return subprocess.run(
        cmd, input=stdin, capture_output=True, env=env_for(tmp_path), timeout=60, check=False
    )


def state_dir(tmp_path: Path) -> Path:
    return tmp_path / "home" / "state" / "gatectl"


def test_stdin_is_read_and_the_exit_code_and_stderr_line_are_real(tmp_path: Path) -> None:
    config = config_file(tmp_path, {"policies": {"p": {"checks": [RULE]}}})
    done = gatectl(tmp_path, "set", "p", "enforced", "--actor", "human:ann", config=config)
    assert done.returncode == 0
    ran = gatectl(tmp_path, "check", "p", stdin=b'{"ci": "bad"}', config=config)
    assert ran.returncode == 11
    doc = json.loads(ran.stdout)
    schema_util.assert_valid("cli/check", doc)
    assert ran.stderr.decode() == f"gatectl: deny p@*: check_denied (r) {doc['decision_id']}\n"
    assert ran.stdout.count(b"\n") == 1
    ok = gatectl(tmp_path, "check", "p", "--input", "-", stdin=b'{"ci": "ok"}', config=config)
    assert (ok.returncode, ok.stderr) == (0, b"")


def test_an_empty_or_closed_stdin_is_input_invalid_never_a_crash(tmp_path: Path) -> None:
    config = config_file(tmp_path, {"policies": {"p": {"checks": [RULE]}}})
    ran = gatectl(tmp_path, "check", "p", stdin=b"", config=config)
    assert ran.returncode == 0
    assert json.loads(ran.stdout)["reason"] == "input_invalid"
    closed = subprocess.run(
        [sys.executable, "-m", "gatectl", "check", "p", "--config", config],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=env_for(tmp_path),
        timeout=60,
        check=False,
    )
    assert closed.returncode == 0 and json.loads(closed.stdout)["reason"] == "input_invalid"


def test_a_stdin_that_never_ends_stops_at_the_deadline(tmp_path: Path) -> None:
    config = config_file(
        tmp_path,
        {"policies": {"p": {"checks": [RULE]}}, "defaults": {"record_reserve": "100ms"}},
    )
    proc = subprocess.Popen(
        [sys.executable, "-m", "gatectl", "check", "p", "--timeout", "1", "--config", config],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env_for(tmp_path),
    )
    try:
        assert proc.stdin is not None
        proc.stdin.write(b'{"ci": ')
        proc.stdin.flush()
        assert proc.stdout is not None
        out = proc.stdout.read()  # stdin stays open: only the deadline can end the read
        proc.wait(timeout=20)
    finally:
        proc.stdin.close() if proc.stdin else None
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    doc = json.loads(out)
    assert proc.returncode == 0 and (doc["decision"], doc["reason"]) == ("escalate", "timeout")


def test_detaching_points_descriptors_0_1_and_2_at_dev_null() -> None:
    code = (
        "import os\n"
        "from gatectl import cli\n"
        "cli._detach_descriptors()\n"
        "import sys\n"
        "links = [os.readlink(f'/proc/self/fd/{n}') for n in (0, 1, 2)]\n"
        "sys.exit(0 if links == ['/dev/null'] * 3 else 3)"
    )
    done = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, check=False, timeout=30
    )
    assert done.returncode == 0, done.stderr


def test_a_recorded_check_leaves_no_descriptor_of_the_caller_open_at_exit(tmp_path: Path) -> None:
    # The real process detaches after printing: the caller still sees the whole result and EOF.
    config = config_file(tmp_path, {"policies": {"p": {"checks": [RULE]}}})
    ran = gatectl(tmp_path, "check", "p", stdin=b'{"ci": "ok"}', config=config)
    assert ran.returncode == 0 and json.loads(ran.stdout)["decision"] == "allow"


def test_two_concurrent_checks_both_record_with_whole_audit_lines(tmp_path: Path) -> None:
    config = config_file(tmp_path, {"policies": {"p": {"checks": [RULE]}}})
    procs = [
        subprocess.Popen(
            [sys.executable, "-m", "gatectl", "check", "p", "--config", config],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env_for(tmp_path),
        )
        for _ in range(2)
    ]
    outs: list[bytes] = []
    for proc in procs:
        out, _ = proc.communicate(b'{"ci": "ok"}', timeout=60)
        outs.append(out)
    ids = {json.loads(o)["decision_id"] for o in outs}
    assert len(ids) == 2 and all(p.returncode == 0 for p in procs)
    sdir = state_dir(tmp_path)
    assert {d["id"] for d in decisions(sdir)} == ids
    assert {r["decision_id"] for r in audit_lines(sdir)} == ids


# --- the combination rule, exhaustively over short check lists ------------------------------

VERDICTS = ("allow", "deny", "escalate", "skipped")


def _entry(i: int, verdict: str) -> engine.Entry:
    reason = {"deny": "check_denied", "escalate": "check_error", "allow": None}.get(verdict)
    return engine.Entry(f"c{i}", "script", verdict, reason, None, 0)


@pytest.mark.parametrize("length", [1, 2, 3, 4])
def test_combination_is_most_severe_with_the_first_deny_else_the_first_escalate(
    length: int,
) -> None:
    for verdicts in product(VERDICTS, repeat=length):
        entries = [_entry(i, v) for i, v in enumerate(verdicts)]
        got = engine.combine(entries)
        ran = [v for v in verdicts if v != "skipped"]
        if not ran:
            assert (got.decision, got.reason) == ("escalate", "check_error")
        elif "deny" in ran:
            first = verdicts.index("deny")
            assert (got.decision, got.reason, got.check) == ("deny", "check_denied", f"c{first}")
        elif "escalate" in ran:
            first = verdicts.index("escalate")
            assert (got.decision, got.check) == ("escalate", f"c{first}")
        else:
            assert (got.decision, got.reason, got.check) == ("allow", "all_passed", None)


def test_an_agent_entry_never_loosens_the_combination() -> None:
    base: list[engine.Entry] = [_entry(0, "deny"), _entry(1, "escalate")]
    agent = engine.Entry("a", "agent", "allow", None, None, 5, 0.99, False)
    assert engine.combine([*base, agent]).decision == "deny"
    assert engine.combine([base[1], agent]).decision == "escalate"


def test_an_unknown_verdict_is_an_escalate_and_enforced_never_exits_0_for_it() -> None:
    odd = engine.Entry("x", "script", "maybe", None, None, 0)
    assert engine.combine([odd]).decision == "escalate"
    assert engine.exit_code("enforced", "maybe") == 13
    assert [engine.exit_code("enforced", d) for d in ("allow", "deny", "escalate")] == [0, 11, 13]
    assert [engine.exit_code("shadow", d) for d in ("allow", "deny", "escalate")] == [0, 0, 0]


def test_the_veto_line_is_capped_by_the_printer() -> None:
    line = engine.veto_line(
        "deny", "p" * 64, "github.com/" + "a" * 240, "check_denied", "c" * 64, "gd-aaaaaaaaaaaa"
    )
    assert len(cli._stderr_line(line)) <= 513
    _: Any = None
