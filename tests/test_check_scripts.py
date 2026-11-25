"""``gatectl check`` with real script checks: the exit-code contract, order, deadline, cleanup."""

from __future__ import annotations

import json
import os
import sys
import textwrap
import time
from pathlib import Path
from typing import Any

import pytest

from tests.check_util import (
    audit_lines,
    decisions,
    do_check,
    do_set,
    isolate,
    log_lines,
    write_input,
)
from tests.command_util import config_file

PY = sys.executable


@pytest.fixture
def sdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def make_script(tmp_path: Path, name: str, body: str) -> list[str]:
    path = tmp_path / f"{name}.py"
    path.write_text(textwrap.dedent(body))
    return [PY, str(path)]


def sc(name: str, argv: list[str], **extra: Any) -> dict[str, Any]:
    return {"name": name, "type": "script", "argv": argv, **extra}


def cfg(
    tmp_path: Path, checks: list[dict[str, Any]], top: dict[str, Any] | None = None, **p: Any
) -> str:
    return config_file(tmp_path, {"policies": {"p": {"checks": checks, **p}}, **(top or {})})


def deny_rule(name: str = "r") -> dict[str, Any]:
    return {"name": name, "type": "rule", "when": [{"path": "x", "op": "exists"}], "then": "deny"}


def alive(pid: int) -> bool:
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            return f.read().rsplit(b")", 1)[1].split()[0] != b"Z"
    except OSError:
        return False


def assert_gone(pid_file: Path) -> None:
    pid = int(pid_file.read_text())
    for _ in range(100):
        if not alive(pid):
            return
        time.sleep(0.05)
    raise AssertionError(f"process {pid} is still alive")


ALLOW = "raise SystemExit(0)"
DENY = 'import json,sys; print(json.dumps({"reason": "no good"})); raise SystemExit(11)'
ESC = "raise SystemExit(13)"


@pytest.mark.parametrize(
    ("body", "verdict", "reason", "detail", "code"),
    [
        (ALLOW, "allow", None, None, 0),
        (DENY, "deny", "check_denied", "no good", 11),
        (ESC, "escalate", "check_escalated", "exit 13", 13),
        ("raise SystemExit(2)", "escalate", "check_error", "exit 2", 13),
        (
            "import os,signal; os.kill(os.getpid(), signal.SIGKILL)",
            "escalate",
            "check_error",
            "signal 9",
            13,
        ),
    ],
)
def test_the_exit_code_decides_each_script_check(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    body: str,
    verdict: str,
    reason: str | None,
    detail: str | None,
    code: int,
) -> None:
    config = cfg(tmp_path, [sc("s", make_script(tmp_path, "s", body))])
    do_set(capsys, config, "p", "enforced")
    got, doc, err = do_check(capsys, config, "p", "--input", write_input(tmp_path, {}))
    assert got == code
    [entry] = doc["checks"]
    assert (entry["verdict"], entry["reason"], entry["detail"]) == (verdict, reason, detail)
    if code in (11, 13):
        assert err.startswith(f"gatectl: {doc['decision']} p@*: {reason} (s) gd-")


def test_a_missing_script_is_tool_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, [sc("s", ["/nonexistent/gatectl-tool"])])
    _, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, {}))
    assert (doc["decision"], doc["reason"]) == ("escalate", "tool_missing")
    assert doc["checks"][0]["detail"] == "/nonexistent/gatectl-tool"


def test_rule_and_script_checks_run_in_listed_order_then_agents_last(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    agent = {"name": "ai", "type": "agent", "instruction": "x"}
    rule = {"name": "r", "type": "rule", "when": [{"path": "x", "op": "absent"}], "then": "allow"}
    config = cfg(
        tmp_path,
        [
            agent,
            sc("s1", make_script(tmp_path, "a", ALLOW)),
            rule,
            sc("s2", make_script(tmp_path, "b", ALLOW)),
        ],
    )
    _, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, {}))
    assert [(c["name"], c["verdict"]) for c in doc["checks"]] == [
        ("s1", "allow"), ("r", "allow"), ("s2", "allow"), ("ai", "escalate"),
    ]  # fmt: skip
    # TODO(#24): the agent run; until then an agent check that would run escalates, never allows
    assert doc["checks"][3]["detail"] == "agent checks are not implemented"
    assert (doc["checks"][3]["confidence"], doc["checks"][3]["reused"]) == (None, False)
    assert doc["decision"] == "escalate" and doc["reason"] == "check_error"


def test_an_agent_check_is_skipped_after_a_deny_or_an_escalate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    agent = {"name": "ai", "type": "agent", "instruction": "x"}
    config = cfg(tmp_path, [agent, deny_rule()])
    _, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, {"x": 1}))
    assert [(c["name"], c["verdict"]) for c in doc["checks"]] == [("r", "deny"), ("ai", "skipped")]
    assert doc["checks"][1]["confidence"] is None and doc["checks"][1]["reused"] is False


def test_the_script_gets_the_whole_input_on_stdin_and_a_scrubbed_environment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "sekret")
    monkeypatch.setenv("KEEP_ME", "yes")
    body = """
        import json, os, sys
        data = json.load(sys.stdin)
        out = {"keys": sorted(data), "token": "GITHUB_TOKEN" in os.environ,
               "keep": os.environ.get("KEEP_ME"), "cwd": os.path.basename(os.getcwd())}
        print(json.dumps({"reason": json.dumps(out)}))
        raise SystemExit(11)
    """
    config = cfg(tmp_path, [sc("s", make_script(tmp_path, "e", body), env_allow=["KEEP_ME"])])
    _, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, {"a": 1, "b": 2}))
    seen = json.loads(doc["checks"][0]["detail"])
    assert seen == {"keys": ["a", "b"], "token": False, "keep": "yes", "cwd": "s-1"}


def test_the_decision_tmp_directory_is_removed_when_the_check_ends(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    body = """
        import os
        os.mkdir("../residue"); open("../residue/f", "w").write("x")
        os.mkdir("../sibling")
    """
    config = cfg(tmp_path, [sc("s", make_script(tmp_path, "r", body))])
    _, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, {}))
    assert doc["decision"] == "allow"
    assert list((sdir / "tmp").iterdir()) == []


def test_stdout_over_the_cap_adds_the_output_truncated_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    body = 'import sys; sys.stdout.write("x" * 200000)'
    config = cfg(tmp_path, [sc("s", make_script(tmp_path, "big", body))])
    code, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, {}))
    assert code == 0 and doc["warnings"] == ["output_truncated"] and doc["decision"] == "allow"


def test_a_rule_deny_after_a_script_timeout_outranks_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    pidfile = tmp_path / "pid"
    body = f"import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); time.sleep(30)"
    config = cfg(
        tmp_path, [sc("slow", make_script(tmp_path, "slow", body), timeout="500ms"), deny_rule()]
    )
    do_set(capsys, config, "p", "enforced")
    code, doc, err = do_check(capsys, config, "p", "--input", write_input(tmp_path, {"x": 1}))
    assert code == 11 and (doc["decision"], doc["reason"]) == ("deny", "check_denied")
    assert [(c["name"], c["verdict"], c["reason"]) for c in doc["checks"]] == [
        ("slow", "escalate", "timeout"), ("r", "deny", "check_denied"),
    ]  # fmt: skip
    assert "(r)" in err
    assert_gone(pidfile)


def test_the_deadline_stops_a_script_and_later_scripts_are_not_started_then_skipped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    pidfile = tmp_path / "pid"
    slow = f"import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); time.sleep(30)"
    never = f"open({str(tmp_path / 'ran')!r}, 'w').write('x')"
    config = cfg(
        tmp_path,
        [
            sc("slow", make_script(tmp_path, "slow", slow), timeout="30s"),
            sc("second", make_script(tmp_path, "n1", never)),
            sc("third", make_script(tmp_path, "n2", never)),
            deny_rule(),
        ],
        {"defaults": {"record_reserve": "500ms"}},
    )
    started = time.monotonic()
    code, doc, _ = do_check(
        capsys, config, "p", "--input", write_input(tmp_path, {"x": 1}), "--timeout", "1.5"
    )
    elapsed = time.monotonic() - started
    assert code == 0 and elapsed < 4
    got = [(c["name"], c["verdict"], c["reason"], c["detail"]) for c in doc["checks"]]
    assert got[0][:3] == ("slow", "escalate", "timeout")
    assert got[1] == ("second", "escalate", "timeout", "not started")
    assert got[2] == ("third", "skipped", None, None)
    assert got[3][:3] == ("r", "deny", "check_denied")  # a rule is never skipped for the deadline
    assert not (tmp_path / "ran").exists()
    assert doc["decision"] == "deny"
    assert_gone(pidfile)


def test_a_budget_smaller_than_the_reserve_reads_nothing_and_escalates_timeout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, [deny_rule()])  # default reserve 2 s, deadline 0.5 s: R is below 0
    code, doc, _ = do_check(
        capsys, config, "p", "--input", write_input(tmp_path, {"x": 1}), "--timeout", "0.5"
    )
    assert code == 0 and (doc["decision"], doc["reason"], doc["checks"]) == (
        "escalate",
        "timeout",
        [],
    )
    [row] = decisions(sdir)
    assert row["reason"] == "timeout"


def test_the_script_timeout_is_the_smaller_of_its_own_and_the_remaining_budget(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    pidfile = tmp_path / "pid"
    slow = f"import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); time.sleep(30)"
    config = cfg(
        tmp_path, [sc("slow", make_script(tmp_path, "slow", slow), timeout="30s")],
        {"defaults": {"record_reserve": "500ms"}},
    )  # fmt: skip
    started = time.monotonic()
    _, doc, _ = do_check(
        capsys, config, "p", "--input", write_input(tmp_path, {}), "--timeout", "1.5"
    )
    assert time.monotonic() - started < 3.5
    assert doc["checks"][0]["reason"] == "timeout"
    assert_gone(pidfile)


def test_a_grandchild_that_ignores_sigterm_is_killed_with_the_group(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    pidfile = tmp_path / "child"
    body = f"""
        import os, signal, subprocess, sys, time
        child = subprocess.Popen([sys.executable, "-c",
            "import os,signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN);"
            "open({str(pidfile)!r},'w').write(str(os.getpid())); time.sleep(60)"])
        time.sleep(60)
    """
    config = cfg(tmp_path, [sc("s", make_script(tmp_path, "gc", body), timeout="1s")])
    _, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, {}))
    assert doc["checks"][0]["reason"] == "timeout"
    assert_gone(pidfile)


def test_two_script_checks_get_numbered_directories_and_everything_is_recorded(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    body = (
        "import json, os\n"
        "print(json.dumps({'reason': os.path.basename(os.getcwd())}))\n"
        "raise SystemExit(13)\n"
    )
    config = cfg(
        tmp_path,
        [sc("a", make_script(tmp_path, "d", body)), sc("b", make_script(tmp_path, "d", body))],
    )
    _, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, {}))
    assert [c["detail"] for c in doc["checks"]] == ["s-1", "s-2"]
    [row] = decisions(sdir)
    assert [c["name"] for c in json.loads(row["checks_json"])] == ["a", "b"]
    assert len(audit_lines(sdir)) == 1 and log_lines(sdir) == []


def test_the_hostile_script_detail_is_sanitized_and_capped(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    body = """
        import json
        print(json.dumps({"reason": "a\\u202eb\\x07" + "z" * 5000}))
        raise SystemExit(11)
    """
    config = cfg(tmp_path, [sc("s", make_script(tmp_path, "h", body))])
    _, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, {}))
    detail = doc["checks"][0]["detail"]
    assert detail.startswith("a�b�") and len(detail) <= 1024


def test_the_state_directory_is_left_without_tmp_residue(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, [sc("s", make_script(tmp_path, "ok", ALLOW))])
    do_check(capsys, config, "p", "--input", write_input(tmp_path, {}))
    assert sorted(p.name for p in (sdir / "tmp").iterdir()) == []
    assert os.path.exists(sdir / "state.db")
