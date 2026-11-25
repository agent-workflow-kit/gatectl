"""Human-only enforcement: no flag, variable, stdin or id lets an automatic caller enforce."""

from __future__ import annotations

import os
import pty
import subprocess
import sys
from pathlib import Path

import pytest

from gatectl import cli
from tests import schema_util
from tests.command_util import run
from tests.set_util import (
    HUMAN,
    REPO,
    audit_lines,
    do_set,
    isolate,
    log_lines,
    make_config,
    row,
)


@pytest.fixture(autouse=True)
def state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def tty(monkeypatch: pytest.MonkeyPatch, value: bool = True) -> None:
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: value)


def assert_refused(code: int, doc: dict[str, object], state_dir: Path) -> None:
    assert code == 20
    error = doc["error"]
    assert isinstance(error, dict)
    assert error["code"] == "refused" and error["reason"] == "human_required"
    assert row(state_dir, "p", "*") is None
    assert audit_lines(state_dir) == []


def test_enforced_without_a_human_is_refused_audit_free_and_logged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    code, doc, err = do_set(capsys, config, "p", "enforced")
    assert_refused(code, doc, state_dir)
    assert err == ""  # --json: the envelope on stdout only
    schema_util.assert_valid("cli/error", doc)
    events = log_lines(state_dir)
    assert len(events) == 1
    event = events[0]
    assert (event["level"], event["event"], event["policy"], event["scope"]) == (
        "warn",
        "warning",
        "p",
        "*",
    )
    schema_util.assert_valid("log", event)
    assert not (state_dir / "state.db").exists()


@pytest.mark.parametrize("flag", ["auto:ann", "auto:unknown", "auto:human", "auto:x@y.z"])
def test_an_explicit_auto_actor_is_refused_even_with_a_tty(
    flag: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tty(monkeypatch)
    config = make_config(tmp_path)
    code, doc, _ = do_set(capsys, config, "p", "enforced", "--actor", flag)
    assert_refused(code, doc, state_dir)


@pytest.mark.parametrize(
    "flag",
    [
        "human:",
        "human",
        "Human:ann",
        "HUMAN:ann",
        "human:ann ",
        " human:ann",
        "human:a b",
        "human:ann\n",
        "human:a/b",
        "human::ann",
        "human:" + "a" * 65,
        "root",
        "humans:ann",
        "",
    ],
)
def test_a_malformed_actor_is_a_usage_error_never_human(
    flag: str, tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    code, out, _ = run(
        capsys, ["set", "p", "enforced", "--actor", flag, "--config", config, "--json"]
    )
    assert code == 2
    assert not state_dir.exists()


def test_the_last_actor_flag_wins(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    code, doc, _ = do_set(capsys, config, "p", "enforced", *HUMAN, "--actor", "auto:ann")
    assert_refused(code, doc, state_dir)
    code, _, _ = do_set(capsys, config, "p", "enforced", "--actor", "auto:ann", *HUMAN)
    assert code == 0


def test_the_environment_never_makes_an_actor_human(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in {
        "GATECTL_ACTOR": "human:ann",
        "GATECTL_ME__NAME": "ann",
        "GATECTL_ME": "human:ann",
        "GATECTL_HUMAN": "1",
        "USER": "ann",
        "LOGNAME": "ann",
        "SUDO_USER": "ann",
        "TERM": "xterm",
        "SSH_TTY": "/dev/pts/9",
        "CI": "",
        "GATECTL_ID": "human:ann",
        "GATECTL_HOOK": "post-state-change",
    }.items():
        monkeypatch.setenv(name, value)
    config = make_config(tmp_path)
    code, doc, _ = do_set(capsys, config, "p", "enforced")
    assert_refused(code, doc, state_dir)


def test_caller_decision_ids_never_authorize(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    code, doc, _ = do_set(
        capsys,
        config,
        "p",
        "enforced",
        "--decision-id",
        "human:ann",
        "--decision-id",
        "gd-aaaaaaaaaaaa",
    )
    assert_refused(code, doc, state_dir)


def test_stdin_content_never_authorizes_and_is_not_read_when_refused(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gatectl import setcmd

    r, w = os.pipe()
    try:
        os.write(w, b"human:ann\n")
        monkeypatch.setattr(setcmd, "STDIN_FD", r)
        config = make_config(tmp_path)
        code, doc, _ = do_set(capsys, config, "p", "enforced", "--reason-file", "-")
        assert_refused(code, doc, state_dir)
        assert os.read(r, 100) == b"human:ann\n"  # untouched
    finally:
        os.close(r)
        os.close(w)


def test_a_tty_makes_the_default_actor_human_and_it_is_audited_as_such(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tty(monkeypatch)
    config = make_config(tmp_path, me={"name": "carol"})
    code, doc, _ = do_set(capsys, config, "p", "enforced")
    assert code == 0 and doc["changed"] is True
    stored = row(state_dir, "p", "*")
    assert stored is not None and stored.set_by == "human:carol"
    line = audit_lines(state_dir)[0]
    assert line["actor"] == "human:carol" and line["stdin_tty"] is True
    assert line["inputs"]["actor_source"] == "default"


def test_a_tty_without_me_name_uses_the_sanitized_os_user_name(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gatectl import setcmd

    tty(monkeypatch)
    monkeypatch.setattr(setcmd, "_os_user_name", lambda: "Dr Who\n")
    config = make_config(tmp_path)
    code, _, _ = do_set(capsys, config, "p", "enforced")
    assert code == 0
    assert audit_lines(state_dir)[0]["actor"] == "human:Dr_Who_"


def test_without_a_tty_the_default_actor_is_auto_unknown_for_off_and_shadow(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    for state in ("shadow", "off"):
        code, _, _ = do_set(capsys, config, "p", state)
        assert code == 0
    assert {ln["actor"] for ln in audit_lines(state_dir)} == {"auto:unknown"}


def test_automation_can_always_lower_with_an_auto_actor(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    code, _, _ = do_set(capsys, config, "p", "off", "--all", "--actor", "auto:cron")
    assert code == 0
    assert audit_lines(state_dir)[0]["actor"] == "auto:cron"


def test_a_refused_enforce_of_an_unknown_or_removed_policy_is_still_refused_first(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    code, doc, _ = do_set(capsys, config, "nope", "enforced", "--repo", REPO)
    assert code == 20 and doc["error"]["code"] == "refused"


def test_a_refused_log_failure_does_not_change_the_refusal(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gatectl import audit

    def broken(*a: object, **k: object) -> None:
        raise OSError(28, "full")

    monkeypatch.setattr(audit, "append_log", broken)
    config = make_config(tmp_path)
    code, doc, _ = do_set(capsys, config, "p", "enforced")
    assert code == 20 and doc["error"]["reason"] == "human_required"


def test_a_real_pty_stdin_is_human_and_a_pipe_or_devnull_is_not(
    tmp_path: Path, state_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end in a child process: only a terminal on stdin makes the default actor human."""
    config = make_config(tmp_path)
    env = {
        "HOME": str(tmp_path / "home"),
        "XDG_CONFIG_HOME": str(tmp_path / "home" / "config"),
        "XDG_STATE_HOME": str(tmp_path / "home" / "state"),
        "PATH": os.environ.get("PATH", ""),
        "LC_ALL": "C",
    }
    argv = [sys.executable, "-m", "gatectl", "set", "p", "enforced", "--config", config, "--json"]

    def start(stdin: int) -> int:
        proc = subprocess.Popen(  # noqa: S603
            argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
        )
        try:
            proc.communicate(timeout=60)
        finally:
            if proc.poll() is None:
                proc.kill()  # exactly the process this test started
                proc.wait()
        return proc.returncode

    assert start(subprocess.DEVNULL) == 20
    r, w = os.pipe()
    os.close(w)
    try:
        assert start(r) == 20
    finally:
        os.close(r)
    assert row(state_dir, "p", "*") is None
    master, slave = pty.openpty()
    try:
        assert start(slave) == 0
    finally:
        os.close(master)
        os.close(slave)
    stored = row(state_dir, "p", "*")
    assert stored is not None and stored.set_by.startswith("human:")
    assert audit_lines(state_dir)[0]["stdin_tty"] is True
