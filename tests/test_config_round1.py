"""Round 1 review fixes: YAML text scalars, huge numbers, problem caps, names, home, NUL."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from gatectl.config import ConfigProblem, resolve_session_cmd
from tests.config_util import load

POLICY = """\
checks:
  - name: r
    type: rule
    when: [{path: a, op: exists}]
    then: deny
"""


def _indent(text: str, n: int = 4) -> str:
    return "".join(" " * n + line + "\n" for line in text.splitlines())


def _codes(problems: object) -> set[tuple[str, str]]:
    return {(p.code, p.path) for p in problems}  # type: ignore[attr-defined]


# --- R1: no YAML 1.1 scalars ---------------------------------------------------------------


def test_state_off_in_yaml_text_is_the_string(tmp_path: Path) -> None:
    cfg = load(tmp_path, "policies:\n  p:\n    state: off\n" + _indent(POLICY))
    entry = cfg.policies["p"]
    assert entry.problems == ()
    assert entry.policy is not None and entry.policy.state == "off"


def test_agent_sandbox_off_in_yaml_text(tmp_path: Path) -> None:
    cfg = load(tmp_path, "agent:\n  sandbox: off\n")
    assert cfg.shared_problems == ()
    assert cfg.shared.agent.sandbox == "off"


def test_me_name_no_in_yaml_text_is_a_string(tmp_path: Path) -> None:
    cfg = load(tmp_path, "me:\n  name: no\n")
    assert cfg.shared.me.name == "no"


def test_policy_keys_on_and_no_in_yaml_text(tmp_path: Path) -> None:
    text = "policies:\n  on:\n" + _indent(POLICY) + "  no:\n" + _indent(POLICY)
    cfg = load(tmp_path, text)
    assert cfg.policy_names() == ["no", "on"]
    assert all(e.problems == () for e in cfg.policies.values())


@pytest.mark.parametrize("scalar", ["010", "1:30", "1_000", "0x10", "0b1", "0o7"])
def test_yaml11_numbers_are_strings(tmp_path: Path, scalar: str) -> None:
    cfg = load(tmp_path, f"agent:\n  max_parallel: {scalar}\n")
    assert _codes(cfg.shared_problems) == {("invalid_value", "agent.max_parallel")}


def test_true_and_false_are_still_booleans(tmp_path: Path) -> None:
    cfg = load(tmp_path, "me:\n  name: true\n")
    assert _codes(cfg.shared_problems) == {("invalid_value", "me.name")}
    cfg = load(tmp_path, "me:\n  name: False\n")
    assert _codes(cfg.shared_problems) == {("invalid_value", "me.name")}


def test_plain_decimals_and_floats_still_parse(tmp_path: Path) -> None:
    cfg = load(tmp_path, "agent:\n  max_parallel: 4\nretention:\n  older_than: 1d\n")
    assert cfg.shared_problems == ()
    assert cfg.shared.agent.max_parallel == 4


# --- R2: huge integers ---------------------------------------------------------------------


@pytest.mark.parametrize("digits", [400, 4000])
@pytest.mark.parametrize("op", ["eq", "lt", "in"])
def test_huge_int_value_is_confined_to_its_policy(tmp_path: Path, digits: int, op: str) -> None:
    big = "9" * digits
    value = f"[{big}]" if op == "in" else big
    bad = (
        "checks:\n  - name: r\n    type: rule\n"
        f"    when: [{{path: a, op: {op}, value: {value}}}]\n    then: deny\n"
    )
    text = "policies:\n  bad:\n" + _indent(bad) + "  good:\n" + _indent(POLICY)
    cfg = load(tmp_path, text)  # must not raise
    assert cfg.policies["good"].problems == ()
    assert cfg.policies["bad"].problems == ()  # a huge integer is a finite number


# --- R3: problem collection is linear ------------------------------------------------------


def test_many_unknown_keys_load_fast(tmp_path: Path) -> None:
    keys = "".join(f"    k{i}: 1\n" for i in range(20000))
    start = time.monotonic()
    cfg = load(tmp_path, "policies:\n  p:\n" + _indent(POLICY) + keys)
    assert time.monotonic() - start < 5
    assert cfg.policies["p"].problems
    assert len(cfg.policies["p"].problems) <= 200


# --- R8: policy_names only lists addressable names -----------------------------------------


def test_policy_names_skips_invalid_names(tmp_path: Path) -> None:
    text = "policies:\n  ok:\n" + _indent(POLICY) + '  "a\\e[31mb\\nc":\n' + _indent(POLICY)
    cfg = load(tmp_path, text)
    assert cfg.policy_names() == ["ok"]
    assert cfg.policy_problems()  # the invalid name is still reported


# --- R9: home from the injected environ ----------------------------------------------------


def test_session_cmd_uses_injected_home(tmp_path: Path) -> None:
    home = tmp_path / "h"
    (home / "bin").mkdir(parents=True)
    exe = home / "bin" / "cs"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    got = resolve_session_cmd(["cs"], dirs=("~/bin",), environ={"HOME": str(home)})
    assert got == [str(exe)]


def test_session_cmd_home_unset_falls_back_to_passwd(tmp_path: Path) -> None:
    import pwd

    pw_home = pwd.getpwuid(os.getuid()).pw_dir
    got = resolve_session_cmd(["no-such-cs-xyz"], dirs=("~/bin",), environ={})
    assert got is None
    # the passwd home is used, not the process HOME: a process HOME must not leak in
    exe_dir = Path(pw_home) / "bin"
    assert not (exe_dir / "no-such-cs-xyz").exists()


def test_session_cmd_ignores_process_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "h"
    (home / "bin").mkdir(parents=True)
    exe = home / "bin" / "cs-proc-home"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setenv("HOME", str(home))
    assert resolve_session_cmd(["cs-proc-home"], dirs=("~/bin",), environ={}) is None


# --- R10: NUL in command and text values ---------------------------------------------------


def _nul_cases() -> dict[str, str]:
    return {
        "hook cmd": 'hooks:\n  post-decision:\n    - cmd: "a\\0b"\n',
        "session_cmd": 'session_cmd: ["a\\0b"]\n',
        "script argv": (
            "policies:\n  p:\n    checks:\n      - name: s\n        type: script\n"
            '        argv: ["a\\0b"]\n'
        ),
        "instruction": (
            "policies:\n  p:\n    checks:\n      - name: s\n        type: agent\n"
            '        skill: "x:y"\n        instruction: "a\\0b"\n'
        ),
    }


@pytest.mark.parametrize("case", list(_nul_cases()))
def test_nul_in_string_is_invalid_value(tmp_path: Path, case: str) -> None:
    cfg = load(tmp_path, _nul_cases()[case])
    found = list(cfg.shared_problems) + cfg.policy_problems()
    assert any(p.code == "invalid_value" for p in found), found
    assert all("\0" not in p.message and "\0" not in p.path for p in found)


# --- R11: message cap ----------------------------------------------------------------------


def test_problem_message_is_capped() -> None:
    assert len(ConfigProblem("invalid_value", "p", "x" * 5000).message) <= 2048


def test_long_env_name_message_is_capped(tmp_path: Path) -> None:
    name = "GATECTL_AGENT__" + "X" * 5000
    cfg = load(tmp_path, {}, environ={name: "1"})
    assert cfg.shared_problems
    assert all(len(p.message) <= 2048 for p in cfg.shared_problems)


def test_me_name_is_a_bounded_string_and_anything_else_is_refused(tmp_path: Path) -> None:
    for ok in ["a b", "", "x" * 1024, "\x1b[31m", "\u202e"]:
        cfg = load(tmp_path, {"me": {"name": ok}})
        assert cfg.shared_problems == (), repr(ok)
        assert cfg.shared.me.name == ok
    for bad in [5, 1.5, True, ["a"], {"a": 1}, "x" * 1025]:
        cfg = load(tmp_path, {"me": {"name": bad}})
        assert _codes(cfg.shared_problems) == {("invalid_value", "me.name")}, repr(bad)
