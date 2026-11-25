"""Per-part validation, overrides, the reach of a config error and session_cmd resolution."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

import pytest

from gatectl import errors
from gatectl.config import (
    SESSION_CMD_DIRS,
    load_for_command,
    requires_valid_shared,
    resolve_session_cmd,
)
from tests.config_util import good_policy, load, write

REPO = "github.com/org/repo"
OTHER = "github.com/org/other"


def _doc(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "policies": {"p": good_policy(), "q": good_policy()},
        "repos": {REPO: {"policies": {"p": {"timeout": "5s"}}}},
    }
    base.update(over)
    return base


# --- the validation matrix: each part separately -------------------------------------------

BAD_PART: dict[str, dict[str, Any]] = {
    "me": {"me": {"name": "a b"}},
    "session_cmd": {"session_cmd": []},
    "defaults": {"defaults": {"timeout": "0"}},
    "agent": {"agent": {"sandbox": "no"}},
    "retention": {"retention": {"older_than": "0"}},
    "hooks": {"hooks": {"post-decision": [{"cmd": ""}]}},
    "top-level unknown": {"bogus": 1},
    "repos structure": {"repos": {"not a repo": {}}},
    "repos unknown key": {"repos": {REPO: {"x": 1}}},
    "repos policies type": {"repos": {REPO: {"policies": 5}}},
    "policies type": {"policies": 5},
}


@pytest.mark.parametrize("part", list(BAD_PART))
def test_a_bad_shared_part_touches_only_shared_problems(tmp_path: Path, part: str) -> None:
    c = load(tmp_path, _doc(**BAD_PART[part]))
    assert c.shared_problems, part
    if part != "policies type":
        assert c.policies["p"].problems == () and c.policies["q"].problems == ()
    assert c.policy_problems() == [] or part == "policies type"


def test_a_bad_policy_touches_only_that_policy(tmp_path: Path) -> None:
    c = load(tmp_path, _doc(policies={"p": {**good_policy(), "timeout": "0"}, "q": good_policy()}))
    assert c.shared_problems == ()
    assert c.policies["p"].problems and c.policies["q"].problems == ()
    assert c.resolve_policy("q") is not None
    with pytest.raises(errors.ConfigInvalidError) as info:
        c.resolve_policy("p")
    assert info.value.exit_code == 2
    assert "policies.p.timeout" in info.value.message
    assert c.warns_config_problem_for("q") is True
    assert c.warns_config_problem_for("p") is False  # its own error is the error, not a warning


def test_no_problems_means_no_warning(tmp_path: Path) -> None:
    c = load(tmp_path, _doc())
    assert c.warns_config_problem_for("p") is False
    assert c.warns_config_problem_for("p", repo=REPO) is False


def test_a_bad_override_fails_only_its_scope(tmp_path: Path) -> None:
    doc = _doc(
        repos={
            REPO: {"policies": {"p": {"timeout": "0"}}},
            OTHER: {"policies": {"p": {"timeout": "9s"}}},
        }
    )
    c = load(tmp_path, doc)
    assert c.shared_problems == ()
    assert c.policies["p"].problems == ()
    assert c.resolve_policy("p").timeout is None  # no repo: the global policy
    assert c.resolve_policy("p", repo=OTHER).timeout is not None
    with pytest.raises(errors.ConfigInvalidError) as info:
        c.resolve_policy("p", repo=REPO)
    assert f"repos.{REPO}.policies.p.timeout" in info.value.message
    assert c.warns_config_problem_for("q") is True  # another policy's override is invalid
    assert c.warns_config_problem_for("p", repo=OTHER) is True
    assert c.warns_config_problem_for("p", repo=REPO) is False


def test_invalid_policy_with_a_valid_override_still_fails_for_the_scope(tmp_path: Path) -> None:
    c = load(tmp_path, _doc(policies={"p": {"checks": []}}))
    with pytest.raises(errors.ConfigInvalidError):
        c.resolve_policy("p", repo=REPO)  # the base is invalid: the override sits on it


def test_override_replaces_keys_whole(tmp_path: Path) -> None:
    rule = {
        "name": "o",
        "type": "rule",
        "when": [{"path": "z", "op": "exists"}],
        "then": "escalate",
    }
    doc = _doc(
        policies={"p": good_policy(timeout="9s", input={"require": ["a"]}, cache_ttl="1m")},
        repos={REPO: {"policies": {"p": {"checks": [rule], "input": {"ignore": ["t"]}}}}},
    )
    c = load(tmp_path, doc)
    base = c.resolve_policy("p")
    eff = c.resolve_policy("p", repo=REPO)
    assert [x.name for x in base.checks] == ["r"]
    assert [x.name for x in eff.checks] == ["o"]
    assert eff.input is not None and eff.input.require == [] and eff.input.ignore == ["t"]
    assert eff.timeout == base.timeout  # keys it does not set come from the policy
    assert eff.cache_ttl == base.cache_ttl
    assert eff.state == "shadow"


def test_override_recommend_is_a_whole_map_with_defaults_filling_gaps(tmp_path: Path) -> None:
    doc = _doc(
        defaults={"recommend": {"confidence": 0.9, "max_miss_rate": 0.2}},
        policies={"p": good_policy(recommend={"confidence": 0.8, "max_miss_rate": 0.3})},
        repos={REPO: {"policies": {"p": {"recommend": {"confidence": 0.99}}}}},
    )
    c = load(tmp_path, doc)
    eff = c.resolve_policy("p", repo=REPO)
    assert (eff.recommend.confidence, eff.recommend.max_miss_rate) == (0.99, 0.2)  # not 0.3


def test_override_state_is_a_config_error_naming_the_key(tmp_path: Path) -> None:
    c = load(tmp_path, _doc(repos={REPO: {"policies": {"p": {"state": "off"}}}}))
    (problem,) = c.overrides[(REPO, "p")].problems
    assert problem.code == "invalid_value"
    assert problem.path == f"repos.{REPO}.policies.p.state"


def test_override_unknown_key_and_unknown_policy(tmp_path: Path) -> None:
    c = load(
        tmp_path,
        _doc(repos={REPO: {"policies": {"p": {"bogus": 1}, "ghost": {"timeout": "5s"}}}}),
    )
    (k,) = c.overrides[(REPO, "p")].problems
    assert (k.code, k.path) == ("override_unknown_key", f"repos.{REPO}.policies.p.bogus")
    (g,) = c.overrides[(REPO, "ghost")].problems
    assert (g.code, g.path) == ("override_unknown_policy", f"repos.{REPO}.policies.ghost")
    assert c.shared_problems == ()
    assert c.resolve_policy("q", repo=REPO) is not None  # unrelated policy unaffected


def test_override_body_must_be_a_map(tmp_path: Path) -> None:
    c = load(tmp_path, _doc(repos={REPO: {"policies": {"p": 5}}}))
    assert c.overrides[(REPO, "p")].problems
    assert c.shared_problems == ()


def test_override_checks_get_the_same_validation_as_policies(tmp_path: Path) -> None:
    dup = {"name": "x", "type": "rule", "when": [{"path": "a", "op": "exists"}], "then": "deny"}
    c = load(tmp_path, _doc(repos={REPO: {"policies": {"p": {"checks": [dup, dup]}}}}))
    (problem,) = c.overrides[(REPO, "p")].problems
    assert problem.path == f"repos.{REPO}.policies.p.checks.1.name"


def test_unknown_policy_resolution_returns_none(tmp_path: Path) -> None:
    c = load(tmp_path, _doc())
    assert c.resolve_policy_or_none("nope") is None
    assert c.policy_names() == ["p", "q"]


def test_invalid_policies_still_count_as_known_names(tmp_path: Path) -> None:
    c = load(tmp_path, _doc(policies={"p": {"checks": []}}))
    assert c.policy_names() == ["p"]  # `set p off` and `outcome` accept it


def test_repo_ids_in_overrides_are_validated_by_the_grammar(tmp_path: Path) -> None:
    bad = [
        "",
        "Github.com/o/r",
        "github.com",
        "github.com/o/../r",
        "github.com/o/r/",
        "x" * 300 + "/a",
    ]
    for repo in bad:
        c = load(tmp_path, _doc(repos={repo: {"policies": {}}}))
        assert [p.code for p in c.shared_problems] == ["invalid_value"], repo
    c = load(tmp_path, _doc(repos={"gitlab.example.com:8443/g/sub/p": {"policies": {}}}))
    assert c.shared_problems == ()


# --- the reach of a config error per command -----------------------------------------------


def _args(**kw: Any) -> argparse.Namespace:
    return argparse.Namespace(**kw)


STRICT = [
    ("check", _args(policy="p")),
    ("reconcile", _args()),
    ("prune", _args()),
    ("cron", _args(action="install")),
    ("set", _args(policy="p", state="enforced", all=False)),
]
LENIENT = [
    ("set", _args(policy="p", state="off", all=False)),
    ("set", _args(policy="p", state="shadow", all=True)),
    ("set", _args(policy="p", state="off", all=True)),
    ("outcome", _args()),
    ("show", _args()),
    ("decisions", _args()),
    ("stats", _args()),
    ("policies", _args()),
    ("export", _args()),
    ("validate", _args(probe=False)),
]


@pytest.mark.parametrize(("command", "args"), STRICT)
def test_requires_valid_shared_strict_commands(command: str, args: argparse.Namespace) -> None:
    assert requires_valid_shared(command, args) is True


@pytest.mark.parametrize(("command", "args"), LENIENT)
def test_requires_valid_shared_lenient_commands(command: str, args: argparse.Namespace) -> None:
    assert requires_valid_shared(command, args) is False


@pytest.mark.parametrize(("command", "args"), STRICT)
@pytest.mark.parametrize(
    "part", ["defaults", "hooks", "repos structure", "session_cmd", "top-level unknown"]
)
def test_strict_commands_exit_2_naming_the_key(
    tmp_path: Path, command: str, args: argparse.Namespace, part: str
) -> None:
    path = write(tmp_path / "c.yaml", _doc(**BAD_PART[part]))
    with pytest.raises(errors.ConfigInvalidError) as info:
        load_for_command(command, args, str(path), environ={})
    assert info.value.exit_code == 2
    assert info.value.code == "config_invalid"
    expected = {
        "defaults": "defaults.timeout",
        "hooks": "hooks.post-decision",
        "repos structure": "repos",
        "session_cmd": "session_cmd",
        "top-level unknown": "bogus",
    }[part]
    assert expected in info.value.message
    assert info.value.details is not None and info.value.details["problems"]


@pytest.mark.parametrize(("command", "args"), LENIENT)
@pytest.mark.parametrize(
    "part",
    [
        "defaults",
        "hooks",
        "repos structure",
        "session_cmd",
        "top-level unknown",
        "agent",
        "me",
        "retention",
    ],
)
def test_lenient_commands_carry_on_with_defaults_and_a_warning(
    tmp_path: Path, command: str, args: argparse.Namespace, part: str
) -> None:
    path = write(tmp_path / "c.yaml", _doc(**BAD_PART[part]))
    loaded = load_for_command(command, args, str(path), environ={})
    assert loaded.shared_warnings() == ["config_problem"]
    assert loaded.shared.defaults.timeout.total_seconds() == 60
    assert loaded.shared.hooks.post_decision == []
    assert "p" in loaded.policy_names()


def test_lenient_command_without_problems_has_no_warning(tmp_path: Path) -> None:
    path = write(tmp_path / "c.yaml", _doc())
    loaded = load_for_command("show", _args(), str(path), environ={})
    assert loaded.shared_warnings() == []


def test_set_off_accepts_a_policy_whose_own_definition_is_invalid(tmp_path: Path) -> None:
    path = write(tmp_path / "c.yaml", _doc(policies={"p": {"checks": []}}))
    loaded = load_for_command(
        "set", _args(policy="p", state="off", all=False), str(path), environ={}
    )
    assert "p" in loaded.policy_names()
    with pytest.raises(errors.ConfigInvalidError):  # a policy that is invalid fails `set enforced`
        loaded.resolve_policy("p")


@pytest.mark.parametrize("command", ["set", "outcome", "show", "validate"])
def test_unparseable_yaml_fails_every_command(tmp_path: Path, command: str) -> None:
    path = tmp_path / "c.yaml"
    path.write_text("a: [\n", encoding="utf-8")
    with pytest.raises(errors.ConfigInvalidError):
        load_for_command(command, _args(state="off", all=False), str(path), environ={})


def test_unreadable_file_exits_1_for_every_command(tmp_path: Path) -> None:
    (tmp_path / "c.yaml").mkdir()
    for command, args in [*STRICT, *LENIENT]:
        with pytest.raises(errors.GatectlError) as info:
            load_for_command(command, args, str(tmp_path / "c.yaml"), environ={})
        assert info.value.exit_code == 1


def test_strict_message_reports_the_count_when_there_are_several_problems(tmp_path: Path) -> None:
    path = write(
        tmp_path / "c.yaml", {"defaults": {"timeout": "0", "script_timeout": "0"}, "bogus": 1}
    )
    loaded = load_for_command("show", _args(), str(path), environ={})
    with pytest.raises(errors.ConfigInvalidError) as info:
        loaded.require_valid_shared()
    assert "3" in info.value.message or "more" in info.value.message
    assert len(info.value.details["problems"]) == 3  # type: ignore[index]


def test_problem_list_in_details_is_capped(tmp_path: Path) -> None:
    doc = {"hooks": {"post-decision": [{"cmd": ""}] * 500}}
    loaded = load(tmp_path, doc)
    with pytest.raises(errors.ConfigInvalidError) as info:
        loaded.require_valid_shared()
    assert len(info.value.details["problems"]) <= 50  # type: ignore[index]
    assert len(info.value.message) <= 2048
    envelope = errors.envelope(info.value)
    assert envelope["error"]["code"] == "config_invalid"


# --- session_cmd resolution -------------------------------------------------------------------


def _exe(path: Path, mode: int = 0o755) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(mode)
    return path


def test_fixed_directory_list() -> None:
    assert SESSION_CMD_DIRS == (
        "~/.local/bin",
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/usr/bin",
        "/bin",
    )


def test_bare_name_is_found_in_the_first_directory_that_has_it(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    _exe(b / "cs")
    assert resolve_session_cmd(["cs", "--x"], dirs=(str(a), str(b))) == [str(b / "cs"), "--x"]
    _exe(a / "cs")
    assert resolve_session_cmd(["cs"], dirs=(str(a), str(b))) == [str(a / "cs")]


def test_home_directory_is_expanded_from_home(tmp_path: Path, isolated_home: Path) -> None:
    exe = _exe(isolated_home / ".local" / "bin" / "claude-session")
    got = resolve_session_cmd(["claude-session"], dirs=SESSION_CMD_DIRS[:1])
    assert got == [str(exe)]


def test_path_is_never_searched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _exe(tmp_path / "onpath" / "only-on-path")
    monkeypatch.setenv("PATH", str(tmp_path / "onpath"))
    assert resolve_session_cmd(["only-on-path"], dirs=(str(tmp_path / "empty"),)) is None
    assert resolve_session_cmd(["only-on-path"]) is None  # the real fixed list


def test_non_executable_directory_and_broken_entries_are_skipped(tmp_path: Path) -> None:
    a, b, c = tmp_path / "a", tmp_path / "b", tmp_path / "c"
    _exe(a / "cs", mode=0o644)  # not executable
    (b / "cs").mkdir(parents=True)  # a directory
    c.mkdir()
    (c / "cs").symlink_to(tmp_path / "gone")  # dangling
    assert resolve_session_cmd(["cs"], dirs=(str(a), str(b), str(c))) is None
    good = _exe(tmp_path / "d" / "cs")
    assert resolve_session_cmd(["cs"], dirs=(str(a), str(b), str(c), str(tmp_path / "d"))) == [
        str(good)
    ]


def test_symlink_to_an_executable_is_used_by_its_own_path(tmp_path: Path) -> None:
    real = _exe(tmp_path / "real" / "tool")
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "cs").symlink_to(real)
    assert resolve_session_cmd(["cs"], dirs=(str(tmp_path / "bin"),)) == [
        str(tmp_path / "bin" / "cs")
    ]


def test_absolute_path_is_checked_not_searched(tmp_path: Path) -> None:
    exe = _exe(tmp_path / "x" / "cs")
    assert resolve_session_cmd([str(exe), "a"]) == [str(exe), "a"]
    assert resolve_session_cmd([str(tmp_path / "missing")]) is None
    assert resolve_session_cmd([str(tmp_path)]) is None
    plain = tmp_path / "plain"
    plain.write_text("x", encoding="utf-8")
    plain.chmod(0o644)
    assert resolve_session_cmd([str(plain)]) is None


def test_a_name_with_a_slash_is_never_searched(tmp_path: Path) -> None:
    _exe(tmp_path / "bin" / "sub" / "cs")
    assert resolve_session_cmd(["sub/cs"], dirs=(str(tmp_path / "bin"),)) is None


def test_relative_home_is_not_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", "relative")
    monkeypatch.chdir(tmp_path)
    _exe(tmp_path / "relative" / ".local" / "bin" / "cs")
    assert resolve_session_cmd(["cs"], dirs=SESSION_CMD_DIRS[:1]) is None


def test_session_cmd_resolution_is_not_done_at_load(tmp_path: Path) -> None:
    c = load(tmp_path, {"session_cmd": ["definitely-not-installed-anywhere"]})
    assert c.shared_problems == ()
    assert c.session_cmd_resolved() is None
    assert os.environ.get("PATH") is not None
