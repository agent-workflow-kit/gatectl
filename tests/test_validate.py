"""``gatectl validate``: every problem and warning code, the exit codes, the schema, hostile input.

The table test (``CASES``) produces each code of ``schemas/cli/validate.json`` from a fixture
config and checks its path and kind (problem or warning). Plugin codes use fixture plugin
directories; the bundled plugin is injected through ``validate_config``.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from gatectl import commands, config, validate
from gatectl.cli import main
from gatectl.config import load_config
from gatectl.errors import InternalError
from tests import schema_util
from tests.config_util import good_policy, write

CANARY = "CANARY-7f3a9c"
LOWER_CANARY = "canary7f3a9c"

PROBLEM_CODES = (
    "unknown_key",
    "invalid_value",
    "invalid_rule",
    "glob_too_long",
    "unresolved_argv0",
    "skill_not_found",
    "plugin_not_found",
    "plugin_placeholders_missing",
    "instruction_file_unreadable",
    "override_unknown_policy",
    "override_unknown_key",
    "bare_skill_name",
    "unsafe_setting_sources",
    "deadline_too_short",
    "session_cmd_unresolved",
    "state_db_missing",
)
WARNING_CODES = (
    "relative_argv",
    "sandbox_lowered",
    "orphan_state",
    "agent_only_policy",
    "session_cmd_unresolved",
)


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if name.startswith("GATECTL_"):
            monkeypatch.delenv(name)


# --- fixtures -------------------------------------------------------------------------------


def make_executable(path: Path, body: str = "#!/bin/sh\nexit 0\n") -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def make_plugin(
    root: Path, name: str, *, skills: tuple[str, ...] = ("skill",), missing: tuple[str, ...] = ()
) -> str:
    """A fixture plugin directory with the four placeholders (minus ``missing``)."""
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": name}))
    for skill in skills:
        (root / "skills" / skill).mkdir(parents=True)
        (root / "skills" / skill / "SKILL.md").write_text("---\nname: x\n---\n")
    if ".claude" not in missing:
        (root / ".claude").mkdir()
    for placeholder in (".mcp.json", "CLAUDE.md", "CLAUDE.local.md"):
        if placeholder not in missing:
            (root / placeholder).write_text("")
    return str(root)


def agent_check(**extra: Any) -> dict[str, Any]:
    return {"name": "judge", "type": "agent", "instruction": "Be careful.", **extra}


def agent_policy(**extra: Any) -> dict[str, Any]:
    """A policy with one rule and one agent check (so it is not agent-only)."""
    body = good_policy(**extra)
    body["checks"] = [*body["checks"], agent_check()]
    return body


def script_check(argv: list[str], name: str = "scr") -> dict[str, Any]:
    return {"name": name, "type": "script", "argv": argv}


@dataclass
class Env:
    """A temp world: a resolvable fake session command and helpers to run validate."""

    tmp: Path
    capsys: pytest.CaptureFixture[str]
    session: str = field(init=False)

    def __post_init__(self) -> None:
        self.session = make_executable(self.tmp / "bin" / "claude-session")

    def base(self, **top: Any) -> dict[str, Any]:
        return {"session_cmd": [self.session], **top}

    def path(self) -> Path:
        return self.tmp / "cfg" / "config.yaml"

    def write(self, data: Any) -> Path:
        return write(self.path(), data)

    def run(self, data: Any, *flags: str) -> tuple[int, dict[str, Any]]:
        self.write(data)
        code = main(["validate", "--json", "--config", str(self.path()), *flags])
        out = self.capsys.readouterr().out
        payload = json.loads(out)
        schema_util.assert_valid("cli/validate", payload)
        return code, payload


@pytest.fixture
def env(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Env:
    return Env(tmp_path, capsys)


def found(payload: dict[str, Any], kind: str) -> set[tuple[str, str]]:
    return {(p["code"], p["path"]) for p in payload[kind]}


# --- the code table ---------------------------------------------------------------------------


@dataclass
class Case:
    code: str
    kind: str  # "problems" or "warnings"
    path: str
    build: Callable[[Env], Any]
    setup: Callable[[Env], None] = lambda env: None


def _state_db(env: Env, policies: tuple[str, ...], *, schema: bool = True) -> None:
    state = Path(os.environ["XDG_STATE_HOME"]) / "gatectl"
    state.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(state / "state.db")
    if schema:
        db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
        db.execute("INSERT INTO meta VALUES ('schema_version', '1')")
    db.execute("CREATE TABLE policy_state (policy TEXT, scope TEXT, state TEXT)")
    for name in policies:
        db.execute("INSERT INTO policy_state VALUES (?, '*', 'shadow')", (name,))
    db.commit()
    db.close()


def _audit_record(env: Env) -> None:
    state = Path(os.environ["XDG_STATE_HOME"]) / "gatectl"
    state.mkdir(parents=True, exist_ok=True)
    (state / "audit.jsonl").write_text('{"x":1}\n')


def _plugin_cfg(env: Env, **plugin_args: Any) -> dict[str, Any]:
    root = make_plugin(env.tmp / "plug", "mine", **plugin_args)
    return env.base(
        agent={"plugin_dirs": [root], "skill": "mine:skill"},
        policies={"p": agent_policy()},
    )


CASES: dict[str, Case] = {
    "unknown_key": Case("unknown_key", "problems", "bogus", lambda e: e.base(bogus=1)),
    "invalid_value": Case(
        "invalid_value",
        "problems",
        "policies.p.timeout",
        lambda e: e.base(policies={"p": good_policy(timeout="0s")}),
    ),
    "invalid_rule_value_forbidden": Case(
        "invalid_rule",
        "problems",
        "policies.p.checks.0.when.0.value",
        lambda e: e.base(
            policies={
                "p": {
                    "checks": [
                        {
                            "name": "r",
                            "type": "rule",
                            "when": [{"path": "a", "op": "exists", "value": 1}],
                            "then": "deny",
                        }
                    ]
                }
            }
        ),
    ),
    "invalid_rule_value_missing": Case(
        "invalid_rule",
        "problems",
        "policies.p.checks.0.when.0.value",
        lambda e: e.base(
            policies={
                "p": {
                    "checks": [
                        {
                            "name": "r",
                            "type": "rule",
                            "when": [{"path": "a", "op": "eq"}],
                            "then": "deny",
                        }
                    ]
                }
            }
        ),
    ),
    "invalid_rule_then": Case(
        "invalid_rule",
        "problems",
        "policies.p.checks.0.then",
        lambda e: e.base(
            policies={
                "p": {
                    "checks": [
                        {
                            "name": "r",
                            "type": "rule",
                            "when": [{"path": "a", "op": "exists"}],
                            "then": "maybe",
                        }
                    ]
                }
            }
        ),
    ),
    "invalid_rule_else": Case(
        "invalid_rule",
        "problems",
        "policies.p.checks.0.else",
        lambda e: e.base(
            policies={
                "p": {
                    "checks": [
                        {
                            "name": "r",
                            "type": "rule",
                            "when": [{"path": "a", "op": "exists"}],
                            "then": "deny",
                            "else": "skipped",
                        }
                    ]
                }
            }
        ),
    ),
    "glob_too_long": Case(
        "glob_too_long",
        "problems",
        "policies.p.checks.0.when.0.value",
        lambda e: e.base(
            policies={
                "p": {
                    "checks": [
                        {
                            "name": "r",
                            "type": "rule",
                            "when": [{"path": "a", "op": "glob", "value": "a" * 129}],
                            "then": "deny",
                        }
                    ]
                }
            }
        ),
    ),
    "unresolved_argv0": Case(
        "unresolved_argv0",
        "problems",
        "policies.p.checks.1.argv.0",
        lambda e: e.base(
            policies={"p": {"checks": [*good_policy()["checks"], script_check(["/nonexistent/x"])]}}
        ),
    ),
    "skill_not_found": Case(
        "skill_not_found",
        "problems",
        "policies.p.checks.1.skill",
        lambda e: e.base(
            policies={
                "p": {
                    "checks": [*good_policy()["checks"], agent_check(skill="gatectl:no-such-skill")]
                }
            }
        ),
    ),
    "plugin_not_found": Case(
        "plugin_not_found",
        "problems",
        "agent.skill",
        lambda e: e.base(agent={"skill": "nosuchplugin:skill"}, policies={"p": agent_policy()}),
    ),
    "plugin_placeholders_missing": Case(
        "plugin_placeholders_missing",
        "problems",
        "agent.plugin_dirs.0",
        lambda e: _plugin_cfg(e, missing=(".mcp.json",)),
    ),
    "instruction_file_unreadable": Case(
        "instruction_file_unreadable",
        "problems",
        "policies.p.checks.1.instruction_file",
        lambda e: e.base(
            policies={
                "p": {
                    "checks": [
                        *good_policy()["checks"],
                        {
                            "name": "judge",
                            "type": "agent",
                            "instruction_file": "/nonexistent/instruction.md",
                        },
                    ]
                }
            }
        ),
    ),
    "override_unknown_policy": Case(
        "override_unknown_policy",
        "problems",
        "repos.example.com/o/r.policies.ghost",
        lambda e: e.base(
            policies={"p": good_policy()},
            repos={"example.com/o/r": {"policies": {"ghost": {"timeout": "30s"}}}},
        ),
    ),
    "override_unknown_key": Case(
        "override_unknown_key",
        "problems",
        "repos.example.com/o/r.policies.p.bogus",
        lambda e: e.base(
            policies={"p": good_policy()},
            repos={"example.com/o/r": {"policies": {"p": {"bogus": 1}}}},
        ),
    ),
    "bare_skill_name": Case(
        "bare_skill_name",
        "problems",
        "agent.skill",
        lambda e: e.base(agent={"skill": "gate-check"}),
    ),
    "unsafe_setting_sources": Case(
        "unsafe_setting_sources",
        "problems",
        "agent.setting_sources",
        lambda e: e.base(agent={"setting_sources": ["user"]}, policies={"p": agent_policy()}),
    ),
    "deadline_too_short": Case(
        "deadline_too_short",
        "problems",
        "policies.p.timeout",
        lambda e: e.base(policies={"p": agent_policy(timeout="36s")}),
    ),
    "session_cmd_unresolved_problem": Case(
        "session_cmd_unresolved",
        "problems",
        "session_cmd",
        lambda e: {
            "session_cmd": ["/nonexistent/claude-session"],
            "policies": {"p": agent_policy()},
        },
    ),
    "state_db_missing": Case(
        "state_db_missing",
        "problems",
        "state.db",
        lambda e: e.base(policies={"p": good_policy()}),
        setup=_audit_record,
    ),
    "relative_argv": Case(
        "relative_argv",
        "warnings",
        "policies.p.checks.1.argv.1",
        lambda e: e.base(
            policies={
                "p": {"checks": [*good_policy()["checks"], script_check([e.session, "./rel/x"])]}
            }
        ),
    ),
    "sandbox_lowered": Case(
        "sandbox_lowered",
        "warnings",
        "agent.sandbox",
        lambda e: e.base(agent={"sandbox": "preferred"}, policies={"p": agent_policy()}),
    ),
    "orphan_state": Case(
        "orphan_state",
        "warnings",
        "policies.gone",
        lambda e: e.base(policies={"p": good_policy()}),
        setup=lambda e: _state_db(e, ("p", "gone")),
    ),
    "agent_only_policy": Case(
        "agent_only_policy",
        "warnings",
        "policies.p",
        lambda e: e.base(policies={"p": {"checks": [agent_check()]}}),
    ),
    "session_cmd_unresolved_warning": Case(
        "session_cmd_unresolved",
        "warnings",
        "session_cmd",
        lambda e: {
            "session_cmd": ["/nonexistent/claude-session"],
            "policies": {"p": good_policy()},
        },
    ),
}


@pytest.mark.parametrize("case", CASES.values(), ids=list(CASES))
def test_each_code_is_produced_with_its_kind_and_path(case: Case, env: Env) -> None:
    case.setup(env)
    code, payload = env.run(case.build(env))
    assert (case.code, case.path) in found(payload, case.kind)
    other = "warnings" if case.kind == "problems" else "problems"
    assert case.code not in {p["code"] for p in payload[other]}
    assert payload["valid"] is (not payload["problems"])
    assert code == (0 if payload["valid"] else 2)


def test_the_table_covers_every_documented_code() -> None:
    schema = json.loads(Path(schema_util.SCHEMAS, "cli", "validate.json").read_text())
    enums = schema["allOf"][1]["properties"]
    documented = {
        ("problems", c) for c in enums["problems"]["items"]["properties"]["code"]["enum"]
    } | {("warnings", c) for c in enums["warnings"]["items"]["properties"]["code"]["enum"]}
    assert documented == {("problems", c) for c in PROBLEM_CODES} | {
        ("warnings", c) for c in WARNING_CODES
    }
    assert documented == {(c.kind, c.code) for c in CASES.values()}


# --- warnings never invalidate; exit codes ---------------------------------------------------


def test_a_config_with_only_warnings_is_valid_and_exits_0(env: Env) -> None:
    cfg = env.base(
        agent={"sandbox": "off"},
        policies={
            "p": {
                "checks": [
                    *good_policy()["checks"],
                    script_check([env.session, "./relative"]),
                    agent_check(),
                ]
            },
            "only-agent": {"checks": [agent_check()]},
        },
    )
    _state_db(env, ("ghost",))
    code, payload = env.run(cfg)
    assert code == 0
    assert payload["valid"] is True and payload["problems"] == []
    assert {c for c, _ in found(payload, "warnings")} == {
        "relative_argv",
        "sandbox_lowered",
        "agent_only_policy",
        "orphan_state",
    }
    assert payload["probe"] is None


def test_an_empty_config_is_valid_and_has_no_warnings(env: Env) -> None:
    code, payload = env.run(env.base())
    assert code == 0
    assert payload == {"valid": True, "problems": [], "warnings": [], "probe": None}


def test_a_missing_default_config_is_an_empty_valid_config(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["validate", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True


def test_the_example_config_is_valid(capsys: pytest.CaptureFixture[str]) -> None:
    example = Path(__file__).resolve().parent.parent / "config.example.yaml"
    code = main(["validate", "--json", "--config", str(example)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0 and payload["problems"] == []


def test_a_problem_makes_the_config_invalid_and_exits_2(env: Env) -> None:
    code, payload = env.run(env.base(policies={"p": good_policy(timeout="0s")}))
    assert code == 2 and payload["valid"] is False and payload["problems"]


def test_a_config_that_does_not_parse_is_a_problem_not_an_envelope(env: Env) -> None:
    env.path().parent.mkdir(parents=True)
    env.path().write_text("a: [unclosed\n")
    code = main(["validate", "--json", "--config", str(env.path())])
    payload = json.loads(env.capsys.readouterr().out)
    schema_util.assert_valid("cli/validate", payload)
    assert code == 2
    assert [(p["code"], p["path"]) for p in payload["problems"]] == [("invalid_value", "config")]


def test_a_missing_explicit_config_is_unreadable_exit_1(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["validate", "--json", "--config", str(env.tmp / "nope.yaml")]) == 1
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "internal"


def test_probe_is_parsed_and_not_yet_implemented(env: Env) -> None:
    # TODO(#26): the probe itself. Until then --probe on a valid config fails loudly (exit 1)
    # instead of printing a result that looks like a skipped probe.
    env.write(env.base())
    assert main(["validate", "--json", "--probe", "--config", str(env.path())]) == 1
    assert json.loads(env.capsys.readouterr().out)["error"]["code"] == "internal"


def test_probe_with_an_invalid_config_still_reports_the_problems(env: Env) -> None:
    code, payload = env.run(env.base(bogus=1), "--probe")
    assert code == 2 and payload["probe"] is None and payload["valid"] is False


# --- other problem sources and eager checks ---------------------------------------------------


def test_every_problem_of_every_part_is_listed_at_once(env: Env) -> None:
    code, payload = env.run(
        {
            "bogus": 1,
            "session_cmd": [env.session],
            "defaults": {"timeout": "0s"},
            "policies": {
                "a": good_policy(timeout="0s"),
                "b": {"checks": [script_check(["/nonexistent/x"])]},
            },
            "repos": {"example.com/o/r": {"policies": {"a": {"bogus": 1}}}},
        }
    )
    assert code == 2
    assert found(payload, "problems") >= {
        ("unknown_key", "bogus"),
        ("invalid_value", "defaults.timeout"),
        ("invalid_value", "policies.a.timeout"),
        ("unresolved_argv0", "policies.b.checks.0.argv.0"),
        ("override_unknown_key", "repos.example.com/o/r.policies.a.bogus"),
    }


def test_an_invalid_environment_override_is_a_problem(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GATECTL_AGENT__SANDBOX", "off")
    code, payload = env.run(env.base())
    assert code == 2
    assert ("invalid_value", "agent.sandbox") in found(payload, "problems")


def test_an_argv0_that_is_not_an_executable_regular_file_is_unresolved(env: Env) -> None:
    plain = env.tmp / "plain"
    plain.write_text("x")
    plain.chmod(0o644)
    fifo = env.tmp / "fifo"
    os.mkfifo(fifo)
    loop = env.tmp / "loop"
    loop.symlink_to(loop)
    good_link = env.tmp / "link"
    good_link.symlink_to(env.session)
    names = {
        "plain": str(plain),
        "directory": str(env.tmp),
        "fifo": str(fifo),
        "loop": str(loop),
        "toolong": "/" + "a" * 5000,
    }
    checks = [good_policy()["checks"][0]] + [script_check([v], k) for k, v in names.items()]
    checks.append(script_check([str(good_link)], "okay"))
    code, payload = env.run(env.base(policies={"p": {"checks": checks}}))
    assert code == 2
    assert found(payload, "problems") == {
        ("unresolved_argv0", f"policies.p.checks.{i}.argv.0") for i in range(1, 6)
    }


def test_argv_zero_is_checked_for_agent_free_policies_and_overrides(env: Env) -> None:
    code, payload = env.run(
        env.base(
            policies={"p": good_policy()},
            repos={
                "example.com/o/r": {
                    "policies": {"p": {"checks": [script_check(["/nonexistent/y", "rel/x"])]}}
                }
            },
        )
    )
    assert code == 2
    assert found(payload, "problems") == {
        ("unresolved_argv0", "repos.example.com/o/r.policies.p.checks.0.argv.0")
    }
    assert found(payload, "warnings") == {
        ("relative_argv", "repos.example.com/o/r.policies.p.checks.0.argv.1")
    }


def test_relative_argv_only_warns_for_path_like_non_absolute_elements(env: Env) -> None:
    argv = [env.session, "plain", "--flag=x/y", "/abs/ok", "a/b", "../c", "-"]
    _, payload = env.run(env.base(policies={"p": {"checks": [script_check(argv)]}}))
    assert found(payload, "warnings") == {
        ("relative_argv", f"policies.p.checks.0.argv.{i}") for i in (2, 4, 5)
    }


def test_skill_resolution_uses_the_check_skill_then_the_agent_block(env: Env) -> None:
    root = make_plugin(env.tmp / "plug", "mine", skills=("good",))
    cfg = env.base(
        agent={"plugin_dirs": [root], "skill": "mine:absent"},
        policies={
            "p": {"checks": [agent_check(skill="mine:good")]},
            "q": {"checks": [agent_check(skill="mine:also-absent")]},
            "r": {"checks": [agent_check()]},
        },
    )
    _, payload = env.run(cfg)
    assert found(payload, "problems") == {
        ("skill_not_found", "policies.q.checks.0.skill"),
        ("skill_not_found", "agent.skill"),
    }


def test_a_skill_directory_without_skill_md_is_not_found(env: Env) -> None:
    root = make_plugin(env.tmp / "plug", "mine", skills=())
    (Path(root) / "skills" / "empty").mkdir(parents=True)
    cfg = env.base(
        agent={"plugin_dirs": [root], "skill": "mine:empty"}, policies={"p": agent_policy()}
    )
    _, payload = env.run(cfg)
    assert ("skill_not_found", "agent.skill") in found(payload, "problems")


def test_the_default_skill_of_the_bundled_plugin_resolves(env: Env) -> None:
    code, payload = env.run(env.base(policies={"p": agent_policy()}))
    assert code == 0, payload
    assert payload["problems"] == []


def test_a_plugin_dir_whose_name_is_taken_is_a_problem(env: Env) -> None:
    one = make_plugin(env.tmp / "one", "dup")
    two = make_plugin(env.tmp / "two", "dup")
    _, payload = env.run(env.base(agent={"plugin_dirs": [one, two]}))
    assert found(payload, "problems") == {("invalid_value", "agent.plugin_dirs.1")}


def test_a_plugin_dir_may_not_reuse_the_bundled_name(env: Env) -> None:
    clash = make_plugin(env.tmp / "clash", "gatectl")
    _, payload = env.run(env.base(agent={"plugin_dirs": [clash]}))
    assert found(payload, "problems") == {("invalid_value", "agent.plugin_dirs.0")}


def test_a_plugin_dir_without_a_readable_name_is_plugin_not_found(env: Env) -> None:
    empty = env.tmp / "empty"
    empty.mkdir()
    fifo_dir = env.tmp / "fifo"
    (fifo_dir / ".claude-plugin").mkdir(parents=True)
    os.mkfifo(fifo_dir / ".claude-plugin" / "plugin.json")
    big = env.tmp / "big"
    (big / ".claude-plugin").mkdir(parents=True)
    (big / ".claude-plugin" / "plugin.json").write_text(
        '{"name":"big","pad":"' + "x" * 2_000_000 + '"}'
    )
    bad = env.tmp / "bad"
    (bad / ".claude-plugin").mkdir(parents=True)
    (bad / ".claude-plugin" / "plugin.json").write_text("[1,")
    _, payload = env.run(
        env.base(agent={"plugin_dirs": [str(empty), str(fifo_dir), str(big), str(bad)]})
    )
    assert found(payload, "problems") == {
        ("plugin_not_found", f"agent.plugin_dirs.{i}") for i in range(4)
    }


def test_each_missing_placeholder_is_reported_for_the_used_plugin_only(env: Env) -> None:
    unused = make_plugin(env.tmp / "unused", "unused", missing=(".claude", "CLAUDE.md"))
    used = make_plugin(env.tmp / "used", "mine", missing=(".claude",))
    cfg = env.base(
        agent={"plugin_dirs": [unused, used], "skill": "mine:skill"},
        policies={"p": agent_policy()},
    )
    _, payload = env.run(cfg)
    assert found(payload, "problems") == {("plugin_placeholders_missing", "agent.plugin_dirs.1")}
    messages = [p["message"] for p in payload["problems"]]
    assert any(".claude/" in m for m in messages)


@pytest.mark.parametrize("name", [".claude", ".mcp.json", "CLAUDE.md", "CLAUDE.local.md"])
def test_every_placeholder_is_required(env: Env, name: str) -> None:
    root = make_plugin(env.tmp / "plug", "mine", missing=(name,))
    cfg = env.base(
        agent={"plugin_dirs": [root], "skill": "mine:skill"}, policies={"p": agent_policy()}
    )
    _, payload = env.run(cfg)
    assert ("plugin_placeholders_missing", "agent.plugin_dirs.0") in found(payload, "problems")


def test_a_placeholder_of_the_wrong_type_counts_as_missing(env: Env) -> None:
    root = make_plugin(env.tmp / "plug", "mine", missing=(".claude", "CLAUDE.md"))
    (Path(root) / ".claude").write_text("a file, not a directory")
    (Path(root) / "CLAUDE.md").mkdir()
    cfg = env.base(
        agent={"plugin_dirs": [root], "skill": "mine:skill"}, policies={"p": agent_policy()}
    )
    _, payload = env.run(cfg)
    assert "plugin_placeholders_missing" in {c for c, _ in found(payload, "problems")}


def test_the_bundled_plugin_is_checked_for_placeholders_when_an_agent_check_exists(
    tmp_path: Path,
) -> None:
    bundled = make_plugin(
        tmp_path / "bundled", "gatectl", skills=("gate-check",), missing=(".mcp.json",)
    )
    session = make_executable(tmp_path / "bin" / "claude-session")
    cfg = write(tmp_path / "c.yaml", {"session_cmd": [session], "policies": {"p": agent_policy()}})
    loaded = load_config(str(cfg), environ={})
    report = validate.validate_config(
        loaded, environ={}, bundled_plugin=bundled, state_dir=tmp_path / "state"
    )
    assert [(p.code, p.path) for p in report.problems] == [("plugin_placeholders_missing", "agent")]
    # No agent check: the bundled directory is not used, so it is not inspected.
    cfg = write(tmp_path / "d.yaml", {"session_cmd": [session], "policies": {"p": good_policy()}})
    report = validate.validate_config(
        load_config(str(cfg), environ={}),
        environ={},
        bundled_plugin=bundled,
        state_dir=tmp_path / "state",
    )
    assert report.problems == []


def test_a_missing_bundled_plugin_makes_the_default_skill_unfindable(tmp_path: Path) -> None:
    session = make_executable(tmp_path / "bin" / "claude-session")
    cfg = write(tmp_path / "c.yaml", {"session_cmd": [session], "policies": {"p": agent_policy()}})
    report = validate.validate_config(
        load_config(str(cfg), environ={}),
        environ={},
        bundled_plugin=str(tmp_path / "no-such-dir"),
        state_dir=tmp_path / "state",
    )
    assert {(p.code, p.path) for p in report.problems} >= {("plugin_not_found", "agent.skill")}


# --- instruction files ----------------------------------------------------------------------


def _file_policy(path: str) -> dict[str, Any]:
    return {
        "p": {
            "checks": [
                *good_policy()["checks"],
                {"name": "judge", "type": "agent", "instruction_file": path},
            ]
        }
    }


def test_a_readable_instruction_file_and_a_link_to_one_are_fine(env: Env) -> None:
    real = env.tmp / "real.md"
    real.write_text("text")
    link = env.tmp / "link.md"
    link.symlink_to(real)
    for path in (real, link):
        code, payload = env.run(env.base(policies=_file_policy(str(path))))
        assert code == 0 and payload["problems"] == []


def test_an_instruction_file_over_64_kib_is_unreadable_and_64_kib_is_not(env: Env) -> None:
    ok = env.tmp / "ok.md"
    ok.write_bytes(b"a" * 65536)
    big = env.tmp / "big.md"
    big.write_bytes(b"a" * 65537)
    assert env.run(env.base(policies=_file_policy(str(ok))))[0] == 0
    code, payload = env.run(env.base(policies=_file_policy(str(big))))
    assert code == 2
    assert found(payload, "problems") == {
        ("instruction_file_unreadable", "policies.p.checks.1.instruction_file")
    }


def test_an_instruction_file_that_is_a_fifo_a_directory_or_a_loop_is_unreadable(env: Env) -> None:
    fifo = env.tmp / "fifo.md"
    os.mkfifo(fifo)
    loop = env.tmp / "loop.md"
    loop.symlink_to(loop)
    for path in (fifo, env.tmp, loop, Path("/dev/null"), Path("/dev/zero")):
        code, payload = env.run(env.base(policies=_file_policy(str(path))))
        assert code == 2, path
        assert ("instruction_file_unreadable", "policies.p.checks.1.instruction_file") in found(
            payload, "problems"
        )


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
def test_an_instruction_file_without_read_permission_is_unreadable(env: Env) -> None:
    locked = env.tmp / "locked.md"
    locked.write_text("x")
    locked.chmod(0)
    code, payload = env.run(env.base(policies=_file_policy(str(locked))))
    assert code == 2
    assert "instruction_file_unreadable" in {c for c, _ in found(payload, "problems")}


# --- agent safety settings ------------------------------------------------------------------


def test_sandbox_and_setting_sources_are_judged_on_each_checks_resolved_values(env: Env) -> None:
    cfg = env.base(
        agent={"sandbox": "required", "setting_sources": ["project"]},
        policies={
            "inherits": {"checks": [agent_check()]},
            "empties": {"checks": [agent_check(setting_sources=[])]},
            "lowers": {"checks": [agent_check(sandbox="off", setting_sources=["user", "local"])]},
            "prefers": {"checks": [agent_check(sandbox="preferred")]},
        },
    )
    _, payload = env.run(cfg)
    assert found(payload, "problems") == {
        ("unsafe_setting_sources", "agent.setting_sources"),
        ("unsafe_setting_sources", "policies.lowers.checks.0.setting_sources"),
    }
    assert found(payload, "warnings") >= {
        ("sandbox_lowered", "policies.lowers.checks.0.sandbox"),
        ("sandbox_lowered", "policies.prefers.checks.0.sandbox"),
    }
    assert not any(p.startswith("policies.empties") for _, p in found(payload, "problems"))


def test_a_per_repo_override_agent_check_is_judged_too(env: Env) -> None:
    cfg = env.base(
        policies={"p": good_policy()},
        repos={
            "example.com/o/r": {
                "policies": {
                    "p": {
                        "checks": [
                            *good_policy()["checks"],
                            agent_check(sandbox="off", setting_sources=["user"]),
                        ]
                    }
                }
            }
        },
    )
    _, payload = env.run(cfg)
    base = "repos.example.com/o/r.policies.p.checks.1"
    assert found(payload, "problems") == {("unsafe_setting_sources", f"{base}.setting_sources")}
    assert found(payload, "warnings") == {("sandbox_lowered", f"{base}.sandbox")}


def test_agent_block_settings_without_any_agent_check_are_not_reported(env: Env) -> None:
    cfg = env.base(
        agent={"sandbox": "off", "setting_sources": ["user"]}, policies={"p": good_policy()}
    )
    code, payload = env.run(cfg)
    assert code == 0 and payload["warnings"] == []


def test_a_repeated_agent_block_finding_is_reported_once(env: Env) -> None:
    cfg = env.base(
        agent={"sandbox": "off"},
        policies={
            "p": {"checks": [agent_check(), agent_check() | {"name": "j2"}]},
            "q": agent_policy(),
        },
    )
    _, payload = env.run(cfg)
    assert [w["path"] for w in payload["warnings"] if w["code"] == "sandbox_lowered"] == [
        "agent.sandbox"
    ]


# --- deadline ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("timeout", "short"),
    [("36s", True), ("36999ms", True), ("37s", False), ("60s", False), ("1s", True)],
)
def test_deadline_too_short_boundary(env: Env, timeout: str, short: bool) -> None:
    _, payload = env.run(env.base(policies={"p": agent_policy(timeout=timeout)}))
    assert ("deadline_too_short" in {c for c, _ in found(payload, "problems")}) is short


def test_deadline_uses_the_defaults_timeout_record_reserve_and_min_start_budget(env: Env) -> None:
    cfg = env.base(
        defaults={"timeout": "40s", "record_reserve": "10s"}, policies={"p": agent_policy()}
    )
    _, payload = env.run(cfg)
    assert found(payload, "problems") == {("deadline_too_short", "defaults.timeout")}
    cfg = env.base(
        agent={"min_start_budget": "1s"}, defaults={"timeout": "8s"}, policies={"p": agent_policy()}
    )
    assert env.run(cfg)[0] == 0


def test_a_policy_without_an_agent_check_has_no_deadline_problem(env: Env) -> None:
    code, _ = env.run(env.base(policies={"p": good_policy(timeout="1s")}))
    assert code == 0


def test_deadline_too_short_applies_to_repo_overrides(env: Env) -> None:
    cfg = env.base(
        policies={"p": agent_policy(), "q": good_policy()},
        repos={
            "example.com/o/r": {
                "policies": {
                    "p": {"timeout": "10s"},
                    "q": {"checks": [agent_check()], "timeout": "20s"},
                }
            },
            "example.com/o/s": {"policies": {"q": {"checks": [agent_check()]}}},
        },
    )
    _, payload = env.run(cfg)
    assert found(payload, "problems") == {
        ("deadline_too_short", "repos.example.com/o/r.policies.p.timeout"),
        ("deadline_too_short", "repos.example.com/o/r.policies.q.timeout"),
    }


def test_an_override_that_drops_the_agent_check_is_not_judged(env: Env) -> None:
    cfg = env.base(
        policies={"p": agent_policy()},
        repos={
            "example.com/o/r": {
                "policies": {"p": {"timeout": "5s", "checks": good_policy()["checks"]}}
            }
        },
    )
    code, _ = env.run(cfg)
    assert code == 0


# --- session_cmd ------------------------------------------------------------------------------


def test_a_session_cmd_that_resolves_is_neither_problem_nor_warning(env: Env) -> None:
    code, payload = env.run(env.base(policies={"p": agent_policy()}))
    assert code == 0 and "session_cmd_unresolved" not in {
        c for c, _ in found(payload, "warnings") | found(payload, "problems")
    }


def test_a_bare_session_cmd_is_searched_in_the_fixed_directories_only(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    on_path = env.tmp / "pathbin"
    make_executable(on_path / "tool-on-path")
    monkeypatch.setenv("PATH", str(on_path))
    _, payload = env.run({"session_cmd": ["tool-on-path"], "policies": {"p": good_policy()}})
    assert found(payload, "warnings") == {("session_cmd_unresolved", "session_cmd")}
    home_bin = Path(os.environ["HOME"]) / ".local" / "bin"
    make_executable(home_bin / "tool-in-home")
    code, payload = env.run({"session_cmd": ["tool-in-home"], "policies": {"p": agent_policy()}})
    assert code == 0 and payload["warnings"] == []


def test_an_agent_check_only_in_an_override_makes_session_cmd_a_problem(env: Env) -> None:
    cfg = {
        "session_cmd": ["/nonexistent/s"],
        "policies": {"p": good_policy()},
        "repos": {"example.com/o/r": {"policies": {"p": {"checks": [agent_check()]}}}},
    }
    code, payload = env.run(cfg)
    assert code == 2
    assert ("session_cmd_unresolved", "session_cmd") in found(payload, "problems")


def test_the_default_session_cmd_is_unresolved_in_a_clean_home(env: Env) -> None:
    if any(
        os.access(os.path.join(d, "claude-session"), os.X_OK)
        for d in ("/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin")
    ):
        pytest.skip("a real claude-session is installed")
    _, payload = env.run({"policies": {"p": good_policy()}})
    assert found(payload, "warnings") == {("session_cmd_unresolved", "session_cmd")}


def test_text_output_prints_the_resolved_session_cmd_path(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    env.write(env.base(policies={"p": good_policy()}))
    assert main(["validate", "--config", str(env.path())]) == 0
    out = capsys.readouterr().out
    assert f"session_cmd: {env.session}" in out.splitlines()
    assert out.splitlines()[-1] == "valid"


def test_text_output_says_when_session_cmd_is_unresolved(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    env.write({"session_cmd": ["/nonexistent/s"]})
    assert main(["validate", "--config", str(env.path())]) == 0
    assert "session_cmd: not found" in capsys.readouterr().out.splitlines()


def test_text_output_lists_problems_and_warnings_and_exits_2(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    env.write(env.base(bogus=1, policies={"p": {"checks": [agent_check()]}}))
    assert main(["validate", "--config", str(env.path())]) == 2
    lines = capsys.readouterr().out.splitlines()
    assert any(line.startswith("problem unknown_key bogus: ") for line in lines)
    assert any(line.startswith("warning agent_only_policy policies.p: ") for line in lines)
    assert lines[-1] == "invalid"


# --- state.db ---------------------------------------------------------------------------------


def test_a_fresh_install_has_no_state_db_and_that_is_not_a_problem(env: Env) -> None:
    # The ask on issue #10: awkit doctor runs validate before the first check.
    code, payload = env.run(env.base(policies={"p": good_policy()}))
    assert code == 0 and payload["problems"] == [] and payload["warnings"] == []


def test_an_empty_audit_log_without_a_state_db_is_still_a_fresh_install(env: Env) -> None:
    state = Path(os.environ["XDG_STATE_HOME"]) / "gatectl"
    state.mkdir(parents=True)
    (state / "audit.jsonl").write_text("")
    code, payload = env.run(env.base())
    assert code == 0 and payload["problems"] == []


@pytest.mark.parametrize("kind", ["zero-length", "directory", "fifo"])
def test_an_unusable_state_db_next_to_an_audit_history_is_state_db_missing(
    env: Env, kind: str
) -> None:
    _audit_record(env)
    db = Path(os.environ["XDG_STATE_HOME"]) / "gatectl" / "state.db"
    if kind == "zero-length":
        db.write_bytes(b"")
    elif kind == "directory":
        db.mkdir()
    else:
        os.mkfifo(db)
    code, payload = env.run(env.base())
    assert code == 2
    assert found(payload, "problems") == {("state_db_missing", "state.db")}


def test_a_state_db_that_exists_is_not_missing(env: Env) -> None:
    _audit_record(env)
    _state_db(env, ("p",))
    code, payload = env.run(env.base(policies={"p": good_policy()}))
    assert code == 0 and payload["problems"] == []


def test_orphan_state_lists_each_policy_in_state_db_but_not_in_the_config(env: Env) -> None:
    _state_db(env, ("p", "removed-a", "removed-b", "removed-a"))
    _, payload = env.run(env.base(policies={"p": good_policy()}))
    assert found(payload, "warnings") == {
        ("orphan_state", "policies.removed-a"),
        ("orphan_state", "policies.removed-b"),
    }


def test_an_invalid_policy_in_the_config_is_not_an_orphan(env: Env) -> None:
    _state_db(env, ("p",))
    _, payload = env.run(env.base(policies={"p": good_policy(bogus=1)}))
    assert found(payload, "warnings") == set()


def test_orphan_state_also_reads_decisions(env: Env) -> None:
    _state_db(env, ())
    state = Path(os.environ["XDG_STATE_HOME"]) / "gatectl"
    db = sqlite3.connect(state / "state.db")
    db.execute("CREATE TABLE decisions (id TEXT, policy TEXT)")
    db.execute("INSERT INTO decisions VALUES ('gd-x', 'only-in-decisions')")
    db.commit()
    db.close()
    _, payload = env.run(env.base())
    assert found(payload, "warnings") == {("orphan_state", "policies.only-in-decisions")}


def test_a_hostile_state_db_is_ignored_not_trusted(env: Env) -> None:
    state = Path(os.environ["XDG_STATE_HOME"]) / "gatectl"
    state.mkdir(parents=True)
    (state / "state.db").write_bytes(b"not a database" * 100)
    code, payload = env.run(env.base())
    assert code == 0 and payload["warnings"] == []


def test_state_db_values_that_are_not_policy_names_are_never_printed(env: Env) -> None:
    _state_db(env, (f"{CANARY}\x1b[31m\n", "UPPER", "x" * 200, "ok-name"))
    state = Path(os.environ["XDG_STATE_HOME"]) / "gatectl"
    db = sqlite3.connect(state / "state.db")
    db.execute("INSERT INTO policy_state VALUES (NULL, '*', 'off')")
    db.execute("INSERT INTO policy_state VALUES (X'DEADBEEF', '*', 'off')")
    db.commit()
    db.close()
    _, payload = env.run(env.base())
    assert found(payload, "warnings") == {("orphan_state", "policies.ok-name")}
    assert CANARY not in json.dumps(payload)


def test_orphan_warnings_are_capped(env: Env) -> None:
    _state_db(env, tuple(f"gone-{i}" for i in range(validate.MAX_REPORTED + 50)))
    _, payload = env.run(env.base())
    assert len(payload["warnings"]) == validate.MAX_REPORTED


def test_state_db_is_opened_read_only_and_left_unchanged(env: Env) -> None:
    _state_db(env, ("gone",))
    state = Path(os.environ["XDG_STATE_HOME"]) / "gatectl"
    before = (state / "state.db").read_bytes()
    env.run(env.base())
    assert (state / "state.db").read_bytes() == before
    assert sorted(p.name for p in state.iterdir()) == ["state.db"]


def _state_dir() -> Path:
    return Path(os.environ["XDG_STATE_HOME"]) / "gatectl"


def _snapshot(directory: Path) -> dict[str, tuple[int, str]]:
    import hashlib

    return {
        p.name: (p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
        for p in sorted(directory.iterdir())
    }


@pytest.mark.parametrize("kind", ["unrelated-table", "no-schema-row", "garbage"])
def test_a_state_db_without_a_schema_version_row_is_state_db_missing(env: Env, kind: str) -> None:
    _audit_record(env)
    state = _state_dir()
    state.mkdir(parents=True, exist_ok=True)
    if kind == "garbage":
        (state / "state.db").write_bytes(b"not a database" * 100)
    else:
        db = sqlite3.connect(state / "state.db")
        if kind == "unrelated-table":
            db.execute("CREATE TABLE other (x)")
        else:
            db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
            db.execute("INSERT INTO meta VALUES ('state_rev', '1')")
        db.commit()
        db.close()
    code, payload = env.run(env.base())
    assert code == 2
    assert found(payload, "problems") == {("state_db_missing", "state.db")}


@pytest.mark.parametrize("kind", ["unrelated-table", "no-schema-row", "garbage"])
def test_a_schema_less_state_db_is_no_problem_without_an_audit_history(env: Env, kind: str) -> None:
    state = _state_dir()
    state.mkdir(parents=True, exist_ok=True)
    (state / "audit.jsonl").write_text("")
    if kind == "garbage":
        (state / "state.db").write_bytes(b"not a database" * 100)
    else:
        db = sqlite3.connect(state / "state.db")
        db.execute("CREATE TABLE other (x)")
        db.commit()
        db.close()
    code, payload = env.run(env.base())
    assert code == 0 and payload["problems"] == []


def test_a_state_db_with_a_schema_version_row_stays_valid_next_to_a_history(env: Env) -> None:
    _audit_record(env)
    _state_db(env, ())
    code, payload = env.run(env.base())
    assert code == 0 and payload["problems"] == []


def _wal_db(policies: tuple[str, ...], where: Path | None = None) -> sqlite3.Connection:
    state = where if where is not None else _state_dir()
    state.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(state / "state.db", isolation_level=None)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA wal_autocheckpoint=0")
    db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT)")
    db.execute("INSERT INTO meta VALUES ('schema_version', '1')")
    db.execute("CREATE TABLE policy_state (policy TEXT, scope TEXT, state TEXT)")
    for name in policies:
        db.execute("INSERT INTO policy_state VALUES (?, '*', 'shadow')", (name,))
    return db


def _closed_wal_db(policies: tuple[str, ...]) -> None:
    _wal_db(policies).close()  # the last close checkpoints and removes -wal and -shm


def test_a_wal_state_db_without_sidecars_is_read_without_creating_any(env: Env) -> None:
    _closed_wal_db(("gone",))
    state = _state_dir()
    assert sorted(p.name for p in state.iterdir()) == ["state.db"]
    before = _snapshot(state)
    mtime = state.stat().st_mtime_ns
    _, payload = env.run(env.base())
    assert found(payload, "warnings") == {("orphan_state", "policies.gone")}
    assert _snapshot(state) == before
    assert state.stat().st_mtime_ns == mtime


def test_rows_that_live_only_in_the_wal_are_read(env: Env) -> None:
    writer = _wal_db(("gone",))
    try:
        state = _state_dir()
        assert (state / "state.db-wal").stat().st_size > 0
        _audit_record(env)
        before = _snapshot(state)
        code, payload = env.run(env.base())
        assert code == 0
        assert found(payload, "warnings") == {("orphan_state", "policies.gone")}
        after = _snapshot(state)
        # A reader of a live WAL database sets lock marks in the -shm index: that file may change.
        assert after.keys() == before.keys()
        assert {k: v for k, v in after.items() if k != "state.db-shm"} == {
            k: v for k, v in before.items() if k != "state.db-shm"
        }
    finally:
        writer.close()


def test_a_symlinked_state_db_with_a_live_wal_is_read_through_the_real_directory(
    env: Env,
) -> None:
    real = env.tmp / "elsewhere"
    writer = _wal_db(("gone",), real)
    try:
        assert (real / "state.db-wal").stat().st_size > 0
        _audit_record(env)
        (_state_dir() / "state.db").symlink_to(real / "state.db")
        code, payload = env.run(env.base())
        assert code == 0
        assert found(payload, "problems") == set()
        assert found(payload, "warnings") == {("orphan_state", "policies.gone")}
    finally:
        writer.close()


def test_a_non_empty_wal_without_shm_is_not_read_and_nothing_is_created(env: Env) -> None:
    writer = _wal_db(("gone",))
    try:
        state = _state_dir()
        (state / "state.db-shm").unlink()
        _audit_record(env)
        before = _snapshot(state)
        code, payload = env.run(env.base())
        assert code == 0
        assert found(payload, "problems") == set()
        assert found(payload, "warnings") == set()
        assert _snapshot(state) == before
    finally:
        writer.close()


def test_a_wal_state_db_swapped_for_a_fifo_after_it_was_opened_is_not_read(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    import signal

    writer = _wal_db(("gone",))
    try:
        _audit_record(env)
        db = _state_dir() / "state.db"
        real_open = os.open
        swapped: list[bool] = []

        def swapping_open(path: Any, *args: Any, **kwargs: Any) -> int:
            fd = real_open(path, *args, **kwargs)
            if Path(path) == db and not swapped:
                swapped.append(True)
                db.unlink()
                os.mkfifo(db)
            return fd

        monkeypatch.setattr(validate.os, "open", swapping_open)
        signal.alarm(20)
        try:
            code, payload = env.run(env.base())
        finally:
            signal.alarm(0)
    finally:
        writer.close()
    assert swapped
    assert code == 2
    assert found(payload, "problems") == {("state_db_missing", "state.db")}


def test_a_wal_state_db_in_a_read_only_directory_still_reports_orphans(env: Env) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    _closed_wal_db(("gone",))
    state = _state_dir()
    state.chmod(0o555)
    try:
        _, payload = env.run(env.base())
    finally:
        state.chmod(0o755)
    assert found(payload, "warnings") == {("orphan_state", "policies.gone")}
    assert sorted(p.name for p in state.iterdir()) == ["state.db"]


def test_a_state_db_swapped_for_a_fifo_between_check_and_open_does_not_hang(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    import signal

    _audit_record(env)
    _state_db(env, ("gone",))
    db = _state_dir() / "state.db"
    real_open = os.open
    swapped: list[bool] = []

    def swapping_open(path: Any, *args: Any, **kwargs: Any) -> int:
        if Path(path) == db and not swapped:
            swapped.append(True)
            db.unlink()
            os.mkfifo(db)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(validate.os, "open", swapping_open)
    signal.alarm(20)  # a hang fails the test instead of the run
    try:
        code, payload = env.run(env.base())
    finally:
        signal.alarm(0)
    assert swapped
    assert code == 2
    assert found(payload, "problems") == {("state_db_missing", "state.db")}


def test_the_fd_type_check_runs_before_a_wal_database_is_connected(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    import signal

    writer = _wal_db(("gone",))
    try:
        _audit_record(env)
        db = _state_dir() / "state.db"
        real_open = os.open
        swapped: list[bool] = []

        def swapping_open(path: Any, *args: Any, **kwargs: Any) -> int:
            if Path(path) == db and not swapped:
                swapped.append(True)
                db.unlink()
                os.mkfifo(db)
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr(validate.os, "open", swapping_open)
        signal.alarm(20)
        try:
            code, payload = env.run(env.base())
        finally:
            signal.alarm(0)
    finally:
        writer.close()
    assert code == 2
    assert found(payload, "problems") == {("state_db_missing", "state.db")}


def test_importing_validate_first_works_in_a_fresh_interpreter() -> None:
    import subprocess
    import sys

    done = subprocess.run(
        [sys.executable, "-I", "-c", "import gatectl.validate"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert done.returncode == 0, done.stderr


def test_text_output_omits_the_session_cmd_line_when_the_config_did_not_parse(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    env.path().parent.mkdir(parents=True, exist_ok=True)
    env.path().write_text("a: [unclosed\n")
    assert main(["validate", "--config", str(env.path())]) == 2
    lines = capsys.readouterr().out.splitlines()
    assert not any(line.startswith("session_cmd:") for line in lines)
    assert lines[-1] == "invalid"


def test_an_invalid_policy_with_an_agent_check_keeps_session_cmd_a_problem(env: Env) -> None:
    cfg = {
        "session_cmd": ["/nonexistent/s"],
        "policies": {"p": {"checks": [agent_check()], "bogus": 1}},
    }
    code, payload = env.run(cfg)
    assert code == 2
    assert ("session_cmd_unresolved", "session_cmd") in found(payload, "problems")
    assert ("session_cmd_unresolved", "session_cmd") not in found(payload, "warnings")


# --- hostile input and untrusted text ------------------------------------------------------


def test_no_config_value_reaches_the_output(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    hostile = f"{CANARY}\x1b]0;x\x07‮\n"
    cfg = {
        "session_cmd": [f"/nonexistent/{hostile}"],
        "me": {"name": hostile},
        "defaults": {"timeout": hostile, "script_env_allow": [hostile]},
        "agent": {
            "skill": f"{LOWER_CANARY}:skill",
            "model": hostile,
            "sandbox": hostile,
            "plugin_dirs": [f"/nonexistent/{hostile}"],
            "env_allowlist": [hostile],
        },
        "policies": {
            "p": {
                "timeout": hostile,
                "checks": [
                    script_check([f"/nonexistent/{hostile}", f"{hostile}/rel"]),
                    agent_check(instruction_file=f"/nonexistent/{hostile}"),
                    {
                        "name": "r",
                        "type": "rule",
                        "when": [{"path": hostile, "op": "glob", "value": hostile * 40}],
                        "then": hostile,
                    },
                ],
            },
            "q": {
                "checks": [
                    script_check([f"/nonexistent/{hostile}", f"{hostile}/rel"]),
                    agent_check(
                        instruction_file=f"/nonexistent/{hostile}",
                        skill=f"{LOWER_CANARY}:skill",
                        model=hostile,
                    ),
                ]
            },
        },
        "repos": {"example.com/o/r": {"policies": {"q": {"timeout": hostile}}}},
    }
    env.write(cfg)
    for flags in ([], ["--json"], ["--verbose"]):
        code = main(["validate", "--config", str(env.path()), *flags])
        captured = capsys.readouterr()
        assert code == 2
        for stream in (captured.out, captured.err):
            assert CANARY not in stream and LOWER_CANARY not in stream
            assert "\x1b" not in stream and "\x07" not in stream and "‮" not in stream


def test_hostile_key_names_are_sanitized_and_capped_in_paths(env: Env) -> None:
    key = f"a\x1b[31m{'k' * 200}‮"
    _, payload = env.run(env.base(**{key: 1}))
    (problem,) = payload["problems"]
    assert problem["code"] == "unknown_key"
    assert "\x1b" not in problem["path"] and "‮" not in problem["path"]
    assert len(problem["path"]) <= 64


def test_messages_are_fixed_text_and_paths_hold_keys_only(env: Env) -> None:
    cfg = env.base(
        policies={
            "p": {
                "checks": [
                    script_check(["/nonexistent/" + CANARY, CANARY + "/x"]),
                    agent_check(instruction_file="/nonexistent/" + CANARY),
                ]
            }
        }
    )
    _, payload = env.run(cfg)
    assert payload["problems"] and payload["warnings"] is not None
    assert CANARY not in json.dumps(payload)


def test_the_number_of_reported_problems_and_warnings_is_capped(env: Env) -> None:
    n = validate.MAX_REPORTED + 40
    policies = {f"p{i}": {"checks": [script_check(["/nonexistent/x", "r/x"])]} for i in range(n)}
    code, payload = env.run(env.base(policies=policies))
    assert code == 2
    assert len(payload["problems"]) == validate.MAX_REPORTED
    assert len(payload["warnings"]) == validate.MAX_REPORTED


def test_a_config_that_is_a_fifo_fails_fast_without_hanging(env: Env) -> None:
    fifo = env.tmp / "cfg.yaml"
    os.mkfifo(fifo)
    assert main(["validate", "--json", "--config", str(fifo)]) == 1


def test_a_symlinked_config_is_followed(env: Env) -> None:
    env.write(env.base())
    link = env.tmp / "link.yaml"
    link.symlink_to(env.path())
    assert main(["validate", "--json", "--config", str(link)]) == 0


def test_validate_never_runs_a_process_or_touches_the_files_it_resolves(env: Env) -> None:
    marker = env.tmp / "ran"
    script = make_executable(env.tmp / "bin" / "tool", f"#!/bin/sh\ntouch {marker}\n")
    session = make_executable(env.tmp / "bin" / "sess", f"#!/bin/sh\ntouch {marker}\n")
    before = os.stat(script)
    cfg = {
        "session_cmd": [session],
        "policies": {"p": {"checks": [script_check([script]), agent_check()]}},
    }
    code, _ = env.run(cfg)
    assert code == 0 and not marker.exists()
    after = os.stat(script)
    assert (before.st_mtime_ns, before.st_ino) == (after.st_mtime_ns, after.st_ino)


def test_validate_does_not_create_the_state_directory(env: Env) -> None:
    env.run(env.base(policies={"p": agent_policy()}))
    assert not (Path(os.environ["XDG_STATE_HOME"]) / "gatectl").exists()


def test_the_result_is_deterministic(env: Env) -> None:
    cfg = env.base(
        bogus=1,
        policies={
            "b": {"checks": [script_check(["/nonexistent/x", "r/y"])]},
            "a": agent_policy(timeout="1s"),
        },
    )
    first = env.run(cfg)
    second = env.run(cfg)
    assert first == second


# --- registration and goldens ----------------------------------------------------------------


def test_validate_is_registered() -> None:
    assert commands.HANDLERS["validate"] is validate.handle


def test_the_handler_raises_internal_error_for_probe_on_a_valid_config(env: Env) -> None:
    env.write(env.base())
    ctx = commands.Context(
        command="validate",
        args=__import__("argparse").Namespace(probe=True),
        json=True,
        config=str(env.path()),
        verbose=False,
        quiet=False,
        actor=None,
        decision_ids=(),
        stdin_tty=False,
    )
    with pytest.raises(InternalError):
        validate.handle(ctx)


def test_unused_names_from_config_stay_importable() -> None:
    assert config.ConfigProblem is validate.ConfigProblem
    assert stat.S_ISREG(os.stat(__file__).st_mode)
