"""Model validation: defaults, ranges (both sides of every boundary), per-key rules."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from gatectl import errors
from tests import schema_util
from tests.config_util import good_policy, load

CANARY = "SECRET-CANARY-91c2"


def _codes(problems: Any) -> list[tuple[str, str]]:
    return [(p.code, p.path) for p in problems]


def _shared(tmp_path: Path, section: str, key: str, value: Any) -> Any:
    return load(tmp_path, {section: {key: value}})


def _policy(tmp_path: Path, **keys: Any) -> Any:
    return load(tmp_path, {"policies": {"p": good_policy(**keys)}})


def _check(tmp_path: Path, check: dict[str, Any]) -> Any:
    return load(tmp_path, {"policies": {"p": {"checks": [check]}}})


# --- defaults --------------------------------------------------------------------------


def test_empty_config_has_every_documented_default(tmp_path: Path) -> None:
    c = load(tmp_path, {})
    s = c.shared
    assert c.shared_problems == ()
    assert s.me.name is None
    assert s.session_cmd == ["claude-session"]
    d = s.defaults
    assert d.timeout == timedelta(seconds=60)
    assert d.script_timeout == timedelta(seconds=20)
    assert d.record_reserve == timedelta(seconds=2)
    assert d.input_max_bytes == 1048576
    assert d.script_env_allow == ["PATH", "HOME", "LANG", "LC_*"]
    assert (d.recommend.confidence, d.recommend.max_miss_rate) == (0.95, 0.05)
    a = s.agent
    assert a.skill == "gatectl:gate-check"
    assert a.plugin_dirs == []
    assert (a.model, a.permission_profile) == (None, None)
    assert a.sandbox == "required"
    assert (a.setting_sources, a.env_allowlist) == ([], [])
    assert a.threshold == 0.8
    assert a.timeout == timedelta(seconds=300)
    assert a.cache_ttl == timedelta(minutes=10)
    assert a.max_parallel == 3
    assert a.min_start_budget == timedelta(seconds=30)
    assert a.input_max_bytes == 65536
    assert s.retention.older_than is None
    assert (s.hooks.post_decision, s.hooks.post_outcome, s.hooks.post_state_change) == ([], [], [])
    assert c.policies == {}


def test_policy_defaults(tmp_path: Path) -> None:
    p = _policy(tmp_path).policies["p"].policy
    assert p is not None
    assert p.state == "shadow"
    assert p.record_input is False
    assert (p.timeout, p.cache_ttl, p.applies_when, p.input) == (None, None, None, None)
    # an unset recommend resolves to defaults.recommend
    assert (p.recommend.confidence, p.recommend.max_miss_rate) == (0.95, 0.05)
    check = p.checks[0]
    assert check.type == "rule"
    assert check.else_ == "allow"


def test_hook_entry_defaults(tmp_path: Path) -> None:
    c = load(tmp_path, {"hooks": {"post-outcome": [{"cmd": "x"}]}})
    h = c.shared.hooks.post_outcome[0]
    assert (h.cmd, h.timeout, h.async_) == ("x", timedelta(seconds=30), False)


# --- ranges: both sides of each boundary ----------------------------------------------------

D = "duration"
RANGES: list[tuple[str, str, list[Any], list[Any]]] = [
    # (section, key, accepted, rejected)
    (
        "defaults",
        "timeout",
        ["1ms", "86400s", "1d", "1440m", "24h"],
        [
            "0",
            0,
            "0s",
            "86401s",
            "2d",
            "1441m",
            "-1s",
            "1.5s",
            "10",
            "s",
            "",
            True,
            None,
            1,
            1.5,
            [],
            {},
        ],
    ),
    ("defaults", "script_timeout", ["1ms", "1d", "999d"], ["0", 0, "0ms", "1", True, None]),
    (
        "defaults",
        "record_reserve",
        ["100ms", "60s", "1m", "101ms"],
        ["99ms", "61s", "61000ms", "0", 0, "1h"],
    ),
    (
        "defaults",
        "input_max_bytes",
        [1, 16777216, 1048576],
        [0, -1, 16777217, "1", 1.5, True, None, 10**30],
    ),
    ("agent", "timeout", ["1ms", "300s"], ["0", 0, "0s", True]),
    (
        "agent",
        "cache_ttl",
        [0, "0", "0s", "1ms", "10m", "999d"],
        ["-1s", "1.5m", True, None, 1, "10"],
    ),
    ("agent", "max_parallel", [1, 32, 3], [0, 33, -1, "3", 1.5, 3.0, True]),
    ("agent", "min_start_budget", ["1s", "1000ms", "2s"], ["999ms", "0", 0, "0s"]),
    (
        "agent",
        "threshold",
        [0, 1, 0.5, 0.0, 1.0, 0.0001, 0.9999],
        [-0.0001, 1.0001, 2, "0.5", True, None],
    ),
    ("agent", "input_max_bytes", [1024, 1048576], [1023, 1048577, 0, "2048", True]),
    ("retention", "older_than", [None, "1ms", "30d"], ["0", 0, "0s", "-1d", True, "x"]),
]


@pytest.mark.parametrize(("section", "key", "good", "bad"), RANGES)
def test_range_boundaries_accepted(
    tmp_path: Path, section: str, key: str, good: list[Any], bad: list[Any]
) -> None:
    for value in good:
        c = _shared(tmp_path, section, key, value)
        assert c.shared_problems == (), (section, key, value)


@pytest.mark.parametrize(("section", "key", "good", "bad"), RANGES)
def test_range_boundaries_rejected_with_default_fallback(
    tmp_path: Path, section: str, key: str, good: list[Any], bad: list[Any]
) -> None:
    default = getattr(getattr(load(tmp_path, {}).shared, section), key)
    for value in bad:
        c = _shared(tmp_path, section, key, value)
        assert _codes(c.shared_problems) == [("invalid_value", f"{section}.{key}")], (key, value)
        assert getattr(getattr(c.shared, section), key) == default
        with pytest.raises(errors.ConfigInvalidError) as info:
            c.require_valid_shared()
        assert f"{section}.{key}" in info.value.message


@pytest.mark.parametrize(
    ("key", "good", "bad"),
    [
        ("confidence", [0.0001, 0.5, 0.9999], [0, 0.0, 1, 1.0, -1, 1.5, "0.5", True]),
        ("max_miss_rate", [0.0001, 0.5, 1, 1.0], [0, 0.0, 1.0001, -0.1, "0.5", True]),
    ],
)
def test_recommend_ranges_in_defaults_and_in_a_policy(
    tmp_path: Path, key: str, good: list[Any], bad: list[Any]
) -> None:
    for value in good:
        assert load(tmp_path, {"defaults": {"recommend": {key: value}}}).shared_problems == ()
        assert _policy(tmp_path, recommend={key: value}).policies["p"].problems == ()
    for value in bad:
        c = load(tmp_path, {"defaults": {"recommend": {key: value}}})
        assert _codes(c.shared_problems) == [("invalid_value", f"defaults.recommend.{key}")]
        pc = _policy(tmp_path, recommend={key: value})
        assert _codes(pc.policies["p"].problems) == [
            ("invalid_value", f"policies.p.recommend.{key}")
        ]


def test_recommend_missing_subkey_takes_defaults_recommend(tmp_path: Path) -> None:
    c = load(
        tmp_path,
        {
            "defaults": {"recommend": {"confidence": 0.9, "max_miss_rate": 0.1}},
            "policies": {"p": good_policy(recommend={"confidence": 0.99})},
        },
    )
    rec = c.resolve_policy("p").recommend
    assert (rec.confidence, rec.max_miss_rate) == (0.99, 0.1)


def test_policy_timeout_range(tmp_path: Path) -> None:
    for value in ("1ms", "86400s", "1d"):
        assert _policy(tmp_path, timeout=value).policies["p"].problems == ()
    for value in ("0", 0, "86401s", "2d", "-1s", True, "1.5s"):
        c = _policy(tmp_path, timeout=value)
        assert _codes(c.policies["p"].problems) == [("invalid_value", "policies.p.timeout")]
        assert c.shared_problems == ()


def test_policy_cache_ttl_zero_is_off_and_garbage_is_rejected(tmp_path: Path) -> None:
    for value in (0, "0", "0s", "5m"):
        assert _policy(tmp_path, cache_ttl=value).policies["p"].problems == ()
    for value in ("-1m", "x", True, 1.5):
        c = _policy(tmp_path, cache_ttl=value)
        assert _codes(c.policies["p"].problems) == [("invalid_value", "policies.p.cache_ttl")]


def _script(**kw: Any) -> dict[str, Any]:
    return {"name": "s", "type": "script", "argv": ["/bin/true"], **kw}


def _agent(**kw: Any) -> dict[str, Any]:
    return {"name": "a", "type": "agent", "instruction": "do it", **kw}


@pytest.mark.parametrize("make", [_script, _agent])
def test_check_timeout_and_cache_ttl_ranges(tmp_path: Path, make: Any) -> None:
    for value in ("1ms", "999d"):
        assert _check(tmp_path, make(timeout=value)).policies["p"].problems == ()
    for value in ("0", 0, "0s", "-1s", True):
        c = _check(tmp_path, make(timeout=value))
        assert _codes(c.policies["p"].problems) == [
            ("invalid_value", "policies.p.checks.0.timeout")
        ]
    assert (
        _check(tmp_path, make(cache_ttl=0)).policies["p"].problems == () if make is _agent else True
    )


def test_agent_check_threshold_range(tmp_path: Path) -> None:
    for value in (0, 1, 0.5):
        assert _check(tmp_path, _agent(threshold=value)).policies["p"].problems == ()
    for value in (-0.01, 1.01, "0.5", True):
        c = _check(tmp_path, _agent(threshold=value))
        assert _codes(c.policies["p"].problems) == [
            ("invalid_value", "policies.p.checks.0.threshold")
        ]


def test_agent_check_cache_ttl_range(tmp_path: Path) -> None:
    assert _check(tmp_path, _agent(cache_ttl=0)).policies["p"].problems == ()
    c = _check(tmp_path, _agent(cache_ttl="-1s"))
    assert _codes(c.policies["p"].problems) == [("invalid_value", "policies.p.checks.0.cache_ttl")]


def test_hook_timeout_range(tmp_path: Path) -> None:
    ok = load(tmp_path, {"hooks": {"post-decision": [{"cmd": "x", "timeout": "1ms"}]}})
    assert ok.shared_problems == ()
    for value in ("0", 0, "0s", True, "x"):
        c = load(tmp_path, {"hooks": {"post-decision": [{"cmd": "x", "timeout": value}]}})
        assert [p.path for p in c.shared_problems] == ["hooks.post-decision.0.timeout"]


def test_input_ignore_may_not_name_repo(tmp_path: Path) -> None:
    ok = _policy(tmp_path, input={"ignore": ["event_id", "Repo", "repository"]})
    assert ok.policies["p"].problems == ()
    c = _policy(tmp_path, input={"ignore": ["event_id", "repo"]})
    (problem,) = c.policies["p"].problems
    assert (problem.code, problem.path) == ("invalid_value", "policies.p.input.ignore.1")
    assert "repo" in problem.message
    # an override too
    c2 = load(
        tmp_path,
        {
            "policies": {"p": good_policy()},
            "repos": {"github.com/o/r": {"policies": {"p": {"input": {"ignore": ["repo"]}}}}},
        },
    )
    assert c2.overrides[("github.com/o/r", "p")].problems[0].code == "invalid_value"


# --- shared keys: value rules ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("section", "key", "good", "bad"),
    [
        (
            "me",
            "name",
            [None, "alice", "a.b_c-d@e", "x" * 64, "", "x" * 1024, "a b", "a/b", "é"],
            ["x" * 1025, 5, ["a"], True],
        ),
        (
            "defaults",
            "script_env_allow",
            [[], ["PATH", "LC_*", "_X1"]],
            [["*"], ["A-B"], ["PATH", "PATH"], "PATH", [1], ["1A"], ["A*B"]],
        ),
        (
            "agent",
            "skill",
            ["a:b", "gatectl:gate-check", "x1:y_z"],
            ["bare", "A:b", "a:", ":b", "a:b:c", "a b:c", "", 5, "a:b\n"],
        ),
        (
            "agent",
            "plugin_dirs",
            [[], ["/a", "/b/c"]],
            [["rel"], [""], "/a", [1], ["/a\n" if False else "x/y"]],
        ),
        ("agent", "model", [None, "haiku"], ["", 5]),
        ("agent", "permission_profile", [None, "/etc/p.json"], ["p.json", "", 5]),
        ("agent", "sandbox", ["required", "preferred", "off"], ["on", "REQUIRED", "", None, True]),
        (
            "agent",
            "setting_sources",
            [[], ["user"], ["user", "project", "local"]],
            [["other"], ["user", "user"], "user", [1]],
        ),
        ("agent", "env_allowlist", [[], ["A", "B_1"]], [["A*"], ["A", "A"], ["1A"], "A"]),
    ],
)
def test_shared_value_rules(
    tmp_path: Path, section: str, key: str, good: list[Any], bad: list[Any]
) -> None:
    for value in good:
        assert _shared(tmp_path, section, key, value).shared_problems == (), (key, value)
    for value in bad:
        c = _shared(tmp_path, section, key, value)
        assert len(c.shared_problems) >= 1, (key, value)
        assert all(p.path.startswith(f"{section}.{key}") for p in c.shared_problems)


def test_bare_skill_name_has_its_own_code(tmp_path: Path) -> None:
    c = _shared(tmp_path, "agent", "skill", "gate-check")
    assert _codes(c.shared_problems) == [("bare_skill_name", "agent.skill")]
    c = _check(tmp_path, _agent(skill="review"))
    assert _codes(c.policies["p"].problems) == [("bare_skill_name", "policies.p.checks.0.skill")]


def test_invalid_leaf_falls_back_but_valid_siblings_survive(tmp_path: Path) -> None:
    c = load(tmp_path, {"defaults": {"timeout": "5s", "script_timeout": "bogus"}})
    assert c.shared.defaults.timeout == timedelta(seconds=5)
    assert c.shared.defaults.script_timeout == timedelta(seconds=20)
    assert _codes(c.shared_problems) == [("invalid_value", "defaults.script_timeout")]


def test_session_cmd_shapes(tmp_path: Path) -> None:
    for good in (["claude-session"], ["/opt/x/cs", "--flag"], ["cs", "a", "b"]):
        assert load(tmp_path, {"session_cmd": good}).shared_problems == ()
    for bad in (
        [],
        "claude-session",
        [""],
        [1],
        ["bin/cs"],
        ["./cs"],
        ["../cs"],
        ["a/b/c"],
        ["cs", ""],
    ):
        c = load(tmp_path, {"session_cmd": bad})
        assert [p.path.split(".")[0] for p in c.shared_problems] == ["session_cmd"], bad
        assert c.shared.session_cmd == ["claude-session"]


def test_unknown_keys_are_named(tmp_path: Path) -> None:
    c = load(
        tmp_path,
        {
            "bogus": 1,
            "me": {"nme": "x"},
            "defaults": {"timeuot": "1s", "recommend": {"conf": 1}},
            "agent": {"x": 1},
            "retention": {"x": 1},
            "hooks": {"post-decison": []},
        },
    )
    got = sorted(_codes(c.shared_problems))
    assert got == sorted(
        [
            ("unknown_key", "bogus"),
            ("unknown_key", "me.nme"),
            ("unknown_key", "defaults.timeuot"),
            ("unknown_key", "defaults.recommend.conf"),
            ("unknown_key", "agent.x"),
            ("unknown_key", "retention.x"),
            ("unknown_key", "hooks.post-decison"),
        ]
    )


@pytest.mark.parametrize("section", ["me", "defaults", "agent", "retention", "hooks"])
@pytest.mark.parametrize("value", [None, 5, "str", [], [1]])
def test_section_of_the_wrong_type_is_a_shared_problem(
    tmp_path: Path, section: str, value: Any
) -> None:
    c = load(tmp_path, {section: value})
    assert [p.path for p in c.shared_problems] == [section]


def test_hook_entry_shapes(tmp_path: Path) -> None:
    good = {"hooks": {"post-decision": [{"cmd": "a b", "timeout": "5s", "async": True}]}}
    assert load(tmp_path, good).shared_problems == ()
    for entry in (
        {},
        {"cmd": ""},
        {"cmd": 5},
        {"cmd": "x", "async": "yes"},
        {"cmd": "x", "z": 1},
        "x",
    ):
        c = load(tmp_path, {"hooks": {"post-decision": [entry]}})
        assert c.shared_problems, entry
    c = load(tmp_path, {"hooks": {"post-decision": {"cmd": "x"}}})
    assert [p.path for p in c.shared_problems] == ["hooks.post-decision"]


# --- policies ------------------------------------------------------------------------------


def test_policy_state_values(tmp_path: Path) -> None:
    for state in ("off", "shadow"):
        assert _policy(tmp_path, state=state).policies["p"].problems == ()
    c = _policy(tmp_path, state="enforced")
    (problem,) = c.policies["p"].problems
    assert (problem.code, problem.path) == ("invalid_value", "policies.p.state")
    assert "gatectl set" in problem.message
    for bad in ("on", "", None, True, "Shadow"):
        (problem,) = _policy(tmp_path, state=bad).policies["p"].problems
        assert problem.path == "policies.p.state"
        assert "gatectl set" not in problem.message


def test_policy_unknown_keys_empty_checks_and_missing_checks(tmp_path: Path) -> None:
    c = load(tmp_path, {"policies": {"p": {**good_policy(), "bogus": 1}}})
    assert _codes(c.policies["p"].problems) == [("unknown_key", "policies.p.bogus")]
    for checks in ([], None, "x", {}):
        c = load(tmp_path, {"policies": {"p": {"checks": checks}}})
        assert c.policies["p"].policy is None
        assert c.policies["p"].problems[0].path.startswith("policies.p.checks")
    c = load(tmp_path, {"policies": {"p": {"timeout": "5s"}}})
    assert _codes(c.policies["p"].problems) == [("invalid_value", "policies.p.checks")]


def test_duplicate_check_names(tmp_path: Path) -> None:
    rule = good_policy()["checks"][0]
    c = load(tmp_path, {"policies": {"p": {"checks": [rule, _script(name="x"), {**rule}]}}})
    assert _codes(c.policies["p"].problems) == [("invalid_value", "policies.p.checks.2.name")]
    c = load(tmp_path, {"policies": {"p": {"checks": [rule, {**rule, "name": "r2"}]}}})
    assert c.policies["p"].problems == ()


def test_unknown_or_missing_check_type(tmp_path: Path) -> None:
    for check in (
        {"name": "x", "type": "shell", "argv": ["/a"]},
        {"name": "x"},
        {"name": "x", "type": 5},
        {"name": "x", "type": ["rule"]},
        "x",
        5,
        None,
    ):
        c = load(tmp_path, {"policies": {"p": {"checks": [check]}}})
        (problem,) = c.policies["p"].problems
        assert problem.code == "invalid_value"
        assert problem.path.startswith("policies.p.checks.0")
        assert c.shared_problems == ()


@pytest.mark.parametrize("name", ["", "A", "-a", "a b", "x" * 65, "a.b", "a\n", 5, None, "é"])
def test_check_name_grammar(tmp_path: Path, name: Any) -> None:
    c = _check(tmp_path, _script(name=name))
    assert [p.path for p in c.policies["p"].problems] == ["policies.p.checks.0.name"]


@pytest.mark.parametrize("name", ["a", "a" * 64, "0", "a_b-c"])
def test_check_name_grammar_accepts(tmp_path: Path, name: str) -> None:
    assert _check(tmp_path, _script(name=name)).policies["p"].problems == ()


def test_script_check_rules(tmp_path: Path) -> None:
    ok = _check(tmp_path, _script(argv=["/usr/bin/x", "rel/path", "-v"], env_allow=["A", "B"]))
    assert ok.policies["p"].problems == ()
    bad: list[tuple[dict[str, Any], str]] = [
        (_script(argv=["relative"]), "policies.p.checks.0.argv.0"),
        (_script(argv=["./x"]), "policies.p.checks.0.argv.0"),
        (_script(argv="/bin/true"), "policies.p.checks.0.argv"),
        (_script(argv=[]), "policies.p.checks.0.argv"),
        (_script(argv=["/a", ""]), "policies.p.checks.0.argv.1"),
        (_script(argv=["/a", 5]), "policies.p.checks.0.argv.1"),
        (_script(env_allow=["A*"]), "policies.p.checks.0.env_allow.0"),
        (_script(env_allow=["A", "A"]), "policies.p.checks.0.env_allow"),
        (_script(env_allow="A"), "policies.p.checks.0.env_allow"),
        (_script(extra=1), "policies.p.checks.0.extra"),
        ({"name": "s", "type": "script"}, "policies.p.checks.0.argv"),
        (_script(instruction="x"), "policies.p.checks.0.instruction"),
    ]
    for check, path in bad:
        c = _check(tmp_path, check)
        assert path in [p.path for p in c.policies["p"].problems], check
        assert c.shared_problems == ()


def test_agent_check_rules(tmp_path: Path) -> None:
    full = _agent(
        skill="p:s",
        model="haiku",
        threshold=0.9,
        timeout="1m",
        cache_ttl="5m",
        permission_profile="/x/p",
        sandbox="preferred",
        setting_sources=[],
        env_allowlist=["A"],
    )
    assert _check(tmp_path, full).policies["p"].problems == ()
    assert (
        _check(tmp_path, {"name": "a", "type": "agent", "instruction_file": "/etc/i.md"})
        .policies["p"]
        .problems
        == ()
    )
    bad: list[tuple[dict[str, Any], str]] = [
        ({"name": "a", "type": "agent"}, "policies.p.checks.0"),
        (_agent(instruction_file="/x"), "policies.p.checks.0"),
        (
            {"name": "a", "type": "agent", "instruction_file": "rel.md"},
            "policies.p.checks.0.instruction_file",
        ),
        (_agent(instruction=""), "policies.p.checks.0.instruction"),
        (_agent(instruction=5), "policies.p.checks.0.instruction"),
        (_agent(sandbox="x"), "policies.p.checks.0.sandbox"),
        (_agent(setting_sources=["x"]), "policies.p.checks.0.setting_sources.0"),
        (_agent(env_allowlist=["A*"]), "policies.p.checks.0.env_allowlist.0"),
        (_agent(permission_profile="rel"), "policies.p.checks.0.permission_profile"),
        (_agent(model=""), "policies.p.checks.0.model"),
        (_agent(argv=["/a"]), "policies.p.checks.0.argv"),
    ]
    for check, path in bad:
        c = _check(tmp_path, check)
        assert any(p.path.startswith(path) for p in c.policies["p"].problems), check


def test_policy_names(tmp_path: Path) -> None:
    for name in ("a", "a" * 64, "0a", "a_b-c"):
        assert load(tmp_path, {"policies": {name: good_policy()}}).policies[name].problems == ()
    for name in ("", "A", "-a", "a" * 65, "a b", "a.b", "é"):
        c = load(tmp_path, {"policies": {name: good_policy()}})
        assert len(c.policies) == 1
        (entry,) = c.policies.values()
        assert entry.policy is None
        assert entry.problems[0].code == "invalid_value"
        assert c.shared_problems == ()


def test_policies_of_the_wrong_type_is_a_shared_problem(tmp_path: Path) -> None:
    for value in (5, [], "x", None):
        c = load(tmp_path, {"policies": value})
        assert [p.path for p in c.shared_problems] == ["policies"]
        assert c.policies == {}


def test_policy_body_of_the_wrong_type(tmp_path: Path) -> None:
    for value in (5, [], "x", None):
        c = load(tmp_path, {"policies": {"p": value}})
        assert [p.path for p in c.policies["p"].problems] == ["policies.p"]


def test_applies_when_and_input_shapes(tmp_path: Path) -> None:
    cond = {"path": "a.b", "op": "eq", "value": 1}
    full = {
        "applies_when": [cond],
        "input": {"require": ["a"], "types": {"a": "string", "b": "integer?"}, "ignore": ["t"]},
        "record_input": True,
    }
    assert _policy(tmp_path, **full).policies["p"].problems == ()
    for key, value, path in [
        ("applies_when", [], "policies.p.applies_when"),
        ("applies_when", "x", "policies.p.applies_when"),
        ("input", {"require": ["a", "a"]}, "policies.p.input.require"),
        ("input", {"require": [""]}, "policies.p.input.require.0"),
        ("input", {"types": {"a": "str"}}, "policies.p.input.types.a"),
        ("input", {"types": {"a": "string??"}}, "policies.p.input.types.a"),
        ("input", {"types": {"": "string"}}, "policies.p.input.types"),
        ("input", {"x": 1}, "policies.p.input.x"),
        ("input", {"ignore": ["a", "a"]}, "policies.p.input.ignore"),
        ("record_input", "yes", "policies.p.record_input"),
        ("record_input", 1, "policies.p.record_input"),
    ]:
        c = _policy(tmp_path, **{key: value})
        assert any(p.path.startswith(path) for p in c.policies["p"].problems), (key, value)


def test_input_types_cover_every_type_name(tmp_path: Path) -> None:
    types = {
        f"k{i}{q}": t + q
        for i, t in enumerate(("string", "integer", "number", "boolean", "object", "array"))
        for q in ("", "?")
    }
    assert _policy(tmp_path, input={"types": types}).policies["p"].problems == ()


# --- rule checks ---------------------------------------------------------------------------


def _rule(*when: Any, **kw: Any) -> dict[str, Any]:
    return {"name": "r", "type": "rule", "when": list(when), "then": "deny", **kw}


VALUE_OPS = ["eq", "ne", "in", "not_in", "lt", "le", "gt", "ge", "glob"]
SAMPLE = {
    "eq": "x",
    "ne": 1,
    "in": ["a", None],
    "not_in": [1],
    "lt": 1,
    "le": 2.5,
    "gt": -1,
    "ge": 0,
    "glob": "a*",
}


@pytest.mark.parametrize("op", VALUE_OPS)
def test_value_is_required_for_comparison_operators(tmp_path: Path, op: str) -> None:
    ok = _check(tmp_path, _rule({"path": "a", "op": op, "value": SAMPLE[op]}))
    assert ok.policies["p"].problems == ()
    c = _check(tmp_path, _rule({"path": "a", "op": op}))
    (problem,) = c.policies["p"].problems
    assert (problem.code, problem.path) == ("invalid_rule", "policies.p.checks.0.when.0.value")


@pytest.mark.parametrize("op", ["exists", "absent"])
def test_value_is_forbidden_for_exists_and_absent(tmp_path: Path, op: str) -> None:
    assert _check(tmp_path, _rule({"path": "a", "op": op})).policies["p"].problems == ()
    for value in (None, 1, "x", [], False):
        c = _check(tmp_path, _rule({"path": "a", "op": op, "value": value}))
        (problem,) = c.policies["p"].problems
        assert (problem.code, problem.path) == ("invalid_rule", "policies.p.checks.0.when.0.value")


def test_eq_ne_accept_null_and_structured_values(tmp_path: Path) -> None:
    for op in ("eq", "ne"):
        for value in (None, [1, {"a": None}], {"k": [1]}, True, 1.5, "s"):
            c = _check(tmp_path, _rule({"path": "a", "op": op, "value": value}))
            assert c.policies["p"].problems == (), value


@pytest.mark.parametrize(
    ("op", "value"),
    [
        ("in", "x"),
        ("in", [[1]]),
        ("in", [{"a": 1}]),
        ("in", None),
        ("not_in", {"a": 1}),
        ("not_in", 5),
        ("lt", "1"),
        ("lt", True),
        ("lt", None),
        ("gt", [1]),
        ("ge", False),
        ("le", {}),
        ("glob", 5),
        ("glob", ""),
        ("glob", None),
        ("glob", ["a"]),
    ],
)
def test_value_types_per_operator(tmp_path: Path, op: str, value: Any) -> None:
    c = _check(tmp_path, _rule({"path": "a", "op": op, "value": value}))
    (problem,) = c.policies["p"].problems
    assert problem.code == "invalid_rule"
    assert problem.path == "policies.p.checks.0.when.0.value"


@pytest.mark.parametrize(
    "path", ["", ".", "a.", ".a", "a..b", "a b", "a.b!", "a\n", "é", "a/b", "$.a", 5, None]
)
def test_condition_path_grammar_rejects(tmp_path: Path, path: Any) -> None:
    c = _check(tmp_path, _rule({"path": path, "op": "exists"}))
    (problem,) = c.policies["p"].problems
    assert (problem.code, problem.path) == ("invalid_rule", "policies.p.checks.0.when.0.path")


@pytest.mark.parametrize("path", ["a", "a.b.0.c", "A-b_c.0", "0"])
def test_condition_path_grammar_accepts(tmp_path: Path, path: str) -> None:
    assert _check(tmp_path, _rule({"path": path, "op": "exists"})).policies["p"].problems == ()


def test_unknown_operator_and_condition_shapes(tmp_path: Path) -> None:
    for cond in (
        {"path": "a", "op": "regex", "value": "x"},
        {"path": "a", "op": 5},
        {"path": "a"},
        {"op": "exists"},
        "a",
        [],
        {"path": "a", "op": "exists", "x": 1},
    ):
        c = _check(tmp_path, _rule(cond))
        assert c.policies["p"].problems, cond
        assert all(p.code in ("invalid_rule", "unknown_key") for p in c.policies["p"].problems)


def test_rule_then_else_and_when(tmp_path: Path) -> None:
    cond = {"path": "a", "op": "exists"}
    for verdict in ("allow", "deny", "escalate"):
        assert (
            _check(tmp_path, _rule(cond, **{"else": verdict, "then": verdict}))
            .policies["p"]
            .problems
            == ()
        )
    for key in ("then", "else"):
        for bad in ("skipped", "ALLOW", "", None, 5, True):
            c = _check(tmp_path, _rule(cond, **{key: bad}))
            (problem,) = c.policies["p"].problems
            assert (problem.code, problem.path) == ("invalid_rule", f"policies.p.checks.0.{key}")
    c = _check(tmp_path, {"name": "r", "type": "rule", "when": [cond]})
    assert _codes(c.policies["p"].problems) == [("invalid_rule", "policies.p.checks.0.then")]
    c = _check(tmp_path, _rule())  # empty when
    assert _codes(c.policies["p"].problems) == [("invalid_rule", "policies.p.checks.0.when")]
    c = _check(tmp_path, {"name": "r", "type": "rule", "then": "deny"})
    assert _codes(c.policies["p"].problems) == [("invalid_rule", "policies.p.checks.0.when")]


def test_applies_when_conditions_follow_the_same_rules(tmp_path: Path) -> None:
    c = _policy(tmp_path, applies_when=[{"path": "a", "op": "eq"}])
    assert _codes(c.policies["p"].problems) == [("invalid_rule", "policies.p.applies_when.0.value")]


def test_glob_length_cap_is_exact(tmp_path: Path) -> None:
    ok = _check(tmp_path, _rule({"path": "a", "op": "glob", "value": "a" * 128}))
    assert ok.policies["p"].problems == ()
    c = _check(tmp_path, _rule({"path": "a", "op": "glob", "value": "a" * 129}))
    assert _codes(c.policies["p"].problems) == [
        ("glob_too_long", "policies.p.checks.0.when.0.value")
    ]
    c = _policy(tmp_path, applies_when=[{"path": "a", "op": "glob", "value": "*" * 129}])
    assert [p.code for p in c.policies["p"].problems] == ["glob_too_long"]


def test_glob_is_tokenized_once_at_load(tmp_path: Path) -> None:
    def tokens(pattern: str) -> tuple[str, ...]:
        c = _check(tmp_path, _rule({"path": "a", "op": "glob", "value": pattern}))
        policy = c.policies["p"].policy
        assert policy is not None
        cond = policy.checks[0].when[0]  # type: ignore[union-attr]
        assert cond.glob_tokens is not None
        return cond.glob_tokens

    assert tokens("a*b") == ("a", "*", "b")
    assert tokens("pr=**") == ("p", "r", "=", "**")
    assert tokens("a?c") == ("a", "?", "c")
    assert tokens("***") == ("**",)  # a run of three or more stars is one `**`
    assert tokens("a**b*c") == ("a", "**", "b", "*", "c")
    assert tokens("[a-z]\\.+(x)|{y}") == tuple("[a-z]\\.+(x)|{y}")  # no other metacharacters
    assert tokens("é*日") == ("é", "*", "日")
    ok = _check(tmp_path, _rule({"path": "a", "op": "eq", "value": "a*"}))
    policy = ok.policies["p"].policy
    assert policy is not None and policy.checks[0].when[0].glob_tokens is None  # type: ignore[union-attr]


# --- messages never echo config values ------------------------------------------------------


def test_messages_never_echo_values(tmp_path: Path) -> None:
    c = load(
        tmp_path,
        {
            "me": {"name": CANARY + "!" * 1100},
            "defaults": {
                "timeout": CANARY,
                "input_max_bytes": CANARY,
                "script_env_allow": [CANARY],
            },
            "agent": {"sandbox": CANARY, "skill": CANARY, "threshold": CANARY},
            "session_cmd": [CANARY + "/x"],
            "retention": {"older_than": CANARY},
            "hooks": {"post-decision": [{"cmd": 5, "timeout": CANARY}]},
            "policies": {
                "p": {
                    "state": CANARY,
                    "timeout": CANARY,
                    "checks": [
                        {"name": CANARY, "type": CANARY},
                        _script(argv=[CANARY]),
                        _rule({"path": CANARY, "op": CANARY}),
                        _rule({"path": "a", "op": "glob", "value": CANARY * 20}),
                        _agent(sandbox=CANARY, skill=CANARY, instruction=5),
                    ],
                    "input": {"types": {"a": CANARY}},
                }
            },
        },
    )
    problems = [*c.shared_problems, *c.policies["p"].problems]
    assert len(problems) >= 15
    for problem in problems:
        assert CANARY not in problem.message
        assert CANARY not in problem.path
    with pytest.raises(errors.ConfigInvalidError) as info:
        c.require_valid_shared()
    assert CANARY not in repr(errors.envelope(info.value))
    with pytest.raises(errors.ConfigInvalidError) as info:
        c.resolve_policy("p")
    assert CANARY not in repr(errors.envelope(info.value))


def test_unknown_key_names_are_sanitized_and_capped_in_paths(tmp_path: Path) -> None:
    nasty = "bad\x1b[31m\nkey" + "k" * 500
    c = load(tmp_path, {"defaults": {nasty: 1}, "policies": {"p": {**good_policy(), nasty: 1}}})
    (shared,) = c.shared_problems
    (pol,) = c.policies["p"].problems
    for problem in (shared, pol):
        assert "\x1b" not in problem.path and "\n" not in problem.path
        assert "�" in problem.path
        assert len(problem.path) < 300
        assert "\x1b" not in problem.message


def test_problem_as_dict_matches_the_problem_schema(tmp_path: Path) -> None:
    import json

    from jsonschema import Draft202012Validator

    defs = json.loads((schema_util.SCHEMAS / "defs.json").read_text(encoding="utf-8"))
    validator = Draft202012Validator(defs["$defs"]["problem"])
    c = load(tmp_path, {"defaults": {"timeout": "x"}, "bogus": 1})
    assert len(c.shared_problems) == 2
    for problem in c.shared_problems:
        assert not list(validator.iter_errors(problem.as_dict()))
