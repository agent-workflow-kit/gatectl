"""Environment overrides: the listed keys only, GATECTL_<KEY> with `__` (interface.md)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from gatectl.config import ENV_KEYS
from tests.config_util import load

CANARY = "SECRET-CANARY-5d1e"

LISTED = [
    "defaults.timeout",
    "defaults.script_timeout",
    "defaults.record_reserve",
    "agent.timeout",
    "agent.cache_ttl",
    "agent.max_parallel",
    "agent.min_start_budget",
    "retention.older_than",
]


def _name(key: str) -> str:
    return "GATECTL_" + key.upper().replace(".", "__")


def test_the_listed_keys_are_exactly_the_documented_ones() -> None:
    assert sorted(ENV_KEYS) == sorted(LISTED)


def test_listed_keys_apply(tmp_path: Path) -> None:
    env = {
        "GATECTL_DEFAULTS__TIMEOUT": "5s",
        "GATECTL_DEFAULTS__SCRIPT_TIMEOUT": "6s",
        "GATECTL_DEFAULTS__RECORD_RESERVE": "500ms",
        "GATECTL_AGENT__TIMEOUT": "7m",
        "GATECTL_AGENT__CACHE_TTL": "0",
        "GATECTL_AGENT__MAX_PARALLEL": "9",
        "GATECTL_AGENT__MIN_START_BUDGET": "2s",
        "GATECTL_RETENTION__OLDER_THAN": "30d",
    }
    c = load(tmp_path, {}, environ=env)
    assert c.shared_problems == ()
    s = c.shared
    assert s.defaults.timeout == timedelta(seconds=5)
    assert s.defaults.script_timeout == timedelta(seconds=6)
    assert s.defaults.record_reserve == timedelta(milliseconds=500)
    assert s.agent.timeout == timedelta(minutes=7)
    assert s.agent.cache_ttl == timedelta(0)
    assert s.agent.max_parallel == 9
    assert s.agent.min_start_budget == timedelta(seconds=2)
    assert s.retention.older_than == timedelta(days=30)


def test_environment_beats_the_file_and_drop_ins(tmp_path: Path) -> None:
    c = load(
        tmp_path,
        {"defaults": {"timeout": "1s"}},
        dropins={"10.yaml": {"defaults": {"timeout": "2s"}}},
        environ={"GATECTL_DEFAULTS__TIMEOUT": "3s"},
    )
    assert c.shared.defaults.timeout == timedelta(seconds=3)


def test_older_than_can_be_set_back_to_null(tmp_path: Path) -> None:
    c = load(
        tmp_path,
        {"retention": {"older_than": "1d"}},
        environ={"GATECTL_RETENTION__OLDER_THAN": "null"},
    )
    assert c.shared.retention.older_than is None


@pytest.mark.parametrize("key", LISTED)
@pytest.mark.parametrize(
    "value",
    [
        "",
        " 5s",
        "5s ",
        "5s\n",
        "5s; rm -rf /",
        "-1",
        "1e3",
        "0x10",
        "٣s",
        "5" * 10_000,
        CANARY,
        "\x00",
        "5s\x00",
        "true",
        "0",
        "null ",
    ],
)
def test_hostile_values_are_problems_not_applied(tmp_path: Path, key: str, value: str) -> None:
    if value == "0" and key in ("agent.cache_ttl",):
        pytest.skip("0 is valid for cache_ttl")
    name = _name(key)
    c = load(tmp_path, {}, environ={name: value})
    assert [(p.code, p.path) for p in c.shared_problems] == [("invalid_value", key)], (key, value)
    (problem,) = c.shared_problems
    assert name in problem.message
    assert CANARY not in problem.message
    # the file/default value survives
    base = load(tmp_path, {})
    section, leaf = key.split(".")
    assert getattr(getattr(c.shared, section), leaf) == getattr(getattr(base.shared, section), leaf)


def test_bad_env_value_falls_back_to_the_file_value(tmp_path: Path) -> None:
    c = load(tmp_path, {"defaults": {"timeout": "9s"}}, environ={"GATECTL_DEFAULTS__TIMEOUT": "x"})
    assert c.shared.defaults.timeout == timedelta(seconds=9)
    assert len(c.shared_problems) == 1


@pytest.mark.parametrize("value", ["1", "32", "007"])
def test_max_parallel_accepts_plain_integers(tmp_path: Path, value: str) -> None:
    c = load(tmp_path, {}, environ={"GATECTL_AGENT__MAX_PARALLEL": value})
    assert c.shared_problems == ()
    assert c.shared.agent.max_parallel == int(value)


@pytest.mark.parametrize("value", ["0", "33", "3.0", "+3", "-3", "1_0", "३"])
def test_max_parallel_rejects(tmp_path: Path, value: str) -> None:
    c = load(tmp_path, {}, environ={"GATECTL_AGENT__MAX_PARALLEL": value})
    assert [p.path for p in c.shared_problems] == ["agent.max_parallel"]
    assert c.shared.agent.max_parallel == 3


SAFETY = [
    "GATECTL_AGENT__SANDBOX",
    "GATECTL_AGENT__PERMISSION_PROFILE",
    "GATECTL_AGENT__SETTING_SOURCES",
    "GATECTL_AGENT__ENV_ALLOWLIST",
    "GATECTL_AGENT__THRESHOLD",
    "GATECTL_AGENT__MODEL",
    "GATECTL_AGENT__INPUT_MAX_BYTES",
    "GATECTL_DEFAULTS__INPUT_MAX_BYTES",
]
LISTS_AND_STRUCTURED = [
    "GATECTL_DEFAULTS__SCRIPT_ENV_ALLOW",
    "GATECTL_AGENT__PLUGIN_DIRS",
    "GATECTL_AGENT__SKILL",
    "GATECTL_SESSION_CMD",
    "GATECTL_ME__NAME",
    "GATECTL_ME",
    "GATECTL_DEFAULTS",
    "GATECTL_DEFAULTS__RECOMMEND",
    "GATECTL_DEFAULTS__RECOMMEND__CONFIDENCE",
    "GATECTL_AGENT",
    "GATECTL_RETENTION",
    "GATECTL_HOOKS",
    "GATECTL_HOOKS__POST_DECISION",
    "GATECTL_POLICIES",
    "GATECTL_POLICIES__P__STATE",
    "GATECTL_REPOS",
    "GATECTL_DEFAULTS__BOGUS",
    "GATECTL_DEFAULTS__TIMEOUT__EXTRA",
    "GATECTL_DEFAULTS___TIMEOUT",
]


@pytest.mark.parametrize("name", [*SAFETY, *LISTS_AND_STRUCTURED])
@pytest.mark.parametrize("value", ["off", "[a, b]", '{"a": 1}', "0.1", "5s", "1"])
def test_unlisted_keys_are_refused_and_never_applied(tmp_path: Path, name: str, value: str) -> None:
    c = load(tmp_path, {}, environ={name: value})
    (problem,) = c.shared_problems
    assert problem.code == "invalid_value"
    assert name in problem.message
    assert "environment" in problem.message
    base = load(tmp_path, {})
    assert c.shared == base.shared  # nothing was applied


def test_safety_key_in_the_file_is_still_fine_and_env_cannot_override_it(tmp_path: Path) -> None:
    c = load(
        tmp_path, {"agent": {"sandbox": "required"}}, environ={"GATECTL_AGENT__SANDBOX": "off"}
    )
    assert c.shared.agent.sandbox == "required"
    assert len(c.shared_problems) == 1


@pytest.mark.parametrize(
    "name",
    [
        "GATECTL_HOOK",
        "GATECTL_ID",
        "GATECTL_OBJECT_TYPE",
        "GATECTL_FOO",
        "GATECTL_",
        "GATECTL",
        "GATECTL_AGENT_TIMEOUT",
        "GATECTL_AGENTS__TIMEOUT",
        "gatectl_defaults__timeout",
        "GateCtl_Defaults__Timeout",
        "XGATECTL_DEFAULTS__TIMEOUT",
        "GATECTL_É",
        "PATH",
    ],
)
def test_other_names_are_ignored(tmp_path: Path, name: str) -> None:
    c = load(tmp_path, {}, environ={name: "5s"})
    base = load(tmp_path, {})
    assert c.shared_problems == ()
    assert c.shared == base.shared


def test_hook_variables_are_never_read_as_config(tmp_path: Path) -> None:
    env = {"GATECTL_HOOK": "post-decision", "GATECTL_ID": "gd-x", "GATECTL_OBJECT_TYPE": "decision"}
    assert load(tmp_path, {}, environ=env).shared_problems == ()


def test_environment_does_not_touch_policies(tmp_path: Path) -> None:
    c = load(
        tmp_path,
        {
            "policies": {
                "p": {
                    "checks": [
                        {
                            "name": "r",
                            "type": "rule",
                            "when": [{"path": "a", "op": "exists"}],
                            "then": "deny",
                        }
                    ],
                    "timeout": "5s",
                }
            }
        },
        environ={"GATECTL_DEFAULTS__TIMEOUT": "9s"},
    )
    p = c.resolve_policy("p")
    assert p.timeout == timedelta(seconds=5)  # a policy's own key beats defaults and env
    assert c.shared.defaults.timeout == timedelta(seconds=9)


def test_env_is_read_from_os_environ_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gatectl.config import load_config
    from tests.config_util import write

    path = write(tmp_path / "c.yaml", {})
    monkeypatch.setenv("GATECTL_DEFAULTS__TIMEOUT", "4s")
    assert load_config(str(path)).shared.defaults.timeout == timedelta(seconds=4)


@pytest.mark.parametrize(
    "name",
    [
        "GATECTL_HOOKS__POST-DECISION",
        "GATECTL_AGENT__timeout",
        "GATECTL_agent__TIMEOUT",
        "GATECTL_Defaults__Timeout",
        "GATECTL_AGENT__SAND-BOX",
        "GATECTL_AGENT__SANDBOX ",
        "GATECTL_AGENT__TIME.OUT",
        "GATECTL_AGENT__É",
        "GATECTL_ME__name",
        "GATECTL_agent",
    ],
)
def test_unlisted_names_are_flagged_whatever_their_characters(tmp_path: Path, name: str) -> None:
    c = load(tmp_path, {}, environ={name: "0s"})
    base = load(tmp_path, {})
    (problem,) = c.shared_problems
    assert problem.code == "invalid_value"
    assert "environment" in problem.message
    assert c.shared == base.shared  # nothing was applied


@pytest.mark.parametrize(
    "name",
    [
        "GATECTL_AGENT-TIMEOUT",
        "GATECTL_agent_timeout",
        "GATECTL_AGENTS__timeout",
        "GATECTL_HOOK-X",
        "GATECTL_HOOKS-X__Y",
        "GATECTL_ſ",
        "GATECTL_KOOKS__X",  # Kelvin sign is not an ASCII K
        "GATECTL_",
    ],
)
def test_names_with_no_section_stay_ignored(tmp_path: Path, name: str) -> None:
    c = load(tmp_path, {}, environ={name: "0s"})
    assert c.shared_problems == ()


def test_hostile_names_and_values_never_reach_a_message(tmp_path: Path) -> None:
    names = [
        f"GATECTL_HOOKS__{CANARY}-x",
        f"GATECTL_agent__{CANARY}\n\x1b[31m",
        f"GATECTL_policies__{CANARY.lower()}‮",
    ]
    c = load(tmp_path, {}, environ={n: CANARY for n in names})
    assert len(c.shared_problems) == 3
    for p in c.shared_problems:
        assert CANARY not in p.message and CANARY.lower() not in p.message
        assert "\x1b" not in p.message and "\n" not in p.message
        assert "\x1b" not in p.path and "\n" not in p.path and "‮" not in p.path
