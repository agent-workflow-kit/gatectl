"""``gatectl policies``: the static view (config only), the repo override, hostile config text."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from gatectl import fingerprint as fp
from gatectl.config import load_config
from gatectl.scope import Scope
from tests import golden, schema_util
from tests.command_util import CANARY, agent, config_file, isolate, payload, rule, run, script

REPO = "github.com/org/repo"


@pytest.fixture(autouse=True)
def state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def cfg(tmp_path: Path, policies: dict[str, Any], **top: Any) -> str:
    return config_file(tmp_path, {"policies": policies, **top})


def view(
    capsys: pytest.CaptureFixture[str], config: str, *extra: str
) -> tuple[int, dict[str, Any], str]:
    code, out, err = run(capsys, ["policies", "--json", "--config", config, *extra])
    return code, (payload(out) if out else {}), err


def test_lists_only_configured_policies_in_name_order(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = cfg(tmp_path, {"zeta": {"checks": [rule()]}, "alpha": {"checks": [rule()]}})
    code, doc, err = view(capsys, config)
    assert (code, err) == (0, "")
    assert [p["name"] for p in doc["policies"]] == ["alpha", "zeta"]
    assert doc["scope"] == "*"
    schema_util.assert_valid("cli/policies", doc)


def test_static_fields_are_the_initial_state_and_no_stored_data(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(
        tmp_path, {"a": {"checks": [rule()]}, "b": {"state": "off", "checks": [rule()]}}
    )
    _, doc, _ = view(capsys, config)
    a, b = doc["policies"]
    assert (a["initial_state"], a["effective_state"]) == ("shadow", "shadow")
    assert (b["initial_state"], b["effective_state"]) == ("off", "off")
    for p in (a, b):
        assert p["scopes"] == [] and p["records"] == []


def test_fingerprint_is_the_real_fingerprint_of_the_effective_definition(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"a": {"checks": [rule(), script()]}})
    _, doc, _ = view(capsys, config)
    loaded = load_config(config, environ={})
    assert doc["policies"][0]["fingerprint"] == fp.fingerprint_for(loaded, "a", Scope("*", False, ()))


def test_checks_are_summarized_in_execution_order(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(
        tmp_path,
        {"a": {"checks": [agent("ai"), script("sc", ["/bin/tool", "--flag", "x y"]), rule("ru")]}},
    )
    _, doc, _ = view(capsys, config)
    checks = doc["policies"][0]["checks"]
    assert [(c["name"], c["type"]) for c in checks] == [
        ("sc", "script"),
        ("ru", "rule"),
        ("ai", "agent"),
    ]
    assert checks[0]["summary"] == "/bin/tool --flag x y"
    assert checks[1]["summary"] == 'ci == "green" then deny else allow'
    assert checks[2]["summary"] == "skill gatectl:gate-check"


def test_an_agent_check_summary_names_its_own_skill_and_the_block_default(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(
        tmp_path,
        {"a": {"checks": [agent("x", skill="p:own"), agent("y")]}},
        agent={"skill": "q:default"},
    )
    _, doc, _ = view(capsys, config)
    assert [c["summary"] for c in doc["policies"][0]["checks"]] == [
        "skill p:own",
        "skill q:default",
    ]


@pytest.mark.parametrize(
    ("condition", "text"),
    [
        ({"path": "a", "op": "ne", "value": 1}, "a != 1"),
        ({"path": "a", "op": "in", "value": ["x", None]}, 'a in ["x", null]'),
        ({"path": "a", "op": "not_in", "value": [1]}, "a not in [1]"),
        ({"path": "a", "op": "lt", "value": 1.5}, "a < 1.5"),
        ({"path": "a", "op": "le", "value": 2}, "a <= 2"),
        ({"path": "a", "op": "gt", "value": 2}, "a > 2"),
        ({"path": "a", "op": "ge", "value": 2}, "a >= 2"),
        ({"path": "a", "op": "glob", "value": "pr=**"}, 'a glob "pr=**"'),
        ({"path": "a", "op": "exists"}, "a exists"),
        ({"path": "a", "op": "absent"}, "a absent"),
        ({"path": "a", "op": "eq", "value": None}, "a == null"),
    ],
)
def test_rule_conditions_summarize_per_operator(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], condition: dict[str, Any], text: str
) -> None:
    check = {
        "name": "r",
        "type": "rule",
        "when": [condition, {"path": "b", "op": "exists"}],
        "then": "escalate",
        "else": "deny",
    }
    _, doc, _ = view(capsys, cfg(tmp_path, {"a": {"checks": [check]}}))
    assert doc["policies"][0]["checks"][0]["summary"] == (
        f"{text} and b exists then escalate else deny"
    )


def test_repo_without_override_shows_the_global_definition(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"a": {"checks": [rule()]}})
    _, glob, _ = view(capsys, config)
    code, scoped, _ = view(capsys, config, "--repo", REPO)
    assert code == 0 and scoped["scope"] == REPO
    assert scoped["policies"] == glob["policies"]


def test_repo_override_shows_the_overriding_definition(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(
        tmp_path,
        {"a": {"checks": [rule("base")]}, "b": {"checks": [rule()]}},
        repos={REPO: {"policies": {"a": {"checks": [script("own")]}}}},
    )
    _, glob, _ = view(capsys, config)
    _, scoped, _ = view(capsys, config, "--repo", REPO)
    base, over = glob["policies"][0], scoped["policies"][0]
    assert [c["name"] for c in over["checks"]] == ["own"]
    assert over["fingerprint"] != base["fingerprint"]
    assert over["initial_state"] == base["initial_state"]
    assert scoped["policies"][1] == glob["policies"][1]  # no override for b
    loaded = load_config(config, environ={})
    assert over["fingerprint"] == fp.fingerprint_for(loaded, "a", Scope(REPO, False, ()))
    schema_util.assert_valid("cli/policies", scoped)


def test_text_form_marks_an_override_definition(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(
        tmp_path,
        {"a": {"checks": [rule()]}, "b": {"checks": [rule()]}},
        repos={REPO: {"policies": {"a": {"checks": [script("own")]}}}},
    )
    code, out, err = run(capsys, ["policies", "--config", config, "--repo", REPO])
    assert (code, err) == (0, "")
    lines = out.splitlines()
    assert any(line.startswith("a ") and "override" in line for line in lines)
    assert not any(line.startswith("b ") and "override" in line for line in lines)
    _, plain, _ = run(capsys, ["policies", "--config", config])
    assert "override" not in plain


def test_star_scope_is_the_global_view(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(
        tmp_path,
        {"a": {"checks": [rule("base")]}},
        repos={REPO: {"policies": {"a": {"checks": [script("own")]}}}},
    )
    _, glob, _ = view(capsys, config)
    code, star, _ = view(capsys, config, "--repo", "*")
    assert code == 0 and star == glob


def test_an_invalid_policy_is_left_out_with_one_stderr_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"good": {"checks": [rule()]}, "bad": {"checks": []}})
    code, doc, err = view(capsys, config)
    assert code == 0
    assert [p["name"] for p in doc["policies"]] == ["good"]
    assert err == "gatectl: warning config_problem: 1 policy not shown, see gatectl validate\n"


def test_an_invalid_override_hides_only_that_policy_for_that_repo(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(
        tmp_path,
        {"a": {"checks": [rule()]}, "b": {"checks": [rule()]}},
        repos={REPO: {"policies": {"a": {"checks": []}}}},
    )
    _, doc, err = view(capsys, config, "--repo", REPO)
    assert [p["name"] for p in doc["policies"]] == ["b"]
    assert "config_problem" in err
    _, glob, err = view(capsys, config)
    assert [p["name"] for p in glob["policies"]] == ["a", "b"]
    assert err == ""


def test_quiet_silences_the_warning_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"bad": {"checks": []}})
    code, doc, err = view(capsys, config, "--quiet")
    assert (code, doc["policies"], err) == (0, [], "")


def test_an_invalid_shared_key_still_lists_with_the_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"a": {"checks": [rule()]}}, defaults={"timeout": "0s"})
    code, doc, err = view(capsys, config)
    assert code == 0 and len(doc["policies"]) == 1
    assert err == "gatectl: warning config_problem: a shared key is invalid, see gatectl validate\n"


def test_an_unparseable_config_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("policies: [unclosed\n")
    code, out, _ = run(capsys, ["policies", "--json", "--config", str(bad)])
    assert code == 2
    assert payload(out)["error"]["code"] == "config_invalid"


def test_no_policies_is_an_empty_list(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, doc, _ = view(capsys, config_file(tmp_path, {}))
    assert (code, doc) == (0, {"scope": "*", "policies": []})


def test_hostile_config_text_is_sanitized_in_summaries(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    hostile = f"{CANARY}\x1b[31m\nINJECT\u202e end\u2028"
    config = cfg(
        tmp_path,
        {
            "a": {
                "checks": [
                    script("sc", ["/bin/t", hostile]),
                    {
                        "name": "ru",
                        "type": "rule",
                        "when": [{"path": "k", "op": "eq", "value": hostile}],
                        "then": "deny",
                    },
                ]
            }
        },
    )
    code, out, _ = run(capsys, ["policies", "--json", "--config", config])
    assert code == 0
    summaries = [c["summary"] for c in payload(out)["policies"][0]["checks"]]
    for text in summaries:
        assert CANARY in text
        assert all(ch == " " or ch.isprintable() for ch in text)
        assert "INJECT" in text and "\n" not in text
    code, text_out, _ = run(capsys, ["policies", "--config", config])
    assert code == 0
    assert not {"\x1b", "\u202e", "\u2028"} & set(text_out)
    assert text_out.count("\n") == len(text_out.splitlines())


def test_summaries_are_capped(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = cfg(tmp_path, {"a": {"checks": [script("sc", ["/bin/t", "x" * 100_000])]}})
    _, doc, _ = view(capsys, config)
    assert len(doc["policies"][0]["checks"][0]["summary"]) <= 512


def test_the_command_runs_nothing_and_writes_nothing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("a process was started")

    monkeypatch.setattr(subprocess, "Popen", boom)
    config = cfg(tmp_path, {"a": {"checks": [script(), agent()]}})
    code, _, _ = view(capsys, config)
    assert code == 0
    assert not state_dir.exists()


def test_the_output_is_golden(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fp, "fingerprint", lambda name, *a, **k: "sha256:" + name[0] * 64)
    config = cfg(
        tmp_path,
        {
            "auto-merge": {
                "checks": [rule("ci-green"), script("lint", ["/nonexistent/lint", "--strict"]), agent("reviewer")]
            },
            "sleeper": {"state": "off", "checks": [rule()]},
        },
    )
    code, out, _ = run(capsys, ["policies", "--json", "--config", config])
    assert code == 0
    golden.assert_output("policies-static", out)
    assert json.loads(out)["policies"][0]["name"] == "auto-merge"
