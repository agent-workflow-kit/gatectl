"""The loader against schemas/config.json and config.example.yaml."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from gatectl import ids
from gatectl.config import load_config
from tests import schema_util
from tests.config_util import good_policy, load

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "schemas" / "config.json").read_text(encoding="utf-8"))
EXAMPLE = ROOT / "config.example.yaml"


def _schema_errors(doc: Any) -> list[str]:
    return [e.message for e in Draft202012Validator(SCHEMA).iter_errors(doc)]


def test_example_config_validates_against_the_schema() -> None:
    doc = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    assert _schema_errors(doc) == []


def test_example_config_loads_with_no_problems_and_equals_the_defaults(tmp_path: Path) -> None:
    from_example = load_config(str(EXAMPLE), environ={})
    assert from_example.shared_problems == ()
    assert from_example.policies == {}
    assert from_example.shared == load(tmp_path, {}).shared


def test_every_commented_example_block_loads(tmp_path: Path) -> None:
    """The commented-out blocks of the example are real config once uncommented."""
    lines = EXAMPLE.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line in ("policies: {}", "repos: {}", "hooks: {}"):
            i += 1
            continue
        if line in ("# policies:", "# repos:", "# hooks:"):
            out.append(line[2:])
            i += 1
            while i < len(lines) and lines[i].startswith("#   "):
                out.append(lines[i][2:])
                i += 1
            continue
        out.append(line)
        i += 1
    text = "\n".join(out) + "\n"
    doc = yaml.safe_load(text)
    assert {"policies", "repos", "hooks"} <= set(doc)
    assert _schema_errors(doc) == []
    path = tmp_path / "ex.yaml"
    path.write_text(text, encoding="utf-8")
    loaded = load_config(str(path), environ={})
    assert loaded.shared_problems == ()
    assert loaded.policy_problems() == []
    assert loaded.resolve_policy("auto-merge", repo="github.com/org/repo") is not None


def _walk_defaults(schema: dict[str, Any], prefix: str = "") -> Iterator[tuple[str, Any]]:
    for key, sub in schema.get("properties", {}).items():
        path = f"{prefix}{key}"
        if "default" in sub:
            yield path, sub["default"]
        if sub.get("type") == "object" and "properties" in sub:
            yield from _walk_defaults(sub, path + ".")
        if "$ref" in sub and sub["$ref"].endswith("recommend_cfg") and "default" not in sub:
            continue


def _as_python(path: str, value: Any) -> Any:
    """Schema defaults are written as JSON; durations are strings in the schema."""
    leaf = path.rsplit(".", 1)[-1]
    if leaf in {"timeout", "script_timeout", "record_reserve", "cache_ttl", "min_start_budget"}:
        return ids.parse_duration(value) if isinstance(value, str) else timedelta(0)
    return value


def test_every_schema_default_is_the_model_default(tmp_path: Path) -> None:
    shared = load(tmp_path, {}).shared
    seen = 0
    for path, default in _walk_defaults(SCHEMA):
        if path in ("me", "defaults", "agent", "retention", "hooks", "policies", "repos"):
            continue
        if path.startswith(("policies", "repos")):
            continue
        node: Any = shared
        for part in path.split("."):
            node = getattr(node, part.replace("-", "_"))
        if path == "defaults.recommend":
            got = {"confidence": node.confidence, "max_miss_rate": node.max_miss_rate}
            assert got == default
        else:
            assert node == _as_python(path, default), path
        seen += 1
    assert seen >= 20


def test_schema_defaults_for_policy_keys(tmp_path: Path) -> None:
    pol = SCHEMA["$defs"]["policy_def"]["properties"]
    p = load(tmp_path, {"policies": {"p": good_policy()}}).resolve_policy("p")
    assert p.state == pol["state"]["default"]
    assert p.record_input == pol["record_input"]["default"]
    rule = SCHEMA["$defs"]["rule_check"]["properties"]
    assert p.checks[0].else_ == rule["else"]["default"]  # type: ignore[union-attr]


# --- loader never accepts what the schema rejects ---------------------------------------------

ONE_RULE = {"name": "r", "type": "rule", "when": [{"path": "a", "op": "exists"}], "then": "deny"}


def _docs() -> list[dict[str, Any]]:
    """Valid and invalid documents; the loader must reject every one the schema rejects."""
    docs: list[dict[str, Any]] = [{}, {"policies": {"p": {"checks": [ONE_RULE]}}}]
    for section, key, values in [
        ("me", "name", ["a b", 5, "", "x" * 65]),
        ("defaults", "timeout", ["x", 5, "1.5s", None, True, ""]),
        ("defaults", "input_max_bytes", [0, 16777217, "1", 1.5]),
        ("defaults", "script_env_allow", [["A", "A"], ["*"], "x"]),
        ("agent", "skill", ["bare", "A:b", 5]),
        ("agent", "plugin_dirs", [["rel"], "x"]),
        ("agent", "permission_profile", ["rel", 5]),
        ("agent", "sandbox", ["on", None]),
        ("agent", "setting_sources", [["x"], ["user", "user"]]),
        ("agent", "env_allowlist", [["A*"]]),
        ("agent", "threshold", [-1, 2, "x"]),
        ("agent", "max_parallel", [0, 33, 1.5]),
        ("agent", "input_max_bytes", [1023, 1048577]),
        ("retention", "older_than", ["x", 5]),
    ]:
        docs.extend({section: {key: v}} for v in values)
    docs += [
        {"bogus": 1},
        {"session_cmd": []},
        {"session_cmd": [""]},
        {"hooks": {"post-decision": [{"cmd": ""}]}},
        {"hooks": {"post-decision": [{"cmd": "x", "bogus": 1}]}},
        {"hooks": {"nope": []}},
        {"repos": {"bad id": {}}},
        {"repos": {"github.com/o/r": {"bogus": 1}}},
        {"policies": {"Bad": {"checks": [ONE_RULE]}}},
        {"policies": {"p": {}}},
        {"policies": {"p": {"checks": []}}},
        {"policies": {"p": {"checks": [ONE_RULE], "state": "enforced"}}},
        {"policies": {"p": {"checks": [ONE_RULE], "bogus": 1}}},
        {"policies": {"p": {"checks": [{**ONE_RULE, "type": "shell"}]}}},
        {"policies": {"p": {"checks": [{**ONE_RULE, "then": "skipped"}]}}},
        {"policies": {"p": {"checks": [{**ONE_RULE, "when": []}]}}},
        {"policies": {"p": {"checks": [{"name": "s", "type": "script", "argv": ["rel"]}]}}},
        {"policies": {"p": {"checks": [{"name": "s", "type": "script", "argv": []}]}}},
        {"policies": {"p": {"checks": [{"name": "a", "type": "agent"}]}}},
        {
            "policies": {
                "p": {
                    "checks": [
                        {"name": "a", "type": "agent", "instruction": "x", "instruction_file": "/x"}
                    ]
                }
            }
        },
        {"policies": {"p": {"checks": [ONE_RULE], "input": {"ignore": ["repo"]}}}},
        {"policies": {"p": {"checks": [ONE_RULE], "applies_when": []}}},
        {"policies": {"p": {"checks": [ONE_RULE], "recommend": {"confidence": 1}}}},
        {"policies": {"p": {"checks": [ONE_RULE], "recommend": {"max_miss_rate": 0}}}},
    ]
    for op in ("eq", "in", "lt", "glob", "exists"):
        for value in (None, 1, "x", [1], [[1]], "a" * 129):
            cond: dict[str, Any] = {"path": "a", "op": op, "value": value}
            docs.append({"policies": {"p": {"checks": [{**ONE_RULE, "when": [cond]}]}}})
        docs.append(
            {"policies": {"p": {"checks": [{**ONE_RULE, "when": [{"path": "a", "op": op}]}]}}}
        )
    return docs


def _all_problems(c: Any) -> list[Any]:
    return [*c.shared_problems, *c.policy_problems()]


@pytest.mark.parametrize("index", range(len(_docs())))
def test_loader_rejects_everything_the_schema_rejects(tmp_path: Path, index: int) -> None:
    doc = _docs()[index]
    if _schema_errors(doc):
        assert _all_problems(load(tmp_path, doc)), json.dumps(doc)[:200]


def test_loader_accepts_everything_the_schema_accepts_except_ranges(tmp_path: Path) -> None:
    """Where the schema accepts a document the loader may only add range rules."""
    for doc in _docs():
        if _schema_errors(doc):
            continue
        problems = _all_problems(load(tmp_path, doc))
        for problem in problems:
            assert problem.code == "invalid_value", (json.dumps(doc)[:200], problem)


def test_schema_golden_defaults_document(tmp_path: Path) -> None:
    """Golden: the defaults, written back as config, validate against the schema."""
    golden = json.loads((ROOT / "tests" / "golden_config" / "defaults.json").read_text("utf-8"))
    assert _schema_errors(golden) == []
    c = load(tmp_path, golden)
    assert c.shared_problems == ()
    assert c.shared == load(tmp_path, {}).shared
    assert schema_util.SCHEMAS.exists()
