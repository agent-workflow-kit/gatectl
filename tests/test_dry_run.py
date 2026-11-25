"""``gatectl check --dry-run``: the static plan, the input verdict, and that nothing runs."""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from gatectl import dryrun
from gatectl import fingerprint as fp
from gatectl.config import load_config
from gatectl.scope import Scope
from tests import golden, schema_util
from tests.command_util import CANARY, agent, config_file, isolate, payload, rule, run, script

REPO = "github.com/org/repo"
OTHER = "github.com/org/other"


@pytest.fixture(autouse=True)
def state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def cfg(tmp_path: Path, policies: dict[str, Any], **top: Any) -> str:
    return config_file(tmp_path, {"policies": policies, **top})


def input_file(tmp_path: Path, content: Any, name: str = "in.json") -> str:
    path = tmp_path / name
    path.write_bytes(content if isinstance(content, bytes) else json.dumps(content).encode())
    return str(path)


def plan(
    capsys: pytest.CaptureFixture[str], config: str, policy: str = "p", *extra: str
) -> tuple[int, dict[str, Any], str]:
    code, out, err = run(capsys, ["check", policy, "--dry-run", "--config", config, *extra])
    return code, (payload(out) if out else {}), err


def would_run(doc: dict[str, Any]) -> list[bool]:
    return [c["would_run"] for c in doc["checks"]]


MIXED = {"checks": [agent("ai"), script("sc", ["/bin/tool", "x"], timeout="5s"), rule("ru")]}


def test_plan_lists_every_check_in_execution_order_with_resolved_fields(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": MIXED}, agent={"timeout": "90s"})
    src = input_file(tmp_path, {"ci": "green"})
    code, doc, err = plan(capsys, config, "p", "--input", src)
    assert (code, err) == (0, "")
    assert doc["checks"] == [
        {
            "name": "sc",
            "type": "script",
            "argv": ["/bin/tool", "x"],
            "skill": None,
            "timeout_ms": 5000,
            "would_run": True,
        },
        {
            "name": "ru",
            "type": "rule",
            "argv": None,
            "skill": None,
            "timeout_ms": None,
            "would_run": True,
        },
        {
            "name": "ai",
            "type": "agent",
            "argv": None,
            "skill": "gatectl:gate-check",
            "timeout_ms": 90000,
            "would_run": True,
        },
    ]
    assert doc["policy"] == "p" and doc["scope"] == "*" and doc["state"] == "shadow"
    assert doc["dry_run"] is True and doc["schema_version"] == 1
    assert doc["input_valid"] is True and doc["warnings"] == []
    schema_util.assert_valid("cli/check-dry-run", doc)


def test_timeouts_default_from_the_config_and_a_check_wins(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(
        tmp_path,
        {
            "p": {
                "checks": [
                    script("a"),
                    script("b", timeout="3s"),
                    agent("c", timeout="7s", skill="x:y"),
                ]
            }
        },
        defaults={"script_timeout": "11s"},
    )
    _, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, {}))
    assert [(c["timeout_ms"], c["skill"]) for c in doc["checks"]] == [
        (11000, None),
        (3000, None),
        (7000, "x:y"),
    ]


def test_output_is_json_without_the_json_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": MIXED})
    code, out, _ = run(
        capsys, ["check", "p", "--dry-run", "--config", config, "--input", input_file(tmp_path, {})]
    )
    assert code == 0 and payload(out)["dry_run"] is True


def test_the_fingerprint_is_the_effective_definitions(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": MIXED})
    _, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, {}))
    loaded = load_config(config, environ={})
    assert doc["fingerprint"] == fp.fingerprint_for(loaded, "p", Scope("*", False, ()))


def test_state_is_the_initial_state_without_a_state_database(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": {"state": "shadow", "checks": [rule()]}})
    _, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, {}))
    assert doc["state"] == "shadow"


def test_state_off_skips_every_check_and_ignores_the_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": {"state": "off", "input": {"require": ["k"]}, **MIXED}})
    code, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, b"not json"))
    assert code == 0 and doc["state"] == "off"
    assert would_run(doc) == [False, False, False]
    assert doc["input_valid"] is True  # step 4: off evaluates neither the declaration nor the input


def test_a_false_applies_when_skips_every_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Any] = []

    def never(conditions: Any, obj: Any) -> bool:
        seen.append((conditions, obj))
        return False

    monkeypatch.setattr(dryrun, "applies", never)
    config = cfg(
        tmp_path,
        {
            "p": {
                "applies_when": [{"path": "k", "op": "exists"}],
                "input": {"require": ["z"]},
                **MIXED,
            }
        },
    )
    _, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, {"a": 1}))
    assert would_run(doc) == [False, False, False]
    assert doc["input_valid"] is True  # step 4a precedes the declaration
    assert len(seen) == 1 and seen[0][1] == {"a": 1}


def test_applies_when_is_not_evaluated_for_an_unusable_input_or_without_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(conditions: Any, obj: Any) -> bool:
        raise AssertionError("evaluated")

    monkeypatch.setattr(dryrun, "applies", boom)
    config = cfg(tmp_path, {"p": {"applies_when": [{"path": "k", "op": "exists"}], **MIXED}})
    _, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, b"[]"))
    assert doc["input_valid"] is False
    config = cfg(tmp_path, {"p": MIXED})  # no applies_when at all
    _, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, {}))
    assert doc["input_valid"] is True


@pytest.mark.parametrize(
    ("declaration", "content"),
    [
        ({"require": ["k"]}, {}),
        ({"require": ["k"]}, {"k": None}),
        ({"types": {"k": "string"}}, {"k": 1}),
        ({"types": {"k": "integer"}}, {"k": True}),
    ],
)
def test_an_input_failing_the_declaration_is_input_invalid_and_exit_0(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    declaration: dict[str, Any],
    content: dict[str, Any],
) -> None:
    config = cfg(tmp_path, {"p": {"input": declaration, **MIXED}})
    code, doc, err = plan(capsys, config, "p", "--input", input_file(tmp_path, content))
    assert (code, err) == (0, "")
    assert doc["input_valid"] is False
    assert would_run(doc) == [False, False, False]
    assert len(doc["checks"]) == 3
    schema_util.assert_valid("cli/check-dry-run", doc)


def test_an_input_passing_the_declaration_is_valid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": {"input": {"require": ["k"], "types": {"k": "string"}}, **MIXED}})
    _, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, {"k": "v"}))
    assert doc["input_valid"] is True and would_run(doc) == [True, True, True]


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"not json",
        b"[]",
        b'"s"',
        b"null",
        b"\xef\xbb\xbf{}",
        b"\xff\xfe",
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":1e999}',
        b'{"a":"\\ud800"}',
        b"{}{}",
        b"[" * 100 + b"]" * 100,
        b'{"a":' * 70 + b"1" + b"}" * 70,
    ],
)
def test_an_unusable_input_is_input_invalid_and_exit_0(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: bytes
) -> None:
    config = cfg(tmp_path, {"p": MIXED})
    code, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, content))
    assert code == 0 and doc["input_valid"] is False
    assert would_run(doc) == [False, False, False]


def test_an_input_over_the_size_cap_is_input_invalid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": MIXED}, defaults={"input_max_bytes": 64})
    code, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, {"pad": "x" * 100}))
    assert code == 0 and doc["input_valid"] is False
    code, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, {"p": "x"}))
    assert doc["input_valid"] is True


def test_an_unencodable_declared_value_is_input_invalid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": {"input": {"require": ["k"]}, **MIXED}})
    raw = b'{"k":"a\\ud800b"}'  # an unpaired surrogate is refused by the strict parser
    _, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, raw))
    assert doc["input_valid"] is False


def test_stdin_is_read_when_there_is_no_input_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    read_end, write_end = os.pipe()
    os.write(write_end, b'{"repo":"' + REPO.encode() + b'"}')
    os.close(write_end)
    monkeypatch.setattr(dryrun, "STDIN_FD", read_end)
    try:
        _, doc, _ = plan(capsys, cfg(tmp_path, {"p": MIXED}), "p")
    finally:
        os.close(read_end)
    assert doc["scope"] == REPO and doc["input_valid"] is True


def test_a_closed_stdin_is_input_invalid_not_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    read_end, write_end = os.pipe()
    os.close(write_end)
    monkeypatch.setattr(dryrun, "STDIN_FD", read_end)
    try:
        code, doc, _ = plan(capsys, cfg(tmp_path, {"p": MIXED}), "p", "--input", "-")
    finally:
        os.close(read_end)
    assert code == 0 and doc["input_valid"] is False


@pytest.mark.parametrize("target", ["missing", "directory"])
def test_an_unusable_input_file_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], target: str
) -> None:
    path = tmp_path / "nope" if target == "missing" else tmp_path
    code, out, err = run(
        capsys,
        ["check", "p", "--dry-run", "--config", cfg(tmp_path, {"p": MIXED}), "--input", str(path)],
    )
    assert code == 2 and payload(out)["error"]["code"] == "usage"
    assert err == "gatectl: usage p\n"


# --- scope -------------------------------------------------------------------------------------


def test_the_scope_comes_from_the_flag_then_the_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": MIXED})
    _, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, {"repo": REPO}))
    assert doc["scope"] == REPO and doc["warnings"] == []
    _, doc, _ = plan(
        capsys, config, "p", "--input", input_file(tmp_path, {"repo": REPO}), "--repo", OTHER
    )
    assert doc["scope"] == OTHER and doc["warnings"] == ["repo_mismatch"]
    _, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, {}), "--repo", OTHER)
    assert doc["scope"] == OTHER and doc["warnings"] == []


def test_an_indeterminate_scope_is_input_invalid_with_the_star_scope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": MIXED})
    _, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, {"repo": 5}))
    assert doc["scope"] == "*" and doc["input_valid"] is False
    assert doc["warnings"] == ["repo_invalid"]
    assert would_run(doc) == [False, False, False]
    schema_util.assert_valid("cli/check-dry-run", doc)


def test_an_unusable_input_without_a_repo_flag_has_the_star_scope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, doc, _ = plan(
        capsys, cfg(tmp_path, {"p": MIXED}), "p", "--input", input_file(tmp_path, b"x")
    )
    assert doc["scope"] == "*" and doc["input_valid"] is False


def test_a_repo_override_is_applied_to_the_plan(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(
        tmp_path,
        {"p": MIXED},
        repos={REPO: {"policies": {"p": {"checks": [script("own", ["/bin/own"])]}}}},
    )
    src = input_file(tmp_path, {})
    _, base, _ = plan(capsys, config, "p", "--input", src, "--repo", OTHER)
    _, over, _ = plan(capsys, config, "p", "--input", src, "--repo", REPO)
    assert [c["name"] for c in over["checks"]] == ["own"]
    assert len(base["checks"]) == 3
    assert over["fingerprint"] != base["fingerprint"]
    loaded = load_config(config, environ={})
    assert over["fingerprint"] == fp.fingerprint_for(loaded, "p", Scope(REPO, False, ()))


def test_an_override_declaration_is_the_one_checked(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(
        tmp_path,
        {"p": MIXED},
        repos={REPO: {"policies": {"p": {"input": {"require": ["k"]}}}}},
    )
    src = input_file(tmp_path, {})
    assert plan(capsys, config, "p", "--input", src, "--repo", REPO)[1]["input_valid"] is False
    assert plan(capsys, config, "p", "--input", src, "--repo", OTHER)[1]["input_valid"] is True


# --- errors and warnings -----------------------------------------------------------------------


def test_an_unknown_policy_exits_2_with_the_kind(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = run(
        capsys, ["check", "nope", "--dry-run", "--config", cfg(tmp_path, {"p": MIXED})]
    )
    assert code == 2
    error = payload(out)["error"]
    assert (error["code"], error["details"]["kind"]) == ("usage", "unknown_policy")
    assert err == "gatectl: usage nope\n"


def test_an_unknown_policy_does_not_read_stdin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dryrun, "STDIN_FD", -1)  # reading it would fail loudly
    code, _, _ = plan(capsys, cfg(tmp_path, {"p": MIXED}), "nope")
    assert code == 2


def test_an_invalid_policy_exits_2_as_a_config_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": {"checks": []}})
    code, out, err = run(capsys, ["check", "p", "--dry-run", "--config", config])
    assert code == 2 and payload(out)["error"]["code"] == "config_invalid"
    assert err == "gatectl: config_invalid p\n"


def test_an_invalid_override_for_the_scope_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": MIXED}, repos={REPO: {"policies": {"p": {"checks": []}}}})
    code, out, _ = run(
        capsys,
        [
            "check",
            "p",
            "--dry-run",
            "--config",
            config,
            "--repo",
            REPO,
            "--input",
            input_file(tmp_path, {}),
        ],
    )
    assert code == 2 and payload(out)["error"]["code"] == "config_invalid"


def test_an_invalid_shared_key_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = cfg(tmp_path, {"p": MIXED}, defaults={"timeout": "0s"})
    code, out, _ = run(capsys, ["check", "p", "--dry-run", "--config", config])
    assert code == 2 and payload(out)["error"]["code"] == "config_invalid"


def test_another_invalid_policy_adds_the_config_problem_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": MIXED, "bad": {"checks": []}})
    _, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, {}))
    assert doc["warnings"] == ["config_problem"]
    schema_util.assert_valid("cli/check-dry-run", doc)


def test_warnings_combine_in_a_fixed_order_without_duplicates(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": MIXED, "bad": {"checks": []}})
    src = input_file(tmp_path, {"repo": REPO})
    _, doc, _ = plan(capsys, config, "p", "--input", src, "--repo", OTHER)
    assert doc["warnings"] == ["repo_mismatch", "config_problem"]


BAD_TIMEOUTS = [
    "0", "-1", "nan", "inf", "abc", "", "86401", "1e999", "1_0", "+5", " 5", "5\n", "5 ",
    "\u0665", "0x5", "1e5", "86400.0000001", ".", "e5", "1e", "NaN", "Infinity", "0.0", "1e-999",
]  # fmt: skip


@pytest.mark.parametrize("value", BAD_TIMEOUTS)
def test_a_bad_timeout_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], value: str
) -> None:
    code, out, _ = run(
        capsys,
        [
            "check",
            "p",
            "--dry-run",
            "--config",
            cfg(tmp_path, {"p": MIXED}),
            "--timeout",
            value,
            "--input",
            input_file(tmp_path, {}),
        ],
    )
    assert code == 2 and payload(out)["error"]["code"] == "usage"


@pytest.mark.parametrize("value", ["0.5", "60", "86400", "5", ".5", "5.", "1e2", "00005", "1E2"])
def test_a_good_timeout_is_accepted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], value: str
) -> None:
    code, _, _ = plan(
        capsys,
        cfg(tmp_path, {"p": MIXED}),
        "p",
        "--timeout",
        value,
        "--input",
        input_file(tmp_path, {}),
    )
    assert code == 0


def test_without_dry_run_check_is_still_not_implemented(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = run(capsys, ["check", "p", "--config", cfg(tmp_path, {"p": MIXED})])
    assert code == 1 and payload(out)["error"]["code"] == "internal"


# --- nothing runs, nothing is recorded ---------------------------------------------------------


def test_a_dry_run_starts_no_process_and_writes_no_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise AssertionError("a process was started")

    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(os, "fork", boom)
    marker = tmp_path / "ran"
    config = cfg(
        tmp_path,
        {"p": {"checks": [script("sc", ["/bin/sh", "-c", f"touch {marker}"]), agent()]}},
    )
    for content in ({}, b"junk"):
        code, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, content))
        assert code == 0 and doc["dry_run"] is True
    assert not marker.exists()
    assert not state_dir.exists()
    assert not (tmp_path / "home" / "state").exists()


def test_an_existing_state_directory_is_left_byte_identical(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    state_dir.mkdir(parents=True)
    for name in ("state.db", "audit.jsonl", "log.jsonl"):
        (state_dir / name).write_bytes(b"sentinel " + name.encode())
    before = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in state_dir.iterdir()}
    config = cfg(tmp_path, {"p": MIXED})
    plan(capsys, config, "p", "--input", input_file(tmp_path, {}))
    plan(capsys, config, "p", "--input", input_file(tmp_path, b"junk"))
    after = {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in state_dir.iterdir()}
    assert after == before


# --- hostile config text -----------------------------------------------------------------------


def test_script_argv_in_the_plan_is_sanitized(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    hostile = f"{CANARY}\x1b[31m\nINJECT\u202e "
    config = cfg(tmp_path, {"p": {"checks": [script("sc", ["/bin/t", hostile])]}})
    code, out, _ = run(
        capsys,
        ["check", "p", "--dry-run", "--config", config, "--input", input_file(tmp_path, {})],
    )
    assert code == 0
    argv = payload(out)["checks"][0]["argv"]
    assert argv[0] == "/bin/t" and CANARY in argv[1]
    assert all(ch == " " or ch.isprintable() for ch in argv[1])
    assert "\x1b" not in out and "\u202e" not in out


def test_a_hostile_input_value_is_never_echoed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": {"input": {"require": ["k"], "types": {"k": "integer"}}, **MIXED}})
    code, out, err = run(
        capsys,
        [
            "check",
            "p",
            "--dry-run",
            "--config",
            config,
            "--input",
            input_file(tmp_path, {"k": CANARY, "repo": CANARY}),
        ],
    )
    assert code == 0
    assert CANARY not in out and CANARY not in err


# --- golden ------------------------------------------------------------------------------------


def test_the_plan_is_golden(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fp, "fingerprint", lambda *a, **k: "sha256:" + "ab" * 32)
    config = cfg(
        tmp_path,
        {
            "auto-merge": {
                "checks": [
                    script("ci-green", ["/nonexistent/ci-green"], timeout="20s"),
                    agent("reviewer"),
                ]
            }
        },
    )
    code, out, _ = run(
        capsys,
        [
            "check",
            "auto-merge",
            "--dry-run",
            "--config",
            config,
            "--input",
            input_file(tmp_path, {}),
        ],
    )
    assert code == 0
    golden.assert_output("check-dry-run", out)


def test_a_bad_timeout_without_dry_run_exits_2_before_not_implemented(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": MIXED})
    code, out, _ = run(capsys, ["check", "p", "--config", config, "--timeout", "abc"])
    assert code == 2 and payload(out)["error"]["code"] == "usage"


def test_a_two_second_timeout_still_reads_a_valid_input_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    src = input_file(tmp_path, {"repo": REPO})
    _, doc, _ = plan(capsys, cfg(tmp_path, {"p": MIXED}), "p", "--timeout", "2", "--input", src)
    assert doc["input_valid"] is True and doc["scope"] == REPO


def test_a_two_second_timeout_still_reads_available_stdin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    read_end, write_end = os.pipe()
    os.write(write_end, b'{"repo":"' + REPO.encode() + b'"}')
    os.close(write_end)
    monkeypatch.setattr(dryrun, "STDIN_FD", read_end)
    try:
        _, doc, _ = plan(capsys, cfg(tmp_path, {"p": MIXED}), "p", "--timeout", "2")
    finally:
        os.close(read_end)
    assert doc["input_valid"] is True and doc["scope"] == REPO


def spy_read_input(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    real = dryrun.inputs.read_input

    def spy(source: Any, **kwargs: Any) -> Any:
        calls.append({"source": source, **kwargs})
        return real(source, **kwargs)

    monkeypatch.setattr(dryrun.inputs, "read_input", spy)
    return calls


@pytest.mark.parametrize(
    ("flag", "policy_timeout", "default", "expected"),
    [
        ("30", "20s", "10s", 30.0),
        (None, "20s", "10s", 20.0),
        (None, None, "10s", 10.0),
    ],
)
def test_the_stdin_deadline_follows_timeout_then_policy_then_default(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    flag: str | None,
    policy_timeout: str | None,
    default: str,
    expected: float,
) -> None:
    calls = spy_read_input(monkeypatch)
    extra = {"timeout": policy_timeout} if policy_timeout else {}
    config = cfg(tmp_path, {"p": {**MIXED, **extra}}, defaults={"timeout": default})
    read_end, write_end = os.pipe()
    os.write(write_end, b"{}")
    os.close(write_end)
    monkeypatch.setattr(dryrun, "STDIN_FD", read_end)
    args = ["--timeout", flag] if flag else []
    try:
        plan(capsys, config, "p", *args)
    finally:
        os.close(read_end)
    # The read window is the budget minus the 2 s record reserve.
    left = calls[0]["deadline"] - time.monotonic()
    assert expected - 2 - 1 < left <= expected - 2


def test_a_file_input_read_has_no_deadline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = spy_read_input(monkeypatch)
    src = input_file(tmp_path, {})
    plan(capsys, cfg(tmp_path, {"p": MIXED}), "p", "--timeout", "1", "--input", src)
    assert calls[0]["deadline"] is None


def test_a_stalled_stdin_with_a_tiny_timeout_is_input_invalid_quickly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    read_end, write_end = os.pipe()  # the write end stays open: nothing arrives, no EOF
    monkeypatch.setattr(dryrun, "STDIN_FD", read_end)
    started = time.monotonic()
    try:
        code, doc, _ = plan(capsys, cfg(tmp_path, {"p": MIXED}), "p", "--timeout", "0.01")
    finally:
        os.close(read_end)
        os.close(write_end)
    assert code == 0 and doc["input_valid"] is False and doc["scope"] == "*"
    assert time.monotonic() - started < 5


def test_an_over_long_argv_element_ends_with_one_ellipsis_within_1024_characters(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = cfg(tmp_path, {"p": {"checks": [script("s", ["/bin/tool", "x" * 5000, "y" * 1024])]}})
    _, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, {}))
    long, exact = doc["checks"][0]["argv"][1:]
    assert len(long) == 1024 and long == "x" * 1023 + "\u2026"
    assert exact == "y" * 1024


@pytest.mark.parametrize(
    ("content", "would", "valid"),
    [
        ({"tool": "Edit", "z": 1}, False, True),  # a false condition: not applicable, input_valid
        ({"tool": "Edit"}, False, True),  # not applicable: the invalid declaration is not evaluated
        ({"tool": "Bash", "z": 1}, True, True),
        ({"z": 1}, True, True),  # an erroring condition counts as applicable (fail closed)
        ({"tool": None, "z": 1}, True, True),
        ({"tool": "Bash"}, False, False),  # applicable, then the declaration fails
    ],
)
def test_applies_when_is_evaluated_by_the_rule_evaluator(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: Any, would: bool, valid: bool
) -> None:
    config = cfg(
        tmp_path,
        {
            "p": {
                "applies_when": [{"path": "tool", "op": "eq", "value": "Bash"}],
                "input": {"require": ["z"]},
                **MIXED,
            }
        },
    )
    _, doc, _ = plan(capsys, config, "p", "--input", input_file(tmp_path, content))
    assert would_run(doc) == [would] * 3
    assert doc["input_valid"] is valid
