"""``gatectl check`` edge cases: the deadline across overrides, applicability, failure paths,
the stored checks and the warnings a runner outcome logs."""

from __future__ import annotations

import json
import sys
import textwrap
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from gatectl import engine, history, runner
from tests.check_util import (
    OTHER,
    REPO,
    decisions,
    do_check,
    do_set,
    isolate,
    log_lines,
    rows,
    write_input,
)
from tests.command_util import config_file, run

PY = sys.executable
DENY_RULE = {
    "name": "r",
    "type": "rule",
    "when": [{"path": "x", "op": "exists"}],
    "then": "deny",
}


@pytest.fixture
def sdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def script_check(tmp_path: Path, name: str, body: str, **extra: Any) -> dict[str, Any]:
    path = tmp_path / f"{name}.py"
    path.write_text(textwrap.dedent(body))
    return {"name": name, "type": "script", "argv": [PY, str(path)], **extra}


def sleeper(tmp_path: Path, name: str, seconds: float, **extra: Any) -> dict[str, Any]:
    return script_check(tmp_path, name, f"import time; time.sleep({seconds})", **extra)


def config(tmp_path: Path, policy: dict[str, Any], **top: Any) -> str:
    return config_file(tmp_path, {"policies": {"p": policy}, **top})


# --- R1: budget exhaustion is signalled out of band ---------------------------------------


def test_a_script_that_prints_not_started_does_not_end_the_later_script_checks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    liar = """
        import time
        print('{"reason": "not started"}', flush=True)
        time.sleep(30)
    """
    cfg = config(
        tmp_path,
        {
            "checks": [
                script_check(tmp_path, "s1", liar, timeout="500ms"),
                script_check(tmp_path, "s2", "raise SystemExit(11)"),
            ]
        },
    )
    do_set(capsys, cfg, "p", "enforced")
    code, doc, _ = do_check(capsys, cfg, "p", "--input", write_input(tmp_path, {}))
    assert code == 11 and doc["decision"] == "deny"
    assert [(c["name"], c["verdict"]) for c in doc["checks"]] == [
        ("s1", "escalate"),
        ("s2", "deny"),
    ]


# --- R2: at most 128 checks per policy ----------------------------------------------------


def many_rules(n: int) -> list[dict[str, Any]]:
    return [
        {
            "name": f"c{i:03d}",
            "type": "rule",
            "when": [{"path": "x", "op": "exists"}],
            "then": "allow",
        }
        for i in range(n)
    ]


def test_a_policy_with_128_checks_records_a_row_that_show_accepts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    cfg = config(tmp_path, {"checks": many_rules(128)})
    code, doc, _ = do_check(capsys, cfg, "p", "--input", write_input(tmp_path, {"x": 1}))
    assert code == 0 and len(doc["checks"]) == 128
    shown, out, _ = run(capsys, ["show", doc["decision_id"], "--config", cfg, "--json"])
    assert shown == 0 and len(json.loads(out)["checks"]) == 128


def test_a_policy_with_129_checks_is_a_config_error_naming_checks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    cfg = config(tmp_path, {"checks": many_rules(129)})
    src = write_input(tmp_path, {"x": 1})
    code, out, _ = run(capsys, ["check", "p", "--config", cfg, "--input", src])
    assert code == 2
    assert decisions(sdir) == []
    code, out, _ = run(capsys, ["validate", "--config", cfg])
    assert code == 2 and "invalid_value" in out and "policies.p.checks" in out


# --- R3: the deadline across per-repo overrides --------------------------------------------


def test_a_per_repo_override_timeout_replaces_the_policy_deadline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    cfg = config_file(
        tmp_path,
        {
            "policies": {"p": {"checks": [sleeper(tmp_path, "slow", 30, timeout="30s")]}},
            "defaults": {"record_reserve": "100ms"},
            "repos": {REPO: {"policies": {"p": {"timeout": "1s"}}}},
        },
    )
    started = time.monotonic()
    _, doc, _ = do_check(capsys, cfg, "p", "--input", write_input(tmp_path, {"repo": REPO}))
    assert time.monotonic() - started < 6
    assert doc["checks"][0]["reason"] == "timeout"
    assert doc["scope"] == REPO


def test_the_timeout_flag_beats_the_per_repo_override(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    cfg = config_file(
        tmp_path,
        {
            "policies": {"p": {"checks": [sleeper(tmp_path, "nap", 1.5)]}},
            "defaults": {"record_reserve": "100ms"},
            "repos": {REPO: {"policies": {"p": {"timeout": "1s"}}}},
        },
    )
    src = write_input(tmp_path, {"repo": REPO})
    _, doc, _ = do_check(capsys, cfg, "p", "--input", src)
    assert doc["checks"][0]["reason"] == "timeout"
    _, doc, _ = do_check(capsys, cfg, "p", "--input", src, "--timeout", "10")
    assert (doc["decision"], doc["checks"][0]["verdict"]) == ("allow", "allow")


def test_an_override_timeout_already_elapsed_is_counted_from_now_not_before(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = engine.Env
    monkeypatch.setattr(
        engine, "Env", lambda: real(monotonic=lambda: time.monotonic() + 10)
    )  # ten seconds have gone by when the repo becomes known
    cfg = config_file(
        tmp_path,
        {
            "policies": {"p": {"checks": [DENY_RULE, sleeper(tmp_path, "never", 30)]}},
            "defaults": {"record_reserve": "100ms"},
            "repos": {REPO: {"policies": {"p": {"timeout": "2s"}}}},
        },
    )
    code, doc, _ = do_check(
        capsys, cfg, "p", "--input", write_input(tmp_path, {"repo": REPO, "x": 1})
    )
    assert code == 0
    got = [(c["name"], c["verdict"], c["reason"], c["detail"]) for c in doc["checks"]]
    assert got == [("r", "deny", "check_denied", None), ("never", "skipped", None, None)]


# --- R3: applicability ---------------------------------------------------------------------

APPLIES = [{"path": "kind", "op": "eq", "value": "pr"}]


def applies_cfg(tmp_path: Path, **extra: Any) -> str:
    return config(tmp_path, {"checks": [DENY_RULE], "applies_when": APPLIES, **extra})


@pytest.mark.parametrize(
    "content",
    [{"x": 1}, {"kind": None, "x": 1}, [1], b"junk"],
)
def test_an_applies_when_that_errors_or_has_no_object_counts_as_applicable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, content: Any
) -> None:
    cfg = applies_cfg(tmp_path)
    _, doc, _ = do_check(capsys, cfg, "p", "--input", write_input(tmp_path, content))
    assert doc["reason"] != "not_applicable" and "decision_id" in doc


def test_an_indeterminate_scope_with_a_false_applies_when_escalates_input_invalid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    cfg = applies_cfg(tmp_path)
    src = write_input(tmp_path, {"kind": "other", "repo": 5})
    _, doc, _ = do_check(capsys, cfg, "p", "--input", src)
    assert (doc["decision"], doc["reason"], doc["checks"]) == ("escalate", "input_invalid", [])


def test_an_indeterminate_scope_records_a_null_state_rev_even_with_stored_rows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    cfg = config(tmp_path, {"checks": [DENY_RULE]})
    do_set(capsys, cfg, "p", "enforced", "--repo", OTHER)
    code, doc, _ = do_check(capsys, cfg, "p", "--input", write_input(tmp_path, {"repo": 5}))
    assert code == 13 and doc["state"] == "enforced"
    [row] = decisions(sdir)
    assert row["state_rev"] is None
    assert rows(sdir, "SELECT count(*) FROM policy_state")[0][0] == 1


# --- R3: warnings ------------------------------------------------------------------------


def test_another_invalid_policy_adds_the_config_problem_warning(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    cfg = config_file(
        tmp_path,
        {
            "policies": {
                "p": {"checks": [DENY_RULE]},
                "q": {"checks": [DENY_RULE], "bogus": 1},
            }
        },
    )
    _, doc, _ = do_check(capsys, cfg, "p", "--input", write_input(tmp_path, {"x": 1}))
    assert doc["warnings"] == ["config_problem"]


# --- R3, R13: the stored checks_json --------------------------------------------------------


def entries(n: int, detail_len: int, name_len: int = 20) -> list[engine.Entry]:
    return [
        engine.Entry(f"{i:04d}".ljust(name_len, "n"), "rule", "allow", None, "d" * detail_len, 1)
        for i in range(n)
    ]


def stored_details(text: str) -> set[int | None]:
    return {None if e["detail"] is None else len(e["detail"]) for e in json.loads(text)}


def test_checks_json_keeps_full_details_when_they_fit() -> None:
    text = engine._checks_json(entries(10, 1024))
    assert stored_details(text) == {1024}


def test_checks_json_shortens_details_to_256_when_1024_is_too_big() -> None:
    text = engine._checks_json(entries(100, 1024))
    assert stored_details(text) == {256} and len(text) <= history.CHECKS_MAX_BYTES


def test_checks_json_drops_details_when_256_is_still_too_big() -> None:
    text = engine._checks_json(entries(200, 1024))
    assert stored_details(text) == {None} and len(text) <= history.CHECKS_MAX_BYTES


def test_a_run_with_long_details_stores_a_row_that_stays_under_the_show_limit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    body = """
        import json
        print(json.dumps({"reason": "z" * 3000}))
        raise SystemExit(13)
    """
    checks = [script_check(tmp_path, f"s{i:02d}", body) for i in range(70)]
    cfg = config(tmp_path, {"checks": checks})
    _, doc, _ = do_check(capsys, cfg, "p", "--input", write_input(tmp_path, {}))
    [row] = decisions(sdir)
    assert len(row["checks_json"]) < history.CHECKS_MAX_BYTES
    assert len(json.loads(row["checks_json"])) == 70
    code, out, _ = run(capsys, ["show", doc["decision_id"], "--config", cfg, "--json"])
    assert code == 0 and len(json.loads(out)["checks"]) == 70


def test_an_agent_entry_stores_its_cache_key_but_never_prints_it() -> None:
    entry = engine.Entry("ai", "agent", "allow", None, None, 5, 0.9, True, cache_key="k" * 10)
    assert entry.stored()["cache_key"] == "k" * 10
    assert "cache_key" not in entry.printed()
    assert json.loads(engine._checks_json([entry]))[0]["cache_key"] == "k" * 10
    plain = engine.Entry("ai", "agent", "allow", None, None, 5, 0.9, False)
    assert "cache_key" not in plain.stored()


# --- R3: the stricter of the states before and after a failure -------------------------------


def test_a_failure_uses_the_stricter_of_the_state_before_and_after(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = config(tmp_path, {"checks": [DENY_RULE]})
    do_set(capsys, cfg, "p", "shadow")
    real = engine._checks_json

    def boom_after_enforcing(_: Any) -> str:
        monkeypatch.setattr(engine, "_checks_json", real)
        do_set(capsys, cfg, "p", "enforced")
        raise RuntimeError("bug")

    monkeypatch.setattr(engine, "_checks_json", boom_after_enforcing)
    code, _, err = run(
        capsys, ["check", "p", "--config", cfg, "--input", write_input(tmp_path, {})]
    )
    assert code == 1 and err == "gatectl: internal p\n"


def test_a_shadow_failure_keeps_the_entries_of_the_checks_that_ran(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = {**DENY_RULE, "name": "first", "then": "escalate"}
    cfg = config(tmp_path, {"checks": [first, {**DENY_RULE, "name": "second"}]})
    real = engine._rule_entry

    def second_raises(run_: Any, check: Any) -> Any:
        if check.name == "second":
            raise RuntimeError("bug")
        return real(run_, check)

    monkeypatch.setattr(engine, "_rule_entry", second_raises)
    code, doc, _ = do_check(capsys, cfg, "p", "--input", write_input(tmp_path, {"x": 1}))
    assert code == 0 and doc["error"] is not None
    assert [(c["name"], c["verdict"]) for c in doc["checks"]] == [("first", "escalate")]


# --- R12: a failure while building the run is a failure by state -----------------------------


def test_a_failure_between_reading_the_state_and_the_checks_follows_the_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = config(tmp_path, {"checks": [DENY_RULE]})
    from gatectl.config import LoadedConfig

    def boom(*_: Any, **__: Any) -> bool:
        raise RuntimeError("bug")

    monkeypatch.setattr(LoadedConfig, "warns_config_problem_for", boom)
    src = write_input(tmp_path, {"x": 1})
    code, doc, _ = do_check(capsys, cfg, "p", "--input", src)
    assert code == 0 and doc["error"] is not None and doc["state"] == "shadow"
    assert "decision_id" not in doc
    do_set(capsys, cfg, "p", "enforced")
    code, _, err = run(capsys, ["check", "p", "--config", cfg, "--input", src])
    assert code == 1 and err == "gatectl: internal p\n"


# --- R14: the warnings a runner outcome logs --------------------------------------------------


@pytest.mark.parametrize("flag", ["leader_unkilled", "pipes_held", "workdir_left"])
def test_a_runner_outcome_flag_is_logged_as_a_warning_event(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    flag: str,
) -> None:
    def stub(*_: Any, **__: Any) -> runner.ScriptOutcome:
        outcome = runner.ScriptOutcome("allow", None, None)
        return replace(outcome, **{flag: True})

    monkeypatch.setattr(runner, "run_script_check", stub)
    cfg = config(tmp_path, {"checks": [script_check(tmp_path, "s", "pass")]})
    code, doc, _ = do_check(capsys, cfg, "p", "--input", write_input(tmp_path, {}))
    assert code == 0 and doc["decision"] == "allow"
    [event] = log_lines(sdir)
    assert (event["event"], event["level"], event["message"]) == ("warning", "warn", flag)
    assert event["decision_id"] == doc["decision_id"]


# --- R15: record_input stores the canonical input, at most input_max_bytes --------------------


def test_record_input_stores_the_canonical_input_within_input_max_bytes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    cfg = config(
        tmp_path,
        {"checks": [DENY_RULE], "record_input": True},
        defaults={"input_max_bytes": 2000},
    )
    src = write_input(tmp_path, b'{ "b" : 1,  "a" : "\xc3\xa9" }')
    do_check(capsys, cfg, "p", "--input", src)
    [row] = decisions(sdir)
    assert row["input_json"] == '{"b":1,"a":"\\u00e9"}'
    big = write_input(tmp_path, {"x": "y" * 5000}, "big.json")
    do_check(capsys, cfg, "p", "--input", big)
    assert len(decisions(sdir)) == 2 and decisions(sdir)[-1]["input_json"] is None
