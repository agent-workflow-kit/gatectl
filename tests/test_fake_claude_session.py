"""The fake ``claude-session`` (tests/fakebin/): every scenario, its argv grammar and its calls.

Each scenario test runs the real fake as a process and checks its exit code and output; outputs
are validated against the pinned claude-session schemas and the agent verdict schema. The fake's
shapes are also compared with real claude-session output recorded at the pinned version
(``tests/pinned/*/samples``).
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from tests import pinned_schemas as pinned
from tests.fake_session import DECISION_ID, FAKE, NONCE, FakeSession, Result
from tests.schema_util import errors as gatectl_errors


@pytest.fixture
def fake(tmp_path: Path) -> FakeSession:
    return FakeSession(tmp_path / "fake")


def started(fake: FakeSession, *extra: str, **env: Any) -> dict[str, Any]:
    result = fake.start(*extra, **env)
    assert result.returncode == 0, result.stderr
    return result.json


def ran(fake: FakeSession, **env: Any) -> tuple[dict[str, Any], Result]:
    """start + exec --session-id for the standard gate-check call."""
    info = started(fake, **env)
    result = fake.run(*fake.exec_args(info), **env)
    return info, result


def status(fake: FakeSession, info: dict[str, Any], **env: Any) -> dict[str, Any]:
    result = fake.run("status", info["csession_id"], "--json", **env)
    assert result.returncode == 0, result.stderr
    assert pinned.errors("status", result.json) == []
    return result.json


def stop_process(proc: subprocess.Popen[str]) -> None:
    """End a process this test started, by its exact PID only."""
    if proc.poll() is None:
        proc.send_signal(signal.SIGKILL)
    proc.communicate()


def wait_until(predicate: Any, what: str, limit: float = 10.0) -> None:
    end = time.monotonic() + limit
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


def agent_verdict_errors(data: bytes) -> list[str]:
    return gatectl_errors("agent-verdict", json.loads(data))


# start


def test_start_prints_the_session_the_run_and_the_exec_argv(fake: FakeSession) -> None:
    result = fake.start()
    assert result.returncode == 0
    out = result.json
    assert pinned.errors("start", out) == []
    assert out["run"] == 1
    assert out["argv"] == [str(FAKE), "exec", "--session-id", out["csession_id"], "--run", "1"]
    assert out["forked_from"] is None
    assert out["env_inherit"] is False


def test_start_output_has_the_same_keys_as_real_claude_session(fake: FakeSession) -> None:
    assert set(started(fake)) == set(pinned.sample("start"))


def test_start_ids_are_distinct_and_match_the_id_grammar(fake: FakeSession) -> None:
    ids = {started(fake)["csession_id"] for _ in range(5)}
    assert len(ids) == 5


def test_start_requires_json(fake: FakeSession) -> None:
    args = [a for a in fake.start_args() if a != "--json"]
    result = fake.run(*args)
    assert result.returncode == 2
    assert "requires --json" in result.stderr


def test_start_refuses_a_headless_session_with_neither_skill_nor_prompt(fake: FakeSession) -> None:
    result = fake.run("start", "--kind", "gate-check", "--mode", "headless", "--json")
    assert result.returncode == 2
    assert result.json["error"]["code"] == "usage"


@pytest.mark.parametrize(
    "bad",
    [
        ["--timeout", "0"],
        ["--label", "Bad=x"],
        ["--label", "nospace here=x"],
        ["--setting-sources", "bogus"],
        ["--env-allowlist-only", "1BAD"],
        ["--skill", "bad skill"],
        ["--prompt-file", "/nonexistent/prompt.md"],
        ["--sandbox", "sometimes"],
    ],
)
def test_start_rejects_values_outside_the_grammar(fake: FakeSession, bad: list[str]) -> None:
    result = fake.start(*bad)
    assert result.returncode == 2, result.stdout
    assert pinned.errors("error", result.json) == []
    assert result.json["error"]["code"] == "usage"


def test_unknown_flags_and_abbreviations_are_usage_errors(fake: FakeSession) -> None:
    assert fake.start("--no-such-flag").returncode == 2
    assert fake.start("--sett", "").returncode == 2  # allow_abbrev is off, as in claude-session
    assert fake.run("status", "--json").returncode == 2  # missing id


def test_unimplemented_commands_are_usage_errors(fake: FakeSession) -> None:
    result = fake.run("reconcile", "--json")
    assert result.returncode == 2
    assert "does not implement" in result.json["error"]["message"]


def test_the_start_flags_gatectl_passes_are_all_accepted(fake: FakeSession) -> None:
    result = fake.start("--repo=github.com/org/repo", "--model=haiku", "--decision-id", "gd-b")
    assert result.returncode == 0, result.stderr
    out = status(fake, result.json)
    assert out["run"]["model"] == "haiku"
    assert out["repo"] == "github.com/org/repo"
    assert out["run"]["decision_ids"] == [DECISION_ID, "gd-b"]
    assert out["run"]["skill"] == "gatectl:gate-check"
    assert out["run"]["input_files"] == ["input.json"]
    assert "decision=" + DECISION_ID in out["labels"]
    assert "kind=gate-check" in out["labels"]


# exec: scenarios

# scenario -> (exit code, outcome, end reason, report status or None, report artifact name)
SCENARIOS: dict[str, tuple[int, str, str, str | None, str | None]] = {
    "valid": (0, "done", "normal", "done", "verdict.json"),
    "nonce_mismatch": (0, "done", "normal", "done", "verdict.json"),
    "wrong_schema": (0, "done", "normal", "done", "verdict.json"),
    "no_artifact": (0, "done", "normal", "done", None),
    "missing_skill": (0, "done", "normal", "done", "verdict.json"),
    "implicit_done": (0, "done", "normal", "done", "result.md"),
    "done_timeout_end": (0, "done", "timeout", "done", "verdict.json"),
    "unreported": (14, "exited-unreported", "no_report", None, None),
    "unreported_no_result": (14, "exited-unreported", "no_result", None, None),
    "timeout": (16, "timeout", "timeout", None, None),
    "needs_input": (13, "needs-input", "normal", "needs-input", None),
    "blocked": (13, "blocked", "normal", "blocked", None),
    "failed": (18, "failed", "normal", "failed", None),
    "killed": (15, "killed", "signal_kill", None, None),
    "lost": (17, "lost", "lost", None, None),
    "status_sha_mismatch": (0, "done", "normal", "done", "verdict.json"),
    "status_size_mismatch": (0, "done", "normal", "done", "verdict.json"),
    "status_name_mismatch": (0, "done", "normal", "done", "verdict.json"),
}


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_scenario_exit_code_and_outcome_object(fake: FakeSession, scenario: str) -> None:
    code, outcome, end_reason, report_status, artifact_name = SCENARIOS[scenario]
    fake.scenario = scenario
    outfile = fake.root / "outcome.json"
    info = started(fake)
    result = fake.run(*fake.exec_args(info, "--outcome-file", str(outfile)))
    assert result.returncode == code, result.stderr
    out = result.json
    assert pinned.errors("exec", out) == []
    assert (out["outcome"], out["end_reason"], out["exit_code"]) == (outcome, end_reason, code)
    assert out["csession_id"] == info["csession_id"]
    assert out["run"] == 1
    assert out["phase"] == "session"
    assert (out["report"] or {}).get("status") == report_status
    assert ((out["report"] or {}).get("artifact") or {}).get("name") == artifact_name
    assert json.loads(outfile.read_text(encoding="utf-8")) == out  # same object in the file


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_scenario_status_validates_and_agrees_with_exec(fake: FakeSession, scenario: str) -> None:
    code, outcome, end_reason, _, _ = SCENARIOS[scenario]
    fake.scenario = scenario
    info, result = ran(fake)
    run = status(fake, info)["run"]
    assert (run["outcome"], run["end_reason"], run["exit_code"]) == (outcome, end_reason, code)
    assert run["state"] == result.json["state"]
    if not scenario.startswith("status_"):  # those deliberately make status lie
        assert run["report"] == result.json["report"]


def _artifact(fake: FakeSession, info: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    artifact = status(fake, info)["run"]["report"]["artifact"]
    return artifact, Path(artifact["path"]).read_bytes()


def test_valid_scenario_artifact_matches_status_and_the_verdict_schema(fake: FakeSession) -> None:
    info, _ = ran(fake)
    artifact, data = _artifact(fake, info)
    assert artifact["sha256"] == hashlib.sha256(data).hexdigest()
    assert artifact["size"] == len(data)
    assert agent_verdict_errors(data) == []
    verdict = json.loads(data)
    assert verdict["nonce"] == NONCE  # echoed from the prompt file
    assert (verdict["decision"], verdict["confidence"]) == ("allow", 0.95)


def test_valid_scenario_content_follows_the_environment(fake: FakeSession) -> None:
    env = {
        "FAKE_CS_DECISION": "deny",
        "FAKE_CS_CONFIDENCE": "0.3",
        "FAKE_CS_REASONS": '["a", "b"]',
        "FAKE_CS_NONCE": "f" * 32,
    }
    info, _ = ran(fake, **env)
    _, data = _artifact(fake, info)
    assert json.loads(data) == {
        "schema_version": 1,
        "nonce": "f" * 32,
        "decision": "deny",
        "confidence": 0.3,
        "reasons": ["a", "b"],
    }


def test_nonce_mismatch_is_schema_valid_but_not_the_prompts_nonce(fake: FakeSession) -> None:
    fake.scenario = "nonce_mismatch"
    info, _ = ran(fake)
    _, data = _artifact(fake, info)
    assert agent_verdict_errors(data) == []
    assert json.loads(data)["nonce"] != NONCE


def test_wrong_schema_artifact_fails_the_verdict_schema(fake: FakeSession) -> None:
    fake.scenario = "wrong_schema"
    info, _ = ran(fake)
    _, data = _artifact(fake, info)
    assert agent_verdict_errors(data)


def test_missing_skill_artifact_is_not_json(fake: FakeSession) -> None:
    fake.scenario = "missing_skill"
    info, result = ran(fake)
    assert result.returncode == 0
    _, data = _artifact(fake, info)
    with pytest.raises(json.JSONDecodeError):
        json.loads(data)


def test_implicit_done_reports_implicit_true_with_a_result_md_artifact(fake: FakeSession) -> None:
    fake.scenario = "implicit_done"
    _, result = ran(fake)
    report = result.json["report"]
    assert report["implicit"] is True
    assert report["summary"] is None
    assert report["artifact"]["name"] == "result.md"


def test_explicit_reports_are_not_implicit(fake: FakeSession) -> None:
    _, result = ran(fake)
    assert result.json["report"]["implicit"] is False


def test_done_run_whose_end_reason_is_timeout_still_exits_zero(fake: FakeSession) -> None:
    fake.scenario = "done_timeout_end"
    info, result = ran(fake)
    assert result.returncode == 0
    assert (result.json["outcome"], result.json["end_reason"]) == ("done", "timeout")
    _, data = _artifact(fake, info)
    assert agent_verdict_errors(data) == []


@pytest.mark.parametrize(
    ("scenario", "field"),
    [
        ("status_sha_mismatch", "sha256"),
        ("status_size_mismatch", "size"),
        ("status_name_mismatch", "name"),
    ],
)
def test_status_mismatch_scenarios_differ_from_the_frozen_file(
    fake: FakeSession, scenario: str, field: str
) -> None:
    info, _ = ran(fake)  # the run is the valid one
    honest, data = _artifact(fake, info)
    assert honest["sha256"] == hashlib.sha256(data).hexdigest()
    fake.scenario = scenario
    lying, _ = _artifact(fake, info)
    assert lying[field] != honest[field]
    others = {k: v for k, v in lying.items() if k != field}
    assert others == {k: v for k, v in honest.items() if k != field}


def test_exit_zero_with_an_outcome_other_than_done(fake: FakeSession) -> None:
    fake.scenario = "exit0_not_done"
    info, result = ran(fake)
    assert result.returncode == 0
    assert result.json["exit_code"] == 0
    assert result.json["outcome"] == "blocked"
    # claude-session never does this (its exit_code rules forbid it), so the pinned schema
    # rejects the object: the fake is deliberately off-schema here, and says so.
    assert pinned.errors("exec", result.json)
    run = fake.run("status", info["csession_id"], "--json").json["run"]
    assert (run["outcome"], run["exit_code"]) == ("blocked", 0)  # status agrees: same off-schema


def test_exit_zero_outcome_is_configurable(fake: FakeSession) -> None:
    fake.scenario = "exit0_not_done"
    _, result = ran(fake, FAKE_CS_EXIT0_OUTCOME="exited-unreported")
    assert (result.returncode, result.json["outcome"], result.json["report"]) == (
        0,
        "exited-unreported",
        None,
    )


# launch failures


@pytest.mark.parametrize(
    ("scenario", "end_reason", "hint_words"),
    [
        ("sandbox_unavailable", "sandbox_unavailable", "bubblewrap"),
        ("claude_not_found", "claude_not_found", "Install Claude Code".lower()),
        ("unsafe_setting_sources", "unsafe_setting_sources", None),
    ],
)
def test_launch_failure_at_start_exits_12_with_the_launch_failed_envelope(
    fake: FakeSession, scenario: str, end_reason: str, hint_words: str | None
) -> None:
    fake.scenario = scenario
    outfile = fake.root / "outcome.json"
    result = fake.start("--outcome-file", str(outfile))
    assert result.returncode == 12
    error = result.json
    assert pinned.errors("error", error) == []
    assert error["error"]["code"] == "launch_failed"
    assert error["error"]["end_reason"] == end_reason
    assert error["error"]["run"] == 1
    session_id = error["error"]["csession_id"]
    assert result.stderr.startswith("claude-session: error: ")
    if hint_words:
        assert hint_words in (error["error"]["hint"] or "").lower()
    # the session was allocated, ended not-started, and the outcome file has the outcome object
    info = {"csession_id": session_id}
    run = status(fake, info)["run"]
    assert (run["outcome"], run["end_reason"], run["exit_code"]) == ("not-started", end_reason, 12)
    assert pinned.errors("exec", json.loads(outfile.read_text(encoding="utf-8"))) == []


@pytest.mark.parametrize("scenario", ["sandbox_unavailable", "claude_not_found"])
def test_launch_failure_at_adoption_prints_a_launch_phase_outcome(
    fake: FakeSession, scenario: str
) -> None:
    info = started(fake)  # valid at start
    fake.scenario = scenario + "@exec"
    result = fake.run(*fake.exec_args(info))
    assert result.returncode == 12
    assert pinned.errors("exec", result.json) == []
    assert result.json["phase"] == "launch"
    assert (result.json["outcome"], result.json["end_reason"]) == ("not-started", scenario)
    assert result.json["state"] == "not-started"
    assert result.json["report"] is None


def test_unsafe_setting_sources_at_adoption(fake: FakeSession) -> None:
    info = started(fake)
    fake.scenario = "unsafe_setting_sources@exec"
    result = fake.run(*fake.exec_args(info))
    assert result.returncode == 12
    assert result.json["end_reason"] == "unsafe_setting_sources"


def test_a_failed_start_session_cannot_be_adopted_and_can_be_forgotten(fake: FakeSession) -> None:
    fake.scenario = "sandbox_unavailable"
    session_id = fake.start().json["error"]["csession_id"]
    adopt = fake.run("exec", "--session-id", session_id, "--run", "1", "--json")
    assert adopt.returncode == 20
    assert adopt.json["error"] == {
        "code": "refused",
        "message": f"cannot adopt {session_id}: expired",
        "reason": "expired",
    }
    assert fake.run("forget", session_id, "--json").returncode == 0


def test_a_non_empty_setting_sources_list_is_refused_for_gate_check_whatever_the_scenario(
    fake: FakeSession,
) -> None:
    result = fake.start("--setting-sources", "user")
    assert result.returncode == 12
    assert result.json["error"]["end_reason"] == "unsafe_setting_sources"
    assert "got: user" in result.json["error"]["message"]


def test_launch_failures_are_listed_like_any_session(fake: FakeSession) -> None:
    fake.scenario = "sandbox_unavailable"
    session_id = fake.start().json["error"]["csession_id"]
    listed = fake.run("list", "--label", f"decision={DECISION_ID}", "--json").json
    assert [s["csession_id"] for s in listed["sessions"]] == [session_id]
    assert listed["sessions"][0]["last_end_reason"] == "sandbox_unavailable"


# exec: adoption refusals


def test_exec_refuses_the_wrong_run_and_a_second_adoption(fake: FakeSession) -> None:
    info = started(fake)
    wrong = fake.run("exec", "--session-id", info["csession_id"], "--run", "2", "--json")
    assert (wrong.returncode, wrong.json["error"]["reason"]) == (20, "expired")
    assert fake.run(*fake.exec_args(info)).returncode == 0
    again = fake.run(*fake.exec_args(info))
    assert (again.returncode, again.json["error"]["reason"]) == (20, "expired")  # final run


def test_exec_refuses_a_run_that_is_already_adopted(fake: FakeSession) -> None:
    fake.scenario = "hang"
    info = started(fake)
    proc = fake.popen(*fake.exec_args(info))
    try:
        wait_until(
            lambda: status(fake, info)["live"] and status(fake, info)["run"]["wrapper_pid"],
            "adoption",
        )
        second = fake.run(*fake.exec_args(info))
        assert (second.returncode, second.json["error"]["reason"]) == (20, "already_adopted")
    finally:
        stop_process(proc)


def test_exec_unknown_session_and_extra_flags(fake: FakeSession) -> None:
    unknown = fake.run("exec", "--session-id", "cs-aaaaaaaa", "--json")
    assert (unknown.returncode, unknown.json["error"]["code"]) == (10, "not_found")
    info = started(fake)
    extra = fake.run(*fake.exec_args(info, "--kind", "x"))
    assert extra.returncode == 2
    assert fake.run("exec", "--json").returncode == 2  # plain exec is not implemented


# status and list


def test_pending_status_shape_matches_real_claude_session(fake: FakeSession) -> None:
    info = started(fake)
    out = status(fake, info)
    real = pinned.sample("status_pending")
    assert out["pending"] is True and out["live"] is True and out["state"] == "starting"
    assert set(out) == set(real)
    assert set(out["run"]) == set(real["run"])
    assert set(out["recent_events"][0]) == set(real["recent_events"][0])
    assert out["run"]["started_at"] is None and out["run"]["cwd"] is None
    assert out["tainted"] is real["tainted"] is True


def test_final_status_shape_matches_real_claude_session(fake: FakeSession) -> None:
    fake.scenario = "unreported"
    info, _ = ran(fake)
    out = status(fake, info)
    real = pinned.sample("status_final")
    assert set(out) == set(real)
    assert set(out["run"]) == set(real["run"])
    assert out["live"] is False
    assert [e["to_state"] for e in out["recent_events"]][-1] == "exited-unreported"
    assert out["recent_events"][-1]["final"] is True


def test_outcome_object_has_the_same_keys_as_real_claude_session(fake: FakeSession) -> None:
    fake.scenario = "unreported"
    _, result = ran(fake)
    assert set(result.json) == set(pinned.sample("outcome_unreported"))


def test_status_sandbox_active_follows_the_run_and_the_override(fake: FakeSession) -> None:
    info, _ = ran(fake)
    assert status(fake, info)["run"]["sandbox_active"] is True
    assert status(fake, info, FAKE_CS_SANDBOX_ACTIVE="0")["run"]["sandbox_active"] is False


def test_status_unknown_session_and_prefixes(fake: FakeSession) -> None:
    info = started(fake)
    unknown = fake.run("status", "cs-aaaaaaaa", "--json")
    assert (unknown.returncode, unknown.json["error"]["code"]) == (10, "not_found")
    assert pinned.errors("error", unknown.json) == []
    prefix = info["csession_id"][3:9].upper()  # case-insensitive, cs- optional
    assert fake.run("status", prefix, "--json").json["csession_id"] == info["csession_id"]
    assert fake.run("status", "cs-ab", "--json").returncode == 2  # prefix too short


def test_list_filters_by_label_and_state_and_validates(fake: FakeSession) -> None:
    mine = started(fake)
    other = fake.run(*fake.start_args("--label", "owner=someone")).json  # same labels + one more
    done_id = started(fake)
    fake.run(*fake.exec_args(done_id))
    result = fake.run("list", "--label", "owner=gatectl", "--label", "policy=reviewer", "--json")
    assert result.returncode == 0
    assert pinned.errors("list", result.json) == []
    ids = {s["csession_id"] for s in result.json["sessions"]}
    assert ids == {mine["csession_id"], other["csession_id"], done_id["csession_id"]}
    none = fake.run("list", "--label", "owner=nobody", "--json").json
    assert none == {"sessions": []}
    pending = fake.run("list", "--pending", "--json").json["sessions"]
    assert {s["csession_id"] for s in pending} == {mine["csession_id"], other["csession_id"]}
    finals = fake.run("list", "--state", "exited", "--json").json["sessions"]
    assert [s["csession_id"] for s in finals] == [done_id["csession_id"]]
    assert finals[0]["last_outcome"] == "done" and finals[0]["report_status"] == "done"
    assert fake.run("list", "--limit", "0", "--json").returncode == 2


def test_list_item_keys_match_real_claude_session(fake: FakeSession) -> None:
    started(fake)
    item = fake.run("list", "--json").json["sessions"][0]
    assert set(item) == set(pinned.sample("list")["sessions"][0])


# forget


def test_forget_refuses_a_pending_session_as_the_real_tool_does(fake: FakeSession) -> None:
    info = started(fake)
    result = fake.run("forget", info["csession_id"], "--actor", "auto:gatectl", "--json")
    assert result.returncode == 20
    assert pinned.errors("error", result.json) == []
    assert result.json["error"]["code"] == "refused"
    assert result.json["error"]["reason"] == "live"
    assert status(fake, info)["live"] is True  # nothing changed


def test_forget_refuses_a_live_session(fake: FakeSession) -> None:
    fake.scenario = "hang"
    info = started(fake)
    proc = fake.popen(*fake.exec_args(info))
    try:
        wait_until(lambda: status(fake, info)["run"]["wrapper_pid"], "adoption")
        result = fake.run("forget", info["csession_id"], "--json")
        assert (result.returncode, result.json["error"]["reason"]) == (20, "live")
    finally:
        stop_process(proc)


def test_forget_hides_a_final_session(fake: FakeSession) -> None:
    info, _ = ran(fake)
    result = fake.run(
        "forget",
        info["csession_id"],
        "--actor",
        "auto:gatectl",
        "--decision-id",
        DECISION_ID,
        "--json",
    )
    assert result.returncode == 0
    assert pinned.errors("forget", result.json) == []
    assert result.json["dry_run"] is False and result.json["skipped"] == []
    assert [e["csession_id"] for e in result.json["forgotten"]] == [info["csession_id"]]
    assert set(result.json["forgotten"][0]) == set(pinned.sample("forget_ok")["forgotten"][0])
    for command in (["status"], ["forget"], ["stop"]):
        later = fake.run(*command, info["csession_id"], "--json")
        assert (later.returncode, later.json["error"]["code"]) == (10, "not_found")
    assert fake.run("list", "--json").json == {"sessions": []}


def test_forget_dry_run_changes_nothing(fake: FakeSession) -> None:
    info, _ = ran(fake)
    dry = fake.run("forget", info["csession_id"], "--dry-run", "--json")
    assert dry.returncode == 0 and dry.json["dry_run"] is True
    assert status(fake, info)["live"] is False  # still known


def test_forget_bulk_mode_is_not_implemented(fake: FakeSession) -> None:
    assert fake.run("forget", "--older-than", "1d", "--json").returncode == 2
    assert fake.run("forget", "--json").returncode == 2


# stop


def test_stop_cancels_a_pending_run(fake: FakeSession) -> None:
    info = started(fake)
    result = fake.run(
        "stop", info["csession_id"], "--grace", "2s", "--actor", "auto:gatectl", "--json"
    )
    assert result.returncode == 0
    assert pinned.errors("stop", result.json) == []
    assert result.json == pinned.sample("stop_cancel") | {"csession_id": info["csession_id"]}
    assert fake.run("forget", info["csession_id"], "--json").returncode == 0  # now final


def test_stop_of_a_final_run_reports_already_final(fake: FakeSession) -> None:
    info, _ = ran(fake)
    result = fake.run("stop", info["csession_id"], "--grace", "2s", "--json")
    assert result.returncode == 0
    assert pinned.errors("stop", result.json) == []
    assert result.json["already_final"] is True and result.json["signals"] == []
    assert result.json["outcome"] == "done"


def test_stop_terminates_a_live_run_with_sigterm(fake: FakeSession) -> None:
    fake.scenario = "hang"
    info = started(fake)
    proc = fake.popen(*fake.exec_args(info))
    try:
        wait_until(lambda: status(fake, info)["run"]["wrapper_pid"], "adoption")
        pid = status(fake, info)["run"]["wrapper_pid"]
        assert pid == proc.pid
        result = fake.run("stop", info["csession_id"], "--grace", "5s", "--json")
        out, _ = proc.communicate(timeout=10)
    finally:
        stop_process(proc)
    assert result.returncode == 0
    assert pinned.errors("stop", result.json) == []
    assert result.json["signals"] == [{"pid": pid, "role": "wrapper", "signal": "SIGTERM"}]
    assert (result.json["outcome"], result.json["end_reason"]) == ("killed", "stopped")
    assert result.json["run_exit_code"] == 15 and result.json["recorded_by_stop"] is False
    outcome = json.loads(out)  # exec printed its own outcome object on the way out
    assert pinned.errors("exec", outcome) == []
    assert (proc.returncode, outcome["end_reason"]) == (15, "stopped")


def test_stop_escalates_to_sigkill_when_exec_ignores_sigterm(fake: FakeSession) -> None:
    fake.scenario = "hang_ignore_term"
    info = started(fake)
    proc = fake.popen(*fake.exec_args(info))
    try:
        wait_until(lambda: status(fake, info)["run"]["wrapper_pid"], "adoption")
        result = fake.run("stop", info["csession_id"], "--grace", "300ms", "--json")
        proc.communicate(timeout=10)
    finally:
        stop_process(proc)
    assert result.returncode == 0
    assert pinned.errors("stop", result.json) == []
    assert [s["signal"] for s in result.json["signals"]] == ["SIGTERM", "SIGKILL"]
    assert result.json["recorded_by_stop"] is True
    assert (result.json["outcome"], result.json["end_reason"]) == ("killed", "stopped")
    assert proc.returncode == -signal.SIGKILL


def test_stop_unknown_session_is_not_found(fake: FakeSession) -> None:
    result = fake.run("stop", "cs-aaaaaaaa", "--json")
    assert (result.returncode, result.json["error"]["code"]) == (10, "not_found")


# exec: hang and signals


@pytest.mark.parametrize(
    ("sig", "reason"),
    [
        (signal.SIGTERM, "forwarded_term"),
        (signal.SIGHUP, "forwarded_hup"),
        (signal.SIGINT, "forwarded_int"),
    ],
)
def test_a_signal_during_a_hang_ends_the_run_killed(
    fake: FakeSession, sig: signal.Signals, reason: str
) -> None:
    fake.scenario = "hang"
    info = started(fake)
    proc = fake.popen(*fake.exec_args(info))
    try:
        wait_until(lambda: status(fake, info)["run"]["wrapper_pid"], "adoption")
        wait_until(lambda: status(fake, info)["state"] == "working", "the session phase")
        proc.send_signal(sig)
        out, _ = proc.communicate(timeout=10)
    finally:
        stop_process(proc)
    outcome = json.loads(out)
    assert pinned.errors("exec", outcome) == []
    assert (proc.returncode, outcome["outcome"], outcome["end_reason"]) == (15, "killed", reason)


def test_a_hang_ends_itself_after_the_hang_limit(fake: FakeSession) -> None:
    fake.scenario = "hang"
    info = started(fake)
    result = fake.run(*fake.exec_args(info), FAKE_CS_HANG_MAX="0.2", timeout=10)
    assert result.returncode == 16 and result.json["end_reason"] == "timeout"


def test_hang_ignoring_sigterm_survives_it_and_ends_by_its_limit(fake: FakeSession) -> None:
    fake.scenario = "hang_ignore_term"
    info = started(fake)
    proc = fake.popen(*fake.exec_args(info), FAKE_CS_HANG_MAX="3")
    try:
        wait_until(lambda: status(fake, info)["state"] == "working", "the session phase")
        proc.send_signal(signal.SIGTERM)
        time.sleep(0.3)
        assert proc.poll() is None  # still running: SIGTERM is ignored
        proc.communicate(timeout=10)
    finally:
        stop_process(proc)
    assert proc.returncode == 16


def test_exec_delay_keeps_the_run_live_for_a_while(fake: FakeSession) -> None:
    info = started(fake)
    proc = fake.popen(*fake.exec_args(info), FAKE_CS_DELAY_EXEC="1")
    try:
        wait_until(lambda: status(fake, info)["state"] == "working", "the session phase")
        assert status(fake, info)["live"] is True
        proc.communicate(timeout=10)
    finally:
        stop_process(proc)
    assert proc.returncode == 0
    assert status(fake, info)["live"] is False


def test_a_wrapper_killed_without_finalizing_is_found_lost(fake: FakeSession) -> None:
    fake.scenario = "hang"
    info = started(fake)
    proc = fake.popen(*fake.exec_args(info))
    try:
        wait_until(lambda: status(fake, info)["state"] == "working", "the session phase")
        proc.send_signal(signal.SIGKILL)
        proc.communicate(timeout=10)
        run = status(fake, info)["run"]
    finally:
        stop_process(proc)
    assert (run["outcome"], run["end_reason"], run["exit_code"]) == ("lost", "lost", 17)


# per-command behaviors


@pytest.mark.parametrize("command", ["start", "status", "list", "stop", "forget"])
@pytest.mark.parametrize(
    ("behavior", "returncode", "stdout_json"),
    [
        ("fail", 12, True),
        ("fail:1", 1, True),
        ("garbage", 0, False),
        ("empty", 0, "empty"),
        ("json_wrong", 0, True),
    ],
)
def test_per_command_behaviors(
    fake: FakeSession, command: str, behavior: str, returncode: int, stdout_json: bool | str
) -> None:
    info = started(fake)
    argv = {
        "start": fake.start_args(),
        "status": ["status", info["csession_id"], "--json"],
        "list": ["list", "--json"],
        "stop": ["stop", info["csession_id"], "--json"],
        "forget": ["forget", info["csession_id"], "--json"],
    }[command]
    env: dict[str, Any] = {f"FAKE_CS_BEHAVIOR_{command.upper()}": behavior}
    result = fake.run(*argv, **env)
    assert result.returncode == returncode
    if stdout_json == "empty":
        assert result.stdout == ""
    elif stdout_json:
        assert result.json is not None
    else:
        with pytest.raises(json.JSONDecodeError):
            json.loads(result.stdout)
    if behavior.startswith("fail"):
        assert result.json["error"]["code"] in ("failed", "internal")


def test_a_failing_exec_behavior_leaves_the_run_adopted_and_unfinished(fake: FakeSession) -> None:
    info = started(fake)
    result = fake.run(*fake.exec_args(info), FAKE_CS_BEHAVIOR_EXEC="fail")
    assert result.returncode == 12
    assert pinned.errors("error", result.json) == []


def test_a_hanging_call_is_signalled_by_its_exact_pid_and_leaves_no_state_change(
    fake: FakeSession,
) -> None:
    info = started(fake)
    proc = fake.popen("status", info["csession_id"], "--json", FAKE_CS_BEHAVIOR_STATUS="hang")
    try:
        wait_until(lambda: any(c["pid"] == proc.pid for c in fake.calls()), "the call record")
        proc.send_signal(signal.SIGTERM)
        proc.communicate(timeout=10)
    finally:
        stop_process(proc)
    assert proc.returncode == -signal.SIGTERM
    assert status(fake, info)["pending"] is True


def test_start_hang_after_allocate_leaves_a_pending_session(fake: FakeSession) -> None:
    proc = fake.popen(*fake.start_args(), FAKE_CS_BEHAVIOR_START="hang_after_allocate")
    try:
        wait_until(
            lambda: fake.run("list", "--pending", "--json").json["sessions"],
            "the allocated session",
        )
        proc.send_signal(signal.SIGTERM)
        out, _ = proc.communicate(timeout=10)
    finally:
        stop_process(proc)
    assert out == ""  # it never printed the start object
    (item,) = fake.run("list", "--json").json["sessions"]
    assert item["pending"] is True


def test_unknown_scenarios_and_behaviors_fail_loudly(fake: FakeSession) -> None:
    fake.scenario = "no_such_scenario"
    bad = fake.start()
    assert bad.returncode == 1
    assert "unknown FAKE_CS_SCENARIO" in bad.stderr
    fake.scenario = "valid@exec"  # the @exec suffix is for launch failures only
    assert fake.start().returncode == 1
    fake.scenario = "valid"
    assert fake.start(FAKE_CS_BEHAVIOR_START="nonsense").returncode == 1


def test_the_state_directory_is_required(fake: FakeSession) -> None:
    done = subprocess.run(  # noqa: S603
        fake.command("list", "--json"),
        capture_output=True,
        text=True,
        env={"PATH": os.environ["PATH"], "HOME": os.environ["HOME"]},
        timeout=30,
    )
    assert done.returncode == 1


# recorded calls


def test_every_call_is_recorded_with_its_exact_argv_and_exit_code(fake: FakeSession) -> None:
    info = started(fake)
    exec_args = fake.exec_args(info)
    fake.run(*exec_args)
    fake.run("status", info["csession_id"], "--json")
    fake.run("forget", info["csession_id"], "--actor", "auto:gatectl", "--decision-id", DECISION_ID)
    fake.run("status", info["csession_id"], "--json")
    calls = fake.calls()
    assert [c["argv"] for c in calls] == [
        fake.start_args(),
        exec_args,
        ["status", info["csession_id"], "--json"],
        ["forget", info["csession_id"], "--actor", "auto:gatectl", "--decision-id", DECISION_ID],
        ["status", info["csession_id"], "--json"],
    ]
    assert [c["code"] for c in calls] == [0, 0, 0, 0, 10]
    assert all(c["scenario"] == "valid" for c in calls)


def test_the_log_keeps_an_empty_string_argument_and_records_the_call_before_it_hangs(
    fake: FakeSession,
) -> None:
    info = started(fake)
    proc = fake.popen("status", info["csession_id"], "--json", FAKE_CS_BEHAVIOR_STATUS="hang")
    try:
        wait_until(lambda: any(c["pid"] == proc.pid for c in fake.calls()), "the call record")
        record = next(c for c in fake.calls() if c["pid"] == proc.pid)
        assert record["code"] is None  # no exit line yet: the call is still running
    finally:
        stop_process(proc)
    start = fake.calls()[0]["argv"]
    assert "--setting-sources" in start and start[start.index("--setting-sources") + 1] == ""
    assert start[start.index("--env-allowlist-only") + 1] == ""


def test_the_log_names_the_environment_without_its_values(fake: FakeSession) -> None:
    started(fake, SECRET_TOKEN_FOR_TEST="hunter2")
    (call,) = fake.calls()
    assert "SECRET_TOKEN_FOR_TEST" in call["env_names"]
    assert "hunter2" not in fake.log.read_text(encoding="utf-8")
    assert call["home"] == os.environ["HOME"]  # the isolated home, never the real one


def test_concurrent_calls_do_not_interleave_log_lines(fake: FakeSession) -> None:
    info = started(fake)
    procs = [fake.popen("status", info["csession_id"], "--json") for _ in range(8)]
    for proc in procs:
        proc.communicate(timeout=30)
    lines = fake.log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 + 16  # start (call + exit) and 8 x (call + exit)
    assert all(isinstance(json.loads(line), dict) for line in lines)


def test_without_a_log_variable_nothing_is_recorded(fake: FakeSession) -> None:
    result = subprocess.run(  # noqa: S603
        fake.command(*fake.start_args()),
        capture_output=True,
        text=True,
        env={k: v for k, v in fake.env().items() if k != "FAKE_CS_LOG"},
        timeout=30,
    )
    assert result.returncode == 0
    assert not fake.log.exists()


def test_version_flag_names_the_pinned_version() -> None:
    done = subprocess.run(  # noqa: S603
        [str(FAKE), "--version"], capture_output=True, text=True, timeout=30
    )
    assert done.returncode == 0
    assert pinned.PINNED_VERSION in done.stdout


def test_the_fake_is_executable_and_has_a_python_shebang() -> None:
    assert os.access(FAKE, os.X_OK)
    assert FAKE.read_text(encoding="utf-8").startswith("#!/usr/bin/env python3\n")
    assert pinned.PINNED_VERSION in FAKE.read_text(encoding="utf-8").split('"""')[1]
