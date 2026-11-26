"""An agent check's run sequence against the fake claude-session: the argv of every call, the
clean-up after every failure, the environment, and what is left behind (nothing).

Issue #24. Judging the run (outcome table, artifact, threshold) is issue #25: until it lands the
judge is a stub that escalates ``check_error`` for every completed run, so these tests look at
the calls, the clean-up and the failure reasons the run sequence itself owns. ``judged`` stands
in for the validated verdict where a test needs one.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any

import pytest

from gatectl import agentjudge, audit, fingerprint
from tests.agent_util import Fake, agent_check, config, judged, limits_env, tmp_entries
from tests.check_util import REPO, do_check, isolate, rows, write_input
from tests.command_util import config_file
from tests.proc_util import Tracker

INPUT = {"ci": "ok", "repo": REPO}


@pytest.fixture
def sdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def run_check(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    cfg: dict[str, Any],
    *extra: str,
    obj: Any = INPUT,
) -> dict[str, Any]:
    config_path = config_file(tmp_path, cfg)
    _, doc, _ = do_check(capsys, config_path, "p", "--input", write_input(tmp_path, obj), *extra)
    return doc


def label_values(argv: list[str]) -> dict[str, str]:
    labels = [argv[i + 1] for i, a in enumerate(argv) if a == "--label"]
    return dict(item.split("=", 1) for item in labels)


def state_tag(sdir: Path) -> str:
    return hashlib.sha256(os.path.realpath(sdir).encode()).hexdigest()[:12]


def slot_rows(sdir: Path) -> list[Any]:
    return rows(sdir, "SELECT decision_id, csession_id FROM agent_slots")


# --- the argv of every call (interface.md, Agent checks, Run sequence) ------------------------


def test_the_calls_are_start_exec_status_forget_with_the_documented_argv(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    doc = run_check(tmp_path, capsys, config(fake, agent_block={"timeout": "30s"}))
    decision_id = doc["decision_id"]
    argvs = fake.argvs()
    assert [a[0] for a in argvs] == ["start", "exec", "status", "forget"]
    start = argvs[0]
    bundled = fingerprint.bundled_plugin_dir()
    folder = sdir / "tmp" / decision_id
    n = re.fullmatch(r"(\d+)s", start[start.index("--timeout") + 1])
    assert n is not None and 30 <= int(n.group(1)) <= 40  # min(30, L) is 30 with a 40 s deadline
    assert start == [
        "start", "--kind", "gate-check", "--mode", "headless",
        "--skill", "gatectl:gate-check",
        "--prompt-file", str(folder / "prompt.md"),
        "--input-file", str(folder / "input.json"),
        "--plugin-dir", bundled,
        "--timeout", f"{n.group(1)}s",
        "--label", "owner=gatectl", "--label", "policy=p",
        "--label", f"decision={decision_id}", "--label", f"state={state_tag(sdir)}",
        "--actor", "auto:gatectl", "--decision-id", decision_id,
        "--permission-profile", f"{bundled}/permission-profile.json",
        "--sandbox", "required",
        "--setting-sources", "",
        "--env-allowlist-only", "",
        "--repo=" + REPO,
        "--json",
    ]  # fmt: skip
    session = fake.records()[0]["id"]
    assert argvs[1] == [
        "exec", "--session-id", session, "--run", "1",
        "--outcome-file", str(folder / "outcome.json"), "--json",
    ]  # fmt: skip
    assert argvs[2] == ["status", session, "--json"]
    assert argvs[3] == ["forget", session, "--actor", "auto:gatectl", "--decision-id", decision_id]


def test_the_timeout_is_the_smaller_of_the_check_timeout_and_the_launch_window(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    cfg = config(fake, checks=[agent_check(timeout="7s")])
    run_check(tmp_path, capsys, cfg)
    start = fake.argvs()[0]
    assert start[start.index("--timeout") + 1] == "7s"


def test_a_fractional_launch_window_rounds_up_to_whole_seconds(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    run_check(tmp_path, capsys, config(fake, timeout="12s", agent_block={"timeout": "300s"}))
    start = fake.argvs()[0]
    # R is just under 11.8 s and L = R - 5 just under 6.8 s: ceil gives 7, never 0 or 6.
    assert start[start.index("--timeout") + 1] == "7s"


def test_model_repo_and_per_check_safety_settings_are_passed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    profile = tmp_path / "profile.json"
    profile.write_text("{}", encoding="utf-8")
    check = agent_check(
        model="haiku",
        sandbox="preferred",
        permission_profile=str(profile),
        env_allowlist=["ALPHA", "BETA"],
    )
    run_check(tmp_path, capsys, config(fake, checks=[check]))
    start = fake.argvs()[0]
    assert "--model=haiku" in start
    assert f"--repo={REPO}" in start
    assert start[start.index("--sandbox") + 1] == "preferred"
    assert start[start.index("--permission-profile") + 1] == str(profile)
    names = [start[i + 1] for i, a in enumerate(start) if a == "--env-allowlist-only"]
    assert names == ["ALPHA", "BETA"]
    assert start[-1] == "--json"


def test_a_check_without_a_repo_passes_no_repo_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    run_check(tmp_path, capsys, config(fake), obj={"ci": "ok"})
    assert not any(a.startswith("--repo") for a in fake.argvs()[0])


def test_a_skill_from_another_plugin_adds_that_one_plugin_dir(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = tmp_path / "other-plugin"
    (other / ".claude-plugin").mkdir(parents=True)
    (other / ".claude-plugin" / "plugin.json").write_text('{"name": "other"}', encoding="utf-8")
    (other / "skills" / "review").mkdir(parents=True)
    (other / "skills" / "review" / "SKILL.md").write_text("# review\n", encoding="utf-8")
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    cfg = config(
        fake,
        checks=[agent_check(skill="other:review")],
        agent_block={"plugin_dirs": [str(other)]},
    )
    run_check(tmp_path, capsys, cfg)
    start = fake.argvs()[0]
    dirs = [start[i + 1] for i, a in enumerate(start) if a == "--plugin-dir"]
    assert dirs == [fingerprint.bundled_plugin_dir(), str(other)]
    assert start[start.index("--skill") + 1] == "other:review"


def test_the_labels_a_reconcile_sweep_needs_are_on_the_session(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    doc = run_check(tmp_path, capsys, config(fake))
    labels = fake.records()[0]["labels"]
    # claude-session adds its own kind=<kind> label to the four gatectl gives
    assert sorted(labels) == sorted(
        [
            "kind=gate-check",
            "owner=gatectl",
            "policy=p",
            f"decision={doc['decision_id']}",
            f"state={state_tag(sdir)}",
        ]
    )
    assert label_values(fake.argvs()[0])["decision"] == doc["decision_id"]


# --- the environment of every call ------------------------------------------------------------


def test_session_calls_get_an_allowlisted_environment(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secretsecret")
    monkeypatch.setenv("GATECTL_DEFAULTS__TIMEOUT", "99s")
    monkeypatch.setenv("SOME_PASSWORD", "x")
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    run_check(tmp_path, capsys, config(fake))
    calls = fake.calls()
    assert [c["argv"][0] for c in calls] == ["start", "exec", "status", "forget"]
    for call in calls:
        names = set(call["env_names"])
        assert {"PATH", "HOME"} <= names
        assert not any(n.startswith("GATECTL_") for n in names)
        assert not {"GITHUB_TOKEN", "SOME_PASSWORD"} & names
        assert call["home"] == os.environ["HOME"]
        assert call["cwd"] == "/"


# --- nothing is left behind -------------------------------------------------------------------


def test_after_a_run_the_session_is_forgotten_the_files_and_the_slot_are_gone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    seen = judged(monkeypatch)
    doc = run_check(tmp_path, capsys, config(fake))
    assert doc["checks"][0]["verdict"] == "allow"
    assert len(seen) == 1
    assert fake.unforgotten() == []
    assert tmp_entries(sdir) == []
    assert slot_rows(sdir) == []


def test_the_slot_row_carries_the_csession_id_while_the_run_lives(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    during: list[list[tuple[Any, ...]]] = []
    real = agentjudge.judge

    def peek(raw: Any, *, threshold: float) -> Any:  # called after exec, before the slot is freed
        during.append(rows(sdir, "SELECT csession_id, decision_id FROM agent_slots"))
        return real(raw, threshold=threshold)

    monkeypatch.setattr(agentjudge, "judge", peek)
    doc = run_check(tmp_path, capsys, config(fake))
    session = fake.records()[0]["id"]
    assert during == [[(session, doc["decision_id"])]]
    assert slot_rows(sdir) == []


# --- start failures ---------------------------------------------------------------------------


@pytest.mark.parametrize("behavior", ["fail", "fail:2", "fail:1", "garbage", "json_wrong", "empty"])
def test_a_failing_or_unusable_start_is_check_error_and_never_an_allow(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: str,
) -> None:
    fake = Fake(tmp_path, FAKE_CS_BEHAVIOR_START=behavior)
    limits_env(monkeypatch)
    judged(monkeypatch)  # a verdict must not be asked for: the run never got there
    doc = run_check(tmp_path, capsys, config(fake))
    entry = doc["checks"][0]
    assert (entry["verdict"], entry["reason"]) == ("escalate", "check_error")
    assert doc["decision"] == "escalate"
    assert "exec" not in fake.verbs()
    assert slot_rows(sdir) == [] and tmp_entries(sdir) == []


def test_a_hung_start_is_abandoned_and_the_session_it_allocated_is_forgotten(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path, FAKE_CS_BEHAVIOR_START="hang_after_allocate")
    limits_env(monkeypatch)
    doc = run_check(tmp_path, capsys, config(fake))
    entry = doc["checks"][0]
    assert (entry["verdict"], entry["reason"]) == ("escalate", "check_error")
    verbs = fake.verbs()
    assert verbs[0] == "start" and "exec" not in verbs
    assert "list" in verbs and "stop" in verbs and "forget" in verbs
    assert fake.unforgotten() == []  # a pending run is cancelled by stop, then forgotten
    listing = next(a for a in fake.argvs() if a[0] == "list")
    assert f"decision={doc['decision_id']}" in listing and "--json" in listing
    for call in (a for a in fake.argvs() if a[0] == "stop"):
        assert call[2:] == ["--grace", "2s", "--actor", "auto:gatectl"]
    assert slot_rows(sdir) == [] and tmp_entries(sdir) == []


@pytest.mark.parametrize("scenario", ["sandbox_unavailable", "claude_not_found"])
def test_a_start_that_exits_12_after_allocating_a_session_still_forgets_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
) -> None:
    fake = Fake(tmp_path, scenario)
    limits_env(monkeypatch)
    doc = run_check(tmp_path, capsys, config(fake))
    assert doc["checks"][0]["verdict"] == "escalate"
    assert [r["state"] for r in fake.records()] == ["not-started"]  # it was allocated
    assert fake.unforgotten() == []
    assert fake.verbs().count("forget") == 1
    assert slot_rows(sdir) == [] and tmp_entries(sdir) == []


def test_non_empty_setting_sources_end_in_a_forgotten_launch_failure(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    doc = run_check(tmp_path, capsys, config(fake, checks=[agent_check(setting_sources=["user"])]))
    start = fake.argvs()[0]
    assert start[start.index("--setting-sources") + 1] == "user"
    assert doc["checks"][0]["verdict"] == "escalate"
    assert fake.unforgotten() == []


# --- status failures --------------------------------------------------------------------------


@pytest.mark.parametrize("behavior", ["fail", "garbage", "json_wrong", "empty", "hang"])
def test_a_failing_timing_out_or_unusable_status_is_check_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: str,
) -> None:
    fake = Fake(tmp_path, FAKE_CS_BEHAVIOR_STATUS=behavior, FAKE_CS_HANG_MAX="30")
    limits_env(monkeypatch)
    judged(monkeypatch)
    doc = run_check(tmp_path, capsys, config(fake))
    entry = doc["checks"][0]
    assert (entry["verdict"], entry["reason"]) == ("escalate", "check_error")
    assert fake.verbs().count("forget") == 1
    assert fake.unforgotten() == []
    assert slot_rows(sdir) == [] and tmp_entries(sdir) == []


def test_a_status_that_names_another_session_is_unusable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gatectl import agent

    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    real = agent.parse_object

    def other(data: bytes) -> Any:
        found = real(data)
        if isinstance(found, dict) and "recent_events" in found:  # only status prints these
            return {**found, "csession_id": "cs-aaaaaaaa"}
        return found

    monkeypatch.setattr(agent, "parse_object", other)
    doc = run_check(tmp_path, capsys, config(fake))
    assert doc["checks"][0]["reason"] == "check_error"
    assert fake.unforgotten() == []


# --- forget -----------------------------------------------------------------------------------


@pytest.mark.parametrize("behavior", ["fail", "fail:20", "hang", "garbage"])
def test_a_failing_forget_never_changes_the_verdict(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    behavior: str,
) -> None:
    fake = Fake(tmp_path, FAKE_CS_BEHAVIOR_FORGET=behavior, FAKE_CS_HANG_MAX="30")
    limits_env(monkeypatch)
    judged(monkeypatch)
    doc = run_check(tmp_path, capsys, config(fake))
    entry = doc["checks"][0]
    assert (entry["verdict"], entry["reason"]) == ("allow", None)
    assert doc["decision"] == "allow"
    assert slot_rows(sdir) == [] and tmp_entries(sdir) == []


# --- the audit line and log never carry what a session said -----------------------------------


def test_nothing_a_session_prints_reaches_the_audit_log_or_detail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path, FAKE_CS_BEHAVIOR_STATUS="garbage")
    limits_env(monkeypatch)
    doc = run_check(tmp_path, capsys, config(fake))
    text = (sdir / "audit.jsonl").read_text(encoding="ascii")
    log = (sdir / "log.jsonl").read_text(encoding="ascii") if (sdir / "log.jsonl").exists() else ""
    assert "csession_id" not in text + log + str(doc["checks"])
    assert audit.state_dir() == sdir


# --- hostile output of claude-session ---------------------------------------------------------


def test_huge_output_from_a_call_is_capped_not_buffered(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wrapper = tmp_path / "noisy"
    wrapper.write_text(  # floods stdout for `status` (50 MB), runs the fake for everything else
        "#!/bin/sh\n"
        'for a in "$@"; do\n'
        '  if [ "$a" = status ]; then yes x | head -c 50000000; exit 0; fi\n'
        "done\n"
        'exec "$@"\n',
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    doc = run_check(tmp_path, capsys, config(None, session_cmd=[str(wrapper), *fake.cmd]))
    entry = doc["checks"][0]
    assert (entry["verdict"], entry["reason"]) == ("escalate", "check_error")
    assert fake.unforgotten() == []


def test_the_tracker_sees_no_leftover_process_after_a_normal_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    run_check(tmp_path, capsys, config(fake))
    assert tracker.items  # calls and watchdogs were recorded; teardown asserts none survives
