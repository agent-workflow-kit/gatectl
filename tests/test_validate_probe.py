"""``gatectl validate --probe`` (issue #26): one real agent run through the same path as ``check``,
against the fake claude-session. The probe stores only its marker; it records no decision.

Nothing here runs the real claude-session (the billed live run belongs to #27).
"""

from __future__ import annotations

import json
import os
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from gatectl import agent, agenthash, engine, fingerprint, ids, probe, slots
from gatectl import store as store_mod
from gatectl.cli import main
from gatectl.config import load_config
from tests import schema_util
from tests.agent_util import Fake, agent_check, config, limits_env, state_store, tmp_entries
from tests.check_util import audit_lines, decisions, isolate, rows
from tests.command_util import config_file
from tests.proc_util import Tracker
from tests.set_util import AGENT_ONLY, RULE_POLICY

CANARY = "CANARY-5d1e8a"
POLICY_WITH_AGENT: dict[str, Any] = {"checks": [AGENT_ONLY["checks"][0], RULE_POLICY["checks"][0]]}


@pytest.fixture
def sdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def validate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], cfg: dict[str, Any], *flags: str
) -> tuple[int, dict[str, Any], str]:
    path = config_file(tmp_path, cfg)
    code = main(["validate", "--json", "--config", path, *flags])
    out = capsys.readouterr().out
    doc = json.loads(out)
    schema_util.assert_valid("cli/validate", doc)
    return code, doc, out


def text_of(tmp_path: Path, capsys: pytest.CaptureFixture[str], cfg: dict[str, Any]) -> str:
    path = config_file(tmp_path, cfg)
    main(["validate", "--probe", "--config", path])
    return capsys.readouterr().out


def meta(sdir: Path, key: str) -> str | None:
    found = rows(sdir, "SELECT value FROM meta WHERE key = ?", key)
    return found[0][0] if found else None


def clean(fake: Fake, sdir: Path) -> None:
    """A probe leaves no session, slot or directory behind, whatever happened."""
    assert fake.unforgotten() == []
    assert tmp_entries(sdir) == []
    assert rows(sdir, "SELECT * FROM agent_slots") == []


def nothing_recorded(sdir: Path) -> None:
    assert decisions(sdir) == []
    assert audit_lines(sdir) == []
    assert rows(sdir, "SELECT * FROM policy_state") == []
    assert rows(sdir, "SELECT * FROM agent_cache") == []


def probe_cfg(fake: Fake | None, **kw: Any) -> dict[str, Any]:
    return config(fake, **kw)


# --- the passing probe ------------------------------------------------------------------------


def test_a_probe_against_the_fake_passes_and_reports_the_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    code, doc, _ = validate(tmp_path, capsys, probe_cfg(fake), "--probe")
    assert code == 0 and doc["valid"] is True
    assert doc["probe"] == {
        "exit_code": 0,
        "end_reason": "normal",
        "sandbox_active": True,
        "ok": True,
        "failed": None,
    }
    assert fake.verbs() == ["start", "exec", "status", "forget"]
    clean(fake, sdir)


def test_the_marker_is_bound_to_the_exact_agent_configuration(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    cfg = probe_cfg(fake)
    assert validate(tmp_path, capsys, cfg, "--probe")[0] == 0
    loaded = load_config(config_file(tmp_path, cfg))
    expected = agenthash.agent_config_hash(loaded.shared, loaded.session_cmd_resolved())
    assert meta(sdir, "probe_agent_hash") == expected
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", expected)
    stamp = meta(sdir, "probe_ok_at")
    assert stamp is not None
    assert abs(datetime.now(UTC) - _parse(stamp)) < timedelta(minutes=1)


def _parse(stamp: str) -> datetime:
    from gatectl import clock

    return clock.parse_ts(stamp)


def test_a_successful_probe_silences_the_set_hint_until_the_agent_configuration_changes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    cfg = probe_cfg(fake, checks=[agent_check(), RULE_POLICY["checks"][0]])

    def hint(path: str) -> str | None:
        main(["set", "p", "enforced", "--config", path, "--actor", "human:ann", "--json"])
        return json.loads(capsys.readouterr().out)["hint"]

    path = config_file(tmp_path, cfg)
    first = hint(path)
    assert first is not None and "validate --probe" in first
    assert main(["validate", "--json", "--probe", "--config", path]) == 0
    capsys.readouterr()
    assert hint(path) is None
    changed = probe_cfg(fake, checks=[agent_check(), RULE_POLICY["checks"][0]])
    changed["agent"]["threshold"] = 0.9
    again = hint(config_file(tmp_path, changed))
    assert again is not None and "validate --probe" in again


def test_a_probe_records_no_decision_no_audit_line_and_no_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    assert validate(tmp_path, capsys, probe_cfg(fake), "--probe")[0] == 0
    nothing_recorded(sdir)
    assert rows(sdir, "SELECT key FROM meta WHERE key LIKE 'probe%' ORDER BY key") == [
        ("probe_agent_hash",),
        ("probe_ok_at",),
    ]


def test_the_probe_uses_the_agent_blocks_settings_a_gd_id_and_the_session_labels(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    cfg = probe_cfg(fake, agent_block={"sandbox": "required", "model": "haiku"})
    assert validate(tmp_path, capsys, cfg, "--probe")[0] == 0
    start = fake.argvs()[0]
    assert start[0] == "start"

    def values(flag: str) -> list[str]:
        return [start[i + 1] for i, a in enumerate(start) if a == flag]

    labels = values("--label")
    (decision,) = values("--decision-id")
    assert re.fullmatch(r"gd-[a-z2-7]{12}", decision)
    assert f"decision={decision}" in labels and "owner=gatectl" in labels
    assert any(x.startswith("policy=") for x in labels)
    assert any(x.startswith("state=") for x in labels)
    assert values("--sandbox") == ["required"] and values("--skill") == ["gatectl:gate-check"]
    assert values("--setting-sources") == [""]
    assert "--model=haiku" in start
    assert values("--kind") == ["gate-check"] and values("--mode") == ["headless"]
    # the same decision id names every later call of the run
    assert all(decision in a for a in fake.argvs() if a[0] == "forget")


def test_the_run_has_an_owned_tmp_directory_a_slot_and_the_probe_instruction(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    seen: dict[str, Any] = {}
    real = agent.run_session

    def spy(gw: Any, launch: agent.Launch, **kw: Any) -> agent.SessionResult:
        folder = sdir / "tmp" / launch.decision_id
        seen["owner"] = (folder / "owner").is_file()
        seen["mode"] = oct(os.stat(folder).st_mode & 0o777)
        seen["prompt"] = Path(launch.prompt_file).read_text(encoding="utf-8")
        seen["input"] = Path(launch.input_file).read_text(encoding="utf-8")
        seen["slots"] = rows(sdir, "SELECT decision_id FROM agent_slots")
        seen["slot_id"] = launch.decision_id
        seen["run"] = kw["slot"] is not None and kw["store"] is not None
        return real(gw, launch, **kw)

    monkeypatch.setattr(agent, "run_session", spy)
    assert validate(tmp_path, capsys, probe_cfg(fake), "--probe")[0] == 0
    assert seen["owner"] and seen["mode"] == "0o700" and seen["run"]
    assert seen["slots"] == [(seen["slot_id"],)]
    assert "allow" in seen["prompt"]
    assert "<untrusted" in seen["input"]
    clean(fake, sdir)


def test_without_probe_no_session_is_ever_started(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    code, doc, _ = validate(tmp_path, capsys, probe_cfg(fake))
    assert code == 0 and doc["probe"] is None
    assert fake.argvs() == []
    assert meta(sdir, "probe_ok_at") is None


def test_an_invalid_config_reports_its_problems_and_starts_nothing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    cfg = probe_cfg(fake)
    cfg["bogus"] = 1
    code, doc, _ = validate(tmp_path, capsys, cfg, "--probe")
    assert code == 2 and doc["probe"] is None and doc["problems"]
    assert fake.argvs() == []
    assert meta(sdir, "probe_ok_at") is None


# --- failures: exit 12 and the reason ---------------------------------------------------------

FAILURES: list[tuple[str, dict[str, str], int | None, str | None, str]] = [
    # id, fake env, exit_code, end_reason, the failed text starts with
    ("nonce_mismatch", {}, 0, "normal", "artifact_invalid"),
    ("wrong_schema", {}, 0, "normal", "artifact_invalid"),
    ("no_artifact", {}, 0, "normal", "artifact_invalid"),
    ("implicit_done", {}, 0, "normal", "artifact_invalid"),
    ("unreported", {}, 14, "no_report", "agent_unreported"),
    ("timeout", {}, 16, "timeout", "timeout"),
    ("blocked", {}, 13, "normal", "check_escalated"),
    ("failed", {}, 18, "normal", "check_error"),
    ("killed", {}, 15, "signal_kill", "check_error"),
    ("lost", {}, 17, "lost", "check_error"),
    ("sandbox_unavailable", {}, 12, "sandbox_unavailable", "sandbox_unavailable"),
    ("claude_not_found", {}, 12, "claude_not_found", "tool_missing"),
    ("unsafe_setting_sources", {}, 12, "unsafe_setting_sources", "check_error"),
    ("valid", {"FAKE_CS_DECISION": "deny"}, 0, "normal", "check_denied"),
    ("valid", {"FAKE_CS_DECISION": "escalate"}, 0, "normal", "check_escalated"),
    ("valid", {"FAKE_CS_CONFIDENCE": "0.1"}, 0, "normal", "low_confidence"),
]


@pytest.mark.parametrize(("scenario", "extra", "exit_code", "end_reason", "reason"), FAILURES)
def test_a_probe_fails_closed_with_exit_12_the_reason_and_a_clean_slate(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
    scenario: str,
    extra: dict[str, str],
    exit_code: int | None,
    end_reason: str | None,
    reason: str,
) -> None:
    fake = Fake(tmp_path, scenario, **extra)
    limits_env(monkeypatch, tracker)
    code, doc, _ = validate(tmp_path, capsys, probe_cfg(fake), "--probe")
    assert code == 12 and doc["valid"] is True and doc["problems"] == []
    got = doc["probe"]
    assert got["ok"] is False
    assert got["exit_code"] == exit_code and got["end_reason"] == end_reason
    assert got["failed"].startswith(reason)
    assert len(got["failed"]) <= 2048
    assert meta(sdir, "probe_ok_at") is None and meta(sdir, "probe_agent_hash") is None
    nothing_recorded(sdir)
    clean(fake, sdir)


def test_a_failed_probe_removes_an_earlier_marker_so_the_hint_returns(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    limits_env(monkeypatch, tracker)
    good = Fake(tmp_path / "good")
    cfg = probe_cfg(good)
    assert validate(tmp_path, capsys, cfg, "--probe")[0] == 0
    assert meta(sdir, "probe_ok_at") is not None
    bad = Fake(tmp_path / "bad", FAKE_CS_DECISION="deny")
    assert validate(tmp_path, capsys, probe_cfg(bad), "--probe")[0] == 12
    assert meta(sdir, "probe_ok_at") is None and meta(sdir, "probe_agent_hash") is None


def test_the_sandbox_must_be_active_when_it_is_required(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path, FAKE_CS_SANDBOX_ACTIVE="0")
    limits_env(monkeypatch, tracker)
    code, doc, _ = validate(tmp_path, capsys, probe_cfg(fake), "--probe")
    assert code == 12
    assert doc["probe"]["sandbox_active"] is False and doc["probe"]["ok"] is False
    assert doc["probe"]["failed"].startswith("sandbox_inactive")
    assert meta(sdir, "probe_ok_at") is None
    clean(fake, sdir)


def test_a_lowered_sandbox_needs_no_active_sandbox_but_it_is_still_reported(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path, FAKE_CS_SANDBOX_ACTIVE="0")
    limits_env(monkeypatch, tracker)
    cfg = probe_cfg(fake, agent_block={"sandbox": "preferred"})
    code, doc, _ = validate(tmp_path, capsys, cfg, "--probe")
    assert code == 0 and doc["probe"]["ok"] is True and doc["probe"]["sandbox_active"] is False
    assert {w["code"] for w in doc["warnings"]} >= {"sandbox_lowered"}


def test_no_text_of_the_session_or_the_model_is_ever_echoed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    limits_env(monkeypatch, tracker)
    reasons = json.dumps([CANARY, "\x1b[31mred"])
    for i, decision in enumerate(("deny", "escalate", "allow")):
        fake = Fake(
            tmp_path / str(i),
            FAKE_CS_DECISION=decision,
            FAKE_CS_REASONS=reasons,
            FAKE_CS_CONFIDENCE="0.99" if decision == "allow" else "0.5",
        )
        cfg = probe_cfg(fake)
        code, doc, raw = validate(tmp_path, capsys, cfg, "--probe")
        assert code == (0 if decision == "allow" else 12)
        assert CANARY not in raw and "\x1b" not in raw
        assert CANARY not in text_of(tmp_path, capsys, cfg)


def test_a_session_cmd_that_is_not_found_fails_the_probe_without_a_session(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    limits_env(monkeypatch, tracker)
    cfg = probe_cfg(None, session_cmd=["claude-session-nowhere"], checks=[RULE_POLICY["checks"][0]])
    code, doc, raw = validate(tmp_path, capsys, cfg, "--probe")
    assert code == 12 and doc["valid"] is True
    assert doc["probe"] == {
        "exit_code": None,
        "end_reason": None,
        "sandbox_active": None,
        "ok": False,
        "failed": doc["probe"]["failed"],
    }
    assert doc["probe"]["failed"].startswith("tool_missing")
    assert "claude-session-nowhere" not in raw
    assert tmp_entries(sdir) == []
    assert rows(sdir, "SELECT * FROM agent_slots") == []


def test_a_missing_skill_fails_the_probe_before_any_session(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    empty = tmp_path / "no-plugin"
    empty.mkdir()
    monkeypatch.setattr(fingerprint, "bundled_plugin_dir", lambda: str(empty))
    cfg = probe_cfg(fake, checks=[RULE_POLICY["checks"][0]])
    code, doc, _ = validate(tmp_path, capsys, cfg, "--probe")
    assert code == 12 and doc["probe"]["failed"].startswith("tool_missing")
    assert fake.argvs() == []
    assert tmp_entries(sdir) == []


def test_a_busy_slot_table_fails_the_probe_inside_its_own_deadline(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    store = state_store()
    with store:
        held = slots.try_acquire(
            store,
            decision_id="gd-bbbbbbbbbbbb",
            max_parallel=1,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    assert held is not None
    cfg = probe_cfg(fake, agent_block={"max_parallel": 1, "timeout": "2s"})
    code, doc, _ = validate(tmp_path, capsys, cfg, "--probe")
    assert code == 12 and doc["probe"]["failed"].startswith("busy")
    assert doc["probe"]["exit_code"] is None
    assert fake.argvs() == []
    assert rows(sdir, "SELECT decision_id FROM agent_slots") == [("gd-bbbbbbbbbbbb",)]
    assert tmp_entries(sdir) == []


def test_a_hanging_session_ends_at_the_probes_own_deadline_and_is_cleaned_up(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path, "hang")
    limits_env(monkeypatch, tracker)
    cfg = probe_cfg(fake, agent_block={"timeout": "2s"})
    code, doc, _ = validate(tmp_path, capsys, cfg, "--probe")
    assert code == 12 and doc["probe"]["ok"] is False
    assert doc["probe"]["failed"].startswith("timeout")
    assert meta(sdir, "probe_ok_at") is None
    clean(fake, sdir)


def test_the_launch_timeout_is_the_agent_blocks_and_bounded(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    cfg = probe_cfg(fake, agent_block={"timeout": "30s"})
    assert validate(tmp_path, capsys, cfg, "--probe")[0] == 0
    start = fake.argvs()[0]
    n = start[start.index("--timeout") + 1]
    assert n == "30s"


def test_files_are_deleted_even_when_the_run_raises(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)

    def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("bug")

    monkeypatch.setattr(agent, "run_session", boom)
    code, doc, _ = validate(tmp_path, capsys, probe_cfg(fake), "--probe")
    assert code == 12 and doc["probe"]["ok"] is False
    assert doc["probe"]["failed"].startswith("check_error")
    assert tmp_entries(sdir) == []
    assert rows(sdir, "SELECT * FROM agent_slots") == []
    assert meta(sdir, "probe_ok_at") is None


def test_the_marker_write_failing_is_a_failed_probe_never_a_silent_pass(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)

    def broken(*a: Any, **k: Any) -> None:
        raise OSError("disk")

    monkeypatch.setattr(probe, "_store_marker", broken)
    code, doc, _ = validate(tmp_path, capsys, probe_cfg(fake), "--probe")
    assert code == 12 and doc["probe"]["ok"] is False
    assert doc["probe"]["failed"].startswith("marker_unwritable")
    assert meta(sdir, "probe_ok_at") is None
    clean(fake, sdir)


# --- the text form and the documented gap -----------------------------------------------------


def test_the_text_form_reports_the_probe_and_the_per_check_override_gap(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    out = text_of(tmp_path, capsys, probe_cfg(fake))
    assert "probe: ok" in out and out.rstrip().splitlines()[-1] == "valid"
    assert "sandbox_active true" in out and "exit_code 0" in out
    assert "per-check" in out and "not covered" in out
    out = text_of(tmp_path, capsys, probe_cfg(Fake(tmp_path / "x", FAKE_CS_DECISION="deny")))
    assert "probe: failed check_denied" in out
    assert out.rstrip().splitlines()[-1] == "probe failed"


def test_validate_still_checks_the_per_check_overrides_the_probe_does_not_cover(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    cfg = probe_cfg(fake, checks=[agent_check(setting_sources=["user"])])
    code, doc, _ = validate(tmp_path, capsys, cfg, "--probe")
    assert code == 2 and doc["probe"] is None
    assert any(p["code"] == "unsafe_setting_sources" for p in doc["problems"])
    assert fake.argvs() == []
    cfg = probe_cfg(fake, checks=[agent_check(sandbox="off")])
    code, doc, _ = validate(tmp_path, capsys, cfg, "--probe")
    assert code == 0 and any(w["code"] == "sandbox_lowered" for w in doc["warnings"])


def test_the_probe_input_is_a_fixed_builtin_that_asks_for_allow() -> None:
    assert "allow" in probe.INSTRUCTION
    assert probe.INPUT == {"probe": "gatectl validate --probe", "expected_decision": "allow"}
    assert probe.POLICY_LABEL == "probe"


# --- review round 1 ---------------------------------------------------------------------------


def make_plugin_dir(root: Path) -> Path:
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text('{"name": "other"}', encoding="utf-8")
    (root / "skills" / "review").mkdir(parents=True)
    (root / "skills" / "review" / "SKILL.md").write_text("# review\n", encoding="utf-8")
    (root / ".claude").mkdir()
    for placeholder in (".mcp.json", "CLAUDE.md", "CLAUDE.local.md"):
        (root / placeholder).write_text("")
    return root


def flag_values(start: list[str], flag: str) -> list[str]:
    return [start[i + 1] for i, a in enumerate(start) if a == flag]


def test_a_min_start_budget_above_the_timeout_still_lets_the_probe_start(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    cfg = probe_cfg(fake, agent_block={"timeout": "20s", "min_start_budget": "30s"})
    code, doc, _ = validate(tmp_path, capsys, cfg, "--probe")
    assert code == 0 and doc["probe"]["ok"] is True
    start = fake.argvs()[0]
    assert flag_values(start, "--timeout") == ["20s"]
    clean(fake, sdir)


def test_the_text_trailer_is_probe_failed_after_a_failed_probe_and_invalid_for_a_bad_config(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    limits_env(monkeypatch, tracker)
    bad = Fake(tmp_path / "bad", FAKE_CS_DECISION="deny")
    assert text_of(tmp_path, capsys, probe_cfg(bad)).rstrip().splitlines()[-1] == "probe failed"
    broken = probe_cfg(Fake(tmp_path / "x"))
    broken["bogus"] = 1
    assert text_of(tmp_path, capsys, broken).rstrip().splitlines()[-1] == "invalid"


def _earlier_marker(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> Fake:
    fake = Fake(tmp_path / "good")
    limits_env(monkeypatch, tracker)
    assert validate(tmp_path, capsys, probe_cfg(fake), "--probe")[0] == 0
    assert meta(sdir, "probe_ok_at") is not None
    return fake


def test_a_session_cmd_that_goes_missing_removes_the_earlier_marker(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    _earlier_marker(tmp_path, capsys, sdir, monkeypatch, tracker)
    cfg = probe_cfg(None, session_cmd=["claude-session-nowhere"], checks=[RULE_POLICY["checks"][0]])
    assert validate(tmp_path, capsys, cfg, "--probe")[0] == 12
    assert meta(sdir, "probe_ok_at") is None and meta(sdir, "probe_agent_hash") is None


def test_a_missing_plugin_removes_the_earlier_marker(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = _earlier_marker(tmp_path, capsys, sdir, monkeypatch, tracker)
    empty = tmp_path / "no-plugin"
    empty.mkdir()
    monkeypatch.setattr(fingerprint, "bundled_plugin_dir", lambda: str(empty))
    cfg = probe_cfg(fake, checks=[RULE_POLICY["checks"][0]])
    assert validate(tmp_path, capsys, cfg, "--probe")[0] == 12
    assert meta(sdir, "probe_ok_at") is None and meta(sdir, "probe_agent_hash") is None


def test_an_input_over_input_max_bytes_fails_with_its_reason_and_removes_the_marker(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = _earlier_marker(tmp_path, capsys, sdir, monkeypatch, tracker)
    calls = len(fake.argvs())
    monkeypatch.setattr(probe, "INPUT", {"blob": ["x" * 40] * 60})
    cfg = probe_cfg(fake, agent_block={"input_max_bytes": 1024})
    code, doc, _ = validate(tmp_path, capsys, cfg, "--probe")
    assert code == 12 and doc["probe"]["failed"].startswith("input_invalid")
    assert len(fake.argvs()) == calls  # no session was started
    assert meta(sdir, "probe_ok_at") is None and meta(sdir, "probe_agent_hash") is None


NOT_CLEARED = "the earlier marker could not be removed"


def _break_clear(monkeypatch: pytest.MonkeyPatch) -> None:
    real = store_mod.Store.execute

    def execute(self: store_mod.Store, sql: str, *args: Any, **kw: Any) -> Any:
        if sql.lstrip().startswith("DELETE FROM meta"):
            raise OSError("disk")
        return real(self, sql, *args, **kw)

    monkeypatch.setattr(store_mod.Store, "execute", execute)


def test_a_marker_that_cannot_be_removed_after_a_failed_probe_is_reported(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    _earlier_marker(tmp_path, capsys, sdir, monkeypatch, tracker)
    _break_clear(monkeypatch)
    bad = Fake(tmp_path / "bad", FAKE_CS_DECISION="deny")
    code, doc, _ = validate(tmp_path, capsys, probe_cfg(bad), "--probe")
    assert code == 12 and doc["probe"]["ok"] is False
    failed = doc["probe"]["failed"]
    assert failed.startswith("check_denied") and failed.endswith(NOT_CLEARED)
    assert len(failed) <= 2048


def test_a_marker_that_cannot_be_removed_after_an_early_failure_is_reported(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    _earlier_marker(tmp_path, capsys, sdir, monkeypatch, tracker)
    _break_clear(monkeypatch)
    cfg = probe_cfg(None, session_cmd=["claude-session-nowhere"], checks=[RULE_POLICY["checks"][0]])
    code, doc, _ = validate(tmp_path, capsys, cfg, "--probe")
    assert code == 12 and doc["probe"]["failed"].endswith(NOT_CLEARED)


def test_an_unwritable_marker_whose_clearing_also_fails_says_so(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)

    def broken(*a: Any, **k: Any) -> None:
        raise OSError("disk")

    monkeypatch.setattr(probe, "_store_marker", broken)
    _break_clear(monkeypatch)
    code, doc, _ = validate(tmp_path, capsys, probe_cfg(fake), "--probe")
    assert code == 12 and doc["probe"]["failed"].startswith("marker_unwritable")
    assert doc["probe"]["failed"].endswith(NOT_CLEARED)


def test_a_non_default_agent_block_and_the_given_environment_reach_the_session(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    monkeypatch.setenv("CLAUDE_FROM_OS", "1")
    seen = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ["HOME"],
        "CLAUDE_FROM_ENV": "1",
        "GATECTL_NOT_ALLOWED": "1",
    }
    limits_env(monkeypatch, tracker, environ=seen)
    cfg = probe_cfg(
        fake,
        agent_block={"sandbox": "preferred", "env_allowlist": ["MY_TOKEN"], "model": "haiku"},
    )
    assert validate(tmp_path, capsys, cfg, "--probe")[0] == 0
    start = fake.argvs()[0]
    assert flag_values(start, "--sandbox") == ["preferred"]
    assert flag_values(start, "--env-allowlist-only") == ["MY_TOKEN"]
    names = fake.calls()[0]["env_names"]
    assert "CLAUDE_FROM_ENV" in names
    assert "CLAUDE_FROM_OS" not in names and "GATECTL_NOT_ALLOWED" not in names


def test_setting_sources_reach_the_session(
    tmp_path: Path,
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    # validate refuses a non-empty setting_sources, so the probe is run directly
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    loaded = load_config(
        config_file(tmp_path, probe_cfg(fake, agent_block={"setting_sources": ["project"]}))
    )
    probe.run_probe(loaded, engine.default_env())
    assert flag_values(fake.argvs()[0], "--setting-sources") == ["project"]


def test_a_configured_plugin_dir_holding_the_skill_is_passed_to_the_session(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    other = make_plugin_dir(tmp_path / "other-plugin")
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    cfg = probe_cfg(fake, agent_block={"skill": "other:review", "plugin_dirs": [str(other)]})
    code, doc, _ = validate(tmp_path, capsys, cfg, "--probe")
    assert (code, doc["problems"]) == (0, [])
    dirs = flag_values(fake.argvs()[0], "--plugin-dir")
    assert dirs == [fingerprint.bundled_plugin_dir(), str(other)]


def test_a_newer_schema_is_the_usual_internal_error_and_nothing_starts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    import sqlite3

    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    sdir.mkdir(parents=True, mode=0o700, exist_ok=True)
    con = sqlite3.connect(sdir / "state.db")
    con.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")
    con.execute("INSERT INTO meta VALUES('schema_version', '999')")
    con.commit()
    con.close()
    (sdir / "state.db").chmod(0o600)
    path = config_file(tmp_path, probe_cfg(fake))
    code = main(["validate", "--probe", "--json", "--config", path])
    out = capsys.readouterr().out
    assert code == 1 and json.loads(out)["error"]["reason"] == "schema_newer"
    assert fake.argvs() == []
    assert rows(sdir, "SELECT key FROM meta WHERE key LIKE 'probe%'") == []


def test_a_failed_text_is_capped_and_sanitized() -> None:
    result = probe._fail("check_error", "\x1b[31m" + "x" * 5000)
    assert result.failed is not None
    assert len(result.failed) <= 2048 and "\x1b" not in result.failed
    assert result.ok is False


def test_the_slot_outlives_the_run_by_more_than_the_agent_timeout(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch, tracker)
    seen: dict[str, Any] = {}
    real = agent.run_session

    def spy(gw: Any, launch: agent.Launch, **kw: Any) -> agent.SessionResult:
        seen["expires"] = rows(sdir, "SELECT expires_at FROM agent_slots")[0][0]
        seen["now"] = datetime.now(UTC)
        return real(gw, launch, **kw)

    monkeypatch.setattr(agent, "run_session", spy)
    cfg = probe_cfg(fake, agent_block={"timeout": "30s"})
    assert validate(tmp_path, capsys, cfg, "--probe")[0] == 0
    assert _parse(seen["expires"]) > seen["now"] + timedelta(seconds=30)


class Jump:
    """A monotonic clock a test can push forward."""

    def __init__(self) -> None:
        self.offset = 0.0

    def __call__(self) -> float:
        import time

        return time.monotonic() + self.offset


def test_no_time_left_before_the_slot_is_budget_exhausted_and_starts_nothing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    clock = Jump()
    limits_env(monkeypatch, tracker, monotonic=clock)
    real = ids.new_decision_id

    def new_id() -> str:
        clock.offset = 10_000.0
        return real()

    monkeypatch.setattr(ids, "new_decision_id", new_id)
    code, doc, _ = validate(tmp_path, capsys, probe_cfg(fake), "--probe")
    assert code == 12 and doc["probe"]["failed"].startswith("budget_exhausted")
    assert fake.argvs() == []
    clean(fake, sdir)


def test_no_time_left_after_the_slot_is_budget_exhausted_and_the_slot_is_released(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path)
    clock = Jump()
    limits_env(monkeypatch, tracker, monotonic=clock)
    real = slots.wait_for_slot

    def wait(*a: Any, **k: Any) -> Any:
        slot = real(*a, **k)
        clock.offset = 10_000.0
        return slot

    monkeypatch.setattr(slots, "wait_for_slot", wait)
    code, doc, _ = validate(tmp_path, capsys, probe_cfg(fake), "--probe")
    assert code == 12 and doc["probe"]["failed"].startswith("budget_exhausted")
    assert fake.argvs() == []
    clean(fake, sdir)


def test_the_hash_follows_the_gatectl_version_and_the_session_cmd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gatectl.config_models import SharedConfig

    shared = SharedConfig()
    before = agenthash.agent_config_hash(shared, ["/x/cs"])
    monkeypatch.setattr(agenthash, "__version__", "999.0.0")
    assert agenthash.agent_config_hash(shared, ["/x/cs"]) != before
    monkeypatch.undo()
    assert agenthash.agent_config_hash(shared, ["/y/cs"]) != before
