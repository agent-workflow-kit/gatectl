"""``agent.py`` below the engine: the argv builders, the settings, the plugin lookup, and a run
against a claude-session that lies (hostile output) or is interrupted (the ``cancel`` hook).

Issue #24. Everything runs against the fake claude-session through the real gateway.
"""

from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from gatectl import agent, agentjudge, fingerprint
from gatectl.config_models import AgentCheck, SharedConfig
from tests import pinned_schemas
from tests.agent_util import Fake, agent_check, config, limits_env, patched_cmd
from tests.check_util import REPO, do_check, isolate, write_input
from tests.command_util import config_file
from tests.proc_util import Tracker

INPUT = {"ci": "ok", "repo": REPO}
LAUNCH = agent.Launch(
    session_cmd=("/x/claude-session",),
    skill="gatectl:gate-check",
    prompt_file="/s/prompt.md",
    input_file="/s/input.json",
    outcome_file="/s/outcome.json",
    plugin_dirs=("/p",),
    timeout_s=30,
    policy="p",
    decision_id="gd-aaaaaaaaaaaa",
    state_tag="0123456789ab",
    permission_profile="/p/profile.json",
    sandbox="required",
    setting_sources=(),
    env_allowlist=(),
)


@pytest.fixture
def sdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


# --- the argv builders ----------------------------------------------------------------------


def test_start_argv_is_the_documented_grammar_in_order() -> None:
    assert agent.start_argv(LAUNCH) == [
        "start", "--kind", "gate-check", "--mode", "headless",
        "--skill", "gatectl:gate-check",
        "--prompt-file", "/s/prompt.md", "--input-file", "/s/input.json",
        "--plugin-dir", "/p", "--timeout", "30s",
        "--label", "owner=gatectl", "--label", "policy=p",
        "--label", "decision=gd-aaaaaaaaaaaa", "--label", "state=0123456789ab",
        "--actor", "auto:gatectl", "--decision-id", "gd-aaaaaaaaaaaa",
        "--permission-profile", "/p/profile.json", "--sandbox", "required",
        "--setting-sources", "", "--env-allowlist-only", "", "--json",
    ]  # fmt: skip


def test_start_argv_repeats_flags_and_joins_setting_sources() -> None:
    from dataclasses import replace

    launch = replace(
        LAUNCH,
        plugin_dirs=("/p", "/q"),
        setting_sources=("user", "local"),
        env_allowlist=("A", "B"),
        repo="github.com/o/r",
        model="haiku",
    )
    argv = agent.start_argv(launch)
    assert argv[argv.index("--setting-sources") + 1] == "user,local"
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--plugin-dir"] == ["/p", "/q"]
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--env-allowlist-only"] == ["A", "B"]
    assert argv[-3:] == ["--repo=github.com/o/r", "--model=haiku", "--json"]


def test_a_value_that_looks_like_a_flag_stays_one_argv_word() -> None:
    from dataclasses import replace

    launch = replace(LAUNCH, model="--evil", repo=None)
    argv = agent.start_argv(launch)
    assert "--model=--evil" in argv  # glued with =, never a separate word a parser could take


def test_exec_argv() -> None:
    assert agent.exec_argv("cs-abcdefgh", 3, "/o.json") == [
        "exec", "--session-id", "cs-abcdefgh", "--run", "3", "--outcome-file", "/o.json", "--json",
    ]  # fmt: skip


def test_launch_seconds_is_the_smaller_rounded_up_and_never_zero() -> None:
    assert agent.launch_seconds(300, 34.2) == 35
    assert agent.launch_seconds(7, 34.2) == 7
    assert agent.launch_seconds(7.2, 100) == 8
    assert agent.launch_seconds(0.0001, 100) == 1
    assert agent.launch_seconds(30, 0.0) == 1


def test_the_state_tag_is_twelve_hex_characters_of_the_realpath(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    assert agent.state_tag(real) == agent.state_tag(link)
    assert len(agent.state_tag(real)) == 12
    assert agent.state_tag(real) != agent.state_tag(tmp_path)


def test_session_env_is_an_allowlist() -> None:
    env = agent.session_env(
        {
            "PATH": "/usr/bin:relative:",
            "HOME": "/h",
            "LC_ALL": "C",
            "XDG_STATE_HOME": "/s",
            "ANTHROPIC_API_KEY": "k",
            "GATECTL_X": "1",
            "GITHUB_TOKEN": "t",
            "SSH_AUTH_SOCK": "/s",
        }
    )
    assert env == {
        "PATH": "/usr/bin",
        "HOME": "/h",
        "LC_ALL": "C",
        "XDG_STATE_HOME": "/s",
        "ANTHROPIC_API_KEY": "k",
    }


def test_missing_session_detail_names_the_command_and_the_install_command_for_claude_session() -> (
    None
):
    assert agent.missing_session_detail(["foo"]) == "foo not found"
    assert agent.missing_session_detail(["/opt/claude-session"]).endswith(agent.INSTALL_HINT)
    assert agent.missing_session_detail(["bad\x07name"]) == "bad�name not found"


# --- settings -------------------------------------------------------------------------------


def shared(**agent_block: Any) -> SharedConfig:
    return SharedConfig.model_validate({"agent": agent_block}) if agent_block else SharedConfig()


def test_settings_default_from_the_agent_block_and_the_bundled_profile() -> None:
    check = AgentCheck.model_validate(agent_check())
    cfg = agent.resolve_settings(check, SharedConfig(), None, "/bundled")
    assert (cfg.skill, cfg.model, cfg.threshold, cfg.sandbox) == (
        "gatectl:gate-check", None, 0.8, "required",
    )  # fmt: skip
    assert cfg.timeout == 300.0 and cfg.cache_ttl == timedelta(minutes=10)
    assert cfg.permission_profile == "/bundled/permission-profile.json"
    assert (cfg.max_parallel, cfg.min_start_budget, cfg.input_max_bytes) == (3, 30.0, 65536)


def test_settings_prefer_the_check_over_the_agent_block() -> None:
    check = AgentCheck.model_validate(
        agent_check(model="m", threshold=0.5, timeout="9s", sandbox="off", env_allowlist=["A"])
    )
    cfg = agent.resolve_settings(check, shared(model="other", threshold=0.9), None, "/b")
    assert (cfg.model, cfg.threshold, cfg.timeout, cfg.sandbox) == ("m", 0.5, 9.0, "off")
    assert cfg.env_allowlist == ("A",)


@pytest.mark.parametrize(
    ("own", "policy", "block", "expected"),
    [
        ("1m", "2m", "3m", 60),
        (None, "2m", "3m", 120),
        (None, None, "3m", 180),
        (0, "2m", "3m", 0),
        (None, 0, "3m", 0),
    ],
)
def test_cache_ttl_precedence(own: Any, policy: Any, block: str, expected: int) -> None:
    raw = agent_check() if own is None else agent_check(cache_ttl=own)
    check = AgentCheck.model_validate(raw)
    policy_ttl = None if policy is None else (timedelta(0) if policy == 0 else timedelta(minutes=2))
    cfg = agent.resolve_settings(check, shared(cache_ttl=block), policy_ttl, "/b")
    assert cfg.cache_ttl == timedelta(seconds=expected)


# --- the plugin lookup ----------------------------------------------------------------------


def make_plugin(root: Path, name: str, skill: str | None = "review") -> Path:
    (root / ".claude-plugin").mkdir(parents=True)
    (root / ".claude-plugin" / "plugin.json").write_text(f'{{"name": "{name}"}}', encoding="utf-8")
    if skill is not None:
        (root / "skills" / skill).mkdir(parents=True)
        (root / "skills" / skill / "SKILL.md").write_text("# skill\n", encoding="utf-8")
    return root


def test_the_bundled_skill_needs_only_the_bundled_plugin() -> None:
    bundled = fingerprint.bundled_plugin_dir()
    assert agent.find_plugin_dirs("gatectl:gate-check", [], bundled) == (bundled,)


def test_another_plugins_skill_adds_exactly_that_directory(tmp_path: Path) -> None:
    bundled = make_plugin(tmp_path / "b", "gatectl", "gate-check")
    other = make_plugin(tmp_path / "o", "other")
    third = make_plugin(tmp_path / "t", "third")
    found = agent.find_plugin_dirs("other:review", [str(third), str(other)], str(bundled))
    assert found == (str(bundled), str(other))


@pytest.mark.parametrize(
    ("skill", "detail"),
    [
        ("ghost:review", "plugin not found: ghost"),
        ("gatectl:ghost", "skill not found: gatectl:ghost"),
        ("gatectl:../x", "skill not found: gatectl:../x"),
        ("gatectl:a/b", "skill not found: gatectl:a/b"),
        ("gatectl:", "skill not found: gatectl:"),
    ],
)
def test_a_missing_plugin_or_skill_is_tool_missing_text(
    tmp_path: Path, skill: str, detail: str
) -> None:
    bundled = make_plugin(tmp_path / "b", "gatectl", "gate-check")
    with pytest.raises(agent.ToolMissing) as caught:
        agent.find_plugin_dirs(skill, [], str(bundled))
    assert caught.value.detail == detail


def test_a_broken_bundled_plugin_is_tool_missing(tmp_path: Path) -> None:
    (tmp_path / "b").mkdir()
    with pytest.raises(agent.ToolMissing) as caught:
        agent.find_plugin_dirs("gatectl:gate-check", [], str(tmp_path / "b"))
    assert caught.value.detail == "bundled plugin not found"


# --- a claude-session that lies --------------------------------------------------------------


def run_check(tmp_path: Path, capsys: pytest.CaptureFixture[str], cmd: list[str]) -> dict[str, Any]:
    path = config_file(tmp_path, config(None, session_cmd=cmd))
    _, doc, _ = do_check(capsys, path, "p", "--input", write_input(tmp_path, INPUT))
    return doc


HOSTILE_IDS = [
    "../../etc/passwd",
    "cs-ABCDEFGH",
    "cs-abcdefg",
    "cs-abcdefgh\n",
    "cs-abcdefgh --evil",
    "x" * 100000,
    "",
    7,
    None,
    ["cs-abcdefgh"],
]


@pytest.mark.parametrize("bad", HOSTILE_IDS, ids=repr)
def test_a_start_that_names_an_unusable_session_id_is_never_acted_on(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    bad: Any,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    cmd = patched_cmd(tmp_path, fake, {"start": {"update": {"csession_id": bad}}})
    doc = run_check(tmp_path, capsys, cmd)
    assert doc["checks"][0]["reason"] == "check_error"
    assert "exec" not in fake.verbs()
    if isinstance(bad, str) and bad:  # whatever the fake was asked, it was never the hostile text
        assert not any(bad in a for argv in fake.argvs() for a in argv)
    assert fake.unforgotten() == []  # the real session was found by its label and forgotten


@pytest.mark.parametrize("bad", [0, -1, True, 2**40, "1", None, 1.5])
def test_a_start_with_an_unusable_run_number_is_check_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    bad: Any,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    cmd = patched_cmd(tmp_path, fake, {"start": {"update": {"run": bad}}})
    doc = run_check(tmp_path, capsys, cmd)
    assert doc["checks"][0]["reason"] == "check_error"
    assert "exec" not in fake.verbs()
    assert fake.unforgotten() == []


@pytest.mark.parametrize(
    "labels",
    [
        ["owner=somebody", "decision=gd-zzzzzzzzzzzz"],
        ["owner=gatectl", "decision=gd-zzzzzzzzzzzz"],  # ours by owner, not by this decision
        [],
        "not a list",
    ],
    ids=["foreign", "other-decision", "no-labels", "labels-not-a-list"],
)
def test_a_list_that_names_foreign_sessions_never_touches_them(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    labels: Any,
) -> None:
    fake = Fake(tmp_path, FAKE_CS_BEHAVIOR_START="hang_after_allocate")
    limits_env(monkeypatch)
    prompt = str(fake.session.prompt)
    made = fake.session.run(
        "start", "--kind", "gate-check", "--mode", "headless", "--skill", "x:y",
        "--prompt-file", prompt, "--label", "owner=somebody", "--timeout", "60s", "--json",
        FAKE_CS_BEHAVIOR_START="",
    )  # fmt: skip
    assert made.returncode == 0, made.stderr
    foreign = made.json["csession_id"]
    item = {"csession_id": foreign, "labels": labels, "live": True, "pending": True}
    cmd = patched_cmd(tmp_path, fake, {"list": {"append": {"sessions": item}}})
    doc = run_check(tmp_path, capsys, cmd)
    assert doc["checks"][0]["reason"] == "check_error"
    touched = {a[1] for a in fake.argvs() if a[0] in ("stop", "forget", "exec", "status")}
    assert foreign not in touched
    survivors = {r["id"] for r in fake.unforgotten()}
    assert survivors == {foreign}  # ours was found by its label and forgotten, theirs untouched


@pytest.mark.parametrize(
    "listing",
    [
        {"raw": "not json"},
        {"replace": []},
        {"replace": {"sessions": "x"}},
        {"replace": {"sessions": [{"csession_id": f"cs-{'a' * 8}"}] * 1000}},
        {"exit": 12},
    ],
    ids=["raw", "array", "sessions-str", "too-many", "exit-12"],
)
def test_an_unusable_list_falls_back_to_the_one_known_session(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    listing: dict[str, Any],
) -> None:
    fake = Fake(tmp_path, FAKE_CS_BEHAVIOR_EXEC="hang", FAKE_CS_HANG_MAX="3")
    limits_env(monkeypatch, limits=agent.Limits(1.5, -2.0, 5.0, 0.5, 0.2, 0.2))
    cmd = patched_cmd(tmp_path, fake, {"list": listing})
    path = config_file(tmp_path, config(None, session_cmd=cmd, checks=[agent_check(timeout="3s")]))
    _, doc, _ = do_check(capsys, path, "p", "--input", write_input(tmp_path, INPUT))
    assert doc["checks"][0]["reason"] == "timeout"
    assert fake.unforgotten() == []  # stopped and forgotten by the id start gave


def test_an_id_that_a_successful_list_did_not_return_is_never_stopped_or_forgotten(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    unlisted = "cs-bbbbbbbb"
    cmd = patched_cmd(tmp_path, fake, {"start": {"update": {"csession_id": unlisted}}})
    doc = run_check(tmp_path, capsys, cmd)
    assert doc["checks"][0]["reason"] == "check_error"
    acted = {a[1] for a in fake.argvs() if a[0] in ("stop", "forget") and len(a) > 1}
    assert unlisted not in acted
    assert fake.unforgotten() == []  # the listed (real) session was forgotten


def test_a_failed_list_stops_then_forgets_the_known_id(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = Fake(tmp_path, FAKE_CS_BEHAVIOR_EXEC="hang", FAKE_CS_HANG_MAX="3")
    limits_env(monkeypatch, limits=agent.Limits(1.5, -2.0, 5.0, 0.5, 0.2, 0.2))
    cmd = patched_cmd(tmp_path, fake, {"list": {"exit": 12}})
    path = config_file(tmp_path, config(None, session_cmd=cmd, checks=[agent_check(timeout="3s")]))
    do_check(capsys, path, "p", "--input", write_input(tmp_path, INPUT))
    tail = [a[0] for a in fake.argvs() if a[0] in ("stop", "forget")]
    assert tail[-2:] == ["stop", "forget"]
    assert tail.count("forget") == 1


def test_a_maximal_legal_outcome_and_status_body_fits_the_caps_and_parses() -> None:
    """claude-session caps summary and reason at 65536 UTF-8 bytes each and prints with
    ensure_ascii, so a control character costs 6 bytes (the worst case); status adds at most 20
    events."""
    import json

    text = "\x01" * 65536
    report = {"status": "done", "implicit": False, "summary": text, "reason": text}
    events = [{"event_id": "e" * 64, "note": "x" * 512} for _ in range(20)]
    outcome = {"csession_id": "cs-aaaaaaaa", "report": report}
    status = {**outcome, "events": events, "labels": ["l" * 128] * 64}
    for body, cap in ((outcome, agent._OUTCOME_CAP), (status, agent._STATUS_CAP)):
        data = json.dumps(body, ensure_ascii=True, allow_nan=False).encode()
        assert len(data) > 64 * 1024
        assert len(data) <= cap
        assert agent.parse_object(data) == body


def _session(now: list[float]) -> agent._Session:
    limits = agent.Limits(call_timeout=5.0, exec_margin=10.0, cleanup_budget=10.0, kill_grace=2.0)
    return agent._Session(
        gw=None, launch=None, nonce="", threshold=0.0, store=None, slot=None,  # type: ignore[arg-type]
        env={}, limits=limits, monotonic=lambda: now[0], cancel=None,
    )  # fmt: skip


def test_the_cleanup_call_budget_sets_the_kill_grace_aside() -> None:
    now = [100.0]
    session = _session(now)
    limits = session.limits
    assert session._bounded() == 5.0  # min(cap 5, 10 - 2)
    now[0] = 106.0
    assert session._bounded() == 2.0  # 4 s left, 2 s of it kill grace
    assert session._bounded(reserve=1.0) == 1.0
    now[0] = 108.0
    assert session._bounded() <= 0  # nothing left but the grace: the call is skipped
    # a call that ignores SIGTERM runs timeout + grace: never past the budget end (110)
    now[0] = 106.0
    assert now[0] + session._bounded() + limits.kill_grace <= 110.0
    # a floor lifts a short timeout, but only when it fits at all
    assert session._bounded(floor=3.0) == 0.0  # 2 s of timeout room: cannot fit
    now[0] = 103.0
    assert session._bounded(floor=3.0, reserve=4.0) == 3.0  # 5 s of room: the floor wins


def _clean_up(
    now: list[float], spent: float, *, hostile: bool, list_takes_all: bool
) -> list[tuple[str, float]]:
    """Walk list, stop, forget the way ``_finish`` allocates them, each call using its whole
    timeout (``hostile``: and then the kill grace too). Returns the (verb, timeout) calls."""
    session = _session(now)
    session._shared()  # the budget starts with the first clean-up call
    now[0] += spent  # what the overdue exec path already charged
    steps = (
        ("list", session._list_timeout),
        ("stop", session._stop_timeout),
        ("forget", session._forget_timeout),
    )
    calls: list[tuple[str, float]] = []
    for verb, allot in steps:
        timeout = allot()
        if timeout <= 0:
            continue
        calls.append((verb, timeout))
        used = timeout if (hostile or (verb == "list" and list_takes_all)) else 0.1
        now[0] += used + (session.limits.kill_grace if hostile else 0.0)
    return calls


def test_the_cleanup_budget_is_shared_out_across_list_stop_and_forget() -> None:
    # full budget, everything quick: all three run
    now = [100.0]
    calls = _clean_up(now, 0.0, hostile=False, list_takes_all=False)
    assert [v for v, _ in calls] == ["list", "stop", "forget"]
    assert dict(calls)["list"] == 4.0  # 10 - 2 grace - 3 (stop: grace + 1) - 1 (forget)
    # full budget, a list that takes its whole timeout: stop still gets grace + 1, forget runs
    now = [100.0]
    calls = _clean_up(now, 0.0, hostile=False, list_takes_all=True)
    assert [v for v, _ in calls] == ["list", "stop", "forget"]
    assert dict(calls)["stop"] >= 3.0 and dict(calls)["forget"] >= 1.0
    assert now[0] <= 110.0
    # 8 s remain after the exec path stopped the session; a slow list
    now = [100.0]
    calls = _clean_up(now, 2.0, hostile=False, list_takes_all=True)
    assert [v for v, _ in calls] == ["list", "stop", "forget"]
    assert dict(calls)["list"] == 2.0 and dict(calls)["stop"] >= 3.0
    assert now[0] <= 110.0
    # everything hangs and ignores SIGTERM: never past the budget end
    for spent in (0.0, 2.0, 5.0, 8.0):
        now = [100.0]
        _clean_up(now, spent, hostile=True, list_takes_all=True)
        assert now[0] <= 110.0, spent
    # low budget (5 s left): no list; the stop is still given its grace plus a second
    now = [100.0]
    calls = _clean_up(now, 5.0, hostile=False, list_takes_all=True)
    assert calls[0][0] == "stop" and calls[0][1] >= 3.0
    # too low for even the grace plus the kill grace: nothing
    now = [100.0]
    assert _clean_up(now, 7.5, hostile=False, list_takes_all=True) == []


def test_an_outcome_that_names_another_session_is_dropped_before_the_judge(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    seen: list[agentjudge.RawRun] = []

    def spy(raw: agentjudge.RawRun, *, threshold: float) -> agentjudge.Judgement:
        seen.append(raw)
        return agentjudge.escalate("check_error", "spy")

    monkeypatch.setattr(agentjudge, "judge", spy)
    cmd = patched_cmd(tmp_path, fake, {"exec": {"update": {"csession_id": "cs-aaaaaaaa"}}})
    run_check(tmp_path, capsys, cmd)
    assert [r.outcome for r in seen] == [None]


def test_a_start_error_envelope_that_names_a_session_is_forgotten_by_that_id(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path, "sandbox_unavailable")
    limits_env(monkeypatch)
    seen: list[tuple[Any, Any]] = []
    real = agentjudge.start_failed

    def spy(code: int | None, end_reason: str | None) -> agentjudge.Judgement:
        seen.append((code, end_reason))
        return real(code, end_reason)

    monkeypatch.setattr(agentjudge, "start_failed", spy)
    run_check(tmp_path, capsys, fake.cmd)
    assert seen == [(12, "sandbox_unavailable")]  # the closed token #25 maps, nothing else
    assert fake.unforgotten() == []


@pytest.mark.parametrize("token", ["UPPER", "a b", "a" * 65, "1x", "", "x\n"])
def test_an_end_reason_outside_the_token_grammar_is_not_passed_on(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    token: str,
) -> None:
    fake = Fake(tmp_path, "sandbox_unavailable")
    limits_env(monkeypatch)
    seen: list[tuple[Any, Any]] = []

    def spy(code: int | None, end_reason: str | None) -> agentjudge.Judgement:
        seen.append((code, end_reason))
        return agentjudge.escalate("check_error", "start failed")

    monkeypatch.setattr(agentjudge, "start_failed", spy)
    patch = {"start": {"replace": {"error": {"end_reason": token}}}}
    run_check(tmp_path, capsys, patched_cmd(tmp_path, fake, patch))
    assert seen == [(12, None)]


# --- cancel (the signal path of #35 uses this hook) -----------------------------------------


def test_a_cancelled_run_stops_forgets_and_reports_a_check_error(
    tmp_path: Path, tracker: Tracker, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    fake = Fake(tmp_path, "hang", FAKE_CS_HANG_MAX="30")
    prompt = tmp_path / "prompt.md"
    prompt.write_text(f"Artifact: verdict.json\nNonce: {'a' * 32}\n", encoding="utf-8")
    data = tmp_path / "input.json"
    data.write_text("{}\n", encoding="utf-8")
    from dataclasses import replace

    launch = replace(
        LAUNCH,
        session_cmd=tuple(fake.cmd),
        prompt_file=str(prompt),
        input_file=str(data),
        outcome_file=str(tmp_path / "outcome.json"),
        plugin_dirs=(str(tmp_path),),
        timeout_s=20,
        permission_profile="review",
    )

    def cancel() -> bool:
        return len(fake.records()) > 0 and fake.records()[0]["wrapper_pid"] is not None

    result = agent.run_session(
        tracker.gateway(),
        launch,
        nonce="a" * 32,
        threshold=0.8,
        environ=dict(os.environ),
        limits=agent.Limits(1.5, 10.0, 5.0, 0.5, 0.2, 0.2),
        cancel=cancel,
    )
    assert (result.judgement.verdict, result.judgement.reason) == ("escalate", "check_error")
    assert fake.unforgotten() == []
    assert fake.verbs()[:2] == ["start", "exec"]
    assert "forget" in fake.verbs()


def test_the_pinned_schemas_accept_what_the_fake_prints_for_the_calls_we_make(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fake is the stand-in for the real tool, so what we parse is what the pinned schemas
    describe (the live issue checks the fake against the real one)."""
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    objs: dict[str, Any] = {}
    real_parse = agent.parse_object

    def record(data: bytes) -> Any:
        found = real_parse(data)
        if found is not None:
            key = "status" if "recent_events" in found else "exec" if "phase" in found else "start"
            objs.setdefault(key, found)
        return found

    monkeypatch.setattr(agent, "parse_object", record)
    run_check(tmp_path, capsys, fake.cmd)
    assert set(objs) == {"start", "exec", "status"}
    for name, obj in objs.items():
        schema = {"start": "start", "exec": "outcome", "status": "status"}[name]
        assert pinned_schemas.errors(schema, obj) == []
