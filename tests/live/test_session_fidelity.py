"""Live checks of what the fake claude-session only assumes (issue #27, notes on #4, #24, #25).

Each test calls the REAL claude-session directly with the same ``start`` argv gatectl builds,
prints the raw bodies, and fails with a message naming what differed from the fake. BILLED where a
test says so; the ones marked "no model" never start one. Deselected by default.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from tests import live_util, pinned_schemas
from tests.live.helpers import CLEAR, CLEAR_POLICY
from tests.live_util import Direct, Live, direct_start, observe

pytestmark = pytest.mark.live

FAKE_STATUS_KEYS = {"csession_id", "state", "live", "pending", "run", "runs", "current_run"}
FAKE_RUN_KEYS = {"run", "outcome", "end_reason", "exit_code", "report", "sandbox_active"}


@pytest.fixture
def direct(live: Live):  # type: ignore[no-untyped-def]
    made: list[Direct] = []

    def make(instruction: str = CLEAR_POLICY, obj: Any = CLEAR, **kw: Any) -> Direct:
        d = direct_start(live, instruction, obj, **kw)
        made.append(d)
        return d

    yield make
    for d in made:
        d.cleanup()


def assert_schema(name: str, body: Any) -> None:
    problems = pinned_schemas.errors(name, body)
    assert not problems, f"real {name} output differs from the pinned schema: {problems[:5]}"


def test_start_exec_status_list_forget_shapes_of_a_done_run(live: Live, direct) -> None:  # type: ignore[no-untyped-def]
    """BILLED (1 run). Real ``start``, adopting ``exec --session-id``, ``status`` of a done run,
    ``list`` and ``forget``: shapes against the pinned schemas and against the fake's keys; the
    artifact's sha256 and size against the file; the path already resolved."""
    live.spend(1, "shapes of a done run")
    d = direct()
    assert d.start.code == 0, f"start failed: {d.start.out[-500:]} {d.start.err[-500:]}"
    observe("start", body=d.body)
    assert_schema("start", d.body)
    ran = d.exec(timeout=280)
    outcome = ran.json() if ran.out.strip() else {}
    observe("exec", exit=ran.code, seconds=round(ran.seconds, 1), outcome=outcome)
    assert ran.code == 0, f"exec exit {ran.code}: {ran.out[-600:]} {ran.err[-400:]}"
    assert_schema("exec", outcome)
    status = d.status()
    observe("status", body=status)
    assert_schema("status", status)
    run = status["run"]
    missing = (FAKE_STATUS_KEYS - set(status)) | (FAKE_RUN_KEYS - set(run))
    assert not missing, f"the fake's status keys are absent in the real status: {sorted(missing)}"
    assert (run["outcome"], run["exit_code"], run["implicit_done"]) == ("done", 0, False)
    art = run["report"]["artifact"]
    path = Path(art["path"])
    assert path.is_absolute() and os.path.realpath(path) == str(path), "path is not resolved"
    assert art["name"] == "verdict.json"
    data = path.read_bytes()
    assert art["size"] == len(data) and art["sha256"] == hashlib.sha256(data).hexdigest()
    observe("run economics", cost_usd=run.get("cost_usd"), num_turns=run.get("num_turns"),
            sandbox_active=run.get("sandbox_active"), end_reason=run.get("end_reason"))  # fmt: skip
    assert run["sandbox_active"] is True
    listed = d.verb("list", "--label", f"decision={d.launch.decision_id}", "--json")
    observe("list", out=listed.out[-1200:])
    assert_schema("list", listed.json())
    forgot = d.forget()
    observe("forget", out=forgot.out)
    assert forgot.code == 0
    assert_schema("forget", forgot.json())
    after = d.verb("list", "--label", f"decision={d.launch.decision_id}", "--json").json()
    assert after["sessions"] == [], "forget did not hide the session at once"


def test_a_missing_skill_exits_0_with_an_unusable_artifact(live: Live, direct) -> None:  # type: ignore[no-untyped-def]
    """BILLED (1 run, may be cheap). The fake assumes exit 0, outcome done, and no valid
    artifact. gatectl never sends a missing skill (preflight), so this reads claude-session."""
    live.spend(1, "missing skill")
    d = direct(skill="gatectl:no-such-skill-" + secrets.token_hex(3), timeout_s=60)
    if d.start.code != 0:
        observe("missing skill refused at start", exit=d.start.code, out=d.start.out[-600:])
        pytest.fail(
            f"the fake assumes `start` accepts a missing skill; real start exit {d.start.code}: "
            f"{d.start.out[-400:]}"
        )
    ran = d.exec(timeout=150)
    status = d.status()
    run = status["run"]
    observe("missing skill", exec_exit=ran.code, outcome=ran.out[-800:], state=run.get("outcome"),
            end_reason=run.get("end_reason"), report=run.get("report"))  # fmt: skip
    report = run.get("report") or {}
    artifact = report.get("artifact")
    usable = False
    if artifact and artifact.get("name") == "verdict.json":
        try:
            body = json.loads(Path(artifact["path"]).read_text(encoding="utf-8"))
            usable = isinstance(body, dict) and body.get("nonce") is not None
        except (OSError, ValueError):
            usable = False
    assert not usable, "a missing skill produced a usable verdict artifact"
    assert ran.code in (0, 13, 14, 16, 12), f"unexpected exit for a missing skill: {ran.code}"
    if ran.code != 0:
        pytest.fail(f"fake assumes exit 0 for a missing skill; real exit was {ran.code}")


def test_a_run_that_never_reports_ends_exit_14(live: Live, direct) -> None:  # type: ignore[no-untyped-def]
    """BILLED (1 run). A prompt that forbids the report call: exit 14 (``agent_unreported``)."""
    live.spend(1, "unreported")
    instruction = (
        "TEST OF THE HARNESS. Do not write verdict.json and do NOT run `claude-session report` "
        "at all. Reply with the single word done in plain text and stop."
    )
    d = direct(instruction, timeout_s=90)
    assert d.start.code == 0
    ran = d.exec(timeout=200)
    observe("unreported", exit=ran.code, out=ran.out[-900:])
    if ran.code == 0:
        pytest.skip("the model reported anyway; exit 14 could not be induced (see output)")
    assert ran.code == 14, f"fake assumes exit 14 for an unreported run; real exit {ran.code}"


def test_a_tiny_timeout_ends_exit_16(live: Live, direct) -> None:  # type: ignore[no-untyped-def]
    """BILLED but bounded by the 6 s timeout. The fake assumes exit 16 and a timeout end reason."""
    live.spend(1, "timeout")
    d = direct(timeout_s=6)
    assert d.start.code == 0
    ran = d.exec(timeout=120)
    outcome = ran.json() if ran.out.strip() else {}
    observe("timeout", exit=ran.code, end_reason=outcome.get("end_reason"), out=ran.out[-700:])
    if ran.code == 0:
        pytest.skip("the run finished within 6 s; exit 16 could not be induced")
    assert ran.code == 16, f"fake assumes exit 16 for a timeout; real exit {ran.code}"


def test_start_then_stop_of_a_pending_run_from_a_headless_caller(live: Live, direct) -> None:  # type: ignore[no-untyped-def]
    """No model. ``start`` leaves a pending run; ``forget`` refuses it; ``stop`` cancels it
    (exit 12 for the run, ``canceled``); then ``forget`` works. The caller has no tty."""
    d = direct()
    assert d.start.code == 0, d.start.err[-500:]
    assert d.body.get("run") == 1
    refused = d.forget()
    observe("forget of a pending run", exit=refused.code, out=refused.out[-500:])
    assert refused.code != 0 or refused.json().get("forgotten") == [], (
        "forget accepted a pending run"
    )
    stopped = d.stop()
    observe("stop of a pending run", exit=stopped.code, body=stopped.out)
    body = stopped.json()
    assert_schema("stop", body)
    assert body.get("canceled") is True and body.get("ended") is True, (
        f"the fake assumes a pending run is canceled; real stop body: {body}"
    )
    again = d.stop()
    observe("second stop", exit=again.code, out=again.out[-400:])
    assert d.forget().code == 0


def test_exec_adopts_the_session_from_a_headless_caller_and_stop_grace_timing(
    live: Live, direct
) -> None:  # type: ignore[no-untyped-def]
    """BILLED (1 run, killed early). ``exec --session-id`` adopts the pending session with no tty;
    ``stop --grace 2s`` of the live run returns within a few seconds. Prints the real timing, exit
    code and ``ended`` flag (the fake assumes exit 12, ended false, for a run that did not end)."""
    live.spend(1, "stop grace timing")
    d = direct()
    assert d.start.code == 0
    child = subprocess.Popen(
        [live.session_cmd, "exec", "--session-id", d.session_id, "--run", str(d.run_number),
         "--outcome-file", d.outcome_file, "--json"],
        env=live.env, cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True,
    )  # fmt: skip
    try:
        deadline = time.monotonic() + 60
        state: dict[str, Any] = {}
        while time.monotonic() < deadline and child.poll() is None:
            state = d.status()
            if state.get("live") and not state.get("pending"):
                break
            time.sleep(1)
        observe("run state before stop", live=state.get("live"), pending=state.get("pending"),
                state=state.get("state"))  # fmt: skip
        assert state.get("live") and not state.get("pending"), "exec did not adopt the session"
        began = time.monotonic()
        stopped = d.stop("2s")
        took = time.monotonic() - began
        body = stopped.json() if stopped.out.strip() else {}
        observe(
            "stop --grace 2s of a live run", seconds=round(took, 2), exit=stopped.code, body=body
        )
        assert took < 20, f"stop --grace 2s took {took:.1f} s"
        assert_schema("stop", body)
        child.communicate(timeout=60)
        observe("exec after stop", exit=child.returncode)
    finally:
        if child.poll() is None:
            live_util.stop_group(child)


def test_the_narrow_login_environment_is_enough_for_an_api_key_run(live: Live, direct) -> None:  # type: ignore[no-untyped-def]
    """BILLED (1 run). D-28: does ``exec`` work with ONLY the API key variable (plus PATH, HOME,
    XDG_*) instead of gatectl's ANTHROPIC_*, CLAUDE_*, AWS_*, CLOUD_ML_REGION, GOOGLE_*? If yes,
    open an issue to narrow the allowlist. Skips unless the login is an API key."""
    if not live.real.get("ANTHROPIC_API_KEY"):
        pytest.skip("only an ANTHROPIC_API_KEY login can be narrowed by this probe")
    if live.real.get("CLAUDE_CODE_USE_BEDROCK") or live.real.get("CLAUDE_CODE_USE_VERTEX"):
        pytest.skip("a Bedrock or Vertex provider flag is set: the narrow set is not an API key")
    live.spend(1, "narrow login environment")
    d = direct(timeout_s=120)
    assert d.start.code == 0
    narrow = {k: v for k, v in live.env.items() if k in ("PATH", "HOME", "LANG", "TERM")}
    narrow.update({k: v for k, v in live.env.items() if k.startswith("XDG_")})
    narrow["ANTHROPIC_API_KEY"] = live.real["ANTHROPIC_API_KEY"]
    ran = d.exec(timeout=250, env=narrow)
    observe(
        "narrow environment (API key only)",
        exit=ran.code,
        out=ran.out[-600:],
        required_env_names=d.body.get("required_env_names"),
        env_inherit=d.body.get("env_inherit"),
    )
    assert ran.code == 0, (
        "the API key alone is NOT enough for the adopting exec: keep the wide allowlist (D-28). "
        f"exit {ran.code}"
    )
    observe("conclusion", note="API key alone suffices: open an issue to narrow the env allowlist")
