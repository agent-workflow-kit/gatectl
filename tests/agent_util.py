"""Helpers for the agent run tests: the fake claude-session as ``session_cmd``, its call log and
sessions, short limits, and a stand-in judge for what issue #25 owns.

Every agent test runs against the fake (``tests/fakebin/claude-session``); the real one is only
for the live issue. The fake reads its scenario from ``FAKE_CS_*`` variables, which gatectl's
allowlisted environment would drop, so they travel as ``env NAME=value`` words of ``session_cmd``.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from gatectl import agent, agentcache, agentjudge, engine
from gatectl import store as store_mod
from tests.fake_session import FAKE, FakeSession
from tests.proc_util import Tracker

ENV_BIN = "/usr/bin/env"
POLICY = "p"
# Short limits so a hung fake call costs a second, not five. The argv the fake sees is the same.
FAST = agent.Limits(call_timeout=1.5, exec_margin=1.0, cleanup_budget=5.0, kill_grace=0.5)
DECISION = agentcache.Verdict("allow", 0.95, ("looks fine",))


class Fake:
    """One fake claude-session: a private state directory, a call log and a scenario."""

    def __init__(self, root: Path, scenario: str = "valid", **env: str) -> None:
        self.session = FakeSession(root / "fake", scenario=scenario)
        self.env: dict[str, str] = dict(env)

    @property
    def cmd(self) -> list[str]:
        env = {
            "FAKE_CS_STATE": str(self.session.state),
            "FAKE_CS_LOG": str(self.session.log),
            "FAKE_CS_SCENARIO": self.session.scenario,
            **self.env,
        }
        return [ENV_BIN, *(f"{k}={v}" for k, v in env.items()), sys.executable, str(FAKE)]

    def calls(self) -> list[dict[str, Any]]:
        return self.session.calls()

    def argvs(self) -> list[list[str]]:
        return self.session.argvs()

    def verbs(self) -> list[str]:
        return [a[0] for a in self.argvs()]

    def records(self) -> list[dict[str, Any]]:
        folder = self.session.state / "sessions"
        if not folder.is_dir():
            return []
        found = sorted(folder.glob("cs-*.json"))
        return [json.loads(p.read_text(encoding="utf-8")) for p in found]

    def unforgotten(self) -> list[dict[str, Any]]:
        return [r for r in self.records() if not r["forgotten"]]


WRAPPER = """\
import json, os, subprocess, sys
VERBS = ("start", "exec", "status", "list", "stop", "forget")
verb = next(a for a in sys.argv[1:] if a in VERBS)
patch = json.loads(os.environ.get("WRAP_PATCH", "{}")).get(verb)
done = subprocess.run(sys.argv[1:], capture_output=True)
out = done.stdout
if patch is not None:
    if "raw" in patch:
        out = patch["raw"].encode("utf-8", "surrogateescape")
    else:
        obj = json.loads(out)
        if "append" in patch:
            for key, item in patch["append"].items():
                obj[key] = [*obj[key], item]
        else:
            obj = patch["replace"] if "replace" in patch else {**obj, **patch["update"]}
        out = json.dumps(obj).encode()
sys.stdout.buffer.write(out)
sys.stderr.buffer.write(done.stderr)
sys.exit(patch.get("exit", done.returncode) if patch else done.returncode)
"""


def patched_cmd(root: Path, fake: Fake, patch: dict[str, Any]) -> list[str]:
    """``session_cmd`` that runs the fake and then rewrites one verb's stdout (and exit code):
    ``{verb: {"update": {...}} | {"replace": obj} | {"append": {key: item}} | {"raw": text}}``,
    each optionally with ``"exit": n``."""
    script = root / "wrap.py"
    script.write_text(WRAPPER, encoding="utf-8")
    return [ENV_BIN, f"WRAP_PATCH={json.dumps(patch)}", sys.executable, str(script), *fake.cmd]


def agent_check(name: str = "a", **extra: Any) -> dict[str, Any]:
    return {"name": name, "type": "agent", "instruction": "Be careful.", **extra}


def config(
    fake: Fake | None,
    *,
    checks: list[dict[str, Any]] | None = None,
    top: dict[str, Any] | None = None,
    session_cmd: list[str] | None = None,
    agent_block: dict[str, Any] | None = None,
    **policy: Any,
) -> dict[str, Any]:
    """A config document with one policy ``p`` made of ``checks`` (default: one agent check)."""
    body: dict[str, Any] = {
        "checks": checks if checks is not None else [agent_check()],
        "timeout": "40s",
        **policy,
    }
    doc: dict[str, Any] = {
        "defaults": {"record_reserve": "200ms"},
        "agent": {"min_start_budget": "1s", "cache_ttl": "10m", **(agent_block or {})},
        "policies": {POLICY: body},
    }
    if session_cmd is not None:
        doc["session_cmd"] = session_cmd
    elif fake is not None:
        doc["session_cmd"] = fake.cmd
    doc.update(top or {})
    return doc


def limits_env(
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker | None = None,
    limits: agent.Limits = FAST,
    **extra: Any,
) -> None:
    """Make ``check`` run with short limits and, when given, the pid-tracking gateway."""

    def make() -> engine.Env:
        if tracker is not None:
            return engine.Env(gateway=tracker.gateway(), limits=limits, **extra)
        return engine.Env(limits=limits, **extra)

    monkeypatch.setattr(engine, "default_env", make)


def judged(
    monkeypatch: pytest.MonkeyPatch,
    verdict: agentcache.Verdict | None = DECISION,
    threshold_from: Callable[[], float] | None = None,
) -> list[agentjudge.RawRun]:
    """Stand in for issue #25's judge: every completed run is the validated ``verdict``.

    Returns the list of the ``RawRun`` values the judge was given (what #25 will receive).
    """
    seen: list[agentjudge.RawRun] = []

    def fake_judge(raw: agentjudge.RawRun, *, threshold: float) -> agentjudge.Judgement:
        seen.append(raw)
        if raw.exec_code != 0 or raw.status is None:  # the table of #25, in one line
            return agentjudge.Judgement("escalate", "check_error", "stand-in")
        if verdict is None:
            return agentjudge.Judgement("escalate", "artifact_invalid", "stand-in")
        return agentjudge.from_verdict(verdict, threshold, cacheable=True)

    monkeypatch.setattr(agentjudge, "judge", fake_judge)
    return seen


def tmp_entries(state_dir: Path) -> list[str]:
    folder = state_dir / "tmp"
    return sorted(os.listdir(folder)) if folder.is_dir() else []


def state_store() -> store_mod.Store:
    """The state database of the isolated state directory, opened for writing."""
    store = store_mod.open_store(create=True)
    assert store is not None
    return store
