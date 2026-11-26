"""The supervisor's job format and entry point, the launcher's spec, the engine wiring and the
concurrency bound. Hostile jobs and hostile hook lists never run anything."""

from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from gatectl import engine, hooks
from gatectl.cli import main
from gatectl.gateway import Stdio
from gatectl.hooks import HookCommand, HookEvent
from tests import schema_util
from tests.check_util import isolate
from tests.command_util import config_file
from tests.fake_gateway import FakeGateway
from tests.hook_util import hook, hook_config
from tests.test_check_process import RULE


def ev(*cmds: str, **kw: Any) -> HookEvent:
    fields: dict[str, Any] = {
        "hook": "post-decision",
        "object_type": "decision",
        "object_id": "gd-abcdefghijkl",
        "payload": {"tool": "gatectl"},
        "commands": tuple(HookCommand(c, 5.0) for c in cmds),
        "policy": "p",
        "scope": "*",
        "decision_id": "gd-abcdefghijkl",
    }
    fields.update(kw)
    return HookEvent(**fields)


def run_supervisor(tmp_path: Path, stdin: bytes) -> subprocess.CompletedProcess[bytes]:
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {"PATH": os.environ["PATH"], "HOME": str(home), "XDG_STATE_HOME": str(home / "state")}
    return subprocess.run(
        [sys.executable, "-I", "-m", "gatectl.supervisor"],
        input=stdin,
        capture_output=True,
        env=env,
        timeout=60,
        check=False,
    )


# --- the job frame -----------------------------------------------------------------------------


def test_a_job_round_trips(tmp_path: Path) -> None:
    original = ev("echo hi", "exit 1")
    parsed, state = hooks.parse_job(hooks.encode_job(original, tmp_path / "state"))
    assert parsed == original and state == tmp_path / "state"


def test_the_job_carries_the_payload_and_never_puts_it_in_argv_or_env() -> None:
    frame = hooks.encode_job(ev("true", payload={"canary": "CANARY-99"}), Path("/s"))
    assert b"CANARY-99" in frame
    spec = hooks.supervisor_spec({"A": "b"})
    assert "CANARY-99" not in " ".join(spec.argv) and "CANARY-99" not in str(dict(spec.env or {}))


@pytest.mark.parametrize(
    "frame",
    [
        b"",
        b"\n",
        b"GATECTL-HOOKS 1 5\nabc",
        b"GATECTL-HOOKS 1 2\n[]",
        b"GATECTL-HOOKS 1 x\n{}",
        b"GATECTL-HOOKS 2 2\n{}",
        b"GATECTL-HOOKS 1 -1\n{}",
        b"GATECTL-HOOKS 1 2\n{}",
        b"GATECTL-HOOKS 1 18\n" + b'{"payload": null}'[:17],
    ],
)
def test_malformed_frames_are_refused(frame: bytes) -> None:
    with pytest.raises(hooks.JobInvalid):
        hooks.parse_job(frame)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(hook="pre-launch"),
        lambda d: d.update(state_dir="relative/dir"),
        lambda d: d.update(commands="rm -rf /"),
        lambda d: d.update(commands=[{"cmd": 1, "timeout": 1}]),
        lambda d: d.update(commands=[{"cmd": "x", "timeout": True}]),
        lambda d: d.update(commands=[{"cmd": "x"}]),
        lambda d: d.update(payload=[1]),
        lambda d: d.update(object_id="x" * 5000),
        lambda d: d.update(object_id=5),
    ],
)
def test_a_well_framed_job_with_hostile_content_is_refused(mutate: Any) -> None:
    doc = json.loads(hooks.encode_job(ev("true"), Path("/s")).split(b"\n", 1)[1])
    mutate(doc)
    body = json.dumps(doc).encode()
    with pytest.raises(hooks.JobInvalid):
        hooks.parse_job(b"GATECTL-HOOKS 1 " + str(len(body)).encode() + b"\n" + body)


# --- the supervisor process --------------------------------------------------------------------


@pytest.mark.parametrize(
    "stdin",
    [
        b"",
        b"garbage",
        b"GATECTL-HOOKS 1 99999999999\n",
        b"GATECTL-HOOKS 1 10\nshort",
        b"\x00" * 100,
    ],
)
def test_the_supervisor_ends_quietly_on_a_hostile_job_and_runs_nothing(
    tmp_path: Path, stdin: bytes
) -> None:
    done = run_supervisor(tmp_path, stdin)
    assert (done.returncode, done.stdout, done.stderr) == (0, b"", b"")
    assert not (tmp_path / "home" / "state" / "gatectl" / "tmp").exists()


def test_the_supervisor_runs_the_job_and_logs_a_failure(tmp_path: Path) -> None:
    state = tmp_path / "state"
    marker = tmp_path / "ran"
    job = hooks.encode_job(ev(f"touch {marker}", "exit 4"), state)
    done = run_supervisor(tmp_path, job)
    assert (done.returncode, done.stdout, done.stderr) == (0, b"", b"")
    assert marker.exists()
    records = [json.loads(x) for x in (state / "log.jsonl").read_text().splitlines()]
    assert [r["data"] for r in records] == [{"index": 1, "reason": "exit", "exit_code": 4}]


def test_with_every_slot_taken_the_hooks_are_skipped_and_logged_busy(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    held = []
    try:
        for n in range(hooks.MAX_SLOTS):
            fd = os.open(state / f"hook-slot-{n}.lock", os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            held.append(fd)
        marker = tmp_path / "ran"
        done = run_supervisor(tmp_path, hooks.encode_job(ev(f"touch {marker}"), state))
        assert done.returncode == 0 and not marker.exists()
        (rec,) = [json.loads(x) for x in (state / "log.jsonl").read_text().splitlines()]
        assert (rec["event"], rec["data"]["reason"]) == ("hook_skipped", "busy")
    finally:
        for fd in held:
            os.close(fd)


def test_a_slot_is_free_again_when_its_holder_ends(tmp_path: Path) -> None:
    first = hooks.acquire_slot(tmp_path)
    assert first is not None
    os.close(first)
    again = hooks.acquire_slot(tmp_path)
    assert again is not None
    os.close(again)


def test_slots_are_close_on_exec_so_no_hook_inherits_one(tmp_path: Path) -> None:
    fd = hooks.acquire_slot(tmp_path)
    assert fd is not None
    try:
        assert not os.get_inheritable(fd)
    finally:
        os.close(fd)


# --- the launcher ------------------------------------------------------------------------------


def test_start_detached_starts_one_supervisor_with_explicit_streams_and_its_own_session(
    tmp_path: Path,
) -> None:
    gw = FakeGateway()
    ok = hooks.start_detached(gw, ev("true"), state_dir=tmp_path, environ={"A": "1"})
    assert ok and len(gw.calls) == 1
    spec = gw.calls[0]
    assert spec.argv[1:] == ("-I", "-m", "gatectl.supervisor")
    assert (spec.stdin, spec.stdout, spec.stderr) == (Stdio.PIPE, Stdio.DEVNULL, Stdio.DEVNULL)
    assert spec.new_session and spec.cwd == "/" and dict(spec.env or {}) == {"A": "1"}


def test_start_detached_with_no_hooks_starts_nothing(tmp_path: Path) -> None:
    gw = FakeGateway()
    assert not hooks.start_detached(gw, ev(), state_dir=tmp_path, environ={})
    assert gw.calls == []


def test_start_detached_never_raises_when_the_supervisor_cannot_start(tmp_path: Path) -> None:
    class Broken:
        def start(self, spec: object) -> object:
            raise OSError(2, "no such file")

    assert not hooks.start_detached(Broken(), ev("true"), state_dir=tmp_path, environ={})  # type: ignore[arg-type]
    (rec,) = [json.loads(x) for x in (tmp_path / "log.jsonl").read_text().splitlines()]
    assert (rec["event"], rec["data"]["reason"]) == ("hook_skipped", "not_started")


def test_start_detached_refuses_a_payload_json_cannot_hold(tmp_path: Path) -> None:
    gw = FakeGateway()
    bad = ev("true", payload={"x": float("nan")})
    assert not hooks.start_detached(gw, bad, state_dir=tmp_path, environ={})
    assert gw.calls == []


def test_a_supervisor_that_never_takes_its_job_is_killed_and_the_event_skipped(
    tmp_path: Path, tracker: Any
) -> None:
    from gatectl.gateway import ChildSpec

    class Stalled:
        """A child whose stdin pipe is full and never drained, as a hung supervisor's would be."""

        def __init__(self) -> None:
            self.inner = tracker.gateway()

        def start(self, spec: ChildSpec) -> Any:
            argv = (sys.executable, "-c", "import time; time.sleep(60)")
            return self.inner.start(
                ChildSpec(
                    argv,
                    stdin=spec.stdin,
                    stdout=spec.stdout,
                    stderr=spec.stderr,
                    new_session=True,
                )
            )

    big = ev("true", payload={"pad": "x" * 200_000})
    assert not hooks.start_detached(Stalled(), big, state_dir=tmp_path, environ={}, deadline=0.5)
    (rec,) = [json.loads(x) for x in (tmp_path / "log.jsonl").read_text().splitlines()]
    assert (rec["event"], rec["data"]["reason"]) == ("hook_skipped", "handoff_failed")
    pid = tracker.items[-1].pid
    assert tracker.wait_dead(pid, 5.0)  # its own group was killed


def test_an_oversized_payload_is_never_sent(tmp_path: Path) -> None:
    gw = FakeGateway()
    huge = ev("true", payload={"pad": "x" * (hooks.MAX_PAYLOAD * 3)})
    assert not hooks.start_detached(gw, huge, state_dir=tmp_path, environ={})
    assert gw.calls == []


# --- the engine wiring -------------------------------------------------------------------------


def configure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *hooks_: dict[str, Any]
) -> tuple[str, FakeGateway]:
    isolate(monkeypatch, tmp_path)
    gw = FakeGateway()
    real = engine.Env
    monkeypatch.setattr(engine, "Env", lambda: real(gateway=gw))
    return hook_config(tmp_path, *hooks_), gw


def test_a_recorded_check_starts_the_supervisor_with_the_schema_valid_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config, gw = configure(tmp_path, monkeypatch, hook("one"), hook("two", async_=True))
    stdin = tmp_path / "in.json"
    stdin.write_text('{"ci": "ok", "note": "INPUT-TEXT"}')
    code = main(["check", "p", "--config", config, "--input", str(stdin)])
    out = json.loads(capsys.readouterr().out)
    assert code == 0 and len(gw.calls) == 1
    parsed, _ = hooks.parse_job(gw.children[0].stdin_written)
    assert [c.cmd for c in parsed.commands] == ["one", "two"]  # config order, async or not
    schema_util.assert_valid("hooks/post-decision", dict(parsed.payload))
    assert parsed.payload["object_id"] == out["decision_id"]
    assert "INPUT-TEXT" not in json.dumps(dict(parsed.payload)) and "labels" not in parsed.payload


@pytest.mark.parametrize("state", ["off"])
def test_no_hook_supervisor_for_an_off_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], state: str
) -> None:
    config, gw = configure(tmp_path, monkeypatch, hook("one"))
    assert main(["set", "p", state, "--config", config, "--actor", "human:ann"]) == 0
    capsys.readouterr()
    assert main(["check", "p", "--config", config]) == 0
    assert gw.calls == []


def test_no_hook_supervisor_for_not_applicable_or_a_check_that_records_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    isolate(monkeypatch, tmp_path)
    gw = FakeGateway()
    real = engine.Env
    monkeypatch.setattr(engine, "Env", lambda: real(gateway=gw))
    na = {"applies_when": [{"path": "kind", "op": "eq", "value": "x"}], "checks": [RULE]}
    config = config_file(
        tmp_path,
        {"policies": {"p": na}, "hooks": {"post-decision": [hook("one")]}},
    )
    stdin = tmp_path / "in.json"
    stdin.write_text('{"kind": "y"}')
    assert main(["check", "p", "--config", config, "--input", str(stdin)]) == 0
    assert json.loads(capsys.readouterr().out)["reason"] == "not_applicable"
    assert gw.calls == []


def test_no_supervisor_is_started_when_no_hook_is_configured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config, gw = configure(tmp_path, monkeypatch)
    assert main(["check", "p", "--config", config]) == 0
    assert gw.calls == []


def test_a_hook_launcher_that_raises_never_changes_the_exit_code_or_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config, _ = configure(tmp_path, monkeypatch, hook("one"))

    def boom(*a: object, **k: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(hooks, "start_detached", boom)
    code = main(["check", "p", "--config", config])
    out = capsys.readouterr()
    assert code == 0 and json.loads(out.out)["decision"] in ("allow", "escalate")
    assert "boom" not in out.err
