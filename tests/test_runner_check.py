"""``run_script_check``: the working directory, the environment and the failure paths."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from gatectl.gateway import Child, ChildSpec, Gateway
from gatectl.runner import RunSpec, run_process, run_script_check
from tests.proc_util import Tracker

PY = sys.executable
ID = "gd-abcdefghijkl"


def check(tracker: Tracker, state: Path, code: str, **kw: object):  # type: ignore[no-untyped-def]
    params: dict[str, object] = {
        "argv": (PY, "-c", code),
        "payload": b"{}",
        "timeout": 10.0,
        "env_allow": [],
        "default_env_allow": ["PATH", "HOME", "LANG", "LC_*"],
        "environ": {"PATH": "/usr/bin:rel", "HOME": "/h", "GITHUB_TOKEN": "t", "X": "1"},
        "state_dir": state,
        "decision_id": ID,
        "n": 1,
    }
    params.update(kw)
    return run_script_check(tracker.gateway(), **params)  # type: ignore[arg-type]


def test_the_check_runs_in_its_private_empty_directory_removed_afterwards(
    tracker: Tracker, tmp_path: Path
) -> None:
    code = (
        "import json, os, stat\n"
        "info = os.stat('.')\n"
        "print(json.dumps({'reason': json.dumps([os.getcwd(), os.listdir('.'),"
        " stat.S_IMODE(info.st_mode)])}))\n"
        "raise SystemExit(11)"
    )
    o = check(tracker, tmp_path, code)
    import json

    cwd, listing, mode = json.loads(o.detail or "[]")
    assert Path(cwd) == (tmp_path / "tmp" / ID / "s-1").resolve()
    assert listing == [] and mode == 0o700
    assert not (tmp_path / "tmp" / ID / "s-1").exists()
    assert (tmp_path / "tmp" / ID / "owner").exists()  # the decision's directory is the caller's


def test_the_second_script_check_gets_its_own_directory(tracker: Tracker, tmp_path: Path) -> None:
    check(tracker, tmp_path, "pass", n=1)
    o = check(tracker, tmp_path, "pass", n=2)
    assert o.verdict == "allow"
    assert sorted(p.name for p in (tmp_path / "tmp" / ID).iterdir()) == ["owner"]


def test_files_the_check_leaves_behind_are_removed(tracker: Tracker, tmp_path: Path) -> None:
    code = (
        "import os\n"
        "os.mkdir('d'); open('d/f', 'w').write('x'); os.chmod('d', 0o000)\n"
        "os.symlink('/etc', 'link')\n"
    )
    o = check(tracker, tmp_path, code)
    assert o.verdict == "allow" and not o.workdir_left
    assert not (tmp_path / "tmp" / ID / "s-1").exists()


def test_a_directory_that_cannot_be_removed_safely_is_left_and_reported(
    tracker: Tracker, tmp_path: Path
) -> None:
    o = check(tracker, tmp_path, "import os; os.mkfifo('p')")
    assert o.verdict == "allow" and o.workdir_left
    assert stat.S_ISFIFO(os.lstat(tmp_path / "tmp" / ID / "s-1" / "p").st_mode)


def test_environment_is_built_from_the_allowlists(tracker: Tracker, tmp_path: Path) -> None:
    code = (
        "import json, os\n"
        "env = {k: v for k, v in os.environ.items() if k != 'LC_CTYPE'}\n"
        "print(json.dumps({'reason': json.dumps(env, sort_keys=True)}))\n"
        "raise SystemExit(11)"
    )
    import json

    o = check(tracker, tmp_path, code)
    assert json.loads(o.detail or "{}") == {"PATH": "/usr/bin", "HOME": "/h"}
    o = check(tracker, tmp_path, code, env_allow=["X", "GITHUB_TOKEN"], n=2)
    assert json.loads(o.detail or "{}")["GITHUB_TOKEN"] == "t"


def test_a_bad_env_allow_is_refused_before_anything_runs(tracker: Tracker, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="env_allow"):
        check(tracker, tmp_path, "pass", env_allow=["A*"])
    assert not (tmp_path / "tmp").exists()


def test_a_bad_decision_id_is_refused(tracker: Tracker, tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="decision id"):
        check(tracker, tmp_path, "pass", decision_id="../escape")


def test_unusable_state_dir_means_the_check_did_not_run(tracker: Tracker, tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("x")
    o = check(tracker, blocker, "pass")
    assert (o.verdict, o.reason, o.detail) == ("escalate", "check_error", "not started")


def test_missing_tool_never_starts_anything(tracker: Tracker, tmp_path: Path) -> None:
    gw = tracker.gateway()
    o = run_script_check(
        gw,
        argv=("/nonexistent/tool",),
        payload=b"{}",
        timeout=5.0,
        env_allow=[],
        default_env_allow=[],
        environ={},
        state_dir=tmp_path,
        decision_id=ID,
        n=1,
    )
    assert (o.verdict, o.reason, o.detail) == ("escalate", "tool_missing", "/nonexistent/tool")
    assert gw.specs == []


# --- failure paths of the watchdog ---------------------------------------------------------


class _BrokenStdin:
    def __init__(self, real: object) -> None:
        self._real = real

    def write(self, data: bytes) -> int:
        raise BrokenPipeError

    def flush(self) -> None:
        raise BrokenPipeError

    def close(self) -> None:
        self._real.close()  # type: ignore[attr-defined]


class _NoLifelineGateway:
    """The first child (the watchdog) has a lifeline that cannot be written."""

    def __init__(self, tracker: Tracker) -> None:
        self._real = tracker.gateway()
        self._first = True

    def start(self, spec: ChildSpec) -> Child:
        child = self._real.start(spec)
        if self._first:
            self._first = False
            child.stdin = _BrokenStdin(child.stdin)  # type: ignore[assignment]
        return child


class _FailingWatchdogGateway:
    def __init__(self) -> None:
        self.started: list[ChildSpec] = []

    def start(self, spec: ChildSpec) -> Child:
        self.started.append(spec)
        raise OSError("no fork for you")


def spec(code: str) -> RunSpec:
    return RunSpec(argv=(PY, "-c", code), env={}, cwd="/", timeout=10.0)


def test_a_watchdog_that_cannot_start_means_the_check_does_not_run() -> None:
    gw: Gateway = _FailingWatchdogGateway()
    r = run_process(gw, spec("pass"))
    assert r.status == "not_started"
    assert len(gw.started) == 1  # type: ignore[attr-defined]


def test_a_check_with_no_lifeline_is_stopped_and_not_started(tracker: Tracker) -> None:
    gw = _NoLifelineGateway(tracker)
    r = run_process(gw, spec("import time; time.sleep(60)"))
    assert r.status == "not_started"
    # Both children are gone: the check was killed and reaped, the watchdog released.
    assert all(not tracker.alive(item.pid) for item in tracker.items)
