"""Support for the live agent tests (``tests/live/``, issue #27).

The live tests run the REAL claude-session and a REAL, BILLED model. Nothing here starts either;
the helpers that do (``Live.gatectl``, ``Live.session``) are only called from tests marked
``live``, which are deselected by default and need ``GATECTL_LIVE=1``.

Safety rules the helpers enforce:

- A private ``HOME`` and private XDG directories per test (``private_env``), so the user's
  claude-session state and gatectl state are never read or written. ``GATECTL_LIVE_HOME=real``
  keeps only ``HOME`` (for a subscription login under ``~/.claude``); every XDG directory stays
  private.
- A hard cap on model runs (``RunBudget``, default 24, ``GATECTL_LIVE_MAX_RUNS``).
- A child is only ever signalled by the PID (and process group) this module started.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from gatectl import config as config_mod

LIVE_VAR = "GATECTL_LIVE"
HOME_VAR = "GATECTL_LIVE_HOME"
MODEL_VAR = "GATECTL_LIVE_MODEL"
BUDGET_VAR = "GATECTL_LIVE_MAX_RUNS"
DEFAULT_MAX_RUNS = 24
DEFAULT_MODEL = "haiku"

# Captured at import, before the autouse fixture of tests/conftest.py points HOME at a scratch
# directory: the live tests need the real login variables and the real HOME (real-home mode).
REAL_ENV: Mapping[str, str] = dict(os.environ)

LOGIN_VARS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN")
PROVIDER_FLAGS = ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX")
# What gatectl's own allowlist lets through to claude-session besides the basics (D-28), as an
# explicit list: never a CLAUDE_ prefix, which would forward CLAUDE_CONFIG_DIR (it bypasses the
# private HOME) and CLAUDE_CODE_ENTRYPOINT.
FORWARD_PREFIXES = ("ANTHROPIC_", "AWS_", "GOOGLE_")
FORWARD_NAMES = (
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLOUD_ML_REGION",
    "PATH",
    "LANG",
    "TERM",
    "USER",
    "LOGNAME",
    "TMPDIR",
)

# The rows of the live verification table (docs/design.md) that belong to agent checks. The
# docs test checks each appears in both the table and the live test map.
AGENT_TABLE_ROWS = (
    "A headless `gate-check` round trip",
    "exits 0 with outcome `done` for a missing skill",
    "Confidence is not calibrated",
    "Under `dontAsk`",
    "A sandboxed run needs placeholder files",
    "`claude-session --dry-run` reports the sandbox available",
    "A run with no report ends exit 14",
    "Three to six parallel runs",
    "A sandboxed injection attempt",
    "`forget` hides the session at once",
    "After a SIGKILL of gatectl",
    "claude-session `start --json` prints",
    "A single Read of a large one-line file",
)


# --- prerequisites --------------------------------------------------------------------------


def _read_proc_version() -> str:
    try:
        return Path("/proc/version").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _resolve(environ: Mapping[str, str]) -> list[str] | None:
    return config_mod.resolve_session_cmd(["claude-session"], environ=environ)


def real_home_mode(environ: Mapping[str, str]) -> bool:
    return environ.get(HOME_VAR) == "real"


def real_home_warning(environ: Mapping[str, str]) -> str | None:
    """The text printed when ``GATECTL_LIVE_HOME=real`` is active; ``None`` otherwise."""
    if not real_home_mode(environ):
        return None
    home = environ.get("HOME", "~")
    return (
        f"GATECTL_LIVE_HOME=real: the live tests use your REAL home {home}. Transcripts of "
        "hostile inputs are written under ~/.claude/projects; ~/.claude.json and an OAuth "
        "refresh-token rotation may sign out your real install; the tool-induction test reads "
        "your recent real transcripts. On macOS the login is in the Keychain, so real mode "
        "skips there. Prefer an API key with the private home."
    )


def session_version(command: str, environ: Mapping[str, str]) -> str:
    """``claude-session --version`` for the prerequisites output (``unknown`` if it cannot run)."""
    try:
        done = subprocess.run(
            [command, "--version"],
            env={"PATH": environ.get("PATH", ""), "HOME": "/nonexistent"},
            capture_output=True,
            text=True,
            timeout=30,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return (done.stdout.strip() or "unknown")[:80]


def live_summary(*, passed: int, skipped: int, failed: int) -> tuple[str, bool]:
    """The closing note of a live run and whether to force a failing exit status: a run in
    which live tests were selected but none passed (all skipped) proves nothing."""
    if passed + skipped + failed == 0:
        return "", False
    note = (
        f"live summary: {passed} passed, {skipped} skipped, {failed} failed. Skipped live "
        "tests prove nothing: read the skip reasons (-rs)."
    )
    if passed == 0 and failed == 0:
        return note + " NO live test passed: failing this run on purpose.", True
    return note, False


def missing_prerequisites(
    environ: Mapping[str, str],
    *,
    platform: str = sys.platform,
    proc_version: str | None = None,
    which: Callable[..., str | None] = shutil.which,
    resolve: Callable[[Mapping[str, str]], list[str] | None] = _resolve,
    exists: Callable[[str], bool] = os.path.exists,
) -> list[str]:
    """Everything that stops a live run, as messages for the skip text. Empty means go."""
    missing: list[str] = []
    if environ.get(LIVE_VAR) != "1":
        missing.append(
            f"set {LIVE_VAR}=1 to run the live tests: they start the real claude-session and a "
            "real model and are BILLED (use `make live GATECTL_LIVE=1`)"
        )
    if resolve(environ) is None:
        dirs = ", ".join(config_mod.SESSION_CMD_DIRS)
        missing.append(f"claude-session not found in {dirs}")
    if which("claude", path=environ.get("PATH")) is None:
        missing.append("`claude` (Claude Code) is not on PATH")
    if platform.startswith("linux"):
        version = _read_proc_version() if proc_version is None else proc_version
        if "microsoft" in version.lower() and "wsl2" not in version.lower():
            missing.append("WSL1 has no sandbox (the live tests need WSL2, Linux or macOS)")
        else:
            for name in ("bwrap", "socat"):
                if which(name, path=environ.get("PATH")) is None:
                    missing.append(f"sandbox prerequisite `{name}` (bubblewrap, socat) is missing")
    elif platform == "darwin":
        if not exists("/usr/bin/sandbox-exec"):
            missing.append("sandbox prerequisite /usr/bin/sandbox-exec (Seatbelt) is missing")
    else:
        missing.append(f"platform {platform} has no supported sandbox")
    home = environ.get("HOME", "")
    creds = os.path.join(home, ".claude", ".credentials.json")
    logged_in = any(environ.get(n) for n in (*LOGIN_VARS, *PROVIDER_FLAGS)) or (
        real_home_mode(environ) and exists(creds)
    )
    if not logged_in:
        missing.append(
            "no login: set ANTHROPIC_API_KEY (or ANTHROPIC_AUTH_TOKEN, CLAUDE_CODE_OAUTH_TOKEN, "
            "CLAUDE_CODE_USE_BEDROCK=1, CLAUDE_CODE_USE_VERTEX=1 with its provider variables); "
            f"a subscription login under ~/.claude needs {HOME_VAR}=real"
        )
    return missing


# --- the private environment ------------------------------------------------------------------


def private_env(root: Path, real: Mapping[str, str] | None = None) -> dict[str, str]:
    """The environment of every live subprocess: private HOME and XDG directories under ``root``,
    PATH and locale, and only the login variables of ``real`` (never CSESSION_*, GATECTL_*)."""
    src = REAL_ENV if real is None else real
    home = str(root / "home") if not real_home_mode(src) else src.get("HOME", str(root / "home"))
    env = {
        "HOME": home,
        "XDG_CONFIG_HOME": str(root / "xdg" / "config"),
        "XDG_DATA_HOME": str(root / "xdg" / "data"),
        "XDG_STATE_HOME": str(root / "xdg" / "state"),
        "XDG_CACHE_HOME": str(root / "xdg" / "cache"),
    }
    for name, value in src.items():
        if name in env or name.startswith(("GATECTL_", "CSESSION_", "XDG_")):
            continue
        if name in FORWARD_NAMES or name.startswith(FORWARD_PREFIXES):
            env[name] = value
    return env


# --- the run budget -----------------------------------------------------------------------------


class BudgetExceeded(Exception):
    pass


class BudgetConfigError(ValueError):
    pass


@dataclass
class RunBudget:
    """A hard cap on model runs for the whole session; one ``spend`` per run a test may start."""

    cap: int
    used: int = 0
    log: list[str] = field(default_factory=list)

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> RunBudget:
        if BUDGET_VAR not in environ:
            return cls(DEFAULT_MAX_RUNS)
        raw = environ[BUDGET_VAR]
        try:
            cap = int(raw)
        except ValueError:
            cap = 0
        if cap <= 0:
            raise BudgetConfigError(
                f"{BUDGET_VAR}={raw!r} is not a positive integer; unset it for the default "
                f"({DEFAULT_MAX_RUNS}) or give the cap of model runs you accept"
            )
        return cls(cap)

    def spend(self, runs: int, what: str) -> None:
        if self.used + runs > self.cap:
            raise BudgetExceeded(
                f"{what}: {runs} model run(s) would pass the cap of {self.cap} "
                f"({self.used} used); raise {BUDGET_VAR} on purpose to go on"
            )
        self.used += runs
        self.log.append(f"{what}: {runs}")


# --- transcripts ----------------------------------------------------------------------------------

FORBIDDEN_TOOLS = ("Agent", "Task")


@dataclass
class Transcripts:
    tools: list[str] = field(default_factory=list)
    files: int = 0
    assistant_messages: int = 0


def transcript_tools(home: Path, marker: str, *, since: float) -> Transcripts:
    """Tool names used in Claude Code transcripts under ``home``/.claude/projects that were
    modified at or after ``since`` and mention ``marker`` (a random token the test put into
    that run's input), in file and line order."""
    found = Transcripts()
    root = home / ".claude" / "projects"
    if not root.is_dir():
        return found
    for path in sorted(root.rglob("*.jsonl")):
        try:
            if path.stat().st_mtime < since:
                continue
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if marker not in raw:
            continue
        found.files += 1
        for row in raw.splitlines():
            try:
                obj = json.loads(row)
            except ValueError:
                continue
            if not isinstance(obj, dict) or obj.get("type") != "assistant":
                continue
            found.assistant_messages += 1
            message = obj.get("message")
            content = message.get("content") if isinstance(message, dict) else None
            for part in content if isinstance(content, list) else []:
                if isinstance(part, dict) and part.get("type") == "tool_use":
                    found.tools.append(str(part.get("name")))
    return found


def forbidden_tools(tools: Sequence[str]) -> list[str]:
    return [t for t in tools if t in FORBIDDEN_TOOLS]


# --- running things -----------------------------------------------------------------------------


@dataclass
class Proc:
    argv: list[str]
    code: int | None
    out: str
    err: str
    seconds: float
    timed_out: bool = False

    def json(self) -> Any:
        return json.loads(self.out)


def run(
    argv: Sequence[str],
    env: Mapping[str, str],
    *,
    timeout: float,
    stdin: bytes | None = None,
    cwd: str = "/",
) -> Proc:
    """Run ``argv`` headless (no tty, own process group). On timeout or an interrupt, signal
    exactly the group of the child this call started, then reap it."""
    began = time.monotonic()
    child = subprocess.Popen(
        list(argv),
        env=dict(env),
        cwd=cwd,
        stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    timed_out = False
    try:
        out, err = child.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        out, err = stop_group(child)
    except BaseException:  # noqa: BLE001 - KeyboardInterrupt too: never leave the child running
        stop_group(child)
        raise
    return Proc(
        list(argv),
        child.returncode,
        out.decode("utf-8", "replace"),
        err.decode("utf-8", "replace"),
        time.monotonic() - began,
        timed_out,
    )


def stop_group(child: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
    """SIGTERM then SIGKILL to the group of a child we started and have not yet reaped. Prints
    the pid and pgid when the child is still not reaped after SIGKILL."""
    out = err = b""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            pass
        try:
            out, err = child.communicate(timeout=5)
            return out, err
        except subprocess.TimeoutExpired:
            continue
    print(
        f"[live] LEFTOVER: child pid {child.pid} (pgid {child.pid}) did not end after SIGTERM "
        "and SIGKILL; stop it by hand (exact pid, never by pattern)"
    )
    return out, err


def _proc_stat(pid: int) -> tuple[str, int] | None:
    """(state, pgrp) of ``pid`` from /proc, or ``None`` when it is gone or unreadable."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    rest = raw.rsplit(")", 1)[-1].split()
    try:
        return rest[0], int(rest[2])
    except (IndexError, ValueError):
        return None


def pid_alive(pid: int) -> bool:
    """Whether ``pid`` is a live (non-zombie) process; reads /proc, sends no signal."""
    stat = _proc_stat(pid)
    return stat is not None and stat[0] != "Z"


def group_members(pgid: int) -> list[int]:
    """Pids whose process group is exactly ``pgid`` (read from /proc, no signal sent)."""
    found: list[int] = []
    try:
        names = os.listdir("/proc")
    except OSError:
        return found
    for name in names:
        if name.isdigit():
            stat = _proc_stat(int(name))
            if stat is not None and stat[1] == pgid:
                found.append(int(name))
    return sorted(found)


def label_problems(labels: Sequence[str], *, policy: str, state_tag: str) -> list[str]:
    """What is missing among the labels gatectl puts on every session it starts."""
    have = set(labels)
    problems = [
        f"{label} missing" for label in ("owner=gatectl", f"policy={policy}") if label not in have
    ]
    if not any(label.startswith("decision=") and len(label) > 9 for label in have):
        problems.append("decision=<id> missing")
    if f"state={state_tag}" not in have:
        problems.append(f"state={state_tag} missing")
    return problems


class Live:
    """One test's private world: environment, state directory, config, and the two programs."""

    def __init__(self, root: Path, budget: RunBudget, real: Mapping[str, str] | None = None):
        self.root = root
        self.budget = budget
        self.real = REAL_ENV if real is None else real
        self.env = private_env(root, self.real)
        self.home = Path(self.env["HOME"])
        for key in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"):
            Path(self.env[key]).mkdir(parents=True, exist_ok=True)
        if not real_home_mode(self.real):
            self.home.mkdir(parents=True, exist_ok=True)
        self.started = time.time() - 2
        found = _resolve(self.real)
        self.session_cmd = found[0] if found else "claude-session"
        self.model = self.real.get(MODEL_VAR, DEFAULT_MODEL)

    @property
    def state_dir(self) -> Path:
        return Path(self.env["XDG_STATE_HOME"]) / "gatectl"

    def spend(self, runs: int, what: str) -> None:
        try:
            self.budget.spend(runs, what)
        except BudgetExceeded as exc:
            import pytest

            pytest.fail(str(exc), pytrace=False)

    def write_config(
        self,
        instruction: str,
        *,
        agent: Mapping[str, Any] | None = None,
        check: Mapping[str, Any] | None = None,
        timeout: str = "200s",
    ) -> str:
        """A config with one policy ``p`` with one agent check, on the real claude-session."""
        doc = {
            "session_cmd": [self.session_cmd],
            "agent": {
                "model": self.model,
                "timeout": "150s",
                "cache_ttl": "0s",
                "min_start_budget": "5s",
                **(agent or {}),
            },
            "policies": {
                "p": {
                    "timeout": timeout,
                    "checks": [
                        {
                            "name": "judge",
                            "type": "agent",
                            "instruction": instruction,
                            **(check or {}),
                        }
                    ],
                }
            },
        }
        path = self.root / "cfg" / "config.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc), encoding="utf-8")
        return str(path)

    def write_input(self, obj: Any, name: str = "input.json") -> str:
        path = self.root / name
        path.write_text(json.dumps(obj), encoding="utf-8")
        return str(path)

    def gatectl(
        self, *argv: str, timeout: float = 300, env: Mapping[str, str] | None = None
    ) -> Proc:
        return run(
            [sys.executable, "-m", "gatectl", *argv],
            env if env is not None else self.env,
            timeout=timeout,
        )

    def session(
        self, *argv: str, timeout: float = 120, env: Mapping[str, str] | None = None
    ) -> Proc:
        """One call of the real claude-session with the allowlisted login environment."""
        return run([self.session_cmd, *argv], env if env is not None else self.env, timeout=timeout)

    def manual(self, *argv: str) -> str:
        """The exact command a human runs by hand against this test's private state."""
        pairs = " ".join(
            f"{k}={self.env[k]}"
            for k in (
                "HOME",
                "XDG_CONFIG_HOME",
                "XDG_DATA_HOME",
                "XDG_STATE_HOME",
                "XDG_CACHE_HOME",
            )
        )
        return f"env {pairs} {self.session_cmd} {' '.join(argv)}"

    def sweep(self) -> list[str]:
        """Stop then forget every gatectl-labelled session left in the private state, print what
        happened, and return one ``LEFTOVER`` line per session that did not end or whose list
        could not be read (empty: nothing is left)."""
        left: list[str] = []
        listed = self.session("list", "--label", "owner=gatectl", "--json", timeout=60)
        try:
            body = listed.json()
        except ValueError:
            body = None
        if listed.code != 0 or not isinstance(body, dict):
            line = (
                f"LEFTOVER: could not list sessions (exit {listed.code}); state dir "
                f"{self.state_dir}; list by hand: {self.manual('list', '--label', 'owner=gatectl')}"
            )
            print(f"[live] {line}")
            return [line]
        for entry in body.get("sessions", []):
            sid = entry.get("csession_id") if isinstance(entry, dict) else None
            if not isinstance(sid, str):
                continue
            labels = [x for x in entry.get("labels", []) if isinstance(x, str)]
            decision = next((x[9:] for x in labels if x.startswith("decision=")), "")
            pids = self.pids(sid)
            stopped = self.session(
                "stop", sid, "--grace", "2s", "--actor", "auto:gatectl", "--json"
            )
            forget = ["forget", sid, "--actor", "auto:gatectl"]
            if decision:
                forget += ["--decision-id", decision]
            forgot = self.session(*forget, "--json")
            print(f"[live] sweep {sid}: stop exit {stopped.code}, forget exit {forgot.code}")
            if stopped.code != 0 or forgot.code != 0:
                line = (
                    f"LEFTOVER {sid}: stop exit {stopped.code}, forget exit {forgot.code}; pids "
                    f"{pids}; state dir {self.state_dir}; stop by hand: "
                    f"{self.manual('stop', sid, '--grace', '2s', '--actor', 'auto:gatectl')}"
                )
                print(f"[live] {line}")
                left.append(line)
        return left

    def pids(self, sid: str) -> dict[str, Any]:
        try:
            body = self.session("status", sid, "--json", timeout=30).json()
        except (ValueError, OSError):
            return {}
        run_ = body.get("run") if isinstance(body, dict) else None
        run_ = run_ if isinstance(run_, dict) else {}
        return {"wrapper_pid": run_.get("wrapper_pid"), "child_pid": run_.get("child_pid")}

    def check(
        self, config: str, input_file: str, *, timeout: float = 300
    ) -> tuple[Proc, dict[str, Any]]:
        done = self.gatectl(
            "check", "p", "--config", config, "--input", input_file, timeout=timeout
        )
        try:
            doc = done.json()
        except ValueError:
            doc = {}
        return done, doc


def observe(label: str, **facts: Any) -> None:
    """Print what a live test saw, for the human who reads the run (``make live`` uses -s)."""
    print(f"\n[live] {label}")
    for key, value in facts.items():
        text = value if isinstance(value, str) else json.dumps(value, default=str, sort_keys=True)
        print(f"[live]   {key}: {text[:2000]}")


# --- direct calls of the real claude-session (the same argv gatectl builds) ---------------------


@dataclass
class Direct:
    """One session started by hand with gatectl's own ``start`` argv, to look at the raw output
    of each verb. ``forget`` the session at the end (``cleanup``) so none is left behind."""

    live: Live
    launch: Any
    files: Any
    start: Proc
    body: dict[str, Any]
    problems: list[str] = field(default_factory=list)

    @property
    def session_id(self) -> str:
        return str(self.body.get("csession_id", ""))

    @property
    def run_number(self) -> int:
        return int(self.body.get("run", 1))

    @property
    def outcome_file(self) -> str:
        return str(self.launch.outcome_file)

    def verb(self, *argv: str, timeout: float = 120, env: Mapping[str, str] | None = None) -> Proc:
        return self.live.session(*argv, timeout=timeout, env=env)

    def exec(self, *, timeout: float = 240, env: Mapping[str, str] | None = None) -> Proc:
        from gatectl import agent

        return self.verb(
            *agent.exec_argv(self.session_id, self.run_number, self.outcome_file),
            timeout=timeout,
            env=env,
        )

    def status(self) -> dict[str, Any]:
        return self.verb("status", self.session_id, "--json").json()

    def stop(self, grace: str = "2s") -> Proc:
        return self.verb(
            "stop", self.session_id, "--grace", grace, "--actor", "auto:gatectl", "--json"
        )

    def forget(self) -> Proc:
        return self.verb(
            "forget", self.session_id, "--actor", "auto:gatectl",
            "--decision-id", self.launch.decision_id, "--json",
        )  # fmt: skip

    def cleanup(self) -> None:
        """Stop a run that is not final, then forget. Never raises (it must not hide the test's
        own failure) but records and prints every failure in ``problems``."""
        if not self.session_id:
            return
        for name, call in (("stop", self.stop), ("forget", self.forget)):
            try:
                done = call()
            except Exception as exc:  # noqa: BLE001
                self.problems.append(f"{name} of {self.session_id} raised {exc!r}")
                continue
            if done.code != 0:
                self.problems.append(f"{name} of {self.session_id} exit {done.code}")
        for problem in self.problems:
            print(f"[live] CLEANUP FAILED: {problem}; state dir {self.live.state_dir}")


def direct_start(
    live: Live,
    instruction: str,
    obj: Any,
    *,
    name: str = "direct",
    timeout_s: int = 120,
    skill: str = "gatectl:gate-check",
    sandbox: str = "required",
    setting_sources: tuple[str, ...] = (),
    extra: Sequence[str] = (),
) -> Direct:
    """Prepare the two files exactly as gatectl does and call the real ``start``."""
    from gatectl import agent, agentfiles, fingerprint, ids

    bundled = fingerprint.bundled_plugin_dir()
    prepared = agentfiles.prepare(
        obj, agentfiles.Instruction(instruction, "0" * 64), input_max_bytes=65536
    )
    decision = ids.new_decision_id()
    directory = live.root / name / decision
    directory.mkdir(parents=True, mode=0o700)
    files = prepared.write(directory)
    launch = agent.Launch(
        session_cmd=(live.session_cmd,),
        skill=skill,
        prompt_file=str(files.prompt_path),
        input_file=str(files.input_path),
        outcome_file=str(directory / agent.OUTCOME_NAME),
        plugin_dirs=(bundled,),
        timeout_s=timeout_s,
        policy="p",
        decision_id=decision,
        state_tag=agent.state_tag(live.state_dir),
        permission_profile=f"{bundled}/{fingerprint.BUNDLED_PROFILE}",
        sandbox=sandbox,
        setting_sources=setting_sources,
        env_allowlist=(),
        model=live.model,
    )
    argv = [*agent.start_argv(launch)]
    argv[argv.index("--json") : argv.index("--json")] = list(extra)
    started = live.session(*argv)
    try:
        body = started.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    return Direct(live, launch, files, started, body)
