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
# What gatectl's own allowlist lets through to claude-session besides the basics (D-28).
FORWARD_PREFIXES = ("ANTHROPIC_", "CLAUDE_", "AWS_", "GOOGLE_")
FORWARD_NAMES = ("CLOUD_ML_REGION", "PATH", "LANG", "TERM", "USER", "LOGNAME", "TMPDIR")

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


@dataclass
class RunBudget:
    """A hard cap on model runs for the whole session; one ``spend`` per run a test may start."""

    cap: int
    used: int = 0
    log: list[str] = field(default_factory=list)

    @classmethod
    def from_environ(cls, environ: Mapping[str, str]) -> RunBudget:
        try:
            cap = int(environ.get(BUDGET_VAR, ""))
        except ValueError:
            cap = DEFAULT_MAX_RUNS
        return cls(cap if cap > 0 else DEFAULT_MAX_RUNS)

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
    """Run ``argv`` headless (no tty, own process group). On timeout, signal exactly the group
    of the child this call started, then reap it."""
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
    return Proc(
        list(argv),
        child.returncode,
        out.decode("utf-8", "replace"),
        err.decode("utf-8", "replace"),
        time.monotonic() - began,
        timed_out,
    )


def stop_group(child: subprocess.Popen[bytes]) -> tuple[bytes, bytes]:
    """SIGTERM then SIGKILL to the group of a child we started and have not yet reaped."""
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
    return out, err


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
        """Best effort: stop a run that is not final, then forget (never raises)."""
        if not self.session_id:
            return
        try:
            self.stop()
            self.forget()
        except Exception:  # noqa: BLE001 - cleanup must not hide the test's own failure
            pass


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
