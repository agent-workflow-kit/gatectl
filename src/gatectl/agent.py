"""The agent run sequence (interface.md, Agent checks: Run sequence, Cleanup; Deadline, Bounds).

``run_session`` drives one claude-session run through the gateway: ``start``, the slot row's
``csession_id``, ``exec --session-id`` (waited for at most ``n`` plus ``exec_margin``), ``status``
and ``forget``. Every other call is bounded by ``call_timeout`` and by what is left of the one
shared clean-up budget. It never raises for a failure of a step: whatever happens it returns a
``Judgement`` (an ``escalate`` for every failure, never an ``allow`` it cannot justify) and
leaves nothing started behind it:

* ``forget`` runs on every path that allocated a session, including a ``start`` that failed
  after allocating one (found by its ``decision=<id>`` label);
* after any failure it runs ``list --label decision=<id>``, ``stop --grace 2s`` for every
  session whose run is not final, then ``forget``; a ``stop`` or ``forget`` that fails is left
  to ``reconcile`` and never changes the verdict;
* an ``exec`` that is overdue gets ``stop <id> --grace 2s`` first, then SIGTERM to its process
  group and SIGKILL after ``kill_grace`` (the runner's sequence, by the pid and group it
  started), and ends the check ``escalate``/``timeout``.

Releasing the slot, writing and deleting the files and the cache belong to the caller (the
engine); this module only needs to know the slot to record the ``csession_id``.

Nothing claude-session prints is trusted or echoed: every output is read with a byte cap
through the runner's selector loop, parsed as strict JSON, and only closed fields (a session id
of the grammar, an integer run number, an ``end_reason`` token, the ``live`` and ``pending``
booleans, the labels) are used. The only thing that leaves this module towards the audit line,
the log or a ``detail`` is a fixed string of this module or of ``agentjudge``.

The environment of every call is built from ``SESSION_ENV_ALLOW`` (names, or ``NAME*`` prefixes):
gatectl reads no token variable itself, but the adopting ``exec`` needs claude-session's own
login variables (``required_env_names`` in its docs), so the ones Claude Code and the common
providers use are passed through and nothing else (no ``GATECTL_*``, no ``*_TOKEN``).
"""

from __future__ import annotations

import hashlib
import math
import os
import re
import stat
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

from gatectl import agentjudge, fingerprint, inputs, runner, slots
from gatectl.agentjudge import Judgement
from gatectl.config_models import AgentCheck, SharedConfig
from gatectl.gateway import Gateway
from gatectl.sanitize import sanitize
from gatectl.store import Store

ACTOR = "auto:gatectl"
OUTCOME_NAME = "outcome.json"
GRACE = "2s"
SESSION_ENV_ALLOW = (
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_*",
    "TMPDIR",
    "TERM",
    "XDG_*",
    "CSESSION_*",
    "ANTHROPIC_*",
    "CLAUDE_*",
    "AWS_*",
    "CLOUD_ML_REGION",
    "GOOGLE_*",
)
INSTALL_HINT = "uv tool install git+https://github.com/agent-workflow-kit/claude-session"
SESSION_ID = re.compile(r"cs-[a-z2-7]{8}", re.ASCII)
_END_REASON = re.compile(r"[a-z][a-z0-9_]{0,63}", re.ASCII)
_OUTPUT_CAP = 64 * 1024
_OUTCOME_CAP = 2 * 1024 * 1024
_STATUS_CAP = 2 * 1024 * 1024
_LIST_CAP = 1024 * 1024
_MAX_LISTED = 64
_MAX_RUN = 2**31 - 1
# start, status and forget (interface.md, Deadline): the launch window is R minus this.
LAUNCH_OVERHEAD = 5.0


@dataclass(frozen=True)
class Limits:
    """The time limits of Deadline and Bounds; the defaults are the documented ones.

    A test shortens them (and may give ``exec_margin`` a negative value to make a short fake run
    overdue); the argv of every call, ``--grace 2s`` included, never changes.
    """

    call_timeout: float = 5.0  # every call but ``exec``
    exec_margin: float = 10.0  # ``exec`` is waited for ``n`` plus this
    cleanup_budget: float = 10.0  # list, stop, signals, second stop and forget share it
    kill_grace: float = 2.0  # SIGTERM to SIGKILL for a call's process group


DEFAULT_LIMITS = Limits()


@dataclass(frozen=True)
class Launch:
    """Everything ``start`` needs, resolved by the caller (nothing here is read from config)."""

    session_cmd: tuple[str, ...]
    skill: str
    prompt_file: str
    input_file: str
    outcome_file: str
    plugin_dirs: tuple[str, ...]
    timeout_s: int
    policy: str
    decision_id: str
    state_tag: str
    permission_profile: str
    sandbox: str
    setting_sources: tuple[str, ...]
    env_allowlist: tuple[str, ...]
    repo: str | None = None
    model: str | None = None


def start_argv(launch: Launch) -> list[str]:
    """Run sequence, step 1 (after ``session_cmd``)."""
    argv = [
        "start", "--kind", "gate-check", "--mode", "headless",
        "--skill", launch.skill,
        "--prompt-file", launch.prompt_file,
        "--input-file", launch.input_file,
    ]  # fmt: skip
    for directory in launch.plugin_dirs:
        argv += ["--plugin-dir", directory]
    argv += ["--timeout", f"{launch.timeout_s}s"]
    labels = (
        ("owner", "gatectl"),
        ("policy", launch.policy),
        ("decision", launch.decision_id),
        ("state", launch.state_tag),
    )
    for key, value in labels:
        argv += ["--label", f"{key}={value}"]
    argv += [
        "--actor", ACTOR, "--decision-id", launch.decision_id,
        "--permission-profile", launch.permission_profile,
        "--sandbox", launch.sandbox,
        "--setting-sources", ",".join(launch.setting_sources),
    ]  # fmt: skip
    for name in launch.env_allowlist or ("",):
        argv += ["--env-allowlist-only", name]
    if launch.repo is not None:
        argv.append(f"--repo={launch.repo}")
    if launch.model is not None:
        argv.append(f"--model={launch.model}")
    argv.append("--json")
    return argv


def exec_argv(session_id: str, run: int, outcome_file: str) -> list[str]:
    return [
        "exec", "--session-id", session_id, "--run", str(run),
        "--outcome-file", outcome_file, "--json",
    ]  # fmt: skip


def parse_object(data: bytes) -> dict[str, Any] | None:
    """A strict JSON object, or ``None`` for anything else (never raises)."""
    try:
        return inputs.parse_input(data)
    except Exception:
        return None


def session_env(environ: Mapping[str, str]) -> dict[str, str]:
    return runner.build_env(environ, SESSION_ENV_ALLOW)


@dataclass(frozen=True)
class SessionResult:
    """What the run came to. ``warnings`` are closed codes for the engine's log (never text)."""

    judgement: Judgement
    warnings: tuple[str, ...] = ()


class _Fail(Exception):
    """A step failed; the judgement is already fixed text."""

    def __init__(self, judgement: Judgement) -> None:
        super().__init__(judgement.reason)
        self.judgement = judgement


def _check_error(detail: str) -> _Fail:
    return _Fail(agentjudge.escalate("check_error", detail))


@dataclass
class _Budget:
    end: float
    monotonic: Callable[[], float]

    def remaining(self) -> float:
        return self.end - self.monotonic()


@dataclass
class _Session:
    gw: Gateway
    launch: Launch
    nonce: str = field(repr=False)
    threshold: float
    store: Store | None
    slot: slots.Slot | None
    env: dict[str, str]
    limits: Limits
    monotonic: Callable[[], float]
    cancel: Callable[[], bool] | None
    allocated: bool = False
    clean: bool = False
    csession_id: str | None = None
    budget: _Budget | None = None
    warnings: list[str] = field(default_factory=list)

    # -- calls -----------------------------------------------------------------------------

    def _call(
        self,
        tail: Sequence[str],
        *,
        timeout: float,
        cap: int = _OUTPUT_CAP,
        cancel: Callable[[], bool] | None = None,
    ) -> runner.RunResult:
        spec = runner.RunSpec(
            argv=(*self.launch.session_cmd, *tail),
            env=self.env,
            cwd="/",
            timeout=max(timeout, 0.01),
            stdout_cap=cap,
            stderr_cap=0,
            kill_grace=self.limits.kill_grace,
        )
        result = runner.run_process(self.gw, spec, cancel=cancel)
        if result.leader_unkilled:
            self.warnings.append("leader_unkilled")
        if result.pipes_held:
            self.warnings.append("pipes_held")
        return result

    def _shared(self) -> _Budget:
        if self.budget is None:
            self.budget = _Budget(self.monotonic() + self.limits.cleanup_budget, self.monotonic)
        return self.budget

    def _bounded(self) -> float:
        """The timeout of a clean-up call: the smaller of the cap and what is left once the
        runner's SIGKILL grace is set aside, so a call that ignores SIGTERM still ends inside
        the shared budget (<= 0: skip the call)."""
        return min(self.limits.call_timeout, self._shared().remaining() - self.limits.kill_grace)

    @staticmethod
    def _ok(result: runner.RunResult) -> bool:
        return result.status == "exited" and result.code == 0

    # -- the sequence ----------------------------------------------------------------------

    def sequence(self) -> Judgement:
        run = self._start()
        self._record_csession()
        code, outcome = self._exec(run)
        if code != 0:
            return self._judge(code, outcome, None)
        status = self._status()
        judgement = self._judge(0, outcome, status)
        self.clean = True
        return judgement

    def _judge(
        self, code: int, outcome: Mapping[str, Any] | None, status: Mapping[str, Any] | None
    ) -> Judgement:
        try:
            raw = agentjudge.RawRun(code, outcome, status, self.nonce)
            judgement = agentjudge.judge(raw, threshold=self.threshold)
            if not isinstance(judgement, Judgement):
                raise TypeError("not a judgement")
            return judgement
        except Exception:
            return agentjudge.escalate("check_error", "agent verdict could not be judged")

    def _start(self) -> int:
        self.allocated = True
        result = self._call(start_argv(self.launch), timeout=self.limits.call_timeout)
        if result.status == "tool_missing":
            raise _Fail(agentjudge.escalate("tool_missing", "claude-session not found"))
        body = None if result.stdout_truncated else parse_object(result.stdout)
        if result.status == "exited" and result.code == 0:
            session_id = _session_id(body)
            if session_id is not None:
                self.csession_id = session_id
            run = body.get("run") if body is not None else None
            if session_id is None or not _is_run(run):
                raise _check_error("start output unusable")
            assert isinstance(run, int)
            return run
        if result.status == "exited":
            # An error envelope may name the session it allocated and why the launch failed.
            error = body.get("error") if body is not None else None
            fields = error if isinstance(error, dict) else {}
            session_id = _session_id(fields)
            if session_id is not None:
                self.csession_id = session_id
            end_reason = fields.get("end_reason")
            token = (
                end_reason
                if isinstance(end_reason, str) and _END_REASON.fullmatch(end_reason)
                else None
            )
            raise _Fail(agentjudge.start_failed(result.code, token))
        raise _check_error("start timed out" if result.status == "timeout" else "start failed")

    def _record_csession(self) -> None:
        if self.store is None or self.slot is None or self.csession_id is None:
            return
        try:
            slots.set_csession(self.store, self.slot, self.csession_id)
        except Exception:  # the slot row only helps reconcile; the run goes on
            self.warnings.append("slot_csession_failed")

    def _exec(self, run: int) -> tuple[int, Mapping[str, Any] | None]:
        assert self.csession_id is not None
        guard = max(self.launch.timeout_s + self.limits.exec_margin, 0.05)
        began = self.monotonic()
        overdue = False
        cancelled = False

        def cancel() -> bool:
            nonlocal overdue, cancelled
            if self.cancel is not None and self.cancel():
                cancelled = True
                return True
            if self.monotonic() - began >= guard:
                overdue = True
                self._stop_known()
                return True
            return False

        result = self._call(
            exec_argv(self.csession_id, run, self.launch.outcome_file),
            timeout=guard + self.limits.call_timeout,
            cap=_OUTCOME_CAP,
            cancel=cancel,
        )
        if overdue or result.status == "timeout":
            raise _Fail(agentjudge.escalate("timeout", "agent run overdue"))
        if cancelled or result.status == "cancelled":
            raise _check_error("agent run cancelled")
        if result.status == "tool_missing":
            raise _Fail(agentjudge.escalate("tool_missing", "claude-session not found"))
        if result.status != "exited" or result.code is None:
            raise _check_error("agent run did not finish")
        body = None if result.stdout_truncated else parse_object(result.stdout)
        if body is not None and body.get("csession_id") != self.csession_id:
            body = None  # it does not describe our session: not an outcome
        return result.code, body

    def _status(self) -> dict[str, Any]:
        assert self.csession_id is not None
        result = self._call(
            ["status", self.csession_id, "--json"],
            timeout=self.limits.call_timeout,
            cap=_STATUS_CAP,
        )
        body = (
            None if not self._ok(result) or result.stdout_truncated else parse_object(result.stdout)
        )
        if body is None or body.get("csession_id") != self.csession_id:
            raise _check_error("status failed or unusable")
        return body

    # -- stopping and forgetting -------------------------------------------------------------

    def _stop(self, session_id: str) -> bool:
        timeout = self._bounded()
        if timeout <= 0:
            return False
        tail = ["stop", session_id, "--grace", GRACE, "--actor", ACTOR]
        return self._ok(self._call(tail, timeout=timeout))

    def _stop_known(self) -> None:
        """The first step of an overdue ``exec``: stop the one session we know."""
        try:
            if self.csession_id is not None:
                self._stop(self.csession_id)
        except Exception:
            self.warnings.append("stop_failed")

    def _forget(self, session_id: str, *, shared: bool) -> bool:
        timeout = self._bounded() if shared else self.limits.call_timeout
        if timeout <= 0:
            return False
        tail = ["forget", session_id, "--actor", ACTOR, "--decision-id", self.launch.decision_id]
        return self._ok(self._call(tail, timeout=timeout))

    def _list(self) -> dict[str, bool] | None:
        """The sessions with our label: id -> whether its run is final. ``None``: no answer."""
        timeout = self._bounded()
        if timeout <= 0:
            return None
        label = f"decision={self.launch.decision_id}"
        result = self._call(["list", "--label", label, "--json"], timeout=timeout, cap=_LIST_CAP)
        body = (
            None if not self._ok(result) or result.stdout_truncated else parse_object(result.stdout)
        )
        items = body.get("sessions") if body is not None else None
        if not isinstance(items, list) or len(items) > _MAX_LISTED:
            return None
        found: dict[str, bool] = {}
        wanted = {"owner=gatectl", label}
        for item in items:
            if not isinstance(item, dict):
                continue
            session_id = _session_id(item)
            labels = item.get("labels")
            if (
                session_id is None
                or not isinstance(labels, list)
                or not wanted <= set(x for x in labels if isinstance(x, str))
            ):
                continue  # not ours (or not a session at all): never touched
            # Anything but a plain "ended" is treated as not final: stopping a final one is
            # harmless, leaving a live one is not.
            found[session_id] = item.get("live") is False and item.get("pending") is False
        return found

    def finish(self) -> None:
        """Failure clean-up, or just ``forget`` after a clean run. Never raises."""
        try:
            self._finish()
        except Exception:
            self.warnings.append("cleanup_failed")

    def _finish(self) -> None:
        if not self.allocated:
            return
        if self.clean and self.csession_id is not None:
            if not self._forget(self.csession_id, shared=False):
                self.warnings.append("forget_failed")
            return
        listed = self._list()
        # An answered list is the truth: only the ids it returned (they carry our labels) are
        # acted on. Without an answer the one id start gave is the target, never known final.
        targets: dict[str, bool] = {}
        if listed is not None:
            targets = dict(listed)
        elif self.csession_id is not None:
            targets[self.csession_id] = False
        for session_id, final in targets.items():
            if not final and not self._stop(session_id):
                self.warnings.append("stop_failed")
        for session_id in targets:
            if not self._forget(session_id, shared=True):
                self.warnings.append("forget_failed")


def _session_id(body: Mapping[str, Any] | None) -> str | None:
    value = body.get("csession_id") if body is not None else None
    return value if isinstance(value, str) and SESSION_ID.fullmatch(value) else None


def _is_run(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= _MAX_RUN


@dataclass(frozen=True)
class Settings:
    """One agent check's effective values: its own key, else the ``agent:`` block's."""

    skill: str
    model: str | None
    threshold: float
    timeout: float
    sandbox: str
    setting_sources: tuple[str, ...]
    env_allowlist: tuple[str, ...]
    permission_profile: str
    cache_ttl: timedelta
    max_parallel: int
    min_start_budget: float
    input_max_bytes: int


def resolve_settings(
    check: AgentCheck, shared: SharedConfig, policy_cache_ttl: timedelta | None, bundled: str
) -> Settings:
    """``cache_ttl`` follows check, then policy, then ``agent``; every other key check, then
    ``agent``. The permission profile defaults to the bundled copy of the ``review`` profile."""
    block = shared.agent

    def pick(own: Any, inherited: Any) -> Any:
        return inherited if own is None else own

    profile = pick(check.permission_profile, block.permission_profile)
    ttl = check.cache_ttl if check.cache_ttl is not None else policy_cache_ttl
    return Settings(
        skill=pick(check.skill, block.skill),
        model=pick(check.model, block.model),
        threshold=float(pick(check.threshold, block.threshold)),
        timeout=pick(check.timeout, block.timeout).total_seconds(),
        sandbox=pick(check.sandbox, block.sandbox),
        setting_sources=tuple(pick(check.setting_sources, block.setting_sources)),
        env_allowlist=tuple(pick(check.env_allowlist, block.env_allowlist)),
        permission_profile=profile
        if profile is not None
        else f"{bundled}/{fingerprint.BUNDLED_PROFILE}",
        cache_ttl=ttl if ttl is not None else block.cache_ttl,
        max_parallel=block.max_parallel,
        min_start_budget=block.min_start_budget.total_seconds(),
        input_max_bytes=block.input_max_bytes,
    )


class ToolMissing(Exception):
    """Something the run needs cannot be found; ``detail`` is sanitized text for the entry."""

    def __init__(self, detail: str) -> None:
        super().__init__("tool_missing")
        self.detail = detail


def _regular_file(path: str) -> bool:
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (OSError, ValueError):
        return False


def find_plugin_dirs(skill: str, extra: Sequence[str], bundled: str) -> tuple[str, ...]:
    """The ``--plugin-dir`` values: the bundled plugin, plus the one other plugin holding the
    check's skill. ``ToolMissing`` when the bundled plugin, the skill's plugin or its
    ``SKILL.md`` cannot be found (nothing is started and no file is written then)."""
    if fingerprint.plugin_name_of(bundled) is None:
        raise ToolMissing("bundled plugin not found")
    plugin, _, name = skill.partition(":")
    found = next((d for d in (bundled, *extra) if fingerprint.plugin_name_of(d) == plugin), None)
    if found is None:
        raise ToolMissing(sanitize(f"plugin not found: {plugin}", 200))
    if (
        name in ("", ".", "..")
        or "/" in name
        or not _regular_file(f"{found}/skills/{name}/SKILL.md")
    ):
        raise ToolMissing(sanitize(f"skill not found: {skill}", 200))
    return (bundled,) if found == bundled else (bundled, found)


def missing_session_detail(session_cmd: Sequence[str]) -> str:
    """The ``detail`` of a ``session_cmd`` that was not found: the command, and for
    ``claude-session`` the install command."""
    first = session_cmd[0] if session_cmd else "claude-session"
    shown = sanitize(first, 200)
    if os.path.basename(first) == "claude-session":
        return f"{shown} not found; install: {INSTALL_HINT}"
    return f"{shown} not found"


def state_tag(state_dir: Path | str) -> str:
    """The ``state=<tag>`` label: 12 hex characters of the SHA-256 of the state directory's
    realpath (every spelling of the path gives one tag)."""
    return hashlib.sha256(
        os.path.realpath(state_dir).encode("utf-8", "surrogateescape")
    ).hexdigest()[:12]


def launch_seconds(check_timeout: float, window: float) -> int:
    """``n``: the smaller of the check's timeout and the launch window ``L``, rounded up to a
    whole second (claude-session rejects 0)."""
    return max(1, math.ceil(min(check_timeout, window)))


def run_session(
    gw: Gateway,
    launch: Launch,
    *,
    nonce: str,
    threshold: float,
    environ: Mapping[str, str],
    limits: Limits = DEFAULT_LIMITS,
    store: Store | None = None,
    slot: slots.Slot | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    cancel: Callable[[], bool] | None = None,
) -> SessionResult:
    """One agent run, start to forget. Returns a judgement; raises only for an interrupt (after
    the clean-up ran)."""
    session = _Session(
        gw=gw,
        launch=launch,
        nonce=nonce,
        threshold=threshold,
        store=store,
        slot=slot,
        env=session_env(environ),
        limits=limits,
        monotonic=monotonic,
        cancel=cancel,
    )
    try:
        judgement = session.sequence()
    except _Fail as failure:
        judgement = failure.judgement
    except Exception:  # a bug or a hostile output nobody planned for: still an escalation
        judgement = agentjudge.escalate("check_error", "agent run failed")
    finally:
        session.finish()
    return SessionResult(judgement, tuple(dict.fromkeys(session.warnings)))
