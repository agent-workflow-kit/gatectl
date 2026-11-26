"""Hooks (interface.md, Hooks): the runner, the detached supervisor's launcher and its job format.

A hook is a shell command (``sh -c``, no substitution) that gets its event payload as stdin from
``tmp/hook-<random>/payload.json`` (mode 0600), the environment of gatectl plus the reserved
``GATECTL_HOOK``, ``GATECTL_ID`` and ``GATECTL_OBJECT_TYPE``, ``/dev/null`` for stdout and
stderr, no descriptor above 2, and its own process group. ``run_hooks`` runs the hooks of one
event one after the other, in the calling process, through ``runner.run_process`` (so the group
kill sequence, the sweep-then-``done``-then-reap order and the lifeline watchdog are the script
runner's own). Failures are ``hook_failed`` log events, a hook that never started is a
``hook_skipped`` one; neither ever raises or changes anything the caller prints.

``start_detached`` is how ``check`` fires its hooks: the result is already printed and the caller's
descriptors already point at ``/dev/null``. It starts ``python -m gatectl.supervisor`` in its own
session (explicit ``/dev/null`` for stdout and stderr, a private pipe for stdin, ``close_fds``),
hands it the job on that pipe within a short deadline, and returns without waiting. The
supervisor (``gatectl.supervisor``) is the only code that runs ``run_hooks`` detached.

The job is one frame: ``GATECTL-HOOKS 1 <n>\\n`` followed by ``n`` bytes of JSON. The payload
travels in the job only, never in argv or the environment; the hook's directory is created by
the supervisor, so its ``owner`` file names the supervisor (what ``reconcile`` checks).

Seams: ``post-outcome`` and ``post-state-change`` are wired by the issues that fire them
(TODO(#31)); they build a ``HookEvent`` and call ``run_hooks`` (``async: false``) or
``start_detached`` (``async: true``).
"""

from __future__ import annotations

import errno
import fcntl
import json
import math
import os
import select
import signal
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gatectl import audit, ids, tmptree
from gatectl.gateway import ChildSpec, Gateway, Stdio
from gatectl.runner import KILL_GRACE, RunSpec, run_process

EVENTS = ("post-decision", "post-outcome", "post-state-change")
SHELL = "/bin/sh"
# Per event: more hooks than this are skipped (and logged), so a config cannot make one event
# hold a supervisor for hours.
MAX_HOOKS = 64
# A payload (and so a job) over this is not sent: a hook payload is small by construction.
MAX_PAYLOAD = 256 * 1024
# Supervisors that may run hooks at the same time, machine-wide (state directory); another one
# logs ``hook_skipped`` (``busy``) and ends. Released by the kernel when its holder dies.
MAX_SLOTS = 16
# The parent gives the supervisor this long to take its job before it is killed and the event
# skipped; and the supervisor this long to receive a complete job.
HANDOFF_DEADLINE = 2.0
READ_DEADLINE = 10.0
RESERVED = ("GATECTL_HOOK", "GATECTL_ID", "GATECTL_OBJECT_TYPE")
_MAGIC = b"GATECTL-HOOKS 1 "
_MAX_FIELD = 1024


@dataclass(frozen=True)
class HookCommand:
    cmd: str
    timeout: float  # seconds


@dataclass(frozen=True)
class HookEvent:
    """One event's hooks and payload. ``policy``, ``scope`` and ``decision_id`` only label the
    log events (each is dropped from them unless it matches its grammar)."""

    hook: str
    object_type: str
    object_id: str
    payload: Mapping[str, Any]
    commands: tuple[HookCommand, ...]
    policy: str | None = None
    scope: str | None = None
    decision_id: str | None = None


@dataclass(frozen=True)
class HookReport:
    index: int
    status: str  # a runner status, or ``skipped``
    code: int | None = None
    signal: int | None = None


# --- logging --------------------------------------------------------------------------------


def log_event(state_dir: Path, ev: HookEvent, event: str, level: str, data: dict[str, Any]) -> None:
    """A hook problem is logged, never raised: a log that cannot be written changes nothing."""
    try:
        policy = ev.policy if ev.policy is not None and ids.is_policy_name(ev.policy) else None
        did = ev.decision_id
        record = audit.log_record(
            level=level,
            event=event,
            policy=policy,
            scope=_scope(ev.scope),
            decision_id=did if isinstance(did, str) and ids.is_decision_id(did) else None,
            hook=ev.hook if ev.hook in EVENTS else None,
            data=data,
        )
        audit.append_log(record, state_dir=state_dir)
    except Exception:  # noqa: S110
        pass


def _scope(scope: str | None) -> str | None:
    if scope is not None and (scope == "*" or ids.is_repo_id(scope)):
        return scope
    return None


# --- the environment ------------------------------------------------------------------------


def build_env(
    environ: Mapping[str, str], hook: str, object_id: str, object_type: str
) -> dict[str, str]:
    """The hook's environment: that of gatectl (valid names and values only), with the three
    reserved names set by gatectl whatever the caller's environment says."""
    env = {
        k: v
        for k, v in environ.items()
        if isinstance(k, str) and isinstance(v, str) and k and "=" not in k
        and "\x00" not in k and "\x00" not in v
    }  # fmt: skip
    values = {"GATECTL_HOOK": hook, "GATECTL_ID": object_id, "GATECTL_OBJECT_TYPE": object_type}
    for name, value in values.items():
        if not isinstance(value, str) or "\x00" in value:
            raise ValueError(f"{name} must be a string without NUL")
        env[name] = value
    return env


def encode_payload(payload: Mapping[str, Any]) -> bytes:
    """Compact ASCII JSON; a value JSON cannot hold raises ``ValueError``/``TypeError``."""
    text = json.dumps(payload, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return text.encode("ascii")


# --- running hooks in this process ----------------------------------------------------------


def run_hooks(
    gw: Gateway,
    ev: HookEvent,
    *,
    state_dir: Path,
    environ: Mapping[str, str],
    cancel: Callable[[], bool] | None = None,
    kill_grace: float = KILL_GRACE,
) -> list[HookReport]:
    """Run ``ev.commands`` one after the other, in order, and wait for each.

    One report per command. ``cancel`` ends the running hook (the kill sequence) and skips the
    rest. A failure of one hook never stops the next; nothing here raises for a hook problem.
    """
    reports: list[HookReport] = []
    payload: bytes | None = None
    why = None
    try:
        payload = encode_payload(ev.payload)
        if len(payload) > MAX_PAYLOAD:
            why = "payload_too_large"
    except (TypeError, ValueError):
        why = "payload_invalid"
    for index, command in enumerate(ev.commands):
        reason = why
        if reason is None and index >= MAX_HOOKS:
            reason = "too_many_hooks"
        if reason is None and cancel is not None and cancel():
            reason = "terminated"
        if reason is None:
            assert payload is not None
            reports.append(
                _run_one(gw, ev, index, command, payload, state_dir, environ, cancel, kill_grace)
            )
        else:
            reports.append(_skipped(state_dir, ev, index, reason))
    return reports


def _skipped(state_dir: Path, ev: HookEvent, index: int, reason: str) -> HookReport:
    log_event(state_dir, ev, "hook_skipped", "warn", {"index": index, "reason": reason})
    return HookReport(index, "skipped")


def _valid_command(command: HookCommand) -> bool:
    timeout = command.timeout
    return (
        isinstance(command.cmd, str)
        and bool(command.cmd)
        and "\x00" not in command.cmd
        and isinstance(timeout, int | float)
        and not isinstance(timeout, bool)
        and math.isfinite(timeout)
        and timeout > 0
    )


def _run_one(
    gw: Gateway,
    ev: HookEvent,
    index: int,
    command: HookCommand,
    payload: bytes,
    state_dir: Path,
    environ: Mapping[str, str],
    cancel: Callable[[], bool] | None,
    kill_grace: float,
) -> HookReport:
    if not _valid_command(command):
        return _skipped(state_dir, ev, index, "invalid_command")
    try:
        env = build_env(environ, ev.hook, ev.object_id, ev.object_type)
    except ValueError:
        return _skipped(state_dir, ev, index, "invalid_environment")
    try:
        directory = tmptree.create_hook_dir(state_dir, payload)
    except (OSError, tmptree.UnsafeTree):
        return _skipped(state_dir, ev, index, "directory")
    try:
        spec = RunSpec(
            argv=(SHELL, "-c", command.cmd),
            env=env,
            cwd="/",
            timeout=float(command.timeout),
            stdin_path=str(directory / tmptree.PAYLOAD),
            capture_output=False,
            kill_grace=kill_grace,
        )
        result = run_process(gw, spec, cancel=cancel)
    finally:
        try:
            tmptree.remove_tree(directory)
        except (OSError, tmptree.UnsafeTree):
            log_event(state_dir, ev, "warning", "warn", {"index": index, "reason": "workdir_left"})
    report = HookReport(index, result.status, result.code, result.signal)
    failure = _failure(result)
    if failure is not None:
        log_event(state_dir, ev, "hook_failed", "warn", {"index": index, **failure})
    return report


def _failure(result: Any) -> dict[str, Any] | None:
    """The ``data`` of a ``hook_failed`` event, or ``None`` for a hook that succeeded."""
    status = result.status
    data: dict[str, Any]
    if status == "exited":
        if result.code == 0:
            return None
        data = {"reason": "exit", "exit_code": result.code}
    elif status == "signaled":
        data = {"reason": "signal", "signal": result.signal}
    elif status == "timeout":
        data = {"reason": "timeout"}
    elif status == "cancelled":
        data = {"reason": "terminated"}
    elif status == "lifeline_lost":
        data = {"reason": "lifeline_lost"}
    else:  # not_started, tool_missing
        data = {"reason": "not_started"}
    if result.leader_unkilled:
        data["leader_unkilled"] = True
    return data


# --- the job ---------------------------------------------------------------------------------


def encode_job(ev: HookEvent, state_dir: Path) -> bytes:
    body = json.dumps(
        {
            "hook": ev.hook,
            "object_type": ev.object_type,
            "object_id": ev.object_id,
            "payload": dict(ev.payload),
            "commands": [{"cmd": c.cmd, "timeout": c.timeout} for c in ev.commands],
            "policy": ev.policy,
            "scope": ev.scope,
            "decision_id": ev.decision_id,
            "state_dir": str(state_dir),
        },
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return _MAGIC + str(len(body)).encode("ascii") + b"\n" + body


class JobInvalid(Exception):
    """The supervisor's job is not a well-formed frame; nothing is run."""


def _text(value: object, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or len(value) > _MAX_FIELD:
        raise JobInvalid("a field is not a short string")
    return value


def parse_job(frame: bytes) -> tuple[HookEvent, Path]:
    """Decode a complete frame (header and body). Strict: anything else raises ``JobInvalid``."""
    if not frame.startswith(_MAGIC):
        raise JobInvalid("not a job")
    head, sep, body = frame.partition(b"\n")
    size = head[len(_MAGIC) :]
    if not sep or not size.isdigit() or int(size) != len(body):
        raise JobInvalid("bad length")
    try:
        doc = json.loads(body.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        raise JobInvalid("not JSON") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("payload"), dict):
        raise JobInvalid("not an object")
    commands = doc.get("commands")
    if not isinstance(commands, list):
        raise JobInvalid("commands")
    parsed: list[HookCommand] = []
    for item in commands:
        if not isinstance(item, dict):
            raise JobInvalid("command")
        timeout = item.get("timeout")
        if isinstance(timeout, bool) or not isinstance(timeout, int | float):
            raise JobInvalid("timeout")
        cmd = item.get("cmd")
        if not isinstance(cmd, str):
            raise JobInvalid("cmd")
        parsed.append(HookCommand(cmd, float(timeout)))
    hook = _text(doc.get("hook"))
    if hook not in EVENTS:
        raise JobInvalid("unknown hook")
    state = _text(doc.get("state_dir"))
    assert hook is not None and state is not None
    if not os.path.isabs(state):
        raise JobInvalid("state_dir")
    ev = HookEvent(
        hook=hook,
        object_type=_text(doc.get("object_type")) or "",
        object_id=_text(doc.get("object_id")) or "",
        payload=doc["payload"],
        commands=tuple(parsed),
        policy=_text(doc.get("policy"), optional=True),
        scope=_text(doc.get("scope"), optional=True),
        decision_id=_text(doc.get("decision_id"), optional=True),
    )
    return ev, Path(state)


def read_job(
    fd: int, *, deadline: float = READ_DEADLINE, cancel: Callable[[], bool] | None = None
) -> bytes:
    """Read one frame from ``fd`` (the supervisor's stdin) within ``deadline`` seconds.

    Raises ``JobInvalid`` for a short, long or late frame. Never reads past the frame's size,
    which is itself capped, so a hostile writer cannot make it hold unbounded memory.
    """
    end = time.monotonic() + deadline
    data = b""
    size: int | None = None
    while True:
        if size is not None and len(data) >= size:
            return data
        if len(data) > MAX_PAYLOAD * 2 + 1024 * 64 and size is None:
            raise JobInvalid("header too long")
        remaining = end - time.monotonic()
        if remaining <= 0 or (cancel is not None and cancel()):
            raise JobInvalid("job not received")
        ready, _, _ = select.select([fd], [], [], min(remaining, 0.05))
        if not ready:
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            raise JobInvalid("job unreadable") from None
        if not chunk:
            raise JobInvalid("job truncated")
        data += chunk
        if size is None:
            head, sep, rest = data.partition(b"\n")
            if sep:
                if not head.startswith(_MAGIC) or not head[len(_MAGIC) :].isdigit():
                    raise JobInvalid("bad header")
                body = int(head[len(_MAGIC) :])
                if body > MAX_PAYLOAD * 2 + 1024 * 64:
                    raise JobInvalid("job too large")
                size = len(head) + 1 + body
                if len(data) > size:
                    raise JobInvalid("trailing bytes")
            elif len(data) > 64:
                raise JobInvalid("bad header")
        elif len(data) > size:
            raise JobInvalid("trailing bytes")


# --- the concurrency bound --------------------------------------------------------------------


def acquire_slot(state_dir: Path) -> int | None:
    """Take one of ``MAX_SLOTS`` advisory locks (``hook-slot-<n>.lock`` in the state directory);
    ``None`` when all are held, ``OSError`` when the lock files cannot be used at all. The
    descriptor is close-on-exec, so no hook inherits it, and the kernel releases the lock when
    the holder ends, however it ends."""
    os.makedirs(state_dir, mode=0o700, exist_ok=True)
    for n in range(MAX_SLOTS):
        path = state_dir / f"hook-slot-{n}.lock"
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            os.close(fd)
            if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
                continue
            raise
        return fd
    return None


# --- the detached launcher --------------------------------------------------------------------


def supervisor_spec(environ: Mapping[str, str]) -> ChildSpec:
    """The supervisor: a Python started isolated (``-I``: no user site, no working directory on
    the path, no ``PYTHON*`` variables), in its own session, stdout and stderr ``/dev/null``,
    stdin a private pipe for the job, running from ``/``."""
    return ChildSpec(
        (sys.executable, "-I", "-m", "gatectl.supervisor"),
        stdin=Stdio.PIPE,
        stdout=Stdio.DEVNULL,
        stderr=Stdio.DEVNULL,
        new_session=True,
        cwd="/",
        env=dict(environ),
    )


def start_detached(
    gw: Gateway,
    ev: HookEvent,
    *,
    state_dir: Path,
    environ: Mapping[str, str],
    deadline: float = HANDOFF_DEADLINE,
) -> bool:
    """Start the supervisor for ``ev`` and return without waiting for it.

    ``False`` when nothing is running for the event (no hooks, a payload that cannot be sent,
    the supervisor not started or not taking its job in ``deadline`` seconds: it is killed by
    its own group, and a ``hook_skipped`` event is logged). Never raises.
    """
    if not ev.commands:
        return False
    try:
        encode_payload(ev.payload)
        frame = encode_job(ev, state_dir)
        if len(frame) > MAX_PAYLOAD * 2 + 1024 * 64:
            raise ValueError("job too large")
        spec = supervisor_spec(environ)
    except (TypeError, ValueError):
        log_event(state_dir, ev, "hook_skipped", "warn", {"reason": "payload_invalid"})
        return False
    try:
        child = gw.start(spec)
    except OSError:
        log_event(state_dir, ev, "hook_skipped", "warn", {"reason": "not_started"})
        return False
    try:
        _handoff(child.stdin, frame, deadline)
    except OSError:
        try:
            child.signal_group(signal.SIGKILL)
        except (OSError, ValueError):
            pass
        log_event(state_dir, ev, "hook_skipped", "warn", {"reason": "handoff_failed"})
        return False
    finally:
        _close(child.stdin)
    return True


def _close(stream: object) -> None:
    close = getattr(stream, "close", None)
    if close is not None:
        try:
            close()
        except OSError:
            pass


def _handoff(stream: Any, frame: bytes, deadline: float) -> None:
    """Write the whole frame without ever blocking longer than ``deadline`` seconds in total."""
    if stream is None:
        raise OSError(errno.EPIPE, "no stdin")
    try:
        fd = stream.fileno()
    except (OSError, ValueError):  # not a real descriptor (a test double)
        stream.write(frame)
        stream.flush()
        return
    os.set_blocking(fd, False)
    end = time.monotonic() + deadline
    view = memoryview(frame)
    while view:
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(errno.ETIMEDOUT, "supervisor does not take its job")
        _, ready, _ = select.select([], [fd], [], remaining)
        if not ready:
            continue
        try:
            view = view[os.write(fd, view) :]
        except BlockingIOError:
            continue


# --- the post-decision payload ----------------------------------------------------------------


def post_decision_event(
    *,
    commands: Sequence[HookCommand],
    decision_id: str,
    policy: str,
    scope: str,
    state: str,
    decision: str,
    reason: str,
    fingerprint: str,
    actor: str,
    checks: Sequence[Mapping[str, Any]],
) -> HookEvent:
    """The ``post-decision`` event (``schemas/hooks/post-decision.json``). Carries no input text
    and no ``labels`` key; a check contributes only its closed fields (never its ``detail``)."""
    payload = {
        "tool": "gatectl",
        "hook": "post-decision",
        "object_type": "decision",
        "object_id": decision_id,
        "repo": None if scope == "*" else scope,
        "policy": policy,
        "scope": scope,
        "state": state,
        "shadow": state == "shadow",
        "enforced": state == "enforced",
        "decision": decision,
        "reason": reason,
        "fingerprint": fingerprint,
        "actor": actor,
        "checks": [
            {k: c[k] for k in ("name", "type", "verdict", "reason", "duration_ms")} for c in checks
        ],
    }
    return HookEvent(
        hook="post-decision",
        object_type="decision",
        object_id=decision_id,
        payload=payload,
        commands=tuple(commands),
        policy=policy,
        scope=scope,
        decision_id=decision_id,
    )
