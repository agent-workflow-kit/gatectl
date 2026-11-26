"""The script runner (interface.md, Script checks): one child, safely.

``run_process`` starts a child in its own process group and runs a selector loop that writes
the payload to its stdin without blocking, reads stdout and stderr together up to a cap, and
enforces a deadline on everything. It ends the child's whole group and tells a lifeline
watchdog before it reaps the leader, in this order:

1. the leader's exit is noticed WITHOUT reaping it (``Child.wait_exited``), so while it is a
   zombie its process group id cannot be reused;
2. the group is swept with SIGKILL (stragglers, a grandchild that ignored SIGTERM);
3. the watchdog is told ``done`` (it will no longer signal anything);
4. only then is the leader reaped.

A timeout (or ``cancel``) sends SIGTERM to the group, SIGKILL after ``kill_grace``. A straggler
that left the group with ``setsid`` is not found (a documented residual risk); it can still
hold a pipe open, so reading after the leader's exit has its own deadline (``drain_grace``)
and the runner never waits on a pipe it does not control.

Every signal goes through ``Child.signal_group`` (a no-op once the leader is reaped, an error
for a child without its own group), from this thread, the one that reaps. Nothing here spawns
or signals anything else, and nothing signals gatectl's own group.

``interpret`` maps the run to a verdict by the exit-code contract; ``run_script`` combines
them; ``run_script_check`` adds the private working directory and the environment.
Nothing here decodes with the locale: output is bytes, and text is decoded as UTF-8.
"""

# TODO(#20): detached hooks reuse ``run_process`` pieces (own group, deadlines, watchdog).
# TODO(#37): where ``os.waitid`` is missing (some macOS builds), ``Child.wait_exited`` in
#   gateway.py needs the ``kqueue`` fallback; the watchdog's start-time guard needs a macOS
#   ``procinfo.start_time``.

from __future__ import annotations

import errno
import math
import os
import re
import selectors
import signal
import stat
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal

from gatectl import inputs, procinfo, tmptree
from gatectl.gateway import Child, ChildSpec, Gateway, Stdio, watchdog_spec
from gatectl.sanitize import MARKER, sanitize

OUTPUT_CAP = 64 * 1024
KILL_GRACE = 2.0
DRAIN_GRACE = 1.0
REASON_MAX = 1024
# How long to wait for a SIGKILLed leader (uninterruptible sleep can outlast it).
_KILL_WAIT = 5.0
# Upper bound on how long the loop sleeps, so the leader's exit and the deadlines are noticed.
_TICK = 0.02
_READ_SIZE = 64 * 1024

Status = Literal[
    "exited",
    "signaled",
    "timeout",
    "cancelled",
    "tool_missing",
    "not_started",
    "lifeline_lost",
]
PhaseHook = Callable[[str, int, int], None]

# Watchdogs of leaders that would not die: kept referenced (so their lifeline stays open until
# gatectl itself ends, when the watchdog kills the group) instead of being closed and dropped.
_PARKED: list[Child] = []


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


@dataclass(frozen=True, kw_only=True)
class RunSpec:
    argv: tuple[str, ...]
    env: Mapping[str, str]
    cwd: str
    timeout: float
    stdin_data: bytes | None = None
    # A file the child reads as its stdin (a hook's payload file); excludes ``stdin_data``.
    stdin_path: str | None = None
    # False: stdout and stderr go to /dev/null and nothing is read (a hook's output is discarded).
    capture_output: bool = True
    stdout_cap: int = OUTPUT_CAP
    stderr_cap: int = OUTPUT_CAP
    kill_grace: float = KILL_GRACE
    drain_grace: float = DRAIN_GRACE

    def __post_init__(self) -> None:
        argv = tuple(self.argv) if isinstance(self.argv, Sequence) else ()
        if isinstance(self.argv, str | bytes) or not argv or not isinstance(argv[0], str):
            raise ValueError("argv must be a non-empty list of strings")
        if not argv[0].startswith("/"):
            raise ValueError(f"argv[0] must be an absolute path, got {argv[0]!r}")
        if any(not isinstance(a, str) or "\x00" in a for a in argv):
            raise ValueError("argv entries must be strings without NUL bytes")
        if not isinstance(self.env, Mapping) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in self.env.items()
        ):
            raise ValueError("env must be a mapping of strings")
        if not isinstance(self.cwd, str) or "\x00" in self.cwd:
            raise ValueError("cwd must be a string")
        if not _is_number(self.timeout) or not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError(f"timeout must be a positive finite number, got {self.timeout!r}")
        if self.stdin_data is not None and not isinstance(self.stdin_data, bytes):
            raise ValueError("stdin_data must be bytes or None")
        if self.stdin_path is not None and (
            self.stdin_data is not None
            or not isinstance(self.stdin_path, str)
            or not self.stdin_path
            or "\x00" in self.stdin_path
        ):
            raise ValueError("stdin_path must be a path string and excludes stdin_data")
        if not isinstance(self.capture_output, bool):
            raise ValueError("capture_output must be a bool")
        for name in ("stdout_cap", "stderr_cap"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer, got {value!r}")
        for name in ("kill_grace", "drain_grace"):
            value = getattr(self, name)
            if not _is_number(value) or not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be a non-negative finite number, got {value!r}")
        object.__setattr__(self, "argv", argv)
        object.__setattr__(self, "env", dict(self.env))


@dataclass(frozen=True, kw_only=True)
class RunResult:
    status: Status
    code: int | None = None  # the exit status, when the leader exited by itself or on SIGTERM
    signal: int | None = None  # the signal that ended the leader
    stdout: bytes = field(default=b"", repr=False)
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    # A process outside the group still held a pipe when the drain deadline passed.
    pipes_held: bool = False
    # The leader survived SIGKILL (uninterruptible sleep): not reaped, group left to the watchdog.
    leader_unkilled: bool = False
    elapsed: float = 0.0


class _Sink:
    """Keeps the first ``cap`` bytes, counts and discards the rest."""

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.data = bytearray()
        self.truncated = False

    def feed(self, chunk: bytes) -> None:
        room = self.cap - len(self.data)
        if len(chunk) > room:
            self.truncated = True
            chunk = chunk[: max(room, 0)]
        self.data += chunk


def _usable(argv0: str) -> bool:
    try:
        info = os.stat(argv0)
    except OSError:
        return False
    return stat.S_ISREG(info.st_mode) and os.access(argv0, os.X_OK)


_MISSING_ERRNOS = {errno.ENOENT, errno.EACCES, errno.ENOEXEC, errno.ENOTDIR, errno.ELOOP}


def run_process(
    gw: Gateway,
    spec: RunSpec,
    *,
    cancel: Callable[[], bool] | None = None,
    on_phase: PhaseHook | None = None,
) -> RunResult:
    """Run ``spec`` to completion (or to its deadline) and return what happened.

    ``cancel`` is polled every tick; when it returns true the kill sequence runs and the
    result is ``cancelled``. ``on_phase(phase, check_pid, watchdog_pid)`` is a test seam called
    at ``started``, ``swept``, ``done_sent`` and ``reaped``.
    """
    return _Run(gw, spec, cancel, on_phase).run()


class _Run:
    def __init__(
        self,
        gw: Gateway,
        spec: RunSpec,
        cancel: Callable[[], bool] | None,
        on_phase: PhaseHook | None,
    ) -> None:
        self.gw = gw
        self.spec = spec
        self.cancel = cancel
        self.on_phase = on_phase
        self.t0 = time.monotonic()
        self.wd: Child | None = None
        self.child: Child | None = None
        self.reason: Literal["timeout", "cancelled", "lifeline_lost"] | None = None
        self.exited = False
        self.pipes_held = False
        self.not_started = False
        self.missing = False
        self.leader_unkilled = False
        self.returncode: int | None = None
        self.out = _Sink(spec.stdout_cap)
        self.err = _Sink(spec.stderr_cap)

    # -- driver ------------------------------------------------------------------------

    def run(self) -> RunResult:
        argv0 = self.spec.argv[0]
        if not _usable(argv0):
            return self._result("tool_missing")
        try:
            self.wd = self.gw.start(watchdog_spec())
        except OSError:
            return self._result("not_started")
        try:
            self._run_check()
        finally:
            self._release_watchdog()
        return self._result(self._status())

    def _run_check(self) -> None:
        spec = self.spec
        out = Stdio.PIPE if spec.capture_output else Stdio.DEVNULL
        if spec.stdin_path is not None:
            stdin = Stdio.FILE
        else:
            stdin = Stdio.DEVNULL if spec.stdin_data is None else Stdio.PIPE
        child_spec = ChildSpec(
            spec.argv,
            stdin=stdin,
            stdin_path=spec.stdin_path,
            stdout=out,
            stderr=out,
            own_group=True,
            cwd=spec.cwd,
            env=spec.env,
        )
        # Everything from here on is inside one try, so the group and the watchdog are always
        # ended, even by a ``BaseException`` (an interrupt) right after the child started.
        try:
            try:
                self.child = self.gw.start(child_spec)
            except OSError as e:
                missing = e.errno in _MISSING_ERRNOS and e.filename == spec.argv[0]
                self.missing = missing
                self.not_started = not missing
                return
            try:
                self._register()
            except _NoLifeline:
                return  # the finally below kills and reaps the child that just started
            self._phase("started")
            self._loop()
        finally:
            if self.child is not None:
                self._teardown()

    def _phase(self, name: str) -> None:
        if self.on_phase is not None and self.child is not None and self.wd is not None:
            self.on_phase(name, self.child.pid, self.wd.pid)

    def _register(self) -> None:
        """Tell the watchdog the check's group; no lifeline means the check is killed at once.

        The check is already running when this is called, so a check with no lifeline may have
        executed for a few microseconds before it is killed and reaped: it is "not started" as
        a verdict, not as a guarantee that nothing ran.
        """
        assert self.child is not None and self.wd is not None and self.wd.stdin is not None
        start = procinfo.start_time(self.child.pid)
        line = f"G {self.child.pid} {start or '-'}\n".encode("ascii")
        try:
            self.wd.stdin.write(line)
            self.wd.stdin.flush()
        except OSError:
            self.not_started = True
            raise _NoLifeline from None
        if self.wd.poll() is not None:  # the watchdog was already gone: nobody guards the group
            self.not_started = True
            raise _NoLifeline

    # -- the selector loop -------------------------------------------------------------

    def _loop(self) -> None:
        child = self.child
        assert child is not None
        spec = self.spec
        sel = selectors.DefaultSelector()
        readers: dict[int, _Sink] = {}
        writer: _Writer | None = None
        try:
            for stream, sink in ((child.stdout, self.out), (child.stderr, self.err)):
                if stream is None:
                    continue  # discarded: sent to /dev/null, nothing to read
                fd = stream.fileno()
                os.set_blocking(fd, False)
                sel.register(fd, selectors.EVENT_READ)
                readers[fd] = sink
            if spec.stdin_data is not None and child.stdin is not None:
                if spec.stdin_data:
                    os.set_blocking(child.stdin.fileno(), False)
                    writer = _Writer(child.stdin, spec.stdin_data)
                    sel.register(writer.fd, selectors.EVENT_WRITE)
                else:
                    _close(child.stdin)
            deadline = self.t0 + spec.timeout
            term_at: float | None = None
            kill_at: float | None = None
            drain_deadline: float | None = None
            while True:
                now = time.monotonic()
                if not self.exited and child.wait_exited(0):
                    self.exited = True
                if self.exited:
                    if drain_deadline is None:
                        child.signal_group(signal.SIGKILL)  # sweep the stragglers
                        drain_deadline = now + spec.drain_grace
                        if writer is not None:
                            sel.unregister(writer.fd)
                            writer.close()
                            writer = None
                    if not readers:
                        break
                    if now >= drain_deadline:
                        self.pipes_held = True
                        break
                else:
                    if term_at is None:
                        if self.cancel is not None and self.cancel():
                            self.reason = "cancelled"
                        elif now >= deadline:
                            self.reason = "timeout"
                        elif self.wd is not None and self.wd.poll() is not None:
                            self.reason = "lifeline_lost"  # nobody would stop the group now
                        if self.reason is not None:
                            child.signal_group(signal.SIGTERM)
                            term_at = now
                    elif kill_at is None:
                        if now >= term_at + spec.kill_grace:
                            child.signal_group(signal.SIGKILL)
                            kill_at = now
                    elif now >= kill_at + _KILL_WAIT:
                        self.leader_unkilled = True
                        break
                wait = _TICK
                if drain_deadline is not None:
                    wait = min(wait, max(drain_deadline - now, 0.0))
                if not sel.get_map():
                    time.sleep(wait)
                    continue
                for key, mask in sel.select(wait):
                    if writer is not None and key.fd == writer.fd:
                        if not writer.pump():
                            sel.unregister(writer.fd)
                            writer.close()
                            writer = None
                    elif mask & selectors.EVENT_READ and not _pump_read(key.fd, readers[key.fd]):
                        sel.unregister(key.fd)
                        del readers[key.fd]
        finally:
            sel.close()
            if writer is not None:
                writer.close()

    # -- ending the child ----------------------------------------------------------------

    def _teardown(self) -> None:
        child, wd = self.child, self.wd
        assert child is not None and wd is not None
        try:
            if self.leader_unkilled:
                return  # the loop already killed it and waited out ``_KILL_WAIT``: no second wait
            if not self.exited:
                child.signal_group(signal.SIGKILL)
                self.exited = child.wait_exited(_KILL_WAIT)
            if not self.exited:
                self.leader_unkilled = True
                return
            child.signal_group(signal.SIGKILL)  # the sweep, with the leader still a zombie
            self._phase("swept")
            if self.reason is None and wd.poll() is not None:
                self.reason = "lifeline_lost"  # it died before ``done``: the run was unguarded
            self._tell_done(wd)
            self._phase("done_sent")
            self.returncode = child.wait(timeout=_KILL_WAIT)
            self._phase("reaped")
        finally:
            for stream in (child.stdin, child.stdout, child.stderr):
                _close(stream)

    def _tell_done(self, wd: Child) -> None:
        try:
            assert wd.stdin is not None
            wd.stdin.write(b"done\n")
            wd.stdin.flush()
        except OSError:
            pass  # the watchdog is gone; there is nobody to tell

    def _release_watchdog(self) -> None:
        wd = self.wd
        if wd is None:
            return
        if self.leader_unkilled:
            _PARKED.append(wd)
            return
        _close(wd.stdin)
        try:
            wd.wait(timeout=2.0)
        except TimeoutError:
            wd.signal_group(signal.SIGKILL)
            try:
                wd.wait(timeout=_KILL_WAIT)
            except TimeoutError:
                _PARKED.append(wd)
        for stream in (wd.stdout, wd.stderr):
            _close(stream)

    # -- the result ----------------------------------------------------------------------

    def _status(self) -> Status:
        if self.not_started:
            return "not_started"
        if self.missing:
            return "tool_missing"
        rc = self.returncode
        if self.reason is not None:
            return self.reason
        if rc is None:
            return "not_started"
        return "signaled" if rc < 0 else "exited"

    def _result(self, status: Status) -> RunResult:
        rc = self.returncode
        return RunResult(
            status=status,
            code=rc if rc is not None and rc >= 0 else None,
            signal=-rc if rc is not None and rc < 0 else None,
            stdout=bytes(self.out.data),
            stdout_truncated=self.out.truncated,
            stderr_truncated=self.err.truncated,
            pipes_held=self.pipes_held,
            leader_unkilled=self.leader_unkilled,
            elapsed=time.monotonic() - self.t0,
        )


class _NoLifeline(Exception):
    pass


def _close(stream: object) -> None:
    close = getattr(stream, "close", None)
    if close is not None:
        try:
            close()
        except OSError:
            pass


def _pump_read(fd: int, sink: _Sink) -> bool:
    """Read what is there; ``False`` at end of file (or an error, which ends the stream)."""
    try:
        data = os.read(fd, _READ_SIZE)
    except BlockingIOError:
        return True
    except OSError:
        return False
    if not data:
        return False
    sink.feed(data)
    return True


class _Writer:
    """Writes the payload to the child's stdin; a closed pipe just ends it."""

    def __init__(self, stream: object, data: bytes) -> None:
        self.stream = stream
        self.fd: int = stream.fileno()  # type: ignore[attr-defined]
        self.view = memoryview(data)
        self.offset = 0

    def pump(self) -> bool:
        """Write what the pipe takes; ``False`` when done or the pipe is closed."""
        try:
            n = os.write(self.fd, self.view[self.offset : self.offset + _READ_SIZE])
        except BlockingIOError:
            return True
        except OSError:  # EPIPE: the child closed or never reads its stdin
            return False
        self.offset += n
        return self.offset < len(self.view)

    def close(self) -> None:
        self.view.release()
        _close(self.stream)


# --- the environment -----------------------------------------------------------------------

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\*?")


def _clean_path(value: str) -> str | None:
    """``PATH`` without empty and relative entries; ``None`` if nothing absolute is left.

    An empty ``PATH`` can mean "the current directory" to a shell, so it is never passed.
    """
    kept = [entry for entry in value.split(":") if entry.startswith("/")]
    return ":".join(kept) if kept else None


def build_env(
    environ: Mapping[str, str],
    default_allow: Sequence[str],
    check_allow: Sequence[str] = (),
) -> dict[str, str]:
    """The environment of a script check, built from scratch from allowlists.

    ``default_allow`` is ``defaults.script_env_allow`` (names, or a name with a trailing ``*``
    for a prefix); ``check_allow`` is the check's ``env_allow`` (exact names only). A variable
    in neither never reaches the check, so token variables stay out unless a check names one.
    An allowed variable that is unset stays unset. ``PATH`` loses its empty and relative
    entries and is left out when none is absolute.
    """
    exact: set[str] = set()
    prefixes: list[str] = []
    for entry in default_allow:
        if not isinstance(entry, str) or not _PATTERN.fullmatch(entry):
            raise ValueError(f"script_env_allow entry is invalid: {entry!r}")
        if entry.endswith("*"):
            prefixes.append(entry[:-1])
        else:
            exact.add(entry)
    for entry in check_allow:
        if not isinstance(entry, str) or not _NAME.fullmatch(entry):
            raise ValueError(f"env_allow entry is invalid (exact names only): {entry!r}")
        exact.add(entry)
    env: dict[str, str] = {}
    for name, value in environ.items():
        if not _NAME.fullmatch(name) or "\x00" in value:
            continue
        if name in exact or any(name.startswith(p) for p in prefixes):
            env[name] = value
    if "PATH" in env:
        cleaned = _clean_path(env["PATH"])
        if cleaned is None:
            del env["PATH"]
        else:
            env["PATH"] = cleaned
    return env


# --- the verdict ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScriptOutcome:
    verdict: Literal["allow", "deny", "escalate"]
    # Closed reason code (interface.md, Reasons); ``None`` for an allow.
    reason: (
        Literal["check_denied", "check_escalated", "check_error", "timeout", "tool_missing"] | None
    )
    detail: str | None
    warnings: tuple[str, ...] = ()
    duration_ms: int = 0
    # The private working directory could not be removed safely and was left for ``reconcile``.
    workdir_left: bool = False
    # The leader survived SIGKILL (not reaped, its group left to the watchdog) / a process
    # outside the group held a pipe past the drain deadline. Not warning codes (the interface's
    # warning list is fixed); the engine logs them.
    leader_unkilled: bool = False
    pipes_held: bool = False


@dataclass(frozen=True)
class _Output:
    reason: str | None = None
    has_decision: bool = False
    decision: object = None


def _parse_stdout(data: bytes) -> _Output:
    """Strict JSON object with an optional ``reason`` and ``decision``; anything else is empty."""
    try:
        obj = inputs.parse_input(data)
    except inputs.InputInvalid:
        return _Output()
    raw = obj.get("reason")
    reason = sanitize(raw, REASON_MAX) if isinstance(raw, str) and raw else None
    if reason is not None and not reason.strip(f" {MARKER}"):
        reason = None  # nothing readable is left: the exit form is the better detail
    return _Output(reason, "decision" in obj, obj.get("decision"))


_BY_CODE = {0: "allow", 11: "deny", 13: "escalate"}


def interpret(argv0: str, result: RunResult) -> ScriptOutcome:
    """Map a run to a verdict: the exit code decides (interface.md, Script checks)."""
    warnings = ("output_truncated",) if result.stdout_truncated or result.stderr_truncated else ()
    ms = int(result.elapsed * 1000)

    def outcome(
        verdict: Literal["allow", "deny", "escalate"],
        reason: Literal["check_denied", "check_escalated", "check_error", "timeout", "tool_missing"]
        | None,
        detail: str | None,
    ) -> ScriptOutcome:
        return ScriptOutcome(
            verdict,
            reason,
            detail,
            warnings,
            ms,
            leader_unkilled=result.leader_unkilled,
            pipes_held=result.pipes_held,
        )

    if result.status == "tool_missing":
        return outcome("escalate", "tool_missing", sanitize(argv0))
    if result.status == "not_started":
        return outcome("escalate", "check_error", "not started")
    parsed = _parse_stdout(result.stdout)
    if result.status == "timeout":
        return outcome("escalate", "timeout", parsed.reason or "timeout")
    if result.status == "lifeline_lost":
        return outcome("escalate", "check_error", "lifeline lost")
    if result.status == "cancelled":
        return outcome("escalate", "check_error", parsed.reason or "cancelled")
    if result.status == "signaled":
        return outcome("escalate", "check_error", parsed.reason or f"signal {result.signal}")
    code = result.code
    expected = _BY_CODE.get(code) if code is not None else None
    fallback = f"exit {code}"
    if expected is None or (parsed.has_decision and parsed.decision != expected):
        return outcome("escalate", "check_error", parsed.reason or fallback)
    if expected == "allow":
        return outcome("allow", None, None)
    if expected == "deny":
        return outcome("deny", "check_denied", parsed.reason or fallback)
    return outcome("escalate", "check_escalated", parsed.reason or fallback)


# --- the whole script check ----------------------------------------------------------------


def _argv(argv: object) -> tuple[str, ...]:
    """The argv as a tuple; a string is refused (it would split into characters)."""
    if isinstance(argv, str | bytes | bytearray) or not isinstance(argv, Sequence):
        raise ValueError("argv must be a list of strings, not a string")
    return tuple(argv)


def run_script(
    gw: Gateway,
    *,
    argv: Sequence[str],
    payload: bytes | None,
    timeout: float,
    env: Mapping[str, str],
    cwd: str,
    kill_grace: float = KILL_GRACE,
    drain_grace: float = DRAIN_GRACE,
    cancel: Callable[[], bool] | None = None,
    on_phase: PhaseHook | None = None,
) -> ScriptOutcome:
    """Run one script check's process and return its verdict."""
    spec = RunSpec(
        argv=_argv(argv),
        env=env,
        cwd=cwd,
        timeout=timeout,
        stdin_data=payload,
        kill_grace=kill_grace,
        drain_grace=drain_grace,
    )
    return interpret(spec.argv[0], run_process(gw, spec, cancel=cancel, on_phase=on_phase))


def run_script_check(
    gw: Gateway,
    *,
    argv: Sequence[str],
    payload: bytes,
    timeout: float,
    env_allow: Sequence[str],
    default_env_allow: Sequence[str],
    environ: Mapping[str, str],
    state_dir: Path,
    decision_id: str,
    n: int,
    cancel: Callable[[], bool] | None = None,
) -> ScriptOutcome:
    """A script check as the engine runs it: private working directory, built environment.

    The directory ``tmp/<decision_id>/s-<n>/`` is created empty (mode 0700) and removed when the
    check ends; if it cannot be removed safely it is left for ``reconcile`` and the outcome says
    so (``workdir_left``). The decision's own ``tmp/<decision_id>/`` directory is the caller's
    to remove when the whole ``check`` ends. A check whose directory cannot be made did not run.

    The caller validates ``env_allow`` and ``defaults.script_env_allow`` first: an invalid
    entry, or a string ``argv``, raises ``ValueError`` before anything is created or started.
    Removal problems (``UnsafeTree`` or any ``OSError``) never replace the verdict: they set
    ``workdir_left``.
    """
    argv = _argv(argv)
    env = build_env(environ, default_env_allow, env_allow)
    try:
        decision_dir = tmptree.create_decision_dir(state_dir, decision_id)
        workdir = tmptree.make_script_dir(decision_dir, n)
    except (OSError, tmptree.UnsafeTree):
        return ScriptOutcome("escalate", "check_error", "not started")
    try:
        result = run_script(
            gw,
            argv=argv,
            payload=payload,
            timeout=timeout,
            env=env,
            cwd=str(workdir),
            cancel=cancel,
        )
    finally:
        left = False
        try:
            tmptree.remove_tree(workdir)
        except (OSError, tmptree.UnsafeTree):
            left = True
    return replace(result, workdir_left=left)
