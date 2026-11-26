"""Gateway: the single boundary for subprocess calls.

Every child process gatectl starts goes through this module, so tests can substitute a fake
(``tests/fake_gateway.py``) by dependency injection and no other module imports ``subprocess``
(``tests/test_import_boundary.py`` enforces that). Commands are argv tuples, never a shell
string, and untrusted text travels on stdin or in files, never in argv or the environment.

Descriptor rules for every child (interface.md, Hooks): stdin, stdout and stderr are each stated
explicitly as ``/dev/null`` or a private pipe (stdin may also be a read-only file: a hook's
payload; there is no way to say "inherit"), and
``close_fds`` is always on, so a child never holds a descriptor of the caller.

This module only starts children and reads their output with a cap; the selector loop and the
group kill sequence are built on it by the script runner. The lifeline watchdog program lives
here too (``WATCHDOG_SOURCE``), because it is the one piece of gatectl that signals a process
group from outside the gateway's own ``Child`` handles: it runs as a separate child and signals
only the group it was told about, under the rules in its docstring.
"""

from __future__ import annotations

import enum
import os
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import IO, Any, Protocol

# Read size for ``read_capped``.
_CHUNK = 64 * 1024


class Stdio(enum.Enum):
    """Where one of a child's standard streams goes. Inheriting the caller's is not an option."""

    DEVNULL = "devnull"
    PIPE = "pipe"
    # stdin only: a read-only file, opened by the gateway (``ChildSpec.stdin_path``).
    FILE = "file"


@dataclass(frozen=True, kw_only=True)
class ChildSpec:
    """Everything needed to start one child; invalid specs are refused at construction."""

    argv: tuple[str, ...]
    stdin: Stdio
    stdout: Stdio
    stderr: Stdio
    own_group: bool = False
    # stdin_path: the file behind ``stdin=Stdio.FILE`` (required exactly then).
    stdin_path: str | None = None
    # A new session (setsid): the child leads its own session and group, so a hangup of the
    # caller's terminal or session never reaches it. Implies its own process group.
    new_session: bool = False
    cwd: str | None = None
    # None: the environment of gatectl. Read-only, and kept out of repr (it may hold secrets).
    env: Mapping[str, str] | None = field(default=None, repr=False)

    def __reduce__(self) -> tuple[Any, ...]:
        # env is a MappingProxyType (unpicklable); rebuild through __init__ with a plain dict.
        env = None if self.env is None else dict(self.env)
        return (
            _rebuild_spec,
            (
                self.argv,
                self.stdin,
                self.stdout,
                self.stderr,
                self.own_group,
                self.cwd,
                env,
                self.stdin_path,
                self.new_session,
            ),
        )

    def __hash__(self) -> int:
        env = None if self.env is None else tuple(sorted(self.env.items()))
        streams = (self.stdin, self.stdout, self.stderr)
        flags = (self.own_group, self.new_session, self.stdin_path)
        return hash((self.argv, streams, flags, self.cwd, env))

    def __init__(
        self,
        argv: Sequence[str],
        *,
        stdin: Stdio,
        stdout: Stdio,
        stderr: Stdio,
        own_group: bool = False,
        cwd: str | None = None,
        env: Mapping[str, str] | None = None,
        stdin_path: str | None = None,
        new_session: bool = False,
    ) -> None:
        if isinstance(argv, str | bytes) or not isinstance(argv, Sequence):
            raise ValueError("argv must be a list or tuple of strings, never a shell string")
        if not argv:
            raise ValueError("argv must not be empty")
        for arg in argv:
            if not isinstance(arg, str) or "\x00" in arg:
                raise ValueError("argv entries must be strings without NUL bytes")
        if not argv[0]:
            raise ValueError("argv[0] must not be empty")
        for name, value in (("stdin", stdin), ("stdout", stdout), ("stderr", stderr)):
            if not isinstance(value, Stdio) or (name != "stdin" and value is Stdio.FILE):
                raise ValueError(f"{name} must be Stdio.DEVNULL or Stdio.PIPE, got {value!r}")
        if not isinstance(own_group, bool):
            raise ValueError(f"own_group must be a bool, got {own_group!r}")
        if not isinstance(new_session, bool):
            raise ValueError(f"new_session must be a bool, got {new_session!r}")
        if (stdin is Stdio.FILE) != (stdin_path is not None) or (
            stdin_path is not None
            and (not isinstance(stdin_path, str) or not stdin_path or "\x00" in stdin_path)
        ):
            raise ValueError("stdin_path is a non-empty path string exactly when stdin is FILE")
        if cwd is not None and (not isinstance(cwd, str) or "\x00" in cwd):
            raise ValueError("cwd must be a string without NUL bytes, or None")
        if env is not None:
            if not isinstance(env, Mapping):
                raise ValueError(f"env must be a mapping of strings, got {type(env).__name__}")
            for key, val in env.items():
                if (
                    not isinstance(key, str)
                    or not isinstance(val, str)
                    or not key
                    or "=" in key
                    or "\x00" in key
                    or "\x00" in val
                ):
                    raise ValueError(f"env has an invalid entry: {key!r}")
        object.__setattr__(self, "argv", tuple(argv))
        object.__setattr__(self, "stdin", stdin)
        object.__setattr__(self, "stdout", stdout)
        object.__setattr__(self, "stderr", stderr)
        object.__setattr__(self, "own_group", own_group)
        object.__setattr__(self, "stdin_path", stdin_path)
        object.__setattr__(self, "new_session", new_session)
        object.__setattr__(self, "cwd", cwd)
        object.__setattr__(self, "env", None if env is None else MappingProxyType(dict(env)))


def _rebuild_spec(
    argv: tuple[str, ...],
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
    own_group: bool,
    cwd: str | None,
    env: dict[str, str] | None,
    stdin_path: str | None,
    new_session: bool,
) -> ChildSpec:
    return ChildSpec(
        argv,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        own_group=own_group,
        cwd=cwd,
        env=env,
        stdin_path=stdin_path,
        new_session=new_session,
    )


class Child(Protocol):
    """A started child. Streams are set only for the ``Stdio.PIPE`` ends the spec asked for."""

    pid: int
    own_group: bool
    stdin: IO[bytes] | None
    stdout: IO[bytes] | None
    stderr: IO[bytes] | None

    def poll(self) -> int | None:
        """The exit status if the child ended, else ``None``. Reaps the leader when it ended.

        Once reaped, stragglers in its group can no longer be signalled (``signal_group``).
        """
        ...

    def wait(self, timeout: float | None = None) -> int:
        """Wait for the child and reap it; raise ``TimeoutError`` after ``timeout`` seconds.

        Like ``poll``, this ends ``signal_group``: sweep stragglers before calling it.
        """
        ...

    def wait_exited(self, timeout: float | None = None) -> bool:
        """Block until the leader has exited WITHOUT reaping it; ``False`` on timeout.

        While the leader is an unreaped zombie its process group id cannot be reused, so
        ``signal_group`` stays safe. The runner's order: ``wait_exited``, ``signal_group`` to
        sweep stragglers, then ``wait``.
        """
        ...

    def signal_group(self, sig: int) -> None:
        """Signal the child's own process group by the pid captured at launch.

        Raises ``ValueError`` for a child that was not started with ``own_group`` (the caller's
        group is never signaled). Does nothing once the child was reaped (by ``poll`` or
        ``wait``), because the group id may have been reused by then; use ``wait_exited`` to
        wait for the leader without reaping it. Call it from the thread that owns
        ``wait``/``poll``, so a reap cannot race the signal.
        """
        ...


class Gateway(Protocol):
    """What the rest of gatectl depends on; the real one and the test fake both implement it."""

    def start(self, spec: ChildSpec) -> Child:
        """Start a child without waiting for it. Raises ``OSError`` if it cannot be started."""
        ...


_STDIO = {Stdio.DEVNULL: subprocess.DEVNULL, Stdio.PIPE: subprocess.PIPE}


class _Child:
    def __init__(self, popen: subprocess.Popen[bytes], own_group: bool) -> None:
        self._popen = popen
        self._reaped = False  # reaped by someone else: the pid may be reused, never signal it
        self.pid = popen.pid
        self.own_group = own_group
        self.stdin = popen.stdin
        self.stdout = popen.stdout
        self.stderr = popen.stderr

    def poll(self) -> int | None:
        return self._popen.poll()

    def wait(self, timeout: float | None = None) -> int:
        try:
            return self._popen.wait(timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise TimeoutError(f"pid {self.pid} still running after {timeout} s") from e

    def wait_exited(self, timeout: float | None = None) -> bool:
        if self._popen.returncode is not None:
            return True
        deadline = None if timeout is None else time.monotonic() + timeout
        flags = os.WEXITED | os.WNOWAIT
        while True:
            try:
                if deadline is None:
                    os.waitid(os.P_PID, self.pid, flags)
                    return True
                if os.waitid(os.P_PID, self.pid, flags | os.WNOHANG) is not None:
                    return True
            except ChildProcessError:  # already reaped elsewhere
                self._reaped = True
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.005, remaining))

    def signal_group(self, sig: int) -> None:
        if not self.own_group:
            raise ValueError("child was not started in its own process group")
        if self._reaped or self._popen.returncode is not None:
            return
        try:
            os.killpg(self.pid, sig)
        except ProcessLookupError:
            pass


class SubprocessGateway:
    """The real gateway: ``subprocess.Popen`` with explicit streams and ``close_fds``."""

    def start(self, spec: ChildSpec) -> Child:
        stdin_fd = -1
        stdin: int | None = _STDIO.get(spec.stdin)
        if spec.stdin is Stdio.FILE:
            assert spec.stdin_path is not None
            # No link is followed, and the descriptor is the child's alone (close-on-exec,
            # closed here once the child has it as fd 0).
            stdin_fd = os.open(spec.stdin_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stdin = stdin_fd
        try:
            popen = subprocess.Popen(
                list(spec.argv),
                stdin=stdin,
                stdout=_STDIO[spec.stdout],
                stderr=_STDIO[spec.stderr],
                close_fds=True,
                shell=False,
                cwd=spec.cwd,
                env=None if spec.env is None else dict(spec.env),
                process_group=0 if spec.own_group and not spec.new_session else None,
                start_new_session=spec.new_session,
            )
        finally:
            if stdin_fd >= 0:
                os.close(stdin_fd)
        return _Child(popen, spec.own_group or spec.new_session)


@dataclass(frozen=True)
class CappedRead:
    data: bytes
    truncated: bool


def read_capped(stream: IO[bytes], cap: int) -> CappedRead:
    """Read ``stream`` to end of file, keeping the first ``cap`` bytes.

    Bytes past the cap are read and discarded so the writer never blocks on a full pipe;
    ``truncated`` says whether any were. Blocks until end of file, so never call it on a live
    child without a deadline, and never sequentially on two pipes of one live child (the
    unread one can fill and deadlock the child): the runner uses a selector loop (#16).
    """
    if cap < 0:
        raise ValueError(f"cap must not be negative, got {cap}")
    kept: list[bytes] = []
    remaining = cap
    truncated = False
    while chunk := stream.read(_CHUNK):
        if remaining >= len(chunk):
            kept.append(chunk)
            remaining -= len(chunk)
        else:
            kept.append(chunk[:remaining])
            remaining = 0
            truncated = True
    return CappedRead(b"".join(kept), truncated)


# --- the lifeline watchdog ----------------------------------------------------------------

# A tiny stdlib-only program, run as ``python -I -S -c``. Its stdin is the lifeline: gatectl
# holds the write end, so EOF means gatectl is gone (a pipe, not PR_SET_PDEATHSIG, which kills
# only the leader and is not available everywhere).
#
# Protocol, one line each:  ``G <pgid> <start>``  registers the check's process group and the
# leader's start time (``-`` when unknown);  ``done``  says the group was swept and the leader
# is about to be reaped, after which the group id may be reused: the watchdog then exits
# WITHOUT signalling anything, whatever happens to the pipe next.
#
# EOF without ``done`` is gatectl dying: the registered group gets SIGKILL, unless its id now
# belongs to a different process (the leader's start time changed, so the pid was reused).
# Nonsense group ids (0, 1, negatives, its own group) are never signalled. It ignores the
# terminal signals, so only SIGKILL stops it; gatectl starts it in its own process group.
WATCHDOG_SOURCE = r"""
import os, signal, sys

for _sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGQUIT):
    signal.signal(_sig, signal.SIG_IGN)


def start_of(pid):
    try:
        with open("/proc/%d/stat" % pid, "rb") as f:
            data = f.read()
        return data[data.rindex(b")") + 2:].split()[19].decode()
    except (OSError, ValueError, IndexError):
        return None


def parse(line):
    parts = line.split(b" ")
    if len(parts) != 3 or parts[0] != b"G" or not parts[1].isdigit():
        return None
    start = parts[2]
    if start != b"-" and not start.isdigit():
        return None
    pgid = int(parts[1])
    if pgid < 2 or pgid >= 2 ** 31 or pgid == os.getpgrp():
        return None
    return pgid, (None if start == b"-" else start.decode())


def kill(target):
    pgid, start = target
    if start is not None:
        now = start_of(pgid)
        if now is not None and now != start:
            return
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (OSError, OverflowError):
        pass


buf = b""
target = None
while True:
    try:
        chunk = os.read(0, 4096)
    except OSError:
        chunk = b""
    if not chunk:
        break
    buf += chunk
    while True:
        i = buf.find(b"\n")
        if i < 0:
            break
        line, buf = buf[:i], buf[i + 1:]
        if line == b"done":
            os._exit(0)
        parsed = parse(line)
        if parsed is not None:
            target = parsed
    if len(buf) > 256:
        buf = b""
if target is not None:
    kill(target)
os._exit(0)
"""


def watchdog_spec() -> ChildSpec:
    """The watchdog child: own process group, stdin a pipe (the lifeline), an empty environment."""
    return ChildSpec(
        (sys.executable, "-I", "-S", "-c", WATCHDOG_SOURCE),
        stdin=Stdio.PIPE,
        stdout=Stdio.DEVNULL,
        stderr=Stdio.DEVNULL,
        own_group=True,
        cwd="/",
        env={},
    )
