"""Gateway: the single boundary for subprocess calls.

Every child process gatectl starts goes through this module, so tests can substitute a fake
(``tests/fake_gateway.py``) by dependency injection and no other module imports ``subprocess``
(``tests/test_import_boundary.py`` enforces that). Commands are argv tuples, never a shell
string, and untrusted text travels on stdin or in files, never in argv or the environment.

Descriptor rules for every child (interface.md, Hooks): stdin, stdout and stderr are each stated
explicitly as ``/dev/null`` or a private pipe (there is no way to say "inherit"), and
``close_fds`` is always on, so a child never holds a descriptor of the caller.

This module only starts children and reads their output with a cap; the selector loop, group
kill sequence and lifeline watchdog are built on it by the script runner.
"""

from __future__ import annotations

import enum
import os
import subprocess
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


@dataclass(frozen=True, kw_only=True)
class ChildSpec:
    """Everything needed to start one child; invalid specs are refused at construction."""

    argv: tuple[str, ...]
    stdin: Stdio
    stdout: Stdio
    stderr: Stdio
    own_group: bool = False
    cwd: str | None = None
    # None: the environment of gatectl. Read-only, and kept out of repr (it may hold secrets).
    env: Mapping[str, str] | None = field(default=None, repr=False)

    def __reduce__(self) -> tuple[Any, ...]:
        # env is a MappingProxyType (unpicklable); rebuild through __init__ with a plain dict.
        env = None if self.env is None else dict(self.env)
        return (
            _rebuild_spec,
            (self.argv, self.stdin, self.stdout, self.stderr, self.own_group, self.cwd, env),
        )

    def __hash__(self) -> int:
        env = None if self.env is None else tuple(sorted(self.env.items()))
        streams = (self.stdin, self.stdout, self.stderr)
        return hash((self.argv, streams, self.own_group, self.cwd, env))

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
            if not isinstance(value, Stdio):
                raise ValueError(f"{name} must be Stdio.DEVNULL or Stdio.PIPE, got {value!r}")
        if not isinstance(own_group, bool):
            raise ValueError(f"own_group must be a bool, got {own_group!r}")
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
) -> ChildSpec:
    return ChildSpec(
        argv, stdin=stdin, stdout=stdout, stderr=stderr, own_group=own_group, cwd=cwd, env=env
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
        popen = subprocess.Popen(
            list(spec.argv),
            stdin=_STDIO[spec.stdin],
            stdout=_STDIO[spec.stdout],
            stderr=_STDIO[spec.stderr],
            close_fds=True,
            shell=False,
            cwd=spec.cwd,
            env=None if spec.env is None else dict(spec.env),
            process_group=0 if spec.own_group else None,
        )
        return _Child(popen, spec.own_group)


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
