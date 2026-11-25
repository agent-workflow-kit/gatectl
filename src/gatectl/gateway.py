"""Gateway: the single boundary for subprocess (and, later, HTTP) calls.

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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import IO, Protocol

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
    env: Mapping[str, str] | None = None  # None: the environment of gatectl

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
        if env is not None:
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
        object.__setattr__(self, "env", dict(env) if env is not None else None)


class Child(Protocol):
    """A started child. Streams are set only for the ``Stdio.PIPE`` ends the spec asked for."""

    pid: int
    own_group: bool
    stdin: IO[bytes] | None
    stdout: IO[bytes] | None
    stderr: IO[bytes] | None

    def poll(self) -> int | None:
        """The exit status if the child ended (reaping it), else ``None``."""
        ...

    def wait(self, timeout: float | None = None) -> int:
        """Wait for the child; raise ``TimeoutError`` after ``timeout`` seconds."""
        ...

    def signal_group(self, sig: int) -> None:
        """Signal the child's own process group by the pid captured at launch.

        Raises ``ValueError`` for a child that was not started with ``own_group`` (the caller's
        group is never signaled). Does nothing once the child was reaped, because the group id
        may have been reused by then.
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

    def signal_group(self, sig: int) -> None:
        if not self.own_group:
            raise ValueError("child was not started in its own process group")
        if self._popen.returncode is not None:
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
    ``truncated`` says whether any were. Blocks until end of file.
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
