"""A fake ``Gateway`` for tests: records every spec it is given and returns scripted children.

Tests pass it wherever code takes a ``Gateway``; nothing patches ``subprocess``. The spec is
validated by ``ChildSpec`` itself, so the fake cannot be handed a child the real gateway would
refuse.
"""

from __future__ import annotations

import io
import signal
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import IO

from gatectl.gateway import Child, ChildSpec, Stdio


@dataclass
class FakeResult:
    """What a scripted child produces."""

    stdout: bytes = b""
    stderr: bytes = b""
    returncode: int = 0
    running: bool = False  # True: poll() is None until a signal arrives or wait() is called


class FakeChild:
    def __init__(self, spec: ChildSpec, result: FakeResult, pid: int) -> None:
        self.spec = spec
        self.pid = pid
        self.own_group = spec.own_group
        self.stdin: IO[bytes] | None = io.BytesIO() if spec.stdin is Stdio.PIPE else None
        self.stdout: IO[bytes] | None = (
            io.BytesIO(result.stdout) if spec.stdout is Stdio.PIPE else None
        )
        self.stderr: IO[bytes] | None = (
            io.BytesIO(result.stderr) if spec.stderr is Stdio.PIPE else None
        )
        self.signals: list[int] = []
        self._returncode: int | None = None if result.running else result.returncode
        self._final = result.returncode

    def poll(self) -> int | None:
        return self._returncode

    def wait(self, timeout: float | None = None) -> int:
        if self._returncode is None:
            if self.signals:
                self._returncode = -self.signals[-1]
            else:
                raise TimeoutError(f"fake child {self.pid} still running")
        return self._returncode

    def signal_group(self, sig: int) -> None:
        if not self.own_group:
            raise ValueError("child is not in its own process group")
        if self._returncode is None:
            self.signals.append(sig)
            if sig == signal.SIGKILL:
                self._returncode = -sig


Script = Callable[[ChildSpec], FakeResult]


@dataclass
class FakeGateway:
    """Records ``calls`` (the specs, in order) and ``children``; ``script`` decides each result."""

    script: Script = lambda spec: FakeResult()
    calls: list[ChildSpec] = field(default_factory=list)
    children: list[FakeChild] = field(default_factory=list)
    _next_pid: int = 1000

    def start(self, spec: ChildSpec) -> Child:
        self.calls.append(spec)
        child = FakeChild(spec, self.script(spec), self._next_pid)
        self._next_pid += 1
        self.children.append(child)
        return child
