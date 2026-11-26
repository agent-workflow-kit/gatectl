"""The detached hook supervisor: ``python -I -m gatectl.supervisor`` (started by ``hooks``).

It runs in its own session with ``/dev/null`` for stdout and stderr and a private pipe on stdin
that carries one job (``hooks.parse_job``). It takes the job, points descriptor 0 at ``/dev/null``
too, takes a concurrency slot, and runs the event's hooks one after the other (``hooks.run_hooks``):
each in its own process group with the hook's timeout, the TERM-then-KILL sequence on that group
only, and a lifeline watchdog that kills the group if this process is killed.

SIGTERM ends the running hook's group, skips the rest and removes the hook's directory; SIGHUP and
SIGINT are ignored (no terminal reaches a session of its own). SIGKILL cannot be handled: the
watchdog kills the hook's group and the directory is left for ``reconcile``. The exit status is
always 0 for a job that was understood: a hook's failure is a log event, never an error here.
"""

from __future__ import annotations

import os
import signal
import sys
from pathlib import Path

from gatectl import hooks
from gatectl.gateway import SubprocessGateway


def _devnull_stdin() -> None:
    try:
        fd = os.open(os.devnull, os.O_RDONLY)
        try:
            os.dup2(fd, 0)
        finally:
            if fd != 0:
                os.close(fd)
    except OSError:
        pass


def main() -> int:
    terminated = [False]

    def on_term(signum: int, frame: object) -> None:
        terminated[0] = True

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    def cancel() -> bool:
        return terminated[0]

    try:
        frame = hooks.read_job(0, cancel=cancel)
    except hooks.JobInvalid:
        return 0  # nothing trustworthy to run, and no state directory to log to
    finally:
        _devnull_stdin()
    try:
        ev, state_dir = hooks.parse_job(frame)
    except hooks.JobInvalid:
        return 0
    try:
        slot = hooks.acquire_slot(state_dir)
    except OSError:
        hooks.log_event(state_dir, ev, "hook_skipped", "warn", {"reason": "no_slot"})
        return 0
    if slot is None:
        hooks.log_event(state_dir, ev, "hook_skipped", "warn", {"reason": "busy"})
        return 0
    try:
        hooks.run_hooks(
            SubprocessGateway(),
            ev,
            state_dir=Path(state_dir),
            environ=os.environ,
            cancel=cancel,
        )
    except Exception:  # noqa: S110  (a supervisor bug must never be a loud failure; the hook's group is already ended)
        pass
    finally:
        os.close(slot)
    return 0


if __name__ == "__main__":
    sys.exit(main())
