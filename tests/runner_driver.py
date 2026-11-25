"""A stand-in for a gatectl process that runs one check and kills itself at a chosen phase.

Usage: ``python runner_driver.py <dir> <phase> <leader>`` where ``phase`` is one of the runner's
phases (``started``, ``swept``, ``done_sent``, ``reaped``) or ``never``, and ``leader`` is
``sleep`` (a leader and a grandchild that both sleep) or ``straggler`` (the leader exits at once
and leaves a sleeping grandchild behind). The pids are written to ``<dir>``.

At ``swept`` and ``done_sent`` a decoy is first put into the check's own process group (the
leader is still an unreaped zombie there, so the group still exists): a watchdog that was told
``done`` must leave it alone, one that was not must kill it. Then the driver sends itself
SIGKILL, so the real runner never gets to clean up. Test-only; it is not part of gatectl.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from gatectl.gateway import SubprocessGateway
from gatectl.runner import RunSpec, run_process

directory = Path(sys.argv[1])
kill_phase = sys.argv[2]
leader = sys.argv[3]

CHECK = """
import os, sys, time
d = sys.argv[1]
if os.fork() == 0:
    open(d + '/gc', 'w').write(str(os.getpid()))
    time.sleep(60)
    os._exit(0)
open(d + '/leader', 'w').write(str(os.getpid()))
if sys.argv[2] == 'sleep':
    time.sleep(60)
"""


def write(name: str, value: int) -> None:
    (directory / name).write_text(str(value))


def on_phase(phase: str, check_pid: int, watchdog_pid: int) -> None:
    write("check.pid", check_pid)
    write("watchdog.pid", watchdog_pid)
    write(f"phase.{phase}", 1)
    if phase != kill_phase:
        return
    if phase == "started":
        # Let the check fork its grandchild first, so the test has a pid to watch die.
        give_up = time.monotonic() + 10
        while time.monotonic() < give_up and not all(
            (directory / n).exists() for n in ("gc", "leader")
        ):
            time.sleep(0.01)
    if phase in ("swept", "done_sent"):
        decoy = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)", f"decoy{directory}"],
            process_group=check_pid,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        write("decoy", decoy.pid)
    os.kill(os.getpid(), signal.SIGKILL)


run_process(
    SubprocessGateway(),
    RunSpec(
        argv=(sys.executable, "-c", CHECK, str(directory), leader),
        env={},
        cwd="/",
        timeout=30.0,
        kill_grace=0.5,
        drain_grace=0.5,
    ),
    on_phase=on_phase,
)
write("finished", 1)
