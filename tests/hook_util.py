"""Helpers for the detached-hook process tests: run a real ``gatectl check`` with hooks, find the
processes it left (by their recorded pids and parentage, read-only) and wait, bounded."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from tests.command_util import config_file
from tests.proc_util import Tracker, read_pid
from tests.test_check_process import RULE, env_for, state_dir

__all__ = ["RULE", "state_dir"]


def hook(cmd: str, *, timeout: str = "30s", async_: bool = False) -> dict[str, Any]:
    return {"cmd": cmd, "timeout": timeout, "async": async_}


def hook_config(tmp_path: Path, *hooks_: dict[str, Any], **policy: Any) -> str:
    return config_file(
        tmp_path,
        {
            "policies": {"p": {"checks": [RULE], **policy}},
            "hooks": {"post-decision": list(hooks_)},
        },
    )


class Caller:
    """A caller of ``gatectl check``: reads stdout and stderr to EOF, timing it."""

    def __init__(self, tmp_path: Path, config: str, stdin: bytes = b'{"ci": "ok"}') -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "gatectl", "check", "p", "--config", config],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env_for(tmp_path),
        )
        assert self.proc.stdin and self.proc.stdout and self.proc.stderr
        self.pipe_links = {
            f"pipe:[{os.fstat(s.fileno()).st_ino}]"
            for s in (self.proc.stdin, self.proc.stdout, self.proc.stderr)
        }
        self.proc.stdin.write(stdin)
        self.proc.stdin.close()

    def read_to_eof(self) -> tuple[bytes, bytes, float]:
        """(stdout, stderr, seconds from the first output byte to EOF on both)."""
        assert self.proc.stdout and self.proc.stderr
        first = self.proc.stdout.read(1)
        t0 = time.monotonic()
        rest = self.proc.stdout.read()
        err = self.proc.stderr.read()
        return first + rest, err, time.monotonic() - t0

    def close(self) -> None:
        for s in (self.proc.stdout, self.proc.stderr):
            if s is not None:
                s.close()
        if self.proc.poll() is None:  # only our own direct child, by its Popen handle
            self.proc.kill()
        self.proc.wait(timeout=10)


def ppid_of(pid: int) -> int:
    data = Path(f"/proc/{pid}/stat").read_bytes()
    return int(data[data.rindex(b")") + 2 :].split()[1])


def children_of(pid: int) -> list[int]:
    """Direct children of ``pid`` (a read-only scan of /proc)."""
    found = []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                if ppid_of(int(entry)) == pid:
                    found.append(int(entry))
            except (OSError, ValueError, IndexError):
                continue
    return found


def fd_links(pid: int) -> set[str]:
    links = set()
    for name in os.listdir(f"/proc/{pid}/fd"):
        try:
            links.add(os.readlink(f"/proc/{pid}/fd/{name}"))
        except OSError:
            continue
    return links


class Hooked:
    """The processes of one running hook: the hook, its supervisor and the watchdog."""

    def __init__(self, tracker: Tracker, hook_pid: int) -> None:
        self.hook = hook_pid
        tracker.track_pid(hook_pid, cmdline_contains=b"sleep")
        self.supervisor = ppid_of(hook_pid)
        tracker.track_pid(self.supervisor, cmdline_contains=b"gatectl.supervisor")
        self.watchdog = [p for p in children_of(self.supervisor) if p != hook_pid]
        for pid in self.watchdog:
            tracker.track_pid(pid)
        for pid in (self.hook, self.supervisor, *self.watchdog):
            tracker.expect_survivor(pid)
        self.tracker = tracker

    def all(self) -> list[int]:
        return [self.hook, self.supervisor, *self.watchdog]


def wait_exists(path: Path, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError(f"{path} never appeared")
        time.sleep(0.02)


def read_json_file(path: Path, timeout: float = 10.0) -> Any:
    deadline = time.monotonic() + timeout
    while True:
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            if time.monotonic() >= deadline:
                raise AssertionError(f"{path} never held JSON") from None
            time.sleep(0.02)


def hooked(tracker: Tracker, pid_file: Path) -> Hooked:
    return Hooked(tracker, read_pid(pid_file))


def log_events(tmp_path: Path) -> list[dict[str, Any]]:
    path = state_dir(tmp_path) / "log.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def wait_for_event(tmp_path: Path, name: str, timeout: float = 10.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        for rec in log_events(tmp_path):
            if rec["event"] == name:
                return rec
        if time.monotonic() >= deadline:
            raise AssertionError(f"no {name} event: {log_events(tmp_path)}")
        time.sleep(0.02)


def hook_dirs(tmp_path: Path) -> list[Path]:
    tmp = state_dir(tmp_path) / "tmp"
    return sorted(tmp.glob("hook-*")) if tmp.exists() else []
