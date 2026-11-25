"""Driver for the fake ``claude-session`` in ``tests/fakebin/``: runs it, reads its call log."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

FAKE = Path(__file__).resolve().parent / "fakebin" / "claude-session"
NONCE = "0123456789abcdef0123456789abcdef"
DECISION_ID = "gd-aaaaaaaaaaaa"


@dataclass
class Result:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def json(self) -> Any:
        return json.loads(self.stdout)


@dataclass
class FakeSession:
    """One private state directory, call log and prompt file for a test."""

    root: Path
    scenario: str = "valid"
    extra_env: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.state = self.root / "state"
        self.log = self.root / "calls.jsonl"
        self.prompt = self.root / "prompt.md"
        self.input_file = self.root / "input.json"
        self.root.mkdir(parents=True, exist_ok=True)
        self.prompt.write_text(
            f"Artifact: verdict.json\nThe nonce of this run is {NONCE}.\nInstruction text.\n",
            encoding="utf-8",
        )
        self.input_file.write_text("{}\n", encoding="utf-8")

    def env(self, **overrides: Any) -> dict[str, str]:
        base = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ["HOME"],  # the autouse fixture points it at a private directory
            "FAKE_CS_STATE": str(self.state),
            "FAKE_CS_LOG": str(self.log),
            "FAKE_CS_SCENARIO": self.scenario,
            **self.extra_env,
        }
        base.update(overrides)
        return base

    def command(self, *args: str) -> list[str]:
        return [sys.executable, str(FAKE), *args]

    def run(self, *args: str, timeout: float = 30, **env: Any) -> Result:
        argv = self.command(*args)
        done = subprocess.run(  # noqa: S603 - the fake is a test fixture
            argv, capture_output=True, text=True, timeout=timeout, env=self.env(**env)
        )
        return Result(list(args), done.returncode, done.stdout, done.stderr)

    def popen(self, *args: str, **env: Any) -> subprocess.Popen[str]:
        return subprocess.Popen(  # noqa: S603
            self.command(*args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=self.env(**env),
            start_new_session=True,
        )

    def start_args(self, *extra: str) -> list[str]:
        """The ``start`` argv of interface.md, Agent checks, Run sequence step 1."""
        return [
            "start",
            "--kind",
            "gate-check",
            "--mode",
            "headless",
            "--skill",
            "gatectl:gate-check",
            "--prompt-file",
            str(self.prompt),
            "--input-file",
            str(self.input_file),
            "--plugin-dir",
            str(self.root),
            "--timeout",
            "60s",
            "--label",
            "owner=gatectl",
            "--label",
            "policy=reviewer",
            "--label",
            f"decision={DECISION_ID}",
            "--label",
            "state=tag",
            "--actor",
            "auto:gatectl",
            "--decision-id",
            DECISION_ID,
            "--permission-profile",
            "review",
            "--sandbox",
            "required",
            "--setting-sources",
            "",
            "--env-allowlist-only",
            "",
            *extra,
            "--json",
        ]

    def start(self, *extra: str, **env: Any) -> Result:
        return self.run(*self.start_args(*extra), **env)

    def exec_args(self, started: Mapping[str, Any], *extra: str) -> list[str]:
        return [
            "exec",
            "--session-id",
            started["csession_id"],
            "--run",
            str(started["run"]),
            *extra,
            "--json",
        ]

    def calls(self) -> list[dict[str, Any]]:
        """Every recorded call, with its exit code when it had one."""
        if not self.log.exists():
            return []
        records = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        exits = {r["pid"]: r["code"] for r in records if r["event"] == "exit"}
        calls = [r for r in records if r["event"] == "call"]
        for call in calls:
            call["code"] = exits.get(call["pid"])
        return calls

    def argvs(self) -> list[list[str]]:
        return [c["argv"] for c in self.calls()]
