"""Shared helpers for the command tests: an isolated environment and a config-writing runner."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from gatectl.cli import main
from tests.config_util import write

CANARY = "CANARY-7f3a9c"


def isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point HOME and the XDG directories at a private directory; return the state directory."""
    for name in list(os.environ):
        if name.startswith("GATECTL_"):
            monkeypatch.delenv(name)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / "state"))
    return home / "state" / "gatectl"


def config_file(tmp_path: Path, data: Mapping[str, Any]) -> str:
    return str(write(tmp_path / "cfg" / "config.yaml", dict(data)))


def run(capsys: pytest.CaptureFixture[str], argv: list[str]) -> tuple[int, str, str]:
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def payload(out: str) -> dict[str, Any]:
    assert out.endswith("\n") and out.count("\n") == 1
    document = json.loads(out)
    assert isinstance(document, dict)
    return document


def rule(name: str = "r", then: str = "deny", **extra: Any) -> dict[str, Any]:
    return {
        "name": name,
        "type": "rule",
        "when": [{"path": "ci", "op": "eq", "value": "green"}],
        "then": then,
        **extra,
    }


def script(name: str = "s", argv: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    return {"name": name, "type": "script", "argv": argv or ["/nonexistent/gatectl-tool"], **extra}


def agent(name: str = "a", **extra: Any) -> dict[str, Any]:
    return {"name": name, "type": "agent", "instruction": "Be careful.", **extra}
