"""The check result goldens are the real command output, byte for byte."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from gatectl import audit, engine, ids
from tests import golden
from tests.check_util import do_set, isolate, write_input
from tests.command_util import config_file, run
from tests.set_util import STALE, seed

REPO = "github.com/org/repo"
FIXED_ID = "gd-4k2m7q5x3a2b"
RULE = {
    "name": "ci-green",
    "type": "rule",
    "when": [{"path": "ci.state", "op": "ne", "value": "passing"}],
    "then": "deny",
}


@pytest.fixture(autouse=True)
def fixed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(ids, "new_decision_id", lambda *a, **k: FIXED_ID)
    real = engine.Env
    monkeypatch.setattr(engine, "Env", lambda: real(monotonic=lambda: 0.0))  # duration_ms is 0
    return isolate(monkeypatch, tmp_path)


def config(tmp_path: Path, **policy: Any) -> str:
    body = {"checks": [RULE], **policy}
    return config_file(tmp_path, {"policies": {"auto-merge": body}})


def check(capsys: pytest.CaptureFixture[str], conf: str, src: str, *extra: str) -> str:
    code, out, _ = run(capsys, ["check", "auto-merge", "--config", conf, "--input", src, *extra])
    assert code in (0, 11, 13)
    return out


def verify(name: str, out: str) -> None:
    if os.environ.get("REGEN_CHECK_GOLDEN") == "1":  # maintainer aid: rewrite the file
        (golden.GOLDEN_DIR / f"{name}.json").write_text(out)
    golden.assert_output(name, out)


PASSING = {"ci": {"state": "passing"}, "repo": REPO}
FAILING = {"ci": {"state": "red"}, "repo": REPO}


def test_shadow_allow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    verify("check-shadow-allow", check(capsys, config(tmp_path), write_input(tmp_path, PASSING)))


def test_enforced_deny_with_a_changed_definition(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], fixed: Path
) -> None:
    conf = config(tmp_path)
    seed(fixed, "auto-merge", "*", "enforced", fingerprint_=STALE)
    out = check(capsys, conf, write_input(tmp_path, FAILING))
    verify("check-enforced-deny", out)


def test_not_applicable(tmp_path: Path, capsys: pytest.CaptureFixture[str], fixed: Path) -> None:
    conf = config(tmp_path, applies_when=[{"path": "kind", "op": "eq", "value": "pr"}])
    do_set(capsys, conf, "auto-merge", "enforced")
    out = check(capsys, conf, write_input(tmp_path, {"kind": "issue"}))
    verify("check-not-applicable", out)


def test_off(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    verify(
        "check-off", check(capsys, config(tmp_path, state="off"), write_input(tmp_path, PASSING))
    )


def test_shadow_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(*_: Any, **__: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(audit, "append_audit", fail)
    verify("check-shadow-error", check(capsys, config(tmp_path), write_input(tmp_path, FAILING)))
