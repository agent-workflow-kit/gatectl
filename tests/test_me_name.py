"""A configured ``me.name`` is sanitized at actor derivation and never makes a command fail."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import pytest

from gatectl import cli, setcmd
from gatectl.config import load_for_command
from gatectl.errors import ConfigInvalidError
from tests.command_util import CANARY, config_file, isolate, rule, run
from tests.set_util import HUMAN, audit_lines, do_set, make_config, row

HOSTILE = f"{CANARY}\x1b]0;x\x07‮\x00\n" + "y" * 500
BAD_NAMES = ["a b", "", HOSTILE, "é" * 100, "x" * 65, "\x1b[2J", "‮⁦"]


@pytest.fixture(autouse=True)
def state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def _tty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)


def _config(tmp_path: Path, name: Any) -> str:
    return make_config(tmp_path, me={"name": name})


@pytest.mark.parametrize("name", BAD_NAMES)
def test_set_enforced_with_a_bad_me_name_and_an_explicit_human_actor_succeeds(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path, name: str
) -> None:
    code, doc, err = do_set(capsys, _config(tmp_path, name), "p", "enforced", *HUMAN)
    assert code == 0, (doc, err)
    stored = row(state_dir, "p", "*")
    assert stored is not None and stored.set_by == "human:ann"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("a b", "human:a_b"),
        ("x" * 65, "human:" + "x" * 64),
        ("é" * 100, "human:" + "_" * 64),
        ("", "human:user"),
    ],
)
def test_the_default_actor_is_the_sanitized_me_name(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    expected: str,
) -> None:
    _tty(monkeypatch)
    monkeypatch.setattr(setcmd, "_os_user_name", lambda: "osuser")
    code, _, err = do_set(capsys, _config(tmp_path, name), "p", "enforced")
    assert code == 0, err
    assert audit_lines(state_dir)[0]["actor"] == expected


def test_an_empty_me_name_is_user_not_the_os_user_name(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _tty(monkeypatch)
    monkeypatch.setattr(setcmd, "_os_user_name", lambda: "osuser")
    do_set(capsys, _config(tmp_path, ""), "p", "shadow")
    assert audit_lines(state_dir)[0]["actor"] == "human:user"


def test_a_null_me_name_still_uses_the_os_user_name(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _tty(monkeypatch)
    monkeypatch.setattr(setcmd, "_os_user_name", lambda: "osuser")
    do_set(capsys, _config(tmp_path, None), "p", "shadow")
    assert audit_lines(state_dir)[0]["actor"] == "human:osuser"


def test_a_hostile_me_name_never_reaches_audit_or_output_unsanitized(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _tty(monkeypatch)
    code, out, err = run(
        capsys, ["set", "p", "enforced", "--config", _config(tmp_path, HOSTILE), "--json"]
    )
    assert code == 0, err
    audit_text = (state_dir / "audit.jsonl").read_text(encoding="ascii")
    log_path = state_dir / "log.jsonl"
    log_text = log_path.read_text(encoding="ascii") if log_path.exists() else ""
    for text in (out, err, audit_text, log_text):
        assert "\x1b" not in text and "‮" not in text and "\x00" not in text
    actor = audit_lines(state_dir)[0]["actor"]
    assert actor.startswith("human:CANARY-7f3a9c__")
    assert len(actor) == len("human:") + 64
    stored = row(state_dir, "p", "*")
    assert stored is not None and stored.set_by == actor


STRICT = [
    ("check", argparse.Namespace(policy="p")),
    ("reconcile", argparse.Namespace()),
    ("prune", argparse.Namespace()),
    ("cron", argparse.Namespace(action="install")),
    ("set", argparse.Namespace(policy="p", state="enforced", all=False)),
]


@pytest.mark.parametrize("name", BAD_NAMES)
@pytest.mark.parametrize(("command", "args"), STRICT)
def test_every_strict_command_loads_with_a_bad_me_name(
    tmp_path: Path, command: str, args: argparse.Namespace, name: str
) -> None:
    # check, reconcile, prune and cron are not implemented yet: what they will call at load is
    # load_for_command, which must not raise for any me.name string.
    path = config_file(tmp_path, {"me": {"name": name}, "policies": {"p": {"checks": [rule()]}}})
    loaded = load_for_command(command, args, path, environ={})
    assert loaded.shared.me.name == name


@pytest.mark.parametrize("bad", [5, True, ["a"], {"a": 1}, "x" * 1025])
def test_a_non_string_or_huge_me_name_is_still_a_config_error(tmp_path: Path, bad: Any) -> None:
    path = config_file(tmp_path, {"me": {"name": bad}, "policies": {"p": {"checks": [rule()]}}})
    with pytest.raises(ConfigInvalidError) as info:
        load_for_command("reconcile", argparse.Namespace(), path, environ={})
    assert info.value.exit_code == 2
    assert "me.name" in info.value.message
