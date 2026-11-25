"""Two ``set`` calls at once: the transaction serializes them and each audit line is consistent."""

from __future__ import annotations

import multiprocessing
import os
from multiprocessing.synchronize import Event
from pathlib import Path
from typing import Any

import pytest

from tests.set_util import audit_lines, isolate, make_config, rows


@pytest.fixture(autouse=True)
def state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def _worker(argv: list[str], go: Event, out: Any) -> None:
    from gatectl.cli import main

    go.wait(30)
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    out.put(main(argv))


def race(argvs: list[list[str]]) -> list[int]:
    ctx = multiprocessing.get_context("fork")
    go = ctx.Event()
    out = ctx.Queue()
    procs = [ctx.Process(target=_worker, args=(a, go, out)) for a in argvs]
    for p in procs:
        p.start()
    go.set()
    codes = [out.get(timeout=60) for _ in procs]
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    return codes


def test_two_identical_sets_change_the_state_once(tmp_path: Path, state_dir: Path) -> None:
    config = make_config(tmp_path)
    argv = ["set", "p", "shadow", "--config", config, "--json"]
    assert race([argv, argv, argv, argv]) == [0, 0, 0, 0]
    assert len(audit_lines(state_dir)) == 1
    assert rows(state_dir, "p")["*"].state == "shadow"


def test_opposing_sets_leave_a_consistent_chain(tmp_path: Path, state_dir: Path) -> None:
    config = make_config(tmp_path)
    shadow = ["set", "p", "shadow", "--config", config, "--json"]
    off = ["set", "p", "off", "--all", "--config", config, "--json"]
    assert race([shadow, off]) == [0, 0]
    lines = audit_lines(state_dir)
    assert 1 <= len(lines) <= 2
    # each line's previous_state is the state the line before it left (the first: the initial off)
    expected = "off"
    for line in lines:
        assert line["result"]["previous_state"] == expected
        expected = line["result"]["state"]
    assert rows(state_dir, "p")["*"].state == expected


def test_a_refused_enforce_racing_a_kill_switch_changes_nothing_but_the_switch(
    tmp_path: Path, state_dir: Path
) -> None:
    config = make_config(tmp_path)
    enforce = ["set", "p", "enforced", "--config", config, "--json"]  # no human: refused
    off = ["set", "p", "off", "--all", "--config", config, "--json"]
    assert sorted(race([enforce, off])) == [0, 20]
    assert rows(state_dir, "p")["*"].state == "off"
    assert [ln["result"]["state"] for ln in audit_lines(state_dir)] == ["off"]
