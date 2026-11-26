"""Fixtures of the live agent tests. They only run for tests marked ``live`` (deselected by
default) and skip with a message that names every missing prerequisite."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests import live_util


@pytest.fixture(scope="session")
def budget() -> live_util.RunBudget:
    warning = live_util.real_home_warning(live_util.REAL_ENV)
    if warning:
        print(f"\n[live] WARNING: {warning}")
    found = live_util._resolve(live_util.REAL_ENV)
    if found:
        version = live_util.session_version(found[0], live_util.REAL_ENV)
        print(f"\n[live] claude-session: {found[0]} ({version}); pinned schemas: 0.45.2")
    return live_util.RunBudget.from_environ(live_util.REAL_ENV)


@pytest.fixture(autouse=True)
def require_prerequisites() -> None:
    missing = live_util.missing_prerequisites(live_util.REAL_ENV)
    if missing:
        pytest.skip("live tests need: " + "; ".join(missing))


@pytest.fixture
def live(tmp_path: Path, budget: live_util.RunBudget) -> Iterator[live_util.Live]:
    world = live_util.Live(tmp_path, budget)
    yield world
    world.sweep()  # stop then forget what the test left; prints LEFTOVER lines for the rest


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Say loudly that skipped live tests prove nothing, and fail a run where none passed."""
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is None:
        return

    def count(kind: str) -> int:
        return sum(
            1
            for rep in reporter.stats.get(kind, [])
            if "tests/live/" in str(getattr(rep, "nodeid", ""))
            and rep.when in (None, "call", "setup")
        )

    note, force = live_util.live_summary(
        passed=count("passed"), skipped=count("skipped"), failed=count("failed") + count("error")
    )
    if note:
        print(f"\n[live] {note}")
    if force and session.exitstatus == 0:
        session.exitstatus = 1
