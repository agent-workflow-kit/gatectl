"""Fixtures of the live agent tests. They only run for tests marked ``live`` (deselected by
default) and skip with a message that names every missing prerequisite."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests import live_util


@pytest.fixture(scope="session")
def budget() -> live_util.RunBudget:
    return live_util.RunBudget.from_environ(live_util.REAL_ENV)


@pytest.fixture(autouse=True)
def require_prerequisites() -> None:
    missing = live_util.missing_prerequisites(live_util.REAL_ENV)
    if missing:
        pytest.skip("live tests need: " + "; ".join(missing))


@pytest.fixture
def live(tmp_path: Path, budget: live_util.RunBudget) -> live_util.Live:
    return live_util.Live(tmp_path, budget)
