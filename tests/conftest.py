from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from tests.proc_util import Tracker


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point HOME and the XDG dirs at a private directory so no test reads the user's config."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(home / ".cache"))
    return home


@pytest.fixture
def tracker() -> Iterator[Tracker]:
    """Records every process a test starts; kills exactly those on teardown, fails on a leak."""
    t = Tracker()
    yield t
    leaked = t.teardown()
    assert not leaked, f"processes outlived the test (killed by their recorded handle): {leaked}"
