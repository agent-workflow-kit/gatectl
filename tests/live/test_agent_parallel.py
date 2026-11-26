"""Live parallel agent checks (issue #27): the slot mechanism with real runs. BILLED."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from typing import Any

import pytest

from tests import live_util
from tests.live.helpers import CLEAR_POLICY, entry, leftovers, slot_rows, tmp_left
from tests.live_util import Live, observe

pytestmark = pytest.mark.live


class SlotSampler(threading.Thread):
    """Samples the slot rows of ``state.db`` (read only) until stopped; keeps the maximum."""

    def __init__(self, live: Live) -> None:
        super().__init__(daemon=True)
        self.live = live
        self.stop_flag = threading.Event()
        self.peak = 0

    def run(self) -> None:
        while not self.stop_flag.is_set():
            self.peak = max(self.peak, slot_rows(self.live))
            time.sleep(0.2)


def launch_all(live: Live, count: int, config: str) -> list[dict[str, Any]]:
    procs = []
    for n in range(count):
        path = live.write_input(
            {"action": "read-docs", "target": "docs/readme.md", "n": n}, f"in{n}.json"
        )
        procs.append(
            subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "gatectl",
                    "check",
                    "p",
                    "--config",
                    config,
                    "--input",
                    path,
                ],
                env=live.env,
                cwd="/",
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )  # fmt: skip
        )
    docs: list[dict[str, Any]] = []
    try:
        for child in procs:
            out, err = child.communicate(timeout=420)
            try:
                docs.append(json.loads(out))
            except ValueError:
                docs.append({"error": err.decode("utf-8", "replace")[-400:]})
    finally:
        for child in procs:
            if child.poll() is None:
                live_util.stop_group(child)
    return docs


def test_three_parallel_runs_finish_without_interference_within_max_parallel(live: Live) -> None:
    live.spend(3, "three parallel runs")
    config = live.write_config(CLEAR_POLICY, agent={"max_parallel": 3})
    sampler = SlotSampler(live)
    sampler.start()
    began = time.monotonic()
    try:
        docs = launch_all(live, 3, config)
    finally:
        sampler.stop_flag.set()
        sampler.join(5)
    seen = [(entry(d).get("verdict"), entry(d).get("reason")) for d in docs]
    observe("three parallel", results=seen, peak_slots=sampler.peak,
            seconds=round(time.monotonic() - began, 1))  # fmt: skip
    assert seen == [("allow", None)] * 3, f"parallel runs interfered: {seen}"
    assert sampler.peak <= 3
    assert leftovers(live) == [] and tmp_left(live) == [] and slot_rows(live) == 0


def test_max_parallel_one_serializes_two_runs(live: Live) -> None:
    """With ``agent.max_parallel: 1`` two simultaneous checks never hold two slots: the second
    waits (or is ``busy``); both end with a usable answer and nothing is left."""
    live.spend(2, "max_parallel 1")
    config = live.write_config(CLEAR_POLICY, agent={"max_parallel": 1}, timeout="400s")
    sampler = SlotSampler(live)
    sampler.start()
    try:
        docs = launch_all(live, 2, config)
    finally:
        sampler.stop_flag.set()
        sampler.join(5)
    seen = [(entry(d).get("verdict"), entry(d).get("reason")) for d in docs]
    observe("max_parallel 1", results=seen, peak_slots=sampler.peak)
    assert sampler.peak <= 1, f"max_parallel=1 held {sampler.peak} slots at once"
    assert all(v in ("allow", "escalate") for v, _ in seen)
    assert all(r in (None, "busy", "budget_exhausted") for _, r in seen), seen
    assert leftovers(live) == [] and slot_rows(live) == 0
