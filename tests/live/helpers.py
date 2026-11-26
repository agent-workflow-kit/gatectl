"""Helpers shared by the live agent tests (no tests here)."""

from __future__ import annotations

import os
import sqlite3
from typing import Any

from tests import live_util
from tests.live_util import Live, observe

CLEAR_POLICY = (
    "Allow the step when the input field `action` is `read-docs` and `target` is "
    "`docs/readme.md`. Deny it when `action` is `delete` or `deploy`. Otherwise escalate."
)
CLEAR = {"action": "read-docs", "target": "docs/readme.md"}


def entry(doc: dict[str, Any]) -> dict[str, Any]:
    checks = doc.get("checks") or [{}]
    return checks[0]


def describe(done: live_util.Proc, doc: dict[str, Any]) -> dict[str, Any]:
    e = entry(doc)
    return {
        "exit": done.code,
        "seconds": round(done.seconds, 1),
        "verdict": e.get("verdict"),
        "reason": e.get("reason"),
        "detail": e.get("detail"),
        "stderr": done.err[-400:],
    }


def leftovers(live: Live) -> list[Any]:
    """Sessions this test's state directory still lists (live or not), via the real ``list``."""
    done = live.session("list", "--label", "owner=gatectl", "--json")
    body = done.json() if done.code == 0 else {}
    return body.get("sessions", body) if isinstance(body, dict) else body


def slot_rows(live: Live) -> int:
    db = live.state_dir / "state.db"
    if not db.exists():
        return 0
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return int(con.execute("SELECT count(*) FROM agent_slots").fetchone()[0])
    except sqlite3.Error:
        return 0
    finally:
        con.close()


def tmp_left(live: Live) -> list[str]:
    folder = live.state_dir / "tmp"
    return sorted(os.listdir(folder)) if folder.is_dir() else []


def one_run(
    live: Live, name: str, instruction: str, obj: Any, **kw: Any
) -> tuple[dict[str, Any], live_util.Proc]:
    live.spend(1, name)
    config = live.write_config(instruction, **kw)
    done, doc = live.check(config, live.write_input(obj))
    observe(name, **describe(done, doc))
    assert doc, f"{name}: no JSON on stdout (exit {done.code}): {done.err[-600:]}"
    return doc, done
