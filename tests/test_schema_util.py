"""The schema helper must be able to fail, or the audit and log schema tests prove nothing."""

from __future__ import annotations

import pytest

from tests.schema_util import errors


def test_rejects_a_bad_log_record() -> None:
    assert errors("log", {"ts": "yesterday", "level": "info", "event": "warning"})


def test_rejects_unknown_log_event() -> None:
    assert errors("log", {"ts": "2026-01-01T00:00:00.000000Z", "level": "info", "event": "x"})


def test_accepts_a_good_log_record() -> None:
    assert not errors(
        "log", {"ts": "2026-01-01T00:00:00.000000Z", "level": "info", "event": "cron"}
    )


def test_cross_file_refs_resolve_in_audit() -> None:
    bad = {
        "ts": "2026-01-01T00:00:00.000000Z",
        "actor": "robot:x",
        "stdin_tty": False,
        "decision_id": "gd-aaaaaaaaaaaa",
        "action": "outcome",
        "target": "gd-aaaaaaaaaaaa",
        "inputs": {
            "signal": "human",
            "outcome": "agree",
            "decision_ids": [],
            "actor_source": "flag",
        },
        "result": {
            "outcome": "agree",
            "signal": "human",
            "effective_outcome": "agree",
            "miss": None,
        },
    }
    assert errors("audit", bad)
    bad["actor"] = "human:x"
    assert not errors("audit", bad)


@pytest.mark.parametrize("target", ["Bad@*", "p@host", "state.db"])
def test_decision_target_pattern_enforced(target: str) -> None:
    record = {
        "ts": "2026-01-01T00:00:00.000000Z",
        "actor": "auto:x",
        "stdin_tty": False,
        "decision_id": "gd-aaaaaaaaaaaa",
        "action": "decision",
        "target": target,
        "inputs": {
            "policy": "p",
            "scope": "*",
            "input_sha256": "0" * 64,
            "fingerprint": "sha256:" + "0" * 64,
            "decision_ids": [],
            "actor_source": "default",
        },
        "result": {
            "decision": "allow",
            "reason": "all_passed",
            "state": "shadow",
            "shadow": True,
            "enforced": False,
        },
    }
    assert errors("audit", record)
