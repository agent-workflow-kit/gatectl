"""``check``: applies_when in every state, its guard idioms, ``off``, the lock retry, drift.

Most of the state-dependent paths landed with the engine; these are the acceptance tests of the
issue that owns them. Already covered elsewhere (kept there, not duplicated):

- the six state pairs and a set to ``off`` during a check: test_check_failures.py
  ``test_a_set_during_the_check_decides_the_recorded_state_the_flags_and_the_exit``;
- a shadow failure (exit 0, no decision_id) and an enforced failure (exit 1):
  test_check_failures.py ``test_a_shadow_failure_exits_0_...``, ``test_an_enforced_failure_...``;
- a busy database held past the reserve: ``test_a_busy_database_retries_once_then_fails...``;
- the retry inside ``Store.transact``: test_store_audit.py (lock wait and the single retry).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gatectl import store as store_mod
from tests.check_util import (
    audit_lines,
    decisions,
    do_check,
    do_set,
    isolate,
    log_lines,
    rows,
    write_input,
)
from tests.command_util import config_file

DENY = {
    "name": "r",
    "type": "rule",
    "when": [{"path": "ci", "op": "ne", "value": "ok"}],
    "then": "deny",
}
PR = {"path": "kind", "op": "eq", "value": "pr"}
NOT_NULL = {"path": "kind", "op": "ne", "value": None}


@pytest.fixture
def sdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def cfg(tmp_path: Path, **policy: Any) -> str:
    body = {"checks": [DENY], **policy}
    return config_file(tmp_path, {"policies": {"p": body}})


def inp(tmp_path: Path, content: Any) -> str:
    return write_input(tmp_path, content)


# --- a false applies_when: every state, nothing recorded or logged ---------------------------


@pytest.mark.parametrize("state", ["shadow", "enforced"])
def test_a_false_applies_when_is_not_applicable_in_shadow_and_enforced_and_leaves_no_trace(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, state: str
) -> None:
    config = cfg(tmp_path, applies_when=[PR])
    do_set(capsys, config, "p", state)
    before = (audit_lines(sdir), log_lines(sdir))
    code, doc, err = do_check(capsys, config, "p", "--input", inp(tmp_path, {"kind": "x"}))
    assert (code, err) == (0, "")
    assert (doc["decision"], doc["reason"], doc["state"]) == ("allow", "not_applicable", state)
    assert (doc["shadow"], doc["enforced"], doc["checks"]) == (False, False, [])
    assert "decision_id" not in doc and "input_sha256" not in doc
    assert decisions(sdir) == []
    assert (audit_lines(sdir), log_lines(sdir)) == before


def test_applies_when_is_not_evaluated_in_state_off(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, applies_when=[PR], state="off")
    code, doc, _ = do_check(capsys, config, "p", "--input", inp(tmp_path, {"kind": "x"}))
    assert code == 0 and doc["decision"] is None and doc["reason"] is None
    assert doc["state"] == "off" and doc["checks"] == []
    assert [e["event"] for e in log_lines(sdir)] == ["check_off"]


def test_a_false_applies_when_beats_an_input_the_declaration_would_refuse(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, applies_when=[PR], input={"require": ["needed"]})
    do_set(capsys, config, "p", "enforced")
    code, doc, _ = do_check(capsys, config, "p", "--input", inp(tmp_path, {"kind": "x"}))
    assert code == 0 and doc["reason"] == "not_applicable"
    code, doc, _ = do_check(
        capsys, config, "p", "--input", inp(tmp_path, {"kind": "pr", "ci": "bad"})
    )
    assert code == 13 and doc["reason"] == "input_invalid"


def test_not_applicable_never_looks_like_an_authorization(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    """A caller that authorizes only on ``enforced: true`` and ``decision: allow`` refuses it."""
    config = cfg(tmp_path, applies_when=[PR])
    for state in ("shadow", "enforced"):
        do_set(capsys, config, "p", state)
        _, doc, _ = do_check(capsys, config, "p", "--input", inp(tmp_path, {"kind": "x"}))
        assert not (doc["enforced"] and doc["decision"] == "allow")
        assert doc["shadow"] is False


# --- the guard idioms --------------------------------------------------------------------------


def test_a_null_on_a_nullable_path_errors_and_counts_as_applicable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, applies_when=[PR])
    do_set(capsys, config, "p", "enforced")
    code, doc, _ = do_check(
        capsys, config, "p", "--input", inp(tmp_path, {"kind": None, "ci": "bad"})
    )
    assert code == 11 and doc["reason"] == "check_denied" and "decision_id" in doc


def test_a_not_null_condition_first_skips_the_gate_for_a_null(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, applies_when=[NOT_NULL, PR])
    do_set(capsys, config, "p", "enforced")
    code, doc, _ = do_check(
        capsys, config, "p", "--input", inp(tmp_path, {"kind": None, "ci": "bad"})
    )
    assert code == 0 and doc["reason"] == "not_applicable"
    # a non-null value goes on to the second condition
    code, doc, _ = do_check(
        capsys, config, "p", "--input", inp(tmp_path, {"kind": "pr", "ci": "bad"})
    )
    assert code == 11 and doc["reason"] == "check_denied"
    code, doc, _ = do_check(capsys, config, "p", "--input", inp(tmp_path, {"kind": "x"}))
    assert code == 0 and doc["reason"] == "not_applicable"


def test_without_the_guard_first_the_error_stops_the_list_and_the_policy_applies(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, applies_when=[PR, NOT_NULL])
    do_set(capsys, config, "p", "enforced")
    code, doc, _ = do_check(
        capsys, config, "p", "--input", inp(tmp_path, {"kind": None, "ci": "bad"})
    )
    assert code == 11 and doc["reason"] == "check_denied"


# --- off ---------------------------------------------------------------------------------------


def test_off_runs_nothing_and_writes_only_a_check_off_event(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from gatectl import engine

    def boom(*_: Any, **__: Any) -> Any:
        raise AssertionError("a check ran under off")

    monkeypatch.setattr(engine, "_run_checks", boom)
    monkeypatch.setattr(engine, "_record", boom)
    config = cfg(tmp_path)
    do_set(capsys, config, "p", "off")
    before = audit_lines(sdir)  # the state_change line of the set
    code, doc, err = do_check(capsys, config, "p", "--input", inp(tmp_path, {"ci": "bad"}))
    assert (code, err, doc["decision"]) == (0, "", None)
    assert decisions(sdir) == [] and audit_lines(sdir) == before
    assert [e["event"] for e in log_lines(sdir)][-1:] == ["check_off"]
    assert rows(sdir, "SELECT COUNT(*) FROM decisions") == [(0,)]


# --- the lock timeout in step 8 ----------------------------------------------------------------


def _busy_writes(monkeypatch: pytest.MonkeyPatch, busy: int) -> list[int]:
    """Make the first ``busy`` calls of ``Store.write`` fail as a lock timeout."""
    calls: list[int] = []
    real = store_mod.Store.write

    def write(self: Any) -> Any:
        calls.append(1)
        if len(calls) <= busy:
            raise store_mod.StoreBusyError("busy")
        return real(self)

    monkeypatch.setattr(store_mod.Store, "write", write)
    return calls


def test_one_lock_timeout_is_retried_and_the_decision_is_recorded(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = cfg(tmp_path)
    do_set(capsys, config, "p", "enforced")
    calls = _busy_writes(monkeypatch, 1)
    code, doc, _ = do_check(capsys, config, "p", "--input", inp(tmp_path, {"ci": "ok"}))
    assert code == 0 and doc.get("error") is None and doc["decision"] == "allow"
    assert len(calls) == 2 and len(decisions(sdir)) == 1


@pytest.mark.parametrize(("state", "code"), [("shadow", 0), ("enforced", 1)])
def test_two_lock_timeouts_fail_after_exactly_one_retry(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
    code: int,
) -> None:
    config = cfg(tmp_path)
    do_set(capsys, config, "p", state)
    calls = _busy_writes(monkeypatch, 99)
    got, doc, err = do_check(capsys, config, "p", "--input", inp(tmp_path, {"ci": "bad"}))
    assert got == code and len(calls) == 2 and decisions(sdir) == []
    assert doc["error"] is not None
    if state == "shadow":
        assert "decision_id" not in doc and (doc["decision"], doc["shadow"]) == ("deny", True)
        assert [e["event"] for e in log_lines(sdir)][-1:] == ["shadow_failure"]
    else:
        assert err == "gatectl: internal p\n"


# --- definition_changed ------------------------------------------------------------------------


def test_definition_changed_is_a_warning_and_never_changes_the_stored_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    do_set(capsys, config, "p", "enforced")
    query = "SELECT state, rev, fingerprint FROM policy_state WHERE policy = 'p'"
    stored = rows(sdir, query)
    changed = cfg(tmp_path / "x", checks=[{**DENY, "then": "escalate"}])
    _, doc, _ = do_check(capsys, changed, "p", "--input", inp(tmp_path, {"ci": "ok"}))
    assert doc["warnings"] == ["definition_changed"] and doc["state"] == "enforced"
    assert rows(sdir, query) == stored
