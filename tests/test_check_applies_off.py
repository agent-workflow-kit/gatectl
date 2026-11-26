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

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from gatectl import store as store_mod
from tests.check_util import (
    REPO,
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


@pytest.mark.parametrize(
    "content",
    [{"kind": "pr"}, {"kind": "x", "needed": 1, "extra": 2}, [1, 2], "text"],
    ids=["missing-required", "object", "array", "string"],
)
def test_off_ignores_the_input_declaration_and_an_input_that_violates_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, content: Any
) -> None:
    config = cfg(tmp_path, applies_when=[PR], input={"require": ["needed"]}, state="off")
    code, doc, err = do_check(capsys, config, "p", "--input", inp(tmp_path, content))
    assert (code, err) == (0, "")
    assert (doc["decision"], doc["reason"], doc["state"], doc["checks"]) == (None, None, "off", [])
    assert "decision_id" not in doc
    assert decisions(sdir) == [] and audit_lines(sdir) == []
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


@pytest.mark.parametrize(
    ("condition", "content"),
    [
        (PR, {"ci": "bad"}),  # the path is missing
        (PR, {"kind": None, "ci": "bad"}),  # null against a non-null eq
        ({"path": "n", "op": "gt", "value": 1}, {"n": "x", "ci": "bad"}),  # type error
        (
            {"path": "s", "op": "glob", "value": "a*"},
            {"s": "a" * 5000, "ci": "bad"},  # subject over the size limit
        ),
    ],
    ids=["missing-path", "null", "type-error", "too-large"],
)
def test_an_error_in_applies_when_counts_as_applicable_and_goes_on_to_the_checks(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    condition: dict[str, Any],
    content: Any,
) -> None:
    config = cfg(tmp_path, applies_when=[condition])
    do_set(capsys, config, "p", "enforced")
    code, doc, _ = do_check(capsys, config, "p", "--input", inp(tmp_path, content))
    assert code == 11 and doc["reason"] == "check_denied" and "decision_id" in doc
    assert len(decisions(sdir)) == 1


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


def _decision_lines(sdir: Path) -> list[dict[str, Any]]:
    return [e for e in audit_lines(sdir) if e["action"] == "decision"]


def test_one_lock_timeout_is_retried_and_the_decision_is_recorded(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = cfg(tmp_path)
    do_set(capsys, config, "p", "enforced")
    calls = _busy_writes(monkeypatch, 1)
    code, doc, _ = do_check(capsys, config, "p", "--input", inp(tmp_path, {"ci": "ok"}))
    assert code == 0 and doc.get("error") is None and doc["decision"] == "allow"
    assert len(calls) == 2 and len(decisions(sdir)) == 1


def test_a_real_lock_held_for_one_timeout_is_retried_and_recorded_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A real blocker holds the write lock; the first attempt times out, the blocker is released
    at that moment (no sleep), and the second attempt really takes the lock."""
    config = config_file(
        tmp_path, {"defaults": {"record_reserve": "100ms"}, "policies": {"p": {"checks": [DENY]}}}
    )
    do_set(capsys, config, "p", "enforced")
    blocker = sqlite3.connect(sdir / "state.db", isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    real = store_mod.Store.write
    attempts: list[bool] = []  # True when the attempt got the lock

    @contextmanager
    def write(self: Any) -> Iterator[Any]:
        got = False
        try:
            with real(self) as opened:
                got = True
                attempts.append(True)
                yield opened
        except store_mod.StoreBusyError:
            if not got:
                attempts.append(False)
                blocker.execute("COMMIT")  # release for the retry
            raise

    monkeypatch.setattr(store_mod.Store, "write", write)
    try:
        code, doc, err = do_check(capsys, config, "p", "--input", inp(tmp_path, {"ci": "ok"}))
    finally:
        blocker.close()
    assert attempts == [False, True]
    assert (code, err) == (0, "") and doc["decision"] == "allow" and doc.get("error") is None
    assert len(decisions(sdir)) == 1
    [line] = _decision_lines(sdir)
    assert line["decision_id"] == doc["decision_id"]


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
    before = audit_lines(sdir)
    calls = _busy_writes(monkeypatch, 99)
    got, doc, err = do_check(capsys, config, "p", "--input", inp(tmp_path, {"ci": "bad"}))
    assert got == code and len(calls) == 2 and decisions(sdir) == []
    assert doc["error"] is not None
    assert audit_lines(sdir) == before  # no audit line for a decision that was not recorded
    if state == "shadow":
        assert "decision_id" not in doc and (doc["decision"], doc["shadow"]) == ("deny", True)
        assert [e["event"] for e in log_lines(sdir)][-1:] == ["shadow_failure"]
        assert err == "gatectl: warning shadow_failure p@*\n"
    else:
        assert err == "gatectl: internal p\n"


def test_a_shadow_failure_is_silent_on_stderr_under_quiet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = cfg(tmp_path)
    do_set(capsys, config, "p", "shadow")
    _busy_writes(monkeypatch, 99)
    code, doc, err = do_check(
        capsys, config, "p", "--input", inp(tmp_path, {"ci": "bad"}), "--quiet"
    )
    assert (code, err) == (0, "")
    assert doc["error"] is not None and "decision_id" not in doc
    assert [e["event"] for e in log_lines(sdir)][-1:] == ["shadow_failure"]


def test_a_busy_error_after_the_lock_was_taken_is_not_retried(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The audit line is written, then the body fails busy: a retry would append a second line."""
    config = cfg(tmp_path)
    do_set(capsys, config, "p", "enforced")
    real = store_mod.Store.append_audit
    calls: list[int] = []

    def append_then_busy(self: Any, record: Any) -> None:
        calls.append(1)
        real(self, record)
        raise store_mod.StoreBusyError("busy")

    monkeypatch.setattr(store_mod.Store, "append_audit", append_then_busy)
    code, doc, err = do_check(capsys, config, "p", "--input", inp(tmp_path, {"ci": "ok"}))
    assert code == 1 and err == "gatectl: internal p\n" and doc["error"] is not None
    assert calls == [1]  # the body ran once
    assert len(_decision_lines(sdir)) == 1  # no second line for the same decision
    assert decisions(sdir) == []  # the row never outlives the failed transaction


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


def test_definition_changed_still_warns_when_a_false_applies_when_makes_it_not_applicable(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, applies_when=[PR])
    do_set(capsys, config, "p", "enforced")
    query = "SELECT state, rev, fingerprint FROM policy_state WHERE policy = 'p'"
    stored = rows(sdir, query)
    changed = cfg(tmp_path / "x", applies_when=[PR], checks=[{**DENY, "then": "escalate"}])
    code, doc, _ = do_check(capsys, changed, "p", "--input", inp(tmp_path, {"kind": "x"}))
    assert code == 0 and doc["reason"] == "not_applicable" and doc["state"] == "enforced"
    assert doc["warnings"] == ["definition_changed"]
    assert rows(sdir, query) == stored and decisions(sdir) == []


# --- a repo override supplies applies_when -----------------------------------------------------


def _override_cfg(tmp_path: Path, *, override: dict[str, Any], **policy: Any) -> str:
    body = {"checks": [DENY], **policy}
    data = {"policies": {"p": body}, "repos": {REPO: {"policies": {"p": override}}}}
    return config_file(tmp_path, data)


def test_a_repo_override_with_a_false_applies_when_is_not_applicable_for_that_repo_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    other = {"path": "kind", "op": "eq", "value": "never"}
    config = _override_cfg(tmp_path, override={"applies_when": [other]})
    do_set(capsys, config, "p", "enforced")
    do_set(capsys, config, "p", "enforced", "--repo", REPO)
    content = inp(tmp_path, {"kind": "pr", "ci": "bad"})
    code, doc, _ = do_check(capsys, config, "p", "--repo", REPO, "--input", content)
    assert code == 0 and doc["reason"] == "not_applicable" and doc["scope"] == REPO
    code, doc, _ = do_check(capsys, config, "p", "--input", content)  # global: no gate at all
    assert code == 11 and doc["reason"] == "check_denied"


def test_a_repo_override_replaces_the_global_applies_when_whole(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    """A key an override sets replaces the global key entirely (interface: Per-repo overrides)."""
    config = _override_cfg(tmp_path, override={"applies_when": [NOT_NULL]}, applies_when=[PR])
    do_set(capsys, config, "p", "enforced")
    do_set(capsys, config, "p", "enforced", "--repo", REPO)
    content = inp(tmp_path, {"kind": "x", "ci": "bad"})
    code, doc, _ = do_check(capsys, config, "p", "--input", content)  # global gate: false
    assert code == 0 and doc["reason"] == "not_applicable"
    code, doc, _ = do_check(capsys, config, "p", "--repo", REPO, "--input", content)
    assert code == 11 and doc["reason"] == "check_denied"
