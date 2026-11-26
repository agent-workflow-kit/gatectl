"""``outcome``: the automatic drop to shadow and the cases where it is skipped."""

from __future__ import annotations

from pathlib import Path

import pytest

from gatectl import store
from tests import schema_util
from tests.command_util import isolate, rule
from tests.history_util import put_decision
from tests.outcome_util import (
    AUTO,
    HUMAN,
    ID,
    OTHER,
    REPO,
    audit_lines,
    log_lines,
    make_config,
    outcome,
    stored,
)
from tests.set_util import row, rows, seed


@pytest.fixture(autouse=True)
def state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


@pytest.fixture
def config(tmp_path: Path) -> str:
    return make_config(tmp_path)


def enforced_decision(
    state_dir: Path, scope: str = "*", *, rev: int | None, decision: str = "allow", **kw: object
) -> None:
    put_decision(
        state_dir,
        ID,
        state="enforced",
        scope=scope,
        repo=None if scope == "*" else scope,
        state_rev=rev,
        decision=decision,
        reason="all_passed" if decision == "allow" else "check_error",
        **kw,  # type: ignore[arg-type]
    )


def test_a_disagree_on_an_enforced_allow_drops_the_scope_to_shadow(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    star = seed(state_dir, "p", "*", "enforced")
    enforced_decision(state_dir, rev=star.rev)
    code, doc, _ = outcome(capsys, config, ID, "disagree", *AUTO)
    assert code == 0 and doc["miss"] == "unsafe"
    assert doc["state_change"] == {"policy": "p", "scope": "*", "state": "shadow", "cause": "miss"}
    schema_util.assert_valid("cli/outcome", doc)
    after = row(state_dir, "p", "*")
    assert after is not None and after.state == "shadow" and after.cause == "miss"
    assert after.set_by == "auto:bot" and after.rev > star.rev
    lines = audit_lines(state_dir)
    assert [line["action"] for line in lines] == ["outcome", "state_change"]
    change = lines[1]
    schema_util.assert_valid("audit", change)
    assert change["target"] == "p@*"
    assert change["result"] == {
        "previous_state": "enforced",
        "state": "shadow",
        "cause": "miss",
        "reason": None,
        "triggered_by": ID,
    }
    assert change["actor"] == "auto:bot"
    assert log_lines(state_dir) == []


def test_the_drop_row_keeps_other_repos_and_only_the_decisions_scope(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    seed(state_dir, "p", "*", "enforced")
    mine = seed(state_dir, "p", REPO, "enforced")
    other = seed(state_dir, "p", OTHER, "enforced")
    enforced_decision(state_dir, REPO, rev=mine.rev)
    _, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert doc["state_change"]["scope"] == REPO
    found = rows(state_dir, "p")
    assert found[REPO].state == "shadow"
    assert found["*"].state == "enforced" and found[OTHER].state == "enforced"
    assert found[OTHER].rev == other.rev


def test_a_repo_decision_that_got_its_state_from_the_star_row_drops_the_repo_scope(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    star = seed(state_dir, "p", "*", "enforced")
    enforced_decision(state_dir, REPO, rev=star.rev)
    _, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert doc["state_change"] == {
        "policy": "p",
        "scope": REPO,
        "state": "shadow",
        "cause": "miss",
    }
    found = rows(state_dir, "p")
    assert found[REPO].state == "shadow" and found["*"].state == "enforced"


def test_a_star_decision_drops_the_star_row_and_so_every_inheriting_repo(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    star = seed(state_dir, "p", "*", "enforced")
    enforced_decision(state_dir, rev=star.rev)
    outcome(capsys, config, ID, "disagree", *HUMAN)
    s = store.open_store(state_dir, create=False)
    assert s is not None
    with s:
        assert s.effective("p", REPO, "shadow").state == "shadow"


def test_a_re_enforcement_since_the_decision_means_no_drop(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    old = seed(state_dir, "p", "*", "enforced")
    new = seed(state_dir, "p", "*", "enforced")
    assert new.rev > old.rev
    enforced_decision(state_dir, rev=old.rev)
    code, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert code == 0 and doc["miss"] == "unsafe" and doc["state_change"] is None
    assert row(state_dir, "p", "*") == new
    assert [line["action"] for line in audit_lines(state_dir)] == ["outcome"]
    events = log_lines(state_dir)
    assert [e["event"] for e in events] == ["drop_skipped"]
    assert events[0]["decision_id"] == ID and events[0]["policy"] == "p"
    schema_util.assert_valid("log", events[0])


def test_a_repo_row_written_since_the_decision_means_no_drop(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    star = seed(state_dir, "p", "*", "enforced")
    enforced_decision(state_dir, REPO, rev=star.rev)
    seed(state_dir, "p", REPO, "enforced")
    _, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert doc["state_change"] is None
    assert rows(state_dir, "p")[REPO].state == "enforced"
    assert [e["event"] for e in log_lines(state_dir)] == ["drop_skipped"]


def test_a_drop_already_done_is_not_done_twice(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    star = seed(state_dir, "p", "*", "enforced")
    enforced_decision(state_dir, rev=star.rev)
    put_decision(
        state_dir,
        "gd-bbbbbbbbbbbb",
        state="enforced",
        state_rev=star.rev,
        object_id="43",
    )
    outcome(capsys, config, ID, "disagree", *HUMAN)
    after = row(state_dir, "p", "*")
    _, doc, _ = outcome(capsys, config, "gd-bbbbbbbbbbbb", "disagree", *HUMAN)
    assert doc["miss"] == "unsafe" and doc["state_change"] is None
    assert row(state_dir, "p", "*") == after
    assert [e["event"] for e in log_lines(state_dir)] == ["drop_skipped"]


def test_a_policy_no_longer_configured_counts_but_changes_no_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path, {"other": {"checks": [rule()]}})
    star = seed(state_dir, "p", "*", "enforced")
    enforced_decision(state_dir, rev=star.rev)
    code, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert code == 0 and doc["miss"] == "unsafe" and doc["state_change"] is None
    assert row(state_dir, "p", "*") == star
    assert len(stored(state_dir)) == 1
    assert [e["event"] for e in log_lines(state_dir)] == ["drop_skipped"]


def test_a_missing_state_row_for_a_decision_that_had_one_means_no_drop(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    enforced_decision(state_dir, rev=7)  # the row is gone: not the effective row any more
    _, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert doc["state_change"] is None
    assert row(state_dir, "p", "*") is None


def test_a_decision_with_no_row_a_row_now_exists_means_no_drop(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    seed(state_dir, "p", "*", "enforced")
    enforced_decision(state_dir, rev=None)
    _, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert doc["state_change"] is None


def test_a_shadow_decision_miss_only_counts(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    star = seed(state_dir, "p", "*", "enforced")
    put_decision(state_dir, ID, state="shadow", state_rev=star.rev)
    _, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert doc["miss"] == "unsafe" and doc["state_change"] is None
    assert row(state_dir, "p", "*") == star
    assert log_lines(state_dir) == []


@pytest.mark.parametrize("verdict", ["deny", "escalate"])
def test_an_over_strict_miss_never_drops(
    verdict: str, capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    star = seed(state_dir, "p", "*", "enforced")
    enforced_decision(state_dir, rev=star.rev, decision=verdict)
    _, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert doc["miss"] == "over_strict" and doc["state_change"] is None
    assert row(state_dir, "p", "*") == star
    assert log_lines(state_dir) == []


def test_only_the_outcome_that_changes_it_to_disagree_drops(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    star = seed(state_dir, "p", "*", "enforced")
    enforced_decision(state_dir, rev=star.rev)
    outcome(capsys, config, ID, "agree", *AUTO)  # never counts
    assert row(state_dir, "p", "*") == star
    outcome(capsys, config, ID, "agree", *HUMAN)
    assert row(state_dir, "p", "*") == star
    _, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)  # agree -> disagree
    assert doc["state_change"] is not None


def test_a_failed_audit_rolls_the_drop_back_too(
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gatectl import audit

    star = seed(state_dir, "p", "*", "enforced")
    enforced_decision(state_dir, rev=star.rev)

    def broken(*args: object, **kwargs: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(audit, "append_audit_many", broken)
    code, _, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert code == 1
    assert row(state_dir, "p", "*") == star and stored(state_dir) == []
