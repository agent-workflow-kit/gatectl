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
from tests.test_set_race import race


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


FINGERPRINT = "sha256:" + "9d" * 32


def test_the_drop_row_keeps_the_decisions_fingerprint(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    star = seed(state_dir, "p", "*", "enforced")
    enforced_decision(state_dir, rev=star.rev, fingerprint=FINGERPRINT)
    assert star.fingerprint != FINGERPRINT
    _, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert doc["state_change"] is not None
    after = row(state_dir, "p", "*")
    assert after is not None and after.fingerprint == FINGERPRINT


def test_the_drop_audit_line_carries_the_sanitized_cut_reason_and_the_outcome_line_none(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    star = seed(state_dir, "p", "*", "enforced")
    enforced_decision(state_dir, rev=star.rev)
    path = tmp_path / "why.txt"
    path.write_bytes(b"bad\x1b[31m " + b"x" * 5000)
    outcome(capsys, config, ID, "disagree", "--reason-file", str(path), *HUMAN)
    reason = stored(state_dir)[0]["reason"]
    assert len(reason) == 1024 and reason.endswith("…") and "\x1b" not in reason
    outcome_line, change = audit_lines(state_dir)
    assert change["result"]["reason"] == reason
    schema_util.assert_valid("audit", change)
    assert "reason" not in outcome_line["result"] and "reason" not in outcome_line["inputs"]


def test_a_stale_enforcement_is_skipped_even_when_the_clock_stepped_back(
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gatectl import outcomecmd

    first = seed(state_dir, "p", "*", "enforced")
    enforced_decision(state_dir, rev=first.rev)
    seed(state_dir, "p", "*", "enforced")
    seed(state_dir, "p", "*", "enforced")
    again = seed(state_dir, "p", "*", "enforced")  # re-enforced since the decision
    assert again.rev > first.rev
    monkeypatch.setattr(outcomecmd, "now_ts", lambda: "2001-01-01T00:00:00.000000Z")
    code, doc, _ = outcome(capsys, config, ID, "disagree", *AUTO)
    assert code == 0 and doc["miss"] == "unsafe" and doc["state_change"] is None
    assert row(state_dir, "p", "*") == again
    assert [line["action"] for line in audit_lines(state_dir)] == ["outcome"]
    assert [e["event"] for e in log_lines(state_dir)] == ["drop_skipped"]


@pytest.mark.parametrize("row_exists", [False, True])
def test_a_decision_without_a_state_rev_never_drops_and_logs_the_skip(
    row_exists: bool, capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    star = seed(state_dir, "p", "*", "enforced") if row_exists else None
    enforced_decision(state_dir, rev=None)  # an indeterminate scope: no row gave its state
    code, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert code == 0 and doc["miss"] == "unsafe" and doc["state_change"] is None
    assert row(state_dir, "p", "*") == star
    assert [e["event"] for e in log_lines(state_dir)] == ["drop_skipped"]


def test_a_star_row_re_enforced_after_a_repo_decision_is_skipped_and_logged(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    star = seed(state_dir, "p", "*", "enforced")
    enforced_decision(state_dir, REPO, rev=star.rev)
    newer = seed(state_dir, "p", "*", "enforced")
    _, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert doc["state_change"] is None
    assert row(state_dir, "p", "*") == newer and row(state_dir, "p", REPO) is None
    assert [e["event"] for e in log_lines(state_dir)] == ["drop_skipped"]


# --- concurrency ------------------------------------------------------------------------------

OTHER_ID = "gd-bbbbbbbbbbbb"


def _argv(config: str, ref: str) -> list[str]:
    return ["outcome", ref, "disagree", "--config", config, "--json", *HUMAN]


def test_two_concurrent_drops_of_one_enforcement_change_the_state_once(
    config: str, state_dir: Path
) -> None:
    star = seed(state_dir, "p", "*", "enforced")
    enforced_decision(state_dir, rev=star.rev)
    put_decision(state_dir, OTHER_ID, state="enforced", state_rev=star.rev, object_id="43")
    assert race([_argv(config, ID), _argv(config, OTHER_ID)]) == [0, 0]
    changes = [x for x in audit_lines(state_dir) if x["action"] == "state_change"]
    assert len(changes) == 1 and changes[0]["result"]["cause"] == "miss"
    found = rows(state_dir, "p")
    assert list(found) == ["*"] and found["*"].state == "shadow"
    assert found["*"].rev == star.rev + 1
    assert len([x for x in audit_lines(state_dir) if x["action"] == "outcome"]) == 2
    assert [e["event"] for e in log_lines(state_dir)] == ["drop_skipped"]


def test_a_drop_racing_a_re_enforcement_leaves_a_consistent_chain(
    config: str, state_dir: Path
) -> None:
    star = seed(state_dir, "p", "*", "enforced")  # a stale fingerprint: set re-enforces it
    enforced_decision(state_dir, rev=star.rev)
    reenforce = ["set", "p", "enforced", "--config", config, "--json", *HUMAN]
    assert race([_argv(config, ID), reenforce]) == [0, 0]
    changes = [x for x in audit_lines(state_dir) if x["action"] == "state_change"]
    drops = [x for x in changes if x["result"]["cause"] == "miss"]
    final = rows(state_dir, "p")["*"]
    assert len(drops) <= 1
    # Every row write is one audit line, in commit order: the last line is the final state.
    assert final.rev == star.rev + len(changes)
    assert changes[-1]["result"]["state"] == final.state
    events = [e["event"] for e in log_lines(state_dir)]
    assert events == ([] if drops else ["drop_skipped"])
    if drops:
        assert [c["result"]["state"] for c in changes] in (["shadow"], ["shadow", "enforced"])
    else:
        assert final.state == "enforced" and len(changes) == 1
