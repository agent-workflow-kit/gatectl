"""``gatectl stats``: records, cases, the bound and the recommendation (interface.md)."""

from __future__ import annotations

import math
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from gatectl import inputs, stats
from gatectl.cli import main
from gatectl.config_models import InputDecl
from tests import golden, schema_util
from tests.command_util import config_file, isolate, rule
from tests.history_util import (
    FP,
    OTHER,
    REPO,
    T0,
    call,
    check_entry,
    did,
    put_decision,
    put_outcome,
    ts,
)
from tests.set_util import current_fingerprint, seed

HUMAN = {"actor": "human:ann", "signal": "human", "kind": "human"}
AUTO = {"actor": "auto:ci", "signal": "revert", "kind": "automatic"}
MARK = "a" * 64


@pytest.fixture(autouse=True)
def state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


@pytest.fixture
def config(tmp_path: Path) -> str:
    return config_file(tmp_path, {"policies": {"p": {"checks": [rule()]}}})


@pytest.fixture
def fp(config: str) -> str:
    return current_fingerprint(config, "p")


def stat(
    capsys: pytest.CaptureFixture[str], config: str, *extra: str
) -> tuple[int, dict[str, Any], str]:
    code, doc, err = call(capsys, "stats", "--config", config, *extra)
    if code == 0:
        schema_util.assert_valid("cli/stats", doc)
    return code, doc, err


def only(doc: dict[str, Any]) -> dict[str, Any]:
    assert len(doc["records"]) == 1, doc["records"]
    return doc["records"][0]


def allows(
    state_dir: Path,
    count: int,
    fp: str,
    *,
    outcome: str | None = "agree",
    start: int = 1,
    scope: str = REPO,
    keyed: bool = True,
) -> None:
    """``count`` allow decisions, each its own case, each with a human ``outcome``."""
    for i in range(start, start + count):
        put_decision(
            state_dir,
            did(i),
            when=ts(i % 3000),
            scope=scope,
            repo=None if scope == "*" else scope,
            fingerprint=fp,
            case_key=f"{i:064x}" if keyed else None,
        )
        if outcome is not None:
            put_outcome(state_dir, did(i), outcome, **HUMAN)  # type: ignore[arg-type]


def test_no_database_prints_no_records_and_creates_nothing(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    code, doc, err = stat(capsys, config)
    assert (code, doc, err) == (0, {"since": None, "records": []}, "")
    assert not state_dir.exists()


def test_counts_misses_signals_and_actor_kinds(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    def put(n: int, decision: str) -> None:
        put_decision(
            state_dir,
            did(n),
            when=ts(n),
            decision=decision,
            scope=REPO,
            repo=REPO,
            fingerprint=fp,
            case_key=f"{n:064x}",
        )

    put(1, "allow")
    put_outcome(state_dir, did(1), "agree", **HUMAN)  # type: ignore[arg-type]
    put(2, "allow")
    put_outcome(state_dir, did(2), "disagree", **AUTO)  # type: ignore[arg-type]
    put(3, "deny")
    put_outcome(state_dir, did(3), "disagree", **HUMAN)  # type: ignore[arg-type]
    put(4, "escalate")
    put(5, "allow")
    put(6, "allow")  # an automatic agree never counts: still pending
    put_outcome(state_dir, did(6), "agree", actor="auto:bot", signal="auto", kind="automatic")
    put(7, "allow")
    put_outcome(
        state_dir, did(7), "agree", actor="auto:unknown", signal="auto", kind="unattributed"
    )
    code, doc, _ = stat(capsys, config)
    r = only(doc)
    assert code == 0
    assert (r["policy"], r["repo"], r["fingerprint"]) == ("p", REPO, fp)
    assert r["decisions"] == {"allow": 5, "deny": 1, "escalate": 1}
    assert r["outcomes"] == {"pending": 4, "agree": 1, "disagree": 2}
    assert (r["unsafe_misses"], r["over_strict_misses"], r["unsafe_miss_cases"]) == (1, 1, 1)
    assert (r["resolved_decisions"], r["resolved_allows"]) == (2, 2)
    # signals and actor kinds count outcome records, not effective outcomes
    assert r["signals"] == {"auto": 2, "human": 2, "revert": 1}
    assert r["actor_kinds"] == {"human": 2, "automatic": 2, "unattributed": 1}
    assert (r["configured"], r["current"]) == (True, True)


def test_a_scope_star_record_has_repo_null_and_repos_are_not_pooled(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    allows(state_dir, 2, fp, scope="*")
    allows(state_dir, 3, fp, start=10, scope=REPO)
    allows(state_dir, 4, fp, start=20, scope=OTHER)
    _, doc, _ = stat(capsys, config)
    got = {(r["repo"], r["resolved_allows"]) for r in doc["records"]}
    assert got == {(None, 2), (REPO, 3), (OTHER, 4)}
    assert [r["repo"] for r in doc["records"]] == [None, OTHER, REPO]  # `*` first, then by id
    _, doc, _ = stat(capsys, config, "--repo", "*")
    assert [r["repo"] for r in doc["records"]] == [None]
    _, doc, _ = stat(capsys, config, "--repo", REPO)
    assert [r["repo"] for r in doc["records"]] == [REPO]


def test_each_fingerprint_is_its_own_record(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    allows(state_dir, 2, fp)
    allows(state_dir, 3, FP, start=10)
    _, doc, _ = stat(capsys, config)
    by_fp = {r["fingerprint"]: r for r in doc["records"]}
    assert by_fp[fp]["current"] is True and by_fp[FP]["current"] is False
    assert by_fp[FP]["recommend"] is None and by_fp[fp]["recommend"] == "not_yet"
    assert by_fp[FP]["resolved_allows"] == 3 and by_fp[fp]["resolved_allows"] == 2


# --- cases --------------------------------------------------------------------------------------


def _polls(
    state_dir: Path, fp: str, key: str, count: int, *, disagree: tuple[int, ...] = ()
) -> None:
    for i in range(count):
        put_decision(
            state_dir,
            did(100 + i),
            when=ts(i),
            scope=REPO,
            repo=REPO,
            fingerprint=fp,
            case_key=key,
        )
        put_outcome(state_dir, did(100 + i), "disagree" if i in disagree else "agree", **HUMAN)  # type: ignore[arg-type]


def test_twenty_polls_with_a_changing_ignored_object_are_one_case(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    decl = InputDecl(require=["head"], ignore=["ci"])
    keys = {
        inputs.case_key(
            decl, {"object_type": "pr", "object_id": "7", "head": "a", "ci": {"poll": i}}
        )
        for i in range(20)
    }
    assert len(keys) == 1
    _polls(state_dir, fp, keys.pop(), 20)
    _, doc, _ = stat(capsys, config)
    r = only(doc)
    assert r["decisions"]["allow"] == 20 and r["resolved_decisions"] == 20
    assert (r["resolved_allows"], r["unsafe_miss_cases"]) == (1, 0)


def test_a_null_object_id_groups_by_the_input_without_ignored_keys(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    decl = InputDecl(ignore=["ci"])
    same = {inputs.case_key(decl, {"head": "a", "ci": i}) for i in range(5)}
    other = inputs.case_key(decl, {"head": "b", "ci": 0})
    assert len(same) == 1 and other not in same
    _polls(state_dir, fp, same.pop(), 5)
    put_decision(state_dir, did(900), scope=REPO, repo=REPO, fingerprint=fp, case_key=other)
    put_outcome(state_dir, did(900), "agree", **HUMAN)  # type: ignore[arg-type]
    _, doc, _ = stat(capsys, config)
    assert only(doc)["resolved_allows"] == 2


def test_a_case_with_two_misses_counts_once_in_k_and_twice_in_misses(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    _polls(state_dir, fp, MARK, 6, disagree=(1, 4))
    _, doc, _ = stat(capsys, config)
    r = only(doc)
    assert (r["unsafe_misses"], r["unsafe_miss_cases"], r["resolved_allows"]) == (2, 1, 1)
    assert r["resolved_decisions"] == 6
    assert r["upper_bound"] == 1.0  # k = n = 1


def test_a_case_counts_in_n_through_any_resolved_allow_and_never_through_a_deny(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    put_decision(state_dir, did(1), case_key="1" * 64, scope=REPO, repo=REPO, fingerprint=fp)
    put_decision(
        state_dir, did(2), case_key="1" * 64, scope=REPO, repo=REPO, fingerprint=fp, when=ts(5)
    )
    put_outcome(state_dir, did(2), "agree", **HUMAN)  # type: ignore[arg-type]  # one pending, one agree
    put_decision(
        state_dir, did(3), case_key="2" * 64, decision="deny", scope=REPO, repo=REPO, fingerprint=fp
    )
    put_outcome(state_dir, did(3), "agree", **HUMAN)  # type: ignore[arg-type]  # a resolved deny
    put_decision(state_dir, did(4), case_key="3" * 64, scope=REPO, repo=REPO, fingerprint=fp)
    _, doc, _ = stat(capsys, config)
    r = only(doc)
    assert (r["resolved_allows"], r["resolved_decisions"]) == (1, 1)


def test_a_decision_without_a_case_key_is_its_own_case(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    allows(state_dir, 3, fp, keyed=False)
    allows(state_dir, 1, fp, start=10, outcome="disagree", keyed=False)
    _, doc, _ = stat(capsys, config)
    r = only(doc)
    assert (r["resolved_allows"], r["unsafe_miss_cases"]) == (4, 1)


def test_the_same_case_key_in_two_records_is_two_cases(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    _polls(state_dir, fp, MARK, 2)
    put_decision(state_dir, did(500), scope=OTHER, repo=OTHER, fingerprint=fp, case_key=MARK)
    put_outcome(state_dir, did(500), "agree", **HUMAN)  # type: ignore[arg-type]
    _, doc, _ = stat(capsys, config)
    assert sorted(r["resolved_allows"] for r in doc["records"]) == [1, 1]


# --- the recommendation -------------------------------------------------------------------------


def test_59_clean_cases_recommend_enforce_and_58_do_not(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    allows(state_dir, 58, fp)
    _, doc, _ = stat(capsys, config)
    r = only(doc)
    assert r["recommend"] == "not_yet" and round(r["upper_bound"], 4) == 0.0503
    allows(state_dir, 1, fp, start=1000)
    _, doc, _ = stat(capsys, config)
    r = only(doc)
    assert r["recommend"] == "enforce" and round(r["upper_bound"], 4) == 0.0495
    assert (r["resolved_allows"], r["unsafe_miss_cases"]) == (59, 0)


def test_an_enforced_scope_is_kept_or_reconsidered(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    seed(state_dir, "p", "*", "enforced", fingerprint_=fp)  # the repo inherits the `*` row
    allows(state_dir, 58, fp)
    assert only(stat(capsys, config)[1])["recommend"] == "reconsider"
    allows(state_dir, 1, fp, start=1000)
    assert only(stat(capsys, config)[1])["recommend"] == "keep"
    allows(state_dir, 1, fp, start=2000, outcome="disagree")
    r = only(stat(capsys, config)[1])
    assert r["recommend"] == "reconsider" and r["unsafe_miss_cases"] == 1


def test_the_repo_row_decides_the_state_over_the_star_row(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    seed(state_dir, "p", "*", "enforced", fingerprint_=fp)
    seed(state_dir, "p", REPO, "shadow", fingerprint_=fp)
    allows(state_dir, 59, fp)
    assert only(stat(capsys, config)[1])["recommend"] == "enforce"


def test_the_policys_recommend_keys_set_the_confidence_and_the_miss_rate(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, state_dir: Path
) -> None:
    loose = config_file(
        tmp_path / "loose",
        {
            "policies": {
                "p": {
                    "checks": [rule()],
                    "recommend": {"confidence": 0.9, "max_miss_rate": 0.1},
                }
            }
        },
    )
    allows(state_dir, 22, current_fingerprint(loose, "p"))
    r = only(stat(capsys, loose)[1])
    assert r["recommend"] == "enforce"  # 1 - 0.1 ** (1 / 22) = 0.0994
    assert r["upper_bound"] == pytest.approx(-math.expm1(math.log(0.1) / 22), abs=2e-6)
    strict = config_file(
        tmp_path / "strict",
        {
            "defaults": {"recommend": {"max_miss_rate": 0.01}},
            "policies": {"p": {"checks": [rule()]}},
        },
    )
    allows(state_dir, 40, current_fingerprint(strict, "p"), start=100)
    assert only(stat(capsys, strict)[1])["recommend"] == "not_yet"


def test_a_record_that_is_no_longer_current_has_no_recommendation(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    allows(state_dir, 70, FP)
    r = only(stat(capsys, config)[1])
    assert (r["current"], r["recommend"]) == (False, None)
    assert r["upper_bound"] < 0.05  # the numbers are still shown


def test_since_selects_decisions_by_time_with_all_their_outcomes_and_nulls_recommend(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    allows(state_dir, 30, fp)  # 12:00:01 .. 12:00:30
    put_outcome(state_dir, did(30), "disagree", when="2030-01-01T00:00:00.000000Z", **AUTO)  # type: ignore[arg-type]
    code, doc, _ = stat(capsys, config, "--since", "2026-11-24T12:00:20Z")
    r = only(doc)
    assert code == 0 and doc["since"] == "2026-11-24T12:00:20.000000Z"
    assert r["decisions"]["allow"] == 11  # 20..30 inclusive
    assert r["unsafe_misses"] == 1 and r["recommend"] is None and r["current"] is True
    assert r["signals"] == {"human": 11, "revert": 1}


def test_a_policy_only_in_state_db_is_unconfigured(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    put_decision(state_dir, did(1), policy="gone", scope=REPO, repo=REPO)
    put_outcome(state_dir, did(1), "agree", **HUMAN)  # type: ignore[arg-type]
    _, doc, _ = stat(capsys, config)
    r = only(doc)
    assert (r["policy"], r["configured"], r["current"], r["recommend"]) == (
        "gone",
        False,
        False,
        None,
    )
    code, doc, _ = stat(capsys, config, "--policy", "gone")
    assert code == 0 and len(doc["records"]) == 1


def test_an_unknown_policy_exits_2(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, did(1))
    code, doc, _ = call(capsys, "stats", "--config", config, "--policy", "nope")
    assert code == 2 and doc["error"]["details"] == {"kind": "unknown_policy"}
    code, _, _ = call(capsys, "stats", "--config", config, "--policy", "Bad Name")
    assert code == 2


@pytest.mark.parametrize("flag", [["--since", "yesterday"], ["--repo", "no spaces"]])
def test_bad_arguments_exit_2(
    capsys: pytest.CaptureFixture[str], config: str, flag: list[str]
) -> None:
    assert call(capsys, "stats", "--config", config, *flag)[0] == 2


def test_policy_filter_and_per_policy_records(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, state_dir: Path
) -> None:
    config = config_file(
        tmp_path, {"policies": {"p": {"checks": [rule()]}, "q": {"checks": [rule()]}}}
    )
    put_decision(state_dir, did(1), policy="p", scope=REPO, repo=REPO)
    put_decision(state_dir, did(2), policy="q", scope=REPO, repo=REPO)
    assert [r["policy"] for r in stat(capsys, config)[1]["records"]] == ["p", "q"]
    assert [r["policy"] for r in stat(capsys, config, "--policy", "q")[1]["records"]] == ["q"]


# --- reasons ------------------------------------------------------------------------------------


def test_reason_counts_count_check_entries_and_a_decision_with_none_counts_its_own_reason(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    def failing(name: str, reason: str) -> dict[str, Any]:
        return check_entry(name, verdict="deny", reason=reason)

    put_decision(
        state_dir,
        did(1),
        when=ts(1),
        decision="deny",
        reason="check_denied",
        scope=REPO,
        fingerprint=fp,
        checks=[failing("a", "check_denied"), failing("b", "check_denied"), check_entry("c")],
    )
    put_decision(
        state_dir,
        did(2),
        when=ts(9),
        decision="escalate",
        reason="timeout",
        scope=REPO,
        fingerprint=fp,
        checks=[failing("a", "timeout")],
    )
    put_decision(state_dir, did(3), when=ts(5), scope=REPO, fingerprint=fp)  # all_passed
    put_decision(
        state_dir,
        did(4),
        when=ts(7),
        decision="escalate",
        reason="input_invalid",
        scope=REPO,
        fingerprint=fp,
        checks=[],
    )
    r = only(stat(capsys, config)[1])
    assert r["reason_counts"] == [
        {"reason": "all_passed", "count": 1, "last_seen": ts(5)},
        {"reason": "check_denied", "count": 2, "last_seen": ts(1)},
        {"reason": "input_invalid", "count": 1, "last_seen": ts(7)},
        {"reason": "timeout", "count": 1, "last_seen": ts(9)},
    ]


# --- reading ------------------------------------------------------------------------------------


def test_the_reader_never_writes(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    allows(state_dir, 5, fp)
    before = {p.name: p.read_bytes() for p in state_dir.iterdir() if p.is_file()}
    assert stat(capsys, config)[0] == 0
    assert stat(capsys, config, "--since", "1d")[0] == 0
    after = {p.name: p.read_bytes() for p in state_dir.iterdir() if p.is_file()}
    assert after.get("state.db") == before.get("state.db")
    sidecars = {"state.db-wal", "state.db-shm"}  # SQLite's own reader files
    assert set(after) - sidecars <= set(before)  # no audit line, no log, no new file


def test_text_output_is_one_sanitized_block_per_record(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    allows(state_dir, 3, fp)
    assert main(["stats", "--config", config]) == 0
    out = capsys.readouterr().out
    assert out.startswith(f"p@{REPO} {fp}")
    assert "recommend: not_yet" in out and "upper bound" in out
    assert main(["stats", "--config", config, "--repo", OTHER]) == 0
    assert capsys.readouterr().out == "no records\n"


def test_the_golden_output_is_printed_byte_for_byte(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gatectl import fingerprint as fpmod

    fixed = "sha256:" + "ab" * 32
    monkeypatch.setattr(fpmod, "fingerprint", lambda *a, **k: fixed)
    config = config_file(tmp_path, {"policies": {"auto-merge": {"checks": [rule()]}}})
    for n, decision in enumerate(["allow", "allow", "allow", "deny"], start=1):
        put_decision(
            state_dir,
            did(n),
            when=T0,
            policy="auto-merge",
            scope=REPO,
            repo=REPO,
            decision=decision,
            reason="all_passed" if decision == "allow" else "check_denied",
            fingerprint=fixed,
            case_key=f"{n:064x}",
            checks=[check_entry()]
            if decision == "allow"
            else [check_entry(verdict="deny", reason="check_denied")],
        )
        if n < 4:
            put_outcome(state_dir, did(n), "agree", actor="human:ann")
    assert main(["stats", "--config", config, "--json"]) == 0
    out = capsys.readouterr().out
    golden.assert_output("stats", out)


# --- no evidence is never enough, a printed bound is never below the true one -------------------


@pytest.mark.parametrize("state", ["off", "shadow"])
def test_a_bound_of_one_never_recommends_enforce_even_with_max_miss_rate_one(state: str) -> None:
    assert stats.recommendation(state, 1.0, 1.0) == "not_yet"


def test_a_bound_of_one_on_an_enforced_scope_is_reconsider_even_with_max_miss_rate_one() -> None:
    assert stats.recommendation("enforced", 1.0, 1.0) == "reconsider"


def test_a_bound_below_one_still_holds_at_max_miss_rate_one() -> None:
    assert stats.recommendation("shadow", 0.99, 1.0) == "enforce"


def test_no_resolved_allows_and_all_misses_are_not_yet_at_max_miss_rate_one(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, state_dir: Path
) -> None:
    loose = config_file(
        tmp_path / "loose",
        {"policies": {"p": {"checks": [rule()], "recommend": {"max_miss_rate": 1}}}},
    )
    fingerprint = current_fingerprint(loose, "p")
    allows(state_dir, 1, fingerprint, outcome=None)  # n = 0
    r = only(stat(capsys, loose)[1])
    assert (r["resolved_allows"], r["upper_bound"], r["recommend"]) == (0, 1.0, "not_yet")
    allows(state_dir, 1, fingerprint, start=10, outcome="disagree")  # k == n == 1
    r = only(stat(capsys, loose)[1])
    assert (r["resolved_allows"], r["unsafe_miss_cases"]) == (1, 1)
    assert (r["upper_bound"], r["recommend"]) == (1.0, "not_yet")


def test_the_printed_bound_rounds_up_to_6_decimals() -> None:
    assert stats.printed_bound(0.0500004) == 0.050001
    assert stats.printed_bound(0.05) == 0.05
    assert stats.printed_bound(1.0) == 1.0
    assert stats.printed_bound(0.7763931) == 0.776394


def test_a_tiny_bound_never_prints_as_zero() -> None:
    assert stats.printed_bound(stats.upper_bound(0, 10_000_000, 0.95)) > 0


def test_the_state_rows_are_read_inside_the_same_snapshot_as_the_decisions(
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
    fp: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gatectl.store import Store

    allows(state_dir, 1, fp)
    seen: list[bool] = []
    real = Store.effective

    def spy(self: Store, *args: Any, **kwargs: Any) -> Any:
        seen.append(self.con.in_transaction)
        return real(self, *args, **kwargs)

    monkeypatch.setattr(Store, "effective", spy)
    stat(capsys, config)
    assert seen == [True]


# --- policies shows the records -----------------------------------------------------------------


def test_policies_lists_the_records_of_the_shown_scope(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, fp: str
) -> None:
    allows(state_dir, 59, fp, scope="*")
    allows(state_dir, 2, FP, start=1000, scope="*")
    allows(state_dir, 3, fp, start=2000, scope=REPO)
    _, doc, _ = call(capsys, "policies", "--config", config)
    schema_util.assert_valid("cli/policies", doc)
    records = doc["policies"][0]["records"]
    assert [(r["repo"], r["fingerprint"], r["recommend"]) for r in records] == [
        (None, FP, None),
        (None, fp, "enforce"),
    ] or [(r["repo"], r["fingerprint"], r["recommend"]) for r in records] == [
        (None, fp, "enforce"),
        (None, FP, None),
    ]
    _, doc, _ = call(capsys, "policies", "--config", config, "--repo", REPO)
    (record,) = doc["policies"][0]["records"]
    assert (record["repo"], record["resolved_allows"]) == (REPO, 3)


def test_policies_with_no_history_has_no_records(
    capsys: pytest.CaptureFixture[str], config: str
) -> None:
    assert call(capsys, "policies", "--config", config)[1]["policies"][0]["records"] == []


def test_the_dependency_on_sqlite_json_is_available() -> None:
    con = sqlite3.connect(":memory:")
    assert con.execute("SELECT json_valid('[]')").fetchone() == (1,)
