"""``gatectl decisions``: filters, order, limit, effective outcome, removed policies, goldens."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from gatectl.cli import main
from tests import golden, schema_util
from tests.command_util import config_file, isolate, rule
from tests.history_util import (
    FP,
    OTHER,
    REPO,
    call,
    did,
    put_decision,
    put_outcome,
    ts,
)


@pytest.fixture(autouse=True)
def state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


@pytest.fixture
def config(tmp_path: Path) -> str:
    return config_file(
        tmp_path,
        {"policies": {"p": {"checks": [rule()]}, "q": {"checks": [rule()]}}},
    )


def ids_of(doc: dict[str, Any]) -> list[str]:
    return [d["decision_id"] for d in doc["decisions"]]


def test_no_state_db_lists_nothing_and_creates_nothing(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    code, doc, err = call(capsys, "decisions", "--config", config)
    assert (code, doc, err) == (0, {"decisions": [], "truncated": False}, "")
    assert not state_dir.exists()


def test_the_golden_output_is_printed_byte_for_byte(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, state_dir: Path
) -> None:
    config = config_file(tmp_path, {"policies": {"auto-merge": {"checks": [rule()]}}})
    put_decision(
        state_dir,
        "gd-4k2m7q5x3a2b",
        policy="auto-merge",
        scope=REPO,
        repo=REPO,
        declared={"head_sha": "0123abcd"},
    )
    put_outcome(state_dir, "gd-4k2m7q5x3a2b", "agree", actor="auto:bot", kind="automatic")
    assert main(["decisions", "--config", config, "--json"]) == 0
    golden.assert_output("decisions", capsys.readouterr().out)


def test_newest_first_by_time_then_id(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, did(1), when=ts(1))
    put_decision(state_dir, did(3), when=ts(3))
    put_decision(state_dir, did(2), when=ts(2))
    code, doc, _ = call(capsys, "decisions", "--config", config)
    assert code == 0
    assert ids_of(doc) == [did(3), did(2), did(1)]
    schema_util.assert_valid("cli/decisions", doc)


def test_limit_truncates_and_says_so(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    for n in range(5):
        put_decision(state_dir, did(n), when=ts(n))
    _, doc, _ = call(capsys, "decisions", "--config", config, "--limit", "3")
    assert ids_of(doc) == [did(4), did(3), did(2)]
    assert doc["truncated"] is True
    _, doc, _ = call(capsys, "decisions", "--config", config, "--limit", "5")
    assert len(doc["decisions"]) == 5 and doc["truncated"] is False


def test_the_default_limit_is_100(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    for n in range(101):
        put_decision(state_dir, did(n), when=f"2026-11-24T12:{n // 60:02d}:{n % 60:02d}.000000Z")
    _, doc, _ = call(capsys, "decisions", "--config", config)
    assert len(doc["decisions"]) == 100 and doc["truncated"] is True


@pytest.mark.parametrize("bad", ["0", "-1", "abc", "1.5", "", "1001", " 5", "5 ", "٣", "1e2"])
def test_a_bad_limit_exits_2_without_echoing_it(
    capsys: pytest.CaptureFixture[str], config: str, bad: str
) -> None:
    code, doc, err = call(capsys, "decisions", "--config", config, "--limit", bad)
    assert code == 2
    assert doc["error"]["code"] == "usage"
    assert len(bad) < 3 or bad not in json.dumps(doc) + err


def test_filter_by_policy(capsys: pytest.CaptureFixture[str], config: str, state_dir: Path) -> None:
    put_decision(state_dir, did(1), when=ts(1), policy="p")
    put_decision(state_dir, did(2), when=ts(2), policy="q")
    _, doc, _ = call(capsys, "decisions", "--config", config, "--policy", "q")
    assert ids_of(doc) == [did(2)]


def test_filter_by_repo_and_star(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, did(1), when=ts(1), scope=REPO, repo=REPO)
    put_decision(state_dir, did(2), when=ts(2), scope=OTHER, repo=OTHER)
    put_decision(state_dir, did(3), when=ts(3), scope="*", repo=None)
    _, doc, _ = call(capsys, "decisions", "--config", config, "--repo", REPO)
    assert ids_of(doc) == [did(1)]
    _, doc, _ = call(capsys, "decisions", "--config", config, "--repo", "*")
    assert ids_of(doc) == [did(3)]
    assert doc["decisions"][0]["repo"] is None and doc["decisions"][0]["scope"] == "*"


def test_filter_by_object_id(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, did(1), when=ts(1), object_id="42")
    put_decision(state_dir, did(2), when=ts(2), object_id="43")
    put_decision(state_dir, did(3), when=ts(3), object_id=None)
    _, doc, _ = call(capsys, "decisions", "--config", config, "--object-id", "42")
    assert ids_of(doc) == [did(1)]


def test_filter_by_decision(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, did(1), when=ts(1), decision="allow")
    put_decision(state_dir, did(2), when=ts(2), decision="deny", reason="check_denied")
    put_decision(state_dir, did(3), when=ts(3), decision="escalate", reason="check_escalated")
    for verdict, expected in (("allow", 1), ("deny", 2), ("escalate", 3)):
        _, doc, _ = call(capsys, "decisions", "--config", config, "--decision", verdict)
        assert ids_of(doc) == [did(expected)]


def test_filter_by_declared_exact_string_match(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, did(1), when=ts(1), declared={"head_sha": "0123abcd", "n": 7})
    put_decision(state_dir, did(2), when=ts(2), declared={"head_sha": "0123abcd9"})
    put_decision(state_dir, did(3), when=ts(3), declared={"other": "0123abcd"})
    _, doc, _ = call(capsys, "decisions", "--config", config, "--declared", "head_sha=0123abcd")
    assert ids_of(doc) == [did(1)]
    # a number is not a string: --declared matches declared strings only
    _, doc, _ = call(capsys, "decisions", "--config", config, "--declared", "n=7")
    assert ids_of(doc) == []


@pytest.mark.parametrize("bad", ["novalue", "=x", "k=" + "v" * 257, "k" * 257 + "=v"])
def test_a_bad_declared_filter_exits_2(
    capsys: pytest.CaptureFixture[str], config: str, bad: str
) -> None:
    code, doc, err = call(capsys, "decisions", "--config", config, "--declared", bad)
    assert code == 2 and doc["error"]["code"] == "usage"
    assert bad not in json.dumps(doc) + err


def test_filter_by_since_time_and_duration(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, did(1), when="2020-01-01T00:00:00.000000Z")
    put_decision(state_dir, did(2), when="2026-11-24T12:00:00.000000Z")
    _, doc, _ = call(capsys, "decisions", "--config", config, "--since", "2026-01-01T00:00:00Z")
    assert ids_of(doc) == [did(2)]
    # inclusive at the boundary, and an offset is honored
    _, doc, _ = call(
        capsys, "decisions", "--config", config, "--since", "2026-11-24T13:00:00.000000+01:00"
    )
    assert ids_of(doc) == [did(2)]
    _, doc, _ = call(capsys, "decisions", "--config", config, "--since", "1d")
    assert ids_of(doc) == []  # the seeded times are fixed, "now" is not


@pytest.mark.parametrize("bad", ["yesterday", "2026-01-01", "2026-01-01T00:00:00", "-1h", "1w"])
def test_a_bad_since_exits_2(capsys: pytest.CaptureFixture[str], config: str, bad: str) -> None:
    code, doc, err = call(capsys, "decisions", "--config", config, "--since", bad)
    assert code == 2 and doc["error"]["code"] == "usage"
    assert bad not in json.dumps(doc) + err


def test_filter_by_outcome_uses_the_effective_outcome(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    for n in range(1, 6):
        put_decision(state_dir, did(n), when=ts(n))
    # 1: no outcome (pending); 2: human agree; 3: auto agree only (still pending);
    # 4: human agree then auto disagree (disagree); 5: disagree then a later human agree (agree)
    put_outcome(state_dir, did(2), "agree")
    put_outcome(state_dir, did(3), "agree", actor="auto:bot", kind="automatic")
    put_outcome(state_dir, did(4), "agree")
    put_outcome(state_dir, did(4), "disagree", actor="auto:bot", kind="automatic")
    put_outcome(state_dir, did(5), "disagree", actor="auto:bot", kind="automatic")
    put_outcome(state_dir, did(5), "agree")
    for outcome, expected in (("pending", [3, 1]), ("agree", [5, 2]), ("disagree", [4])):
        _, doc, _ = call(capsys, "decisions", "--config", config, "--outcome", outcome)
        assert ids_of(doc) == [did(n) for n in expected]
    _, doc, _ = call(capsys, "decisions", "--config", config)
    shown = {d["decision_id"]: d["effective_outcome"] for d in doc["decisions"]}
    assert shown == {
        did(1): "pending",
        did(2): "agree",
        did(3): "pending",
        did(4): "disagree",
        did(5): "agree",
    }


def test_filters_combine_with_and(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, did(1), when=ts(1), policy="p", decision="deny", reason="check_denied")
    put_decision(state_dir, did(2), when=ts(2), policy="p", decision="allow")
    put_decision(state_dir, did(3), when=ts(3), policy="q", decision="deny", reason="check_denied")
    _, doc, _ = call(capsys, "decisions", "--config", config, "--policy", "p", "--decision", "deny")
    assert ids_of(doc) == [did(1)]


def test_a_removed_policy_is_listed_with_configured_false(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, did(1), when=ts(1), policy="gone")
    put_decision(state_dir, did(2), when=ts(2), policy="p")
    _, doc, _ = call(capsys, "decisions", "--config", config)
    configured = {d["policy"]: d["configured"] for d in doc["decisions"]}
    assert configured == {"gone": False, "p": True}
    _, doc, _ = call(capsys, "decisions", "--config", config, "--policy", "gone")
    assert ids_of(doc) == [did(1)]


def test_an_unknown_policy_exits_2_with_the_unknown_policy_kind(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, did(1), policy="p")
    code, doc, _ = call(capsys, "decisions", "--config", config, "--policy", "nope")
    assert code == 2
    assert doc["error"]["code"] == "usage"
    assert doc["error"]["details"] == {"kind": "unknown_policy"}


@pytest.mark.parametrize("bad", ["P", "a b", "", "a" * 65, "p%", "p_", "../p"])
def test_a_malformed_policy_filter_exits_2(
    capsys: pytest.CaptureFixture[str], config: str, bad: str
) -> None:
    code, doc, _ = call(capsys, "decisions", "--config", config, "--policy", bad)
    assert code == 2 and doc["error"]["code"] == "usage"


def test_a_bad_repo_exits_2(capsys: pytest.CaptureFixture[str], config: str) -> None:
    code, doc, _ = call(capsys, "decisions", "--config", config, "--repo", "Not A Repo")
    assert code == 2 and doc["error"]["code"] == "usage"


def test_rows_carry_every_documented_field(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(
        state_dir,
        did(1),
        scope=REPO,
        repo=REPO,
        actor="human:ann",
        tool="Bash",
        state="enforced",
        state_rev=7,
        declared={"a": 1, "b": "x"},
        case_key="1" * 64,
        input_sha256="2" * 64,
    )
    _, doc, _ = call(capsys, "decisions", "--config", config)
    (row,) = doc["decisions"]
    assert row["actor"] == "human:ann" and row["tool"] == "Bash"
    assert row["state"] == "enforced" and row["state_rev"] == 7
    assert row["declared"] == {"a": 1, "b": "x"}
    assert row["case_key"] == "1" * 64 and row["input_sha256"] == "2" * 64
    assert row["fingerprint"] == FP and row["hook"] == "pre-merge"
    schema_util.assert_valid("cli/decisions", doc)


def test_text_output_is_one_sanitized_line_per_decision(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, did(1), when=ts(1))
    put_decision(state_dir, did(2), when=ts(2), object_id="x\x1b[31my")
    code = main(["decisions", "--config", config])
    out = capsys.readouterr().out
    assert code == 0
    lines = out.splitlines()
    assert len(lines) == 2 and lines[0].startswith(did(2))
    assert "\x1b" not in out
    assert all(c == "\n" or c.isprintable() for c in out)


def test_text_output_for_nothing_and_for_truncation(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    assert main(["decisions", "--config", config]) == 0
    assert capsys.readouterr().out == "no decisions\n"
    for n in range(3):
        put_decision(state_dir, did(n), when=ts(n))
    assert main(["decisions", "--config", config, "--limit", "2"]) == 0
    out = capsys.readouterr().out
    assert len(out.splitlines()) == 3 and "truncated" in out.splitlines()[-1]


# --- round 1 ------------------------------------------------------------------------------------


def test_a_history_and_no_state_db_exits_1_state_db_missing(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    state_dir.mkdir(parents=True, mode=0o700)
    (state_dir / "audit.jsonl").write_text('{"ts":"2026-11-24T12:00:00.000000Z"}\n')
    code, doc, _ = call(capsys, "decisions", "--config", config)
    assert code == 1 and doc["error"]["reason"] == "state_db_missing"


def test_declared_filter_does_not_match_a_duplicate_key_row_that_is_then_refused(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    """json_each sees both duplicates, Python's last wins: such a row is a tamper (exit 1)."""
    put_decision(state_dir, did(1), raw={"declared_json": '{"k":"a","k":"b"}'})
    code, doc, _ = call(capsys, "decisions", "--config", config, "--declared", "k=a")
    assert code == 1 and doc["error"]["message"] == "state.db holds an invalid decision row"
