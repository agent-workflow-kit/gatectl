"""``gatectl show``: id resolution (exit 2, 10, 21), the full record, history, cache source."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from gatectl import history, store
from gatectl.cli import main
from gatectl.errors import NotFoundError
from tests import golden, schema_util
from tests.command_util import config_file, isolate, rule
from tests.history_util import (
    REPO,
    T0,
    call,
    check_entry,
    did,
    put_cache,
    put_decision,
    put_outcome,
    sql,
    ts,
)

ID = "gd-4k2m7q5x3a2b"


@pytest.fixture(autouse=True)
def state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


@pytest.fixture
def config(tmp_path: Path) -> str:
    return config_file(tmp_path, {"policies": {"p": {"checks": [rule()]}}})


def show(
    capsys: pytest.CaptureFixture[str], config: str, ref: str
) -> tuple[int, dict[str, Any], str]:
    return call(capsys, "show", ref, "--config", config)


def test_the_golden_output_is_printed_byte_for_byte(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, state_dir: Path
) -> None:
    config = config_file(tmp_path, {"policies": {"auto-merge": {"checks": [rule()]}}})
    put_decision(
        state_dir,
        ID,
        policy="auto-merge",
        scope=REPO,
        repo=REPO,
        declared={"head_sha": "0123abcd"},
    )
    put_outcome(state_dir, ID, "agree", actor="human:ann", signal="human", kind="human")
    assert main(["show", ID, "--config", config, "--json"]) == 0
    golden.assert_output("show", capsys.readouterr().out)


def test_full_id_and_prefixes_resolve_to_the_same_decision(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    for ref in (ID, ID[3:], ID[:9], "4k2m7q", ID[:-1]):
        code, doc, _ = show(capsys, config, ref)
        assert code == 0 and doc["decision_id"] == ID, ref


def test_a_short_prefix_exits_2(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    code, doc, _ = show(capsys, config, "gd-4k2m7")
    assert code == 2 and doc["error"]["code"] == "usage"


@pytest.mark.parametrize(
    "ref", ["gd-4k2m7%", "gd-4k2m7_", "%", "gd-%%%%%%", "4k2m7q'; --", "GD-4K2M7Q", "gd-gd-4k2m7q"]
)
def test_like_wildcards_and_junk_are_usage_errors(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path, ref: str
) -> None:
    put_decision(state_dir, ID)
    code, doc, err = show(capsys, config, ref)
    assert code == 2 and doc["error"]["code"] == "usage"
    assert ref not in json.dumps(doc) + err


def test_an_unknown_id_exits_10(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    code, doc, _ = show(capsys, config, "gd-zzzzzz")
    assert code == 10 and doc["error"]["code"] == "not_found"


def test_no_database_is_not_found_and_nothing_is_created(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    code, doc, _ = show(capsys, config, ID)
    assert code == 10 and doc["error"]["code"] == "not_found"
    assert not state_dir.exists()


def test_an_ambiguous_prefix_exits_21(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, "gd-abcdefaaaaaa")
    put_decision(state_dir, "gd-abcdefbbbbbb")
    code, doc, _ = show(capsys, config, "gd-abcdef")
    assert code == 21 and doc["error"]["code"] == "ambiguous"
    code, doc, _ = show(capsys, config, "gd-abcdefa")
    assert code == 0 and doc["decision_id"] == "gd-abcdefaaaaaa"


def test_the_full_id_wins_over_longer_tampered_neighbours(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    put_decision(state_dir, ID + "zz", raw={"id": ID + "zz"})  # not an id: never counts
    code, doc, _ = show(capsys, config, ID)
    assert code == 0 and doc["decision_id"] == ID


def test_show_has_every_check_the_declared_fields_and_the_input_hash(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    checks = [
        check_entry("lint", verdict="deny", reason="check_denied", detail="2 errors"),
        check_entry("judge", type="agent", verdict="allow", confidence=0.9, reused=False),
        check_entry("late", type="script", verdict="skipped", duration_ms=0),
    ]
    put_decision(
        state_dir,
        ID,
        decision="deny",
        reason="check_denied",
        checks=checks,
        declared={"head_sha": "abc"},
        input_sha256="9" * 64,
    )
    code, doc, _ = show(capsys, config, ID)
    assert code == 0
    assert [c["name"] for c in doc["checks"]] == ["lint", "judge", "late"]
    assert doc["checks"][0]["detail"] == "2 errors"
    assert doc["checks"][1]["confidence"] == 0.9 and doc["checks"][1]["reused"] is False
    assert doc["declared"] == {"head_sha": "abc"} and doc["input_sha256"] == "9" * 64
    assert doc["cache_source"] is None
    schema_util.assert_valid("cli/show", doc)


def test_outcome_history_is_in_insertion_order_with_the_effective_outcome(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    put_outcome(state_dir, ID, "agree", when="2026-11-24T12:00:09.000000Z")
    put_outcome(
        state_dir,
        ID,
        "disagree",
        actor="auto:bot",
        signal="revert",
        kind="automatic",
        reason="it broke",
        when="2026-11-24T12:00:01.000000Z",  # earlier clock, later sequence
    )
    _, doc, _ = show(capsys, config, ID)
    assert [o["outcome"] for o in doc["outcomes"]] == ["agree", "disagree"]
    assert doc["outcomes"][1] == {
        "time": "2026-11-24T12:00:01.000000Z",
        "outcome": "disagree",
        "signal": "revert",
        "actor": "auto:bot",
        "actor_kind": "automatic",
        "reason": "it broke",
    }
    assert doc["effective_outcome"] == "disagree"
    schema_util.assert_valid("cli/show", doc)


def test_an_automatic_agree_leaves_the_decision_pending(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    put_outcome(state_dir, ID, "agree", actor="auto:bot", kind="automatic")
    _, doc, _ = show(capsys, config, ID)
    assert doc["effective_outcome"] == "pending" and len(doc["outcomes"]) == 1


def test_the_cache_source_names_the_decision_that_produced_the_reused_result(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    key = "sha256:" + "5" * 64
    put_cache(state_dir, key, did(9))
    put_decision(
        state_dir,
        ID,
        checks=[check_entry("judge", type="agent", confidence=0.8, reused=True, cache_key=key)],
    )
    _, doc, _ = show(capsys, config, ID)
    assert doc["cache_source"] == {"decision_id": did(9)}
    assert "cache_key" not in doc["checks"][0]
    schema_util.assert_valid("cli/show", doc)


def test_a_reused_check_whose_cache_row_is_gone_has_no_source(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(
        state_dir,
        ID,
        checks=[
            check_entry(
                "judge", type="agent", confidence=0.8, reused=True, cache_key="sha256:" + "6" * 64
            )
        ],
    )
    _, doc, _ = show(capsys, config, ID)
    assert doc["cache_source"] is None


def test_a_removed_policy_shows_configured_false(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID, policy="gone")
    _, doc, _ = show(capsys, config, ID)
    assert doc["configured"] is False and doc["policy"] == "gone"


def test_text_output_is_sanitized_lines(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID, checks=[check_entry(detail="bad \x1b[31m‮ text")])
    put_outcome(state_dir, ID, "agree", reason="why\x07not")
    assert main(["show", ID, "--config", config]) == 0
    out = capsys.readouterr().out
    assert ID in out and "bad" in out
    assert all(c == "\n" or c.isprintable() for c in out)


def test_show_never_writes(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    before = (state_dir / "state.db").read_bytes()
    audit = sorted(p.name for p in state_dir.iterdir() if p.name.startswith(("audit", "log")))
    assert show(capsys, config, ID)[0] == 0
    assert (state_dir / "state.db").read_bytes() == before
    assert audit == sorted(
        p.name for p in state_dir.iterdir() if p.name.startswith(("audit", "log"))
    )
    sql(state_dir, "SELECT 1")  # the database is still a plain, usable file


# --- round 1 ------------------------------------------------------------------------------------


def _reused(key: str) -> list[dict[str, Any]]:
    return [check_entry("judge", type="agent", confidence=0.8, reused=True, cache_key=key)]


def test_a_cache_row_replaced_after_the_decision_is_not_its_source(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    """A key refresh makes the row name a later decision; that one did not produce the result."""
    key = "sha256:" + "5" * 64
    put_cache(state_dir, key, did(9), when=ts(30))  # replaced after the decision (T0)
    put_decision(state_dir, ID, checks=_reused(key))
    _, doc, _ = show(capsys, config, ID)
    assert doc["cache_source"] is None


def test_a_cache_row_that_was_expired_at_the_decision_time_is_not_its_source(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    key = "sha256:" + "5" * 64
    put_cache(state_dir, key, did(9), when=ts(0), expires_at=T0)  # expired at the decision's time
    put_decision(state_dir, ID, checks=_reused(key))
    _, doc, _ = show(capsys, config, ID)
    assert doc["cache_source"] is None


def test_a_cache_row_that_expired_after_the_decision_is_still_its_source(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    key = "sha256:" + "5" * 64
    put_cache(state_dir, key, did(9), when=ts(0), expires_at=ts(5))  # live at T0, expired now
    put_decision(state_dir, ID, checks=_reused(key))
    _, doc, _ = show(capsys, config, ID)
    assert doc["cache_source"] == {"decision_id": did(9)}


def test_show_reads_one_snapshot_so_an_outcome_in_between_stays_consistent(
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    put_decision(state_dir, ID)
    real = history._outcomes

    def racing(store: Any, decision_id: str) -> list[dict[str, Any]]:
        put_outcome(state_dir, ID, "disagree", actor="human:ann")  # lands between the reads
        return real(store, decision_id)

    monkeypatch.setattr(history, "_outcomes", racing)
    code, doc, _ = show(capsys, config, ID)
    assert code == 0
    assert doc["effective_outcome"] == "pending" and doc["outcomes"] == []


def test_a_decision_pruned_after_it_was_resolved_does_not_break_show(
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    put_decision(state_dir, ID)
    real = history.resolve

    def racing(store: Any, ref: Any) -> str:
        found = real(store, ref)
        sql(state_dir, "DELETE FROM decisions WHERE id = ?", ID)  # a prune lands right after
        return found

    monkeypatch.setattr(history, "resolve", racing)
    code, doc, _ = show(capsys, config, ID)
    assert code == 0 and doc["decision_id"] == ID


def test_loading_a_vanished_decision_is_not_found(state_dir: Path) -> None:
    put_decision(state_dir, did(2))
    s = store.open_store(state_dir, create=False)
    assert s is not None
    with s, pytest.raises(NotFoundError):
        history.load(s, ID, set())


def test_non_string_declared_values_print_as_compact_json_in_text(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID, declared={"n": 7, "flag": True, "list": [1, "é"], "z": None})
    code = main(["show", ID, "--config", config])
    out = capsys.readouterr().out
    assert code == 0
    assert "declared n: 7\n" in out and "declared flag: true\n" in out
    assert 'declared list: [1,"\\u00e9"]\n' in out and "declared z: null\n" in out
    assert "True" not in out and "None" not in out


def test_a_non_ascii_declared_value_under_the_cap_is_not_refused(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    """The writer measures canonical UTF-8 bytes; 200 two-byte characters are 404, not 1200."""
    value = ["é" * 200]
    put_decision(state_dir, ID, declared={"k": value})
    code, doc, _ = show(capsys, config, ID)
    assert code == 0 and doc["declared"]["k"] == value


def test_a_declared_value_over_the_byte_cap_is_refused(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID, declared={"k": ["é" * 250, "é" * 250, "é" * 250]})
    code, _, _ = show(capsys, config, ID)
    assert code == 1


def test_duplicate_declared_keys_are_a_tamper(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID, raw={"declared_json": '{"a":"x","a":"y"}'})
    code, doc, err = show(capsys, config, ID)
    assert code == 1 and doc["error"]["code"] == "internal"
    assert doc["error"]["message"] == "state.db holds an invalid decision row"


def test_show_with_a_history_and_no_state_db_exits_1_state_db_missing(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    state_dir.mkdir(parents=True, mode=0o700)
    (state_dir / "audit.jsonl").write_text('{"ts":"2026-11-24T12:00:00.000000Z"}\n')
    code, doc, _ = show(capsys, config, ID)
    assert code == 1 and doc["error"]["reason"] == "state_db_missing"
