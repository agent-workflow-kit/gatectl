"""``gatectl set``: state rows, equality rules, ``--all``, removed policies, hints, audit."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from gatectl import audit, setcmd, store
from gatectl.errors import InternalError
from tests import golden, schema_util
from tests.command_util import run
from tests.set_util import (
    AGENT_ONLY,
    ALIEN,
    HUMAN,
    OTHER,
    REPO,
    RULE_POLICY,
    SCRIPT_POLICY,
    STALE,
    audit_lines,
    count_rows,
    current_fingerprint,
    do_set,
    isolate,
    make_config,
    row,
    rows,
    seed,
    seed_decision,
    set_meta,
)

MARKER = "sha256:" + "0" * 64


@pytest.fixture(autouse=True)
def state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


# --- the basic write ----------------------------------------------------------------------


def test_set_shadow_prints_the_golden_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path, {"auto-merge": RULE_POLICY})
    from gatectl.cli import main

    assert main(["set", "auto-merge", "shadow", "--config", config, "--json"]) == 0
    golden.assert_output("set", capsys.readouterr().out)


def test_a_change_writes_one_row_and_one_audit_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    note = tmp_path / "note.txt"
    note.write_text("because\n")
    code, doc, err = do_set(capsys, config, "p", "shadow", "--reason-file", str(note))
    assert (code, err) == (0, "")
    assert doc == {
        "policy": "p",
        "scope": "*",
        "state": "shadow",
        "previous_state": "off",
        "changed": True,
        "scopes_changed": ["*"],
        "hint": None,
    }
    schema_util.assert_valid("cli/set", doc)
    stored = row(state_dir, "p", "*")
    assert stored is not None
    assert (stored.state, stored.cause, stored.set_by) == ("shadow", "set", "auto:unknown")
    assert stored.fingerprint == current_fingerprint(config, "p")
    lines = audit_lines(state_dir)
    assert len(lines) == 1
    schema_util.assert_valid("audit", lines[0])
    line = lines[0]
    assert line["action"] == "state_change" and line["target"] == "p@*"
    assert line["actor"] == "auto:unknown" and line["stdin_tty"] is False
    assert line["inputs"]["actor_source"] == "default"
    assert line["result"] == {
        "previous_state": "off",
        "state": "shadow",
        "cause": "set",
        "reason": "because",
        "triggered_by": None,
    }


def test_an_equal_row_is_a_no_op(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    do_set(capsys, config, "p", "shadow")
    first = row(state_dir, "p", "*")
    code, doc, _ = do_set(capsys, config, "p", "shadow")
    assert code == 0
    assert doc["changed"] is False and doc["scopes_changed"] == []
    assert doc["previous_state"] == doc["state"] == "shadow"
    assert row(state_dir, "p", "*") == first
    assert len(audit_lines(state_dir)) == 1


def test_an_absent_row_counts_as_a_change_even_when_the_state_is_the_same(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)  # the initial state is off
    code, doc, _ = do_set(capsys, config, "p", "off")
    assert code == 0 and doc["changed"] is True
    assert doc["previous_state"] == doc["state"] == "off"
    assert row(state_dir, "p", "*") is not None
    assert len(audit_lines(state_dir)) == 1


def test_a_repo_set_writes_only_that_repo_and_previous_state_is_the_effective_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    seed(state_dir, "p", "*", "enforced", fingerprint_=current_fingerprint(config, "p"))
    code, doc, _ = do_set(capsys, config, "p", "shadow", "--repo", REPO)
    assert code == 0
    assert (doc["scope"], doc["previous_state"], doc["state"]) == (REPO, "enforced", "shadow")
    assert doc["scopes_changed"] == [REPO]
    found = rows(state_dir, "p")
    assert found["*"].state == "enforced" and found[REPO].state == "shadow"
    assert audit_lines(state_dir)[0]["target"] == f"p@{REPO}"


def test_repo_star_names_the_global_scope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    code, doc, _ = do_set(capsys, config, "p", "shadow", "--repo", "*")
    assert code == 0 and doc["scope"] == "*"
    assert set(rows(state_dir, "p")) == {"*"}


def test_a_global_set_never_rewrites_a_repo_row(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    before = seed(state_dir, "p", REPO, "enforced")
    code, doc, _ = do_set(capsys, config, "p", "off")
    assert code == 0 and doc["scopes_changed"] == ["*"]
    assert rows(state_dir, "p")[REPO] == before


# --- enforced, re-enforcement -------------------------------------------------------------


def test_a_human_can_enforce_and_the_row_carries_the_fingerprint(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    code, doc, _ = do_set(capsys, config, "p", "enforced", *HUMAN)
    assert code == 0 and doc["state"] == "enforced" and doc["changed"] is True
    stored = row(state_dir, "p", "*")
    assert stored is not None
    assert stored.set_by == "human:ann"
    assert stored.fingerprint == current_fingerprint(config, "p")
    line = audit_lines(state_dir)[0]
    assert line["actor"] == "human:ann" and line["inputs"]["actor_source"] == "flag"


def test_enforcing_an_already_current_enforced_row_is_a_no_op(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    do_set(capsys, config, "p", "enforced", *HUMAN)
    code, doc, _ = do_set(capsys, config, "p", "enforced", *HUMAN)
    assert code == 0 and doc["changed"] is False and doc["scopes_changed"] == []
    assert len(audit_lines(state_dir)) == 1


def test_re_enforcing_a_stale_row_writes_a_new_fingerprint_and_audit_record(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    old = seed(state_dir, "p", "*", "enforced", fingerprint_=STALE)
    code, doc, _ = do_set(capsys, config, "p", "enforced", *HUMAN)
    assert code == 0 and doc["changed"] is True and doc["scopes_changed"] == ["*"]
    assert doc["previous_state"] == doc["state"] == "enforced"
    new = row(state_dir, "p", "*")
    assert new is not None
    assert new.fingerprint == current_fingerprint(config, "p") != STALE
    assert new.set_by == "human:ann" and new.set_at != old.set_at and new.rev > old.rev
    line = audit_lines(state_dir)[0]
    assert line["result"]["previous_state"] == line["result"]["state"] == "enforced"
    schema_util.assert_valid("audit", line)


def test_a_repo_row_is_compared_with_its_own_override_definition(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(
        tmp_path,
        {"p": RULE_POLICY},
        repos={
            REPO: {"policies": {"p": {"timeout": "30s", "checks": [SCRIPT_POLICY["checks"][0]]}}}
        },
    )
    own = current_fingerprint(config, "p", REPO)
    assert own != current_fingerprint(config, "p", "*")
    seed(state_dir, "p", REPO, "enforced", fingerprint_=own)
    code, doc, _ = do_set(capsys, config, "p", "enforced", "--repo", REPO, *HUMAN)
    assert code == 0 and doc["changed"] is False
    seed(state_dir, "p", OTHER, "enforced", fingerprint_=own)  # the global definition differs
    _, doc, _ = do_set(capsys, config, "p", "enforced", "--repo", OTHER, *HUMAN)
    assert doc["changed"] is True


def test_lowering_an_enforced_row_is_a_change(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    seed(state_dir, "p", "*", "enforced", fingerprint_=current_fingerprint(config, "p"))
    code, doc, _ = do_set(capsys, config, "p", "off")
    assert code == 0 and (doc["previous_state"], doc["state"]) == ("enforced", "off")


# --- set --all ----------------------------------------------------------------------------


def test_all_with_enforced_or_with_repo_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    for args in (
        ("p", "enforced", "--all", *HUMAN),
        ("p", "off", "--all", "--repo", REPO),
        ("p", "off", "--all", "--repo", "*"),
    ):
        code, doc, _ = do_set(capsys, config, *args)
        assert code == 2 and doc["error"]["code"] == "usage"
    assert not (state_dir / "state.db").exists()
    assert audit_lines(state_dir) == []


def test_all_writes_the_star_row_and_every_stored_row_in_one_call(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    seed(state_dir, "p", "*", "enforced", fingerprint_=current_fingerprint(config, "p"))
    seed(state_dir, "p", REPO, "enforced")
    seed(state_dir, "p", OTHER, "shadow")
    seed(state_dir, "q", "*", "enforced")  # another policy: untouched
    code, doc, _ = do_set(capsys, config, "p", "shadow", "--all")
    assert code == 0
    assert doc["scope"] == "*" and (doc["previous_state"], doc["state"]) == ("enforced", "shadow")
    assert doc["changed"] is True and doc["scopes_changed"] == ["*", REPO]
    found = rows(state_dir, "p")
    assert {s: r.state for s, r in found.items()} == {
        "*": "shadow",
        REPO: "shadow",
        OTHER: "shadow",
    }
    assert rows(state_dir, "q")["*"].state == "enforced"
    lines = audit_lines(state_dir)
    assert [ln["target"] for ln in lines] == ["p@*", f"p@{REPO}"]
    assert all(ln["result"]["state"] == "shadow" for ln in lines)
    assert [ln["result"]["previous_state"] for ln in lines] == ["enforced", "enforced"]
    for ln in lines:
        schema_util.assert_valid("audit", ln)


def test_all_with_no_rows_creates_the_star_row_from_the_initial_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    code, doc, _ = do_set(capsys, config, "p", "off", "--all")
    assert code == 0 and doc["changed"] is True and doc["scopes_changed"] == ["*"]
    assert doc["previous_state"] == "off"
    assert set(rows(state_dir, "p")) == {"*"}


def test_all_leaves_equal_rows_alone(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    star = seed(state_dir, "p", "*", "off")
    repo = seed(state_dir, "p", REPO, "off")
    code, doc, _ = do_set(capsys, config, "p", "off", "--all")
    assert code == 0 and doc["changed"] is False and doc["scopes_changed"] == []
    assert rows(state_dir, "p") == {"*": star, REPO: repo}
    assert audit_lines(state_dir) == []


def test_all_reports_a_changed_repo_row_even_when_the_star_row_is_equal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    seed(state_dir, "p", "*", "off")
    seed(state_dir, "p", REPO, "enforced")
    code, doc, _ = do_set(capsys, config, "p", "off", "--all")
    assert code == 0 and doc["changed"] is True and doc["scopes_changed"] == [REPO]
    assert (doc["previous_state"], doc["state"]) == ("off", "off")


def test_a_failed_audit_line_rolls_back_every_row_of_all(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = make_config(tmp_path)
    seed(state_dir, "p", "*", "enforced")
    seed(state_dir, "p", REPO, "enforced")
    real = audit._write
    calls = {"n": 0}

    def flaky(fd: int, data: bytes) -> int:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError(28, "no space")
        return real(fd, data)

    monkeypatch.setattr(audit, "_write", flaky)
    code, doc, _ = do_set(capsys, config, "p", "off", "--all")
    assert code == 1 and doc["error"]["code"] == "internal"
    assert {s: r.state for s, r in rows(state_dir, "p").items()} == {
        "*": "enforced",
        REPO: "enforced",
    }
    assert InternalError  # AuditWriteError is an InternalError (exit 1)


def test_a_failed_audit_line_leaves_no_row_for_a_single_set(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = make_config(tmp_path)

    def broken(fd: int, data: bytes) -> int:
        raise OSError(28, "no space")

    monkeypatch.setattr(audit, "_write", broken)
    code, _, _ = do_set(capsys, config, "p", "shadow")
    assert code == 1
    assert count_rows(state_dir) == 0


def test_caller_decision_ids_are_recorded_in_the_audit_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    do_set(capsys, config, "p", "shadow", "--decision-id", "hook:1", "--decision-id", "b2")
    line = audit_lines(state_dir)[0]
    assert line["inputs"]["decision_ids"] == ["hook:1", "b2"]
    assert line["decision_id"] == ["hook:1", "b2"]
    schema_util.assert_valid("audit", line)


# --- removed, unknown and invalid policies -------------------------------------------------


def test_a_removed_policy_can_be_lowered_but_not_enforced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path, {"p": RULE_POLICY})
    seed(state_dir, "gone", REPO, "enforced")
    code, doc, _ = do_set(capsys, config, "gone", "shadow")
    assert code == 0 and doc["changed"] is True and doc["scopes_changed"] == ["*"]
    stored = row(state_dir, "gone", "*")
    assert stored is not None and stored.fingerprint == MARKER
    code, doc, _ = do_set(capsys, config, "gone", "off", "--all")
    assert code == 0 and doc["scopes_changed"] == ["*", REPO]
    stored = row(state_dir, "gone", REPO)
    assert stored is not None and stored.fingerprint == MARKER
    before = rows(state_dir, "gone")
    code, doc, _ = do_set(capsys, config, "gone", "enforced", *HUMAN)
    assert code == 2 and doc["error"]["code"] == "usage"
    assert rows(state_dir, "gone") == before


def test_a_removed_policy_known_only_from_its_decisions_can_be_lowered(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    seed_decision(state_dir, "gone", REPO)
    code, doc, _ = do_set(capsys, config, "gone", "shadow", "--repo", REPO)
    assert code == 0 and doc["changed"] is True


def test_an_unknown_policy_exits_2_and_creates_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    for state in ("off", "shadow"):
        code, doc, _ = do_set(capsys, config, "nope", state)
        assert code == 2 and doc["error"]["details"]["kind"] == "unknown_policy"
    code, _, _ = do_set(capsys, config, "nope", "enforced", *HUMAN)
    assert code == 2
    assert not state_dir.exists()


def test_a_bad_policy_name_exits_2_without_echoing_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    for name in ("Bad", "../x", "a" * 65, "p\n", "", "p;rm"):
        code, out, _ = run(capsys, ["set", name, "off", "--config", config, "--json"])
        assert code == 2
        assert len(name.strip()) < 3 or name.strip() not in out
    assert not state_dir.exists()


def test_an_invalid_policy_can_still_be_lowered_but_not_enforced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path, {"p": {"timeout": "0s", "checks": [RULE_POLICY["checks"][0]]}})
    code, doc, _ = do_set(capsys, config, "p", "off", "--all")
    assert code == 0 and doc["changed"] is True
    stored = row(state_dir, "p", "*")
    assert stored is not None and stored.fingerprint == MARKER
    code, _, _ = do_set(capsys, config, "p", "enforced", *HUMAN)
    assert code == 2


def test_a_shared_config_problem_stops_enforced_but_not_the_kill_switch(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path, {"p": RULE_POLICY}, hooks={"bogus": 1})
    code, doc, err = do_set(capsys, config, "p", "off", "--all")
    assert code == 0 and doc["changed"] is True
    assert "config_problem" in err
    code, doc, _ = do_set(capsys, config, "p", "enforced", *HUMAN)
    assert code == 2 and doc["error"]["code"] == "config_invalid"
    code, _, err = do_set(capsys, config, "p", "shadow", "--all", "--quiet")
    assert code == 0 and err == ""


# --- hints --------------------------------------------------------------------------------

NO_PROBE = "validate --probe"
NO_DET = "no script or rule check"
NO_DECISION = "recorded decision"


def hint_of(capsys: pytest.CaptureFixture[str], config: str, *args: str) -> str | None:
    code, doc, _ = do_set(capsys, config, "p", "enforced", *HUMAN, *args)
    assert code == 0
    hint = doc["hint"]
    assert hint is None or isinstance(hint, str)
    return hint


def test_an_agent_only_policy_gets_the_probe_and_the_no_deterministic_check_hints(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path, {"p": AGENT_ONLY})
    hint = hint_of(capsys, config)
    assert hint is not None
    assert NO_PROBE in hint and NO_DET in hint and NO_DECISION not in hint
    first, second = hint.split(" ", 1)[0], hint
    assert first and second
    assert "\n" not in hint


def test_a_rule_policy_with_no_agent_check_gets_no_hint(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    assert hint_of(capsys, config) is None


def test_a_policy_with_only_an_agent_check_and_a_rule_gets_the_probe_hint_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(
        tmp_path, {"p": {"checks": [AGENT_ONLY["checks"][0], RULE_POLICY["checks"][0]]}}
    )
    hint = hint_of(capsys, config)
    assert hint is not None and NO_PROBE in hint and NO_DET not in hint


def test_a_matching_probe_marker_silences_the_probe_hint_and_a_stale_one_does_not(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    from gatectl import agenthash
    from gatectl.config import load_config

    config = make_config(
        tmp_path, {"p": {"checks": [AGENT_ONLY["checks"][0], RULE_POLICY["checks"][0]]}}
    )
    loaded = load_config(config)
    current = agenthash.agent_config_hash(loaded.shared, loaded.session_cmd_resolved())
    set_meta(state_dir, "probe_ok_at", "2026-01-01T00:00:00.000000Z")
    set_meta(state_dir, "probe_agent_hash", ALIEN)
    hint = hint_of(capsys, config)
    assert hint is not None and NO_PROBE in hint
    set_meta(state_dir, "probe_agent_hash", current)
    seed(state_dir, "p", "*", "shadow")
    assert hint_of(capsys, config) is None
    set_meta(state_dir, "probe_ok_at", "")  # no successful probe recorded
    seed(state_dir, "p", "*", "shadow")
    hint = hint_of(capsys, config)
    assert hint is not None and NO_PROBE in hint


def test_the_agent_hash_follows_the_agent_block_the_session_cmd_and_the_version() -> None:
    from gatectl import agenthash
    from gatectl.config_models import SharedConfig

    a = SharedConfig()
    b = SharedConfig.model_validate({"agent": {"timeout": "90s"}})
    h = agenthash.agent_config_hash
    assert h(a, ["/x/cs"]) == h(SharedConfig(), ["/x/cs"])
    assert h(a, ["/x/cs"]) != h(b, ["/x/cs"])
    assert h(a, ["/x/cs"]) != h(a, ["/y/cs"])
    assert h(a, None) != h(a, ["/x/cs"])
    assert h(a, ["/x/cs"]).startswith("sha256:") and len(h(a, ["/x/cs"])) == 71


def test_a_repo_with_no_recorded_decision_gets_the_spelling_hint(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    hint = hint_of(capsys, config, "--repo", REPO)
    assert hint is not None and NO_DECISION in hint and NO_PROBE not in hint
    seed_decision(state_dir, "p", OTHER)
    hint = hint_of(capsys, config, "--repo", OTHER)
    assert hint is None
    assert hint_of(capsys, config) is None  # the global scope never gets this hint


def test_all_three_hints_are_joined_by_one_space_each(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path, {"p": AGENT_ONLY})
    hint = hint_of(capsys, config, "--repo", REPO)
    assert hint is not None
    assert NO_PROBE in hint and NO_DET in hint and NO_DECISION in hint
    assert "  " not in hint and hint == hint.strip()
    assert hint.index(NO_PROBE) < hint.index(NO_DET) < hint.index(NO_DECISION)


def test_off_and_shadow_never_carry_a_hint(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path, {"p": AGENT_ONLY})
    for state in ("off", "shadow"):
        _, doc, _ = do_set(capsys, config, "p", state, "--repo", REPO)
        assert doc["hint"] is None


# --- reasons ------------------------------------------------------------------------------


def reason_of(state_dir: Path) -> str | None:
    value = audit_lines(state_dir)[-1]["result"]["reason"]
    assert value is None or isinstance(value, str)
    return value


def test_a_reason_file_is_recorded_sanitized_and_never_echoed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    path = tmp_path / "reason.txt"
    path.write_bytes(b"CANARY-9 why\x1b[31m red\ttab\n")
    code, out_doc, err = do_set(capsys, config, "p", "shadow", "--reason-file", str(path))
    assert code == 0 and err == ""
    assert "CANARY-9" not in str(out_doc)
    recorded = reason_of(state_dir)
    assert recorded is not None and recorded.startswith("CANARY-9 why")
    assert "\x1b" not in recorded and "\t" not in recorded and not recorded.endswith("\n")


def test_a_long_reason_is_cut_to_1_kib(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    path = tmp_path / "reason.txt"
    path.write_bytes(b"x" * 5000)
    code, _, _ = do_set(capsys, config, "p", "shadow", "--reason-file", str(path))
    assert code == 0 and reason_of(state_dir) == "x" * 1024


def test_an_empty_reason_is_null(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    path = tmp_path / "reason.txt"
    path.write_bytes(b"\n")
    do_set(capsys, config, "p", "shadow", "--reason-file", str(path))
    assert reason_of(state_dir) is None


def test_invalid_utf8_and_unicode_in_a_reason_stay_ascii_in_the_audit_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    path = tmp_path / "reason.txt"
    path.write_bytes("café ‮ \xff".encode("latin-1", "ignore") + b"\xff\xfe")
    code, _, _ = do_set(capsys, config, "p", "shadow", "--reason-file", str(path))
    assert code == 0
    assert (state_dir / "audit.jsonl").read_bytes().isascii()
    recorded = reason_of(state_dir)
    assert recorded is not None and "‮" not in recorded


@pytest.mark.parametrize("kind", ["missing", "directory", "fifo"])
def test_an_unusable_reason_file_exits_2_and_changes_nothing(
    kind: str, tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    import os

    config = make_config(tmp_path)
    target = tmp_path / "r"
    if kind == "directory":
        target.mkdir()
    elif kind == "fifo":
        os.mkfifo(target)
    code, doc, _ = do_set(capsys, config, "p", "shadow", "--reason-file", str(target))
    assert code == 2 and doc["error"]["code"] == "usage"
    assert str(target) not in str(doc)
    assert not (state_dir / "state.db").exists()


def test_a_reason_from_stdin_is_read_and_a_stalled_stdin_is_a_usage_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os

    config = make_config(tmp_path)
    r, w = os.pipe()
    try:
        os.write(w, b"from stdin")
        os.close(w)
        w = -1
        monkeypatch.setattr(setcmd, "STDIN_FD", r)
        code, _, _ = do_set(capsys, config, "p", "shadow", "--reason-file", "-")
        assert code == 0 and reason_of(state_dir) == "from stdin"
    finally:
        os.close(r)
        if w >= 0:
            os.close(w)
    r, w = os.pipe()  # a writer that never closes
    try:
        monkeypatch.setattr(setcmd, "STDIN_FD", r)
        monkeypatch.setattr(setcmd, "REASON_WAIT_SECONDS", 0.2)
        code, _, _ = do_set(capsys, config, "p", "off", "--reason-file", "-")
        assert code == 2
        stored = row(state_dir, "p", "*")
        assert stored is not None and stored.state == "shadow"
    finally:
        os.close(r)
        os.close(w)


# --- storage failures ----------------------------------------------------------------------


def test_a_missing_state_db_next_to_an_audit_history_exits_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    state_dir.mkdir(parents=True)
    (state_dir / "audit.jsonl").write_bytes(b'{"ts":"x"}\n')
    code, doc, _ = do_set(capsys, config, "p", "shadow")
    assert code == 1 and doc["error"]["reason"] == "state_db_missing"
    assert not (state_dir / "state.db").exists()


def test_the_store_is_a_real_database_after_a_set(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make_config(tmp_path)
    do_set(capsys, config, "p", "shadow")
    s = store.open_store(state_dir, create=False)
    assert s is not None
    with s:
        assert s.schema_version() == store.latest_version()


def test_a_failed_all_leaves_no_audit_line_for_a_rolled_back_row(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = make_config(tmp_path)
    seed(state_dir, "p", "*", "enforced")
    seed(state_dir, "p", REPO, "enforced")
    real = audit.encode_line
    calls = {"n": 0}

    def flaky(record: Mapping[str, Any], **kw: bool) -> bytes:
        calls["n"] += 1
        if calls["n"] == 2:
            raise ValueError("unencodable")
        return real(record, **kw)

    monkeypatch.setattr(audit, "encode_line", flaky)
    code, doc, _ = do_set(capsys, config, "p", "off", "--all")
    assert code == 1 and doc["error"]["code"] == "internal"
    assert audit_lines(state_dir) == []
    assert {r.state for r in rows(state_dir, "p").values()} == {"enforced"}


def test_the_audit_lines_are_appended_inside_the_transaction(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = make_config(tmp_path)
    seen: list[bool] = []
    real = store.Store.append_audit_many

    def spy(self: store.Store, records: Sequence[Mapping[str, Any]]) -> None:
        seen.append(self.con.in_transaction)
        real(self, records)

    monkeypatch.setattr(store.Store, "append_audit_many", spy)
    code, _, _ = do_set(capsys, config, "p", "shadow")
    assert code == 0 and seen == [True]


def test_the_set_time_is_taken_inside_the_transaction(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = make_config(tmp_path)
    events: list[str] = []
    real_begin = store.Store._begin
    real_now = setcmd.now_ts

    def begin(self: store.Store) -> None:
        events.append("begin")
        real_begin(self)

    def now() -> str:
        events.append("now")
        return real_now()

    monkeypatch.setattr(store.Store, "_begin", begin)
    monkeypatch.setattr(setcmd, "now_ts", now)
    code, _, _ = do_set(capsys, config, "p", "shadow")
    assert code == 0
    assert events.index("now") > events.index("begin")


def test_all_refuses_a_partial_set_past_the_row_limit(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = make_config(tmp_path)
    seed(state_dir, "p", "*", "enforced")
    seed(state_dir, "p", REPO, "enforced")
    seed(state_dir, "p", OTHER, "enforced")
    seed(state_dir, "p", "github.com/org/third", "enforced")
    monkeypatch.setattr(store, "_ROW_LIMIT", 3)
    code, doc, _ = do_set(capsys, config, "p", "off", "--all")
    assert code == 1 and doc["error"]["code"] == "internal"
    assert {r.state for r in rows(state_dir, "p").values()} == {"enforced"}
    assert audit_lines(state_dir) == []


def test_all_accepts_exactly_the_row_limit(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = make_config(tmp_path)
    seed(state_dir, "p", "*", "enforced")
    seed(state_dir, "p", REPO, "enforced")
    seed(state_dir, "p", OTHER, "enforced")
    monkeypatch.setattr(store, "_ROW_LIMIT", 3)
    code, _doc, _ = do_set(capsys, config, "p", "off", "--all")
    assert code == 0
    assert {r.state for r in rows(state_dir, "p").values()} == {"off"}


def test_a_stdin_closed_at_launch_reads_as_empty_and_is_valid_afterwards(
    tmp_path: Path, state_dir: Path
) -> None:
    import os
    import subprocess
    import sys

    config = make_config(tmp_path)
    script = (
        "import os, sys\n"
        "from gatectl.cli import main\n"
        "code = main(sys.argv[1:])\n"
        "os.fstat(0)\n"  # descriptor 0 must be valid, not free for any later open
        "assert os.get_inheritable(0)\n"  # and survive exec into children
        "sys.exit(code)\n"
    )
    env = {
        "HOME": str(tmp_path / "home"),
        "XDG_CONFIG_HOME": str(tmp_path / "home" / "config"),
        "XDG_STATE_HOME": str(tmp_path / "home" / "state"),
        "PATH": os.environ.get("PATH", ""),
        "LC_ALL": "C",
    }
    argv = [sys.executable, "-I", "-c", script]
    argv += ["set", "p", "off", "--reason-file", "-", "--config", config, "--json"]

    def close_stdin() -> None:
        os.close(0)

    proc = subprocess.run(  # noqa: S603
        argv,
        capture_output=True,
        env={**env, "PYTHONPATH": os.pathsep.join(sys.path)},
        preexec_fn=close_stdin,  # noqa: PLW1509
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert audit_lines(state_dir)[0]["result"]["reason"] is None
