"""``gatectl check``: failures after the state is known, state races, drift, actors, recording."""

from __future__ import annotations

import itertools
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from gatectl import audit, cli, engine, inputs, rules
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
from tests.command_util import CANARY, config_file, run

RULE = {
    "name": "r",
    "type": "rule",
    "when": [{"path": "ci", "op": "ne", "value": "ok"}],
    "then": "deny",
}


@pytest.fixture
def sdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def cfg(tmp_path: Path, top: dict[str, Any] | None = None, **policy: Any) -> str:
    body = {"checks": [RULE], **policy}
    return config_file(tmp_path, {"policies": {"p": body}, **(top or {})})


def good(tmp_path: Path) -> str:
    return write_input(tmp_path, {"ci": "ok"})


def break_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_: Any, **__: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(audit, "append_audit", fail)


# --- the audit line is part of the transaction ---------------------------------------------


def test_a_shadow_failure_exits_0_without_a_decision_id_and_logs_it(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = cfg(tmp_path)
    break_audit(monkeypatch)
    code, doc, err = do_check(capsys, config, "p", "--input", write_input(tmp_path, {"ci": "bad"}))
    assert code == 0
    assert "decision_id" not in doc and "input_sha256" not in doc
    assert (doc["decision"], doc["reason"], doc["state"], doc["shadow"]) == (
        "deny", "check_denied", "shadow", True,
    )  # fmt: skip
    assert doc["error"]["code"] == "internal" and doc["checks"][0]["verdict"] == "deny"
    assert err == "gatectl: warning shadow_failure p@*\n"
    assert decisions(sdir) == []  # the row never outlives a failed audit line
    assert [e["event"] for e in log_lines(sdir)] == ["shadow_failure"]


def test_an_enforced_failure_exits_1_with_the_envelope(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = cfg(tmp_path)
    do_set(capsys, config, "p", "enforced")
    break_audit(monkeypatch)
    code, doc, err = do_check(capsys, config, "p", "--input", good(tmp_path))
    assert code == 1 and doc["error"]["code"] == "internal"
    assert err == "gatectl: internal p\n"
    assert decisions(sdir) == []


def test_a_busy_database_retries_once_then_fails_by_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, {"defaults": {"record_reserve": "100ms"}})
    do_set(capsys, config, "p", "shadow")
    blocker = sqlite3.connect(sdir / "state.db", isolation_level=None)
    blocker.execute("BEGIN IMMEDIATE")
    try:
        code, doc, _ = do_check(capsys, config, "p", "--input", good(tmp_path))
        assert code == 0 and "decision_id" not in doc and doc["error"] is not None
        blocker.execute("COMMIT")
        do_set(capsys, config, "p", "enforced")
        blocker.execute("BEGIN IMMEDIATE")
        code, doc, err = do_check(capsys, config, "p", "--input", good(tmp_path))
        assert code == 1 and err == "gatectl: internal p\n"
    finally:
        blocker.close()
    assert decisions(sdir) == []


def test_an_unexpected_exception_in_a_check_is_a_failure_never_an_allow(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = cfg(tmp_path)

    def boom(*_: Any) -> Any:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(rules, "run_rule", boom)
    code, doc, err = do_check(capsys, config, "p", "--input", good(tmp_path))
    assert code == 0 and (doc["decision"], doc["reason"]) == ("escalate", "check_error")
    assert "decision_id" not in doc and CANARY not in json.dumps(doc) + err
    do_set(capsys, config, "p", "enforced")
    code, out, err = run(capsys, ["check", "p", "--config", config, "--input", good(tmp_path)])
    assert code == 1 and CANARY not in out + err and err == "gatectl: internal p\n"


def test_an_unreadable_state_database_is_exit_1_whatever_the_policy_says(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    do_set(capsys, config, "p", "enforced")
    (sdir / "state.db").write_bytes(b"this is not a database" * 100)
    code, out, err = run(capsys, ["check", "p", "--config", config, "--input", good(tmp_path)])
    assert code == 1 and err.startswith("gatectl: internal p")
    assert json.loads(out)["error"]["code"] == "internal"


def test_a_missing_database_next_to_an_audit_history_is_state_db_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    sdir.mkdir(parents=True)
    (sdir / "audit.jsonl").write_text('{"ts":"x"}\n')
    code, out, _ = run(capsys, ["check", "p", "--config", config, "--input", good(tmp_path)])
    assert code == 1 and json.loads(out)["error"]["reason"] == "state_db_missing"


# --- a set that commits while the checks run: the six state pairs ---------------------------

STATES = ("off", "shadow", "enforced")


@pytest.mark.parametrize(("before", "after"), [p for p in itertools.permutations(STATES, 2)])
def test_a_set_during_the_check_decides_the_recorded_state_the_flags_and_the_exit(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    before: str,
    after: str,
) -> None:
    config = cfg(tmp_path)
    do_set(capsys, config, "p", before)
    real = engine._checks_json

    def racing(entries: Any) -> str:
        monkeypatch.setattr(engine, "_checks_json", real)
        do_set(capsys, config, "p", after)
        return real(entries)

    monkeypatch.setattr(engine, "_checks_json", racing)
    code, doc, err = do_check(capsys, config, "p", "--input", write_input(tmp_path, {"ci": "bad"}))
    if before == "off":
        # off is decided at step 4, before any check runs: the set is not seen
        assert (doc["state"], doc["decision"], code) == ("off", None, 0)
        assert decisions(sdir) == []
        return
    if after == "off":
        assert (doc["state"], doc["decision"], doc["checks"], code) == ("off", None, [], 0)
        assert "decision_id" not in doc and decisions(sdir) == []
        assert audit_lines(sdir)[-1]["action"] == "state_change"
        return
    assert doc["state"] == after
    assert (doc["shadow"], doc["enforced"]) == (after == "shadow", after == "enforced")
    assert code == (11 if after == "enforced" else 0)
    [row] = decisions(sdir)
    assert row["state"] == after and row["id"] == doc["decision_id"]
    [line] = [r for r in audit_lines(sdir) if r["action"] == "decision"]
    assert line["result"]["state"] == after
    stored = rows(sdir, "SELECT rev FROM policy_state WHERE policy = 'p' AND scope = '*'")
    assert row["state_rev"] == stored[0][0]


# --- definition_changed ------------------------------------------------------------------------


def test_an_enforced_row_with_a_stale_fingerprint_warns_and_the_state_stands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    do_set(capsys, config, "p", "enforced")
    changed = cfg(tmp_path / "x", timeout="30s", checks=[{**RULE, "then": "escalate"}])
    code, doc, _ = do_check(capsys, changed, "p", "--input", write_input(tmp_path, {"ci": "bad"}))
    assert doc["warnings"] == ["definition_changed"] and doc["state"] == "enforced"
    assert code == 13
    code, doc, _ = do_check(capsys, config, "p", "--input", good(tmp_path))
    assert doc["warnings"] == [] and code == 0


def test_a_shadow_row_with_the_marker_fingerprint_never_warns(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    do_set(capsys, config, "p", "shadow")
    _, doc, _ = do_check(capsys, config, "p", "--input", good(tmp_path))
    assert doc["warnings"] == []


def test_the_dry_run_warns_too(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    do_set(capsys, config, "p", "enforced")
    changed = cfg(tmp_path / "x", checks=[{**RULE, "then": "escalate"}])
    code, out, _ = run(
        capsys, ["check", "p", "--dry-run", "--config", changed, "--input", good(tmp_path)]
    )
    assert code == 0 and json.loads(out)["warnings"] == ["definition_changed"]


# --- actors, recording -------------------------------------------------------------------------

HOSTILE = f"{CANARY}\x1b]0;x\x07‮\x00\n" + "y" * 500


def test_a_hostile_me_name_never_reaches_the_audit_log_or_the_output(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = cfg(tmp_path, {"me": {"name": HOSTILE}})
    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: True)
    code, out, err = run(capsys, ["check", "p", "--config", config, "--input", good(tmp_path)])
    assert code == 0
    [row] = decisions(sdir)
    assert row["actor"].startswith("human:") and len(row["actor"]) <= 70
    assert set(row["actor"][6:]) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._@-"
    )
    assert audit_lines(sdir)[0]["actor"] == row["actor"]
    assert "\x1b" not in out + err and "\x00" not in (sdir / "audit.jsonl").read_text()


def test_the_default_actor_without_a_tty_is_auto_unknown(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    do_check(capsys, cfg(tmp_path), "p", "--input", good(tmp_path))
    [row] = decisions(sdir)
    assert row["actor"] == "auto:unknown"
    assert audit_lines(sdir)[0]["inputs"]["actor_source"] == "default"


def test_the_callers_decision_ids_are_in_the_audit_line_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    code, doc, _ = do_check(
        capsys, cfg(tmp_path), "p", "--input", good(tmp_path), "--decision-id", "caller-1"
    )
    assert code == 0 and "caller-1" not in json.dumps(doc)
    assert audit_lines(sdir)[0]["inputs"]["decision_ids"] == ["caller-1"]


def test_record_input_stores_the_canonical_input_in_the_database_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, record_input=True)
    do_check(capsys, config, "p", "--input", write_input(tmp_path, {"ci": "ok", "z": CANARY}))
    [row] = decisions(sdir)
    assert json.loads(row["input_json"]) == {"ci": "ok", "z": CANARY}
    assert CANARY not in (sdir / "audit.jsonl").read_text()


def test_the_case_key_follows_the_object_or_the_input_without_ignored_keys(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, input={"require": ["head"], "ignore": ["ts"]})
    for ts in (1, 2):
        do_check(capsys, config, "p", "--input", write_input(tmp_path, {"head": "a", "ts": ts}))
    a, b = decisions(sdir)
    assert a["case_key"] == b["case_key"] and a["input_sha256"] != b["input_sha256"]
    do_check(capsys, config, "p", "--input", write_input(tmp_path, {"head": "b", "ts": 1}))
    assert decisions(sdir)[-1]["case_key"] != a["case_key"]


def test_the_case_key_of_an_object_ignores_other_fields(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    base = {"object_type": "pr", "object_id": "7", "head": "a"}
    assert inputs.case_key(None, base) == inputs.case_key(None, {**base, "other": 1})
    from gatectl.config_models import InputDecl

    d = InputDecl(require=["head"])
    assert inputs.case_key(d, base) != inputs.case_key(d, {**base, "head": "b"})
    assert inputs.case_key(d, base) == inputs.case_key(d, {**base, "other": 1})


def test_a_declared_value_set_that_is_too_large_to_store_is_input_invalid(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    keys = [f"k{i}" for i in range(200)]
    config = cfg(tmp_path, input={"require": keys})
    payload = {k: "x" * 250 for k in keys}
    code, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, payload))
    assert code == 0 and (doc["decision"], doc["reason"]) == ("escalate", "input_invalid")


def test_a_lone_surrogate_in_a_declared_string_is_rejected_by_the_parser(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, input={"require": ["head"]})
    raw = b'{"head": "\\ud800", "ci": "ok"}'
    _, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, raw))
    assert doc["reason"] == "input_invalid"


def test_applies_when_false_answers_not_applicable_in_every_state_and_records_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, applies_when=[{"path": "kind", "op": "eq", "value": "pr"}])
    do_set(capsys, config, "p", "enforced")
    code, doc, err = do_check(capsys, config, "p", "--input", write_input(tmp_path, {"kind": "x"}))
    assert (code, err) == (0, "")
    assert (doc["decision"], doc["reason"], doc["shadow"], doc["enforced"], doc["state"]) == (
        "allow", "not_applicable", False, False, "enforced",
    )  # fmt: skip
    assert "decision_id" not in doc and "input_sha256" not in doc and doc["checks"] == []
    assert decisions(sdir) == []
    # an error in applies_when counts as applicable
    code, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, {"ci": "bad"}))
    assert code == 11 and doc["reason"] == "check_denied"
    _ = REPO
