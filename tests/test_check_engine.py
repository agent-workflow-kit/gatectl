"""``gatectl check`` end to end for rule-only policies: states, exit codes, recording."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests import schema_util
from tests.check_util import (
    HUMAN,
    OTHER,
    REPO,
    audit_lines,
    decisions,
    do_check,
    do_set,
    isolate,
    log_lines,
    write_input,
)
from tests.command_util import CANARY, config_file, run

CI = {
    "name": "ci-green",
    "type": "rule",
    "when": [{"path": "ci.state", "op": "ne", "value": "passing"}],
    "then": "deny",
}
GUARD = {
    "name": "guard",
    "type": "rule",
    "when": [{"path": "hold", "op": "eq", "value": True}],
    "then": "escalate",
}
GOOD = {"ci": {"state": "passing"}, "repo": REPO, "head": "abc"}
BAD = {"ci": {"state": "failing"}, "repo": REPO, "head": "abc"}


@pytest.fixture
def sdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def cfg(tmp_path: Path, checks: list[dict[str, Any]] | None = None, **policy: Any) -> str:
    body = {"checks": checks if checks is not None else [CI], **policy}
    return config_file(tmp_path, {"policies": {"p": body}})


def enforce(capsys: pytest.CaptureFixture[str], config: str, *args: str) -> None:
    do_set(capsys, config, "p", "enforced", *args)


def test_an_enforced_deny_exits_11_with_one_stderr_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    enforce(capsys, config)
    src = write_input(tmp_path, BAD)
    code, doc, err = do_check(capsys, config, "p", "--input", src, "--actor", "auto:t")
    assert code == 11
    assert (doc["decision"], doc["reason"], doc["state"]) == ("deny", "check_denied", "enforced")
    assert (doc["shadow"], doc["enforced"], doc["scope"]) == (False, True, REPO)
    decision_id = doc["decision_id"]
    assert err == f"gatectl: deny p@{REPO}: check_denied (ci-green) {decision_id}\n"
    assert doc["checks"] == [
        {
            "name": "ci-green",
            "type": "rule",
            "verdict": "deny",
            "reason": "check_denied",
            "detail": None,
            "duration_ms": doc["checks"][0]["duration_ms"],
        }
    ]


def test_an_enforced_escalate_exits_13_and_names_the_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, [GUARD])
    enforce(capsys, config)
    src = write_input(tmp_path, {"hold": True})
    code, doc, err = do_check(capsys, config, "p", "--input", src)
    assert code == 13
    assert (doc["decision"], doc["reason"], doc["scope"]) == ("escalate", "check_escalated", "*")
    assert err == f"gatectl: escalate p@*: check_escalated (guard) {doc['decision_id']}\n"


def test_an_enforced_allow_exits_0_with_enforced_true_and_no_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    enforce(capsys, config)
    code, doc, err = do_check(capsys, config, "p", "--input", write_input(tmp_path, GOOD))
    assert (code, err) == (0, "")
    assert (doc["decision"], doc["reason"]) == ("allow", "all_passed")
    assert (doc["shadow"], doc["enforced"]) == (False, True)


def test_a_shadow_deny_exits_0_and_prints_shadow_true(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    code, doc, err = do_check(capsys, config, "p", "--input", write_input(tmp_path, BAD))
    assert (code, err) == (0, "")
    assert (doc["decision"], doc["state"]) == ("deny", "shadow")
    assert (doc["shadow"], doc["enforced"]) == (True, False)


def test_the_decision_row_and_the_audit_line_are_recorded_together(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(
        tmp_path,
        input={"require": ["head"], "types": {"head": "string"}},
    )
    payload = {**GOOD, "tool": "gh", "hook": "pre", "object_type": "pr", "object_id": "7"}
    code, doc, _ = do_check(
        capsys, config, "p", "--input", write_input(tmp_path, payload), "--actor", "auto:ci"
    )
    assert code == 0
    [row] = decisions(sdir)
    assert row["id"] == doc["decision_id"] and row["policy"] == "p" and row["scope"] == REPO
    assert (row["decision"], row["reason"], row["state"]) == ("allow", "all_passed", "shadow")
    assert row["fingerprint"] == doc["fingerprint"] and row["actor"] == "auto:ci"
    assert (row["tool"], row["hook"], row["object_type"], row["object_id"]) == (
        "gh",
        "pre",
        "pr",
        "7",
    )
    assert row["repo"] == REPO and row["input_sha256"] == doc["input_sha256"]
    assert json.loads(row["declared_json"]) == {"head": "abc"}
    assert row["state_rev"] is None and row["input_json"] is None
    stored = json.loads(row["checks_json"])
    assert [(c["name"], c["verdict"]) for c in stored] == [("ci-green", "allow")]
    [line] = [r for r in audit_lines(sdir) if r["action"] == "decision"]
    schema_util.assert_valid("audit", line)
    assert line["decision_id"] == doc["decision_id"] and line["target"] == f"p@{REPO}"
    assert line["ts"] == row["time"] and line["actor"] == "auto:ci"
    assert line["inputs"]["input_sha256"] == doc["input_sha256"]
    assert line["result"] == {
        "decision": "allow",
        "reason": "all_passed",
        "state": "shadow",
        "shadow": True,
        "enforced": False,
    }


def test_the_result_never_carries_input_text(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, [CI])
    src = write_input(tmp_path, {**BAD, "note": CANARY, "ci": {"state": CANARY}})
    code, out, err = run(capsys, ["check", "p", "--config", config, "--input", src])
    assert code == 0 and CANARY not in out and CANARY not in err
    assert CANARY not in (sdir / "audit.jsonl").read_text()


def test_decision_id_and_input_sha256_are_present_exactly_when_recorded(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    code, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, GOOD))
    assert code == 0 and "decision_id" in doc and len(doc["input_sha256"]) == 64
    assert doc["warnings"] == [] and doc["error"] is None


def test_a_rule_error_escalates_with_the_path_and_problem(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    enforce(capsys, config)
    code, doc, err = do_check(capsys, config, "p", "--input", write_input(tmp_path, {"x": 1}))
    assert code == 13
    [entry] = doc["checks"]
    assert (entry["verdict"], entry["reason"], entry["detail"]) == (
        "escalate",
        "check_error",
        "ci.state: missing",
    )
    assert doc["reason"] == "check_error"
    assert err.startswith("gatectl: escalate p@*: check_error (ci-green) gd-")


@pytest.mark.parametrize(
    "content",
    [b"not json", b"[1]", b"", b'{"a":1}{"b":2}', b'{"a":1,"a":2}', b"\xff\xfe", b'{"a":NaN}'],
)
def test_an_unusable_input_escalates_input_invalid_with_no_checks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, content: bytes
) -> None:
    import hashlib

    config = cfg(tmp_path)
    enforce(capsys, config)
    code, doc, err = do_check(capsys, config, "p", "--input", write_input(tmp_path, content))
    assert code == 13
    assert (doc["decision"], doc["reason"], doc["checks"], doc["scope"]) == (
        "escalate",
        "input_invalid",
        [],
        "*",
    )
    assert doc["input_sha256"] == hashlib.sha256(content).hexdigest()
    assert err == f"gatectl: escalate p@*: input_invalid {doc['decision_id']}\n"
    [row] = decisions(sdir)
    assert row["declared_json"] is None and row["tool"] is None and row["case_key"] is None


def test_an_input_over_the_cap_is_input_invalid_and_hashes_the_bytes_read(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    import hashlib

    config = config_file(
        tmp_path, {"policies": {"p": {"checks": [CI]}}, "defaults": {"input_max_bytes": 1000}}
    )
    big = b'{"a":"' + b"x" * 5000 + b'"}'
    code, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, big))
    assert code == 0 and doc["reason"] == "input_invalid" and doc["checks"] == []
    assert doc["input_sha256"] == hashlib.sha256(big[:1001]).hexdigest()


def test_a_declaration_failure_records_null_declared_fields(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, input={"require": ["head"]})
    payload = {"tool": "gh", "object_id": "7"}
    code, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, payload))
    assert code == 0 and (doc["decision"], doc["reason"]) == ("escalate", "input_invalid")
    [row] = decisions(sdir)
    assert row["declared_json"] is None and row["tool"] is None and row["object_id"] is None


def test_an_invalid_payload_repo_is_indeterminate_and_warns(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    code, doc, _ = do_check(
        capsys, config, "p", "--input", write_input(tmp_path, {**GOOD, "repo": "Not A Repo"})
    )
    assert code == 0
    assert (doc["decision"], doc["reason"], doc["scope"]) == ("escalate", "input_invalid", "*")
    assert doc["warnings"] == ["repo_invalid"] and doc["checks"] == []
    [row] = decisions(sdir)
    assert row["repo"] is None and row["state_rev"] is None


def test_an_indeterminate_scope_takes_the_strictest_stored_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    do_set(capsys, config, "p", "shadow")
    do_set(capsys, config, "p", "enforced", "--repo", OTHER)
    bad_repo = write_input(tmp_path, {"repo": 5})
    code, doc, err = do_check(capsys, config, "p", "--input", bad_repo)
    assert code == 13 and doc["state"] == "enforced"
    assert err.startswith("gatectl: escalate p@*: input_invalid gd-")


def test_an_indeterminate_scope_honors_set_all_off(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    do_set(capsys, config, "p", "enforced", "--repo", OTHER)
    do_set(capsys, config, "p", "off", "--all")
    code, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, b"junk"))
    assert code == 0 and doc["state"] == "off" and doc["decision"] is None
    assert "decision_id" not in doc and decisions(sdir) == []


def test_an_indeterminate_scope_without_rows_uses_the_initial_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, state="off")
    code, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, b"junk"))
    assert code == 0 and doc["state"] == "off"


def test_the_flag_repo_is_the_scope_and_a_mismatch_warns(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    code, doc, _ = do_check(
        capsys, config, "p", "--input", write_input(tmp_path, GOOD), "--repo", OTHER
    )
    assert code == 0 and doc["scope"] == OTHER and doc["warnings"] == ["repo_mismatch"]
    [row] = decisions(sdir)
    assert row["scope"] == OTHER and row["repo"] == OTHER


def test_off_prints_the_off_result_and_records_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, state="off")
    code, doc, err = do_check(capsys, config, "p", "--input", write_input(tmp_path, BAD))
    assert (code, err) == (0, "")
    assert (doc["state"], doc["decision"], doc["reason"], doc["checks"]) == ("off", None, None, [])
    assert (doc["shadow"], doc["enforced"]) == (False, False)
    assert "decision_id" not in doc and "input_sha256" not in doc
    assert decisions(sdir) == [] and audit_lines(sdir) == []
    assert [e["event"] for e in log_lines(sdir)] == ["check_off"]


def test_unknown_policy_and_bad_timeout_exit_2_with_the_fixed_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    code, out, err = run(capsys, ["check", "nope", "--config", config, "--input", "x"])
    assert code == 2 and err == "gatectl: usage nope\n"
    assert json.loads(out)["error"]["code"] == "usage"
    code, out, err = run(
        capsys,
        [
            "check",
            "p",
            "--config",
            config,
            "--input",
            write_input(tmp_path, GOOD),
            "--timeout",
            "-1",
        ],
    )
    assert code == 2 and err == "gatectl: usage p\n"
    assert decisions(sdir) == []


def test_a_missing_input_file_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    code, _, err = run(capsys, ["check", "p", "--config", config, "--input", str(tmp_path / "no")])
    assert code == 2 and err == "gatectl: usage p\n"


def test_stdin_that_is_a_terminal_without_input_is_a_usage_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from gatectl import inputs

    monkeypatch.setattr(inputs, "_is_tty", lambda fd: True)
    config = cfg(tmp_path)
    code, _, err = run(capsys, ["check", "p", "--config", config])
    assert code == 2 and err == "gatectl: usage p\n"


def test_the_first_deny_ends_the_run_and_the_reason_is_its_own(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, [GUARD, CI, {**CI, "name": "later"}])
    enforce(capsys, config)
    src = write_input(tmp_path, {"hold": True, "ci": {"state": "red"}})
    code, doc, err = do_check(capsys, config, "p", "--input", src)
    assert code == 11 and doc["reason"] == "check_denied"
    assert [(c["name"], c["verdict"]) for c in doc["checks"]] == [
        ("guard", "escalate"),
        ("ci-green", "deny"),
        ("later", "skipped"),
    ]
    skipped = doc["checks"][2]
    assert skipped == {
        "name": "later",
        "type": "rule",
        "verdict": "skipped",
        "reason": None,
        "detail": None,
        "duration_ms": 0,
    }
    assert "(ci-green)" in err


def test_an_escalate_does_not_stop_later_rule_checks(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, [GUARD, {**CI, "name": "second"}])
    src = write_input(tmp_path, {"hold": True, "ci": {"state": "passing"}})
    _, doc, _ = do_check(capsys, config, "p", "--input", src)
    assert [(c["name"], c["verdict"]) for c in doc["checks"]] == [
        ("guard", "escalate"),
        ("second", "allow"),
    ]
    assert (doc["decision"], doc["reason"]) == ("escalate", "check_escalated")


def test_the_reason_of_the_first_escalate_in_check_order_wins(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path, [CI, GUARD])
    _, doc, _ = do_check(capsys, config, "p", "--input", write_input(tmp_path, {"hold": True}))
    assert doc["reason"] == "check_error"  # ci.state is missing: the first escalate
    assert doc["checks"][1]["reason"] == "check_escalated"


def test_a_removed_policy_with_only_stored_rows_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path
) -> None:
    config = cfg(tmp_path)
    do_set(capsys, config, "p", "shadow")
    other = config_file(tmp_path / "x", {"policies": {"q": {"checks": [CI]}}})
    code, _, err = run(
        capsys, ["check", "p", "--config", other, "--input", write_input(tmp_path, GOOD)]
    )
    assert code == 2 and err == "gatectl: usage p\n"
    assert HUMAN
