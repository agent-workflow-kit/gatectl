"""``gatectl outcome``: records, the effective-outcome rule, classification, ids, reasons, audit."""

from __future__ import annotations

import itertools
import os
import pty
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from gatectl import audit, history, outcomecmd, store
from tests import golden, schema_util
from tests.command_util import isolate, run
from tests.history_util import did, put_decision, put_outcome
from tests.outcome_util import (
    AUTO,
    HUMAN,
    ID,
    audit_lines,
    make_config,
    outcome,
    stored,
)


@pytest.fixture(autouse=True)
def state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


@pytest.fixture
def config(tmp_path: Path) -> str:
    return make_config(tmp_path)


# --- the golden output ------------------------------------------------------------------------


def test_the_golden_output_is_printed_byte_for_byte(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    code, out, _ = run(capsys, ["outcome", ID, "agree", "--config", config, "--json", *HUMAN])
    assert code == 0
    golden.assert_output("outcome", out)


# --- the effective-outcome rule ---------------------------------------------------------------

EVENTS = [
    ("human:a", "agree"),
    ("auto:b", "agree"),
    ("human:a", "disagree"),
    ("auto:b", "disagree"),
]


def seq_id(n: int) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    return "gd-" + alphabet[n // 1024] + alphabet[(n // 32) % 32] + alphabet[n % 32] + "k" * 9


def model(seq: Sequence[tuple[str, str]]) -> str:
    """The rule as written in interface.md: the last record that counts decides."""
    effective = "pending"
    for actor, verdict in seq:
        if verdict == "disagree" or actor.startswith("human:"):
            effective = verdict
    return effective


def test_the_effective_rule_matches_the_model_for_every_sequence_up_to_length_5(
    state_dir: Path,
) -> None:
    sequences = [s for n in range(6) for s in itertools.product(EVENTS, repeat=n)]
    ids = {}
    for n, seq in enumerate(sequences):
        decision_id = seq_id(n)
        ids[decision_id] = seq
        put_decision(state_dir, decision_id)
        for actor, verdict in seq:
            kind = "human" if actor.startswith("human:") else "automatic"
            put_outcome(state_dir, decision_id, verdict, actor=actor, kind=kind)
    s = store.open_store(state_dir, create=False)
    assert s is not None
    with s:
        for decision_id, seq in ids.items():
            assert history.effective_outcome(s, decision_id) == model(seq), seq


# (actor, actor_kind, outcome): the rule keys on the actor prefix, never on the kind column.
ODD_EVENTS = [
    ("human:a", "human", "agree"),
    ("human:a", "automatic", "agree"),  # kind disagrees with the prefix: still counts
    ("auto:b", "human", "agree"),  # kind disagrees with the prefix: never counts
    ("auto:unknown", "unattributed", "agree"),
    ("humane:x", "automatic", "agree"),
    ("human", "human", "agree"),  # no colon: not a human actor
    ("human:a", "human", "disagree"),
    ("auto:b", "human", "disagree"),
    ("auto:unknown", "unattributed", "disagree"),
    ("human", "automatic", "disagree"),
]


def test_the_effective_rule_keys_on_the_actor_prefix_not_the_kind_or_a_lookalike(
    state_dir: Path,
) -> None:
    sequences = [s for n in range(4) for s in itertools.product(ODD_EVENTS, repeat=n)]
    ids = {}
    for n, seq in enumerate(sequences):
        decision_id = seq_id(n)
        ids[decision_id] = seq
        put_decision(state_dir, decision_id)
        for actor, kind, verdict in seq:
            put_outcome(state_dir, decision_id, verdict, actor=actor, kind=kind)
    s = store.open_store(state_dir, create=False)
    assert s is not None
    with s:
        for decision_id, seq in ids.items():
            expected = model([(actor, verdict) for actor, _, verdict in seq])
            assert history.effective_outcome(s, decision_id) == expected, seq


def test_the_spec_example_human_agree_auto_disagree_human_agree_ends_agree(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    steps = [
        (("human:a", "agree"), True, "agree", None),
        (("auto:b", "disagree"), True, "disagree", "unsafe"),
        (("human:a", "agree"), True, "agree", None),
    ]
    for (actor, verdict), changed, effective, miss in steps:
        code, doc, _ = outcome(capsys, config, ID, verdict, "--actor", actor)
        assert code == 0
        assert (doc["changed"], doc["effective_outcome"], doc["miss"]) == (
            changed,
            effective,
            miss,
        )
        schema_util.assert_valid("cli/outcome", doc)
    assert [r["outcome"] for r in stored(state_dir)] == ["agree", "disagree", "agree"]


def test_an_automatic_agree_is_recorded_but_never_counts(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    code, doc, _ = outcome(capsys, config, ID, "agree", *AUTO)
    assert code == 0 and doc["changed"] is False and doc["effective_outcome"] == "pending"
    assert len(stored(state_dir)) == 1
    outcome(capsys, config, ID, "disagree", *AUTO)
    code, doc, _ = outcome(capsys, config, ID, "agree", *AUTO)
    assert doc["changed"] is False and doc["effective_outcome"] == "disagree"
    assert doc["miss"] is None


def test_a_second_disagree_has_no_miss_and_changes_nothing(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    _, first, _ = outcome(capsys, config, ID, "disagree", *AUTO)
    _, second, _ = outcome(capsys, config, ID, "disagree", *AUTO)
    assert first["miss"] == "unsafe" and first["changed"] is True
    assert second["miss"] is None and second["changed"] is False
    assert second["effective_outcome"] == "disagree"
    assert len(stored(state_dir)) == 2  # every call appends one record


def test_a_stepped_back_clock_cannot_reorder_outcomes(
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    put_decision(state_dir, ID)
    monkeypatch.setattr(outcomecmd, "now_ts", lambda: "2026-11-24T13:00:00.000000Z")
    outcome(capsys, config, ID, "disagree", *HUMAN)
    monkeypatch.setattr(outcomecmd, "now_ts", lambda: "2026-11-24T12:00:00.000000Z")
    _, doc, _ = outcome(capsys, config, ID, "agree", *HUMAN)
    assert doc["effective_outcome"] == "agree" and doc["changed"] is True
    s = store.open_store(state_dir, create=False)
    assert s is not None
    with s:
        assert history.effective_outcome(s, ID) == "agree"


def test_equal_timestamps_are_ordered_by_seq(
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    put_decision(state_dir, ID)
    monkeypatch.setattr(outcomecmd, "now_ts", lambda: "2026-11-24T12:00:00.000000Z")
    outcome(capsys, config, ID, "agree", *HUMAN)
    _, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert doc["effective_outcome"] == "disagree"
    rows = stored(state_dir)
    assert rows[0]["seq"] < rows[1]["seq"]


# --- classification ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("verdict", "miss"), [("allow", "unsafe"), ("deny", "over_strict"), ("escalate", "over_strict")]
)
def test_the_miss_kind_follows_the_decision(
    verdict: str,
    miss: str,
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
) -> None:
    put_decision(
        state_dir,
        ID,
        decision=verdict,
        reason="all_passed" if verdict == "allow" else "check_error",
    )
    _, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert doc["miss"] == miss and doc["state_change"] is None


def test_an_agree_is_never_a_miss(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    _, doc, _ = outcome(capsys, config, ID, "agree", *HUMAN)
    assert doc["miss"] is None


def test_a_human_agree_after_a_disagree_changes_it_without_a_miss(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    outcome(capsys, config, ID, "disagree", *AUTO)
    _, doc, _ = outcome(capsys, config, ID, "agree", *HUMAN)
    assert doc["changed"] is True and doc["miss"] is None


# --- ids --------------------------------------------------------------------------------------


def test_an_unknown_id_exits_10_and_creates_nothing(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    code, doc, _ = outcome(capsys, config, ID, "agree", *HUMAN)
    assert code == 10
    assert doc["error"]["code"] == "not_found"
    assert doc["error"]["message"] == "unknown or pruned id; see audit.jsonl"
    assert not state_dir.exists()


def test_a_pruned_or_unknown_id_in_an_existing_store_exits_10(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, did(1))
    code, doc, _ = outcome(capsys, config, did(2), "disagree", *HUMAN)
    assert code == 10 and doc["error"]["message"] == "unknown or pruned id; see audit.jsonl"
    assert stored(state_dir) == [] and audit_lines(state_dir) == []


def test_a_unique_prefix_with_or_without_gd_resolves(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    for ref in ("gd-4k2m7q", "4k2m7q", ID[3:]):
        code, doc, _ = outcome(capsys, config, ref, "agree", *HUMAN)
        assert code == 0 and doc["decision_id"] == ID


def test_an_ambiguous_prefix_exits_21_and_records_nothing(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, "gd-4k2m7qaaaaaa")
    put_decision(state_dir, "gd-4k2m7qbbbbbb")
    code, doc, _ = outcome(capsys, config, "gd-4k2m7q", "disagree", *HUMAN)
    assert code == 21 and doc["error"]["code"] == "ambiguous"
    assert stored(state_dir) == []


@pytest.mark.parametrize(
    "ref",
    [
        "gd-%%%%%%",
        "gd-4k2m7_",
        "%",
        "gd-4k2m7",
        "gd-",
        "",
        "gd-4k2m7q5x3a2bc",
        "GD-4K2M7Q",
        "gd-4k2m71",
        "gd-4k2m7q\n",
        "gd-4k2m7q' OR 1=1 --",
        "../../etc/passwd",
    ],
)
def test_a_bad_reference_is_a_usage_error_and_records_nothing(
    ref: str, capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    code, doc, _ = outcome(capsys, config, ref, "disagree", *HUMAN)
    assert code == 2 and doc["error"]["code"] == "usage"
    assert stored(state_dir) == [] and audit_lines(state_dir) == []


@pytest.mark.parametrize("verdict", ["pending", "AGREE", "yes", ""])
def test_only_agree_and_disagree_are_verdicts(
    verdict: str, capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    code, _, _ = outcome(capsys, config, ID, verdict, *HUMAN)
    assert code == 2 and stored(state_dir) == []


# --- signal and actor -------------------------------------------------------------------------


def test_the_default_signal_is_human_for_a_human_actor_else_auto(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    _, doc, _ = outcome(capsys, config, ID, "agree", *HUMAN)
    assert doc["signal"] == "human" and doc["actor"] == "human:ann"
    _, doc, _ = outcome(capsys, config, ID, "agree", *AUTO)
    assert doc["signal"] == "auto"
    _, doc, _ = outcome(capsys, config, ID, "disagree")
    assert doc["signal"] == "auto" and doc["actor"] == "auto:unknown"
    _, doc, _ = outcome(capsys, config, ID, "disagree", "--signal", "revert", *AUTO)
    assert doc["signal"] == "revert"
    assert [r["signal"] for r in stored(state_dir)] == ["human", "auto", "auto", "revert"]
    assert [r["actor_kind"] for r in stored(state_dir)] == [
        "human",
        "automatic",
        "unattributed",
        "automatic",
    ]


@pytest.mark.parametrize("signal", ["", "Human", "1abc", "a b", "a" * 33, "x\n", "-x", "a/b", "é"])
def test_a_bad_signal_is_a_usage_error(
    signal: str, capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    code, _, _ = outcome(capsys, config, ID, "disagree", "--signal", signal, *HUMAN)
    assert code == 2 and stored(state_dir) == []


def test_a_signal_never_makes_an_agree_count(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    _, doc, _ = outcome(capsys, config, ID, "agree", "--signal", "human", *AUTO)
    assert doc["effective_outcome"] == "pending"


def tty(monkeypatch: pytest.MonkeyPatch, value: bool = True) -> None:
    from gatectl import cli

    monkeypatch.setattr(cli, "_stdin_is_tty", lambda: value)


def test_a_tty_makes_the_default_actor_human_and_counts(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tty(monkeypatch)
    config = make_config(tmp_path, me={"name": "carol"})
    put_decision(state_dir, ID)
    _, doc, _ = outcome(capsys, config, ID, "agree")
    assert doc["actor"] == "human:carol" and doc["effective_outcome"] == "agree"
    line = audit_lines(state_dir)[0]
    assert line["stdin_tty"] is True and line["inputs"]["actor_source"] == "default"


def test_the_environment_stdin_and_caller_ids_never_make_an_actor_human(
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in {
        "GATECTL_ACTOR": "human:ann",
        "GATECTL_ME__NAME": "ann",
        "GATECTL_HUMAN": "1",
        "USER": "ann",
        "LOGNAME": "ann",
        "SUDO_USER": "ann",
        "SSH_TTY": "/dev/pts/9",
        "TERM": "xterm",
    }.items():
        monkeypatch.setenv(name, value)
    put_decision(state_dir, ID)
    r, w = os.pipe()
    try:
        os.write(w, b"human:ann\n")
        monkeypatch.setattr(outcomecmd, "STDIN_FD", r)
        _, doc, _ = outcome(
            capsys,
            config,
            ID,
            "agree",
            "--decision-id",
            "human:ann",
            "--decision-id",
            ID,
        )
        assert doc["actor"] == "auto:unknown" and doc["effective_outcome"] == "pending"
        assert os.read(r, 100) == b"human:ann\n"  # stdin was never read
    finally:
        os.close(r)
        os.close(w)


@pytest.mark.parametrize(
    "flag", ["human:", "human", "Human:ann", "human:ann ", "human:a b", "human:ann\n", "root", ""]
)
def test_a_malformed_actor_is_a_usage_error_and_never_human(
    flag: str, capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    code, _, _ = outcome(capsys, config, ID, "agree", "--actor", flag)
    assert code == 2 and stored(state_dir) == []


def test_the_last_actor_flag_wins(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    _, doc, _ = outcome(capsys, config, ID, "agree", *HUMAN, "--actor", "auto:ann")
    assert doc["actor"] == "auto:ann" and doc["effective_outcome"] == "pending"


def test_a_real_pty_stdin_is_human_and_a_pipe_or_devnull_is_not(
    tmp_path: Path, state_dir: Path
) -> None:
    config = make_config(tmp_path)
    put_decision(state_dir, ID)
    env = {
        "HOME": str(tmp_path / "home"),
        "XDG_CONFIG_HOME": str(tmp_path / "home" / "config"),
        "XDG_STATE_HOME": str(tmp_path / "home" / "state"),
        "PATH": os.environ.get("PATH", ""),
        "LC_ALL": "C",
    }
    argv = [sys.executable, "-m", "gatectl", "outcome", ID, "agree", "--config", config, "--json"]

    def start(stdin: int) -> bytes:
        proc = subprocess.Popen(  # noqa: S603
            argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
        )
        try:
            out, _ = proc.communicate(timeout=60)
        finally:
            if proc.poll() is None:
                proc.kill()  # exactly the process this test started
                proc.wait()
        assert proc.returncode == 0
        return out

    assert b'"effective_outcome":"pending"' in start(subprocess.DEVNULL)
    r, w = os.pipe()
    os.close(w)
    try:
        assert b'"actor":"auto:unknown"' in start(r)
    finally:
        os.close(r)
    master, slave = pty.openpty()
    try:
        assert b'"effective_outcome":"agree"' in start(slave)
    finally:
        os.close(master)
        os.close(slave)
    assert [r["actor_kind"] for r in stored(state_dir)] == [
        "unattributed",
        "unattributed",
        "human",
    ]
    assert audit_lines(state_dir)[-1]["stdin_tty"] is True


# --- the reason -------------------------------------------------------------------------------


def test_a_reason_file_is_stored_sanitized(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    path = tmp_path / "why.txt"
    path.write_bytes(b"bad\x1b[31m merge\x00\xff\xfe end\r\n")
    code, doc, _ = outcome(capsys, config, ID, "disagree", "--reason-file", str(path), *HUMAN)
    assert code == 0
    reason = stored(state_dir)[0]["reason"]
    assert reason == "bad�[31m merge��� end"
    assert "reason" not in doc  # never printed in the result


def test_an_empty_reason_is_null(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    path = tmp_path / "why.txt"
    path.write_bytes(b"\n")
    outcome(capsys, config, ID, "disagree", "--reason-file", str(path), *HUMAN)
    assert stored(state_dir)[0]["reason"] is None


def test_a_long_reason_is_cut_to_1_kib_with_a_final_ellipsis(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    path = tmp_path / "why.txt"
    path.write_bytes(b"x" * 5000)
    outcome(capsys, config, ID, "disagree", "--reason-file", str(path), *HUMAN)
    reason = stored(state_dir)[0]["reason"]
    assert len(reason) == 1024 and reason.endswith("…") and reason[:-1] == "x" * 1023


def test_a_reason_of_exactly_1_kib_is_kept_whole(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    path = tmp_path / "why.txt"
    path.write_bytes(b"y" * 1024)
    outcome(capsys, config, ID, "disagree", "--reason-file", str(path), *HUMAN)
    assert stored(state_dir)[0]["reason"] == "y" * 1024


def test_a_cut_inside_a_multibyte_character_leaves_no_marker(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    path = tmp_path / "why.txt"
    path.write_bytes("€".encode() * 500)  # byte 1024 splits a character
    outcome(capsys, config, ID, "disagree", "--reason-file", str(path), *HUMAN)
    reason = stored(state_dir)[0]["reason"]
    assert "�" not in reason and reason.endswith("…")
    assert len(reason.encode()) <= 1030 and len(reason) <= 1024


def test_stdin_is_read_for_a_dash_and_a_stalled_writer_times_out_at_10_s(
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    put_decision(state_dir, ID)
    r, w = os.pipe()
    try:
        os.write(w, b"from stdin")
        os.close(w)
        w = -1
        monkeypatch.setattr(outcomecmd, "STDIN_FD", r)
        outcome(capsys, config, ID, "disagree", "--reason-file", "-", *HUMAN)
        assert stored(state_dir)[0]["reason"] == "from stdin"
    finally:
        os.close(r)
        if w >= 0:
            os.close(w)
    assert outcomecmd.REASON_WAIT_SECONDS == 10.0
    r, w = os.pipe()  # a writer that never closes
    try:
        monkeypatch.setattr(outcomecmd, "STDIN_FD", r)
        monkeypatch.setattr(outcomecmd, "REASON_WAIT_SECONDS", 0.2)
        code, _, _ = outcome(capsys, config, ID, "agree", "--reason-file", "-", *HUMAN)
        assert code == 2
        assert len(stored(state_dir)) == 1  # nothing recorded
    finally:
        os.close(r)
        os.close(w)


def test_stdin_is_never_read_past_1_kib_plus_one_byte(
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    put_decision(state_dir, ID)
    r, w = os.pipe()
    try:
        os.write(w, b"z" * 3000)
        monkeypatch.setattr(outcomecmd, "STDIN_FD", r)
        code, _, _ = outcome(capsys, config, ID, "disagree", "--reason-file", "-", *HUMAN)
        assert code == 0
        assert stored(state_dir)[0]["reason"] == "z" * 1023 + "…"
    finally:
        os.close(r)
        os.close(w)


@pytest.mark.parametrize("name", ["missing.txt", "."])
def test_a_missing_or_irregular_reason_file_is_a_usage_error(
    name: str, tmp_path: Path, capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    code, doc, _ = outcome(
        capsys, config, ID, "disagree", "--reason-file", str(tmp_path / name), *HUMAN
    )
    assert code == 2 and stored(state_dir) == []
    assert str(tmp_path) not in doc["error"]["message"]


# --- the audit line ---------------------------------------------------------------------------


def test_every_call_appends_exactly_one_valid_audit_line(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    for verdict, extra in (("agree", AUTO), ("agree", HUMAN), ("disagree", AUTO)):
        outcome(capsys, config, ID, verdict, "--decision-id", "caller:1", *extra)
    lines = audit_lines(state_dir)
    assert len(lines) == 3  # the miss is on a shadow decision: no state change line
    assert {line["action"] for line in lines} == {"outcome"}
    for line in lines:
        schema_util.assert_valid("audit", line)
        assert line["target"] == ID and line["decision_id"] == ID
        assert line["inputs"]["decision_ids"] == ["caller:1"]
    assert lines[0]["actor"] == "auto:bot" and lines[0]["stdin_tty"] is False
    assert lines[0]["inputs"]["actor_source"] == "flag"
    assert lines[0]["result"] == {
        "outcome": "agree",
        "signal": "auto",
        "effective_outcome": "pending",
        "miss": None,
    }
    assert lines[2]["result"]["miss"] == "unsafe"


def test_the_reason_is_not_in_the_audit_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    path = tmp_path / "why.txt"
    path.write_text("SECRET-REASON-TEXT")
    outcome(capsys, config, ID, "agree", "--reason-file", str(path), *HUMAN)
    assert "SECRET-REASON-TEXT" not in (state_dir / "audit.jsonl").read_text()


def test_the_audit_line_is_appended_inside_the_transaction(
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    put_decision(state_dir, ID)
    seen: list[bool] = []
    real = store.Store.append_audit_many

    def spy(self: store.Store, records: Sequence[Mapping[str, Any]]) -> None:
        seen.append(self.con.in_transaction)
        real(self, records)

    monkeypatch.setattr(store.Store, "append_audit_many", spy)
    code, _, _ = outcome(capsys, config, ID, "agree", *HUMAN)
    assert code == 0 and seen == [True]


def test_a_failed_audit_append_rolls_the_outcome_back(
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    put_decision(state_dir, ID)

    def broken(*args: object, **kwargs: object) -> bytes:
        raise ValueError("unencodable")

    monkeypatch.setattr(audit, "encode_line", broken)
    code, doc, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert code == 1 and doc["error"]["code"] == "internal"
    assert stored(state_dir) == []


def test_the_audit_failure_is_not_retried(
    capsys: pytest.CaptureFixture[str],
    config: str,
    state_dir: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    put_decision(state_dir, ID)
    calls = {"n": 0}

    def broken(*args: object, **kwargs: object) -> None:
        calls["n"] += 1
        raise OSError("disk full")

    monkeypatch.setattr(audit, "append_audit_many", broken)
    code, _, _ = outcome(capsys, config, ID, "disagree", *HUMAN)
    assert code == 1 and calls["n"] == 1 and stored(state_dir) == []


def test_a_missing_state_db_next_to_an_audit_history_exits_1(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    state_dir.mkdir(parents=True)
    (state_dir / "audit.jsonl").write_bytes(b'{"ts":"x"}\n')
    code, doc, _ = outcome(capsys, config, ID, "agree", *HUMAN)
    assert code == 1 and doc["error"]["reason"] == "state_db_missing"
    assert not (state_dir / "state.db").exists()


# --- the text form ----------------------------------------------------------------------------


def test_the_text_form_is_one_sanitized_line(
    capsys: pytest.CaptureFixture[str], config: str, state_dir: Path
) -> None:
    put_decision(state_dir, ID)
    code, out, _ = run(capsys, ["outcome", ID, "disagree", "--config", config, *HUMAN])
    assert code == 0
    assert out.count("\n") == 1 and ID in out and "disagree" in out
    assert out.isprintable() or out.endswith("\n")


# --- concurrency ------------------------------------------------------------------------------


def _worker(argv: list[str], go: Any, out: Any) -> None:
    from gatectl.cli import main

    go.wait(30)
    devnull = os.open(os.devnull, os.O_WRONLY)
    os.dup2(devnull, 1)
    os.dup2(devnull, 2)
    out.put(main(argv))


def test_concurrent_outcomes_get_distinct_seq_and_one_audit_line_each(
    config: str, state_dir: Path
) -> None:
    import multiprocessing

    put_decision(state_dir, ID)
    ctx = multiprocessing.get_context("fork")
    go = ctx.Event()
    out = ctx.Queue()
    argvs = [
        ["outcome", ID, v, "--config", config, "--json", "--actor", a]
        for v, a in [
            ("disagree", "auto:a"),
            ("agree", "human:b"),
            ("disagree", "auto:c"),
            ("agree", "auto:d"),
        ]
    ]
    procs = [ctx.Process(target=_worker, args=(a, go, out)) for a in argvs]
    for p in procs:
        p.start()
    go.set()
    codes = [out.get(timeout=60) for _ in procs]
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    assert codes == [0, 0, 0, 0]
    rows = stored(state_dir)
    assert len({r["seq"] for r in rows}) == 4
    lines = [line for line in audit_lines(state_dir) if line["action"] == "outcome"]
    assert len(lines) == 4
    # each line's effective outcome is consistent with the order the rows were inserted
    by_actor = {line["actor"]: line["result"]["effective_outcome"] for line in lines}
    seq_of = {r["actor"]: r["seq"] for r in rows}
    running = "pending"
    for actor in sorted(seq_of, key=seq_of.__getitem__):
        verdict = next(r["outcome"] for r in rows if r["actor"] == actor)
        if verdict == "disagree" or actor.startswith("human:"):
            running = verdict
        assert by_actor[actor] == running
