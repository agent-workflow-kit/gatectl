"""An agent check inside ``check``: what is refused before any slot or session (tool_missing,
input_invalid), the deadline steps (budget_exhausted, busy), the files and the slot, the cache
(reuse, ``--no-cache``, what is never cached) and the rule that nothing unvalidated can allow.

Issue #24. The judge is issue #25's: ``judged`` stands in for a validated verdict.
"""

from __future__ import annotations

import errno
import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from gatectl import agentcache, agentfiles, agentjudge, cli, engine, fingerprint, slots, tmptree
from tests.agent_util import (
    DECISION,
    FAST,
    Fake,
    agent_check,
    config,
    judged,
    limits_env,
    state_store,
    tmp_entries,
)
from tests.check_util import (
    REPO,
    decisions,
    do_check,
    do_set,
    isolate,
    log_lines,
    rows,
    write_input,
)
from tests.command_util import config_file

INPUT = {"ci": "ok", "repo": REPO}


@pytest.fixture
def sdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def check(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    cfg: dict[str, Any],
    *extra: str,
    obj: Any = INPUT,
    name: str = "in.json",
) -> tuple[int, dict[str, Any], str]:
    path = config_file(tmp_path, cfg)
    return do_check(capsys, path, "p", "--input", write_input(tmp_path, obj, name), *extra)


def entry_of(doc: dict[str, Any], index: int = 0) -> tuple[str, str | None]:
    return doc["checks"][index]["verdict"], doc["checks"][index]["reason"]


def nothing_left(sdir: Path) -> None:
    assert tmp_entries(sdir) == []
    assert rows(sdir, "SELECT * FROM agent_slots") == []


# --- tool_missing: before any slot, file or session ---------------------------------------


def assert_refused_early(fake: Fake, sdir: Path) -> None:
    assert fake.argvs() == []  # no session call at all
    assert tmp_entries(sdir) == []  # no file written
    assert rows(sdir, "SELECT * FROM agent_slots") == []  # no slot taken


def test_a_session_cmd_that_is_not_found_is_tool_missing_with_the_install_command(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    limits_env(monkeypatch)
    _, doc, _ = check(tmp_path, capsys, config(None, session_cmd=["claude-session-nowhere"]))
    assert entry_of(doc) == ("escalate", "tool_missing")
    assert doc["checks"][0]["detail"] == "claude-session-nowhere not found"
    _, doc, _ = check(tmp_path, capsys, config(None, session_cmd=["/nowhere/claude-session"]))
    assert doc["checks"][0]["detail"] == (
        "/nowhere/claude-session not found; install: "
        "uv tool install git+https://github.com/agent-workflow-kit/claude-session"
    )
    nothing_left(sdir)


def test_a_missing_bundled_plugin_is_tool_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    empty = tmp_path / "no-plugin"
    empty.mkdir()
    monkeypatch.setattr(fingerprint, "bundled_plugin_dir", lambda: str(empty))
    _, doc, _ = check(tmp_path, capsys, config(fake))
    assert entry_of(doc) == ("escalate", "tool_missing")
    assert doc["checks"][0]["detail"] == "bundled plugin not found"
    assert_refused_early(fake, sdir)


def test_a_skill_whose_plugin_is_not_found_is_tool_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    _, doc, _ = check(tmp_path, capsys, config(fake, checks=[agent_check(skill="ghost:review")]))
    assert entry_of(doc) == ("escalate", "tool_missing")
    assert doc["checks"][0]["detail"] == "plugin not found: ghost"
    assert_refused_early(fake, sdir)


def test_a_skill_whose_skill_md_is_missing_is_tool_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    _, doc, _ = check(tmp_path, capsys, config(fake, checks=[agent_check(skill="gatectl:ghost")]))
    assert entry_of(doc) == ("escalate", "tool_missing")
    assert doc["checks"][0]["detail"] == "skill not found: gatectl:ghost"
    assert_refused_early(fake, sdir)


def test_a_skill_md_that_is_a_directory_or_a_fifo_is_not_found(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    other = tmp_path / "other"
    (other / ".claude-plugin").mkdir(parents=True)
    (other / ".claude-plugin" / "plugin.json").write_text('{"name": "other"}', encoding="utf-8")
    (other / "skills" / "dir" / "SKILL.md").mkdir(parents=True)  # a directory, not a file
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    cfg = config(
        fake,
        checks=[agent_check(skill="other:dir")],
        agent_block={"plugin_dirs": [str(other)]},
    )
    _, doc, _ = check(tmp_path, capsys, cfg)
    assert entry_of(doc) == ("escalate", "tool_missing")
    assert_refused_early(fake, sdir)


@pytest.mark.parametrize("path", ["/nonexistent/instruction.md", "/tmp"])
def test_an_unreadable_instruction_file_is_tool_missing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    path: str,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    check_ = {"name": "a", "type": "agent", "instruction_file": path}
    _, doc, _ = check(tmp_path, capsys, config(fake, checks=[check_]))
    assert entry_of(doc) == ("escalate", "tool_missing")
    assert doc["checks"][0]["detail"] == "instruction unreadable"
    assert path not in json.dumps(doc)
    assert_refused_early(fake, sdir)


def test_an_instruction_file_that_changed_since_the_fingerprint_is_tool_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    instruction = tmp_path / "instruction.md"
    instruction.write_text("Be careful.\n", encoding="utf-8")
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    monkeypatch.setattr(fingerprint, "read_instruction_file", lambda _p: b"Be reckless.\n")
    check_ = {"name": "a", "type": "agent", "instruction_file": str(instruction)}
    _, doc, _ = check(tmp_path, capsys, config(fake, checks=[check_]))
    assert entry_of(doc) == ("escalate", "tool_missing")
    assert_refused_early(fake, sdir)


def test_a_definition_that_changed_since_the_fingerprint_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    calls: list[int] = []
    real = fingerprint.fingerprint_of

    def drifting(defined: dict[str, Any]) -> str:
        calls.append(1)
        return real(defined) if len(calls) == 1 else "sha256:" + "0" * 64

    monkeypatch.setattr(fingerprint, "fingerprint_of", drifting)
    _, doc, _ = check(tmp_path, capsys, config(fake))
    assert entry_of(doc) == ("escalate", "check_error")
    assert_refused_early(fake, sdir)


# --- input_invalid -------------------------------------------------------------------------


def test_an_input_too_large_for_an_agent_check_is_refused_before_any_slot(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    cfg = config(fake, agent_block={"input_max_bytes": 1024})
    _, doc, _ = check(tmp_path, capsys, cfg, obj={**INPUT, "blob": ["x" * 40] * 60})
    assert entry_of(doc) == ("escalate", "input_invalid")
    assert doc["checks"][0]["detail"] == "too large for an agent check"
    assert_refused_early(fake, sdir)


def test_a_line_over_16_kib_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    cfg = config(fake, agent_block={"input_max_bytes": 65536})
    _, doc, _ = check(tmp_path, capsys, cfg, obj={**INPUT, "line": "x" * 20000})
    assert doc["checks"][0]["detail"] == "line too long for an agent check"
    assert entry_of(doc) == ("escalate", "input_invalid")
    assert_refused_early(fake, sdir)


# --- the Deadline steps --------------------------------------------------------------------


def test_too_little_time_left_is_budget_exhausted_with_no_slot_and_no_session(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    cfg = config(fake, timeout="8s", agent_block={"min_start_budget": "5s"})  # L = 2.8 s < 5 s
    _, doc, _ = check(tmp_path, capsys, cfg)
    assert entry_of(doc) == ("escalate", "budget_exhausted")
    assert_refused_early(fake, sdir)


def test_the_budget_is_checked_again_once_the_slot_is_held_and_the_slot_is_released(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    offset = [0.0]
    limits_env(monkeypatch, monotonic=lambda: time.monotonic() + offset[0])
    real = slots.wait_for_slot

    def slow(*args: Any, **kwargs: Any) -> Any:
        slot = real(*args, **kwargs)
        offset[0] = 1000.0  # the wait ate the whole budget
        return slot

    monkeypatch.setattr(slots, "wait_for_slot", slow)
    _, doc, _ = check(tmp_path, capsys, config(fake))
    assert entry_of(doc) == ("escalate", "budget_exhausted")
    assert_refused_early(fake, sdir)


def test_a_deadline_passed_before_the_definition_is_read_again_is_budget_exhausted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    offset = [0.0]
    limits_env(monkeypatch, monotonic=lambda: time.monotonic() + offset[0])
    real = agentcache.get

    def late(*args: Any, **kwargs: Any) -> Any:
        offset[0] = 1000.0  # the clock jumps past the deadline between the two steps
        return real(*args, **kwargs)

    monkeypatch.setattr(agentcache, "get", late)
    _, doc, _ = check(tmp_path, capsys, config(fake))
    assert entry_of(doc) == ("escalate", "budget_exhausted")
    assert_refused_early(fake, sdir)


def test_slot_starvation_is_busy(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    cfg = config(fake, timeout="8s", agent_block={"max_parallel": 1, "min_start_budget": "1s"})
    config_path = config_file(tmp_path, cfg)
    do_check(capsys, config_path, "p", "--input", write_input(tmp_path, INPUT))  # creates state
    with state_store() as store:
        held = slots.try_acquire(
            store,
            decision_id="gd-bbbbbbbbbbbb",
            max_parallel=1,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        assert held is not None  # a live holder: this very process
    calls_before = len(fake.argvs())
    began = time.monotonic()
    _, doc, _ = do_check(capsys, config_path, "p", "--input", write_input(tmp_path, INPUT))
    assert entry_of(doc) == ("escalate", "busy")
    assert time.monotonic() - began < 6  # waited until L fell below min_start_budget
    assert len(fake.argvs()) == calls_before
    assert rows(sdir, "SELECT decision_id FROM agent_slots") == [("gd-bbbbbbbbbbbb",)]
    assert tmp_entries(sdir) == []


# --- files and slot -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        OSError(errno.ENOSPC, "No space left on device /secret/path"),
        FileExistsError("/secret/path"),
        tmptree.UnsafeTree("/secret/path: not owned by this user"),
    ],
)
def test_a_file_that_cannot_be_written_is_check_error_without_the_error_text(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: Exception,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)

    def boom(*_a: Any, **_k: Any) -> None:
        raise failure

    monkeypatch.setattr(agentfiles.PreparedFiles, "write", boom)
    _, doc, _ = check(tmp_path, capsys, config(fake))
    assert entry_of(doc) == ("escalate", "check_error")
    assert doc["checks"][0]["detail"] == "agent files could not be written"
    everything = json.dumps(doc) + json.dumps(log_lines(sdir)) + (sdir / "audit.jsonl").read_text()
    assert "secret" not in everything
    assert_refused_early(fake, sdir)


def test_a_decision_directory_that_cannot_be_created_is_check_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)

    def boom(*_a: Any, **_k: Any) -> Path:
        raise OSError(errno.EACCES, "denied")

    monkeypatch.setattr(tmptree, "create_decision_dir", boom)
    _, doc, _ = check(tmp_path, capsys, config(fake))
    assert entry_of(doc) == ("escalate", "check_error")
    assert_refused_early(fake, sdir)


def test_the_files_hold_the_fenced_input_and_the_nonce_only_while_the_run_lives(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    seen: dict[str, Any] = {}
    stand_in = judged(monkeypatch)
    real = agentjudge.judge

    def peek(raw: agentjudge.RawRun, *, threshold: float) -> agentjudge.Judgement:
        folder = next((sdir / "tmp").iterdir())
        seen["files"] = sorted(p.name for p in folder.iterdir())
        seen["prompt"] = (folder / "prompt.md").read_text(encoding="utf-8")
        seen["input"] = (folder / "input.json").read_text(encoding="utf-8")
        return real(raw, threshold=threshold)

    monkeypatch.setattr(agentjudge, "judge", peek)
    # `judged` replaced the module attribute before this; `real` is the stand-in
    _, doc, _ = check(tmp_path, capsys, config(fake))
    assert stand_in and doc["checks"][0]["verdict"] == "allow"
    assert {"input.json", "prompt.md", "owner", "outcome.json"} >= set(seen["files"])
    assert {"input.json", "prompt.md"} <= set(seen["files"])
    assert seen["input"].startswith('<untrusted source="gatectl-input" id="')
    nonce = stand_in[0].nonce
    assert len(nonce) == 32 and nonce in seen["prompt"]
    assert nonce not in repr(stand_in[0])
    # nothing durable carries the nonce: audit, log, the printed result, the fake's call log
    everything = json.dumps(doc) + (sdir / "audit.jsonl").read_text(encoding="ascii")
    everything += json.dumps(log_lines(sdir)) + fake.session.log.read_text(encoding="utf-8")
    assert nonce not in everything
    nothing_left(sdir)


def test_a_slot_that_was_lost_mid_run_never_breaks_the_check(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    real = agentjudge.judge

    def lose_slot(raw: agentjudge.RawRun, *, threshold: float) -> agentjudge.Judgement:
        with state_store() as store:
            store.transact(lambda: store.execute("DELETE FROM agent_slots", ()))
        return real(raw, threshold=threshold)

    monkeypatch.setattr(agentjudge, "judge", lose_slot)
    _, doc, _ = check(tmp_path, capsys, config(fake))
    assert entry_of(doc) == ("allow", None)
    nothing_left(sdir)


def test_files_that_cannot_be_deleted_never_change_the_verdict(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)

    def boom(_self: Any) -> None:
        raise OSError("could not remove a private file /secret/path")

    monkeypatch.setattr(agentfiles.AgentFiles, "delete", boom)
    _, doc, _ = check(tmp_path, capsys, config(fake))
    assert entry_of(doc) == ("allow", None)
    text = json.dumps(log_lines(sdir)) + (sdir / "audit.jsonl").read_text()
    assert "secret" not in text
    assert any(line.get("message") == "workdir_left" for line in log_lines(sdir))
    assert fake.unforgotten() == []


def test_a_failing_delete_still_removes_the_outcome_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    removed: list[list[str]] = []
    real = tmptree.remove_private_files

    def spy(directory: Any, names: Any) -> Any:
        removed.append(list(names))
        return real(directory, names)

    def boom(_self: Any) -> None:
        raise OSError("no")

    monkeypatch.setattr(agentfiles.AgentFiles, "delete", boom)
    monkeypatch.setattr(tmptree, "remove_private_files", spy)
    _, doc, _ = check(tmp_path, capsys, config(fake))
    assert entry_of(doc) == ("allow", None)
    assert ["outcome.json"] in removed
    assert any(line.get("message") == "workdir_left" for line in log_lines(sdir))


def test_two_agent_checks_each_get_their_own_session_and_files(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    cfg = config(fake, checks=[agent_check("one"), agent_check("two", instruction="Other.")])
    _, doc, _ = check(tmp_path, capsys, cfg)
    assert [entry_of(doc, i) for i in (0, 1)] == [("allow", None), ("allow", None)]
    assert fake.verbs() == ["start", "exec", "status", "forget"] * 2
    assert len(fake.records()) == 2 and fake.unforgotten() == []
    nothing_left(sdir)


def test_an_agent_check_after_a_deny_or_an_escalate_is_skipped_and_starts_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    deny = {
        "name": "r",
        "type": "rule",
        "when": [{"path": "ci", "op": "eq", "value": "ok"}],
        "then": "deny",
    }
    _, doc, _ = check(tmp_path, capsys, config(fake, checks=[agent_check(), deny]))
    assert [c["verdict"] for c in doc["checks"]] == ["deny", "skipped"]
    assert fake.argvs() == []
    # an escalating first agent check skips the second
    cfg = config(fake, checks=[agent_check("one"), agent_check("two", instruction="Other.")])
    judged(monkeypatch, agentcache.Verdict("escalate", 0.9, ("not sure",)))
    _, doc, _ = check(tmp_path, capsys, cfg)
    assert [c["verdict"] for c in doc["checks"]] == ["escalate", "skipped"]
    assert fake.verbs().count("start") == 1


# --- nothing unvalidated can allow ---------------------------------------------------------


def test_with_the_stub_judge_a_complete_run_never_allows(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    _, doc, _ = check(tmp_path, capsys, config(fake))  # TODO(#25): real validation
    assert entry_of(doc) == ("escalate", "check_error")
    assert doc["checks"][0]["detail"] == agentjudge.NOT_VALIDATED
    assert doc["decision"] == "escalate"
    assert fake.verbs() == ["start", "exec", "status", "forget"]
    nothing_left(sdir)


def test_an_allow_cannot_be_built_without_a_validated_artifact() -> None:
    with pytest.raises(ValueError):
        agentjudge.Judgement("allow", None, None)
    with pytest.raises(ValueError):
        agentjudge.Judgement("allow", "check_error", None, 0.9, DECISION)
    with pytest.raises(ValueError):
        agentjudge.Judgement("escalate", "check_error", None, cacheable=True)
    with pytest.raises(ValueError):
        agentjudge.Judgement("maybe", None, None)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", ["raises", "not a judgement", None])
def test_a_judge_that_fails_or_returns_garbage_is_check_error(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    bad: Any,
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)

    def broken(_raw: Any, *, threshold: float) -> Any:
        if bad == "raises":
            raise RuntimeError("boom /secret/path")
        return bad

    monkeypatch.setattr(agentjudge, "judge", broken)
    _, doc, _ = check(tmp_path, capsys, config(fake))
    assert entry_of(doc) == ("escalate", "check_error")
    assert "secret" not in json.dumps(doc) + json.dumps(log_lines(sdir))
    assert fake.unforgotten() == []
    nothing_left(sdir)


def test_the_judge_gets_the_exec_outcome_and_the_status_of_this_session(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    seen = judged(monkeypatch)
    check(tmp_path, capsys, config(fake))
    [raw] = seen
    session = fake.records()[0]["id"]
    assert raw.exec_code == 0
    assert raw.outcome is not None and raw.outcome["csession_id"] == session
    assert raw.outcome["outcome"] == "done"
    assert raw.status is not None and raw.status["csession_id"] == session
    assert raw.status["run"]["report"]["artifact"]["name"] == "verdict.json"


@pytest.mark.parametrize(
    ("scenario", "code"),
    [("unreported", 14), ("timeout", 16), ("needs_input", 13), ("failed", 18), ("killed", 15)],
)
def test_a_run_that_exits_non_zero_is_judged_without_asking_status(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    scenario: str,
    code: int,
) -> None:
    fake = Fake(tmp_path, scenario)
    limits_env(monkeypatch)
    seen = judged(monkeypatch)
    _, doc, _ = check(tmp_path, capsys, config(fake))
    assert entry_of(doc) == ("escalate", "check_error")
    assert [(r.exec_code, r.status) for r in seen] == [(code, None)]
    assert "status" not in fake.verbs()
    assert fake.unforgotten() == []
    nothing_left(sdir)


def test_an_exec_that_prints_nothing_usable_reaches_the_judge_as_no_outcome(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path, FAKE_CS_BEHAVIOR_EXEC="garbage")
    limits_env(monkeypatch)
    seen = judged(monkeypatch)
    check(tmp_path, capsys, config(fake))
    assert [r.outcome for r in seen] == [None]


# --- the cache ------------------------------------------------------------------------------


def cache_rows(sdir: Path) -> list[tuple[Any, ...]]:
    return rows(sdir, "SELECT key, decision_id, expires_at FROM agent_cache")


def checks_of(sdir: Path, decision_id: str) -> list[dict[str, Any]]:
    [row] = [d for d in decisions(sdir) if d["id"] == decision_id]
    return json.loads(row["checks_json"])


def test_a_valid_artifact_is_cached_by_the_decision_that_produced_it_and_reused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    cfg = config(fake)
    _, first, _ = check(tmp_path, capsys, cfg)
    assert first["checks"][0]["reused"] is False
    [(key, producer, _)] = cache_rows(sdir)
    assert producer == first["decision_id"]
    assert "cache_key" not in checks_of(sdir, first["decision_id"])[0]
    calls = len(fake.argvs())

    _, second, _ = check(tmp_path, capsys, cfg)
    assert second["decision_id"] != first["decision_id"]
    entry = second["checks"][0]
    assert entry["reused"] is True and entry["verdict"] == "allow"
    assert entry["confidence"] == 0.95 and entry["detail"] == "looks fine"
    assert len(fake.argvs()) == calls  # no session was started
    assert "cache_key" not in entry  # internal, never printed
    assert checks_of(sdir, second["decision_id"])[0]["cache_key"] == key
    assert cache_rows(sdir)[0][1] == first["decision_id"]  # the producer is unchanged
    assert tmp_entries(sdir) == []


def test_a_cache_hit_needs_no_budget_no_slot_and_no_session_cmd(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    cfg = config(fake)
    check(tmp_path, capsys, cfg)
    broken = {**cfg, "session_cmd": ["/nowhere/claude-session"], "agent": {**cfg["agent"]}}
    broken["agent"]["max_parallel"] = 1
    path = config_file(tmp_path, broken)
    with state_store() as store:
        assert slots.try_acquire(
            store,
            decision_id="gd-bbbbbbbbbbbb",
            max_parallel=1,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    # a deadline too short to start anything (L < 0), a full slot table, no claude-session
    _, doc, _ = do_check(
        capsys, path, "p", "--input", write_input(tmp_path, INPUT), "--timeout", "3"
    )
    assert doc["checks"][0]["reused"] is True and doc["decision"] == "allow"


def test_no_cache_skips_the_lookup_but_still_writes_the_fresh_result(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    cfg = config(fake)
    _, first, _ = check(tmp_path, capsys, cfg)
    _, second, _ = check(tmp_path, capsys, cfg, "--no-cache")
    assert second["checks"][0]["reused"] is False
    assert fake.verbs().count("start") == 2
    assert [r[1] for r in cache_rows(sdir)] == [second["decision_id"]]  # refreshed producer
    assert first["decision_id"] != second["decision_id"]


def test_a_failed_run_is_never_cached(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    limits_env(monkeypatch)
    stub = agentjudge.judge
    judged(monkeypatch)
    for scenario in ("unreported", "timeout", "failed", "sandbox_unavailable"):
        check(tmp_path, capsys, config(Fake(tmp_path / scenario, scenario)))
    assert cache_rows(sdir) == []
    # a run whose artifact the judge refused is not cached either
    judged(monkeypatch, None)
    check(tmp_path, capsys, config(Fake(tmp_path / "refused")))
    assert cache_rows(sdir) == []
    # and neither is the stub's verdict (nothing is validated yet)
    monkeypatch.setattr(agentjudge, "judge", stub)
    check(tmp_path, capsys, config(Fake(tmp_path / "stub")))
    assert cache_rows(sdir) == []


def test_a_deny_and_an_escalate_artifact_are_cached_too(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch, agentcache.Verdict("deny", 0.9, ("no",)))
    cfg = config(fake)
    check(tmp_path, capsys, cfg)
    _, again, _ = check(tmp_path, capsys, cfg)
    assert again["checks"][0]["reused"] is True
    assert again["checks"][0]["verdict"] == "deny"
    assert again["checks"][0]["reason"] == "check_denied"
    assert fake.verbs().count("start") == 1


def test_the_threshold_applies_to_a_reused_result_as_to_a_fresh_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch, agentcache.Verdict("allow", 0.5, ("unsure",)))
    cfg = config(fake)
    _, first, _ = check(tmp_path, capsys, cfg)
    _, second, _ = check(tmp_path, capsys, cfg)
    assert entry_of(first) == ("escalate", "low_confidence")
    assert entry_of(second) == ("escalate", "low_confidence")
    assert second["checks"][0]["reused"] is True


def test_a_different_input_or_scope_or_check_does_not_hit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    cfg = config(fake)
    check(tmp_path, capsys, cfg)
    check(tmp_path, capsys, cfg, obj={**INPUT, "ci": "other"}, name="b.json")
    check(tmp_path, capsys, cfg, obj={"ci": "ok"}, name="c.json")  # scope * instead of the repo
    assert fake.verbs().count("start") == 3


def test_volatile_input_keys_are_ignored_by_the_cache_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    cfg = config(fake, input={"ignore": ["ts"]})
    check(tmp_path, capsys, cfg, obj={**INPUT, "ts": 1})
    _, doc, _ = check(tmp_path, capsys, cfg, obj={**INPUT, "ts": 2}, name="b.json")
    assert doc["checks"][0]["reused"] is True
    assert fake.verbs().count("start") == 1


def test_cache_ttl_zero_neither_reads_nor_writes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    cfg = config(fake, agent_block={"cache_ttl": 0})
    check(tmp_path, capsys, cfg)
    assert cache_rows(sdir) == []
    check(tmp_path, capsys, cfg)
    assert fake.verbs().count("start") == 2


def test_cache_ttl_follows_check_then_policy_then_agent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    # the policy says 0 (no cache) over the agent block's 10 minutes
    check(tmp_path, capsys, config(fake, cache_ttl=0))
    assert cache_rows(sdir) == []
    # the check's own 5 minutes win over the policy's 0
    cfg = config(fake, cache_ttl=0, checks=[agent_check(cache_ttl="5m")])
    check(tmp_path, capsys, cfg, name="b.json")
    [(_, _, expires)] = cache_rows(sdir)
    seconds = (
        datetime.fromisoformat(expires.replace("Z", "+00:00")) - datetime.now(UTC)
    ).total_seconds()
    assert 240 < seconds <= 300


def test_a_tampered_cache_row_fails_closed_never_as_a_verdict(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    cfg = config(fake)
    check(tmp_path, capsys, cfg)
    with state_store() as store:
        store.transact(lambda: store.execute("UPDATE agent_cache SET artifact_json = 'junk'", ()))
    # shadow: exit 0 with the error object; enforced: exit 1 (never an allow)
    code, doc, _ = check(tmp_path, capsys, cfg)
    assert code == 0 and doc["error"] is not None
    do_set(capsys, config_file(tmp_path, cfg), "p", "enforced")
    code, doc, _ = do_check(
        capsys, config_file(tmp_path, cfg), "p", "--input", write_input(tmp_path, INPUT),
        validate=False,
    )  # fmt: skip
    assert code == 1 and "error" in doc


def test_a_cache_that_cannot_be_written_never_changes_the_decision(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)

    def boom(*_a: Any, **_k: Any) -> bool:
        raise RuntimeError("disk /secret/path")

    monkeypatch.setattr(agentcache, "put", boom)
    _, doc, _ = check(tmp_path, capsys, config(fake))
    assert doc["decision"] == "allow" and "decision_id" in doc
    assert "secret" not in json.dumps(log_lines(sdir))


def test_a_decision_that_was_not_recorded_writes_no_cache_row(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    cfg = config(fake)
    config_path = config_file(tmp_path, cfg)
    real = engine._record

    def switch_off(run: Any, *a: Any, **k: Any) -> Any:
        do_set(capsys, config_path, "p", "off")  # a set to off lands while the checks ran
        return real(run, *a, **k)

    monkeypatch.setattr(engine, "_record", switch_off)
    _, doc, _ = do_check(capsys, config_path, "p", "--input", write_input(tmp_path, INPUT))
    assert doc["state"] == "off"
    assert cache_rows(sdir) == []


# --- an unexpected failure and an interrupt --------------------------------------------------


def test_a_bug_in_the_agent_step_is_check_error_not_an_exception(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)

    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("boom /secret/path")

    monkeypatch.setattr(agentfiles, "prepare", boom)
    _, doc, _ = check(tmp_path, capsys, config(fake))
    assert entry_of(doc) == ("escalate", "check_error")
    assert "secret" not in json.dumps(doc) + json.dumps(log_lines(sdir))
    assert_refused_early(fake, sdir)


def test_an_interrupt_during_the_run_still_forgets_the_session_and_frees_everything(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)

    def interrupted(_raw: Any, *, threshold: float) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(agentjudge, "judge", interrupted)
    path = config_file(tmp_path, config(fake))
    argv = ["check", "p", "--config", path, "--input", write_input(tmp_path, INPUT)]
    with pytest.raises(KeyboardInterrupt):
        cli.main(argv)
    assert fake.unforgotten() == []
    assert fake.verbs().count("forget") == 1
    nothing_left(sdir)


def test_the_check_hands_run_session_the_resolved_settings(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], sdir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = Fake(tmp_path)
    limits_env(monkeypatch)
    judged(monkeypatch)
    seen: list[dict[str, Any]] = []
    real = engine.agent.run_session

    def spy(*args: Any, **kwargs: Any) -> Any:
        seen.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(engine.agent, "run_session", spy)
    cfg = config(fake, agent_block={"threshold": 0.9}, checks=[agent_check(threshold=0.7)])
    check(tmp_path, capsys, cfg)
    assert seen[0]["threshold"] == 0.7  # the check's own threshold wins over the agent block's
    assert seen[0]["limits"] == FAST
    assert callable(seen[0].get("monotonic"))
