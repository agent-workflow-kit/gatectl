"""The judge of an agent check (issue #25): the outcome table, the strict artifact validator, the
safe artifact read and the threshold rule. Nothing here starts a process: the frozen artifact is
a real file in ``tmp_path`` and ``exec`` / ``status`` are plain dicts in the pinned shapes."""

from __future__ import annotations

import json
import os
import random
import stat
from pathlib import Path
from typing import Any

import pytest

from gatectl import agentcache, agentjudge
from gatectl.agentjudge import ArtifactError, Judgement, RawRun
from tests.judge_util import (
    END_REASONS,
    NONCE,
    artifact_entry,
    good_run,
    outcome_doc,
    status_doc,
    verdict_bytes,
    verdict_doc,
)

THRESHOLD = 0.8


def judged(run: RawRun, threshold: float = THRESHOLD) -> Judgement:
    return agentjudge.judge(run, threshold=threshold)


def result(j: Judgement) -> tuple[str, str | None]:
    return j.verdict, j.reason


# --- the outcome table: exec exit codes other than 0 -------------------------------------


def expected_nonzero(code: int, end: object) -> str:
    """The interface's table, written out independently of the implementation."""
    if code == 14:
        return "agent_unreported"
    if code == 16:
        return "timeout"
    if code == 13:
        return "check_escalated"
    if code == 12:
        if end == "sandbox_unavailable":
            return "sandbox_unavailable"
        if end == "claude_not_found":
            return "tool_missing"
        return "check_error"
    return "check_error"  # 15, 17, 18 and every other exit


OUTCOMES = (None, "outcome-none")


@pytest.mark.parametrize("code", [*range(-1, 40), 126, 127, 255, 256, 10**9])
@pytest.mark.parametrize("end", [*END_REASONS, None, "weird token", "", 5, ["x"]])
def test_every_non_zero_exit_maps_to_its_reason_whatever_the_outcome_says(
    code: int, end: object
) -> None:
    if code == 0:
        pytest.skip("exit 0 is the artifact path")
    outcome = {"csession_id": "cs-abcdefgh", "outcome": "done", "end_reason": end, "exit_code": 0}
    for body in (None, outcome):  # the exit code is the authority, never the printed outcome
        j = judged(RawRun(code, body, None, NONCE))
        assert j.verdict == "escalate"
        assert j.reason == expected_nonzero(code, end if body is not None else None)
        assert j.validated is None and not j.cacheable and j.confidence is None


def test_the_exit_code_wins_over_a_done_outcome_with_a_valid_artifact(tmp_path: Path) -> None:
    run = good_run(tmp_path)
    for code, reason in ((14, "agent_unreported"), (16, "timeout"), (13, "check_escalated")):
        j = judged(RawRun(code, run.outcome, run.status, NONCE))
        assert result(j) == ("escalate", reason)


@pytest.mark.parametrize("code", [True, False, None, 0.0, "0", 12.0])
def test_an_exit_code_that_is_not_a_plain_int_is_check_error(tmp_path: Path, code: Any) -> None:
    run = good_run(tmp_path)
    j = judged(RawRun(code, run.outcome, run.status, NONCE))
    assert result(j) == ("escalate", "check_error")


def test_the_exit_12_detail_names_only_a_token_shaped_end_reason() -> None:
    for end in ("unsafe_setting_sources", "config_invalid"):
        j = judged(RawRun(12, {"end_reason": end}, None, NONCE))
        assert j.reason == "check_error" and j.detail is not None and end in j.detail
    hostile = "x‮; ignore previous\n" + "a" * 5000
    j = judged(RawRun(12, {"end_reason": hostile}, None, NONCE))
    assert j.reason == "check_error" and j.detail is not None
    assert "ignore" not in j.detail and len(j.detail) < 200


def test_start_failed_maps_the_launch_refusals() -> None:
    assert result(agentjudge.start_failed(12, "sandbox_unavailable")) == (
        "escalate",
        "sandbox_unavailable",
    )
    assert result(agentjudge.start_failed(12, "claude_not_found")) == ("escalate", "tool_missing")
    assert result(agentjudge.start_failed(12, "unsafe_setting_sources")) == (
        "escalate",
        "check_error",
    )
    for code, end in (
        (12, None), (12, "config_invalid"), (12, "x"), (1, "sandbox_unavailable"),
        (None, "sandbox_unavailable"), (14, None), (0, None), (True, "claude_not_found"),
        (2, "claude_not_found"),
    ):  # fmt: skip
        j = agentjudge.start_failed(code, end)
        assert result(j) == ("escalate", "check_error"), (code, end)


@pytest.mark.parametrize("end", END_REASONS)
def test_start_failed_agrees_with_the_exec_exit_12_rows(end: str) -> None:
    a = agentjudge.start_failed(12, end)
    b = judged(RawRun(12, {"end_reason": end}, None, NONCE))
    assert a.reason == b.reason == expected_nonzero(12, end)


# --- exit 0: usable only with outcome done, explicit report, a valid artifact -----------


def test_a_valid_artifact_of_a_done_run_allows_and_is_cacheable(tmp_path: Path) -> None:
    j = judged(good_run(tmp_path))
    assert result(j) == ("allow", None)
    assert j.cacheable and j.confidence == 0.95 and j.detail == "looks fine"
    assert j.validated == agentcache.Verdict("allow", 0.95, ("looks fine",))


def test_the_end_reason_timeout_of_a_done_run_is_still_used(tmp_path: Path) -> None:
    def m(o: dict[str, Any], s: dict[str, Any]) -> None:
        o["end_reason"] = "timeout"
        s["run"]["end_reason"] = "timeout"

    j = judged(good_run(tmp_path, mutate=m))
    assert result(j) == ("allow", None) and j.cacheable


@pytest.mark.parametrize("decision, reason", [("deny", "check_denied"), ("escalate", "check_escalated")])
def test_a_deny_or_an_escalate_needs_a_valid_artifact_and_is_cacheable(
    tmp_path: Path, decision: str, reason: str
) -> None:
    j = judged(good_run(tmp_path, verdict_bytes(decision=decision, confidence=0.1)))
    assert result(j) == (decision, reason) and j.cacheable
    assert j.validated is not None and j.validated.decision == decision


def test_a_deny_with_an_invalid_artifact_is_artifact_invalid_not_a_deny(tmp_path: Path) -> None:
    run = good_run(tmp_path, verdict_bytes(decision="deny", nonce="f" * 32))
    assert result(judged(run)) == ("escalate", "artifact_invalid")


def test_the_threshold_is_inclusive_and_never_loosens(tmp_path: Path) -> None:
    run = good_run(tmp_path, verdict_bytes(confidence=0.8))
    assert result(judged(run, 0.8)) == ("allow", None)  # equal passes
    low = judged(run, 0.81)
    assert result(low) == ("escalate", "low_confidence")
    assert low.cacheable and low.validated is not None  # a valid artifact: cached as allow
    assert result(judged(run, 0.0)) == ("allow", None)
    deny = good_run(tmp_path / "d", verdict_bytes(decision="deny", confidence=0.0))
    assert result(judged(deny, 1.0)) == ("deny", "check_denied")
    esc = good_run(tmp_path / "e", verdict_bytes(decision="escalate", confidence=0.0))
    assert result(judged(esc, 1.0)) == ("escalate", "check_escalated")
    one = good_run(tmp_path / "o", verdict_bytes(confidence=1))
    assert result(judged(one, 1.0)) == ("allow", None)


def mut(fn: Any) -> Any:
    def apply(o: dict[str, Any], s: dict[str, Any]) -> None:
        fn(o, s)

    return apply


def both_reports(o: dict[str, Any], s: dict[str, Any], **over: Any) -> None:
    o["report"].update(over)
    s["run"]["report"].update(over)


EXIT0_BREAKS: dict[str, Any] = {
    "outcome not done": lambda o, s: o.update(outcome="blocked"),
    "outcome failed": lambda o, s: o.update(outcome="failed"),
    "outcome needs-input": lambda o, s: o.update(outcome="needs-input"),
    "outcome missing": lambda o, s: o.pop("outcome"),
    "outcome Done": lambda o, s: o.update(outcome="Done"),
    "outcome list": lambda o, s: o.update(outcome=["done"]),
    "exit_code missing": lambda o, s: o.pop("exit_code"),
    "exit_code 3": lambda o, s: o.update(exit_code=3),
    "exit_code false": lambda o, s: o.update(exit_code=False),
    "report null": lambda o, s: o.update(report=None),
    "report missing": lambda o, s: o.pop("report"),
    "report implicit": lambda o, s: o["report"].update(implicit=True),
    "report implicit 0": lambda o, s: o["report"].update(implicit=0),
    "report implicit missing": lambda o, s: o["report"].pop("implicit"),
    "report implicit null": lambda o, s: o["report"].update(implicit=None),
    "report not done": lambda o, s: o["report"].update(status="blocked"),
    "report artifact null": lambda o, s: o["report"].update(artifact=None),
    "status empty": lambda o, s: s.clear(),
    "status run missing": lambda o, s: s.pop("run"),
    "status run list": lambda o, s: s.update(run=[]),
    "status report null": lambda o, s: s["run"].update(report=None),
    "status report missing": lambda o, s: s["run"].pop("report"),
    "status artifact null": lambda o, s: s["run"]["report"].update(artifact=None),
    "status artifact string": lambda o, s: s["run"]["report"].update(artifact="verdict.json"),
    "status report implicit": lambda o, s: s["run"]["report"].update(implicit=True),
    "status report not done": lambda o, s: s["run"]["report"].update(status="failed"),
    "status outcome not done": lambda o, s: s["run"].update(outcome="killed"),
    "status outcome missing": lambda o, s: s["run"].pop("outcome"),
    "status exit_code 16": lambda o, s: s["run"].update(exit_code=16),
    "status run number differs": lambda o, s: s["run"].update(run=2),
    "status run number bool": lambda o, s: s["run"].update(run=True),
    "name other": lambda o, s: s["run"]["report"]["artifact"].update(name="other.json"),
    "name result.md": lambda o, s: s["run"]["report"]["artifact"].update(name="result.md"),
    "name missing": lambda o, s: s["run"]["report"]["artifact"].pop("name"),
    "path missing": lambda o, s: s["run"]["report"]["artifact"].pop("path"),
    "path int": lambda o, s: s["run"]["report"]["artifact"].update(path=5),
    "path relative": lambda o, s: s["run"]["report"]["artifact"].update(path="verdict.json"),
    "path nul": lambda o, s: s["run"]["report"]["artifact"].update(path="/x\0y/verdict.json"),
    "path dotdot": lambda o, s: s["run"]["report"]["artifact"].update(
        path=s["run"]["report"]["artifact"]["path"] + "/../verdict.json"
    ),
    "path doubled slash": lambda o, s: s["run"]["report"]["artifact"].update(
        path=s["run"]["report"]["artifact"]["path"].replace("/verdict.json", "//verdict.json")
    ),
    "path huge": lambda o, s: s["run"]["report"]["artifact"].update(path="/" + "a/" * 5000),
    "sha differs": lambda o, s: s["run"]["report"]["artifact"].update(sha256="0" * 64),
    "sha uppercase": lambda o, s: s["run"]["report"]["artifact"].update(
        sha256=s["run"]["report"]["artifact"]["sha256"].upper()
    ),
    "sha short": lambda o, s: s["run"]["report"]["artifact"].update(sha256="abc"),
    "sha int": lambda o, s: s["run"]["report"]["artifact"].update(sha256=1),
    "size plus one": lambda o, s: s["run"]["report"]["artifact"].update(
        size=s["run"]["report"]["artifact"]["size"] + 1
    ),
    "size minus one": lambda o, s: s["run"]["report"]["artifact"].update(
        size=s["run"]["report"]["artifact"]["size"] - 1
    ),
    "size zero": lambda o, s: s["run"]["report"]["artifact"].update(size=0),
    "size negative": lambda o, s: s["run"]["report"]["artifact"].update(size=-1),
    "size bool": lambda o, s: s["run"]["report"]["artifact"].update(size=True),
    "size float": lambda o, s: s["run"]["report"]["artifact"].update(
        size=float(s["run"]["report"]["artifact"]["size"])
    ),
    "size over the cap": lambda o, s: s["run"]["report"]["artifact"].update(size=16385),
    "size string": lambda o, s: s["run"]["report"]["artifact"].update(size="10"),
    "outcome artifact sha differs": lambda o, s: o["report"]["artifact"].update(sha256="1" * 64),
    "outcome artifact size differs": lambda o, s: o["report"]["artifact"].update(size=1),
    "outcome artifact name differs": lambda o, s: o["report"]["artifact"].update(name="x.json"),
}


@pytest.mark.parametrize("name", sorted(EXIT0_BREAKS))
def test_every_break_of_an_exit_0_run_is_artifact_invalid_or_check_error_never_an_allow(
    tmp_path: Path, name: str
) -> None:
    run = good_run(tmp_path, mutate=mut(EXIT0_BREAKS[name]))
    j = judged(run)
    assert j.verdict == "escalate" and j.validated is None and not j.cacheable
    assert j.reason == "artifact_invalid", name


def test_exit_0_with_no_status_is_check_error(tmp_path: Path) -> None:
    run = good_run(tmp_path)
    assert result(judged(RawRun(0, run.outcome, None, NONCE))) == ("escalate", "check_error")


def test_exit_0_with_no_outcome_at_all_is_artifact_invalid(tmp_path: Path) -> None:
    run = good_run(tmp_path)
    assert result(judged(RawRun(0, None, run.status, NONCE))) == ("escalate", "artifact_invalid")
    assert result(judged(RawRun(0, None, None, NONCE))) == ("escalate", "artifact_invalid")
    assert result(judged(RawRun(0, [1], run.status, NONCE))) == ("escalate", "artifact_invalid")  # type: ignore[arg-type]
    assert result(judged(RawRun(0, run.outcome, [1], NONCE))) == ("escalate", "check_error")  # type: ignore[arg-type]


def test_a_missing_skill_run_is_artifact_invalid(tmp_path: Path) -> None:
    text = b"Unknown skill: the fake could not find the requested skill.\n"
    assert result(judged(good_run(tmp_path, text))) == ("escalate", "artifact_invalid")


def test_the_nonce_never_appears_in_the_judgement_or_the_run_repr(tmp_path: Path) -> None:
    run = good_run(tmp_path, verdict_bytes(nonce="f" * 32))
    assert NONCE not in repr(run)
    j = judged(run)
    assert NONCE not in repr(j) and "f" * 32 not in repr(j)
    ok = judged(good_run(tmp_path / "ok"))
    assert NONCE not in repr(ok)


# --- the strict validator ------------------------------------------------------------------

GOOD = verdict_doc()


def dump(doc: Any, **kw: Any) -> bytes:
    return json.dumps(doc, **kw).encode("utf-8")


def test_a_valid_artifact_parses_to_a_verdict() -> None:
    v = agentjudge.parse_artifact(dump(GOOD), NONCE)
    assert v == agentcache.Verdict("allow", 0.95, ("looks fine",))
    assert agentjudge.parse_artifact(dump(verdict_doc(confidence=1)), NONCE).confidence == 1.0
    assert isinstance(agentjudge.parse_artifact(dump(verdict_doc(confidence=0)), NONCE).confidence, float)
    assert agentjudge.parse_artifact(dump(verdict_doc(reasons=[])), NONCE).reasons == ()
    pretty = json.dumps(GOOD, indent=2) + "\n"
    assert agentjudge.parse_artifact(pretty.encode(), NONCE).decision == "allow"


BAD_ARTIFACTS: dict[str, bytes] = {
    "empty": b"",
    "whitespace": b" \n",
    "not json": b"allow",
    "array": dump([GOOD]),
    "string": dump("allow"),
    "null": b"null",
    "number": b"1",
    "truncated": dump(GOOD)[:-1],
    "trailing garbage": dump(GOOD) + b"x",
    "two objects": dump(GOOD) + dump(GOOD),
    "bom": b"\xef\xbb\xbf" + dump(GOOD),
    "invalid utf8": dump(GOOD).replace(b"looks", b"lo\xffks"),
    "latin1": "looks é".encode("latin-1").join([b'{"a":"', b'"}']),
    "nul byte": dump(GOOD).replace(b"looks", b"lo\x00ks"),
    "raw control char in string": dump(GOOD).replace(b"looks", b"lo\nks"),
    "single quotes": dump(GOOD).replace(b'"', b"'"),
    "trailing comma": dump(GOOD)[:-1] + b",}",
    "comment": b"/*x*/" + dump(GOOD),
    "NaN confidence": dump(GOOD).replace(b"0.95", b"NaN"),
    "Infinity confidence": dump(GOOD).replace(b"0.95", b"Infinity"),
    "-Infinity confidence": dump(GOOD).replace(b"0.95", b"-Infinity"),
    "huge exponent": dump(GOOD).replace(b"0.95", b"1e999"),
    "huge negative exponent confidence": dump(GOOD).replace(b"0.95", b"-1e999"),
    "huge int": dump(GOOD).replace(b"0.95", b"9" * 5000),
    "duplicate key": dump(GOOD)[:-1] + b',"decision":"deny"}',
    "duplicate key allow last": b'{"decision":"deny","schema_version":1,"nonce":"' + NONCE.encode()
    + b'","confidence":0.9,"reasons":[],"decision":"allow"}',
    "duplicate nonce": dump(GOOD)[:-1] + dump(NONCE).join([b',"nonce":', b"}"]),
    "deep nesting": b'{"a":' + b"[" * 7000 + b"]" * 7000 + b"}",
    "unknown key": dump({**GOOD, "extra": 1}),
    "unknown key null": dump({**GOOD, "x": None}),
    "case-folded key": dump({**{k: v for k, v in GOOD.items() if k != "decision"}, "Decision": "allow"}),
    "padded key": dump({**{k: v for k, v in GOOD.items() if k != "nonce"}, "nonce ": NONCE}),
    "empty object": b"{}",
    "schema 2": dump(verdict_doc(schema_version=2)),
    "schema 0": dump(verdict_doc(schema_version=0)),
    "schema true": dump(verdict_doc(schema_version=True)),
    "schema 1.0": dump(verdict_doc(schema_version=1.0)),
    "schema string": dump(verdict_doc(schema_version="1")),
    "schema null": dump(verdict_doc(schema_version=None)),
    "nonce other": dump(verdict_doc(nonce="f" * 32)),
    "nonce upper": dump(verdict_doc(nonce=NONCE.upper())),
    "nonce prefix": dump(verdict_doc(nonce=NONCE[:-1])),
    "nonce suffix": dump(verdict_doc(nonce=NONCE + "0")),
    "nonce spaced": dump(verdict_doc(nonce=" " + NONCE)),
    "nonce newline": dump(verdict_doc(nonce=NONCE + "\n")),
    "nonce int": dump(verdict_doc(nonce=int(NONCE, 16))),
    "nonce null": dump(verdict_doc(nonce=None)),
    "nonce list": dump(verdict_doc(nonce=[NONCE])),
    "nonce non-ascii": dump(verdict_doc(nonce="é" * 32)),
    "nonce surrogate": b'{"schema_version":1,"nonce":"\\ud800","decision":"allow","confidence":1,"reasons":[]}',
    "decision maybe": dump(verdict_doc(decision="maybe")),
    "decision upper": dump(verdict_doc(decision="ALLOW")),
    "decision padded": dump(verdict_doc(decision="allow ")),
    "decision list": dump(verdict_doc(decision=["allow"])),
    "decision dict": dump(verdict_doc(decision={"a": 1})),
    "decision null": dump(verdict_doc(decision=None)),
    "decision true": dump(verdict_doc(decision=True)),
    "confidence 1.5": dump(verdict_doc(confidence=1.5)),
    "confidence -0.1": dump(verdict_doc(confidence=-0.1)),
    "confidence 2": dump(verdict_doc(confidence=2)),
    "confidence -1": dump(verdict_doc(confidence=-1)),
    "confidence true": dump(verdict_doc(confidence=True)),
    "confidence false": dump(verdict_doc(confidence=False)),
    "confidence string": dump(verdict_doc(confidence="0.9")),
    "confidence null": dump(verdict_doc(confidence=None)),
    "confidence list": dump(verdict_doc(confidence=[0.9])),
    "reasons string": dump(verdict_doc(reasons="because")),
    "reasons null": dump(verdict_doc(reasons=None)),
    "reasons dict": dump(verdict_doc(reasons={"a": "b"})),
    "reasons 11": dump(verdict_doc(reasons=["r"] * 11)),
    "reasons 501 chars": dump(verdict_doc(reasons=["r" * 501])),
    "reasons non-string": dump(verdict_doc(reasons=["a", 1])),
    "reasons null item": dump(verdict_doc(reasons=[None])),
    "reasons nested": dump(verdict_doc(reasons=[["a"]])),
    "reasons dict item": dump(verdict_doc(reasons=[{"a": "b"}])),
    "missing schema_version": dump({k: v for k, v in GOOD.items() if k != "schema_version"}),
    "missing nonce": dump({k: v for k, v in GOOD.items() if k != "nonce"}),
    "missing decision": dump({k: v for k, v in GOOD.items() if k != "decision"}),
    "missing confidence": dump({k: v for k, v in GOOD.items() if k != "confidence"}),
    "missing reasons": dump({k: v for k, v in GOOD.items() if k != "reasons"}),
    "over 16 KiB": dump(verdict_doc(reasons=["r" * 400] * 10)) + b" " * 16384,
}


@pytest.mark.parametrize("name", sorted(BAD_ARTIFACTS))
def test_every_hostile_artifact_is_refused_with_a_fixed_detail(name: str) -> None:
    with pytest.raises(ArtifactError) as info:
        agentjudge.parse_artifact(BAD_ARTIFACTS[name], NONCE)
    detail = info.value.detail
    assert isinstance(detail, str) and detail and len(detail) < 100
    assert NONCE not in detail and "f" * 32 not in detail


@pytest.mark.parametrize("name", sorted(BAD_ARTIFACTS))
def test_every_hostile_artifact_is_artifact_invalid_through_the_judge(
    tmp_path: Path, name: str
) -> None:
    run = good_run(tmp_path, BAD_ARTIFACTS[name])
    if len(BAD_ARTIFACTS[name]) > 16384:
        assert result(judged(run)) == ("escalate", "artifact_invalid")
        return
    j = judged(run)
    assert result(j) == ("escalate", "artifact_invalid") and j.validated is None


def test_a_non_bytes_artifact_or_nonce_is_refused() -> None:
    for data in ("{}", None, 5, bytearray(dump(GOOD))):
        with pytest.raises(ArtifactError):
            agentjudge.parse_artifact(data, NONCE)  # type: ignore[arg-type]
    for nonce in (None, 5, "", b"x"):
        with pytest.raises(ArtifactError):
            agentjudge.parse_artifact(dump(GOOD), nonce)  # type: ignore[arg-type]


def test_an_artifact_with_an_empty_run_nonce_never_validates() -> None:
    with pytest.raises(ArtifactError):
        agentjudge.parse_artifact(dump(verdict_doc(nonce="")), "")


def test_the_nonce_is_compared_in_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[bytes, bytes]] = []
    real = agentjudge.hmac.compare_digest

    def spy(a: Any, b: Any) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(agentjudge.hmac, "compare_digest", spy)
    agentjudge.parse_artifact(dump(GOOD), NONCE)
    assert calls and all(isinstance(a, bytes) for a, _ in calls)


def test_reasons_are_sanitized_and_capped_before_they_reach_detail_and_the_cache(
    tmp_path: Path,
) -> None:
    hostile = ["ok\x1b[31mred\x00", "bidi‮evil", "line\nbreak", "\ud800lone"]
    data = dump(verdict_doc(reasons=hostile), ensure_ascii=True).decode().encode()
    j = judged(good_run(tmp_path, data))
    assert j.verdict == "allow" and j.validated is not None
    for text in (j.detail or "", *j.validated.reasons):
        assert all(c == " " or c.isprintable() for c in text)
    assert "\x1b" not in (j.detail or "") and "‮" not in (j.detail or "")
    assert j.validated.reasons[0] == "ok�[31mred�"


def test_detail_is_the_reasons_joined_and_cut_to_1024(tmp_path: Path) -> None:
    reasons = ["a" * 500] * 10
    j = judged(good_run(tmp_path, verdict_bytes(reasons=reasons)))
    assert j.detail == ("a" * 500 + "; " + "a" * 500 + "; " + "a" * 24)[:1024]
    assert len(j.detail) == 1024
    two = judged(good_run(tmp_path / "t", verdict_bytes(reasons=["one", "two"])))
    assert two.detail == "one; two"
    none = judged(good_run(tmp_path / "n", verdict_bytes(reasons=[])))
    assert none.detail is None and none.verdict == "allow"


def test_only_the_four_fields_reach_the_verdict(tmp_path: Path) -> None:
    j = judged(good_run(tmp_path))
    assert j.validated is not None
    assert set(vars(j.validated)) == {"decision", "confidence", "reasons"}


# --- reading the artifact -----------------------------------------------------------------


def test_the_artifact_is_read_once_through_the_status_path(tmp_path: Path) -> None:
    data = verdict_bytes()
    p = tmp_path / "verdict.json"
    p.write_bytes(data)
    assert agentjudge.read_artifact(artifact_entry(p, data)) == data


def invalid_read(entry: dict[str, Any]) -> str:
    with pytest.raises(ArtifactError) as info:
        agentjudge.read_artifact(entry)
    return info.value.detail


def test_a_symlink_as_the_artifact_is_refused(tmp_path: Path) -> None:
    data = verdict_bytes()
    real = tmp_path / "real.json"
    real.write_bytes(data)
    link = tmp_path / "verdict.json"
    link.symlink_to(real)
    invalid_read(artifact_entry(link, data))
    assert result(judged(good_run(tmp_path / "x"))) == ("allow", None)  # control


def test_a_symlinked_directory_component_is_refused(tmp_path: Path) -> None:
    data = verdict_bytes()
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "verdict.json").write_bytes(data)
    (tmp_path / "alias").symlink_to(tmp_path / "real")
    invalid_read(artifact_entry(tmp_path / "alias" / "verdict.json", data))
    # the same bytes through the real path are fine
    assert agentjudge.read_artifact(artifact_entry(tmp_path / "real" / "verdict.json", data)) == data


def test_a_fifo_is_refused_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "verdict.json"
    os.mkfifo(fifo)
    invalid_read(artifact_entry(fifo, b"{}"))


def test_a_directory_a_missing_file_and_a_device_are_refused(tmp_path: Path) -> None:
    d = tmp_path / "verdict.json"
    d.mkdir()
    invalid_read(artifact_entry(d, b"{}"))
    invalid_read(artifact_entry(tmp_path / "ghost.json", b"{}"))
    invalid_read(artifact_entry(Path("/dev/null"), b""))
    invalid_read(artifact_entry(Path("/"), b"{}"))


def test_a_huge_file_is_refused_by_the_cap_and_never_read_whole(tmp_path: Path) -> None:
    p = tmp_path / "verdict.json"
    with open(p, "wb") as f:
        f.truncate(50 * 1024 * 1024)  # sparse: costs no disk
    data = b"\0" * 8
    invalid_read(artifact_entry(p, data, size=50 * 1024 * 1024))  # status over the cap
    invalid_read(artifact_entry(p, data, size=8))  # status small, the file is not
    assert result(judged(good_run(tmp_path / "g"))) == ("allow", None)


def test_a_file_one_byte_over_the_cap_is_refused_even_when_status_agrees(tmp_path: Path) -> None:
    data = b" " * 16385
    p = tmp_path / "verdict.json"
    p.write_bytes(data)
    invalid_read(artifact_entry(p, data))
    ok = b" " * 16384
    p.write_bytes(ok)
    assert agentjudge.read_artifact(artifact_entry(p, ok)) == ok  # exactly at the cap is read


def test_a_truncated_or_extended_file_does_not_match_status(tmp_path: Path) -> None:
    data = verdict_bytes()
    p = tmp_path / "verdict.json"
    p.write_bytes(data[:-3])
    invalid_read(artifact_entry(p, data))
    p.write_bytes(data + b" ")
    invalid_read(artifact_entry(p, data))
    p.write_bytes(data[:-1] + b"X")  # same size, other bytes
    invalid_read(artifact_entry(p, data))


def test_a_file_swapped_after_status_is_refused(tmp_path: Path) -> None:
    run = good_run(tmp_path)
    evil = verdict_bytes(decision="allow", confidence=1, reasons=["swapped"])
    path = tmp_path / "verdict.json"
    path.chmod(0o644)
    path.write_bytes(evil + b" " * (len(verdict_bytes()) - len(evil)))  # same size, other bytes
    assert result(judged(run)) == ("escalate", "artifact_invalid")


def test_a_file_replaced_by_a_symlink_after_status_is_refused(tmp_path: Path) -> None:
    run = good_run(tmp_path)
    path = tmp_path / "verdict.json"
    other = tmp_path / "other.json"
    other.write_bytes(path.read_bytes())  # identical bytes, so only the link can be the reason
    path.unlink()
    path.symlink_to(other)
    assert result(judged(run)) == ("escalate", "artifact_invalid")


def test_a_file_rewritten_while_it_is_read_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = verdict_bytes()
    p = tmp_path / "verdict.json"
    p.write_bytes(data)
    entry = artifact_entry(p, data)
    real_read = os.read
    done: list[bool] = []

    def racing_read(fd: int, n: int) -> bytes:
        out = real_read(fd, n)
        if not done:
            done.append(True)
            with open(p, "r+b") as f:  # same size and bytes, but the file was touched
                f.write(data[:1])
            os.utime(p, ns=(1, 1))
        return out

    monkeypatch.setattr(agentjudge.os, "read", racing_read)
    invalid_read(entry)


def test_the_read_never_leaks_a_descriptor(tmp_path: Path) -> None:
    before = len(os.listdir("/proc/self/fd"))
    for i in range(30):
        p = tmp_path / f"v{i}.json"
        p.write_bytes(b"x")
        with pytest.raises(ArtifactError):
            agentjudge.read_artifact(artifact_entry(p, b"y"))
        with pytest.raises(ArtifactError):
            agentjudge.read_artifact(artifact_entry(tmp_path / "ghost" / "v", b"y"))
    assert len(os.listdir("/proc/self/fd")) == before


def test_the_read_opens_the_file_without_following_or_blocking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    flags: list[int] = []
    real = os.open

    def spy(path: Any, fl: int, *a: Any, **k: Any) -> int:
        flags.append(fl)
        return real(path, fl, *a, **k)

    monkeypatch.setattr(agentjudge.os, "open", spy)
    data = verdict_bytes()
    p = tmp_path / "verdict.json"
    p.write_bytes(data)
    agentjudge.read_artifact(artifact_entry(p, data))
    leaf = flags[-1]
    assert leaf & os.O_NOFOLLOW and leaf & os.O_NONBLOCK and leaf & os.O_CLOEXEC
    assert not leaf & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC)
    assert all(f & os.O_NOFOLLOW for f in flags[1:])  # every component after the root


def test_the_read_never_modifies_the_artifact(tmp_path: Path) -> None:
    data = verdict_bytes()
    p = tmp_path / "verdict.json"
    p.write_bytes(data)
    p.chmod(0o444)
    before = os.stat(p)
    agentjudge.read_artifact(artifact_entry(p, data))
    after = os.stat(p)
    assert (before.st_mtime_ns, before.st_ino, stat.S_IMODE(after.st_mode)) == (
        after.st_mtime_ns,
        after.st_ino,
        0o444,
    )


# --- fuzz: deterministic seeds ------------------------------------------------------------

SCALARS: list[Any] = [
    None, True, False, 0, 1, -1, 2, 0.0, 0.5, 1.0, 1.0000001, -0.0, 1e308, "", "allow", "deny",
    "escalate", "x" * 500, "x" * 501, NONCE, "é", "‮", "\x00", [], {}, [1], {"a": 1}, [None],
    ["allow"],
]  # fmt: skip


def oracle(doc: Any) -> bool:
    """An independent statement of 'valid artifact', over the parsed object."""
    if not isinstance(doc, dict) or set(doc) != set(GOOD):
        return False
    sv, nonce, decision, conf, reasons = (doc[k] for k in GOOD)
    return (
        type(sv) is int
        and sv == 1
        and isinstance(nonce, str)
        and nonce == NONCE
        and isinstance(decision, str)
        and decision in ("allow", "deny", "escalate")
        and type(conf) in (int, float)
        and 0 <= conf <= 1
        and isinstance(reasons, list)
        and len(reasons) <= 10
        and all(isinstance(r, str) and len(r) <= 500 for r in reasons)
    )


def random_doc(rng: random.Random) -> Any:
    doc = dict(GOOD)
    for _ in range(rng.randint(0, 3)):
        op = rng.choice(("set", "drop", "add", "swap"))
        key = rng.choice([*GOOD, "extra", "Decision"])
        if op == "set":
            doc[key] = rng.choice(SCALARS)
        elif op == "drop":
            doc.pop(key, None)
        elif op == "add":
            doc[key] = rng.choice(SCALARS)
        else:
            doc["reasons"] = [rng.choice(SCALARS) for _ in range(rng.randint(0, 12))]
    return doc


@pytest.mark.parametrize("seed", range(8))
def test_fuzz_structured_documents_agree_with_the_oracle(seed: int) -> None:
    rng = random.Random(seed)
    for _ in range(250):
        doc = random_doc(rng)
        try:
            data = json.dumps(doc).encode("utf-8")
        except (ValueError, TypeError):
            continue
        try:
            got: agentcache.Verdict | None = agentjudge.parse_artifact(data, NONCE)
        except ArtifactError:
            got = None
        want = oracle(json.loads(data))  # NaN and Infinity cannot appear: json.dumps wrote them
        if "NaN" in data.decode() or "Infinity" in data.decode():
            assert got is None
            continue
        assert (got is not None) == want, doc
        if got is not None:
            assert got.decision == doc["decision"] and got.confidence == float(doc["confidence"])


@pytest.mark.parametrize("seed", range(8))
def test_fuzz_corrupted_bytes_never_crash_and_never_validate_a_different_document(
    seed: int,
) -> None:
    rng = random.Random(1000 + seed)
    base = json.dumps(verdict_doc(), indent=rng.choice((None, 2))).encode()
    for _ in range(300):
        data = bytearray(base)
        for _ in range(rng.randint(1, 4)):
            op = rng.choice(("flip", "del", "ins", "cut", "dup"))
            i = rng.randrange(len(data)) if data else 0
            if op == "flip" and data:
                data[i] ^= 1 << rng.randrange(8)
            elif op == "del" and data:
                del data[i]
            elif op == "ins":
                data.insert(i, rng.randrange(256))
            elif op == "cut" and data:
                del data[i:]
            elif op == "dup" and data:
                data[i:i] = data[i : i + rng.randint(1, 12)]
        try:
            got = agentjudge.parse_artifact(bytes(data), NONCE)
        except ArtifactError:
            continue
        # accepted: it must be exactly what strict parsing of the same bytes says
        doc = json.loads(bytes(data).decode("utf-8"))
        assert oracle(doc)
        assert got.decision == doc["decision"]


@pytest.mark.parametrize("seed", range(4))
def test_fuzz_random_run_objects_never_allow_without_a_valid_file(
    tmp_path: Path, seed: int
) -> None:
    rng = random.Random(5000 + seed)
    for i in range(150):
        good = good_run(tmp_path / f"g{seed}-{i}")
        assert good.outcome is not None and good.status is not None
        outcome, status = dict(good.outcome), dict(good.status)
        code = rng.choice((0, 0, 0, 12, 13, 14, 16, 17, 18, 1))
        for target in (outcome, status):
            for _ in range(rng.randint(0, 3)):
                k = rng.choice(list(target) or ["x"])
                action = rng.choice(("pop", "scalar", "keep"))
                if action == "pop":
                    target.pop(k, None)
                elif action == "scalar":
                    target[k] = rng.choice(SCALARS)
        j = judged(RawRun(code, rng.choice((outcome, None)), rng.choice((status, None)), NONCE))
        if j.verdict == "allow":
            # an allow needs everything: exit 0, and the untouched, valid, matching artifact
            assert code == 0 and j.validated is not None and j.reason is None
            assert j.validated == agentcache.Verdict("allow", 0.95, ("looks fine",))


# --- an agent check can only tighten a combined decision ---------------------------------

SEVERITY = {"allow": 0, "escalate": 1, "deny": 2}


@pytest.mark.parametrize("seed", range(4))
def test_adding_an_agent_check_can_only_tighten_the_combined_decision(seed: int) -> None:
    from gatectl import engine

    rng = random.Random(9000 + seed)
    verdicts = ("allow", "deny", "escalate")
    for _ in range(200):
        others = [
            engine.Entry(f"c{i}", "script", rng.choice(verdicts), "x", None, 0)
            for i in range(rng.randint(0, 4))
        ]
        before = engine.combine(others).decision if others else "allow"
        verdict = rng.choice(verdicts)
        conf = rng.choice((0.0, 0.5, 0.8, 0.9, 1.0))
        threshold = rng.choice((0.0, 0.8, 1.0))
        j = agentjudge.from_verdict(agentcache.Verdict(verdict, conf, ()), threshold)
        entry = engine.Entry("a", "agent", j.verdict, j.reason, j.detail, 0, confidence=j.confidence)
        after = engine.combine([*others, entry]).decision
        assert SEVERITY[after] >= SEVERITY[before]
        # and the agent's own verdict never outranks the artifact's decision
        assert SEVERITY[j.verdict] >= SEVERITY[verdict]
