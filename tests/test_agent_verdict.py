"""The outcome table and the artifact rules of an agent check, end to end through ``check``
against the fake claude-session (issue #25): every row of interface.md's table, the threshold,
the cache write conditions and the hostile artifacts. The real judge runs; nothing is stubbed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from gatectl import agentjudge
from tests.agent_util import Fake, agent_check, config, limits_env, tmp_entries
from tests.check_util import REPO, do_check, isolate, rows, write_input
from tests.command_util import config_file
from tests.proc_util import Tracker

INPUT = {"ci": "ok", "repo": REPO}


@pytest.fixture
def sdir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], cfg: dict[str, Any], *extra: str
) -> dict[str, Any]:
    path = config_file(tmp_path, cfg)
    _, doc, _ = do_check(capsys, path, "p", "--input", write_input(tmp_path, INPUT), *extra)
    return doc


def entry(doc: dict[str, Any]) -> tuple[str, str | None]:
    return doc["checks"][0]["verdict"], doc["checks"][0]["reason"]


def cache_count(sdir: Path) -> int:
    return len(rows(sdir, "SELECT key FROM agent_cache"))


def clean(fake: Fake, sdir: Path) -> None:
    assert fake.unforgotten() == []
    assert tmp_entries(sdir) == []
    assert rows(sdir, "SELECT * FROM agent_slots") == []


# --- the table, row by row ------------------------------------------------------------------

TABLE = [
    # scenario, expected (verdict, reason), the calls made
    ("valid", ("allow", None), ["start", "exec", "status", "forget"]),
    ("done_timeout_end", ("allow", None), ["start", "exec", "status", "forget"]),
    ("unreported", ("escalate", "agent_unreported"), ["start", "exec", "forget"]),
    ("unreported_no_result", ("escalate", "agent_unreported"), ["start", "exec", "forget"]),
    ("timeout", ("escalate", "timeout"), ["start", "exec", "forget"]),
    ("needs_input", ("escalate", "check_escalated"), ["start", "exec", "forget"]),
    ("blocked", ("escalate", "check_escalated"), ["start", "exec", "forget"]),
    ("failed", ("escalate", "check_error"), ["start", "exec", "forget"]),
    ("killed", ("escalate", "check_error"), ["start", "exec", "forget"]),
    ("lost", ("escalate", "check_error"), ["start", "exec", "forget"]),
    ("nonce_mismatch", ("escalate", "artifact_invalid"), ["start", "exec", "status", "forget"]),
    ("wrong_schema", ("escalate", "artifact_invalid"), ["start", "exec", "status", "forget"]),
    ("no_artifact", ("escalate", "artifact_invalid"), ["start", "exec", "status", "forget"]),
    ("missing_skill", ("escalate", "artifact_invalid"), ["start", "exec", "status", "forget"]),
    ("implicit_done", ("escalate", "artifact_invalid"), ["start", "exec", "status", "forget"]),
    ("exit0_not_done", ("escalate", "artifact_invalid"), ["start", "exec", "status", "forget"]),
    (
        "status_sha_mismatch",
        ("escalate", "artifact_invalid"),
        ["start", "exec", "status", "forget"],
    ),
    (
        "status_size_mismatch",
        ("escalate", "artifact_invalid"),
        ["start", "exec", "status", "forget"],
    ),
    (
        "status_name_mismatch",
        ("escalate", "artifact_invalid"),
        ["start", "exec", "status", "forget"],
    ),
    # exit 12 at start (the session is allocated and forgotten) ...
    ("sandbox_unavailable", ("escalate", "sandbox_unavailable"), None),
    ("claude_not_found", ("escalate", "tool_missing"), None),
    ("unsafe_setting_sources", ("escalate", "check_error"), None),
    # ... and at adoption (exec exit 12)
    ("sandbox_unavailable@exec", ("escalate", "sandbox_unavailable"), ["start", "exec", "forget"]),
    ("claude_not_found@exec", ("escalate", "tool_missing"), ["start", "exec", "forget"]),
    ("unsafe_setting_sources@exec", ("escalate", "check_error"), ["start", "exec", "forget"]),
]


@pytest.mark.parametrize(("scenario", "want", "verbs"), TABLE, ids=[t[0] for t in TABLE])
def test_each_row_of_the_outcome_table_maps_to_its_reason(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
    scenario: str,
    want: tuple[str, str | None],
    verbs: list[str] | None,
) -> None:
    fake = Fake(tmp_path, scenario)
    limits_env(monkeypatch, tracker)
    doc = run(tmp_path, capsys, config(fake))
    assert entry(doc) == want
    assert doc["decision"] == ("allow" if want[0] == "allow" else "escalate")
    got = fake.verbs()
    if verbs is not None and "status" in verbs:
        assert got == verbs
    elif verbs is not None:
        assert "status" not in got and got[:2] == ["start", "exec"] and got[-1] == "forget"
    assert cache_count(sdir) == (1 if want[0] == "allow" else 0)  # only a valid done artifact
    clean(fake, sdir)


@pytest.mark.parametrize("outcome", ["blocked", "failed", "needs-input"])
def test_exit_0_with_an_outcome_that_is_not_done_is_artifact_invalid(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path, "exit0_not_done", FAKE_CS_EXIT0_OUTCOME=outcome)
    limits_env(monkeypatch, tracker)
    assert entry(run(tmp_path, capsys, config(fake))) == ("escalate", "artifact_invalid")
    assert cache_count(sdir) == 0


def test_a_done_run_with_the_end_reason_timeout_is_used_as_a_verdict(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path, "done_timeout_end", FAKE_CS_DECISION="deny")
    limits_env(monkeypatch, tracker)
    doc = run(tmp_path, capsys, config(fake))
    assert entry(doc) == ("deny", "check_denied")
    assert doc["checks"][0]["detail"] == "fake reason"
    assert cache_count(sdir) == 1


def test_the_unsafe_setting_sources_refusal_is_check_error_with_the_token_in_the_detail(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path, "unsafe_setting_sources")
    limits_env(monkeypatch, tracker)
    doc = run(tmp_path, capsys, config(fake))
    assert entry(doc) == ("escalate", "check_error")
    assert doc["checks"][0]["detail"] == "launch refused: unsafe_setting_sources"


# --- decisions, confidence and the threshold ------------------------------------------------


@pytest.mark.parametrize(
    ("decision", "confidence", "want"),
    [
        ("allow", "0.95", ("allow", None)),
        ("allow", "0.8", ("allow", None)),  # equal to the default threshold passes
        ("allow", "0.79", ("escalate", "low_confidence")),
        ("allow", "0", ("escalate", "low_confidence")),
        ("allow", "1", ("allow", None)),
        ("deny", "0", ("deny", "check_denied")),
        ("deny", "0.99", ("deny", "check_denied")),
        ("escalate", "0", ("escalate", "check_escalated")),
        ("escalate", "1", ("escalate", "check_escalated")),
    ],
)
def test_the_artifact_decision_stands_and_only_an_allow_is_gated_by_confidence(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    decision: str,
    confidence: str,
    want: tuple[str, str | None],
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path, FAKE_CS_DECISION=decision, FAKE_CS_CONFIDENCE=confidence)
    limits_env(monkeypatch, tracker)
    assert entry(run(tmp_path, capsys, config(fake))) == want
    assert cache_count(sdir) == 1  # a valid artifact of a done run, whatever it decided


def test_a_per_check_threshold_overrides_the_agent_default(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    limits_env(monkeypatch, tracker)
    fake = Fake(tmp_path, FAKE_CS_CONFIDENCE="0.6")
    low = config(fake, agent_block={"threshold": 0.5}, checks=[agent_check(threshold=0.7)])
    assert entry(run(tmp_path, capsys, low)) == ("escalate", "low_confidence")
    fake2 = Fake(tmp_path / "two", FAKE_CS_CONFIDENCE="0.6")
    high = config(fake2, agent_block={"threshold": 0.9}, checks=[agent_check(threshold=0.5)])
    assert entry(run(tmp_path, capsys, high)) == ("allow", None)
    fake3 = Fake(tmp_path / "three", FAKE_CS_CONFIDENCE="0.6")
    default = config(fake3, agent_block={"threshold": 0.7})
    assert entry(run(tmp_path, capsys, default)) == ("escalate", "low_confidence")


def test_a_deny_is_never_loosened_by_any_threshold(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    limits_env(monkeypatch, tracker)
    fake = Fake(tmp_path, FAKE_CS_DECISION="deny", FAKE_CS_CONFIDENCE="0")
    cfg = config(fake, checks=[agent_check(threshold=1.0)])
    doc = run(tmp_path, capsys, cfg)
    assert entry(doc) == ("deny", "check_denied") and doc["decision"] == "deny"


def test_the_detail_is_the_sanitized_reasons_joined_and_capped(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    reasons = ["fine‮\x1b[0m", "second"]
    fake = Fake(tmp_path, FAKE_CS_REASONS=json.dumps(reasons))
    limits_env(monkeypatch, tracker)
    doc = run(tmp_path, capsys, config(fake))
    detail = doc["checks"][0]["detail"]
    assert detail == "fine��[0m; second"


def test_a_long_reasons_list_is_capped_at_1024(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path, FAKE_CS_REASONS=json.dumps(["r" * 500] * 10))
    limits_env(monkeypatch, tracker)
    doc = run(tmp_path, capsys, config(fake))
    assert len(doc["checks"][0]["detail"]) == 1024


@pytest.mark.parametrize(
    "env",
    [
        {"FAKE_CS_CONFIDENCE": "1.5"},
        {"FAKE_CS_CONFIDENCE": "-0.1"},
        {"FAKE_CS_CONFIDENCE": '"0.9"'},
        {"FAKE_CS_CONFIDENCE": "true"},
        {"FAKE_CS_CONFIDENCE": "null"},
        {"FAKE_CS_DECISION": "maybe"},
        {"FAKE_CS_DECISION": "ALLOW"},
        {"FAKE_CS_REASONS": json.dumps(["r"] * 11)},
        {"FAKE_CS_REASONS": json.dumps(["r" * 501])},
        {"FAKE_CS_REASONS": json.dumps([1])},
        {"FAKE_CS_REASONS": '"because"'},
        {"FAKE_CS_NONCE": "f" * 32},
    ],
)
def test_a_bad_field_in_an_otherwise_valid_run_is_artifact_invalid_and_never_cached(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    env: dict[str, str],
    tracker: Tracker,
) -> None:
    fake = Fake(tmp_path, **env)
    limits_env(monkeypatch, tracker)
    doc = run(tmp_path, capsys, config(fake))
    assert entry(doc) == ("escalate", "artifact_invalid")
    assert doc["decision"] == "escalate" and cache_count(sdir) == 0
    assert "f" * 32 not in json.dumps(doc)


# --- hostile status objects (wrapped around the fake) ----------------------------------------


REWRITE = """\
import json, os, subprocess, sys
mode, argv = sys.argv[1], sys.argv[2:]
done = subprocess.run(argv, capture_output=True)
out = done.stdout
if "status" in argv and "--json" in argv:
    obj = json.loads(out)
    rep = obj["run"]["report"]
    art = rep["artifact"]
    real = art["path"]
    folder = os.path.dirname(os.path.dirname(os.path.dirname(real)))
    if mode == "symlink":
        link = os.path.join(folder, "link.json")
        os.symlink(real, link)
        art["path"] = link
    elif mode == "dir_symlink":
        link = os.path.join(folder, "linkdir")
        os.symlink(os.path.dirname(real), link)
        art["path"] = link + "/verdict.json"
    elif mode == "null_artifact":
        rep["artifact"] = None
    elif mode == "no_report":
        obj["run"]["report"] = None
    elif mode == "other_run":
        obj["run"]["run"] = 2
    elif mode == "not_done":
        obj["run"]["outcome"] = "failed"
    out = json.dumps(obj).encode()
sys.stdout.buffer.write(out)
sys.stderr.buffer.write(done.stderr)
sys.exit(done.returncode)
"""


@pytest.mark.parametrize(
    "mode",
    ["symlink", "dir_symlink", "null_artifact", "no_report", "other_run", "not_done"],
)
def test_a_hostile_status_object_is_artifact_invalid_even_with_a_valid_file_behind_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    tracker: Tracker,
) -> None:
    import sys

    script = tmp_path / "rewrite.py"
    script.write_text(REWRITE, encoding="utf-8")
    fake = Fake(tmp_path)
    cmd = [sys.executable, str(script), mode, *fake.cmd]
    limits_env(monkeypatch, tracker)
    doc = run(tmp_path, capsys, config(None, session_cmd=cmd))
    assert entry(doc) == ("escalate", "artifact_invalid")
    assert cache_count(sdir) == 0 and doc["decision"] == "escalate"


def test_the_agentjudge_module_spawns_nothing() -> None:
    source = Path(agentjudge.__file__).read_text(encoding="utf-8")
    for word in ("subprocess", "gateway", "os.system", "os.exec", "os.spawn", "popen"):
        assert word not in source


def test_an_allow_through_check_always_has_a_valid_artifact_behind_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    sdir: Path,
    monkeypatch: pytest.MonkeyPatch,
    tracker: Tracker,
) -> None:
    """Every scenario of the fake: an allow comes out of exactly the two scenarios whose run is
    done with a valid artifact."""
    limits_env(monkeypatch, tracker)
    import re

    from tests.fake_session import FAKE

    text = Path(FAKE).read_text(encoding="utf-8")
    block = text[text.index("SESSION_SCENARIOS = {") : text.index("HANG_SCENARIOS")]
    in_fake = set(re.findall(r'^    "(\w+)": \(', block, re.M)) | set(
        re.findall(r'^    "(\w+)": \(', text[text.index("LAUNCH_FAILURES = {") :], re.M)
    )
    assert in_fake <= {t[0] for t in TABLE}  # every scenario of the fake has a row in the table
    allows = set()
    for scenario in sorted(t[0] for t in TABLE):
        sub = tmp_path / scenario.replace("@", "_")
        sub.mkdir()
        doc = run(sub, capsys, config(Fake(sub, scenario)), "--no-cache")
        if doc["checks"][0]["verdict"] == "allow":
            allows.add(scenario)
    assert allows == {"valid", "done_timeout_end"}
