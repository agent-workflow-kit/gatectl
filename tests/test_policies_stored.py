"""``gatectl policies``: the stored view (state rows, the effective state, definition changes)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from gatectl import fingerprint as fp
from gatectl import store
from gatectl.cli import main
from tests import golden, schema_util
from tests.command_util import CANARY, config_file, isolate, rule, run, script
from tests.set_util import (
    ALIEN,
    OTHER,
    REPO,
    STALE,
    current_fingerprint,
    seed,
)

MARKER = "sha256:" + "0" * 64


@pytest.fixture(autouse=True)
def state_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    return isolate(monkeypatch, tmp_path)


def make(tmp_path: Path, policies: dict[str, Any] | None = None, **top: Any) -> str:
    body = policies if policies is not None else {"p": {"checks": [rule()]}}
    return config_file(tmp_path, {"policies": body, **top})


def view(
    capsys: pytest.CaptureFixture[str], config: str, *extra: str
) -> tuple[int, dict[str, Any], str]:
    code, out, err = run(capsys, ["policies", "--json", "--config", config, *extra])
    return code, (json.loads(out) if out else {}), err


def only(doc: dict[str, Any], name: str = "p") -> dict[str, Any]:
    (found,) = [p for p in doc["policies"] if p["name"] == name]
    return found


def test_the_stored_view_is_golden(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    state_dir: Path,
) -> None:
    fixed = "sha256:" + "ab" * 32
    monkeypatch.setattr(fp, "fingerprint", lambda *a, **k: fixed)
    config = make(tmp_path, {"auto-merge": {"checks": [rule("ci-green")]}})
    s = store.open_store(state_dir, create=True)
    assert s is not None
    with s, s.write():
        s.write_state_row(
            "auto-merge",
            "*",
            "enforced",
            set_by="human:ann",
            set_at="2026-11-24T12:00:00.000000Z",
            cause="set",
            fingerprint=fixed,
        )
    from tests.history_util import did, put_decision, put_outcome

    for n in (1, 2):  # two clean, human-confirmed allows: n = 2, k = 0
        put_decision(
            state_dir,
            did(n),
            policy="auto-merge",
            fingerprint=fixed,
            case_key=f"{n:064x}",
            checks=[],
        )
        put_outcome(state_dir, did(n), "agree", actor="human:ann")
    assert main(["policies", "--config", config, "--json"]) == 0
    golden.assert_output("policies", capsys.readouterr().out)


def test_no_database_shows_the_initial_state_and_creates_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    _, doc, _ = view(capsys, make(tmp_path))
    p = only(doc)
    assert p["scopes"] == [] and p["records"] == []
    assert p["effective_state"] == p["initial_state"] == "shadow"
    assert p["effective_cause"] is None and p["effective_set_at"] is None
    assert not state_dir.exists()


def test_scopes_list_every_stored_row_with_its_fields(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make(tmp_path)
    star = seed(state_dir, "p", "*", "shadow", fingerprint_=ALIEN, set_by="human:ann")
    repo = seed(state_dir, "p", REPO, "off", fingerprint_=STALE, cause="miss", set_by="auto:x")
    _, doc, _ = view(capsys, config)
    assert only(doc)["scopes"] == [
        {
            "scope": "*",
            "state": "shadow",
            "set_by": "human:ann",
            "set_at": "2026-01-01T00:00:00.000000Z",
            "cause": "set",
            "fingerprint": ALIEN,
            "definition_changed": False,
            "rev": star.rev,
        },
        {
            "scope": REPO,
            "state": "off",
            "set_by": "auto:x",
            "set_at": "2026-01-01T00:00:00.000000Z",
            "cause": "miss",
            "fingerprint": STALE,
            "definition_changed": False,
            "rev": repo.rev,
        },
    ]
    schema_util.assert_valid("cli/policies", doc)


def test_other_policies_rows_are_not_mixed_in(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make(tmp_path, {"p": {"checks": [rule()]}, "q": {"checks": [rule()]}})
    seed(state_dir, "q", "*", "off")
    _, doc, _ = view(capsys, config)
    assert only(doc, "p")["scopes"] == [] and only(doc, "p")["effective_state"] == "shadow"
    assert only(doc, "q")["effective_state"] == "off"


def test_effective_state_is_the_repo_row_then_the_star_row_then_the_initial_state(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make(tmp_path, {"p": {"state": "off", "checks": [rule()]}})
    _, doc, _ = view(capsys, config, "--repo", REPO)
    assert only(doc)["effective_state"] == "off"
    star = seed(state_dir, "p", "*", "shadow")
    _, doc, _ = view(capsys, config, "--repo", REPO)
    p = only(doc)
    assert p["effective_state"] == "shadow" and p["effective_set_at"] == star.set_at
    repo = seed(
        state_dir, "p", REPO, "enforced", fingerprint_=current_fingerprint(config, "p", REPO)
    )
    _, doc, _ = view(capsys, config, "--repo", REPO)
    assert only(doc)["effective_state"] == "enforced"
    assert only(doc)["effective_set_at"] == repo.set_at
    _, doc, _ = view(capsys, config, "--repo", OTHER)  # no row of its own: the * row
    assert only(doc)["effective_state"] == "shadow"
    _, doc, _ = view(capsys, config)  # the * scope never sees a repo row
    assert only(doc)["effective_state"] == "shadow"
    _, doc, _ = view(capsys, config, "--repo", "*")
    assert only(doc)["effective_state"] == "shadow"
    assert {s["scope"] for s in only(doc)["scopes"]} == {"*", REPO}  # every stored row is listed


def test_the_effective_cause_is_the_cause_of_the_row_that_decides(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make(tmp_path)
    seed(state_dir, "p", "*", "shadow", cause="miss", set_by="auto:gatectl")
    seed(state_dir, "p", REPO, "enforced", fingerprint_=current_fingerprint(config, "p", REPO))
    _, doc, _ = view(capsys, config)
    assert only(doc)["effective_cause"] == "miss"
    _, doc, _ = view(capsys, config, "--repo", REPO)
    assert only(doc)["effective_cause"] == "set"
    schema_util.assert_valid("cli/policies", doc)


def test_a_stale_enforced_row_is_marked_definition_changed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make(tmp_path)
    seed(state_dir, "p", "*", "enforced", fingerprint_=STALE)
    _, doc, _ = view(capsys, config)
    (row,) = only(doc)["scopes"]
    assert row["definition_changed"] is True and row["fingerprint"] == STALE
    assert only(doc)["effective_state"] == "enforced"  # the state does not change


def test_a_current_enforced_row_is_not_definition_changed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make(tmp_path)
    seed(state_dir, "p", "*", "enforced", fingerprint_=current_fingerprint(config, "p"))
    _, doc, _ = view(capsys, config)
    assert only(doc)["scopes"][0]["definition_changed"] is False


def test_a_row_is_compared_with_its_own_scopes_definition(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make(
        tmp_path,
        {"p": {"checks": [rule("base")]}},
        repos={REPO: {"policies": {"p": {"checks": [script("own")]}}}},
    )
    own = current_fingerprint(config, "p", REPO)
    glob = current_fingerprint(config, "p")
    assert own != glob
    seed(state_dir, "p", "*", "enforced", fingerprint_=glob)
    seed(state_dir, "p", REPO, "enforced", fingerprint_=own)
    seed(state_dir, "p", OTHER, "enforced", fingerprint_=own)  # the global one is current there
    _, doc, _ = view(capsys, config)
    changed = {s["scope"]: s["definition_changed"] for s in only(doc)["scopes"]}
    assert changed == {"*": False, REPO: False, OTHER: True}


@pytest.mark.parametrize("state", ["off", "shadow"])
def test_a_non_enforced_row_is_never_definition_changed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path, state: str
) -> None:
    config = make(tmp_path)
    seed(state_dir, "p", "*", state, fingerprint_=STALE)
    _, doc, _ = view(capsys, config)
    assert only(doc)["scopes"][0]["definition_changed"] is False


def test_the_marker_fingerprint_is_not_shown_as_a_real_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make(tmp_path)
    seed(state_dir, "p", "*", "shadow", fingerprint_=MARKER)
    seed(state_dir, "p", REPO, "off", fingerprint_=MARKER)
    code, out, _ = run(capsys, ["policies", "--json", "--config", config])
    doc = json.loads(out)
    assert code == 0 and MARKER not in out
    assert [s["fingerprint"] for s in only(doc)["scopes"]] == [None, None]
    assert [s["definition_changed"] for s in only(doc)["scopes"]] == [False, False]
    schema_util.assert_valid("cli/policies", doc)


def test_an_enforced_row_with_the_marker_is_definition_changed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    seed(state_dir, "p", "*", "enforced", fingerprint_=MARKER)
    _, doc, _ = view(capsys, make(tmp_path))
    assert only(doc)["scopes"][0]["definition_changed"] is True  # impossible by set: a tamper


def test_an_enforced_row_whose_scope_definition_is_invalid_is_definition_changed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make(
        tmp_path,
        {"p": {"checks": [rule()]}},
        repos={REPO: {"policies": {"p": {"checks": []}}}},  # an invalid override
    )
    seed(state_dir, "p", REPO, "enforced", fingerprint_=STALE)
    code, doc, _ = view(capsys, config)
    assert code == 0
    assert only(doc)["scopes"][0]["definition_changed"] is True


def test_rows_of_a_removed_policy_are_not_listed_and_return_with_the_name(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    seed(state_dir, "gone", "*", "off", set_by="human:ann")
    seed(state_dir, "gone", REPO, "shadow")
    _, doc, _ = view(capsys, make(tmp_path))
    assert [p["name"] for p in doc["policies"]] == ["p"]  # policies lists configured ones only
    again = make(tmp_path / "again", {"p": {"checks": [rule()]}, "gone": {"checks": [rule()]}})
    _, doc, _ = view(capsys, again)
    back = only(doc, "gone")
    assert [(s["scope"], s["state"]) for s in back["scopes"]] == [("*", "off"), (REPO, "shadow")]
    assert back["effective_state"] == "off" and back["initial_state"] == "shadow"


def test_records_come_from_the_decision_history(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    from tests.history_util import put_decision

    config = make(tmp_path)
    put_decision(
        state_dir, "gd-aakkkkkkkkkk", policy="p", fingerprint=current_fingerprint(config, "p")
    )
    _, doc, _ = view(capsys, config)
    (record,) = only(doc)["records"]
    assert (record["policy"], record["repo"], record["current"]) == ("p", None, True)
    assert record["recommend"] == "not_yet" and record["decisions"]["allow"] == 1


def test_hostile_stored_text_in_a_state_row_is_refused_never_echoed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    evil = f"{CANARY}\x1b[31m\x00‮" + "x" * 2000
    seed(state_dir, "p", "*", "shadow", set_by="human:ann")
    from tests.history_util import sql

    sql(state_dir, "UPDATE policy_state SET set_by = ?, set_at = ?", evil, evil)
    config = make(tmp_path)
    code, out, err = run(capsys, ["policies", "--json", "--config", config])
    assert code == 1 and json.loads(out)["error"]["code"] == "internal"
    assert CANARY not in out + err and "\\u001b" not in out and "\\u202e" not in out
    code, out, err = run(capsys, ["policies", "--config", config])
    assert code == 1 and CANARY not in out + err
    assert all(c == "\n" or c.isprintable() for c in out + err)


@pytest.mark.parametrize(
    "update",
    [
        "UPDATE policy_state SET state = 'x'",
        "UPDATE policy_state SET scope = 'Not A Repo'",
        "UPDATE policy_state SET cause = 'y'",
        "UPDATE policy_state SET rev = 0",
    ],
)
def test_a_tampered_row_exits_1_with_fixed_text(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path, update: str
) -> None:
    seed(state_dir, "p", "*", "shadow")
    import sqlite3

    con = sqlite3.connect(state_dir / "state.db")
    con.execute("PRAGMA ignore_check_constraints = ON")
    con.execute(update)
    con.commit()
    con.close()
    code, out, err = run(capsys, ["policies", "--json", "--config", make(tmp_path)])
    assert code == 1 and json.loads(out)["error"]["code"] == "internal"
    assert "Not A Repo" not in out + err


def test_the_stored_view_never_writes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    seed(state_dir, "p", "*", "enforced", fingerprint_=STALE)
    before = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in state_dir.iterdir()
        if p.is_file() and p.stat().st_size > 0 and not p.name.endswith("-shm")
    }
    config = make(tmp_path)
    view(capsys, config)
    view(capsys, config, "--repo", REPO)
    after = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in state_dir.iterdir()
        if p.is_file() and p.stat().st_size > 0 and not p.name.endswith("-shm")
    }
    assert before == after


def test_text_form_lists_each_scope_row(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    config = make(tmp_path)
    seed(state_dir, "p", "*", "enforced", fingerprint_=STALE, set_by="human:ann")
    seed(state_dir, "p", REPO, "shadow", fingerprint_=MARKER, cause="miss", set_by="auto:gatectl")
    code, out, err = run(capsys, ["policies", "--config", config])
    assert (code, err) == (0, "")
    assert "  * enforced human:ann" in out and "definition changed" in out
    assert f"  {REPO} shadow auto:gatectl" in out and "miss" in out
    assert MARKER not in out
    assert all(c == "\n" or c.isprintable() for c in out)


# --- round 1 ------------------------------------------------------------------------------------


def test_a_history_and_no_state_db_exits_1_state_db_missing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    state_dir.mkdir(parents=True, mode=0o700)
    (state_dir / "audit.jsonl").write_text('{"ts":"2026-11-24T12:00:00.000000Z"}\n')
    code, doc, _ = view(capsys, make(tmp_path))
    assert code == 1 and doc["error"]["reason"] == "state_db_missing"


@pytest.mark.parametrize(
    ("column", "value"),
    [
        ("set_by", "root"),
        ("set_by", "human:" + "x" * 100),
        ("set_by", f"human:{CANARY}\x1b[31m"),
        ("set_at", "yesterday"),
        ("set_at", "2026-11-24T12:00:00Z"),
        ("fingerprint", "sha256:abc"),
        ("fingerprint", "x" * 2000),
        ("fingerprint", "sha256:" + "A" * 64),
    ],
)
def test_schema_invalid_set_by_set_at_or_fingerprint_is_refused(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    state_dir: Path,
    column: str,
    value: str,
) -> None:
    from tests.history_util import sql

    seed(state_dir, "p", "*", "shadow", set_by="human:ann")
    sql(state_dir, f"UPDATE policy_state SET {column} = ?", value)  # noqa: S608
    code, out, err = run(capsys, ["policies", "--json", "--config", make(tmp_path)])
    assert code == 1 and json.loads(out)["error"]["code"] == "internal"
    assert json.loads(out)["error"]["message"] == "state.db holds an invalid state row"
    assert CANARY not in out + err


def test_a_nul_in_a_stored_row_value_is_not_hidden_by_sqlite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path
) -> None:
    """substr() stops at a NUL: ``human:ann<NUL>junk`` must not be read as ``human:ann``."""
    from tests.history_util import sql

    seed(state_dir, "p", "*", "shadow", set_by="human:ann")
    sql(state_dir, "UPDATE policy_state SET set_by = ?", "human:ann\x00junk")
    code, out, _ = run(capsys, ["policies", "--json", "--config", make(tmp_path)])
    assert code == 1
    assert json.loads(out)["error"]["message"] == "state.db holds an invalid state row"


@pytest.mark.parametrize("column", ["scope", "state", "cause"])
def test_a_nul_after_a_valid_closed_value_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state_dir: Path, column: str
) -> None:
    seed(state_dir, "p", "*", "shadow")
    current = {"scope": "*", "state": "shadow", "cause": "set"}[column]
    # the CHECK constraints are per connection: a tamper writes past them
    import sqlite3

    con = sqlite3.connect(state_dir / "state.db")
    con.execute("PRAGMA ignore_check_constraints = ON")
    con.execute(f"UPDATE policy_state SET {column} = ?", (current + "\x00junk",))  # noqa: S608
    con.commit()
    con.close()
    code, out, _ = run(capsys, ["policies", "--json", "--config", make(tmp_path)])
    assert code == 1
    assert json.loads(out)["error"]["message"] == "state.db holds an invalid state row"
