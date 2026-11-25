"""Scope resolution: ``--repo``, the payload repo, indeterminate scopes and effective definitions.

Table-driven over interface.md, Identifiers (Repo id and Scope) and Check order step 3.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from gatectl import commands, errors
from gatectl.cli import main
from gatectl.commands import Context, Result
from gatectl.scope import (
    STAR,
    Scope,
    check_repo_flag,
    resolve_effective,
    resolve_scope,
)
from tests.config_util import good_policy, load

A = "github.com/org/a"
B = "github.com/org/b"

# (repo flag, payload, expected scope, indeterminate, warnings)
# payload None means unusable (over the cap, not a strict JSON object, not fully read).
ROWS: list[tuple[str | None, dict[str, Any] | None, str, bool, tuple[str, ...]]] = [
    # --repo absent
    (None, {}, "*", False, ()),
    (None, {"repo": None}, "*", False, ()),
    (None, {"repo": A}, A, False, ()),
    (None, {"repo": "Github.com/org/a"}, "*", True, ("repo_invalid",)),  # upper-case host
    (None, {"repo": ""}, "*", True, ("repo_invalid",)),
    (None, {"repo": "*"}, "*", True, ("repo_invalid",)),
    (None, {"repo": 5}, "*", True, ("repo_invalid",)),
    (None, {"repo": True}, "*", True, ("repo_invalid",)),
    (None, {"repo": False}, "*", True, ("repo_invalid",)),
    (None, {"repo": 0}, "*", True, ("repo_invalid",)),
    (None, {"repo": []}, "*", True, ("repo_invalid",)),
    (None, {"repo": {}}, "*", True, ("repo_invalid",)),
    (None, {"repo": [A]}, "*", True, ("repo_invalid",)),
    (None, {"repo": A + "/"}, "*", True, ("repo_invalid",)),
    (None, {"repo": A + "\n"}, "*", True, ("repo_invalid",)),
    (None, {"repo": "github.com/org/.."}, "*", True, ("repo_invalid",)),
    (None, {"repo": "github.com/./a"}, "*", True, ("repo_invalid",)),
    (None, {"repo": "github.com/" + "a" * 300}, "*", True, ("repo_invalid",)),
    (None, None, "*", True, ()),  # unusable input: no repo can be trusted
    # --repo given: the payload never selects the scope or the state
    (A, {}, A, False, ()),
    (A, {"repo": None}, A, False, ()),
    (A, {"repo": A}, A, False, ()),
    (A, {"repo": B}, A, False, ("repo_mismatch",)),
    (A, {"repo": "github.com/org/A"}, A, False, ("repo_mismatch",)),  # no case folding
    (A, {"repo": "Github.com/org/a"}, A, False, ("repo_invalid",)),  # not valid: invalid wins
    (A, {"repo": 5}, A, False, ("repo_invalid",)),
    (A, {"repo": ""}, A, False, ("repo_invalid",)),
    (A, {"repo": "*"}, A, False, ("repo_invalid",)),
    (A, None, A, False, ()),  # an unusable input does not unseat a trusted --repo
]


@pytest.mark.parametrize("payload", [[], [A], "x", A, 5, True, False, 1.5])
def test_a_non_mapping_payload_is_unusable(payload: Any) -> None:
    assert resolve_scope(None, payload) == Scope("*", True, ())
    assert resolve_scope(A, payload) == Scope(A, False, ())


@pytest.mark.parametrize(("flag", "payload", "scope", "indeterminate", "warnings"), ROWS)
def test_scope_rows(
    flag: str | None,
    payload: dict[str, Any] | None,
    scope: str,
    indeterminate: bool,
    warnings: tuple[str, ...],
) -> None:
    got = resolve_scope(flag, payload)
    assert got == Scope(scope, indeterminate, warnings)


def test_a_payload_without_repo_is_scope_star_and_never_warns() -> None:
    # A caller whose payload has no repo (a tracker hook, say) is ordinary, not an error.
    got = resolve_scope(None, {"project": "x", "action": "start"})
    assert got.scope == STAR and not got.indeterminate and got.warnings == ()


def test_the_payload_is_never_modified_or_echoed() -> None:
    payload = {"repo": "https://user:secret@github.com/org/a"}
    got = resolve_scope(None, payload)
    assert got.indeterminate and "secret" not in repr(got)
    assert payload == {"repo": "https://user:secret@github.com/org/a"}


@pytest.mark.parametrize(
    "url",
    [
        "https://user:secret@github.com/org/a",
        "git@github.com:org/a.git",
        "user:secret@github.com/org/a",
        "github.com/org/a?token=abc",
        "github.com/org/a#frag",
        "github.com/org/a@x",
        "github.com/org/*",
        "github.com/org/a b",
        "github.com/org/а",  # Cyrillic a
        "github.com/org/a\x00",
        "github.com/org/a\x1b[31m",
        "github.com/org/a‮",
        "gіthub.com/org/a",  # Cyrillic i in the host
        "github.com/org//a",
        "//github.com/org/a",
        "/github.com/org/a",
        "github.com",
        "github.com/",
        "github.com:/org/a",
        "github.com:123456/org/a",
        "github.com\\org\\a",
    ],
)
def test_hostile_repos_are_invalid_and_never_echoed(url: str) -> None:
    got = resolve_scope(None, {"repo": url})
    assert got == Scope(STAR, True, ("repo_invalid",))
    with pytest.raises(errors.UsageError) as exc:
        check_repo_flag("check", url)
    assert "secret" not in exc.value.message and url not in exc.value.message
    assert errors.exit_code_of(exc.value) == 2


@pytest.mark.parametrize("path", [".", "..", "a/./b", "a/../b", "a/.."])
def test_dot_segments_are_invalid(path: str) -> None:
    assert resolve_scope(None, {"repo": f"github.com/{path}"}).indeterminate


def test_dotted_names_that_are_not_dot_segments_are_valid() -> None:
    for tail in ("...", ".a", "a.", "..a", "a..b", ".git"):
        assert resolve_scope(None, {"repo": f"github.com/o/{tail}"}).scope.endswith(tail), tail


def test_repo_length_boundary() -> None:
    prefix = "github.com/"
    ok = prefix + "a" * (255 - len(prefix))
    assert resolve_scope(None, {"repo": ok}).scope == ok
    assert resolve_scope(None, {"repo": ok + "a"}).indeterminate
    # a huge value is rejected without work or echo
    assert resolve_scope(None, {"repo": "a" * 10_000_000}).indeterminate


def test_a_repo_with_a_port_is_valid() -> None:
    r = "git.example.com:8443/team/proj"
    assert resolve_scope(None, {"repo": r}).scope == r


# --- the --repo flag per command ----------------------------------------------------------

STAR_COMMANDS = ("decisions", "stats", "policies", "set")
FLAG_COMMANDS = ("check", "decisions", "stats", "policies", "set")


@pytest.mark.parametrize("command", FLAG_COMMANDS)
def test_flag_accepts_a_valid_repo_everywhere(command: str) -> None:
    assert check_repo_flag(command, A) == A


@pytest.mark.parametrize("command", FLAG_COMMANDS)
@pytest.mark.parametrize(
    "bad", ["", " ", "Github.com/org/a", A + "/", A + "\n", "..", "a", "github.com/org/..", "**"]
)
def test_flag_failing_the_grammar_exits_2_everywhere(command: str, bad: str) -> None:
    with pytest.raises(errors.UsageError):
        check_repo_flag(command, bad)


@pytest.mark.parametrize("command", STAR_COMMANDS)
def test_star_is_accepted_where_listed(command: str) -> None:
    assert check_repo_flag(command, "*") == "*"


def test_star_is_refused_by_check() -> None:
    with pytest.raises(errors.UsageError):
        check_repo_flag("check", "*")


@pytest.mark.parametrize("command", ["outcome", "show", "validate", "export", "prune", "cron"])
def test_star_is_refused_by_any_other_command(command: str) -> None:
    with pytest.raises(errors.UsageError):
        check_repo_flag(command, "*")


def test_an_absent_flag_is_none() -> None:
    assert check_repo_flag("check", None) is None


# --- through the CLI -----------------------------------------------------------------------


@pytest.fixture
def seen(monkeypatch: pytest.MonkeyPatch) -> list[Context]:
    contexts: list[Context] = []

    def handler(ctx: Context) -> Result:
        contexts.append(ctx)
        return Result(payload={"ok": True})

    monkeypatch.setattr(
        commands, "HANDLERS", {n: handler for n in (*FLAG_COMMANDS, "show", "validate")}
    )
    return contexts


def _argv(command: str, repo: str) -> list[str]:
    base = {
        "check": ["check", "pol"],
        "set": ["set", "pol", "off"],
    }.get(command, [command])
    return [*base, "--repo", repo]


@pytest.mark.parametrize("command", FLAG_COMMANDS)
def test_cli_rejects_a_bad_repo_with_exit_2_and_no_echo(
    seen: list[Context], capsys: pytest.CaptureFixture[str], command: str
) -> None:
    secret = "https://user:hunter2@github.com/org/a"
    code = main([*_argv(command, secret), "--json"])
    out = capsys.readouterr()
    assert code == 2 and seen == []
    assert "hunter2" not in out.out + out.err
    assert json.loads(out.out)["error"]["code"] == "usage"


def test_cli_check_refuses_star_but_decisions_accepts_it(
    seen: list[Context], capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(_argv("check", "*")) == 2
    capsys.readouterr()
    assert seen == []
    assert main(_argv("decisions", "*")) == 0
    assert seen[-1].args.repo == "*"


def test_cli_passes_a_valid_repo_through_unchanged(seen: list[Context]) -> None:
    assert main(_argv("check", A)) == 0
    assert seen[-1].args.repo == A


# --- effective definitions -----------------------------------------------------------------


def _config(tmp_path: Path) -> Any:
    return load(
        tmp_path,
        {
            "policies": {
                "p": good_policy(timeout="9s", input={"require": ["a"]}),
                "q": good_policy(),
            },
            "repos": {A: {"policies": {"p": {"timeout": "5s"}}}},
        },
    )


@pytest.mark.parametrize(
    ("scope", "timeout"),
    [
        (Scope(A, False, ()), 5),
        (Scope(B, False, ()), 9),
        (Scope("github.com/org/A", False, ()), 9),  # exact comparison: no case folding
        (Scope(STAR, False, ()), 9),
        (Scope(STAR, True, ("repo_invalid",)), 9),
    ],
)
def test_effective_definition_by_scope(tmp_path: Path, scope: Scope, timeout: int) -> None:
    eff = resolve_effective(_config(tmp_path), "p", scope)
    assert eff.policy.timeout is not None and eff.policy.timeout.total_seconds() == timeout
    assert eff.scope == scope.scope
    assert eff.indeterminate is scope.indeterminate
    assert eff.warnings == scope.warnings


def test_an_indeterminate_scope_never_applies_a_repo_override(tmp_path: Path) -> None:
    c = _config(tmp_path)
    got = resolve_effective(c, "p", resolve_scope(None, {"repo": A + "/"}))
    assert got.indeterminate and got.overridden is False
    assert got.policy == c.resolve_policy("p")


def test_a_hand_built_indeterminate_repo_scope_never_applies_an_override(tmp_path: Path) -> None:
    c = _config(tmp_path)
    got = resolve_effective(c, "p", Scope(A, True, ()))
    assert got.overridden is False
    assert got.policy == c.resolve_policy("p")


def test_overridden_flag(tmp_path: Path) -> None:
    c = _config(tmp_path)
    assert resolve_effective(c, "p", Scope(A, False, ())).overridden is True
    assert resolve_effective(c, "q", Scope(A, False, ())).overridden is False
    assert resolve_effective(c, "p", Scope(B, False, ())).overridden is False


def test_unknown_policy_is_a_usage_error(tmp_path: Path) -> None:
    with pytest.raises(errors.UsageError):
        resolve_effective(_config(tmp_path), "nope", Scope(A, False, ()))


def test_a_broken_override_fails_only_its_scope(tmp_path: Path) -> None:
    c = load(
        tmp_path,
        {
            "policies": {"p": good_policy()},
            "repos": {A: {"policies": {"p": {"state": "off"}}}},
        },
    )
    with pytest.raises(errors.ConfigInvalidError):
        resolve_effective(c, "p", Scope(A, False, ()))
    assert resolve_effective(c, "p", Scope(B, False, ())).policy is not None
    assert resolve_effective(c, "p", Scope(STAR, True, ())).policy is not None


def test_an_override_is_matched_on_the_whole_repo_not_a_prefix(tmp_path: Path) -> None:
    c = _config(tmp_path)
    for other in (A + "x", A + "/sub", "x" + A, A.upper()):
        assert resolve_effective(c, "p", Scope(other, False, ())).overridden is False, other
