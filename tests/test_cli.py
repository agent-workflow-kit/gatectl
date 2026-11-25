from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

from gatectl import commands
from gatectl.cli import main
from gatectl.commands import Context, Result
from gatectl.errors import UsageError
from tests import schema_util

ALL_COMMANDS = (
    "check",
    "outcome",
    "decisions",
    "show",
    "stats",
    "set",
    "policies",
    "validate",
    "export",
    "reconcile",
    "prune",
    "cron",
)

# The smallest valid argv (without global flags) for each command.
MIN_ARGV: dict[str, list[str]] = {
    "check": ["check", "pol"],
    "outcome": ["outcome", "gd-abcdefghijkl", "agree"],
    "decisions": ["decisions"],
    "show": ["show", "gd-abcdefghijkl"],
    "stats": ["stats"],
    "set": ["set", "pol", "off"],
    "policies": ["policies"],
    "validate": ["validate"],
    "export": ["export"],
    "reconcile": ["reconcile"],
    "prune": ["prune"],
    "cron": ["cron", "install"],
}


@pytest.fixture
def seen(monkeypatch: pytest.MonkeyPatch) -> list[Context]:
    """Replace every handler with one that records its context and returns an empty result."""
    contexts: list[Context] = []

    def handler(ctx: Context) -> Result:
        contexts.append(ctx)
        return Result(payload={"ok": True})

    monkeypatch.setattr(commands, "HANDLERS", {name: handler for name in ALL_COMMANDS})
    return contexts


def run(capsys: pytest.CaptureFixture[str], argv: list[str]) -> tuple[int, str, str]:
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# --- version and help ---------------------------------------------------------------------


def test_version_prints_version_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == "gatectl 0.0.0"


def test_the_command_table_lists_every_documented_command() -> None:
    assert tuple(spec.name for spec in commands.SPECS) == ALL_COMMANDS


def test_no_arguments_is_a_usage_error() -> None:
    assert main([]) == 2


def test_top_level_help_names_every_command(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for name in ALL_COMMANDS:
        assert name in out


@pytest.mark.parametrize("name", ALL_COMMANDS)
def test_help_works_for_every_command(name: str, capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main([name, "--help"])
    assert exc.value.code == 0
    assert f"gatectl {name}" in capsys.readouterr().out


# --- global flags -------------------------------------------------------------------------


@pytest.mark.parametrize("name", ALL_COMMANDS)
def test_every_command_accepts_every_global_flag_after_its_name(
    name: str, seen: list[Context], capsys: pytest.CaptureFixture[str]
) -> None:
    argv = [
        *MIN_ARGV[name],
        "--json",
        "--config",
        "/c.yaml",
        "--verbose",
        "--actor",
        "human:ann",
        "--decision-id",
        "a1",
        "--decision-id",
        "b2",
    ]
    code, _, _ = run(capsys, argv)
    assert code == 0
    ctx = seen[0]
    assert ctx.json is True
    assert ctx.config == "/c.yaml"
    assert ctx.verbose is True
    assert ctx.quiet is False
    assert ctx.actor == "human:ann"
    assert ctx.decision_ids == ("a1", "b2")


def test_global_flags_also_work_before_the_command_and_merge(
    seen: list[Context], capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, _ = run(
        capsys,
        ["--quiet", "--decision-id", "a1", "stats", "--decision-id", "b2", "--actor", "auto:x"],
    )
    assert code == 0
    ctx = seen[0]
    assert ctx.quiet is True
    assert ctx.decision_ids == ("a1", "b2")
    assert ctx.actor == "auto:x"


def test_a_flag_after_the_command_does_not_reset_one_given_before_it(
    seen: list[Context], capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, ["--json", "--config", "/c.yaml", "stats"])
    assert seen[0].json is True
    assert seen[0].config == "/c.yaml"


def test_defaults_when_no_global_flag_is_given(
    seen: list[Context], capsys: pytest.CaptureFixture[str]
) -> None:
    run(capsys, ["stats"])
    ctx = seen[0]
    assert (ctx.json, ctx.config, ctx.verbose, ctx.quiet, ctx.actor) == (
        False,
        None,
        False,
        False,
        None,
    )
    assert ctx.decision_ids == ()


def _error_of(out: str) -> dict[str, Any]:
    document = json.loads(out)
    schema_util.assert_valid("cli/error", document)
    return document["error"]


def test_sixteen_decision_ids_are_accepted(
    seen: list[Context], capsys: pytest.CaptureFixture[str]
) -> None:
    flags = [x for i in range(16) for x in ("--decision-id", f"id{i}")]
    code, _, _ = run(capsys, ["stats", *flags])
    assert code == 0
    assert len(seen[0].decision_ids) == 16


def test_a_seventeenth_decision_id_exits_2(
    seen: list[Context], capsys: pytest.CaptureFixture[str]
) -> None:
    flags = [x for i in range(17) for x in ("--decision-id", f"id{i}")]
    code, out, err = run(capsys, ["stats", "--json", *flags])
    assert code == 2
    assert seen == []
    assert _error_of(out)["code"] == "usage"
    assert "id16" not in out + err


def test_the_decision_id_limit_counts_both_positions(
    seen: list[Context], capsys: pytest.CaptureFixture[str]
) -> None:
    before = [x for i in range(9) for x in ("--decision-id", f"id{i}")]
    after = [x for i in range(8) for x in ("--decision-id", f"jd{i}")]
    code, _, _ = run(capsys, [*before, "stats", *after])
    assert code == 2
    assert seen == []


@pytest.mark.parametrize(
    "bad", ["", "has space", "x" * 129, "semi;colon", "new\nline", "ünï", "a$b", "SECRET#TOKEN"]
)
def test_a_bad_decision_id_exits_2_without_echoing_it(
    bad: str, seen: list[Context], capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = run(capsys, ["stats", "--json", "--decision-id", bad])
    assert code == 2
    assert seen == []
    assert _error_of(out)["code"] == "usage"
    for text in (out, err):
        assert bad.strip() == "" or bad not in text


@pytest.mark.parametrize(
    "bad",
    ["", "bob", "human:", "human:a b", "robot:x", "human:" + "n" * 65, "auto:\x1b[31m", "HUMAN:x"],
)
def test_a_bad_actor_exits_2_without_echoing_it(
    bad: str, seen: list[Context], capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = run(capsys, ["stats", "--json", "--actor", bad])
    assert code == 2
    assert seen == []
    assert _error_of(out)["code"] == "usage"
    for text in (out, err):
        assert bad in ("", "human:") or bad not in text  # "human:" is in the fixed text


def test_verbose_and_quiet_together_are_a_usage_error(
    seen: list[Context], capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = run(capsys, ["stats", "--json", "--verbose", "--quiet"])
    assert code == 2
    assert _error_of(out)["code"] == "usage"


# --- parse errors never echo input --------------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ["SECRET-cmd"],
        ["stats", "--SECRET-flag"],
        ["stats", "SECRET-extra"],
        ["outcome", "gd-abcdefghijkl", "SECRET-choice"],
        ["set", "pol", "SECRET-state"],
        ["cron", "SECRET-action"],
        ["--SECRET-flag", "stats"],
        ["stats", "--limit", "SECRET"],
        ["check", "pol", "--timeout"],
        ["--config"],
    ],
)
def test_parse_errors_exit_2_and_never_echo_the_value(
    argv: list[str], seen: list[Context], capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, err = run(capsys, [*argv, "--json"])
    assert code == 2
    assert "SECRET" not in out + err
    assert _error_of(out)["code"] == "usage"


def test_a_missing_positional_is_a_usage_error(
    seen: list[Context], capsys: pytest.CaptureFixture[str]
) -> None:
    code, out, _ = run(capsys, ["show", "--json"])
    assert code == 2
    assert _error_of(out)["code"] == "usage"


def test_abbreviated_flags_are_not_accepted(
    seen: list[Context], capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, _ = run(capsys, ["stats", "--jso"])
    assert code == 2


# --- command-specific flags ---------------------------------------------------------------


def test_command_specific_flags_reach_the_handler(
    seen: list[Context], capsys: pytest.CaptureFixture[str]
) -> None:
    run(
        capsys,
        [
            "check", "pol", "--input", "-", "--timeout", "2.5", "--repo", "h/o/r",
            "--no-cache", "--dry-run",
        ],
    )  # fmt: skip
    a = seen[-1].args
    assert (a.policy, a.input, a.timeout, a.repo, a.no_cache, a.dry_run) == (
        "pol", "-", "2.5", "h/o/r", True, True,
    )  # fmt: skip
    run(capsys, ["outcome", "gd-abc", "disagree", "--signal", "human", "--reason-file", "-"])
    a = seen[-1].args
    assert (a.id, a.outcome, a.signal, a.reason_file) == ("gd-abc", "disagree", "human", "-")
    run(
        capsys,
        [
            "decisions", "--since", "1h", "--policy", "p", "--repo", "*", "--object-id", "x",
            "--outcome", "pending", "--decision", "deny", "--declared", "k=v", "--limit", "5",
        ],
    )  # fmt: skip
    a = seen[-1].args
    assert (a.since, a.policy, a.repo, a.object_id, a.outcome, a.decision) == (
        "1h", "p", "*", "x", "pending", "deny",
    )  # fmt: skip
    assert (a.declared, a.limit) == ("k=v", "5")
    run(capsys, ["set", "pol", "enforced", "--repo", "h/o/r", "--all", "--reason-file", "f"])
    a = seen[-1].args
    assert (a.policy, a.state, a.repo, a.all, a.reason_file) == (
        "pol", "enforced", "h/o/r", True, "f",
    )  # fmt: skip
    run(capsys, ["export", "--log", "--since", "1d"])
    assert (seen[-1].args.log, seen[-1].args.since) == (True, "1d")
    run(capsys, ["validate", "--probe"])
    assert seen[-1].args.probe is True
    run(capsys, ["reconcile", "--dry-run"])
    assert seen[-1].args.dry_run is True
    run(capsys, ["prune", "--older-than", "30d", "--dry-run"])
    assert (seen[-1].args.older_than, seen[-1].args.dry_run) == ("30d", True)
    run(capsys, ["cron", "uninstall", "--dry-run"])
    assert (seen[-1].args.action, seen[-1].args.dry_run) == ("uninstall", True)
    run(capsys, ["policies", "--repo", "h/o/r"])
    assert seen[-1].args.repo == "h/o/r"
    run(capsys, ["stats", "--policy", "p", "--repo", "*", "--since", "1h"])
    assert (seen[-1].args.policy, seen[-1].args.repo, seen[-1].args.since) == ("p", "*", "1h")


def test_the_choices_are_closed(seen: list[Context], capsys: pytest.CaptureFixture[str]) -> None:
    for argv in (
        ["outcome", "gd-abc", "maybe"],
        ["set", "pol", "on"],
        ["decisions", "--outcome", "done"],
        ["decisions", "--decision", "block"],
        ["cron", "list"],
    ):
        assert run(capsys, argv)[0] == 2


# --- output and errors --------------------------------------------------------------------


def _stub(monkeypatch: pytest.MonkeyPatch, name: str, fn: Callable[[Context], Result]) -> None:
    monkeypatch.setattr(commands, "HANDLERS", {name: fn})


def test_check_always_prints_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub(monkeypatch, "check", lambda ctx: Result(payload={"a": 1}, text="human"))
    code, out, _ = run(capsys, ["check", "pol"])
    assert (code, out) == (0, '{"a":1}\n')


def test_other_commands_print_text_without_json_and_json_with_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub(monkeypatch, "stats", lambda ctx: Result(payload={"a": 1}, text="human line"))
    assert run(capsys, ["stats"]) == (0, "human line\n", "")
    assert run(capsys, ["stats", "--json"]) == (0, '{"a":1}\n', "")


def test_a_payload_without_text_prints_json_even_without_the_flag(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub(monkeypatch, "stats", lambda ctx: Result(payload={"a": "é"}))
    assert run(capsys, ["stats"]) == (0, '{"a":"\\u00e9"}\n', "")


def test_the_handler_exit_code_is_returned_and_stderr_text_is_sanitized(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub(
        monkeypatch,
        "check",
        lambda ctx: Result(payload={"a": 1}, exit_code=11, stderr="gatectl: deny p\x1b[0m"),
    )
    code, out, err = run(capsys, ["check", "pol"])
    assert code == 11
    assert out == '{"a":1}\n'
    assert err == "gatectl: deny p�[0m\n"


def test_a_check_error_prints_the_envelope_and_one_stderr_line(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(ctx: Context) -> Result:
        raise UsageError("unknown policy", details={"kind": "unknown_policy"})

    _stub(monkeypatch, "check", boom)
    code, out, err = run(capsys, ["check", "pol"])
    assert code == 2
    body = _error_of(out)
    assert (body["code"], body["details"]) == ("usage", {"kind": "unknown_policy"})
    assert err == "gatectl: usage pol\n"


def test_the_check_stderr_line_omits_a_policy_that_is_not_a_valid_name(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(ctx: Context) -> Result:
        raise UsageError("x")

    _stub(monkeypatch, "check", boom)
    code, out, err = run(capsys, ["check", "BAD\x1b name"])
    assert code == 2
    assert err == "gatectl: usage\n"
    assert "BAD" not in out


def test_check_prints_its_stderr_line_even_when_quiet(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(ctx: Context) -> Result:
        raise UsageError("x")

    _stub(monkeypatch, "check", boom)
    assert run(capsys, ["check", "pol", "--quiet"])[2] == "gatectl: usage pol\n"


def test_other_commands_print_a_human_error_line_without_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(ctx: Context) -> Result:
        from gatectl.errors import NotFoundError

        raise NotFoundError("no such decision")

    _stub(monkeypatch, "show", boom)
    code, out, err = run(capsys, ["show", "gd-abcdefghijkl"])
    assert (code, out, err) == (10, "", "gatectl: not_found: no such decision\n")
    code, out, err = run(capsys, ["show", "gd-abcdefghijkl", "--json"])
    assert code == 10
    assert _error_of(out)["code"] == "not_found"
    assert err == ""
    assert run(capsys, ["show", "gd-abcdefghijkl", "--quiet"]) == (10, "", "")


def test_an_unexpected_exception_exits_1_without_leaking_its_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(ctx: Context) -> Result:
        raise RuntimeError("SECRET /home/x")

    _stub(monkeypatch, "stats", boom)
    code, out, err = run(capsys, ["stats", "--json"])
    assert code == 1
    assert _error_of(out)["code"] == "internal"
    assert "SECRET" not in out + err


def test_an_unimplemented_command_fails_with_a_clear_internal_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(commands, "HANDLERS", {})
    code, out, _ = run(capsys, ["policies", "--json"])
    assert code == 1
    body = _error_of(out)
    assert body["code"] == "internal"
    assert body["message"] == "command not implemented: policies"


def test_every_command_is_unimplemented_or_has_a_handler(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Whatever the registry holds, a command never crashes the parser: it exits through a handler
    # or through the not-implemented error.
    assert set(commands.HANDLERS) <= set(ALL_COMMANDS)


def test_a_bare_run_exits_cleanly_when_stdin_is_not_a_tty(
    seen: list[Context], capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("sys.stdin", None)
    assert run(capsys, ["stats"])[0] == 0
    assert seen[0].stdin_tty is False
