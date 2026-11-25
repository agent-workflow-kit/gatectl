"""Command-line entry point for gatectl: parsing, dispatch, output and the error envelope."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Iterator, Mapping
from dataclasses import replace
from typing import Any, NoReturn

from gatectl import __version__, commands, errors, ids, scope
from gatectl.commands import CommandSpec, Context, Result
from gatectl.sanitize import sanitize

STDERR_CAP = 512  # interface.md, check: one sanitized line, at most 512 characters
_GLOBAL_DESTS = frozenset(
    {"json", "config", "verbose", "quiet", "actor", "decision_ids_top", "decision_ids_sub"}
)

_ARGUMENT_ERROR = re.compile(r"argument ([^:]+): (.*)", re.DOTALL)


def _safe_parse_message(message: str) -> str:
    """Reduce an argparse message to text that names the argument but never quotes a value."""
    if message.startswith("the following arguments are required: "):
        return message  # only flag and metavar names
    if message.startswith("unrecognized arguments"):
        return "unrecognized arguments"
    found = _ARGUMENT_ERROR.fullmatch(message)
    if found is not None:
        name, rest = found.groups()
        if rest.startswith("expected "):
            return f"argument {name}: {rest}"
        if rest.startswith("invalid choice"):
            return f"argument {name}: invalid choice"
        return f"argument {name}: invalid value"
    return "invalid usage"


class _Parser(argparse.ArgumentParser):
    """An argparse parser whose errors raise ``UsageError`` with a value-free message."""

    def error(self, message: str) -> NoReturn:
        raise errors.UsageError(sanitize(_safe_parse_message(message), 256))


def _add_global_flags(parser: argparse.ArgumentParser, *, top: bool) -> None:
    """Add the global flags. On a subparser every default is suppressed so a flag given before
    the command is not reset; ``--decision-id`` uses its own dest in each place and the two lists
    are merged afterwards."""

    def default(value: Any) -> Any:
        return value if top else argparse.SUPPRESS

    parser.add_argument(
        "--json", action="store_true", default=default(False), help="emit machine-readable JSON"
    )
    parser.add_argument(
        "--config", metavar="PATH", default=default(None), help="config file (replaces the default)"
    )
    parser.add_argument(
        "--verbose", action="store_true", default=default(False), help="more stderr output"
    )
    parser.add_argument(
        "--quiet", action="store_true", default=default(False), help="less stderr output"
    )
    parser.add_argument(
        "--actor", metavar="A", default=default(None), help="human:<name> or auto:<name>"
    )
    parser.add_argument(
        "--decision-id",
        metavar="ID",
        action="append",
        default=default(None),
        dest="decision_ids_top" if top else "decision_ids_sub",
        help="the caller's own decision id (repeatable, at most 16)",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="gatectl",
        description="Policy decisions (allow / deny / escalate) with first-class shadow mode.",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=f"gatectl {__version__}")
    _add_global_flags(parser, top=True)
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    for spec in commands.SPECS:
        child = sub.add_parser(
            spec.name,
            help=spec.help,
            description=spec.help,
            allow_abbrev=False,
            prog=f"gatectl {spec.name}",
        )
        spec.add_arguments(child)
        _add_global_flags(child, top=False)
    return parser


def _stdin_is_tty() -> bool:
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (ValueError, OSError):
        return False


def _context(ns: argparse.Namespace) -> Context:
    """Validate the global flags and build the handler's context."""
    decision_ids = ids.validate_caller_decision_ids(
        [*(ns.decision_ids_top or ()), *(getattr(ns, "decision_ids_sub", None) or ())]
    )
    if ns.actor is not None:
        ids.parse_actor(ns.actor)
    if hasattr(ns, "repo"):
        scope.check_repo_flag(ns.command, ns.repo)
    own = {k: v for k, v in vars(ns).items() if k not in _GLOBAL_DESTS and k != "command"}
    return Context(
        command=ns.command,
        args=argparse.Namespace(**own),
        json=ns.json,
        config=ns.config,
        verbose=ns.verbose and not ns.quiet,  # --quiet wins when both are given
        quiet=ns.quiet,
        actor=ns.actor,
        decision_ids=decision_ids,
        stdin_tty=_stdin_is_tty(),
    )


def render_json(payload: Mapping[str, Any]) -> str:
    """The one JSON form of every printed result: compact, ASCII only, one line, newline last.

    Key order is the producer's (``schema_version`` first); tests pin it with golden files.
    """
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n"


def _write(stream: Any, text: str) -> bool:
    """Write and flush; a closed, broken or full stream is ignored so the exit code survives.
    False when the write failed.

    After a failed write the stream's file descriptor is pointed at ``/dev/null`` so the flush of
    the interpreter's shutdown stays quiet and cannot turn the exit code into 120.
    """
    try:
        stream.write(text)
        stream.flush()
    except (OSError, ValueError, AttributeError):  # AttributeError: the stream is None (closed fd)
        _silence(stream)
        return False
    return True


def _silence(stream: Any) -> None:
    try:
        fd = stream.fileno()
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, fd)
        finally:
            os.close(devnull)
    except (OSError, ValueError, AttributeError):
        pass  # no real descriptor (a captured stream, or already closed): nothing to redirect


def _stderr_line(text: str) -> str:
    return sanitize(text, STDERR_CAP).replace("\n", " ") + "\n"


def _error_exit(exc: BaseException, *, json_mode: bool, is_check: bool, policy: str | None) -> int:
    envelope = errors.envelope(exc)
    body = envelope["error"]
    if is_check or json_mode:
        _write(sys.stdout, render_json(envelope))
    if is_check:
        # One line built from closed fields only (interface.md, check).
        line = f"gatectl: {body['code']}" + (f" {policy}" if policy else "")
        _write(sys.stderr, _stderr_line(line))
    elif not json_mode:
        # --quiet never suppresses this line: cron's `reconcile --quiet` must keep its reason.
        _write(sys.stderr, _stderr_line(f"gatectl: {body['code']}: {body['message']}"))
    return errors.exit_code_of(exc)


def _spec(name: str | None) -> CommandSpec | None:
    return next((s for s in commands.SPECS if s.name == name), None)


_GLOBAL_VALUE_FLAGS = frozenset({"--config", "--actor", "--decision-id"})


def _value_flags(spec: CommandSpec) -> frozenset[str]:
    """The option strings of a command (and the global flags) that take a value."""
    probe = argparse.ArgumentParser(add_help=False)
    spec.add_arguments(probe)
    own = {o for a in probe._actions if a.nargs != 0 for o in a.option_strings}  # noqa: SLF001
    return _GLOBAL_VALUE_FLAGS | own


def _prescan(argv: list[str]) -> tuple[str | None, bool, str | None]:
    """Find (command, real --json, check's policy name) in argv that failed to parse.

    A token counts only as a real flag or command outside the value of a value-taking flag and
    before ``--``. The command is the first remaining non-flag token, and only if it names a
    command. The policy is the first positional after ``check``, only if it is a valid name.
    """
    command: str | None = None
    value_flags = _GLOBAL_VALUE_FLAGS
    json_flag = False
    policy: str | None = None
    policy_seen = False
    command_seen = False
    skip = False
    for token in argv:
        if skip:
            skip = False
            continue
        if token == "--":
            break
        if token.startswith("-"):
            if token == "--json":
                json_flag = True
            elif token in value_flags:
                skip = True
            continue
        if not command_seen:
            command_seen = True
            spec = _spec(token)
            if spec is not None:
                command = token
                value_flags = _value_flags(spec)
        elif command == "check" and not policy_seen:
            policy_seen = True
            policy = token if ids.is_policy_name(token) else None
    return command, json_flag, policy


def main(argv: list[str] | None = None) -> int:
    args_in = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    try:
        ns = parser.parse_args(args_in)
    except errors.UsageError as exc:
        # The parse failed, so the command is unknown; scan the tokens only to pick the output
        # form (an error envelope for check and --json, a text line otherwise).
        command, json_flag, policy = _prescan(args_in)
        is_check = command == "check"
        return _error_exit(
            exc, json_mode=json_flag, is_check=is_check, policy=policy if is_check else None
        )
    if ns.command is None:
        return _error_exit(
            errors.UsageError("no command given"), json_mode=ns.json, is_check=False, policy=None
        )
    spec = _spec(ns.command)
    is_check = bool(spec and spec.always_json)
    policy = getattr(ns, "policy", None) if is_check else None
    if not (isinstance(policy, str) and ids.is_policy_name(policy)):
        policy = None
    try:
        ctx = _context(ns)
        result = commands.dispatch(ctx)
        return _emit(result, json_mode=ctx.json or is_check)
    except Exception as exc:  # the envelope hides the text of anything that is not ours
        return _error_exit(exc, json_mode=ns.json, is_check=is_check, policy=policy)


def _stream(chunks: Iterator[str]) -> None:
    """Write a streamed result chunk by chunk; stop (and close the source) at a failed write.
    An error the source raises propagates: what was written stays, the envelope follows."""
    try:
        for chunk in chunks:
            if not _write(sys.stdout, chunk):
                break
    finally:
        close = getattr(chunks, "close", None)
        if close is not None:
            close()


def _emit(result: Result, *, json_mode: bool) -> int:
    if result.stream is not None:
        _stream(result.stream)
        if result.stderr_after is not None:
            result = replace(result, stderr=result.stderr_after() or result.stderr)
    elif result.payload is not None and (json_mode or result.text is None):
        _write(sys.stdout, render_json(result.payload))
    elif result.text is not None:
        _write(sys.stdout, result.text + "\n")
    if result.stderr is not None:
        _write(sys.stderr, _stderr_line(result.stderr))
    return result.exit_code
