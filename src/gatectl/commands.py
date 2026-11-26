"""The command table: every command's arguments and the registry of their handlers.

Adding a command implementation (later issues) touches two places only: write the handler in
its own module, then add one line to ``HANDLERS`` below. Argument definitions live in ``SPECS``
and are already complete for every command in interface.md, Commands; an issue that needs a
flag changes only that command's ``_add_*`` function.

A handler takes a ``Context`` and returns a ``Result``, or raises a ``GatectlError`` (the
dispatcher prints the error envelope and exits with the error's code). It never prints.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass

from gatectl import decisions, engine, export, outcomecmd, policies, setcmd, statscmd, validate
from gatectl.context import Context, Result
from gatectl.errors import InternalError

Handler = Callable[[Context], Result]


@dataclass(frozen=True)
class CommandSpec:
    name: str
    help: str
    add_arguments: Callable[[argparse.ArgumentParser], None]
    always_json: bool = False  # prints its result as JSON whatever --json says


def _add_check(p: argparse.ArgumentParser) -> None:
    p.add_argument("policy", metavar="<policy>")
    p.add_argument("--input", metavar="FILE", help="input file, or - for stdin")
    p.add_argument("--timeout", metavar="SECONDS")
    p.add_argument("--repo", metavar="ID")
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="print the plan; run and record nothing")


def _add_outcome(p: argparse.ArgumentParser) -> None:
    p.add_argument("id", metavar="<decision-id>")
    p.add_argument("outcome", choices=("agree", "disagree"), metavar="agree|disagree")
    p.add_argument("--signal", metavar="S")
    p.add_argument("--reason-file", metavar="F", help="reason file, or - for stdin")


def _add_decisions(p: argparse.ArgumentParser) -> None:
    p.add_argument("--since", metavar="T")
    p.add_argument("--policy", metavar="P")
    p.add_argument("--repo", metavar="R")
    p.add_argument("--object-id", metavar="X")
    p.add_argument("--outcome", choices=("pending", "agree", "disagree"))
    p.add_argument("--decision", choices=("allow", "deny", "escalate"))
    p.add_argument("--declared", metavar="KEY=VALUE")
    p.add_argument("--limit", metavar="N")


def _add_show(p: argparse.ArgumentParser) -> None:
    p.add_argument("id", metavar="<decision-id>")


def _add_stats(p: argparse.ArgumentParser) -> None:
    p.add_argument("--policy", metavar="P")
    p.add_argument("--repo", metavar="R")
    p.add_argument("--since", metavar="T")


def _add_set(p: argparse.ArgumentParser) -> None:
    p.add_argument("policy", metavar="<policy>")
    p.add_argument("state", choices=("off", "shadow", "enforced"), metavar="off|shadow|enforced")
    p.add_argument("--repo", metavar="ID")
    p.add_argument("--all", action="store_true")
    p.add_argument("--reason-file", metavar="F", help="reason file, or - for stdin")


def _add_policies(p: argparse.ArgumentParser) -> None:
    p.add_argument("--repo", metavar="ID")


def _add_validate(p: argparse.ArgumentParser) -> None:
    p.add_argument("--probe", action="store_true")


def _add_export(p: argparse.ArgumentParser) -> None:
    p.add_argument("--log", action="store_true", help="export log.jsonl instead of audit.jsonl")
    p.add_argument("--since", metavar="T")


def _add_reconcile(p: argparse.ArgumentParser) -> None:
    p.add_argument("--dry-run", action="store_true")


def _add_prune(p: argparse.ArgumentParser) -> None:
    p.add_argument("--older-than", metavar="D")
    p.add_argument("--dry-run", action="store_true")


def _add_cron(p: argparse.ArgumentParser) -> None:
    p.add_argument("action", choices=("install", "uninstall"), metavar="install|uninstall")
    p.add_argument("--dry-run", action="store_true")


SPECS: tuple[CommandSpec, ...] = (
    CommandSpec("check", "evaluate a policy and print the decision", _add_check, always_json=True),
    CommandSpec("outcome", "record whether a decision was right", _add_outcome),
    CommandSpec("decisions", "list recorded decisions", _add_decisions),
    CommandSpec("show", "show one decision in full", _add_show),
    CommandSpec("stats", "track records and recommendations", _add_stats),
    CommandSpec("set", "set a policy's state", _add_set),
    CommandSpec("policies", "list policies, states and records", _add_policies),
    CommandSpec("validate", "lint the config", _add_validate),
    CommandSpec("export", "print audit or log records as JSON lines", _add_export),
    CommandSpec("reconcile", "free stale slots, sessions and temp directories", _add_reconcile),
    CommandSpec("prune", "delete old decisions and expired cache rows", _add_prune),
    CommandSpec("cron", "install or remove the maintenance crontab block", _add_cron),
)

# Command name -> handler. A command with no entry fails with "command not implemented".
# TODO(#32, #33, #34): each implementing issue registers its
# handler here, one line per command.
HANDLERS: dict[str, Handler] = {
    "check": engine.handle,
    "decisions": decisions.handle_decisions,
    "export": export.handle,
    "outcome": outcomecmd.handle,
    "policies": policies.handle,
    "set": setcmd.handle,
    "show": decisions.handle_show,
    "stats": statscmd.handle,
    "validate": validate.handle,
}


def dispatch(ctx: Context) -> Result:
    handler = HANDLERS.get(ctx.command)
    if handler is None:
        raise InternalError(f"command not implemented: {ctx.command}")
    return handler(ctx)
