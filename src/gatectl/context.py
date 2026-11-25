"""What a command handler receives and returns.

Kept apart from ``gatectl.commands`` so a handler module can import these types without
importing the command table (which imports the handler modules).
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Context:
    """What a handler gets: the validated global flags and its own parsed arguments."""

    command: str
    args: argparse.Namespace
    json: bool
    config: str | None
    verbose: bool
    quiet: bool
    actor: str | None  # validated against the grammar, not yet resolved to a default
    decision_ids: tuple[str, ...]  # the caller's --decision-id values, validated
    stdin_tty: bool


@dataclass(frozen=True)
class Result:
    """What a handler returns.

    ``payload`` is the result object. It is printed as JSON when ``--json`` is given, always for
    ``check``, and whenever there is no ``text``. ``text`` is the human form (already sanitized
    by the handler) used without ``--json``. ``stderr`` is one sanitized line for stderr.
    """

    payload: Mapping[str, Any] | None = None
    text: str | None = None
    exit_code: int = 0
    stderr: str | None = None
    # A result too large to hold (``export``): chunks of stdout text, written as they come. The
    # handler still never prints; the dispatcher writes each chunk and stops at a closed pipe.
    # ``stderr_after`` runs once the stream ends and may give the one stderr line.
    stream: Iterator[str] | None = None
    stderr_after: Callable[[], str | None] | None = None
