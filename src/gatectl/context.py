"""What a command handler receives and returns.

Kept apart from ``gatectl.commands`` so a handler module can import these types without
importing the command table (which imports the handler modules).
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
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
