"""Identifier grammars, decision ids, actors and durations (interface.md, Identifiers).

Validators that only answer yes or no return a bool. Parsers that turn a flag value into a
typed value raise ``UsageError`` (exit 2) with a fixed message that never echoes the value.
"""

from __future__ import annotations

import base64
import os
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import timedelta

from gatectl.errors import AmbiguousError, NotFoundError, UsageError

_NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_SIGNAL = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_CALLER_ID = re.compile(r"[A-Za-z0-9._:@/-]{1,128}")
_DECISION_ID = re.compile(r"gd-[a-z2-7]{12}")
_BASE32_PREFIX = re.compile(r"[a-z2-7]*")
# The repo grammar of schemas/defs.json (``repo_id``), written for ``fullmatch`` (``$`` would
# also match before a trailing newline).
_REPO = re.compile(
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*"
    r"(?::[0-9]{1,5})?(?:/(?!\.\.?(?:/|\Z))[A-Za-z0-9._-]+)+"
)
_ACTOR = re.compile(r"(human|auto):([A-Za-z0-9._@-]{1,64})")
_ACTOR_BAD_CHAR = re.compile(r"[^A-Za-z0-9._@-]")
_DURATION = re.compile(r"([0-9]{1,15})(ms|s|m|h|d)")

MAX_REPO_LEN = 255
MAX_CALLER_DECISION_IDS = 16
DECISION_PREFIX_MIN = 6
DECISION_ID_CHARS = 12
_UNITS = {
    "ms": "milliseconds",
    "s": "seconds",
    "m": "minutes",
    "h": "hours",
    "d": "days",
}


def _full(pattern: re.Pattern[str], value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def is_policy_name(value: str) -> bool:
    return _full(_NAME, value)


def is_check_name(value: str) -> bool:
    return _full(_NAME, value)


def is_signal(value: str) -> bool:
    return _full(_SIGNAL, value)


def is_caller_decision_id(value: str) -> bool:
    """The hook decision-id grammar callers validate; also the ``--decision-id`` grammar."""
    return _full(_CALLER_ID, value)


def is_repo_id(value: str) -> bool:
    return isinstance(value, str) and len(value) <= MAX_REPO_LEN and _full(_REPO, value)


def is_decision_id(value: str) -> bool:
    return _full(_DECISION_ID, value)


def validate_caller_decision_ids(values: Sequence[str]) -> tuple[str, ...]:
    """Check the repeatable ``--decision-id`` values: at most 16, each in the grammar."""
    if len(values) > MAX_CALLER_DECISION_IDS:
        raise UsageError("too many --decision-id values (at most 16)")
    for value in values:
        if not is_caller_decision_id(value):
            raise UsageError("invalid --decision-id value")
    return tuple(values)


# --- decision ids -----------------------------------------------------------------------


def new_decision_id(random_bytes: Callable[[int], bytes] = os.urandom) -> str:
    """``gd-`` plus 12 lowercase base32 characters from 8 random bytes (60 of the 64 bits)."""
    raw = random_bytes(8)
    if len(raw) != 8:
        raise ValueError("random source returned the wrong number of bytes")
    return "gd-" + base64.b32encode(raw).decode("ascii").lower()[:DECISION_ID_CHARS]


@dataclass(frozen=True)
class DecisionRef:
    """A parsed decision reference: the base32 text after ``gd-`` (6 to 12 characters)."""

    prefix: str

    @property
    def is_full(self) -> bool:
        return len(self.prefix) == DECISION_ID_CHARS

    @property
    def full_id(self) -> str | None:
        return f"gd-{self.prefix}" if self.is_full else None


def parse_decision_ref(text: str) -> DecisionRef:
    """Parse a full id or a prefix of at least 6 characters; ``gd-`` is stripped once.

    Every character must be base32 (``a-z``, ``2-7``) before any lookup, so a ``%`` or ``_``
    can never reach a ``LIKE`` pattern. A bad reference exits 2.
    """
    if not isinstance(text, str):
        raise UsageError("invalid decision id")
    body = text[3:] if text.startswith("gd-") else text
    if _BASE32_PREFIX.fullmatch(body) is None:
        raise UsageError("invalid decision id: only a-z and 2-7 are allowed after gd-")
    if len(body) < DECISION_PREFIX_MIN:
        raise UsageError("decision id prefix too short (at least 6 characters after gd-)")
    if len(body) > DECISION_ID_CHARS:
        raise UsageError("invalid decision id: too long")
    return DecisionRef(body)


def resolve_decision_ref(ref: DecisionRef, known: Iterable[str]) -> str:
    """Pick the one known id that ``ref`` names: unknown exits 10, ambiguous exits 21."""
    matches = {k for k in known if is_decision_id(k) and k[3:].startswith(ref.prefix)}
    if not matches:
        raise NotFoundError("no such decision")
    if len(matches) > 1:
        raise AmbiguousError("decision id prefix is ambiguous")
    return next(iter(matches))


# --- actors ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Actor:
    kind: str  # "human" or "auto"
    name: str

    def __str__(self) -> str:
        return f"{self.kind}:{self.name}"


@dataclass(frozen=True)
class ResolvedActor:
    actor: Actor
    source: str  # "flag" or "default"
    is_human: bool


def parse_actor(text: str) -> Actor:
    match = _ACTOR.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        raise UsageError("invalid --actor: expected human:<name> or auto:<name>")
    return Actor(match.group(1), match.group(2))


def actor_name(raw: object) -> str:
    """Make a ``me.name`` or OS user name fit the actor grammar.

    Each disallowed character becomes ``_``, the result is cut to 64 characters, and an empty
    one becomes ``user``.
    """
    if not isinstance(raw, str) or not raw:
        return "user"
    return _ACTOR_BAD_CHAR.sub("_", raw)[:64] or "user"


def resolve_actor(flag: str | None, *, stdin_tty: bool, name: str | None) -> ResolvedActor:
    """The effective actor (interface.md, Actors and human actions).

    With ``--actor``, the value must parse and it is human only when it is ``human:``. Without
    it the default is ``human:<name>`` on a TTY and ``auto:unknown`` otherwise.
    """
    if flag is not None:
        actor = parse_actor(flag)
        return ResolvedActor(actor, "flag", actor.kind == "human")
    if stdin_tty:
        return ResolvedActor(Actor("human", actor_name(name)), "default", True)
    return ResolvedActor(Actor("auto", "unknown"), "default", False)


# --- durations ---------------------------------------------------------------------------


def parse_duration(text: str) -> timedelta:
    """``0``, or an integer and a unit (``ms``, ``s``, ``m``, ``h``, ``d``)."""
    if isinstance(text, str):
        if text == "0":
            return timedelta(0)
        match = _DURATION.fullmatch(text)
        if match is not None:
            try:
                return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})
            except OverflowError:
                pass
    raise UsageError("invalid duration: expected 0 or an integer with a unit (ms, s, m, h, d)")
