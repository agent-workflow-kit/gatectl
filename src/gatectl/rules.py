"""The closed rule evaluator and the linear glob matcher (interface: Rule checks).

A rule is a pure function of the input: this module starts no process and reads neither the
environment nor the clock, and it imports neither ``re`` nor ``fnmatch``. The input is
untrusted: no value, however hostile, makes an evaluation raise. Every comparison is iterative
(no recursion over a nested value) and a glob costs at most pattern length times subject length.

A rule check is never skipped for the deadline (Deadline), so the evaluator takes no deadline.
``between`` is a seam the check engine may use to observe the gap between two conditions; it is
called with no argument and nothing else here reads its result.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from gatectl.config_models import Condition, RuleCheck

MAX_SUBJECT_BYTES = 4096
MAX_LIST_ELEMENTS = 256
MAX_TOTAL_BYTES = 16384
_MAX_INDEX_DIGITS = 9  # no input array has a billion elements; longer is simply absent


# --- the glob matcher --------------------------------------------------------------------------


class GlobMatcher:
    """Match tokens from ``tokenize_glob`` against a whole subject, never backtracking.

    The live pattern positions (0..n, position ``i`` meaning "tokens before ``i`` are matched")
    are one Python int used as a bit set. Each subject character is one step of a fixed number
    of bit operations on an int of at most ``n + 1`` bits, so a match costs O(n * m). The
    tokenizer merges every run of stars, so two star tokens are never adjacent and one
    epsilon step (``*`` and ``**`` may match nothing) closes the set.
    """

    def __init__(self, tokens: Sequence[str]) -> None:
        literal: dict[str, int] = {}
        one = star = double = 0
        for i, token in enumerate(tokens):
            bit = 1 << i
            if token == "*":
                star |= bit
            elif token == "**":
                double |= bit
            elif token == "?":
                one |= bit
            else:
                literal[token] = literal.get(token, 0) | bit
        self._n = len(tokens)
        self._literal = literal
        self._one = one
        self._star = star
        self._double = double
        self._eps = star | double
        self.steps = 0
        self.max_state_bits = 0

    def matches(self, subject: str) -> bool:
        eps, star, double, one, literal = (
            self._eps,
            self._star,
            self._double,
            self._one,
            self._literal,
        )
        live = 1 | ((1 & eps) << 1)
        steps = 0
        widest = live.bit_length()
        result = False
        for char in subject:
            steps += 1
            nxt = ((live & literal.get(char, 0)) << 1) | (live & double)
            if char != "/":
                nxt |= ((live & one) << 1) | (live & star)
            if not nxt:
                live = 0
                break
            live = nxt | ((nxt & eps) << 1)
            widest = max(widest, live.bit_length())
        else:
            result = bool((live >> self._n) & 1)
        self.steps = steps
        self.max_state_bits = widest
        return result


# --- values -------------------------------------------------------------------------------------

_MISSING = object()


def _kind(value: Any) -> str:
    if value is None:
        return "null"
    kind = type(value)
    if kind is bool:
        return "bool"
    if kind is int or kind is float:
        return "num"
    if kind is str:
        return "str"
    if kind is list:
        return "list"
    if kind is dict:
        return "dict"
    return "other"


def _is_real_number(value: Any) -> bool:
    kind = type(value)
    if kind is int:
        return True
    return kind is float and math.isfinite(value)


def _json_equal(left: Any, right: Any) -> bool:
    """JSON equality: a boolean never equals a number; containers compare whole; no recursion."""
    stack = [(left, right)]
    while stack:
        a, b = stack.pop()
        kind = _kind(a)
        if kind != _kind(b):
            return False
        if kind == "null":
            continue
        if kind == "bool":
            if a is not b:
                return False
        elif kind == "num" or kind == "str":
            if a != b:  # NaN is never equal to anything
                return False
        elif kind == "list":
            if len(a) != len(b):
                return False
            stack.extend(zip(a, b, strict=True))
        elif kind == "dict":
            if len(a) != len(b):
                return False
            for key, item in a.items():
                other = b.get(key, _MISSING)
                if other is _MISSING:
                    return False
                stack.append((item, other))
        else:
            return False
    return True


def _lookup(obj: Any, path: str) -> Any:
    """The value at a dotted path, or ``_MISSING``. A null on the way makes the rest missing."""
    current = obj
    for segment in path.split("."):
        if type(current) is dict:
            current = current.get(segment, _MISSING)
        elif type(current) is list:
            if not (
                segment.isascii()
                and segment.isdigit()
                and len(segment) <= _MAX_INDEX_DIGITS
                and (segment == "0" or segment[0] != "0")
            ):
                return _MISSING
            index = int(segment)
            if index >= len(current):
                return _MISSING
            current = current[index]
        else:
            return _MISSING
        if current is _MISSING:
            return _MISSING
    return current


# --- conditions ----------------------------------------------------------------------------------

Outcome = Literal["true", "false", "error"]


@dataclass(frozen=True, slots=True)
class Evaluation:
    """``outcome``: ``true`` (all held), ``false`` (one did not) or ``error`` (see ``detail``)."""

    outcome: Outcome
    detail: str | None = None


_TRUE = Evaluation("true")
_FALSE = Evaluation("false")


def _error(path: str, problem: str) -> Evaluation:
    return Evaluation("error", f"{path}: {problem}")


def _glob_subjects(value: Any) -> list[str] | str:
    """The strings to match, or the problem (``null``, ``type`` or ``too large``)."""
    if value is None:
        return "null"
    if type(value) is str:
        value = [value]
    elif type(value) is list:
        if len(value) > MAX_LIST_ELEMENTS:
            return "too large"
    else:
        return "type"
    total = 0
    for item in value:
        if type(item) is not str:
            return "type"
        if len(item) > MAX_SUBJECT_BYTES:  # characters never outnumber bytes
            return "too large"
        size = len(item.encode("utf-8", "surrogatepass"))
        total += size
        if size > MAX_SUBJECT_BYTES or total > MAX_TOTAL_BYTES:
            return "too large"
    return value


def _one(condition: Condition, obj: Any) -> Evaluation:
    op, path = condition.op, condition.path
    found = _lookup(obj, path)
    if op == "exists":
        return _FALSE if found is _MISSING else _TRUE
    if op == "absent":
        return _TRUE if found is _MISSING else _FALSE
    if found is _MISSING:
        return _error(path, "missing")
    expected = condition.value

    if op == "eq" or op == "ne":
        if found is None and expected is not None:
            return _error(path, "null")
        equal = _json_equal(found, expected)
        return _TRUE if equal == (op == "eq") else _FALSE

    if op == "in" or op == "not_in":
        if found is None:
            if None not in expected:
                return _error(path, "null")
        elif _kind(found) not in ("bool", "num", "str"):
            return _error(path, "type")
        member = any(_json_equal(found, item) for item in expected)
        return _TRUE if member == (op == "in") else _FALSE

    if op == "glob":
        subjects = _glob_subjects(found)
        if isinstance(subjects, str):
            return _error(path, subjects)
        tokens = condition.glob_tokens
        assert tokens is not None  # set when the config was validated
        matcher = GlobMatcher(tokens)
        return _TRUE if any(matcher.matches(s) for s in subjects) else _FALSE

    # lt, le, gt, ge
    if found is None:
        return _error(path, "null")
    if not _is_real_number(found):
        return _error(path, "type")
    if op == "lt":
        holds = found < expected
    elif op == "le":
        holds = found <= expected
    elif op == "gt":
        holds = found > expected
    else:
        holds = found >= expected
    return _TRUE if holds else _FALSE


def evaluate(
    conditions: Sequence[Condition],
    obj: Mapping[str, Any] | Any,
    *,
    between: Callable[[], None] | None = None,
) -> Evaluation:
    """An ordered AND that stops at the first false or error condition (never raises on ``obj``)."""
    for index, condition in enumerate(conditions):
        if index and between is not None:
            between()
        result = _one(condition, obj)
        if result.outcome != "true":
            return result
    return _TRUE


def applies(conditions: Sequence[Condition], obj: Mapping[str, Any]) -> bool:
    """``applies_when``: only a false condition says the policy does not apply (an error does)."""
    return evaluate(conditions, obj).outcome != "false"


@dataclass(frozen=True, slots=True)
class RuleVerdict:
    verdict: Literal["allow", "deny", "escalate"]
    reason: Literal["check_error"] | None
    detail: str | None


def run_rule(check: RuleCheck, obj: Mapping[str, Any] | Any) -> RuleVerdict:
    """One rule check: ``then`` if all hold, ``else`` if one is false, else an escalation."""
    result = evaluate(check.when, obj)
    if result.outcome == "error":
        return RuleVerdict("escalate", "check_error", result.detail)
    return RuleVerdict(check.then if result.outcome == "true" else check.else_, None, None)
