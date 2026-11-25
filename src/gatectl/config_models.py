"""Pydantic models of the config (interface.md, Config, Policies and Checks).

Every model rejects unknown keys and is strict: no value is coerced (a string never becomes a
number, a number never becomes a boolean). A failed check raises a ``PydanticCustomError`` whose
``type`` is a problem code of ``schemas/defs.json`` and whose message is fixed text: no message
ever contains the offending value, because config text is untrusted (interface.md, Untrusted
text). ``gatectl.config`` turns the validation errors into ``ConfigProblem`` records.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Mapping
from datetime import timedelta
from typing import Annotated, Any, ClassVar, Literal, LiteralString, cast

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PrivateAttr,
    StringConstraints,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic_core import InitErrorDetails, PydanticCustomError

from gatectl import ids
from gatectl.errors import UsageError

GLOB_MAX_LEN = 128
MAX_TIMEOUT = timedelta(seconds=86400)


def fail(code: str, message: str, *loc: str | int) -> ValidationError:
    """A validation error at ``loc`` (relative to the model being validated)."""
    return ValidationError.from_exception_data(
        "config",
        [
            InitErrorDetails(
                type=PydanticCustomError(cast(LiteralString, code), cast(LiteralString, message)),
                loc=loc,
                input=None,
            )
        ],
    )


def _bad(message: str) -> PydanticCustomError:
    return PydanticCustomError("invalid_value", cast(LiteralString, message))


# --- durations ---------------------------------------------------------------------------


def _to_duration(value: Any) -> timedelta:
    """``0``, or a string of an integer and a unit; nothing else (a boolean is not 0)."""
    if isinstance(value, timedelta):
        return value
    if type(value) is int and value == 0:
        return timedelta(0)
    if isinstance(value, str):
        try:
            return ids.parse_duration(value)
        except UsageError:
            pass
    raise _bad("expected a duration: 0, or an integer and a unit (ms, s, m, h, d)")


def _range(
    message: str,
    *,
    low: timedelta | None = None,
    low_open: bool = False,
    high: timedelta | None = None,
) -> Callable[[timedelta], timedelta]:
    def check(value: timedelta) -> timedelta:
        if low is not None and (value < low or (low_open and value == low)):
            raise _bad(message)
        if high is not None and value > high:
            raise _bad(message)
        return value

    return check


_ZERO = timedelta(0)
_Dur = Annotated[timedelta, BeforeValidator(_to_duration)]
Duration = _Dur
"""Any duration, ``0`` included (a ``cache_ttl``)."""
PositiveDuration = Annotated[
    timedelta,
    BeforeValidator(_to_duration),
    AfterValidator(_range("must be greater than 0", low=_ZERO, low_open=True)),
]
DeadlineDuration = Annotated[
    timedelta,
    BeforeValidator(_to_duration),
    AfterValidator(
        _range(
            "must be greater than 0 and at most 86400 s", low=_ZERO, low_open=True, high=MAX_TIMEOUT
        )
    ),
]
ReserveDuration = Annotated[
    timedelta,
    BeforeValidator(_to_duration),
    AfterValidator(
        _range(
            "must be from 100 ms to 60 s",
            low=timedelta(milliseconds=100),
            high=timedelta(seconds=60),
        )
    ),
]
StartBudgetDuration = Annotated[
    timedelta,
    BeforeValidator(_to_duration),
    AfterValidator(_range("must be at least 1 s", low=timedelta(seconds=1))),
]


def _int_range(low: int, high: int) -> Callable[[int], int]:
    def check(value: int) -> int:
        if not low <= value <= high:
            raise _bad(f"must be from {low} to {high}")
        return value

    return check


def _unit(value: float) -> float:
    if not (math.isfinite(value) and 0 <= value <= 1):
        raise _bad("must be from 0 to 1")
    return value


Confidence = Annotated[float, AfterValidator(_unit)]


def _open_unit(value: float) -> float:
    if not (math.isfinite(value) and 0 < value < 1):
        raise _bad("must be above 0 and below 1")
    return value


def _miss_rate(value: float) -> float:
    if not (math.isfinite(value) and 0 < value <= 1):
        raise _bad("must be above 0 and at most 1")
    return value


# --- strings -----------------------------------------------------------------------------

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_ENV_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\*?")
_SKILL = re.compile(r"[a-z0-9][a-z0-9_-]*:[a-z0-9][a-z0-9_-]*")
_COND_PATH = re.compile(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*")
_TYPE_NAME = re.compile(r"(?:string|integer|number|boolean|object|array)\??")


def _matching(rx: re.Pattern[str], message: str) -> Callable[[str], str]:
    def check(value: str) -> str:
        if rx.fullmatch(value) is None:
            raise _bad(message)
        return value

    return check


def _nonempty(value: str) -> str:
    if not value:
        raise _bad("must not be empty")
    if "\0" in value:
        raise _bad("must not contain a NUL character")
    return value


def _absolute(value: str) -> str:
    if not value.startswith("/"):
        raise _bad("must be an absolute path")
    return value


def _check_name(value: str) -> str:
    if not ids.is_check_name(value):
        raise _bad("invalid check name: expected [a-z0-9][a-z0-9_-]{0,63}")
    return value


def _skill(value: str) -> str:
    if _SKILL.fullmatch(value) is None:
        if ":" not in value and ids.is_policy_name(value):
            raise PydanticCustomError(
                "bare_skill_name", "a skill is <plugin>:<skill>; a bare name is not allowed"
            )
        raise _bad("a skill is <plugin>:<skill>")
    return value


def _unique(values: list[str]) -> list[str]:
    if len(set(values)) != len(values):
        raise _bad("entries must be unique")
    return values


NonEmptyStr = Annotated[str, AfterValidator(_nonempty)]
AbsolutePath = Annotated[str, AfterValidator(_absolute)]
EnvName = Annotated[str, AfterValidator(_matching(_ENV_NAME, "invalid variable name"))]
EnvNamePattern = Annotated[
    str, AfterValidator(_matching(_ENV_PATTERN, "invalid variable name (a trailing * is allowed)"))
]
CheckName = Annotated[str, AfterValidator(_check_name)]
Skill = Annotated[str, AfterValidator(_skill)]
Sandbox = Literal["required", "preferred", "off"]
Decision = Literal["allow", "deny", "escalate"]


class _Base(BaseModel):
    """Strict, closed, immutable; a ``null`` is accepted only by the keys that say so."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, allow_inf_nan=False)
    nullable: ClassVar[frozenset[str]] = frozenset()

    @model_validator(mode="before")
    @classmethod
    def _no_nulls(cls, data: Any) -> Any:
        if isinstance(data, Mapping):
            known = {(f.alias or name): name for name, f in cls.model_fields.items()}
            for key, value in data.items():
                if value is None and key in known and known[key] not in cls.nullable:
                    raise fail("invalid_value", "must not be null", key)
        return data


# --- shared sections ---------------------------------------------------------------------


# Any string is a valid me.name (it is sanitized when the actor is derived); the cap only keeps a
# huge value out of memory and out of the sanitizer.
ME_NAME_MAX_LEN = 1024


class Me(_Base):
    nullable = frozenset({"name"})
    name: Annotated[str, StringConstraints(max_length=ME_NAME_MAX_LEN)] | None = None


class RecommendCfg(_Base):
    confidence: Annotated[float, AfterValidator(_open_unit)] = 0.95
    max_miss_rate: Annotated[float, AfterValidator(_miss_rate)] = 0.05


class RecommendSpec(_Base):
    """A policy's ``recommend``: a missing sub-key takes the value of ``defaults.recommend``."""

    confidence: Annotated[float, AfterValidator(_open_unit)] | None = None
    max_miss_rate: Annotated[float, AfterValidator(_miss_rate)] | None = None


class Defaults(_Base):
    timeout: DeadlineDuration = timedelta(seconds=60)
    script_timeout: PositiveDuration = timedelta(seconds=20)
    record_reserve: ReserveDuration = timedelta(seconds=2)
    input_max_bytes: Annotated[int, AfterValidator(_int_range(1, 16777216))] = 1048576
    script_env_allow: Annotated[list[EnvNamePattern], AfterValidator(_unique)] = Field(
        default_factory=lambda: ["PATH", "HOME", "LANG", "LC_*"]
    )
    recommend: RecommendCfg = Field(default_factory=RecommendCfg)


class Agent(_Base):
    nullable = frozenset({"model", "permission_profile"})
    skill: Skill = "gatectl:gate-check"
    plugin_dirs: list[AbsolutePath] = Field(default_factory=list)
    model: NonEmptyStr | None = None
    permission_profile: AbsolutePath | None = None
    sandbox: Sandbox = "required"
    setting_sources: Annotated[
        list[Literal["user", "project", "local"]], AfterValidator(_unique)
    ] = Field(default_factory=list)
    env_allowlist: Annotated[list[EnvName], AfterValidator(_unique)] = Field(default_factory=list)
    threshold: Confidence = 0.8
    timeout: PositiveDuration = timedelta(seconds=300)
    cache_ttl: Duration = timedelta(minutes=10)
    max_parallel: Annotated[int, AfterValidator(_int_range(1, 32))] = 3
    min_start_budget: StartBudgetDuration = timedelta(seconds=30)
    input_max_bytes: Annotated[int, AfterValidator(_int_range(1024, 1048576))] = 65536


class Retention(_Base):
    nullable = frozenset({"older_than"})
    older_than: PositiveDuration | None = None


class HookEntry(_Base):
    cmd: NonEmptyStr
    timeout: PositiveDuration = timedelta(seconds=30)
    async_: bool = Field(default=False, alias="async")


class Hooks(_Base):
    post_decision: list[HookEntry] = Field(default_factory=list, alias="post-decision")
    post_outcome: list[HookEntry] = Field(default_factory=list, alias="post-outcome")
    post_state_change: list[HookEntry] = Field(default_factory=list, alias="post-state-change")


class SessionCmd(_Base):
    """``session_cmd`` as a model so it is validated like every other shared part."""

    argv: Annotated[list[NonEmptyStr], Field(min_length=1)] = Field(
        default_factory=lambda: ["claude-session"]
    )

    @model_validator(mode="after")
    def _first_element(self) -> SessionCmd:
        first = self.argv[0]
        if "/" in first and not first.startswith("/"):
            raise fail("invalid_value", "a name with a / must be an absolute path", "argv", 0)
        return self


class SharedConfig(_Base):
    """The shared part: validated at load, section by section."""

    me: Me = Field(default_factory=Me)
    session_cmd: list[str] = Field(default_factory=lambda: ["claude-session"])
    defaults: Defaults = Field(default_factory=Defaults)
    agent: Agent = Field(default_factory=Agent)
    retention: Retention = Field(default_factory=Retention)
    hooks: Hooks = Field(default_factory=Hooks)


# --- glob --------------------------------------------------------------------------------


def tokenize_glob(pattern: str) -> tuple[str, ...]:
    """Split a glob into tokens once: ``*``, ``**``, ``?`` and one token per literal character.

    A run of three or more stars is one ``**``. Nothing else is a metacharacter, so a literal
    token is any token that is not one of those three (a literal ``*`` cannot exist).
    """
    tokens: list[str] = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if c == "*":
            j = i
            while j < len(pattern) and pattern[j] == "*":
                j += 1
            tokens.append("**" if j - i >= 2 else "*")
            i = j
        else:
            tokens.append(c)
            i += 1
    return tuple(tokens)


# --- rule conditions ---------------------------------------------------------------------

Op = Literal["eq", "ne", "in", "not_in", "lt", "le", "gt", "ge", "glob", "exists", "absent"]


def _is_number(value: Any) -> bool:
    if type(value) is int:
        return True  # an integer is always finite; isfinite(int) overflows on huge ones
    return type(value) is float and math.isfinite(value)


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, str | bool) or _is_number(value)


class Condition(_Base):
    """``{path, op, value}``; ``value`` is required or forbidden per operator."""

    nullable = frozenset({"value"})
    path: str
    op: Op
    value: Any = None
    _glob_tokens: tuple[str, ...] | None = PrivateAttr(default=None)

    @property
    def glob_tokens(self) -> tuple[str, ...] | None:
        """The pattern tokenized at load, for ``glob`` conditions; else ``None``."""
        return self._glob_tokens

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        if _COND_PATH.fullmatch(value) is None:
            raise PydanticCustomError(
                "invalid_rule", "path is dotted keys of [A-Za-z0-9_-] with numeric array indexes"
            )
        return value

    @model_validator(mode="after")
    def _value_rules(self) -> Condition:
        present = "value" in self.model_fields_set
        op, value = self.op, self.value

        def rule(message: str) -> ValidationError:
            return fail("invalid_rule", message, "value")

        if op in ("exists", "absent"):
            if present:
                raise rule(f"value is forbidden for {op}")
            return self
        if not present:
            raise rule(f"value is required for {op}")
        if op in ("in", "not_in"):
            if not (isinstance(value, list) and all(_is_scalar(v) for v in value)):
                raise rule(f"value for {op} must be a list of scalars")
        elif op in ("lt", "le", "gt", "ge"):
            if not _is_number(value):
                raise rule(f"value for {op} must be a number")
        elif op == "glob":
            if not isinstance(value, str) or not value:
                raise rule("value for glob must be a non-empty string")
            if len(value) > GLOB_MAX_LEN:
                raise fail("glob_too_long", "glob pattern is longer than 128 characters", "value")
            self._glob_tokens = tokenize_glob(value)
        elif not _json_ok(value):
            raise rule(f"value for {op} must be JSON")
        return self


def _json_ok(value: Any) -> bool:
    """A JSON value: loading already refused every other type, so only floats need a look."""
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif not _is_scalar(item):
            return False
    return True


# --- checks ------------------------------------------------------------------------------


class ScriptCheck(_Base):
    name: CheckName
    type: Literal["script"]
    argv: Annotated[list[NonEmptyStr], Field(min_length=1)]
    timeout: PositiveDuration | None = None
    env_allow: Annotated[list[EnvName], AfterValidator(_unique)] | None = None

    @model_validator(mode="after")
    def _argv0(self) -> ScriptCheck:
        if not self.argv[0].startswith("/"):
            raise fail("invalid_value", "argv[0] must be an absolute path", "argv", 0)
        return self


class RuleCheck(_Base):
    name: CheckName
    type: Literal["rule"]
    when: Annotated[list[Condition], Field(min_length=1)]
    then: Decision
    else_: Decision = Field(default="allow", alias="else")


class AgentCheck(_Base):
    nullable = frozenset({"model", "permission_profile"})
    name: CheckName
    type: Literal["agent"]
    instruction: NonEmptyStr | None = None
    instruction_file: AbsolutePath | None = None
    skill: Skill | None = None
    model: NonEmptyStr | None = None
    threshold: Confidence | None = None
    timeout: PositiveDuration | None = None
    cache_ttl: Duration | None = None
    permission_profile: AbsolutePath | None = None
    sandbox: Sandbox | None = None
    setting_sources: (
        Annotated[list[Literal["user", "project", "local"]], AfterValidator(_unique)] | None
    ) = None
    env_allowlist: Annotated[list[EnvName], AfterValidator(_unique)] | None = None

    @model_validator(mode="after")
    def _exactly_one_instruction(self) -> AgentCheck:
        if (self.instruction is None) == (self.instruction_file is None):
            raise fail(
                "invalid_value", "exactly one of instruction and instruction_file is required"
            )
        return self


Check = Annotated[ScriptCheck | RuleCheck | AgentCheck, Field(discriminator="type")]


# --- policies ----------------------------------------------------------------------------


class InputDecl(_Base):
    require: Annotated[list[NonEmptyStr], AfterValidator(_unique)] = Field(default_factory=list)
    types: dict[str, str] = Field(default_factory=dict)
    ignore: Annotated[list[NonEmptyStr], AfterValidator(_unique)] = Field(default_factory=list)

    @model_validator(mode="after")
    def _rules(self) -> InputDecl:
        for key, kind in self.types.items():
            if not key:
                raise fail("invalid_value", "a key name must not be empty", "types")
            if _TYPE_NAME.fullmatch(kind) is None:
                raise fail(
                    "invalid_value",
                    "a type is string, integer, number, boolean, object or array (? for nullable)",
                    "types",
                    key,
                )
        for index, key in enumerate(self.ignore):
            if key == "repo":
                raise fail(
                    "invalid_value",
                    "ignore may not name repo: the scope is part of the cache key",
                    "ignore",
                    index,
                )
        return self


def _no_duplicate_names(checks: list[Any]) -> None:
    seen: set[str] = set()
    for index, check in enumerate(checks):
        if check.name in seen:
            raise fail("invalid_value", "duplicate check name", "checks", index, "name")
        seen.add(check.name)


def _initial_state(value: Any) -> Any:
    if value == "enforced":
        raise _bad("a policy's state in the config is off or shadow; use gatectl set to enforce")
    if value not in ("off", "shadow"):
        raise _bad("state must be off or shadow")
    return value


class Policy(_Base):
    state: Annotated[Literal["off", "shadow"], BeforeValidator(_initial_state)] = "shadow"
    timeout: DeadlineDuration | None = None
    applies_when: Annotated[list[Condition], Field(min_length=1)] | None = None
    input: InputDecl | None = None
    checks: Annotated[list[Check], Field(min_length=1)]
    cache_ttl: Duration | None = None
    record_input: bool = False
    recommend: RecommendSpec = Field(default_factory=RecommendSpec)

    @model_validator(mode="after")
    def _names(self) -> Policy:
        _no_duplicate_names(self.checks)
        return self


class PolicyOverride(_Base):
    """``repos.<id>.policies.<name>``: any policy key except ``state``."""

    timeout: DeadlineDuration | None = None
    applies_when: Annotated[list[Condition], Field(min_length=1)] | None = None
    input: InputDecl | None = None
    checks: Annotated[list[Check], Field(min_length=1)] | None = None
    cache_ttl: Duration | None = None
    record_input: bool | None = None
    recommend: RecommendSpec | None = None

    @model_validator(mode="before")
    @classmethod
    def _no_state(cls, data: Any) -> Any:
        if isinstance(data, Mapping) and "state" in data:
            raise fail(
                "invalid_value",
                "state is not allowed in an override: a repo's state is its stored row",
                "state",
            )
        return data

    @model_validator(mode="after")
    def _names(self) -> PolicyOverride:
        if self.checks is not None:
            _no_duplicate_names(self.checks)
        return self
