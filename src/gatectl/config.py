"""Load, merge and validate the config (interface.md, Config; design.md, Modules).

The config is the main file plus ``config.d/*.yaml`` drop-ins, read as untrusted text:

* a file is opened without blocking, must be a regular file, and is capped in size;
* YAML is parsed with a closed loader: no anchors, aliases, merge keys, duplicate keys,
  non-string keys, tags beyond plain JSON-like data, deep nesting or non-finite numbers;
* every message names a key or a file and never carries a config value (config text is
  untrusted; key names in paths are sanitized and capped).

Validation is per part (interface.md: "the reach of a config error"). The shared part (``me``,
``session_cmd``, ``defaults``, ``agent``, ``retention``, ``hooks`` and the structure of ``repos``)
is validated section by section; an invalid leaf falls back to its built-in default and is
reported as a problem. Each policy and each per-repo override is validated on its own, so an
invalid one fails only its own scope. ``load_config`` never raises for a problem in a part; it
raises only when the files cannot be read (exit 1) or cannot be parsed (exit 2).
"""

from __future__ import annotations

import argparse
import os
import pwd
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ValidationError

from gatectl import ids
from gatectl.config_models import (
    Agent,
    Defaults,
    Hooks,
    Me,
    Policy,
    PolicyOverride,
    RecommendSpec,
    Retention,
    SessionCmd,
    SharedConfig,
)
from gatectl.errors import ConfigInvalidError, InternalError, UsageError
from gatectl.sanitize import sanitize

MAX_CONFIG_BYTES = 1024 * 1024  # one file
MAX_TOTAL_BYTES = 4 * MAX_CONFIG_BYTES  # the main file and every drop-in together
MAX_DROPINS = 256
MAX_DEPTH = 64  # nesting of maps and lists
MAX_PROBLEMS_IN_DETAILS = 50
PATH_SEGMENT_CAP = 64
PATH_CAP = 256
MESSAGE_CAP = 2048

SESSION_CMD_DIRS = (
    "~/.local/bin",
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/usr/bin",
    "/bin",
)

# The only keys that may be set as GATECTL_<KEY> (interface.md, Environment variables).
ENV_KEYS: dict[str, str] = {
    "defaults.timeout": "duration",
    "defaults.script_timeout": "duration",
    "defaults.record_reserve": "duration",
    "agent.timeout": "duration",
    "agent.cache_ttl": "duration",
    "agent.max_parallel": "int",
    "agent.min_start_budget": "duration",
    "retention.older_than": "duration_or_null",
}
_ENV_PREFIX = "GATECTL_"
_ENV_VALUE_CAP = 64
_TOP_KEYS = ("me", "session_cmd", "defaults", "agent", "retention", "hooks", "policies", "repos")
_SECTIONS: dict[str, type[BaseModel]] = {
    "me": Me,
    "defaults": Defaults,
    "agent": Agent,
    "retention": Retention,
    "hooks": Hooks,
}

# Commands whose result depends on the whole shared part (interface.md, Config).
_STRICT_COMMANDS = frozenset({"check", "reconcile", "prune", "cron"})


# --- problems -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class ConfigProblem:
    """One problem: a code of ``schemas/defs.json`` ``problem``, a dotted path and fixed text."""

    code: str
    path: str
    message: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "message", sanitize(self.message, MESSAGE_CAP))

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


def _seg(part: str | int) -> str:
    return sanitize(part, PATH_SEGMENT_CAP) if isinstance(part, str) else str(part)


def _path(parts: tuple[str | int, ...]) -> str:
    return sanitize(".".join(_seg(p) for p in parts), PATH_CAP)


def problem_path(*parts: str | int) -> str:
    """The dotted, sanitized and capped path of a problem (every segment is a key or an index)."""
    return _path(parts)


_BUILTIN_MESSAGES = {
    "string_type": "expected a string",
    "int_type": "expected an integer",
    "int_parsing": "expected an integer",
    "bool_type": "expected a boolean",
    "float_type": "expected a number",
    "list_type": "expected a list",
    "dict_type": "expected a map",
    "model_type": "expected a map",
    "model_attributes_type": "expected a map",
    "literal_error": "not one of the allowed values",
    "too_short": "must not be empty",
    "string_too_short": "must not be empty",
    "missing": "required key is missing",
    "union_tag_invalid": "unknown check type",
    "union_tag_not_found": "a check needs a type (script, rule or agent)",
    "finite_number": "must be a finite number",
}
_CHECK_TAGS = frozenset({"script", "rule", "agent"})


def _clean_loc(loc: tuple[str | int, ...]) -> tuple[str | int, ...]:
    """Drop the union tag pydantic puts after a check's index, and the dict-key marker."""
    out: list[str | int] = []
    for i, seg in enumerate(loc):
        if seg == "[key]":
            continue
        if isinstance(seg, str) and seg in _CHECK_TAGS and i >= 2 and loc[i - 2] == "checks":
            if isinstance(loc[i - 1], int):
                continue
        out.append(seg)
    return tuple(out)


def _in_rule(loc: tuple[str | int, ...]) -> bool:
    """Whether ``loc`` is inside ``applies_when`` or a rule check's when/then/else."""
    if loc and loc[0] == "applies_when":
        return True
    for i, seg in enumerate(loc):
        if seg == "checks" and i + 2 < len(loc) and isinstance(loc[i + 1], int):
            return loc[i + 2] in ("when", "then", "else")
    return False


_MAX_COLLECTED = 200  # per part; only MAX_PROBLEMS_IN_DETAILS are ever reported


def _problems(
    exc: ValidationError,
    prefix: tuple[str | int, ...],
    *,
    override: bool = False,
    strip_first: bool = False,
) -> list[ConfigProblem]:
    out: list[ConfigProblem] = []
    seen: set[tuple[str, str, str]] = set()
    for err in exc.errors(include_url=False, include_context=False, include_input=False):
        if len(out) >= _MAX_COLLECTED:
            break
        loc = _clean_loc(tuple(err["loc"]))
        if strip_first and loc:
            loc = loc[1:]
        kind = err["type"]
        if kind == "extra_forbidden":
            code = "override_unknown_key" if override else "unknown_key"
            message = "unknown key"
        elif kind in _CUSTOM_CODES:
            code, message = kind, err["msg"]
        else:
            code = "invalid_value"
            message = _BUILTIN_MESSAGES.get(kind, "invalid value")
        if code == "invalid_value" and _in_rule(loc):
            code = "invalid_rule"
        problem = ConfigProblem(code, _path((*prefix, *loc)), sanitize(message, MESSAGE_CAP))
        key = (problem.code, problem.path, problem.message)
        if key not in seen:
            seen.add(key)
            out.append(problem)
    return out


_CUSTOM_CODES = frozenset({"invalid_value", "invalid_rule", "glob_too_long", "bare_skill_name"})


# --- reading files ------------------------------------------------------------------------------


def _file_label(path: str) -> str:
    return sanitize(os.path.basename(path), 64) or "config"


def _unreadable(path: str) -> InternalError:
    # An unreadable config is an unknown state (exit 1). The message never carries the path:
    # it may be a raw flag value.
    return InternalError(f"config file is unreadable: {_file_label(path)}")


def _invalid(path: str, what: str) -> ConfigInvalidError:
    return ConfigInvalidError(f"{_file_label(path)}: {what}")


def _read_file(path: str, budget: int) -> bytes:
    """Read a regular file of at most ``MAX_CONFIG_BYTES`` (and ``budget``) bytes.

    Opened without blocking (a FIFO cannot hang the open) and checked after the open (a device,
    a directory or a FIFO is refused); a symlink to a regular file is followed.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise _unreadable(path) from exc
    try:
        try:
            st = os.fstat(fd)
        except OSError as exc:
            raise _unreadable(path) from exc
        if not stat.S_ISREG(st.st_mode):
            raise _unreadable(path)
        limit = min(MAX_CONFIG_BYTES, budget)
        if st.st_size > limit:
            raise _invalid(path, "file is too large")
        chunks: list[bytes] = []
        total = 0
        while True:
            try:
                chunk = os.read(fd, 65536)
            except OSError as exc:
                raise _unreadable(path) from exc
            if not chunk:
                break
            total += len(chunk)
            if total > limit:  # grew while reading
                raise _invalid(path, "file is too large")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


class _Rejected(Exception):
    def __init__(self, reason: str, mark: Any = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.line = None if mark is None else mark.line + 1


_BOOL = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")
_INT = re.compile(r"^[-+]?(?:0|[1-9][0-9]*)$")
_FLOAT = re.compile(
    r"^(?:[-+]?(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?|[-+]?[0-9]+[eE][-+]?[0-9]+|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$"
)


def _core_resolvers() -> dict[str | None, list[tuple[str, re.Pattern[str]]]]:
    """The implicit resolvers of SafeLoader without YAML 1.1 booleans, octals and sexagesimals.

    A copy: SafeLoader's own table is never mutated. ``off``, ``no``, ``010``, ``1:30`` and
    ``1_000`` stay strings; ``true``/``false`` (any of the three spellings) are booleans.
    """
    table: dict[str | None, list[tuple[str, re.Pattern[str]]]] = {}
    for first, entries in yaml.SafeLoader.yaml_implicit_resolvers.items():
        kept: list[tuple[str, re.Pattern[str]]] = []
        for tag, regexp in entries:
            if tag == "tag:yaml.org,2002:bool":
                regexp = _BOOL
            elif tag == "tag:yaml.org,2002:int":
                regexp = _INT
            elif tag == "tag:yaml.org,2002:float":
                regexp = _FLOAT
            kept.append((tag, regexp))
        table[first] = kept
    return table


class _Loader(yaml.SafeLoader):
    """A SafeLoader with no anchors, aliases, merge keys, duplicate or non-string keys."""

    yaml_implicit_resolvers = _core_resolvers()

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._depth = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        event = self.peek_event()
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
            raise _Rejected("anchors and aliases are not supported", event.start_mark)
        nested = isinstance(event, yaml.SequenceStartEvent | yaml.MappingStartEvent)
        if nested:
            self._depth += 1
            if self._depth > MAX_DEPTH:
                raise _Rejected("nesting is too deep", event.start_mark)
        try:
            return super().compose_node(parent, index)
        finally:
            if nested:
                self._depth -= 1

    def flatten_mapping(self, node: Any) -> None:
        return None  # no `<<`: it is then an undefined tag and is refused

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        seen: set[str] = set()
        for key_node, _value_node in node.value:
            key = self.construct_object(key_node, deep=True)
            if not isinstance(key, str):
                raise _Rejected("keys must be strings", key_node.start_mark)
            if key in seen:
                raise _Rejected("duplicate key", key_node.start_mark)
            seen.add(key)
        return super().construct_mapping(node, deep)


def _check_tree(root: Any) -> bool:
    """Only plain JSON-like data: maps of strings, lists, strings, numbers, booleans, null."""
    stack = [root]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, value in item.items():
                if not _encodable(key):
                    return False
                stack.append(value)
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str):
            if not _encodable(item):
                return False
        elif isinstance(item, float):
            if item != item or item in (float("inf"), float("-inf")):
                return False
        elif item is not None and not isinstance(item, bool | int):
            return False
    return True


def _encodable(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:  # a lone surrogate
        return False
    return True


def _parse(data: bytes, path: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _invalid(path, "file is not valid UTF-8") from exc
    try:
        loader = _Loader(text)
        try:
            tree = loader.get_single_data()
        finally:
            loader.dispose()
    except _Rejected as exc:
        where = "" if exc.line is None else f" at line {exc.line}"
        raise _invalid(path, f"{exc.reason}{where}") from None
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark or exc.context_mark
        where = "" if mark is None else f" at line {mark.line + 1}, column {mark.column + 1}"
        raise _invalid(path, f"invalid YAML{where}") from None
    except yaml.YAMLError:
        raise _invalid(path, "invalid YAML (unsupported characters)") from None
    except (RecursionError, ValueError, OverflowError, MemoryError):
        raise _invalid(path, "cannot be parsed as YAML") from None
    if tree is None:
        return {}
    if not _check_tree(tree):
        raise _invalid(path, "contains a value that is not plain data")
    if not isinstance(tree, dict):
        raise _invalid(path, "the top level must be a map")
    return tree


def _merge(base: Any, over: Any, path: tuple[str, ...] = ()) -> Any:
    """Maps merge, ``hooks.<event>`` lists append, everything else is replaced by the later one."""
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for key, value in over.items():
            out[key] = _merge(base[key], value, (*path, key)) if key in base else value
        return out
    if isinstance(base, list) and isinstance(over, list) and len(path) == 2 and path[0] == "hooks":
        return [*base, *over]
    return over


def _home(environ: Mapping[str, str]) -> Path:
    """``$HOME`` when absolute, else the passwd home, else ``/``."""
    home = environ.get("HOME", "")
    if not (home and os.path.isabs(home)):
        try:
            home = pwd.getpwuid(os.getuid()).pw_dir
        except KeyError:
            home = "/"
    return Path(home)


def default_config_path(environ: Mapping[str, str]) -> Path:
    """``$XDG_CONFIG_HOME/gatectl/config.yaml``, else ``~/.config/gatectl/config.yaml``.

    A relative or empty ``XDG_CONFIG_HOME`` is ignored (as the state directory's is).
    """
    xdg = environ.get("XDG_CONFIG_HOME", "")
    if xdg and os.path.isabs(xdg):
        return Path(xdg) / "gatectl" / "config.yaml"
    return _home(environ) / ".config" / "gatectl" / "config.yaml"


def _dropins(directory: str) -> list[str]:
    try:
        with os.scandir(directory) as it:
            names = [e.name for e in it if e.name.endswith(".yaml") and not e.name.startswith(".")]
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise _unreadable(directory) from exc
    if len(names) > MAX_DROPINS:
        raise ConfigInvalidError("config.d has too many files")
    return [os.path.join(directory, n) for n in sorted(names)]


def _load_files(config_path: str | None, environ: Mapping[str, str]) -> dict[str, Any]:
    explicit = config_path is not None
    main = (
        os.path.abspath(config_path)
        if config_path is not None
        else str(default_config_path(environ))
    )
    budget = MAX_TOTAL_BYTES
    merged: dict[str, Any] = {}
    files: list[tuple[str, bool]] = [(main, explicit)]
    files += [(p, True) for p in _dropins(os.path.join(os.path.dirname(main), "config.d"))]
    for path, must_exist in files:
        try:
            data = _read_file(path, budget)
        except InternalError as exc:
            if not must_exist and not os.path.lexists(path):
                continue
            raise exc
        budget -= len(data)
        merged = _merge(merged, _parse(data, path))
    return merged


# --- environment overrides ----------------------------------------------------------------------


def _env_value(kind: str, text: str) -> Any:
    if len(text) > _ENV_VALUE_CAP:
        raise ValueError(text[:0])
    if kind == "int":
        if re.fullmatch(r"[0-9]{1,4}", text) is None:
            raise ValueError(text[:0])
        return int(text)
    if kind == "duration_or_null" and text == "null":
        return None
    return text


def _read_env(
    environ: Mapping[str, str],
) -> tuple[dict[str, dict[str, Any]], list[ConfigProblem]]:
    """The listed keys that are set and valid, and a problem for each refused or invalid one."""
    values: dict[str, dict[str, Any]] = {}
    problems: list[ConfigProblem] = []
    for name in sorted(environ):
        if not name.startswith(_ENV_PREFIX):
            continue
        rest = name[len(_ENV_PREFIX) :]
        if re.fullmatch(r"[A-Z0-9_]+", rest) is None:
            continue
        segments = [s.lower() for s in rest.split("__")]
        if segments[0] not in _TOP_KEYS:
            continue  # GATECTL_HOOK, GATECTL_ID and the like are not config
        key = ".".join(segments)
        if key not in ENV_KEYS:
            problems.append(
                ConfigProblem(
                    "invalid_value",
                    _path(tuple(segments)),
                    f"{name} cannot be set from the environment (only the listed keys can)",
                )
            )
            continue
        section, leaf = key.split(".")
        try:
            value = _env_value(ENV_KEYS[key], environ[name])
            _SECTIONS[section].model_validate({leaf: value})
        except (ValueError, ValidationError):
            problems.append(
                ConfigProblem("invalid_value", key, f"invalid value in environment variable {name}")
            )
            continue
        values.setdefault(section, {})[leaf] = value
    return values, problems


# --- validating the parts -----------------------------------------------------------------------


def _clone(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _clone(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clone(v) for v in value]
    return value


def _without_errors(raw: dict[str, Any], exc: ValidationError) -> dict[str, Any]:
    """A copy of ``raw`` without the keys that failed (a list's owning key goes whole)."""
    out = _clone(raw)
    for err in exc.errors(include_url=False, include_context=False, include_input=False):
        node: Any = out
        loc = err["loc"]
        for i, seg in enumerate(loc):
            if not (isinstance(seg, str) and isinstance(node, dict) and seg in node):
                break
            if i + 1 == len(loc) or isinstance(loc[i + 1], int):
                del node[seg]
                break
            node = node[seg]
    return out


def _validate_part(
    model: type[BaseModel],
    raw: Any,
    prefix: tuple[str, ...],
    *,
    wrap: str | None = None,
) -> tuple[Any, list[ConfigProblem]]:
    """Validate one shared section; an invalid leaf falls back to its default."""

    def build(data: Any) -> Any:
        return model.model_validate({wrap: data} if wrap else data)

    try:
        return build(raw), []
    except ValidationError as exc:
        problems = _problems(exc, prefix, strip_first=wrap is not None)
        if isinstance(raw, dict) and wrap is None:
            try:
                return build(_without_errors(raw, exc)), problems
            except ValidationError:
                pass
    return model(), problems


def _resolve_recommend(spec: RecommendSpec, defaults: Defaults) -> RecommendSpec:
    return RecommendSpec(
        confidence=defaults.recommend.confidence if spec.confidence is None else spec.confidence,
        max_miss_rate=(
            defaults.recommend.max_miss_rate if spec.max_miss_rate is None else spec.max_miss_rate
        ),
    )


@dataclass(frozen=True)
class PolicyEntry:
    """A policy, or a per-repo override of one, validated on its own.

    ``policy`` is set for a valid policy (its ``recommend`` already completed from
    ``defaults.recommend``), ``override`` for a valid override; both are ``None`` when
    ``problems`` is not empty.
    """

    name: str
    repo: str | None
    problems: tuple[ConfigProblem, ...]
    policy: Policy | None = None
    override: PolicyOverride | None = None


def _arith_problem(prefix: tuple[str, ...]) -> ConfigProblem:
    return ConfigProblem("invalid_value", _path(prefix), "invalid value")


def _policy_entry(name: str, body: Any, defaults: Defaults) -> PolicyEntry:
    prefix = ("policies", name)
    if not ids.is_policy_name(name):
        problem = ConfigProblem("invalid_value", _path(prefix), "invalid policy name")
        return PolicyEntry(name, None, (problem,))
    try:
        policy = Policy.model_validate(body)
    except ValidationError as exc:
        return PolicyEntry(name, None, tuple(_problems(exc, prefix)))
    except OverflowError:  # arithmetic on hostile numbers is an invalid value, never a crash
        return PolicyEntry(name, None, (_arith_problem(prefix),))
    policy = policy.model_copy(update={"recommend": _resolve_recommend(policy.recommend, defaults)})
    return PolicyEntry(name, None, (), policy=policy)


def _override_entry(
    repo: str, name: str, body: Any, known: set[str], defaults: Defaults
) -> PolicyEntry:
    prefix = ("repos", repo, "policies", name)
    if not ids.is_policy_name(name):
        problem = ConfigProblem("invalid_value", _path(prefix), "invalid policy name")
        return PolicyEntry(name, repo, (problem,))
    if name not in known:
        problem = ConfigProblem(
            "override_unknown_policy", _path(prefix), "override names a policy that is not defined"
        )
        return PolicyEntry(name, repo, (problem,))
    try:
        override = PolicyOverride.model_validate(body)
    except ValidationError as exc:
        return PolicyEntry(name, repo, tuple(_problems(exc, prefix, override=True)))
    except OverflowError:
        return PolicyEntry(name, repo, (_arith_problem(prefix),))
    if override.recommend is not None:
        override = override.model_copy(
            update={"recommend": _resolve_recommend(override.recommend, defaults)}
        )
    return PolicyEntry(name, repo, (), override=override)


def _structure_problem(path: tuple[str, ...], message: str) -> ConfigProblem:
    return ConfigProblem("invalid_value", _path(path), message)


def _build_shared(
    merged: dict[str, Any], environ: Mapping[str, str]
) -> tuple[SharedConfig, list[ConfigProblem]]:
    problems: list[ConfigProblem] = []
    for key in merged:
        if key not in _TOP_KEYS:
            problems.append(ConfigProblem("unknown_key", _path((key,)), "unknown key"))
    env_values, env_problems = _read_env(environ)
    parts: dict[str, Any] = {}
    for name, model in _SECTIONS.items():
        raw = merged.get(name, {})
        if isinstance(raw, dict) and name in env_values:
            raw = {**raw, **env_values[name]}
        parts[name], found = _validate_part(model, raw, (name,))
        problems.extend(found)
    if "session_cmd" in merged:
        cmd, found = _validate_part(
            SessionCmd, merged["session_cmd"], ("session_cmd",), wrap="argv"
        )
        parts["session_cmd"] = list(cmd.argv) if found == [] else ["claude-session"]
        problems.extend(found)
    else:
        parts["session_cmd"] = ["claude-session"]
    problems.extend(env_problems)
    return SharedConfig.model_construct(**parts), problems


def _build_parts(
    merged: dict[str, Any], defaults: Defaults
) -> tuple[dict[str, PolicyEntry], dict[tuple[str, str], PolicyEntry], list[ConfigProblem]]:
    problems: list[ConfigProblem] = []
    policies: dict[str, PolicyEntry] = {}
    raw_policies = merged.get("policies", {})
    if isinstance(raw_policies, dict):
        for name, body in raw_policies.items():
            policies[name] = _policy_entry(name, body, defaults)
    else:
        problems.append(_structure_problem(("policies",), "expected a map"))
        raw_policies = {}
    known = set(raw_policies)

    overrides: dict[tuple[str, str], PolicyEntry] = {}
    raw_repos = merged.get("repos", {})
    if not isinstance(raw_repos, dict):
        problems.append(_structure_problem(("repos",), "expected a map"))
        return policies, overrides, problems
    for repo, body in raw_repos.items():
        if not ids.is_repo_id(repo):
            problems.append(_structure_problem(("repos", repo), "invalid repo id"))
            continue
        if not isinstance(body, dict):
            problems.append(_structure_problem(("repos", repo), "expected a map"))
            continue
        for key in body:
            if key != "policies":
                problems.append(
                    ConfigProblem("unknown_key", _path(("repos", repo, key)), "unknown key")
                )
        by_policy = body.get("policies", {})
        if not isinstance(by_policy, dict):
            problems.append(_structure_problem(("repos", repo, "policies"), "expected a map"))
            continue
        for name, override_body in by_policy.items():
            overrides[(repo, name)] = _override_entry(repo, name, override_body, known, defaults)
    return policies, overrides, problems


# --- the loaded config --------------------------------------------------------------------------


def _raise(problems: list[ConfigProblem] | tuple[ConfigProblem, ...]) -> ConfigInvalidError:
    first = problems[0]
    more = f" (and {len(problems) - 1} more)" if len(problems) > 1 else ""
    return ConfigInvalidError(
        sanitize(f"invalid config: {first.path}: {first.message}{more}", MESSAGE_CAP),
        details={
            "count": len(problems),
            "problems": [p.as_dict() for p in problems[:MAX_PROBLEMS_IN_DETAILS]],
        },
    )


@dataclass(frozen=True)
class LoadedConfig:
    """The result of ``load_config``: the shared part, every policy and every override."""

    shared: SharedConfig
    shared_problems: tuple[ConfigProblem, ...]
    policies: Mapping[str, PolicyEntry]
    overrides: Mapping[tuple[str, str], PolicyEntry]

    def require_valid_shared(self) -> None:
        """Exit 2 naming the key when any shared key is invalid (``check``, ``reconcile``, ...)."""
        if self.shared_problems:
            raise _raise(self.shared_problems)

    def shared_warnings(self) -> list[str]:
        """The warning a command that carries on with defaults adds to its result."""
        return ["config_problem"] if self.shared_problems else []

    def policy_names(self) -> list[str]:
        """Every addressable policy name (an invalid name cannot be named on a command line)."""
        return sorted(n for n in self.policies if ids.is_policy_name(n))

    def policy_problems(self) -> list[ConfigProblem]:
        """Every problem of every policy and override."""
        found = [p for e in self.policies.values() for p in e.problems]
        found += [p for e in self.overrides.values() for p in e.problems]
        return found

    def resolve_policy_or_none(self, name: str, repo: str | None = None) -> Policy | None:
        if name not in self.policies:
            return None
        return self.resolve_policy(name, repo)

    def resolve_policy(self, name: str, repo: str | None = None) -> Policy:
        """The effective definition of a policy for a scope, or a config error (exit 2).

        An override replaces each key it sets as a whole. Only this policy and this scope's
        override are consulted: any other invalid part is not an error here.
        """
        entry = self.policies.get(name)
        if entry is None:
            raise UsageError("unknown policy", details={"kind": "unknown_policy"})
        if entry.policy is None:
            raise _raise(entry.problems)
        if repo is None or (repo, name) not in self.overrides:
            return entry.policy
        scoped = self.overrides[(repo, name)]
        if scoped.override is None:
            raise _raise(scoped.problems)
        update = {k: getattr(scoped.override, k) for k in scoped.override.model_fields_set}
        return entry.policy.model_copy(update=update)

    def warns_config_problem_for(self, name: str, repo: str | None = None) -> bool:
        """Whether a ``check`` of this policy and scope adds the warning ``config_problem``.

        True when another policy or another override is invalid; this policy's own problems
        (and its override's) are the check's error, not a warning.
        """
        own = {("policy", name)}
        if repo is not None:
            own.add(("override", f"{repo}\0{name}"))
        for key, entry in self.policies.items():
            if entry.problems and ("policy", key) not in own:
                return True
        for (r, n), entry in self.overrides.items():
            if entry.problems and ("override", f"{r}\0{n}") not in own:
                return True
        return False

    def session_cmd_resolved(self) -> list[str] | None:
        """``session_cmd`` with its first element resolved (never through ``PATH``), or None."""
        return resolve_session_cmd(self.shared.session_cmd)


def load_config(
    config_path: str | None = None, *, environ: Mapping[str, str] | None = None
) -> LoadedConfig:
    """Read the files, apply the environment and validate every part.

    Raises ``InternalError`` (exit 1) when a file cannot be read and ``ConfigInvalidError``
    (exit 2) when the text cannot be parsed. Problems inside a part do not raise: they are in
    ``shared_problems`` and in each entry's ``problems``.
    """
    env = os.environ if environ is None else environ
    merged = _load_files(config_path, env)
    shared, shared_problems = _build_shared(merged, env)
    policies, overrides, structure = _build_parts(merged, shared.defaults)
    return LoadedConfig(
        shared=shared,
        shared_problems=tuple(shared_problems + structure),
        policies=policies,
        overrides=overrides,
    )


def requires_valid_shared(command: str, args: argparse.Namespace) -> bool:
    """Whether a shared-structure error stops this command with exit 2 (interface.md, Config).

    ``check``, ``reconcile``, ``prune``, ``cron`` and ``set ... enforced``; every other command
    carries on with built-in defaults and a ``config_problem`` warning.
    """
    if command in _STRICT_COMMANDS:
        return True
    return command == "set" and getattr(args, "state", None) == "enforced"


def load_for_command(
    command: str,
    args: argparse.Namespace,
    config_path: str | None,
    *,
    environ: Mapping[str, str] | None = None,
) -> LoadedConfig:
    """Load the config for a command and apply its reach rule."""
    loaded = load_config(config_path, environ=environ)
    if requires_valid_shared(command, args):
        loaded.require_valid_shared()
    return loaded


# --- session_cmd --------------------------------------------------------------------------------


def _is_executable_file(path: str) -> bool:
    try:
        return stat.S_ISREG(os.stat(path).st_mode) and os.access(path, os.X_OK)
    except (OSError, ValueError):
        return False


def resolve_session_cmd(
    session_cmd: list[str],
    *,
    dirs: tuple[str, ...] = SESSION_CMD_DIRS,
    environ: Mapping[str, str] | None = None,
) -> list[str] | None:
    """Resolve ``session_cmd[0]`` to an absolute path; never searches ``PATH``.

    An absolute path is checked as given. A bare name is searched in ``dirs`` in order and the
    first regular executable file wins. A name with a ``/`` that is not absolute is never
    searched. ``None`` when nothing is found.
    """
    if not session_cmd:
        return None
    first, rest = session_cmd[0], session_cmd[1:]
    if first.startswith("/"):
        return [first, *rest] if _is_executable_file(first) else None
    if "/" in first or not first:
        return None
    home = str(_home(os.environ if environ is None else environ))
    for directory in dirs:
        if directory.startswith("~"):
            directory = home.rstrip("/") + directory[1:]
        candidate = os.path.join(directory, first)
        if _is_executable_file(candidate):
            return [candidate, *rest]
    return None


__all__ = [
    "ENV_KEYS",
    "MAX_CONFIG_BYTES",
    "MAX_DROPINS",
    "SESSION_CMD_DIRS",
    "ConfigProblem",
    "LoadedConfig",
    "PolicyEntry",
    "default_config_path",
    "load_config",
    "load_for_command",
    "problem_path",
    "requires_valid_shared",
    "resolve_session_cmd",
]
