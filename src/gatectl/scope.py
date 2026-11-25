"""Scope resolution and effective definitions (interface.md, Identifiers and Check order step 3).

A decision's scope is a repo id or ``*``. The trusted source is ``--repo``; the payload ``repo``
is only a fallback and never overrides the flag. When no repo can be trusted the scope is
**indeterminate**: its scope is ``*`` and the caller must escalate (the strictest-state rule
lives with the store and engine). Nothing here echoes a repo value: values may carry
credentials, control characters or markup, so results and errors hold closed codes only.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from gatectl import ids
from gatectl.config import LoadedConfig
from gatectl.config_models import Policy
from gatectl.errors import UsageError
from gatectl.ids import is_repo_id

STAR = "*"
WARN_INVALID = "repo_invalid"
WARN_MISMATCH = "repo_mismatch"

# The commands whose ``--repo`` may be ``*`` (interface.md, Scope). ``check`` never takes it.
STAR_COMMANDS = frozenset({"decisions", "stats", "policies", "set"})


def check_repo_flag(command: str, value: str | None) -> str | None:
    """Validate a ``--repo`` value for a command; a bad value exits 2 without being echoed."""
    if value is None:
        return None
    if value == STAR:
        if command in STAR_COMMANDS:
            return value
        raise UsageError("invalid --repo: * is not accepted by this command")
    if not is_repo_id(value):
        raise UsageError("invalid --repo: expected host/path")
    return value


@dataclass(frozen=True)
class Scope:
    """The resolved scope of one decision.

    ``scope`` is a valid repo id, or ``*``. ``indeterminate`` is only ever true with scope
    ``*``. ``warnings`` are closed codes (``repo_invalid``, ``repo_mismatch``).
    """

    scope: str
    indeterminate: bool
    warnings: tuple[str, ...]


def resolve_scope(repo_flag: str | None, payload: Mapping[str, Any] | None) -> Scope:
    """Resolve the scope from a validated ``--repo`` and the parsed input.

    ``payload`` is the parsed input object, or ``None`` when the input is unusable (over the cap,
    not a strict JSON object, or not fully read by the deadline). ``repo_flag`` must already have
    passed ``check_repo_flag`` (a flag of ``*`` never reaches ``check``).
    """
    present = payload is not None and payload.get("repo") is not None
    value = payload.get("repo") if payload is not None else None
    valid = present and isinstance(value, str) and ids.is_repo_id(value)
    if repo_flag is not None:
        if not present:
            return Scope(repo_flag, False, ())
        if not valid:
            return Scope(repo_flag, False, (WARN_INVALID,))
        if value != repo_flag:
            return Scope(repo_flag, False, (WARN_MISMATCH,))
        return Scope(repo_flag, False, ())
    if payload is None:
        return Scope(STAR, True, ())
    if not present:
        return Scope(STAR, False, ())
    if valid:
        assert isinstance(value, str)
        return Scope(value, False, ())
    return Scope(STAR, True, (WARN_INVALID,))


@dataclass(frozen=True)
class Effective:
    """A policy's effective definition for a scope.

    ``overridden`` is true when a per-repo override was applied. An indeterminate scope is ``*``
    and takes the global definition.
    """

    policy: Policy
    scope: str
    indeterminate: bool
    overridden: bool
    warnings: tuple[str, ...]


def resolve_effective(config: LoadedConfig, name: str, scope: Scope) -> Effective:
    """The effective definition of ``name`` for ``scope``.

    An unknown policy exits 2; an invalid policy or an invalid override for this scope is a
    config error (exit 2). Only this policy and this scope's override are consulted. The
    override is looked up by exact repo id, and never for ``*``.
    """
    repo = None if scope.scope == STAR else scope.scope
    policy = config.resolve_policy(name, repo=repo)
    overridden = repo is not None and (repo, name) in config.overrides
    return Effective(policy, scope.scope, scope.indeterminate, overridden, scope.warnings)
