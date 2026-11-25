"""``gatectl check --dry-run``: the resolved plan, with nothing run and nothing recorded.

It follows Check order steps 1 to 5 as far as the config and the input allow: load and validate
the policy, read and parse the input, resolve the scope and the override, compute the fingerprint
and the state, and judge the declaration. It never starts a process, opens ``state.db`` or writes
``audit.jsonl`` and ``log.jsonl``.
"""

from __future__ import annotations

import re
import time
from collections.abc import Mapping, Sequence
from typing import Any

from gatectl import fingerprint as fingerprint_mod
from gatectl import inputs, plan
from gatectl.config import load_for_command
from gatectl.config_models import (
    AgentCheck,
    Check,
    Condition,
    InputDecl,
    RuleCheck,
    ScriptCheck,
)
from gatectl.context import Context, Result
from gatectl.errors import InternalError, UsageError
from gatectl.inputs import InputInvalid
from gatectl.scope import resolve_effective, resolve_scope

STDIN_FD = 0
MAX_TIMEOUT_SECONDS = 86400
_SECONDS = re.compile(r"[0-9]+(?:\.[0-9]+)?")


def parse_timeout(text: str | None) -> float | None:
    """``--timeout``: a plain decimal number of seconds, greater than 0 and at most 86400."""
    if text is None:
        return None
    if _SECONDS.fullmatch(text) is None or not 0 < float(text) <= MAX_TIMEOUT_SECONDS:
        raise UsageError("invalid --timeout: expected seconds greater than 0 and at most 86400")
    return float(text)


def applies(conditions: Sequence[Condition], obj: Mapping[str, Any]) -> bool:
    """Whether ``applies_when`` holds for the input.

    TODO(#17, #19): evaluate the conditions with the rule evaluator. Until it lands every
    policy applies, which is the fail-closed answer of Check order step 4a.
    """
    return True


def _usable(decl: InputDecl | None, obj: Mapping[str, Any]) -> bool:
    """The declaration, and the recordability of what would be recorded (step 5)."""
    try:
        inputs.check_declaration(decl, obj)
        inputs.declared_fields(decl, obj)
        inputs.identity(obj)
    except InputInvalid:
        return False
    return True


def _plan_check(check: Check, shared: Any, would_run: bool) -> dict[str, Any]:
    argv: list[str] | None = None
    skill: str | None = None
    timeout: int | None = None
    if isinstance(check, ScriptCheck):
        argv = plan.script_argv(check)
        limit = check.timeout if check.timeout is not None else shared.defaults.script_timeout
        timeout = plan.milliseconds(limit)
    elif isinstance(check, AgentCheck):
        skill = plan.agent_skill(check, shared)
        limit = check.timeout if check.timeout is not None else shared.agent.timeout
        timeout = plan.milliseconds(limit)
    else:
        assert isinstance(check, RuleCheck)
    return {
        "name": check.name,
        "type": check.type,
        "argv": argv,
        "skill": skill,
        "timeout_ms": timeout,
        "would_run": would_run,
    }


def handle(ctx: Context) -> Result:
    if not ctx.args.dry_run:
        # TODO(#18): the check engine.
        raise InternalError("command not implemented: check")
    override = parse_timeout(ctx.args.timeout)
    loaded = load_for_command(ctx.command, ctx.args, ctx.config)
    name: str = ctx.args.policy
    base = loaded.resolve_policy(name)  # unknown or invalid policy: exit 2, before any read
    shared = loaded.shared
    deadline_s = override
    if deadline_s is None:
        limit = base.timeout if base.timeout is not None else shared.defaults.timeout
        deadline_s = limit.total_seconds()

    raw = inputs.read_input(
        ctx.args.input,
        max_bytes=shared.defaults.input_max_bytes,
        stdin_fd=STDIN_FD,
        deadline=time.monotonic() + deadline_s,
        reserve=shared.defaults.record_reserve.total_seconds(),
    )
    obj: dict[str, Any] | None = None
    if raw.status == "complete":
        try:
            obj = inputs.parse_input(raw.data)
        except InputInvalid:
            obj = None

    scope = resolve_scope(ctx.args.repo, obj)
    effective = resolve_effective(loaded, name, scope)
    policy = effective.policy
    repo = None if scope.scope == "*" else scope.scope

    # Steps 4, 4a and 5: off and a false applies_when end the check before the declaration.
    if policy.state == "off":
        run, valid = False, True
    elif (
        policy.applies_when is not None
        and obj is not None
        and not scope.indeterminate
        and not applies(policy.applies_when, obj)
    ):
        run, valid = False, True
    else:
        valid = obj is not None and not scope.indeterminate and _usable(policy.input, obj)
        run = valid

    warnings = list(scope.warnings)
    if loaded.warns_config_problem_for(name, repo):
        warnings.append("config_problem")
    result = {
        "schema_version": 1,
        "dry_run": True,
        "policy": name,
        "scope": scope.scope,
        # TODO(#12): the effective state comes from the stored rows; until then it is the
        # initial state.
        "state": policy.state,
        "fingerprint": fingerprint_mod.fingerprint(name, policy, shared),
        "input_valid": valid,
        "checks": [_plan_check(c, shared, run) for c in plan.execution_order(policy)],
        "warnings": warnings,
    }
    return Result(payload=result)
