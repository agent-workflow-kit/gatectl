"""What ``policies`` and ``check --dry-run`` share: check order and one-line check summaries.

Everything here is derived from the effective definition alone. Config text is untrusted (it may
carry control characters or markup), so every string built here goes through the sanitizer.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Sequence
from datetime import timedelta

from gatectl.config_models import (
    AgentCheck,
    Check,
    Condition,
    Policy,
    RuleCheck,
    ScriptCheck,
    SharedConfig,
)
from gatectl.sanitize import sanitize

SUMMARY_CAP = 512
ARGV_ELEMENT_CAP = 1024

_OPERATORS = {
    "eq": "==",
    "ne": "!=",
    "in": "in",
    "not_in": "not in",
    "lt": "<",
    "le": "<=",
    "gt": ">",
    "ge": ">=",
    "glob": "glob",
    "exists": "exists",
    "absent": "absent",
}
_NO_VALUE = frozenset({"exists", "absent"})


def execution_order(policy: Policy) -> list[Check]:
    """Script and rule checks in listed order, then agent checks in listed order."""
    agents = [c for c in policy.checks if isinstance(c, AgentCheck)]
    others = [c for c in policy.checks if not isinstance(c, AgentCheck)]
    return [*others, *agents]


def milliseconds(value: timedelta) -> int:
    return value // timedelta(milliseconds=1)


def agent_skill(check: AgentCheck, shared: SharedConfig) -> str:
    return check.skill if check.skill is not None else shared.agent.skill


def script_argv(check: ScriptCheck) -> list[str]:
    """The argv for display: each element sanitized and cut."""
    return [_display_element(a) for a in check.argv]


def _display_element(element: str) -> str:
    """Sanitized, and at most ``ARGV_ELEMENT_CAP`` characters with a final ``…`` when cut."""
    if len(element) <= ARGV_ELEMENT_CAP:
        return sanitize(element, ARGV_ELEMENT_CAP)
    return sanitize(element, ARGV_ELEMENT_CAP - 1) + "\u2026"


def _condition(condition: Condition) -> str:
    text = f"{condition.path} {_OPERATORS[condition.op]}"
    if condition.op in _NO_VALUE:
        return text
    return f"{text} {json.dumps(condition.value, ensure_ascii=False)}"


def conditions_summary(conditions: Sequence[Condition]) -> str:
    return " and ".join(_condition(c) for c in conditions)


def summarize(check: Check, shared: SharedConfig) -> str:
    """One line: the argv of a script, the conditions of a rule, or the skill of an agent."""
    if isinstance(check, ScriptCheck):
        text = " ".join(shlex.quote(a) for a in check.argv)
    elif isinstance(check, RuleCheck):
        text = f"{conditions_summary(check.when)} then {check.then} else {check.else_}"
    else:
        text = f"skill {agent_skill(check, shared)}"
    return sanitize(text, SUMMARY_CAP)
