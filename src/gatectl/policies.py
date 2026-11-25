"""``gatectl policies``: the static view, answered from the config alone (interface.md, policies).

Each configured policy is shown with its initial state, its effective definition for the scope
(``--repo``, else ``*``), the fingerprint of that definition and a summary of each check. The
stored scope rows and the track records come from ``state.db`` and are added by the stored view.
"""

from __future__ import annotations

from typing import Any

from gatectl import fingerprint as fingerprint_mod
from gatectl import plan
from gatectl.config import LoadedConfig, load_for_command
from gatectl.context import Context, Result
from gatectl.errors import ConfigInvalidError
from gatectl.sanitize import sanitize
from gatectl.scope import STAR, Scope, resolve_effective


def _entry(loaded: LoadedConfig, name: str, scope: Scope) -> tuple[dict[str, Any], bool] | None:
    """The result entry of one policy and whether an override defined it; None when invalid."""
    try:
        effective = resolve_effective(loaded, name, scope)
    except ConfigInvalidError:
        return None
    shared = loaded.shared
    state = effective.policy.state
    entry = {
        "name": name,
        "initial_state": state,
        # TODO(#15): stored rows, the effective state taken from them, and the records.
        "scopes": [],
        "effective_state": state,
        "fingerprint": fingerprint_mod.fingerprint(name, effective.policy, shared),
        "checks": [
            {"name": c.name, "type": c.type, "summary": plan.summarize(c, shared)}
            for c in plan.execution_order(effective.policy)
        ],
        "records": [],
    }
    return entry, effective.overridden


def _text(scope: str, rows: list[tuple[dict[str, Any], bool]]) -> str:
    lines = [f"scope: {scope}"]
    for entry, overridden in rows:
        mark = " (override)" if overridden else ""
        lines.append(f"{entry['name']} {entry['effective_state']} {entry['fingerprint']}{mark}")
        lines += [f"  {c['name']} {c['type']} {c['summary']}" for c in entry["checks"]]
    if not rows:
        lines.append("no policies")
    return "\n".join(lines)


def _warning(shared_invalid: bool, hidden: int) -> str | None:
    parts = []
    if shared_invalid:
        parts.append("a shared key is invalid")
    if hidden:
        parts.append(
            f"{hidden} policy not shown" if hidden == 1 else f"{hidden} policies not shown"
        )
    if not parts:
        return None
    return sanitize(f"gatectl: warning config_problem: {'; '.join(parts)}, see gatectl validate")


def handle(ctx: Context) -> Result:
    loaded = load_for_command(ctx.command, ctx.args, ctx.config)
    scope_name: str = ctx.args.repo or STAR
    scope = Scope(scope_name, False, ())
    rows: list[tuple[dict[str, Any], bool]] = []
    for name in loaded.policy_names():
        found = _entry(loaded, name, scope)
        if found is not None:
            rows.append(found)
    hidden = len(loaded.policies) - len(rows)
    warning = _warning(bool(loaded.shared_problems), hidden)
    payload = {"scope": scope_name, "policies": [entry for entry, _ in rows]}
    return Result(
        payload=payload,
        text=_text(scope_name, rows),
        stderr=None if ctx.quiet else warning,
    )
