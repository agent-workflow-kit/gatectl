"""``gatectl policies``: every configured policy with its stored state (interface.md, policies).

Each configured policy is shown with its initial state, its effective definition for the scope
(``--repo``, else ``*``), the fingerprint of that definition and a summary of each check, plus what
``state.db`` holds: every stored scope row, and the effective state for the scope (the repo row,
else the ``*`` row, else the initial state) with the cause and time of the row that decides it.
The database is read-only here: nothing is created, migrated or written, and a missing one means
no rows.

A row's ``definition_changed`` is true only for an ``enforced`` row whose fingerprint differs from
the current fingerprint of the row's own scope (a scope whose definition cannot be computed counts
as changed). The marker fingerprint of a row written for a scope with no definition
(``setcmd.NO_DEFINITION``) is never printed as a fingerprint: it is ``null``.
"""

from __future__ import annotations

import re
from typing import Any

from gatectl import fingerprint as fingerprint_mod
from gatectl import ids, plan
from gatectl import store as store_mod
from gatectl.clock import parse_ts
from gatectl.config import LoadedConfig, load_for_command
from gatectl.context import Context, Result
from gatectl.errors import ConfigInvalidError, GatectlError, InternalError, UsageError
from gatectl.sanitize import sanitize
from gatectl.scope import STAR, Scope, resolve_effective
from gatectl.setcmd import NO_DEFINITION

_LINE_CAP = 1200
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")  # the marker NO_DEFINITION has this form too


def _checked(row: store_mod.StateRow) -> store_mod.StateRow:
    """A stored row whose ``set_by``, ``set_at`` and ``fingerprint`` follow their schemas.

    ``store._row`` (shared with the check engine, which never prints these three) only sanitizes
    them; this command prints them, and ``schemas/cli/policies.json`` is closed, so a tampered
    row is refused with fixed text (exit 1) rather than printed.
    """
    try:
        ids.parse_actor(row.set_by)
        parse_ts(row.set_at)
    except (GatectlError, ValueError):
        raise InternalError("state.db holds an invalid state row") from None
    if _FINGERPRINT.fullmatch(row.fingerprint) is None:
        raise InternalError("state.db holds an invalid state row")
    return row


class _Current:
    """The current fingerprint of each scope's own definition of one policy, computed lazily."""

    def __init__(self, loaded: LoadedConfig, name: str, global_fingerprint: str | None) -> None:
        self.loaded = loaded
        self.name = name
        self.known: dict[str, str | None] = {STAR: global_fingerprint}

    def of(self, scope: str) -> str | None:
        """None when the scope's definition cannot be computed (an invalid override)."""
        if scope != STAR and (scope, self.name) not in self.loaded.overrides:
            scope = STAR  # no override: the repo is compared with the global definition
        if scope not in self.known:
            try:
                self.known[scope] = fingerprint_mod.fingerprint_for(
                    self.loaded, self.name, Scope(scope, False, ())
                )
            except (ConfigInvalidError, UsageError):
                self.known[scope] = None
        return self.known[scope]


def _scope_rows(rows: list[store_mod.StateRow], current: _Current) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for row in rows:
        marker = row.fingerprint == NO_DEFINITION
        changed = row.state == "enforced" and (marker or current.of(row.scope) != row.fingerprint)
        out.append(
            {
                "scope": row.scope,
                "state": row.state,
                "set_by": row.set_by,
                "set_at": row.set_at,
                "cause": row.cause,
                "fingerprint": None if marker else row.fingerprint,
                "definition_changed": changed,
                "rev": row.rev,
            }
        )
    return out


def _deciding(rows: list[store_mod.StateRow], scope: str) -> store_mod.StateRow | None:
    """The row that gives the scope its state: its own row, else the ``*`` row."""
    by_scope = {r.scope: r for r in rows}
    for key in (scope, STAR):
        if key in by_scope:
            return by_scope[key]
    return None


def _entry(
    loaded: LoadedConfig, name: str, scope: Scope, store: store_mod.Store | None
) -> tuple[dict[str, Any], bool] | None:
    """The result entry of one policy and whether an override defined it; None when invalid."""
    try:
        effective = resolve_effective(loaded, name, scope)
    except ConfigInvalidError:
        return None
    shared = loaded.shared
    initial = effective.policy.state
    fingerprint = fingerprint_mod.fingerprint(name, effective.policy, shared)
    rows = [_checked(r) for r in store.rows(name)] if store is not None else []
    deciding = _deciding(rows, scope.scope)
    # The global fingerprint is the one of the ``*`` scope; for a repo with an override the shown
    # one is the override's, so the lazy lookup computes the ``*`` one on first use.
    current = _Current(loaded, name, None if scope.scope != STAR else fingerprint)
    if scope.scope != STAR:
        del current.known[STAR]
    entry = {
        "name": name,
        "initial_state": initial,
        "scopes": _scope_rows(rows, current),
        "effective_state": deciding.state if deciding is not None else initial,
        "effective_cause": deciding.cause if deciding is not None else None,
        "effective_set_at": deciding.set_at if deciding is not None else None,
        "fingerprint": fingerprint,
        "checks": [
            {"name": c.name, "type": c.type, "summary": plan.summarize(c, shared)}
            for c in plan.execution_order(effective.policy)
        ],
        # TODO(#29): the track record of each fingerprint (stats builds them).
        "records": [],
    }
    return entry, effective.overridden


def _text(scope: str, rows: list[tuple[dict[str, Any], bool]]) -> str:
    lines = [f"scope: {scope}"]
    for entry, overridden in rows:
        mark = " (override)" if overridden else ""
        lines.append(f"{entry['name']} {entry['effective_state']} {entry['fingerprint']}{mark}")
        for s in entry["scopes"]:
            note = " (definition changed)" if s["definition_changed"] else ""
            lines.append(
                f"  {s['scope']} {s['state']} {s['set_by']} {s['set_at']} rev={s['rev']}"
                f" {s['cause']}{note}"
            )
        lines += [f"  {c['name']} {c['type']} {c['summary']}" for c in entry["checks"]]
    if not rows:
        lines.append("no policies")
    return "\n".join(sanitize(line, _LINE_CAP) for line in lines)


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
    store = store_mod.open_store(create=False)
    rows: list[tuple[dict[str, Any], bool]] = []
    try:
        for name in loaded.policy_names():
            found = _entry(loaded, name, scope, store)
            if found is not None:
                rows.append(found)
    finally:
        if store is not None:
            store.close()
    hidden = len(loaded.policies) - len(rows)
    warning = _warning(bool(loaded.shared_problems), hidden)
    payload = {"scope": scope_name, "policies": [entry for entry, _ in rows]}
    return Result(
        payload=payload,
        text=_text(scope_name, rows),
        stderr=None if ctx.quiet else warning,
    )
