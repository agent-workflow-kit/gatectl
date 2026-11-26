"""``gatectl set``: write the state of one scope, or of every scope with ``--all``.

interface.md, State changes and Actors and human actions. The rules this module enforces:

* ``enforced`` is a human action. The check runs first, before the config is read, before any
  reason is read and before anything is created, and looks only at the global ``--actor`` flag
  and whether stdin is a terminal (``Context.actor`` and ``Context.stdin_tty``). The
  environment, ``--decision-id`` values and stdin content never take part. A refusal is exit 20,
  a ``warning`` log event and no audit record.
* The whole change is one ``Store.transact`` body: it re-reads the rows under the write lock,
  decides what changed, writes the rows and appends one ``state_change`` audit line per changed
  scope before the commit. Nothing retries around it, so a second run cannot append a second
  line; an audit failure rolls every row back (exit 1).
* Free text (the reason) is untrusted: read with a byte cap, sanitized, capped, stored in the
  audit line only and never printed. Every error message is fixed text.
"""

from __future__ import annotations

import time
from typing import Any

from gatectl import audit, ids, inputs
from gatectl import fingerprint as fingerprint_mod
from gatectl import store as store_mod
from gatectl.agenthash import agent_config_hash
from gatectl.clock import now_ts
from gatectl.config import LoadedConfig, load_for_command
from gatectl.config_models import AgentCheck, Policy, RuleCheck, ScriptCheck
from gatectl.context import Context, Result
from gatectl.errors import ConfigInvalidError, InternalError, RefusedError, UsageError
from gatectl.sanitize import sanitize, sanitize_bytes
from gatectl.scope import STAR, Scope, resolve_effective

STDIN_FD = 0
REASON_MAX_BYTES = 1024
REASON_WAIT_SECONDS = 10.0
# Stored for a scope whose effective definition cannot be computed (a removed policy, or a
# configured policy or override that does not validate): a row set to off or shadow never has its
# fingerprint compared, and the column is NOT NULL and in the fingerprint grammar.
NO_DEFINITION = "sha256:" + "0" * 64
# What a policy that is not in the config (or does not validate) counts as its initial state.
DEFAULT_INITIAL = "shadow"

HINT_PROBE = "No validate --probe has succeeded for the current agent configuration; run it."
HINT_NO_DETERMINISTIC = (
    "The policy has no script or rule check, so no deterministic check backs an automatic action."
)
HINT_REPO = (
    "This policy has no recorded decision for this repo; "
    "the repo spelling matches nothing seen yet."
)


def _check_usage(ctx: Context) -> tuple[str, str, str | None, bool]:
    name: str = ctx.args.policy
    state: str = ctx.args.state
    repo: str | None = ctx.args.repo
    every: bool = ctx.args.all
    if not ids.is_policy_name(name):
        raise UsageError("invalid policy name")
    if every and repo is not None:
        raise UsageError("--all cannot be combined with --repo")
    if every and state == "enforced":
        raise UsageError("--all is accepted only with off or shadow")
    return name, state, repo, every


def _refuse(ctx: Context, name: str, scope: str, source: str) -> RefusedError:
    try:
        audit.append_log(
            audit.log_record(
                level="warn",
                event="warning",
                message="set enforced refused: human_required",
                policy=name,
                scope=scope,
                data={"actor": ctx.actor, "stdin_tty": ctx.stdin_tty, "actor_source": source},
            )
        )
    except (OSError, ValueError, TypeError):
        pass  # the refusal stands whether or not the log can be written
    return RefusedError("setting a policy to enforced needs a human actor")


def _read_reason(source: str | None) -> str | None:
    if source is None:
        return None
    try:
        raw = inputs.read_input(
            source,
            max_bytes=REASON_MAX_BYTES,
            stdin_fd=STDIN_FD,
            deadline=time.monotonic() + REASON_WAIT_SECONDS,
        )
    except UsageError:
        raise UsageError("--reason-file is missing, unreadable or not a regular file") from None
    if raw.status not in ("complete", "too_large"):
        raise UsageError("--reason-file could not be read completely")
    data = raw.data[:REASON_MAX_BYTES].rstrip(b"\r\n")
    text = sanitize_bytes(data, REASON_MAX_BYTES)
    return text or None


class _Fingerprints:
    """The current fingerprint of each scope's own definition, computed at most once."""

    def __init__(self, loaded: LoadedConfig, name: str) -> None:
        self.loaded = loaded
        self.name = name
        self.known: dict[str, str] = {}

    def of(self, scope: str) -> str:
        if scope not in self.known:
            try:
                self.known[scope] = fingerprint_mod.fingerprint_for(
                    self.loaded, self.name, Scope(scope, False, ())
                )
            except (ConfigInvalidError, UsageError):  # removed or invalid: no definition
                self.known[scope] = NO_DEFINITION
        return self.known[scope]


def _initial_state(loaded: LoadedConfig, name: str) -> str:
    entry = loaded.policies.get(name)
    if entry is not None and entry.policy is not None:
        return entry.policy.state
    return DEFAULT_INITIAL


def _hints(
    loaded: LoadedConfig, policy: Policy, store: store_mod.Store, name: str, repo: str | None
) -> str | None:
    parts: list[str] = []
    checks = policy.checks
    if any(isinstance(c, AgentCheck) for c in checks):
        current = agent_config_hash(loaded.shared, loaded.session_cmd_resolved())
        ok_at = store.meta("probe_ok_at")
        if not ok_at or store.meta("probe_agent_hash") != current:
            parts.append(HINT_PROBE)
    if not any(isinstance(c, ScriptCheck | RuleCheck) for c in checks):
        parts.append(HINT_NO_DETERMINISTIC)
    if repo is not None and repo != STAR and not store.has_decision(name, repo):
        parts.append(HINT_REPO)
    return " ".join(parts) or None


def _audit_line(
    ctx: Context,
    resolved: ids.ResolvedActor,
    *,
    name: str,
    scope: str,
    previous: str,
    state: str,
    reason: str | None,
) -> dict[str, Any]:
    return audit.audit_record(
        action="state_change",
        target=f"{name}@{scope}",
        decision_id=ctx.decision_ids,
        actor=str(resolved.actor),
        stdin_tty=ctx.stdin_tty,
        actor_source=resolved.source,
        caller_decision_ids=ctx.decision_ids,
        inputs={"policy": name, "scope": scope, "state": state},
        result={
            "previous_state": previous,
            "state": state,
            "cause": "set",
            "reason": reason,
            "triggered_by": None,
        },
    )


def handle(ctx: Context) -> Result:
    name, state, repo, every = _check_usage(ctx)
    scope = repo if repo is not None else STAR
    # 1. The human-only rule, before anything is read or created. Only the flag and the terminal
    #    decide; the name in the actor is irrelevant to whether it is human.
    first = ids.resolve_actor(ctx.actor, stdin_tty=ctx.stdin_tty, name=None)
    if state == "enforced" and not first.is_human:
        raise _refuse(ctx, name, scope, first.source)

    loaded = load_for_command("set", ctx.args, ctx.config)
    resolved = ids.resolve_actor(
        ctx.actor,
        stdin_tty=ctx.stdin_tty,
        # An empty configured name is sanitized to ``user``; only an absent one uses the OS name.
        name=ids.default_actor_name(loaded.shared.me.name),
    )
    reason = _read_reason(ctx.args.reason_file)

    in_config = name in loaded.policies
    if state == "enforced":
        # Raises the config error of an unknown or invalid policy or override (exit 2).
        effective = resolve_effective(loaded, name, Scope(scope, False, ()))
        enforce_policy: Policy | None = effective.policy
    else:
        enforce_policy = None

    if not in_config:
        probe = store_mod.open_store(create=False)
        known = False
        if probe is not None:
            with probe:
                known = probe.has_policy(name)
        if not known:
            raise UsageError("unknown policy", details={"kind": "unknown_policy"})

    fps = _Fingerprints(loaded, name)

    initial = _initial_state(loaded, name)
    reserve = loaded.shared.defaults.record_reserve.total_seconds()
    store = store_mod.open_store(create=True, busy_timeout=reserve)
    assert store is not None
    with store:

        def body() -> tuple[str, str, list[str]]:
            when = now_ts()  # inside the lock: set_at is not older than the rows it replaces
            found = {r.scope: r for r in store.rows(name, limit=store_mod._ROW_LIMIT + 1)}
            if every and len(found) > store_mod._ROW_LIMIT:
                # the read is capped: a partial set would silently miss the rows past the cap
                raise InternalError("too many rows to set every scope of the policy")
            star = found.get(STAR)
            star_state = star.state if star is not None else initial
            targets = [STAR, *sorted(s for s in found if s != STAR)] if every else [scope]
            changed: list[str] = []
            records: list[dict[str, Any]] = []
            for target in targets:
                row = found.get(target)
                if row is not None:
                    previous = row.state
                else:
                    previous = star_state
                equal = row is not None and row.state == state
                if equal and state == "enforced":
                    assert row is not None
                    equal = row.fingerprint == fps.of(target)
                if equal:
                    continue
                store.write_state_row(
                    name,
                    target,
                    state,
                    set_by=str(resolved.actor),
                    set_at=when,
                    cause="set",
                    fingerprint=fps.of(target),
                )
                records.append(
                    _audit_line(
                        ctx,
                        resolved,
                        name=name,
                        scope=target,
                        previous=previous,
                        state=state,
                        reason=reason,
                    )
                )
                changed.append(target)
            # One write for every line, after every row is written: a failure appends none.
            store.append_audit_many(records)
            row = found.get(STAR if every else scope)
            return (row.state if row is not None else star_state), state, changed

        previous_state, new_state, changed = store.transact(body)
        # TODO(#31): fire the post-state-change hook for each changed scope whose state differs
        # from its previous state (a re-enforcement fires none), after the commit.
        hint = None
        if state == "enforced" and enforce_policy is not None:
            hint = _hints(loaded, enforce_policy, store, name, repo)

    payload = {
        "policy": name,
        "scope": scope,
        "state": new_state,
        "previous_state": previous_state,
        "changed": bool(changed),
        "scopes_changed": changed,
        "hint": hint,
    }
    text = f"{name}@{scope}: " + (
        f"{previous_state} -> {new_state}" if changed else f"{new_state} (unchanged)"
    )
    if hint:
        text += " " + hint
    warning = None
    if loaded.shared_problems and not ctx.quiet:
        warning = "gatectl: warning config_problem: a shared key is invalid, see gatectl validate"
    return Result(payload=payload, text=sanitize(text, 1024), stderr=warning)
