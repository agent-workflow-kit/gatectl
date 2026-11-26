"""``gatectl outcome``: append one outcome record and, on an unsafe miss, drop the scope to shadow.

interface.md, Outcomes and the ``outcome`` command. The rules this module enforces:

* Nobody is refused: the actor decides what an ``agree`` is worth, never what is accepted. An
  ``agree`` counts only when the stored actor is ``human:*`` (the SQL rule in ``history.py``), and
  the actor is human only through ``--actor human:<name>`` or a terminal on stdin
  (``Context.actor`` and ``Context.stdin_tty``). The environment, ``--decision-id`` values, stdin
  content and ``--signal`` never take part.
* The id resolves under the strict rules of ``show`` (base32 only, so a LIKE wildcard is a usage
  error, exit 2); unknown or pruned is exit 10, an ambiguous prefix exit 21.
* The record, the effective-outcome re-read, the optional drop row and every audit line are one
  ``Store.transact`` body. Nothing retries around it, so a second run cannot append a second line;
  an audit failure rolls everything back (exit 1).
* The reason is untrusted: read with a byte cap, sanitized, cut to 1 KiB with a final ``…``,
  stored in ``state.db`` only and never printed.
"""

from __future__ import annotations

import codecs
import time
from dataclasses import dataclass
from typing import Any

from gatectl import audit, history, ids, inputs
from gatectl import store as store_mod
from gatectl.clock import now_ts
from gatectl.config import LoadedConfig, load_for_command
from gatectl.context import Context, Result
from gatectl.errors import InternalError, NotFoundError, UsageError
from gatectl.sanitize import sanitize
from gatectl.setcmd import _os_user_name

STDIN_FD = 0
REASON_MAX_BYTES = 1024
REASON_WAIT_SECONDS = 10.0
ELLIPSIS = "…"
NOT_FOUND = "unknown or pruned id; see audit.jsonl"
DEFAULT_INITIAL = "shadow"
_TAMPERED = "state.db holds an invalid decision row"


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
    cut = len(raw.data) > REASON_MAX_BYTES
    data = raw.data[:REASON_MAX_BYTES]
    # A cut inside a multi-byte character drops the partial tail instead of printing a marker.
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    if cut:
        text = sanitize(decoder.decode(data, final=False), REASON_MAX_BYTES)
        return text[: REASON_MAX_BYTES - 1] + ELLIPSIS
    text = sanitize(decoder.decode(data, final=True).rstrip("\r\n"), REASON_MAX_BYTES)
    return text or None


def _actor_kind(actor: ids.Actor) -> str:
    if actor.kind == "human":
        return "human"
    return "unattributed" if actor.name == "unknown" else "automatic"


@dataclass(frozen=True)
class _Decision:
    policy: str
    scope: str
    state: str
    verdict: str
    state_rev: int | None
    fingerprint: str


def _load_decision(store: store_mod.Store, decision_id: str) -> _Decision:
    rows = store.query(
        f"SELECT {store_mod.cut_sql('policy')}, {store_mod.cut_sql('scope')},"  # noqa: S608
        f" {store_mod.cut_sql('state')}, {store_mod.cut_sql('decision')}, state_rev,"
        f" {store_mod.cut_sql('fingerprint')} FROM decisions WHERE id = ?",
        (decision_id,),
    )
    if not rows:
        raise NotFoundError(NOT_FOUND)
    policy, scope, state, verdict, rev, fp = rows[0]
    policy, scope, state, verdict, fp = (
        store_mod.uncut(v) for v in (policy, scope, state, verdict, fp)
    )
    if not (
        isinstance(policy, str)
        and ids.is_policy_name(policy)
        and isinstance(scope, str)
        and (scope == "*" or ids.is_repo_id(scope))
        and state in store_mod.STATES
        and verdict in history.DECISIONS
        and isinstance(fp, str)
        and (rev is None or (isinstance(rev, int) and not isinstance(rev, bool) and rev >= 0))
    ):
        raise InternalError(_TAMPERED)
    return _Decision(policy, scope, str(state), str(verdict), rev, fp)


def _initial_state(loaded: LoadedConfig, name: str) -> str:
    entry = loaded.policies.get(name)
    if entry is not None and entry.policy is not None:
        return entry.policy.state
    return DEFAULT_INITIAL


@dataclass
class _Done:
    decision_id: str
    policy: str
    scope: str
    previous: str
    effective: str
    miss: str | None
    state_change: dict[str, str] | None
    skipped_drop: bool


def handle(ctx: Context) -> Result:
    ref = ids.parse_decision_ref(ctx.args.id)
    verdict: str = ctx.args.outcome
    if ctx.args.signal is not None and not ids.is_signal(ctx.args.signal):
        raise UsageError("invalid --signal: expected ^[a-z][a-z0-9_-]{0,31}$")
    loaded = load_for_command(ctx.command, ctx.args, ctx.config)
    resolved = ids.resolve_actor(
        ctx.actor,
        stdin_tty=ctx.stdin_tty,
        name=_os_user_name() if loaded.shared.me.name is None else loaded.shared.me.name,
    )
    actor = str(resolved.actor)
    signal: str = ctx.args.signal or ("human" if resolved.is_human else "auto")
    reason = _read_reason(ctx.args.reason_file)

    # A reader first: an id that cannot exist never creates state.db.
    probe = store_mod.open_store(create=False)
    if probe is None:
        raise NotFoundError(NOT_FOUND)
    probe.close()

    reserve = loaded.shared.defaults.record_reserve.total_seconds()
    store = store_mod.open_store(create=True, busy_timeout=reserve)
    assert store is not None
    with store:

        def body() -> _Done:
            try:
                decision_id = history.resolve(store, ref)
            except NotFoundError:
                raise NotFoundError(NOT_FOUND) from None
            d = _load_decision(store, decision_id)
            previous = history.effective_outcome(store, decision_id)
            when = now_ts()  # inside the lock, like the sequence number
            store.execute(
                "INSERT INTO outcomes(decision_id, time, outcome, signal, actor, actor_kind,"
                " reason) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (decision_id, when, verdict, signal, actor, _actor_kind(resolved.actor), reason),
            )
            effective = history.effective_outcome(store, decision_id)
            miss: str | None = None
            if effective == "disagree" and previous != "disagree":
                miss = "unsafe" if d.verdict == "allow" else "over_strict"
            records: list[dict[str, Any]] = []
            state_change: dict[str, str] | None = None
            skipped = False
            if miss == "unsafe" and d.state == "enforced":
                if _drop_applies(store, loaded, d):
                    store.write_state_row(
                        d.policy,
                        d.scope,
                        "shadow",
                        set_by=actor,
                        set_at=when,
                        cause="miss",
                        fingerprint=d.fingerprint,
                    )
                    state_change = {
                        "policy": d.policy,
                        "scope": d.scope,
                        "state": "shadow",
                        "cause": "miss",
                    }
                else:
                    skipped = True
            records.append(
                audit.audit_record(
                    action="outcome",
                    target=decision_id,
                    decision_id=decision_id,
                    actor=actor,
                    stdin_tty=ctx.stdin_tty,
                    actor_source=resolved.source,
                    caller_decision_ids=ctx.decision_ids,
                    inputs={"signal": signal, "outcome": verdict},
                    result={
                        "outcome": verdict,
                        "signal": signal,
                        "effective_outcome": effective,
                        "miss": miss,
                    },
                    ts=when,
                )
            )
            if state_change is not None:
                records.append(
                    audit.audit_record(
                        action="state_change",
                        target=f"{d.policy}@{d.scope}",
                        decision_id=ctx.decision_ids,
                        actor=actor,
                        stdin_tty=ctx.stdin_tty,
                        actor_source=resolved.source,
                        caller_decision_ids=ctx.decision_ids,
                        inputs={"policy": d.policy, "scope": d.scope, "state": "shadow"},
                        result={
                            "previous_state": "enforced",
                            "state": "shadow",
                            "cause": "miss",
                            "reason": reason,
                            "triggered_by": decision_id,
                        },
                        ts=when,
                    )
                )
            store.append_audit_many(records)
            return _Done(
                decision_id, d.policy, d.scope, previous, effective, miss, state_change, skipped
            )

        done = store.transact(body)

    # TODO(#31): fire post-outcome (previous_effective_outcome is done.previous) and, when
    # done.state_change is set, post-state-change (cause miss), after the commit.
    if done.skipped_drop:
        _log_drop_skipped(done)
    payload = {
        "decision_id": done.decision_id,
        "outcome": verdict,
        "signal": signal,
        "actor": actor,
        "changed": done.effective != done.previous,
        "effective_outcome": done.effective,
        "miss": done.miss,
        "state_change": done.state_change,
    }
    text = f"{done.decision_id} {verdict} by {actor} (signal {signal}): effective {done.effective}"
    if done.miss:
        text += f", {done.miss} miss"
    if done.state_change:
        text += f"; {done.policy}@{done.scope} enforced -> shadow"
    warning = None
    if loaded.shared_problems and not ctx.quiet:
        warning = "gatectl: warning config_problem: a shared key is invalid, see gatectl validate"
    return Result(payload=payload, text=sanitize(text, 1024), stderr=warning)


def _drop_applies(store: store_mod.Store, loaded: LoadedConfig, d: _Decision) -> bool:
    """Whether the miss still belongs to the enforcement that gave the decision its state: the
    policy is configured and the effective row of the decision's scope is that same row."""
    if d.policy not in loaded.policies:
        return False
    now = store.effective(d.policy, d.scope, _initial_state(loaded, d.policy))
    return now.state == "enforced" and now.rev == d.state_rev


def _log_drop_skipped(done: _Done) -> None:
    try:
        audit.append_log(
            audit.log_record(
                level="info",
                event="drop_skipped",
                message="outcome miss did not change a state",
                policy=done.policy,
                scope=done.scope,
                decision_id=done.decision_id,
            )
        )
    except (OSError, ValueError, TypeError):
        pass  # the outcome is recorded whether or not the log can be written
