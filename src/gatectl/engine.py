"""The ``check`` engine: one decision, from the flags to the exit code (interface.md, Check order).

The steps, in order (the numbers are the interface's):

1. resolve: the flags, the config, the policy (an unknown or invalid one is exit 2);
2. read the input, bounded by the deadline (``inputs.read_input``);
3. scope, per-repo definition, fingerprint and the effective state (the strictest stored state
   for an indeterminate scope), read read-only: an unreadable state is exit 1 (unknown);
4. ``off`` prints the off result and records nothing; 4a. a false ``applies_when`` answers
   ``not_applicable``;
5. an unusable input, an indeterminate scope or a declaration mismatch skips every check;
6. rule and script checks in listed order; 7. agent checks, only while the result is ``allow``;
8. combine and record: one ``Store.transact`` body re-reads the state, inserts the decision row
   and appends its audit line, so the state read there decides everything that is printed.

Failure policy. From step 3 on the state is known. A failure after that (the decision cannot be
recorded, an unexpected exception anywhere) never blocks in ``shadow``: exit 0, the would-be
decision, no ``decision_id`` and an ``error`` object (``shadow_failure`` log event); in
``enforced`` it is exit 1 (the error envelope), so a bug can never turn into an ``allow``. Before
step 3 an unexpected exception is exit 1 as well (the state is unknown).

Nothing printed or stored here carries input text, except what the schemas allow: the declared
fields and identity strings (capped) and the ``detail`` of a check (sanitized and capped).

Deadline. ``Context.started`` is the monotonic start of the process. ``R`` (``_budget``) is the
deadline minus now minus ``defaults.record_reserve``; a rule check never looks at it, a script
check starts only while it is above 0 and gets the smaller of its own timeout and ``R``.

Seams: agent checks are not implemented yet (TODO(#24): the run sequence; until then an agent
check that would run escalates ``check_error``, never allows), and the detached ``post-decision``
hook supervisor starts after the descriptors are pointed at ``/dev/null`` (TODO(#20)).
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from gatectl import audit, drift, history, ids, inputs, plan, rules, runner, tmptree
from gatectl import fingerprint as fingerprint_mod
from gatectl import store as store_mod
from gatectl.clock import now_ts
from gatectl.config import LoadedConfig, load_for_command
from gatectl.config_models import AgentCheck, Check, Policy, RuleCheck, ScriptCheck
from gatectl.context import Context, Result
from gatectl.dryrun import parse_timeout
from gatectl.errors import InternalError
from gatectl.gateway import Gateway, SubprocessGateway
from gatectl.inputhash import input_sha256, input_sha256_raw
from gatectl.inputs import InputInvalid, RawInput
from gatectl.sanitize import sanitize
from gatectl.scope import STAR, Scope, resolve_effective, resolve_scope
from gatectl.setcmd import _os_user_name

STDIN_FD = 0
DETAIL_CAP = history.DETAIL_CAP
SHADOW_ERROR_MESSAGE = "could not record the decision"
AGENT_NOT_IMPLEMENTED = "agent checks are not implemented"
_SEVERITY = {"allow": 0, "escalate": 1, "deny": 2}
_STRICTNESS = {"off": 0, "shadow": 1, "enforced": 2}
_EXIT_ENFORCED = {"allow": 0, "deny": 11, "escalate": 13}


# --- check entries and the combination rule ------------------------------------------------


@dataclass
class Entry:
    """One check's result. ``printed`` is the ``check_entry`` shape of ``schemas/defs.json``;
    ``stored`` adds the internal ``cache_key`` of an agent entry that read the cache."""

    name: str
    type: str
    verdict: str
    reason: str | None
    detail: str | None
    duration_ms: int
    confidence: float | None = None
    reused: bool = False
    cache_key: str | None = None

    def printed(self, detail_cap: int = DETAIL_CAP) -> dict[str, Any]:
        detail = None if self.detail is None else sanitize(self.detail, detail_cap) or None
        entry: dict[str, Any] = {
            "name": self.name,
            "type": self.type,
            "verdict": self.verdict,
            "reason": self.reason,
            "detail": detail,
            "duration_ms": self.duration_ms,
        }
        if self.type == "agent":
            entry["confidence"] = self.confidence
            entry["reused"] = self.reused
        return entry

    def stored(self, detail_cap: int = DETAIL_CAP) -> dict[str, Any]:
        entry = self.printed(detail_cap)
        if self.cache_key is not None:
            entry["cache_key"] = self.cache_key
        return entry


def skipped(check: Check) -> Entry:
    return Entry(check.name, check.type, "skipped", None, None, 0)


@dataclass(frozen=True)
class Combined:
    """The decision, its reason and the check that gave the reason (None when no check did)."""

    decision: str
    reason: str
    check: str | None


def combine(entries: Sequence[Entry]) -> Combined:
    """The most severe verdict (deny over escalate over allow); the reason is that of the first
    ``deny``, else of the first ``escalate`` in check order, else ``all_passed``.

    A ``skipped`` entry counts for nothing. Anything unexpected (an unknown verdict, or no check
    ran at all) is an ``escalate``: this function never produces an ``allow`` it cannot justify.
    """
    worst = "allow"
    first: dict[str, Entry] = {}
    ran = False
    for entry in entries:
        if entry.verdict == "skipped":
            continue
        ran = True
        verdict = entry.verdict if entry.verdict in _SEVERITY else "escalate"
        first.setdefault(verdict, entry)
        if _SEVERITY[verdict] > _SEVERITY[worst]:
            worst = verdict
    if not ran:
        return Combined("escalate", "check_error", None)
    if worst == "allow":
        return Combined("allow", "all_passed", None)
    entry = first[worst]
    fallback = "check_denied" if worst == "deny" else "check_error"
    return Combined(worst, entry.reason or fallback, entry.name)


# --- the result and the one stderr line ---------------------------------------------------


def _result(
    *,
    policy: str,
    scope: str,
    state: str,
    shadow: bool,
    enforced: bool,
    decision: str | None,
    reason: str | None,
    fingerprint: str,
    checks: Sequence[Entry],
    warnings: Sequence[str],
    error: Mapping[str, Any] | None = None,
    decision_id: str | None = None,
    input_hash: str | None = None,
) -> dict[str, Any]:
    """The check result; ``decision_id`` and ``input_sha256`` appear only when given (exactly
    when a decision was recorded), never as null."""
    doc: dict[str, Any] = {"schema_version": 1}
    if decision_id is not None:
        doc["decision_id"] = decision_id
    doc.update(
        {
            "policy": policy,
            "scope": scope,
            "state": state,
            "shadow": shadow,
            "enforced": enforced,
            "decision": decision,
            "reason": reason,
            "fingerprint": fingerprint,
        }
    )
    if input_hash is not None:
        doc["input_sha256"] = input_hash
    doc["checks"] = [c.printed() for c in checks]
    doc["warnings"] = list(dict.fromkeys(warnings))
    doc["error"] = None if error is None else dict(error)
    return doc


def veto_line(
    decision: str, policy: str, scope: str, reason: str, check: str | None, decision_id: str
) -> str:
    """``gatectl: <decision> <policy>@<scope>: <reason> (<check name>) <decision_id>``, built
    only from closed fields (the grammar of each; the check name is configured, not input)."""
    named = f" ({check})" if check is not None else ""
    return f"gatectl: {decision} {policy}@{scope}: {reason}{named} {decision_id}"


def exit_code(state: str, decision: str) -> int:
    """0 for ``shadow``; for ``enforced`` 0, 11 or 13 by the decision. An unknown decision in
    ``enforced`` is 13 (never 0)."""
    if state != "enforced":
        return 0
    return _EXIT_ENFORCED.get(decision, 13)


# --- the environment of one run ------------------------------------------------------------


@dataclass(frozen=True)
class Env:
    """What a run depends on, so tests can substitute it."""

    gateway: Gateway = field(default_factory=SubprocessGateway)
    monotonic: Callable[[], float] = time.monotonic
    environ: Mapping[str, str] = field(default_factory=lambda: os.environ)


def handle(ctx: Context) -> Result:
    """``check``: a dry run is the plan, anything else is the engine."""
    if ctx.args.dry_run:
        from gatectl import dryrun

        return dryrun.handle(ctx)
    return run(ctx, Env())


# --- the run -----------------------------------------------------------------------------


def _strictest(*states: str) -> str:
    return max(states, key=lambda s: _STRICTNESS.get(s, 2))


def _actor(ctx: Context, loaded: LoadedConfig) -> ids.ResolvedActor:
    """The effective actor. Never fails: a bad ``me.name`` is sanitized, not refused."""
    name = _os_user_name() if loaded.shared.me.name is None else loaded.shared.me.name
    return ids.resolve_actor(ctx.actor, stdin_tty=ctx.stdin_tty, name=name)


def _log(event: str, level: str = "info", **fields: Any) -> None:
    """Write a ``log.jsonl`` event; a log that cannot be written never changes an answer."""
    try:
        audit.append_log(audit.log_record(level=level, event=event, **fields))
    except Exception:  # noqa: S110
        pass


def _declared_json(declared: Mapping[str, Any]) -> str:
    text = json.dumps(declared, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    if len(text.encode("ascii")) > history.DECLARED_MAX_BYTES:
        raise InputInvalid("unrecordable")
    return text


def _checks_json(entries: Sequence[Entry]) -> str:
    """The stored ``checks_json``; details are shortened (1024, 256, then dropped) while it
    would be over the size ``show`` accepts."""
    text = ""
    for cap in (DETAIL_CAP, 256, 0):
        text = json.dumps(
            [e.stored(cap) for e in entries], separators=(",", ":"), ensure_ascii=True
        )
        if len(text) <= history.CHECKS_MAX_BYTES:
            break
    return text


@dataclass
class _Run:
    """The state of one ``check`` that the failure path needs."""

    ctx: Context
    env: Env
    loaded: LoadedConfig
    name: str
    policy: Policy
    scope: Scope
    fingerprint: str
    resolved: store_mod.Resolved
    raw: RawInput
    obj: dict[str, Any] | None
    deadline: float
    reserve: float
    warnings: list[str]
    entries: list[Entry] = field(default_factory=list)
    would_be: Combined | None = None
    decision_id: str | None = None
    script_n: int = 0

    @property
    def state(self) -> str:
        return self.resolved.state

    def new_id(self) -> str:
        if self.decision_id is None:
            self.decision_id = ids.new_decision_id()
        return self.decision_id

    def budget(self) -> float:
        """``R``: the deadline minus now minus the record reserve."""
        return self.deadline - self.env.monotonic() - self.reserve


def run(ctx: Context, env: Env) -> Result:
    override = parse_timeout(ctx.args.timeout)  # exit 2 before anything is read
    loaded = load_for_command(ctx.command, ctx.args, ctx.config)
    name: str = ctx.args.policy
    base = loaded.resolve_policy(name)  # unknown or invalid policy: exit 2, before any read
    defaults = loaded.shared.defaults
    reserve = defaults.record_reserve.total_seconds()
    limit = base.timeout if base.timeout is not None else defaults.timeout
    deadline = ctx.started + (override if override is not None else limit.total_seconds())

    raw = inputs.read_input(
        ctx.args.input,
        max_bytes=defaults.input_max_bytes,
        stdin_fd=STDIN_FD,
        deadline=deadline,
        reserve=reserve,
        monotonic=env.monotonic,
    )
    obj: dict[str, Any] | None = None
    if raw.status == "complete":
        try:
            obj = inputs.parse_input(raw.data)
        except Exception:  # InputInvalid, or anything a hostile input provokes: not an object
            obj = None

    scope = resolve_scope(ctx.args.repo, obj)
    effective = resolve_effective(loaded, name, scope)
    policy = effective.policy
    if override is None:
        own = policy.timeout if policy.timeout is not None else defaults.timeout
        if own != limit:  # the override's timeout counts from the start, never before now
            deadline = max(env.monotonic(), ctx.started + own.total_seconds())
    fingerprint = fingerprint_mod.fingerprint(
        name,
        policy,
        loaded.shared,
        deadline=deadline,
        monotonic=env.monotonic,
    )
    # Unreadable storage is an exception here: exit 1, the state is unknown.
    resolved = store_mod.read_effective(
        name, scope.scope, policy.state, indeterminate=scope.indeterminate
    )
    warnings = list(scope.warnings)
    repo = None if scope.scope == STAR else scope.scope
    if loaded.warns_config_problem_for(name, repo):
        warnings.append("config_problem")

    state = _Run(
        ctx, env, loaded, name, policy, scope, fingerprint, resolved, raw, obj,
        deadline, reserve, warnings,
    )  # fmt: skip
    try:
        return _decide(state)
    except Exception as exc:  # the state is known: shadow never blocks, enforced fails closed
        return _failure(state, exc)


def _off(run: _Run) -> Result:
    _log("check_off", policy=run.name, scope=run.scope.scope)
    doc = _result(
        policy=run.name,
        scope=run.scope.scope,
        state="off",
        shadow=False,
        enforced=False,
        decision=None,
        reason=None,
        fingerprint=run.fingerprint,
        checks=[],
        warnings=run.warnings,
    )
    return Result(payload=doc)


def _changed(run: _Run, resolved: store_mod.Resolved) -> bool:
    try:
        return drift.definition_changed(
            run.loaded, run.name, resolved, scope=run.scope.scope, current=run.fingerprint
        )
    except Exception:  # cannot tell: warn
        return resolved.state == "enforced"


def _decide(run: _Run) -> Result:
    if run.state == "off":
        return _off(run)
    obj = run.obj
    policy = run.policy
    if (
        policy.applies_when is not None
        and obj is not None
        and not run.scope.indeterminate
        and not rules.applies(policy.applies_when, obj)
    ):
        warnings = list(run.warnings)
        if _changed(run, run.resolved):
            warnings.append(drift.WARNING)
        doc = _result(
            policy=run.name,
            scope=run.scope.scope,
            state=run.state,
            shadow=False,
            enforced=False,
            decision="allow",
            reason="not_applicable",
            fingerprint=run.fingerprint,
            checks=[],
            warnings=warnings,
        )
        return Result(payload=doc)

    invalid = _input_problem(run)
    if invalid is not None:
        run.would_be = Combined("escalate", invalid[0], None)
        declared, identity = invalid[1], invalid[2]
    else:
        declared, identity = None, None
        assert obj is not None
        run.would_be = None
    entries: list[Entry] = []
    if invalid is None:
        entries = _run_checks(run)
    run.entries = entries
    combined = run.would_be if invalid is not None else combine(entries)
    assert combined is not None
    run.would_be = combined
    if invalid is None:
        assert obj is not None
        declared = inputs.declared_fields(policy.input, obj)
        identity = inputs.identity(obj)
    return _record(run, combined, declared, identity)


def _input_problem(
    run: _Run,
) -> tuple[str, dict[str, Any] | None, inputs.Identity | None] | None:
    """Step 5: None when the input is usable, else (reason, declared fields, identity).

    The declared fields and identity are None when the input did not parse or fails the
    declaration (or cannot be recorded); an indeterminate scope with a good declaration records
    them.
    """
    raw, obj = run.raw, run.obj
    if raw.status != "complete" or obj is None:
        return ("timeout" if raw.status == "timeout" else "input_invalid", None, None)
    try:
        inputs.check_declaration(run.policy.input, obj)
        declared = inputs.declared_fields(run.policy.input, obj)
        _declared_json(declared)
        identity = inputs.identity(obj)
    except InputInvalid:
        return ("input_invalid", None, None)
    if run.scope.indeterminate:
        return ("input_invalid", declared, identity)
    return None


# --- steps 6 and 7 ---------------------------------------------------------------------------


def _verdict_reason(verdict: str) -> str | None:
    return {"deny": "check_denied", "escalate": "check_escalated"}.get(verdict)


def _rule_entry(run: _Run, check: RuleCheck) -> Entry:
    assert run.obj is not None
    started = run.env.monotonic()
    found = rules.run_rule(check, run.obj)
    ms = max(0, int((run.env.monotonic() - started) * 1000))
    reason = found.reason or _verdict_reason(found.verdict)
    return Entry(check.name, "rule", found.verdict, reason, found.detail, ms)


def _script_entry(run: _Run, check: ScriptCheck) -> Entry:
    defaults = run.loaded.shared.defaults
    remaining = run.budget()
    if remaining <= 0:
        return Entry(check.name, "script", "escalate", "timeout", "not started", 0)
    own = check.timeout if check.timeout is not None else defaults.script_timeout
    run.script_n += 1
    decision_id = run.new_id()
    try:
        out = runner.run_script_check(
            run.env.gateway,
            argv=check.argv,
            payload=run.raw.data,
            timeout=min(own.total_seconds(), remaining),
            env_allow=check.env_allow or [],
            default_env_allow=defaults.script_env_allow,
            environ=run.env.environ,
            state_dir=audit.state_dir(),
            decision_id=decision_id,
            n=run.script_n,
        )
    except Exception:  # an invalid env list or an unstartable check is a bug, not a verdict
        _log("warning", "warn", message="a script check could not be started",
             policy=run.name, scope=run.scope.scope, decision_id=decision_id,
             data={"check": check.name})  # fmt: skip
        return Entry(check.name, "script", "escalate", "check_error", "not started", 0)
    for flag in ("workdir_left", "leader_unkilled", "pipes_held"):
        if getattr(out, flag):
            _log("warning", "warn", message=flag, policy=run.name, scope=run.scope.scope,
                 decision_id=decision_id, data={"check": check.name})  # fmt: skip
    for code in out.warnings:
        run.warnings.append(code)
    verdict = out.verdict if out.verdict in _SEVERITY else "escalate"
    reason = None if verdict == "allow" else (out.reason or "check_error")
    return Entry(check.name, "script", verdict, reason, out.detail, out.duration_ms)


def _run_checks(run: _Run) -> list[Entry]:
    """Steps 6 and 7. Results come back in execution order: rule and script checks in listed
    order, then agent checks."""
    order = plan.execution_order(run.policy)
    entries: list[Entry] = []
    denied = False
    out_of_time = False
    try:
        for check in order:
            if isinstance(check, AgentCheck):
                continue
            if denied:
                entries.append(skipped(check))
            elif isinstance(check, RuleCheck):
                entries.append(_rule_entry(run, check))
            elif out_of_time:
                entries.append(skipped(check))
            else:
                assert isinstance(check, ScriptCheck)
                entry = _script_entry(run, check)
                out_of_time = entry.detail == "not started" and entry.reason == "timeout"
                entries.append(entry)
            denied = denied or entries[-1].verdict == "deny"
        so_far = combine(entries).decision if entries else "allow"
        for check in order:
            if not isinstance(check, AgentCheck):
                continue
            if so_far != "allow":
                entries.append(skipped(check))
                continue
            entries.append(_agent_entry(run, check))
            so_far = combine(entries).decision
    finally:
        _remove_tmp(run)
    return entries


def _agent_entry(run: _Run, check: AgentCheck) -> Entry:
    # TODO(#24): the agent run sequence (cache, slot, claude-session). Until it lands an agent
    # check that would run escalates; it can never allow.
    return Entry(
        check.name, "agent", "escalate", "check_error", AGENT_NOT_IMPLEMENTED, 0, None, False
    )


def _remove_tmp(run: _Run) -> None:
    """Remove ``tmp/<decision_id>/`` wholesale when the checks end (a script's residue beside or
    renamed from ``s-<n>/`` is not found by the per-check removal); a leftover is
    ``workdir_left``."""
    if run.decision_id is None:
        return
    path = audit.state_dir() / "tmp" / run.decision_id
    left = False
    try:
        tmptree.remove_tree(path)
    except Exception:
        left = True
    if left or os.path.lexists(path):
        _log("warning", "warn", message="workdir_left", policy=run.name, scope=run.scope.scope,
             decision_id=run.decision_id)  # fmt: skip


# --- step 8 ----------------------------------------------------------------------------


def _input_hash(run: _Run) -> str:
    if run.obj is not None:
        return input_sha256(run.obj)
    return input_sha256_raw(run.raw.data)


def _record(
    run: _Run,
    combined: Combined,
    declared: Mapping[str, Any] | None,
    identity: inputs.Identity | None,
) -> Result:
    ctx, policy = run.ctx, run.policy
    decision_id = run.new_id()
    actor = _actor(ctx, run.loaded)
    input_hash = _input_hash(run)
    obj = run.obj
    parsed_ok = obj is not None and declared is not None
    case_key = inputs.case_key(policy.input, obj) if parsed_ok and obj is not None else None
    ident = identity if identity is not None else inputs.NO_IDENTITY
    declared_json = _declared_json(declared) if declared is not None else None
    checks_json = _checks_json(run.entries)
    input_json = None
    if policy.record_input and obj is not None:
        input_json = json.dumps(obj, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    repo = None if run.scope.scope == STAR else run.scope.scope

    store = store_mod.open_store(create=True, busy_timeout=run.reserve)
    assert store is not None
    with store:

        def body() -> tuple[store_mod.Resolved, str]:
            resolved = store.effective(
                run.name, run.scope.scope, policy.state, indeterminate=run.scope.indeterminate
            )
            if resolved.state == "off":
                return resolved, ""
            when = now_ts()  # the instant of the insert, inside the lock
            shadow, enforced = resolved.state == "shadow", resolved.state == "enforced"
            store.insert_decision(
                store_mod.DecisionRow(
                    id=decision_id,
                    time=when,
                    policy=run.name,
                    scope=run.scope.scope,
                    fingerprint=run.fingerprint,
                    state=resolved.state,
                    decision=combined.decision,
                    reason=combined.reason,
                    tool=ident.tool,
                    hook=ident.hook,
                    object_type=ident.object_type,
                    object_id=ident.object_id,
                    repo=repo,
                    input_sha256=input_hash,
                    case_key=case_key,
                    state_rev=resolved.rev,
                    declared_json=declared_json,
                    checks_json=checks_json,
                    actor=str(actor.actor),
                    input_json=input_json,
                )
            )
            store.append_audit(
                audit.audit_record(
                    action="decision",
                    target=f"{run.name}@{run.scope.scope}",
                    decision_id=decision_id,
                    actor=str(actor.actor),
                    stdin_tty=ctx.stdin_tty,
                    actor_source=actor.source,
                    caller_decision_ids=ctx.decision_ids,
                    inputs={
                        "policy": run.name,
                        "scope": run.scope.scope,
                        "input_sha256": input_hash,
                        "fingerprint": run.fingerprint,
                    },
                    result={
                        "decision": combined.decision,
                        "reason": combined.reason,
                        "state": resolved.state,
                        "shadow": shadow,
                        "enforced": enforced,
                    },
                    ts=when,
                )
            )
            return resolved, when

        # No retry of mine around this: Store.transact retries only a lock never obtained.
        resolved, when = store.transact(body)

    if resolved.state == "off":  # a set to off committed while the checks ran: nothing recorded
        run.resolved = resolved
        run.entries = []
        return _off(run)
    warnings = list(run.warnings)
    if _changed(run, resolved):
        warnings.append(drift.WARNING)
    state = resolved.state
    doc = _result(
        decision_id=decision_id,
        policy=run.name,
        scope=run.scope.scope,
        state=state,
        shadow=state == "shadow",
        enforced=state == "enforced",
        decision=combined.decision,
        reason=combined.reason,
        fingerprint=run.fingerprint,
        input_hash=input_hash,
        checks=run.entries,
        warnings=warnings,
    )
    code = exit_code(state, combined.decision)
    line = None
    if code in (11, 13):
        line = veto_line(
            combined.decision, run.name, run.scope.scope, combined.reason, combined.check,
            decision_id,
        )  # fmt: skip
    # TODO(#20): start the detached post-decision hook supervisor here, after the commit.
    return Result(payload=doc, exit_code=code, stderr=line, detach=True)


def _failure(run: _Run, exc: Exception) -> Result:
    """A failure after the state is known. ``enforced`` (as read before or after the failure,
    whichever is stricter) is exit 1; ``shadow`` is exit 0 with the would-be decision."""
    state = run.state
    try:
        again = store_mod.read_effective(
            run.name, run.scope.scope, run.policy.state, indeterminate=run.scope.indeterminate
        )
        state = _strictest(state, again.state)
    except Exception:  # noqa: S110  (keep what was known)
        pass
    if state == "enforced":
        if isinstance(exc, InternalError):
            raise exc
        raise InternalError("internal error") from None
    would_be = run.would_be or Combined("escalate", "check_error", None)
    reason = exc.reason if isinstance(exc, InternalError) else None
    _log(
        "shadow_failure",
        "error",
        message=sanitize(SHADOW_ERROR_MESSAGE),
        policy=run.name,
        scope=run.scope.scope,
    )
    doc = _result(
        policy=run.name,
        scope=run.scope.scope,
        state=state,
        shadow=state == "shadow",
        enforced=False,
        decision=would_be.decision,
        reason=would_be.reason,
        fingerprint=run.fingerprint,
        checks=run.entries,
        warnings=run.warnings,
        error={
            "code": "internal",
            "message": SHADOW_ERROR_MESSAGE,
            "reason": reason,
            "details": None,
        },
    )
    line = None
    if not run.ctx.quiet:
        line = f"gatectl: warning shadow_failure {run.name}@{run.scope.scope}"
    return Result(payload=doc, exit_code=0, stderr=line)
