"""Read-only readers of the decision history in ``state.db``: ``decisions`` and ``show``.

Everything here reads through ``Store.query`` (a read-only connection: nothing is created,
migrated or written) with fixed SQL text and bound parameters. A caller's value is never part of
the SQL, and a decision-id prefix is matched as a range, never with ``LIKE``.

Every stored value is untrusted (a same-user process can edit the database). A text column is cut
in SQL before it is read (by bytes: ``length()`` and ``substr()`` stop at a NUL, which would hide
it and the rest of the value); a value that must follow a closed grammar (ids, times, states,
fingerprints, reason codes, check entries, actors) and does not is refused with the fixed text
``state.db holds an invalid decision row`` (exit 1), never echoed; free text (``tool``, ``hook``,
``object_type``, ``object_id``, declared strings, a check ``detail``, an outcome reason) is
sanitized and cut to its cap. The effective outcome is computed in SQL from the outcome records in
sequence order (interface.md, Outcomes): the last ``disagree`` or human ``agree`` decides, and an
automatic ``agree`` never counts.

The check engine writes ``checks_json``. Its entries are the ``check_entry`` shape of
``schemas/defs.json``; an agent entry that reused a cached result also carries
``cache_key``, the ``agent_cache.key`` it read, which ``show`` follows to the decision that
produced the result (``cache_source``) and never prints. The engine (``_agent_entry``) writes
it for a reused result only.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from gatectl import ids
from gatectl.clock import parse_ts
from gatectl.errors import GatectlError, InternalError, NotFoundError
from gatectl.inputhash import canonical_input
from gatectl.sanitize import sanitize
from gatectl.scope import STAR
from gatectl.store import Store, cut_sql, uncut

DEFAULT_LIMIT = 100
MAX_LIMIT = 1000
OUTCOME_LIMIT = 1000  # outcome records ``show`` prints for one decision
TEXT_CAP = 256  # the cap of the input strings a row carries (tool, hook, declared values, ...)
DETAIL_CAP = 1024  # a check detail and an outcome reason
DECLARED_MAX_BYTES = 32768  # stored declared_json read (a larger one is a tamper)
CHECKS_MAX_BYTES = 65536  # stored checks_json read
MAX_CHECKS = 256
_DECLARED_VALUE_MAX = 1024  # canonical JSON of a non-string declared value
_DECLARED_DEPTH = 8

STATES = ("off", "shadow", "enforced")
DECISIONS = ("allow", "deny", "escalate")
VERDICTS = ("allow", "deny", "escalate", "skipped")
CHECK_TYPES = ("script", "rule", "agent")
OUTCOMES = ("agree", "disagree")
ACTOR_KINDS = ("human", "automatic", "unattributed")
# schemas/defs.json ``reason``: a closed list (tests pin this tuple against the schema).
REASONS = (
    "all_passed",
    "check_denied",
    "check_escalated",
    "input_invalid",
    "timeout",
    "budget_exhausted",
    "busy",
    "tool_missing",
    "agent_unreported",
    "artifact_invalid",
    "low_confidence",
    "sandbox_unavailable",
    "check_error",
    "not_applicable",
)

_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_CACHE_KEY = re.compile(r"[A-Za-z0-9:._-]{1,128}")

_TAMPERED = "state.db holds an invalid decision row"
_ONE_BASE32_UP = {c: chr(ord(c) + 1) for c in "abcdefghijklmnopqrstuvwxyz234567"}


def _tampered() -> InternalError:
    return InternalError(_TAMPERED)


def _bounded(column: str, max_bytes: int) -> str:
    """The column when it is NULL or text of at most ``max_bytes`` bytes (a NUL counts); else an
    empty blob (invalid). ``length()`` of text stops at a NUL, so the bytes are measured."""
    return (
        f"CASE WHEN {column} IS NULL THEN NULL"
        f" WHEN typeof({column}) = 'text' AND length(CAST({column} AS BLOB)) <= {max_bytes}"
        f" THEN {column} ELSE zeroblob(0) END"
    )


# The effective outcome (interface.md, Outcomes): the last outcome record that counts (any
# disagree, or an agree from a human actor), else pending. ``d`` is the decisions row.
_EFFECTIVE = (
    "COALESCE((SELECT o.outcome FROM outcomes o WHERE o.decision_id = d.id"
    " AND (o.outcome = 'disagree' OR (o.outcome = 'agree' AND substr(o.actor, 1, 6) = 'human:'"
    " AND instr(CAST(o.actor AS BLOB), x'00') = 0))"
    " ORDER BY o.seq DESC LIMIT 1), 'pending')"
)

_COLUMNS = (
    ", ".join(
        cut_sql(f"d.{c}")
        for c in (
            "id",
            "time",
            "policy",
            "scope",
            "state",
            "decision",
            "reason",
            "fingerprint",
            "actor",
            "tool",
            "hook",
            "object_type",
            "object_id",
            "repo",
            "input_sha256",
            "case_key",
        )
    )
    + ", d.state_rev, "
    + _bounded("d.declared_json", DECLARED_MAX_BYTES)
    + ", "
    + _EFFECTIVE
)

_SHOW_COLUMNS = _COLUMNS + ", " + _bounded("d.checks_json", CHECKS_MAX_BYTES)


@dataclass(frozen=True)
class Filters:
    """The validated filters of ``decisions``; every value is bound as a parameter."""

    since: str | None = None  # fixed-form timestamp, inclusive
    policy: str | None = None
    scope: str | None = None  # a repo id, or ``*``
    object_id: str | None = None
    outcome: str | None = None
    decision: str | None = None
    declared: tuple[str, str] | None = None


# --- validation of stored values ----------------------------------------------------------------


def _text(value: object, cap: int) -> str:
    if not isinstance(value, str):
        raise _tampered()
    return sanitize(value, cap)


def _opt_text(value: object, cap: int) -> str | None:
    return None if value is None else _text(value, cap)


def _timestamp(value: object) -> str:
    if not isinstance(value, str):
        raise _tampered()
    try:
        parse_ts(value)
    except ValueError:
        raise _tampered() from None
    return value


def _one_of(value: object, allowed: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise _tampered()
    return value


def _matching(value: object, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise _tampered()
    return value


def _actor(value: object) -> str:
    if not isinstance(value, str):
        raise _tampered()
    try:
        ids.parse_actor(value)
    except GatectlError:
        raise _tampered() from None
    return value


def _reject_constant(_: str) -> Any:
    raise ValueError("not a JSON number")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``json.loads`` hook: SQLite's ``json_each`` yields both of two equal keys and Python keeps
    the last, so a stored object with a duplicate key is a tamper."""
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _finite(value: object) -> bool:
    return not isinstance(value, float) or math.isfinite(value)


def _declared_value(value: Any, depth: int) -> Any:
    if isinstance(value, str):
        return sanitize(value, TEXT_CAP)
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _tampered()
        return value
    if depth >= _DECLARED_DEPTH:
        raise _tampered()
    if isinstance(value, list):
        return [_declared_value(v, depth + 1) for v in value]
    if isinstance(value, dict):
        return _declared_object(value, depth + 1)
    raise _tampered()


def _declared_object(value: Mapping[str, Any], depth: int) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, item in value.items():
        clean = sanitize(key, TEXT_CAP)
        base, n = clean, 1
        while clean in out:  # two keys that sanitize to the same text both stay visible
            n += 1
            clean = f"{base}~{n}"
        out[clean] = _declared_value(item, depth)
    return out


def _canonical_size(value: Any) -> int:
    """The UTF-8 bytes of a declared value's canonical JSON: what the writer capped at 1 KiB
    (``inputs.VALUE_CAP``), so a stored value that was legitimately under the cap is not refused."""
    try:
        return len(canonical_input(value).encode("utf-8", errors="surrogatepass"))
    except (ValueError, TypeError, RecursionError):
        raise _tampered() from None


def _declared(raw: object) -> dict[str, Any]:
    """The declared fields: strings capped at 256, other values at 1 KiB of canonical JSON."""
    if raw is None:
        return {}
    if not isinstance(raw, str):
        raise _tampered()
    try:
        parsed = json.loads(
            raw, parse_constant=_reject_constant, object_pairs_hook=_no_duplicate_keys
        )
    except (ValueError, RecursionError):
        raise _tampered() from None
    if not isinstance(parsed, dict):
        raise _tampered()
    declared = _declared_object(parsed, 0)
    for value in parsed.values():
        if not isinstance(value, str) and _canonical_size(value) > _DECLARED_VALUE_MAX:
            raise _tampered()
    return declared


def _int_at_least_zero(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _tampered()
    return value


def _decision(raw: tuple[Any, ...], configured: Mapping[str, Any] | set[str]) -> dict[str, Any]:
    raw = (*(uncut(v) for v in raw[:16]), *raw[16:])
    (
        raw_id,
        when,
        policy,
        scope,
        state,
        decision,
        reason,
        fingerprint,
        actor,
        tool,
        hook,
        object_type,
        object_id,
        repo,
        input_sha256,
        case_key,
        state_rev,
        declared,
        effective,
    ) = raw[:19]
    if not isinstance(raw_id, str) or not ids.is_decision_id(raw_id):
        raise _tampered()
    if not isinstance(policy, str) or not ids.is_policy_name(policy):
        raise _tampered()
    if not isinstance(scope, str) or not (scope == STAR or ids.is_repo_id(scope)):
        raise _tampered()
    if repo is not None and not (isinstance(repo, str) and ids.is_repo_id(repo)):
        raise _tampered()
    return {
        "decision_id": raw_id,
        "time": _timestamp(when),
        "policy": policy,
        "scope": scope,
        "state": _one_of(state, STATES),
        "decision": _one_of(decision, DECISIONS),
        "reason": _one_of(reason, REASONS),
        "fingerprint": _matching(fingerprint, _FINGERPRINT),
        "actor": _actor(actor),
        "tool": _opt_text(tool, TEXT_CAP),
        "hook": _opt_text(hook, TEXT_CAP),
        "object_type": _opt_text(object_type, TEXT_CAP),
        "object_id": _opt_text(object_id, TEXT_CAP),
        "repo": repo,
        "declared": _declared(declared),
        "input_sha256": _matching(input_sha256, _HEX64),
        "state_rev": _int_at_least_zero(state_rev),
        "case_key": None if case_key is None else _matching(case_key, _HEX64),
        "configured": policy in configured,
        "effective_outcome": _one_of(effective, ("pending", *OUTCOMES)),
    }


def _confidence(value: object) -> float | int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _tampered()
    if not _finite(value) or not 0 <= value <= 1:
        raise _tampered()
    return value


def _check_entry(raw: object) -> tuple[dict[str, Any], str | None]:
    """One validated check entry (the output form) and its ``cache_key`` when it has one."""
    if not isinstance(raw, dict):
        raise _tampered()
    try:
        name, kind, verdict, reason = raw["name"], raw["type"], raw["verdict"], raw["reason"]
        detail, duration = raw["detail"], raw["duration_ms"]
    except KeyError:
        raise _tampered() from None
    if not isinstance(name, str) or not ids.is_check_name(name):
        raise _tampered()
    kind = _one_of(kind, CHECK_TYPES)
    verdict = _one_of(verdict, VERDICTS)
    if verdict in ("allow", "skipped"):
        if reason is not None:
            raise _tampered()
    else:
        reason = _one_of(reason, REASONS)
    if not isinstance(duration, int) or isinstance(duration, bool) or duration < 0:
        raise _tampered()
    entry: dict[str, Any] = {
        "name": name,
        "type": kind,
        "verdict": verdict,
        "reason": reason,
        "detail": _opt_text(detail, DETAIL_CAP),
        "duration_ms": duration,
    }
    if verdict == "skipped" and (entry["detail"] is not None or duration != 0):
        raise _tampered()
    reused = False
    if kind == "agent":
        if "confidence" not in raw or not isinstance(raw.get("reused"), bool):
            raise _tampered()
        reused = raw["reused"]
        entry["confidence"] = _confidence(raw["confidence"])
        entry["reused"] = reused
        if verdict == "skipped" and (entry["confidence"] is not None or reused):
            raise _tampered()
    elif "confidence" in raw or "reused" in raw:
        raise _tampered()
    cache_key = raw.get("cache_key")
    if cache_key is not None:
        _matching(cache_key, _CACHE_KEY)
    return entry, cache_key if reused else None


def _checks(raw: object) -> tuple[list[dict[str, Any]], list[str]]:
    """The check entries and the cache keys of the entries that reused a cached result."""
    if raw is None:
        return [], []
    if not isinstance(raw, str):
        raise _tampered()
    try:
        parsed = json.loads(raw, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise _tampered() from None
    if not isinstance(parsed, list) or len(parsed) > MAX_CHECKS:
        raise _tampered()
    entries: list[dict[str, Any]] = []
    keys: list[str] = []
    for item in parsed:
        entry, key = _check_entry(item)
        entries.append(entry)
        if key is not None:
            keys.append(key)
    return entries, keys


# --- the queries --------------------------------------------------------------------------------


def _where(filters: Filters) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    args: list[Any] = []
    if filters.since is not None:
        clauses.append("d.time >= ?")
        args.append(filters.since)
    if filters.policy is not None:
        clauses.append("d.policy = ?")
        args.append(filters.policy)
    if filters.scope is not None:
        clauses.append("d.scope = ?")
        args.append(filters.scope)
    if filters.object_id is not None:
        clauses.append("d.object_id = ?")
        args.append(filters.object_id)
    if filters.decision is not None:
        clauses.append("d.decision = ?")
        args.append(filters.decision)
    if filters.outcome is not None:
        clauses.append(f"{_EFFECTIVE} = ?")
        args.append(filters.outcome)
    if filters.declared is not None:
        clauses.append(
            "CASE WHEN typeof(d.declared_json) = 'text'"
            f" AND length(CAST(d.declared_json AS BLOB)) <= {DECLARED_MAX_BYTES}"
            " AND instr(CAST(d.declared_json AS BLOB), x'00') = 0"
            " AND json_valid(d.declared_json)"
            " THEN EXISTS (SELECT 1 FROM json_each(d.declared_json) j"
            " WHERE j.key = ? AND j.type = 'text' AND j.value = ?) ELSE 0 END"
        )
        args.extend(filters.declared)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", args


def list_decisions(
    store: Store, filters: Filters, limit: int, configured: Mapping[str, Any] | set[str]
) -> tuple[list[dict[str, Any]], bool]:
    """Up to ``limit`` decisions, newest first, and whether more matched."""
    where, args = _where(filters)
    rows = store.query(
        f"SELECT {_COLUMNS} FROM decisions d{where}"  # noqa: S608  (fixed text, bound values)
        " ORDER BY d.time DESC, d.id DESC LIMIT ?",
        [*args, limit + 1],
    )
    found = [_decision(r, configured) for r in rows[:limit]]
    return found, len(rows) > limit


def resolve(store: Store, ref: ids.DecisionRef) -> str:
    """The one stored id ``ref`` names: unknown exits 10, ambiguous exits 21."""
    low = f"gd-{ref.prefix}"
    high = low[:-1] + _ONE_BASE32_UP[low[-1]]
    rows = store.query(
        f"SELECT {cut_sql('id')} FROM decisions WHERE id >= ? AND id < ? ORDER BY id LIMIT 100",
        (low, high),
    )
    found = [uncut(r[0]) for r in rows]
    return ids.resolve_decision_ref(ref, [f for f in found if isinstance(f, str)])


def _outcomes(store: Store, decision_id: str) -> list[dict[str, Any]]:
    rows = store.query(
        f"SELECT time, outcome, signal, actor, actor_kind, {cut_sql('reason', DETAIL_CAP + 1)}"
        " FROM outcomes WHERE decision_id = ? ORDER BY seq LIMIT ?",
        (decision_id, OUTCOME_LIMIT),
    )
    out: list[dict[str, Any]] = []
    for when, outcome, signal, actor, kind, packed in rows:
        reason = uncut(packed, DETAIL_CAP + 1)
        if not isinstance(signal, str) or not ids.is_signal(signal):
            raise _tampered()
        out.append(
            {
                "time": _timestamp(when),
                "outcome": _one_of(outcome, OUTCOMES),
                "signal": signal,
                "actor": _actor(actor),
                "actor_kind": _one_of(kind, ACTOR_KINDS),
                "reason": _opt_text(reason, DETAIL_CAP),
            }
        )
    return out


def _cache_source(store: Store, keys: list[str], decided_at: str) -> dict[str, str] | None:
    """The decision that produced the cached result a reused check read, or None.

    The cache row counts only if it already existed (``time`` not after the decision) and was
    not yet expired (``expires_at`` after it) at the decision's time: a refreshed key names a
    later decision, and an expired row was not a hit. A row that was replaced and a row that was
    pruned are both None (interface.md, show).
    """
    for key in keys:
        rows = store.query(
            f"SELECT {cut_sql('decision_id')} FROM agent_cache WHERE key = ?"
            " AND typeof(time) = 'text' AND typeof(expires_at) = 'text'"
            " AND time <= ? AND expires_at > ?",
            (key, decided_at, decided_at),
        )
        found = uncut(rows[0][0]) if rows else None
        if isinstance(found, str) and ids.is_decision_id(found):
            return {"decision_id": found}
    return None


def load(
    store: Store, decision_id: str, configured: Mapping[str, Any] | set[str]
) -> dict[str, Any]:
    """The ``show`` document of one stored decision id. Call it inside ``store.snapshot()`` with
    the ``resolve`` that found the id, so every read sees one state; an id that is gone anyway is
    not found (exit 10)."""
    rows = store.query(
        f"SELECT {_SHOW_COLUMNS} FROM decisions d WHERE d.id = ?",  # noqa: S608
        (decision_id,),
    )
    if not rows:
        raise NotFoundError("no such decision")
    row = rows[0]
    base = _decision(row, configured)
    checks, keys = _checks(row[19])
    return {
        **base,
        "checks": checks,
        "cache_source": _cache_source(store, keys, base["time"]),
        "outcomes": _outcomes(store, decision_id),
    }
