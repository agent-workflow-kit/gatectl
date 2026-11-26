"""``gatectl stats``: track records and recommendations (interface.md, Track records).

A read-only reader of ``state.db``: nothing is created, migrated or written, and a missing database
is no records. Every statement is fixed text with bound values; the decisions are aggregated in SQL
(so a large history is never loaded), and only the aggregates reach Python, where each key is
checked against its grammar. A stored value that does not follow its grammar is refused with the
fixed text ``state.db holds an invalid decision row`` (exit 1), never printed. The effective
outcome is the one SQL expression of ``history`` (``_EFFECTIVE``), so the rule has one home.

A **case** is the decisions of one record (policy, scope, fingerprint) sharing a ``case_key``; a
decision with no ``case_key`` is a case of its own (it can never hide a miss inside another case).
``n`` counts the cases with a resolved ``allow``, ``k`` those with an unsafe miss.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from gatectl import fingerprint as fingerprint_mod
from gatectl import history, ids, stats
from gatectl import store as store_mod
from gatectl.clock import format_ts, parse_since, parse_ts
from gatectl.config import LoadedConfig, load_for_command
from gatectl.context import Context, Result
from gatectl.decisions import _parse_policy, _require_known, _warning
from gatectl.errors import ConfigInvalidError, InternalError, UsageError
from gatectl.sanitize import sanitize
from gatectl.scope import STAR, Scope, resolve_effective
from gatectl.store import Store, cut_sql, uncut

_TAMPERED = "state.db holds an invalid decision row"
_LINE_CAP = 1200
_BOUND_DIGITS = 6
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}")

_FIELDS = (  # the schema's member order (the printed order)
    "decisions",
    "outcomes",
    "unsafe_misses",
    "over_strict_misses",
    "unsafe_miss_cases",
    "signals",
    "actor_kinds",
    "reason_counts",
)

Key = tuple[str, str, str]  # policy, scope, fingerprint

# One decision row follows the grammars this command reads, or it is refused. Each JSON function
# runs only behind its type and size guard (SQLite does not short-circuit AND).
_VALID_ROW = (
    "CASE WHEN (d.case_key IS NULL OR (typeof(d.case_key) = 'text'"
    " AND length(CAST(d.case_key AS BLOB)) = 64 AND d.case_key NOT GLOB '*[^0-9a-f]*'))"
    " AND typeof(d.time) = 'text' AND length(CAST(d.time AS BLOB)) = 27"
    " AND d.time GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]"
    ".[0-9][0-9][0-9][0-9][0-9][0-9]Z'"
    " AND typeof(d.id) = 'text'"
    f" AND (d.checks_json IS NULL OR (typeof(d.checks_json) = 'text'"
    f" AND length(CAST(d.checks_json AS BLOB)) <= {history.CHECKS_MAX_BYTES}"
    " AND instr(CAST(d.checks_json AS BLOB), x'00') = 0))"
    " THEN CASE WHEN d.checks_json IS NULL THEN 1"
    " WHEN NOT json_valid(d.checks_json) THEN 0"
    " WHEN json_type(d.checks_json) <> 'array' THEN 0"
    f" WHEN json_array_length(d.checks_json) > {history.MAX_CHECKS} THEN 0"
    " WHEN EXISTS (SELECT 1 FROM json_each(d.checks_json) j WHERE j.type <> 'object') THEN 0"
    " ELSE 1 END ELSE 0 END"
)
_KEY = ", ".join(cut_sql(f"d.{c}") for c in ("policy", "scope", "fingerprint"))
_CASE_KEY = "CASE WHEN d.case_key IS NULL THEN 'n:' || d.id ELSE 'c:' || d.case_key END"
_RESOLVED = "d.decision = 'allow' AND " + history._EFFECTIVE + " IN ('agree', 'disagree')"
_UNSAFE = "d.decision = 'allow' AND " + history._EFFECTIVE + " = 'disagree'"
_ENTRY_REASON = "json_extract(j.value, '$.reason')"


def _tampered() -> InternalError:
    return InternalError(_TAMPERED)


def _and(where: str, condition: str) -> str:
    return f"{where} AND {condition}" if where else f" WHERE {condition}"


def _count(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise _tampered()
    return value


def _key(raw: Sequence[object]) -> Key:
    policy, scope, fingerprint = (uncut(v) for v in raw[:3])
    if not isinstance(policy, str) or not ids.is_policy_name(policy):
        raise _tampered()
    if not isinstance(scope, str) or not (scope == STAR or ids.is_repo_id(scope)):
        raise _tampered()
    if not isinstance(fingerprint, str) or _FINGERPRINT.fullmatch(fingerprint) is None:
        raise _tampered()
    return policy, scope, fingerprint


def _time(value: object) -> str:
    if not isinstance(value, str):
        raise _tampered()
    try:
        parse_ts(value)
    except ValueError:
        raise _tampered() from None
    return value


def _blank() -> dict[str, Any]:
    return {
        "decisions": {"allow": 0, "deny": 0, "escalate": 0},
        "outcomes": {"pending": 0, "agree": 0, "disagree": 0},
        "unsafe_misses": 0,
        "over_strict_misses": 0,
        "unsafe_miss_cases": 0,
        "signals": {},
        "actor_kinds": {"human": 0, "automatic": 0, "unattributed": 0},
        "reason_counts": [],
        "resolved_decisions": 0,
        "resolved_allows": 0,
    }


def _aggregate(store: Store, filters: history.Filters) -> dict[Key, dict[str, Any]]:
    where, args = history._where(filters)
    found: dict[Key, dict[str, Any]] = {}

    def record(raw: Sequence[object]) -> dict[str, Any]:
        return found.setdefault(_key(raw), _blank())

    with store.snapshot():
        bad = store.query(
            f"SELECT 1 FROM decisions d{_and(where, f'({_VALID_ROW}) = 0')} LIMIT 1",  # noqa: S608
            args,
        )
        if bad:
            raise _tampered()
        by_verdict = store.query(
            f"SELECT {_KEY}, {cut_sql('d.decision')}, {history._EFFECTIVE}, COUNT(*)"  # noqa: S608
            f" FROM decisions d{where} GROUP BY 1, 2, 3, 4, 5",
            args,
        )
        cases = store.query(
            f"SELECT p, s, f, SUM(resolved), SUM(unsafe) FROM ("  # noqa: S608
            f"SELECT {cut_sql('d.policy')} AS p, {cut_sql('d.scope')} AS s,"
            f" {cut_sql('d.fingerprint')} AS f, {_CASE_KEY} AS ck,"
            f" MAX(CASE WHEN {_RESOLVED} THEN 1 ELSE 0 END) AS resolved,"
            f" MAX(CASE WHEN {_UNSAFE} THEN 1 ELSE 0 END) AS unsafe"
            f" FROM decisions d{where} GROUP BY 1, 2, 3, 4) GROUP BY 1, 2, 3",
            args,
        )
        signals = store.query(
            f"SELECT {_KEY}, {cut_sql('o.signal')}, {cut_sql('o.actor_kind')}, COUNT(*)"  # noqa: S608
            f" FROM decisions d JOIN outcomes o ON o.decision_id = d.id{where}"
            " GROUP BY 1, 2, 3, 4, 5",
            args,
        )
        entry_reasons = store.query(
            f"SELECT {_KEY}, {_ENTRY_REASON}, COUNT(*), MAX(d.time)"  # noqa: S608
            f" FROM decisions d, json_each(COALESCE(d.checks_json, '[]')) j{where}"
            " GROUP BY 1, 2, 3, 4",
            args,
        )
        own_reasons = store.query(
            f"SELECT {_KEY}, {cut_sql('d.reason')}, COUNT(*), MAX(d.time) FROM decisions d"  # noqa: S608
            + _and(
                where,
                "NOT EXISTS (SELECT 1 FROM json_each(COALESCE(d.checks_json, '[]')) j"
                f" WHERE {_ENTRY_REASON} IS NOT NULL)",
            )
            + " GROUP BY 1, 2, 3, 4",
            args,
        )
    for row in by_verdict:
        rec = record(row)
        decision, effective, count = uncut(row[3]), row[4], _count(row[5])
        if decision not in history.DECISIONS or effective not in ("pending", *history.OUTCOMES):
            raise _tampered()
        rec["decisions"][decision] += count
        rec["outcomes"][effective] += count
        if effective == "disagree":
            rec["unsafe_misses" if decision == "allow" else "over_strict_misses"] += count
        if decision == "allow" and effective != "pending":
            rec["resolved_decisions"] += count
    for row in cases:
        rec = record(row)
        rec["resolved_allows"], rec["unsafe_miss_cases"] = _count(row[3]), _count(row[4])
    for row in signals:
        rec = record(row)
        signal, kind, count = uncut(row[3]), uncut(row[4]), _count(row[5])
        if (
            not isinstance(signal, str)
            or not ids.is_signal(signal)
            or kind not in history.ACTOR_KINDS
        ):
            raise _tampered()
        rec["signals"][signal] = rec["signals"].get(signal, 0) + count
        rec["actor_kinds"][kind] += count
    seen: dict[tuple[Key, str], list[Any]] = {}
    for row, entry in [(r, True) for r in entry_reasons] + [(r, False) for r in own_reasons]:
        record(row)
        reason = row[3] if entry else uncut(row[3])
        if reason is None:
            continue
        if not isinstance(reason, str) or reason not in history.REASONS:
            raise _tampered()
        slot = seen.setdefault((_key(row), reason), [0, ""])
        slot[0] += _count(row[4])
        slot[1] = max(slot[1], _time(row[5]))
    for (key, reason), (count, last) in sorted(seen.items(), key=lambda i: (i[0][0], i[0][1])):
        found[key]["reason_counts"].append({"reason": reason, "count": count, "last_seen": last})
    for rec in found.values():
        rec["signals"] = dict(sorted(rec["signals"].items()))
    return found


class _Config:
    """What the config says about each (policy, scope): its current fingerprint, ``recommend``."""

    def __init__(self, loaded: LoadedConfig, store: Store) -> None:
        self.loaded = loaded
        self.store = store
        self.cache: dict[tuple[str, str], tuple[str, str, float, float] | None] = {}

    def of(self, policy: str, scope: str) -> tuple[str, str, float, float] | None:
        """(current fingerprint, state, confidence, max_miss_rate), or None when the policy is not
        configured or its definition for the scope cannot be computed."""
        if (policy, scope) in self.cache:
            return self.cache[(policy, scope)]
        found: tuple[str, str, float, float] | None = None
        if policy in self.loaded.policies:
            where = Scope(scope, False, ())
            try:
                effective = resolve_effective(self.loaded, policy, where)
                current = fingerprint_mod.fingerprint_for(self.loaded, policy, where)
            except (ConfigInvalidError, UsageError):
                self.cache[(policy, scope)] = None
                return None
            defaults = self.loaded.shared.defaults.recommend
            spec = effective.policy.recommend
            state = self.store.effective(policy, scope, effective.policy.state).state
            found = (
                current,
                state,
                defaults.confidence if spec.confidence is None else spec.confidence,
                defaults.max_miss_rate if spec.max_miss_rate is None else spec.max_miss_rate,
            )
        self.cache[(policy, scope)] = found
        return found


def build_records(
    store: Store, loaded: LoadedConfig, filters: history.Filters
) -> list[dict[str, Any]]:
    """The records (the ``record`` shape of ``schemas/defs.json``) of the selected decisions,
    ordered by policy, then scope (``*`` first), then fingerprint."""
    found = _aggregate(store, filters)
    config = _Config(loaded, store)
    out: list[dict[str, Any]] = []
    for policy, scope, fingerprint in sorted(found, key=lambda k: (k[0], k[1] != STAR, k[1], k[2])):
        rec = found[(policy, scope, fingerprint)]
        known = config.of(policy, scope)
        current = known is not None and known[0] == fingerprint
        n, k = rec["resolved_allows"], rec["unsafe_miss_cases"]
        confidence = known[2] if known is not None else loaded.shared.defaults.recommend.confidence
        if k > n:
            raise _tampered()
        bound = stats.upper_bound(k, n, confidence)
        recommend = None
        if current and known is not None and filters.since is None:
            recommend = stats.recommendation(known[1], bound, known[3])
        out.append(
            {
                "policy": policy,
                "repo": None if scope == STAR else scope,
                "fingerprint": fingerprint,
                **{k: rec[k] for k in _FIELDS},
                "configured": policy in loaded.policies,
                "current": current,
                "resolved_decisions": rec["resolved_decisions"],
                "resolved_allows": rec["resolved_allows"],
                "upper_bound": round(bound, _BOUND_DIGITS),
                "recommend": recommend,
            }
        )
    return out


def _text(records: list[dict[str, Any]]) -> str:
    if not records:
        return "no records"
    lines: list[str] = []
    for r in records:
        note = ("" if r["configured"] else " (policy removed)") + ("" if r["current"] else " (old)")
        d, o = r["decisions"], r["outcomes"]
        lines += [
            f"{r['policy']}@{r['repo'] or STAR} {r['fingerprint']}{note}",
            f"  decisions: allow {d['allow']} deny {d['deny']} escalate {d['escalate']}",
            f"  outcomes: pending {o['pending']} agree {o['agree']} disagree {o['disagree']}",
            f"  misses: unsafe {r['unsafe_misses']} ({r['unsafe_miss_cases']} cases)"
            f" over-strict {r['over_strict_misses']}",
            f"  cases: {r['resolved_allows']} resolved allows ({r['resolved_decisions']}"
            f" decisions), upper bound {r['upper_bound']}",
            f"  recommend: {r['recommend'] if r['recommend'] is not None else 'none'}",
        ]
        lines += [
            f"  reason {c['reason']}: {c['count']} (last {c['last_seen']})"
            for c in r["reason_counts"]
        ]
    return "\n".join(sanitize(line, _LINE_CAP) for line in lines)


def handle(ctx: Context) -> Result:
    args = ctx.args
    since = None
    if args.since is not None:
        since = format_ts(parse_since(args.since, datetime.now(UTC)))
    filters = history.Filters(since=since, policy=_parse_policy(args.policy), scope=args.repo)
    loaded = load_for_command(ctx.command, args, ctx.config)
    store = store_mod.open_store(create=False)
    records: list[dict[str, Any]] = []
    if store is None:
        _require_known(loaded, None, filters.policy)
    else:
        with store:
            _require_known(loaded, store, filters.policy)
            records = build_records(store, loaded, filters)
    return Result(
        payload={"since": since, "records": records},
        text=_text(records),
        stderr=_warning(ctx, loaded),
    )
