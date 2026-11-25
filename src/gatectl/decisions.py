"""``gatectl decisions`` and ``gatectl show``: the read-only view of the recorded decisions.

interface.md, Commands. Both read ``state.db`` through a read-only store (nothing is created,
migrated or written; a missing database is an empty history) and print stored text that is
untrusted: ``history.py`` validates and sanitizes it. Every argument is validated before the store
is opened and none is echoed in an error; filters reach SQL only as bound parameters.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from gatectl import history, ids
from gatectl import store as store_mod
from gatectl.clock import format_ts, parse_since
from gatectl.config import LoadedConfig, load_for_command
from gatectl.context import Context, Result
from gatectl.errors import NotFoundError, UsageError
from gatectl.sanitize import sanitize

_LIMIT = re.compile(r"[0-9]{1,4}", re.ASCII)
_FLAG_TEXT_MAX = 256
_LINE_CAP = 1200
_CONFIG_WARNING = "gatectl: warning config_problem: a shared key is invalid, see gatectl validate"


def parse_limit(text: str | None) -> int:
    """``--limit``: an unsigned ASCII integer from 1 to 1000 (default 100)."""
    if text is None:
        return history.DEFAULT_LIMIT
    if _LIMIT.fullmatch(text) is not None and 1 <= int(text) <= history.MAX_LIMIT:
        return int(text)
    raise UsageError("invalid --limit: expected an integer from 1 to 1000")


def _parse_declared(text: str | None) -> tuple[str, str] | None:
    if text is None:
        return None
    key, sep, value = text.partition("=")
    if not sep or not key or len(key) > _FLAG_TEXT_MAX or len(value) > _FLAG_TEXT_MAX:
        raise UsageError("invalid --declared: expected key=value (each at most 256 characters)")
    return key, value


def _parse_object_id(text: str | None) -> str | None:
    if text is not None and len(text) > _FLAG_TEXT_MAX:
        raise UsageError("invalid --object-id: at most 256 characters")
    return text


def _parse_policy(text: str | None) -> str | None:
    if text is not None and not ids.is_policy_name(text):
        raise UsageError("invalid --policy")
    return text


def _filters(ctx: Context) -> history.Filters:
    args = ctx.args
    since = None
    if args.since is not None:
        since = format_ts(parse_since(args.since, datetime.now(UTC)))
    return history.Filters(
        since=since,
        policy=_parse_policy(args.policy),
        scope=args.repo,  # already validated by the dispatcher; ``*`` selects scope ``*``
        object_id=_parse_object_id(args.object_id),
        outcome=args.outcome,
        decision=args.decision,
        declared=_parse_declared(args.declared),
    )


def _warning(ctx: Context, loaded: LoadedConfig) -> str | None:
    return _CONFIG_WARNING if loaded.shared_problems and not ctx.quiet else None


def _line(text: str) -> str:
    return sanitize(text, _LINE_CAP)


def _decision_line(d: dict[str, Any]) -> str:
    parts = [
        d["decision_id"],
        d["time"],
        f"{d['policy']}@{d['scope']}",
        d["decision"],
        d["reason"],
        f"state={d['state']}",
        f"outcome={d['effective_outcome']}",
    ]
    if d["object_id"] is not None:
        parts.append(f"object={d['object_type'] or '-'}:{d['object_id']}")
    if not d["configured"]:
        parts.append("(policy removed)")
    return _line(" ".join(parts))


def handle_decisions(ctx: Context) -> Result:
    limit = parse_limit(ctx.args.limit)
    filters = _filters(ctx)
    loaded = load_for_command(ctx.command, ctx.args, ctx.config)
    store = store_mod.open_store(create=False)
    rows: list[dict[str, Any]] = []
    truncated = False
    if store is None:
        _require_known(loaded, None, filters.policy)
    else:
        with store:
            _require_known(loaded, store, filters.policy)
            rows, truncated = history.list_decisions(store, filters, limit, set(loaded.policies))
    lines = [_decision_line(d) for d in rows] or ["no decisions"]
    if truncated:
        lines.append("(truncated: more decisions match; raise --limit)")
    return Result(
        payload={"decisions": rows, "truncated": truncated},
        text="\n".join(lines),
        stderr=_warning(ctx, loaded),
    )


def _require_known(loaded: LoadedConfig, store: store_mod.Store | None, policy: str | None) -> None:
    """A ``--policy`` that is neither configured nor in ``state.db`` exits 2."""
    if policy is None or policy in loaded.policies:
        return
    if store is not None and store.has_policy(policy):
        return
    raise UsageError("unknown policy", details={"kind": "unknown_policy"})


def _show_text(d: dict[str, Any]) -> str:
    lines = [
        f"{d['decision_id']} {d['policy']}@{d['scope']} {d['decision']} ({d['reason']})"
        + ("" if d["configured"] else " (policy removed)"),
        f"time: {d['time']}",
        f"state: {d['state']} (rev {d['state_rev'] if d['state_rev'] is not None else '-'})",
        f"actor: {d['actor']}",
        f"fingerprint: {d['fingerprint']}",
        f"input_sha256: {d['input_sha256']}",
        f"case_key: {d['case_key'] or '-'}",
        f"tool: {d['tool'] or '-'}  hook: {d['hook'] or '-'}",
        f"object: {d['object_type'] or '-'}:{d['object_id'] or '-'}  repo: {d['repo'] or '-'}",
        f"effective outcome: {d['effective_outcome']}",
    ]
    for key, value in d["declared"].items():
        shown = (
            value
            if isinstance(value, str)
            else json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        )
        lines.append(f"declared {key}: {shown}")
    if d["cache_source"] is not None:
        lines.append(f"cache source: {d['cache_source']['decision_id']}")
    lines.append("checks:")
    for c in d["checks"]:
        extra = f" {c['reason']}" if c["reason"] else ""
        lines.append(f"  {c['name']} {c['type']} {c['verdict']}{extra} {c['duration_ms']}ms")
        if c["detail"]:
            lines.append(f"    {c['detail']}")
    lines.append("outcomes:" if d["outcomes"] else "outcomes: none")
    for o in d["outcomes"]:
        lines.append(f"  {o['time']} {o['outcome']} {o['signal']} {o['actor']}")
        if o["reason"]:
            lines.append(f"    {o['reason']}")
    return "\n".join(_line(line) for line in lines)


def handle_show(ctx: Context) -> Result:
    ref = ids.parse_decision_ref(ctx.args.id)
    loaded = load_for_command(ctx.command, ctx.args, ctx.config)
    store = store_mod.open_store(create=False)
    if store is None:
        raise NotFoundError("no such decision")
    with store, store.snapshot():
        document = history.load(store, history.resolve(store, ref), set(loaded.policies))
    return Result(payload=document, text=_show_text(document), stderr=_warning(ctx, loaded))
