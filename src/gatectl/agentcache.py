"""The agent result cache in ``state.db`` (interface.md, Agent checks: Reuse; Input declaration).

**Key.** SHA-256 of the canonical JSON array
``["gatectl-agent-cache-v1", fingerprint, check_name, scope, input_hash]``. The fingerprint
already covers everything that can change a verdict except the input (the policy name,
``input``, every check with its resolved skill, model, threshold, profile, sandbox and the
hashes of the instruction, profile, ``SKILL.md`` and ``plugin.json``); the other three parts are
the check name, the scope and the hash of the input without the policy's ``input.ignore`` keys.
JSON strings are quoted and escaped, so no choice of component text can move a boundary or
spell another key; each component is also checked against its grammar first.

**Rows.** ``agent_cache(key, time, expires_at, artifact_json, decision_id)``: ``time`` is the
write time, ``expires_at`` is ``time`` plus the effective ``cache_ttl``, ``decision_id`` is the
decision that produced the row (``show`` reads it as ``cache_source``; a refreshed key loses
its earlier producer). A row counts only while ``time <= now < expires_at``: a row dated in the
future (the clock stepped back) or past its expiry is ignored, and expiry is judged at read time.
A ``cache_ttl`` of 0 (or less) neither reads nor writes.

**Trust.** Only the validated artifact fields are stored (never the nonce): ``decision``,
``confidence`` and ``reasons``. Everything read back is validated again, strictly, before it is
used; a row that is in force but malformed raises a fixed-text ``InternalError`` (exit 1), never
a verdict, and never echoes what it holds. ``reasons`` can quote input: they are sanitized and
capped when stored and when read.

Whether a result may be cached (a valid artifact of a ``done`` run only), ``--no-cache`` and the
reuse sequence are the engine's (``engine._agent_entry``, ``engine._write_cache``); this module
stores what it is given.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from gatectl import clock, ids
from gatectl.errors import InternalError
from gatectl.inputhash import input_sha256
from gatectl.sanitize import sanitize
from gatectl.store import Store

KEY_VERSION = "gatectl-agent-cache-v1"
MAX_ROWS = 5000
MAX_ARTIFACT_BYTES = 32768  # 10 reasons of 500 four-byte characters fit with room to spare
MAX_REASONS = 10
MAX_REASON_CHARS = 500
DECISIONS = ("allow", "deny", "escalate")
_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}", re.ASCII)
_HASH = re.compile(r"[0-9a-f]{64}", re.ASCII)
_BAD_ROW = "state.db holds an invalid agent cache row"
_SELECT = (
    "SELECT CASE WHEN typeof(time) = 'text' THEN 'T' || hex(substr(CAST(time AS BLOB), 1, 64))"
    " ELSE NULL END,"
    " CASE WHEN typeof(expires_at) = 'text'"
    " THEN 'T' || hex(substr(CAST(expires_at AS BLOB), 1, 64)) ELSE NULL END,"
    " CASE WHEN typeof(artifact_json) = 'text'"
    f" THEN 'T' || hex(substr(CAST(artifact_json AS BLOB), 1, {MAX_ARTIFACT_BYTES + 1}))"
    " ELSE NULL END,"
    " CASE WHEN decision_id IS NULL THEN 'N' WHEN typeof(decision_id) = 'text'"
    " THEN 'T' || hex(substr(CAST(decision_id AS BLOB), 1, 64)) ELSE 'X' END"
    " FROM agent_cache WHERE key = ?"
)


def _confidence_ok(conf: object) -> bool:
    """An int or float in [0, 1]. An int is range-checked as an int: ``math.isfinite`` would
    convert it to a float first, which raises ``OverflowError`` for a huge one."""
    if isinstance(conf, bool):
        return False
    if isinstance(conf, int):
        return 0 <= conf <= 1
    if isinstance(conf, float):
        return math.isfinite(conf) and 0 <= conf <= 1
    return False


@dataclass(frozen=True)
class Verdict:
    """The validated artifact fields that are cached. Construction validates strictly."""

    decision: str
    confidence: float
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        conf = self.confidence
        if not (
            isinstance(self.decision, str)
            and self.decision in DECISIONS
            and _confidence_ok(conf)
            and isinstance(self.reasons, tuple)
            and len(self.reasons) <= MAX_REASONS
            and all(isinstance(r, str) and len(r) <= MAX_REASON_CHARS for r in self.reasons)
        ):
            raise ValueError("not a valid verdict")


@dataclass(frozen=True)
class CacheHit:
    verdict: Verdict
    decision_id: str | None
    time: str
    expires_at: str


def _full(pattern: re.Pattern[str], value: object) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def cache_key(*, fingerprint: str, check_name: str, scope: str, input_hash: str) -> str:
    """The cache key (see the module text). ``ValueError`` for a component out of its grammar."""
    if not _full(_FINGERPRINT, fingerprint):
        raise ValueError("fingerprint must be sha256: and 64 lowercase hex characters")
    if not isinstance(check_name, str) or not ids.is_check_name(check_name):
        raise ValueError("check_name is not a check name")
    if not isinstance(scope, str) or not (scope == "*" or ids.is_repo_id(scope)):
        raise ValueError("scope must be * or a repo id")
    if not _full(_HASH, input_hash):
        raise ValueError("input_hash must be 64 lowercase hex characters")
    text = json.dumps(
        [KEY_VERSION, fingerprint, check_name, scope, input_hash],
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def input_hash_for_key(parsed: Mapping[str, Any], ignore: Sequence[str]) -> str:
    """``input_sha256`` of the input with the policy's ``input.ignore`` top-level keys removed.
    Nested keys of the same name are kept: only top-level keys are volatile fields."""
    if not isinstance(parsed, Mapping):
        raise TypeError("the input must be an object")
    skip = set(ignore)
    return input_sha256({k: v for k, v in parsed.items() if k not in skip})


def _check_key(key: object) -> str:
    if not _full(_HASH, key):
        raise ValueError("not a cache key")
    return key  # type: ignore[return-value]


def _bad() -> InternalError:
    return InternalError(_BAD_ROW)


def _no_dups(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key")
        out[k] = v
    return out


def _no_constant(_: str) -> Any:
    raise ValueError("not JSON")


def _decode(value: object, limit: int | None = None) -> str | None:
    if not (isinstance(value, str) and value.startswith("T")):
        return None
    try:
        raw = bytes.fromhex(value[1:])
        if limit is not None and len(raw) > limit:
            return None
        return raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _parse_artifact(text: str) -> Verdict:
    try:
        doc = json.loads(text, object_pairs_hook=_no_dups, parse_constant=_no_constant)
    except (ValueError, RecursionError):
        raise _bad() from None
    if not (
        isinstance(doc, dict)
        and set(doc) == {"schema_version", "decision", "confidence", "reasons"}
        and type(doc["schema_version"]) is int
        and doc["schema_version"] == 1
        and isinstance(doc["reasons"], list)
        and all(isinstance(r, str) and len(r) <= MAX_REASON_CHARS for r in doc["reasons"])
    ):
        raise _bad()
    try:
        return Verdict(
            doc["decision"],
            doc["confidence"],
            tuple(
                sanitize(r, MAX_REASON_CHARS) if isinstance(r, str) else r for r in doc["reasons"]
            ),
        )
    except (ValueError, TypeError, OverflowError):
        raise _bad() from None


def get(store: Store, key: str, *, now: datetime, ttl: timedelta) -> CacheHit | None:
    """The cached verdict for ``key`` that is in force at ``now``, else ``None``.

    ``ttl`` is the effective ``cache_ttl``: zero (or less) disables the read. Works on a
    read-only store.
    """
    _check_key(key)
    if ttl <= timedelta(0):
        return None
    now_ts = clock.format_ts(now)
    rows = store.query(_SELECT, (key,))
    if not rows:
        return None
    raw_time, raw_expires, raw_artifact, raw_decision = rows[0]
    time_s = _decode(raw_time)
    expires_s = _decode(raw_expires)
    if time_s is None or expires_s is None:
        raise _bad()
    try:
        clock.parse_ts(time_s)
        clock.parse_ts(expires_s)
    except ValueError:
        raise _bad() from None
    if time_s > now_ts or expires_s <= now_ts:
        return None  # in the future (clock stepped back), or expired: ignored, not an error
    decision_id: str | None
    if raw_decision == "N":
        decision_id = None
    else:
        decision_id = _decode(raw_decision, 64)
        if decision_id is None or not ids.is_decision_id(decision_id):
            raise _bad()
    text = _decode(raw_artifact, MAX_ARTIFACT_BYTES)
    if text is None:
        raise _bad()
    return CacheHit(_parse_artifact(text), decision_id, time_s, expires_s)


def put(
    store: Store,
    key: str,
    verdict: Verdict,
    *,
    decision_id: str,
    now: datetime,
    ttl: timedelta,
) -> bool:
    """Store (or refresh) the verdict under ``key``; returns False when nothing was written
    (``ttl`` zero or less, or an expiry that does not fit the timestamp form). ``now`` must be
    aware: a naive one is a ``ValueError``, as in ``get``.

    One transaction: the row is replaced (so the producer is the latest writer), rows past their
    expiry are dropped, and the table is cut to ``MAX_ROWS`` newest rows.
    """
    _check_key(key)
    if not isinstance(verdict, Verdict):
        raise ValueError("verdict must be a Verdict")
    if not isinstance(decision_id, str) or not ids.is_decision_id(decision_id):
        raise ValueError("decision_id must be a gd- decision id")
    if ttl <= timedelta(0):
        return False
    now_ts = clock.format_ts(now)  # ValueError for a naive ``now``, as in ``get``
    try:
        expires_ts = clock.format_ts(now + ttl)
    except (OverflowError, ValueError):
        return False
    artifact = json.dumps(
        {
            "schema_version": 1,
            "decision": verdict.decision,
            "confidence": verdict.confidence,
            "reasons": [sanitize(r, MAX_REASON_CHARS) for r in verdict.reasons],
        },
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )

    def body() -> bool:
        store.execute(
            "INSERT OR REPLACE INTO agent_cache(key, time, expires_at, artifact_json, decision_id)"
            " VALUES (?, ?, ?, ?, ?)",
            (key, now_ts, expires_ts, artifact, decision_id),
        )
        store.execute("DELETE FROM agent_cache WHERE expires_at <= ? AND key <> ?", (now_ts, key))
        # the row just written is never evicted; rows dated after ``now`` (the clock stepped
        # back) go first, then the oldest
        store.execute(
            "DELETE FROM agent_cache WHERE key IN (SELECT key FROM agent_cache WHERE key <> ?"
            " ORDER BY (time > ?) DESC, time ASC, key ASC"
            " LIMIT max(0, (SELECT COUNT(*) FROM agent_cache) - ?))",
            (key, now_ts, MAX_ROWS),
        )
        return True

    return store.transact(body)
