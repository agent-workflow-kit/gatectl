"""The agent result cache (interface.md, Agent checks: Reuse; Input declaration: ignore)."""

from __future__ import annotations

import json
import multiprocessing
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from gatectl import agentcache, store
from gatectl.errors import InternalError

NOW = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)
TTL = timedelta(minutes=10)
FP = "sha256:" + "a" * 64
FP2 = "sha256:" + "b" * 64
IH = "c" * 64
D1 = "gd-aaaaaaaaaaaa"
D2 = "gd-bbbbbbbbbbbb"
REPO = "github.com/org/repo"
OTHER = "github.com/org/other"
VERDICT = agentcache.Verdict("allow", 0.9, ("looks fine",))


@pytest.fixture
def sdir(tmp_path: Path) -> Path:
    return tmp_path / "state" / "gatectl"


@pytest.fixture
def st(sdir: Path) -> Iterator[store.Store]:
    s = store.open_store(sdir, create=True)
    assert s is not None
    yield s
    s.close()


def key(**kw: Any) -> str:
    args: dict[str, Any] = {
        "fingerprint": FP,
        "check_name": "reviewer",
        "scope": REPO,
        "input_hash": IH,
    }
    args.update(kw)
    return agentcache.cache_key(**args)


def put(st: store.Store, k: str | None = None, **kw: Any) -> bool:
    verdict = kw.pop("verdict", VERDICT)
    args: dict[str, Any] = {"decision_id": D1, "now": NOW, "ttl": TTL}
    args.update(kw)
    return agentcache.put(st, k or key(), verdict, **args)


def get(st: store.Store, k: str | None = None, **kw: Any) -> agentcache.CacheHit | None:
    args: dict[str, Any] = {"now": NOW + timedelta(seconds=1), "ttl": TTL}
    args.update(kw)
    return agentcache.get(st, k or key(), **args)


def raw_row(
    st: store.Store,
    k: str,
    *,
    time: Any = "2026-03-04T05:06:07.000000Z",
    expires: Any = "2026-03-04T05:16:07.000000Z",
    artifact: Any = None,
    decision: Any = D1,
) -> None:
    if artifact is None:
        artifact = json.dumps(
            {"schema_version": 1, "decision": "allow", "confidence": 0.9, "reasons": ["ok"]}
        )
    with st.write():
        st.con.execute(
            "INSERT OR REPLACE INTO agent_cache(key, time, expires_at, artifact_json, decision_id)"
            " VALUES (?, ?, ?, ?, ?)",
            (k, time, expires, artifact, decision),
        )


# --- the key --------------------------------------------------------------------------------


def test_the_key_is_64_lowercase_hex_and_stable() -> None:
    k = key()
    assert len(k) == 64 and set(k) <= set("0123456789abcdef")
    assert k == key()


@pytest.mark.parametrize(
    "change",
    [
        {"fingerprint": FP2},
        {"check_name": "other"},
        {"scope": OTHER},
        {"scope": "*"},
        {"input_hash": "d" * 64},
    ],
)
def test_every_component_changes_the_key(change: dict[str, str]) -> None:
    assert key(**change) != key()


def test_the_key_is_not_a_plain_concatenation() -> None:
    # moving a boundary between components must not give the same key
    a = agentcache.cache_key(fingerprint=FP, check_name="ab", scope="github.com/c", input_hash=IH)
    b = agentcache.cache_key(fingerprint=FP, check_name="a", scope="bgithub.com/c", input_hash=IH)
    assert a != b


def test_the_key_binds_to_the_exact_json_shape_not_a_separator() -> None:
    # names allow '-' and '_', scopes allow '/', '.', ':': none of them may merge two fields
    assert key(check_name="a-b", scope="c.d/e") != key(check_name="a", scope="b-c.d/e")
    assert key(check_name="ab", scope="c.d/e") != key(check_name="a", scope="bc.d/e")


@pytest.mark.parametrize(
    "bad",
    [
        {"fingerprint": "sha256:" + "a" * 63},
        {"fingerprint": "sha256:" + "A" * 64},
        {"fingerprint": "a" * 64},
        {"fingerprint": FP + "\n"},
        {"fingerprint": 5},
        {"check_name": ""},
        {"check_name": "Has Space"},
        {"check_name": "a" * 65},
        {"scope": ""},
        {"scope": "no/spaces here"},
        {"scope": None},
        {"input_hash": "c" * 63},
        {"input_hash": "C" * 64},
        {"input_hash": "c" * 64 + "\n"},
        {"input_hash": b"c" * 64},
    ],
)
def test_a_malformed_component_is_refused(bad: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        key(**bad)


def test_input_hash_without_ignored_keys_ignores_only_those_keys() -> None:
    base = {"tool": "x", "ts": "1", "nested": {"ts": "same"}}
    h = agentcache.input_hash_for_key(base, ["ts"])
    assert (
        agentcache.input_hash_for_key({"tool": "x", "ts": "2", "nested": {"ts": "same"}}, ["ts"])
        == h
    )
    assert (
        agentcache.input_hash_for_key({"tool": "y", "ts": "1", "nested": {"ts": "same"}}, ["ts"])
        != h
    )
    # a nested key of the same name is not ignored: only top-level keys are
    assert (
        agentcache.input_hash_for_key({"tool": "x", "ts": "1", "nested": {"ts": "z"}}, ["ts"]) != h
    )


def test_input_hash_with_nothing_ignored_is_the_whole_input_hash() -> None:
    from gatectl.inputhash import input_sha256

    value = {"a": 1, "b": [1, 2]}
    assert agentcache.input_hash_for_key(value, []) == input_sha256(value)


def test_input_hash_ignoring_an_absent_key_is_harmless() -> None:
    assert agentcache.input_hash_for_key({"a": 1}, ["zzz"]) == agentcache.input_hash_for_key(
        {"a": 1}, []
    )


def test_input_hash_does_not_mutate_the_input() -> None:
    value = {"a": 1, "ts": 2}
    agentcache.input_hash_for_key(value, ["ts"])
    assert value == {"a": 1, "ts": 2}


def test_input_hash_distinguishes_key_order_free_but_value_sensitive() -> None:
    assert agentcache.input_hash_for_key({"a": 1, "b": 2}, []) == agentcache.input_hash_for_key(
        {"b": 2, "a": 1}, []
    )
    assert agentcache.input_hash_for_key({"a": 1}, []) != agentcache.input_hash_for_key(
        {"a": "1"}, []
    )
    assert agentcache.input_hash_for_key({"a": 1}, []) != agentcache.input_hash_for_key(
        {"a": True}, []
    )


def test_input_hash_requires_an_object() -> None:
    with pytest.raises(TypeError):
        agentcache.input_hash_for_key([1], [])  # type: ignore[arg-type]


# --- the verdict ----------------------------------------------------------------------------


def test_verdict_validates_its_fields() -> None:
    assert agentcache.Verdict("escalate", 0, ()).confidence == 0
    for args in [
        ("maybe", 0.5, ()),
        ("allow", -0.1, ()),
        ("allow", 1.1, ()),
        ("allow", float("nan"), ()),
        ("allow", float("inf"), ()),
        ("allow", True, ()),
        ("allow", "0.5", ()),
        ("allow", 0.5, ("x",) * 11),
        ("allow", 0.5, ("x" * 501,)),
        ("allow", 0.5, (5,)),
        ("allow", 0.5, "abc"),
        ("allow", 0.5, ["a"]),
    ]:
        with pytest.raises(ValueError):
            agentcache.Verdict(*args)  # type: ignore[arg-type]


def test_verdict_boundaries_are_accepted() -> None:
    agentcache.Verdict("deny", 1, ("x" * 500,) * 10)
    agentcache.Verdict("deny", 0.0, ())


# --- put and get ----------------------------------------------------------------------------


def test_put_then_get_returns_the_verdict_and_its_producer(st: store.Store) -> None:
    assert put(st) is True
    hit = get(st)
    assert hit is not None
    assert hit.verdict == VERDICT
    assert hit.decision_id == D1
    assert hit.time == "2026-03-04T05:06:07.000000Z"
    assert hit.expires_at == "2026-03-04T05:16:07.000000Z"


def test_get_on_a_missing_key_is_none(st: store.Store) -> None:
    assert get(st) is None


def test_a_row_for_another_key_is_never_returned(st: store.Store) -> None:
    put(st)
    for change in (
        {"fingerprint": FP2},
        {"check_name": "other"},
        {"scope": OTHER},
        {"input_hash": "d" * 64},
    ):
        assert get(st, key(**change)) is None


def test_the_row_is_valid_until_expires_at_exclusive(st: store.Store) -> None:
    put(st)
    assert get(st, now=NOW + TTL - timedelta(microseconds=1)) is not None
    assert get(st, now=NOW + TTL) is None
    assert get(st, now=NOW + TTL + timedelta(days=30)) is None


def test_a_row_at_its_own_time_is_valid(st: store.Store) -> None:
    put(st)
    assert get(st, now=NOW) is not None


def test_a_row_dated_in_the_future_is_ignored(st: store.Store) -> None:
    put(st)
    assert get(st, now=NOW - timedelta(microseconds=1)) is None
    assert get(st, now=NOW - timedelta(days=2)) is None  # the clock stepped back


def test_a_future_dated_row_with_far_expiry_is_ignored(st: store.Store) -> None:
    raw_row(st, key(), time="2999-01-01T00:00:00.000000Z", expires="2999-12-31T00:00:00.000000Z")
    assert get(st) is None


def test_ttl_zero_neither_reads_nor_writes(st: store.Store) -> None:
    assert put(st, ttl=timedelta(0)) is False
    assert st.con.execute("SELECT COUNT(*) FROM agent_cache").fetchone() == (0,)
    put(st)
    assert get(st, ttl=timedelta(0)) is None
    assert get(st) is not None


def test_a_negative_ttl_is_also_disabled(st: store.Store) -> None:
    assert put(st, ttl=timedelta(seconds=-5)) is False
    assert st.con.execute("SELECT COUNT(*) FROM agent_cache").fetchone() == (0,)


def test_a_ttl_that_overflows_the_calendar_writes_nothing(st: store.Store) -> None:
    assert put(st, ttl=timedelta(days=3_000_000)) is False
    assert st.con.execute("SELECT COUNT(*) FROM agent_cache").fetchone() == (0,)


def test_the_row_carries_its_own_expiry_so_a_shorter_later_ttl_still_honours_it(
    st: store.Store,
) -> None:
    put(st, ttl=timedelta(hours=1))
    assert get(st, now=NOW + timedelta(minutes=30), ttl=timedelta(minutes=1)) is not None


def test_put_replaces_the_row_and_the_producer(st: store.Store) -> None:
    put(st, decision_id=D1)
    later = NOW + timedelta(minutes=2)
    assert put(st, decision_id=D2, now=later, verdict=agentcache.Verdict("deny", 0.7, ("no",)))
    hit = get(st, now=later)
    assert hit is not None
    assert (hit.decision_id, hit.verdict.decision) == (D2, "deny")
    assert st.con.execute("SELECT COUNT(*) FROM agent_cache").fetchone() == (1,)


def test_put_stores_no_nonce_and_only_the_validated_fields(st: store.Store) -> None:
    put(st)
    text = st.con.execute("SELECT artifact_json FROM agent_cache").fetchone()[0]
    assert json.loads(text) == {
        "schema_version": 1,
        "decision": "allow",
        "confidence": 0.9,
        "reasons": ["looks fine"],
    }


def test_reasons_are_sanitized_when_stored_and_when_read(st: store.Store) -> None:
    v = agentcache.Verdict("allow", 0.9, ("a\x00b‮c\ud800d\x7fe\n",))
    put(st, verdict=v)
    stored = json.loads(st.con.execute("SELECT artifact_json FROM agent_cache").fetchone()[0])
    assert stored["reasons"] == ["a�b�c�d�e�"]
    hit = get(st)
    assert hit is not None and hit.verdict.reasons == tuple(stored["reasons"])


def test_reasons_can_quote_input_but_stay_inside_the_caps(st: store.Store) -> None:
    quoted = tuple("x" * 500 for _ in range(10))
    put(st, verdict=agentcache.Verdict("allow", 1, quoted))
    hit = get(st)
    assert hit is not None and hit.verdict.reasons == quoted


def test_the_decision_id_must_be_a_decision_id(st: store.Store) -> None:
    for bad in (None, "", "gd-AAAAAAAAAAAA", "x", "gd-aaaaaaaaaaaa\n", 5):
        with pytest.raises(ValueError):
            put(st, decision_id=bad)


def test_put_needs_a_writable_store(sdir: Path, st: store.Store) -> None:
    reader = store.open_store(sdir, create=False)
    assert reader is not None
    with reader, pytest.raises(RuntimeError):
        put(reader)


def test_get_works_on_a_read_only_store(sdir: Path, st: store.Store) -> None:
    put(st)
    reader = store.open_store(sdir, create=False)
    assert reader is not None
    with reader:
        assert get(reader) is not None


def test_put_drops_expired_rows_and_bounds_the_table(st: store.Store) -> None:
    raw_row(st, "e" * 64, expires="2000-01-01T00:00:00.000000Z", time="1999-12-31T23:50:00.000000Z")
    put(st)
    keys = [r[0] for r in st.con.execute("SELECT key FROM agent_cache")]
    assert "e" * 64 not in keys
    assert key() in keys


def test_the_table_is_capped(st: store.Store, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agentcache, "MAX_ROWS", 5)
    for i in range(12):
        put(st, key(input_hash=f"{i:064x}"), now=NOW + timedelta(seconds=i))
    assert st.con.execute("SELECT COUNT(*) FROM agent_cache").fetchone() == (5,)
    # the newest survive
    assert get(st, key(input_hash=f"{11:064x}"), now=NOW + timedelta(seconds=12)) is not None
    assert get(st, key(input_hash=f"{0:064x}"), now=NOW + timedelta(seconds=12)) is None


# --- tampered rows --------------------------------------------------------------------------


def good(**over: Any) -> str:
    base: dict[str, Any] = {
        "schema_version": 1,
        "decision": "allow",
        "confidence": 0.9,
        "reasons": ["ok"],
    }
    base.update(over)
    return json.dumps(base)


@pytest.mark.parametrize(
    "artifact",
    [
        "not json",
        "[]",
        "null",
        "{}",
        good(decision="maybe"),
        good(decision=None),
        good(confidence=2),
        good(confidence=-1),
        good(confidence=True),
        good(confidence="0.9"),
        good(reasons="ok"),
        good(reasons=[1]),
        good(reasons=["x"] * 11),
        good(reasons=["x" * 501]),
        good(schema_version=2),
        good(schema_version=True),
        good(schema_version="1"),
        good(extra=1),
        '{"schema_version":1,"decision":"allow","decision":"deny","confidence":1,"reasons":[]}',
        '{"schema_version":1,"decision":"allow","confidence":NaN,"reasons":[]}',
        '{"schema_version":1,"decision":"allow","confidence":1e999,"reasons":[]}',
        "x" * 40000,
        " " * 40000 + good(),
        b"\xff\xfe" + good().encode(),
        5,
    ],
)
def test_a_tampered_artifact_is_a_fixed_text_error_never_a_verdict(
    st: store.Store, artifact: Any
) -> None:
    raw_row(st, key(), artifact=artifact)
    with pytest.raises(InternalError) as info:
        get(st)
    assert "CANARY" not in str(info.value)
    assert str(info.value) == "state.db holds an invalid agent cache row"


def test_a_tampered_artifact_text_is_never_echoed(st: store.Store) -> None:
    raw_row(st, key(), artifact="CANARY-7f3a9c not json")
    with pytest.raises(InternalError) as info:
        get(st)
    assert "CANARY" not in str(info.value) and "CANARY" not in repr(info.value)


@pytest.mark.parametrize(
    "fields",
    [
        {"time": "yesterday"},
        {"time": 5},
        {"expires": "tomorrow"},
        {"expires": None},
        {"time": "2026-03-04T05:06:07Z"},  # not the fixed-width form
        {"decision": "not-an-id"},
        {"decision": 7},
        {"time": "2026-03-04T05:06:07.000000Z\n"},
    ],
)
def test_tampered_times_or_producer_are_a_fixed_text_error(
    st: store.Store, fields: dict[str, Any]
) -> None:
    if fields.get("expires", 1) is None:
        pytest.skip("expires_at is NOT NULL")
    raw_row(st, key(), **fields)
    with pytest.raises(InternalError) as info:
        get(st)
    assert str(info.value) == "state.db holds an invalid agent cache row"


def test_a_null_producer_is_accepted_as_no_producer(st: store.Store) -> None:
    raw_row(st, key(), decision=None)
    hit = get(st)
    assert hit is not None and hit.decision_id is None


def test_a_tampered_row_that_is_expired_or_future_is_ignored_not_an_error(
    st: store.Store,
) -> None:
    raw_row(
        st,
        key(),
        artifact="garbage",
        expires="2000-01-01T00:00:00.000000Z",
        time="1999-01-01T00:00:00.000000Z",
    )
    assert get(st) is None
    raw_row(
        st,
        key(),
        artifact="garbage",
        time="2999-01-01T00:00:00.000000Z",
        expires="2999-01-02T00:00:00.000000Z",
    )
    assert get(st) is None


def test_put_overwrites_a_tampered_row(st: store.Store) -> None:
    raw_row(st, key(), artifact="garbage")
    assert put(st) is True
    assert get(st) is not None


def test_get_refuses_a_malformed_key_without_touching_the_database(st: store.Store) -> None:
    for bad in ("", "x", "A" * 64, "a" * 63, "a" * 64 + "\n", "' OR 1=1 --"):
        with pytest.raises(ValueError):
            agentcache.get(st, bad, now=NOW, ttl=TTL)


def test_a_key_that_looks_like_sql_cannot_reach_a_row(st: store.Store) -> None:
    put(st)
    with pytest.raises(ValueError):
        agentcache.get(st, "%" * 64, now=NOW, ttl=TTL)


# --- a hit needs no slot --------------------------------------------------------------------


def test_get_and_put_never_touch_the_slot_table(st: store.Store) -> None:
    put(st)
    get(st)
    assert st.con.execute("SELECT COUNT(*) FROM agent_slots").fetchone() == (0,)


# --- two writers ----------------------------------------------------------------------------


def _writer(directory: str, index: int, out: Any) -> None:
    s = store.open_store(Path(directory), create=True, busy_timeout=20.0)
    assert s is not None
    verdict = agentcache.Verdict("allow", 0.9, (f"writer {index}",))
    ok = 0
    for _ in range(15):
        ok += agentcache.put(
            s,
            key(),
            verdict,
            decision_id="gd-" + "abcdefgh"[index] * 12,
            now=datetime.now(UTC),
            ttl=TTL,
        )
        hit = agentcache.get(s, key(), now=datetime.now(UTC) + timedelta(seconds=1), ttl=TTL)
        assert hit is not None and hit.verdict.decision == "allow"
    s.close()
    out.put(ok)


def test_racing_writers_of_one_key_leave_exactly_one_valid_row(sdir: Path, st: store.Store) -> None:
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    procs = [ctx.Process(target=_writer, args=(str(sdir), i, out)) for i in range(4)]
    try:
        for p in procs:
            p.start()
        results = [out.get(timeout=120) for _ in procs]
        for p in procs:
            p.join(30)
    finally:
        for p in procs:
            if p.is_alive():
                p.terminate()
            p.join(10)
    assert [p.exitcode for p in procs] == [0] * 4
    assert results == [15] * 4
    assert st.con.execute("SELECT COUNT(*) FROM agent_cache").fetchone() == (1,)
    hit = get(st, now=datetime.now(UTC) + timedelta(seconds=1))
    assert hit is not None
    assert hit.verdict.reasons[0].startswith("writer ")
