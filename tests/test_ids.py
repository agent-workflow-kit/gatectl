"""Identifier grammars, decision ids, actors, durations (interface.md, Identifiers)."""

from __future__ import annotations

import re
from datetime import timedelta

import pytest

from gatectl import ids
from gatectl.errors import AmbiguousError, NotFoundError, UsageError


def test_error_exit_codes() -> None:
    assert UsageError.exit_code == 2
    assert NotFoundError.exit_code == 10
    assert AmbiguousError.exit_code == 21


@pytest.mark.parametrize("checker", [ids.is_policy_name, ids.is_check_name])
class TestNames:
    def test_valid(self, checker) -> None:
        for ok in ["a", "0", "a-b_c", "a" * 64, "9x"]:
            assert checker(ok), ok

    def test_invalid(self, checker) -> None:
        for bad in ["", "A", "-a", "_a", "a" * 65, "a b", "a.b", "é", "a\n", "a/b", "\n"]:
            assert not checker(bad), repr(bad)

    def test_non_str_is_invalid(self, checker) -> None:
        assert not checker(None)  # type: ignore[arg-type]
        assert not checker(b"a")  # type: ignore[arg-type]


def test_signal() -> None:
    for ok in ["human", "auto", "a", "a" * 32, "a-b_c9"]:
        assert ids.is_signal(ok), ok
    for bad in ["", "1a", "A", "-a", "a" * 33, "a.b", "a\n", "é"]:
        assert not ids.is_signal(bad), repr(bad)


def test_caller_decision_id() -> None:
    for ok in ["a", "A.b_c:d@e/f-g", "x" * 128, "gd-abcdef"]:
        assert ids.is_caller_decision_id(ok), ok
    for bad in ["", "x" * 129, "a b", "a\n", "a%", "é", "a;b", "a\x00"]:
        assert not ids.is_caller_decision_id(bad), repr(bad)


class TestCallerDecisionIds:
    def test_up_to_sixteen(self) -> None:
        values = [f"id{i}" for i in range(16)]
        assert ids.validate_caller_decision_ids(values) == tuple(values)
        assert ids.validate_caller_decision_ids([]) == ()

    def test_seventeen_is_usage_error(self) -> None:
        with pytest.raises(UsageError):
            ids.validate_caller_decision_ids([f"id{i}" for i in range(17)])

    def test_bad_value_is_usage_error_without_echo(self) -> None:
        with pytest.raises(UsageError) as exc:
            ids.validate_caller_decision_ids(["ok", "bad value\x1b"])
        assert "bad value" not in str(exc.value)
        assert "\x1b" not in str(exc.value)


class TestRepoId:
    @pytest.mark.parametrize(
        "ok",
        [
            "github.com/org/repo",
            "git.example.com:8443/group/sub/repo.git",
            "localhost/a",
            "a/b",
            "github.com/Org/Repo_1.x-y",
            "h-1.example.com/p",
            "github.com/" + "a" * 244,
        ],
    )
    def test_valid(self, ok: str) -> None:
        assert ids.is_repo_id(ok)

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "github.com",
            "github.com/",
            "GitHub.com/org/repo",
            "github.com/org/../repo",
            "github.com/./repo",
            "github.com/org/..",
            "github.com//repo",
            "github.com/org/repo/",
            "github.com/org/repo\n",
            "github.com/org/re po",
            "github.com/org/répo",
            "-a.com/x",
            "a-.com/x",
            "host:/x",
            "host:123456/x",
            "host:1a/x",
            "github.com/" + "a" * 245,
            "*",
            "http://github.com/o/r",
            "github.com/org/repo\x00",
            "github.com/٠",
        ],
    )
    def test_invalid(self, bad: str) -> None:
        assert not ids.is_repo_id(bad)

    def test_exactly_255_valid_and_256_not(self) -> None:
        base = "h/"
        assert ids.is_repo_id(base + "a" * 253)
        assert not ids.is_repo_id(base + "a" * 254)

    def test_dotted_segments_that_are_not_dots_allowed(self) -> None:
        assert ids.is_repo_id("h/...")
        assert ids.is_repo_id("h/.a")

    def test_non_str(self) -> None:
        # Deliberately wrong type: the predicate must answer False, not raise, for non-strings.
        assert not ids.is_repo_id(None)  # type: ignore[arg-type]


class TestDecisionIdGeneration:
    def test_shape(self) -> None:
        for _ in range(50):
            assert re.fullmatch(r"gd-[a-z2-7]{12}", ids.new_decision_id())

    def test_satisfies_caller_grammar(self) -> None:
        assert ids.is_caller_decision_id(ids.new_decision_id())

    def test_is_random(self) -> None:
        assert len({ids.new_decision_id() for _ in range(100)}) == 100

    def test_deterministic_with_injected_bytes(self) -> None:
        assert ids.new_decision_id(lambda n: b"\x00" * n) == "gd-aaaaaaaaaaaa"
        assert ids.new_decision_id(lambda n: b"\xff" * n) == "gd-777777777777"

    def test_short_random_source_rejected(self) -> None:
        with pytest.raises(ValueError, match="random"):
            ids.new_decision_id(lambda n: b"\x00")

    def test_is_decision_id(self) -> None:
        assert ids.is_decision_id("gd-abcdefghij1l") is False
        assert ids.is_decision_id("gd-abcdefghijkm") is True
        assert not ids.is_decision_id("gd-abcdefghijk")
        assert not ids.is_decision_id("gd-ABCDEFGHIJKM")
        assert not ids.is_decision_id("gd-abcdefghijkm\n")
        assert not ids.is_decision_id("abcdefghijkm")


class TestDecisionRefParsing:
    def test_full_id(self) -> None:
        ref = ids.parse_decision_ref("gd-abcdefghijkm")
        assert ref.prefix == "abcdefghijkm"
        assert ref.is_full
        assert ref.full_id == "gd-abcdefghijkm"

    def test_unique_prefix_with_and_without_gd(self) -> None:
        for text in ["gd-abcdef", "abcdef"]:
            ref = ids.parse_decision_ref(text)
            assert ref.prefix == "abcdef"
            assert not ref.is_full
            assert ref.full_id is None

    def test_longer_prefix(self) -> None:
        assert ids.parse_decision_ref("gd-abcdefg").prefix == "abcdefg"

    @pytest.mark.parametrize("bad", ["gd-abcde", "abcde", "gd-", "", "gd-a", "gd-gd-"])
    def test_short_prefix_is_usage_error(self, bad: str) -> None:
        with pytest.raises(UsageError):
            ids.parse_decision_ref(bad)

    @pytest.mark.parametrize(
        "bad",
        [
            "gd-abc%ef",
            "gd-abc_ef",
            "gd-abcde%",
            "%%%%%%",
            "gd-abcde1",  # 1 is not base32
            "gd-abcde8",
            "gd-abcdE7",
            "gd-abcdef\n",
            "gd-abc def",
            "gd-gd-abcdef",  # the gd- is stripped once only
            "GD-abcdef",
            "gd-abcdefghijklm",  # 13 characters
            "gd-abcdé!",
            "gd-abcdef\x00",
            "gd-abc*ef",
        ],
    )
    def test_non_base32_or_too_long_is_usage_error(self, bad: str) -> None:
        with pytest.raises(UsageError):
            ids.parse_decision_ref(bad)

    def test_error_does_not_echo_input(self) -> None:
        with pytest.raises(UsageError) as exc:
            ids.parse_decision_ref("gd-%\x1b[31m")
        assert "\x1b" not in str(exc.value)
        assert "%" not in str(exc.value)

    def test_resolve_unique_prefix(self) -> None:
        known = ["gd-aaaaaaaaaaaa", "gd-bbbbbbbbbbbb"]
        assert ids.resolve_decision_ref(ids.parse_decision_ref("gd-aaaaaa"), known) == known[0]

    def test_resolve_full_id(self) -> None:
        known = ["gd-aaaaaaaaaaaa", "gd-aaaaaabbbbbb"]
        ref = ids.parse_decision_ref("gd-aaaaaaaaaaaa")
        assert ids.resolve_decision_ref(ref, known) == "gd-aaaaaaaaaaaa"

    def test_resolve_ambiguous_exits_21(self) -> None:
        known = ["gd-aaaaaaaaaaaa", "gd-aaaaaabbbbbb"]
        with pytest.raises(AmbiguousError):
            ids.resolve_decision_ref(ids.parse_decision_ref("gd-aaaaaa"), known)

    def test_resolve_unknown_exits_10(self) -> None:
        with pytest.raises(NotFoundError):
            ids.resolve_decision_ref(ids.parse_decision_ref("gd-cccccc"), ["gd-aaaaaaaaaaaa"])

    def test_resolve_ignores_non_decision_candidates(self) -> None:
        with pytest.raises(NotFoundError):
            ids.resolve_decision_ref(ids.parse_decision_ref("gd-aaaaaa"), ["gd-aaaaaa"])


class TestActor:
    def test_valid_explicit(self) -> None:
        for text, kind, name in [
            ("human:alice", "human", "alice"),
            ("auto:ci.bot", "auto", "ci.bot"),
            ("human:A.b_c@d-e", "human", "A.b_c@d-e"),
            ("auto:" + "a" * 64, "auto", "a" * 64),
        ]:
            actor = ids.parse_actor(text)
            assert (actor.kind, actor.name) == (kind, name)
            assert str(actor) == text

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "human",
            "human:",
            "alice",
            "robot:x",
            "Human:x",
            "human:" + "a" * 65,
            "human:a b",
            "human:a\n",
            "human:é",
            "auto:a:b",
            "human: ",
            "human:a/b",
        ],
    )
    def test_invalid_explicit_is_usage_error(self, bad: str) -> None:
        with pytest.raises(UsageError):
            ids.parse_actor(bad)

    def test_name_charset_replacement(self) -> None:
        assert ids.actor_name("jo smith") == "jo_smith"
        assert ids.actor_name("jö/x\n") == "j__x_"
        assert ids.actor_name("ok.name@host-1_x") == "ok.name@host-1_x"

    def test_name_cut_to_64(self) -> None:
        assert ids.actor_name("a" * 100) == "a" * 64
        assert ids.actor_name("é" * 100) == "_" * 64

    def test_empty_name_becomes_user(self) -> None:
        assert ids.actor_name("") == "user"
        assert ids.actor_name(None) == "user"

    def test_default_actor_with_tty_is_human(self) -> None:
        r = ids.resolve_actor(None, stdin_tty=True, name="jo smith")
        assert str(r.actor) == "human:jo_smith"
        assert r.source == "default"
        assert r.is_human

    def test_default_actor_without_tty_is_auto_unknown(self) -> None:
        r = ids.resolve_actor(None, stdin_tty=False, name="jo")
        assert str(r.actor) == "auto:unknown"
        assert r.source == "default"
        assert not r.is_human

    def test_default_tty_empty_name(self) -> None:
        r = ids.resolve_actor(None, stdin_tty=True, name="")
        assert str(r.actor) == "human:user"

    def test_explicit_human_is_human_without_tty(self) -> None:
        r = ids.resolve_actor("human:alice", stdin_tty=False, name="x")
        assert r.is_human
        assert r.source == "flag"

    def test_explicit_auto_is_not_human_even_with_tty(self) -> None:
        r = ids.resolve_actor("auto:bot", stdin_tty=True, name="x")
        assert not r.is_human
        assert r.source == "flag"

    def test_explicit_invalid_is_usage_error(self) -> None:
        with pytest.raises(UsageError):
            ids.resolve_actor("human:", stdin_tty=True, name="x")

    def test_default_is_a_valid_actor(self) -> None:
        for tty in (True, False):
            for name in ["", "a b", "é" * 80, "x" * 80]:
                r = ids.resolve_actor(None, stdin_tty=tty, name=name)
                assert ids.parse_actor(str(r.actor)) == r.actor


class TestActorName:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("ann", "ann"),
            ("a.b_c@d-e", "a.b_c@d-e"),
            ("a b", "a_b"),
            ("Dr Who\n", "Dr_Who_"),
            ("a\x1b[31mb", "a__31mb"),
            ("a\u202eb\u2066c", "a_b_c"),
            ("a\x00b", "a_b"),
            ("\u00e9", "_"),
            ("x" * 200, "x" * 64),
            ("\u00e9" * 200, "_" * 64),
            ("", "user"),
            (None, "user"),
            ("   ", "___"),
        ],
    )
    def test_sanitizes(self, raw: str | None, expected: str) -> None:
        assert ids.actor_name(raw) == expected

    @pytest.mark.parametrize("raw", [5, 1.5, True, ["a"], {"a": 1}, b"x"])
    def test_a_non_string_becomes_user(self, raw: object) -> None:
        assert ids.actor_name(raw) == "user"  # type: ignore[arg-type]

    def test_every_result_is_a_valid_actor_name(self) -> None:
        for raw in ["", "\n", "x" * 5000, "\x1b]0;t\x07", "\u202e", "a\x00"]:
            assert ids.parse_actor(f"human:{ids.actor_name(raw)}").name == ids.actor_name(raw)


class TestDuration:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("0", timedelta(0)),
            ("500ms", timedelta(milliseconds=500)),
            ("20s", timedelta(seconds=20)),
            ("10m", timedelta(minutes=10)),
            ("2h", timedelta(hours=2)),
            ("7d", timedelta(days=7)),
            ("0s", timedelta(0)),
            ("007s", timedelta(seconds=7)),
        ],
    )
    def test_valid(self, text: str, expected: timedelta) -> None:
        assert ids.parse_duration(text) == expected

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "s",
            "10",
            "10x",
            "1.5s",
            "-1s",
            "+1s",
            " 1s",
            "1s ",
            "1s\n",
            "1 s",
            "1S",
            "1w",
            "1h30m",
            "١s",  # Arabic-Indic digit one
            "1" * 30 + "s",
            "99999999999999d",
            "00",
            "0d0",
        ],
    )
    def test_invalid(self, bad: str) -> None:
        with pytest.raises(UsageError):
            ids.parse_duration(bad)

    def test_non_str(self) -> None:
        with pytest.raises(UsageError):
            ids.parse_duration(None)  # type: ignore[arg-type]


def _schema_pattern(def_name: str) -> re.Pattern[str]:
    """The schema's regex with ``$`` read as end of string (as in ECMA-262, not Python's
    ``$``, which also matches before a trailing newline)."""
    import json

    from tests.schema_util import SCHEMAS

    defs = json.loads((SCHEMAS / "defs.json").read_text(encoding="utf-8"))["$defs"]
    pattern = defs[def_name]["pattern"] if "pattern" in defs[def_name] else None
    assert pattern is not None
    return re.compile(pattern.replace("$", r"\Z"))


_CORPUS = [
    "a", "abc", "a-b_c", "-a", "_a", "A", "a" * 64, "a" * 65, "", " ", "a b", "a\n", "\na",
    "gd-abcdefghijkl", "gd-abcdefghijk", "gd-abcdefghijkl\n", "gd-ABCDEFGHIJKL", "gd-abcdefghij18",
    "sig", "s" * 32, "s" * 33, "1sig", "a:b", "a@b/c", "x" * 128, "x" * 129, "a\x00", "é",
    "h/p", "h.io/a/b", "h:80/a", "h:123456/a", "h/..", "h/.", "h/a/..", "h/a\n", "h//a", "H/a",
    "-h/a", "h-/a", "h/...", "h/.a",
]  # fmt: skip


@pytest.mark.parametrize(
    ("def_name", "predicate"),
    [
        ("policy_name", ids.is_policy_name),
        ("check_name", ids.is_check_name),
        ("decision_id", ids.is_decision_id),
        ("signal", ids.is_signal),
        ("repo_id", ids.is_repo_id),
    ],
)
def test_ids_match_the_schema_patterns(def_name, predicate) -> None:
    pattern = _schema_pattern(def_name)
    for value in _CORPUS:
        expected = pattern.fullmatch(value) is not None
        if def_name == "repo_id":
            expected = expected and len(value) <= 255
        assert predicate(value) == expected, (def_name, value)


def test_caller_decision_id_matches_the_schema_item_pattern() -> None:
    import json

    from tests.schema_util import SCHEMAS

    defs = json.loads((SCHEMAS / "defs.json").read_text(encoding="utf-8"))["$defs"]
    pattern = re.compile(defs["decision_ids"]["items"]["pattern"].replace("$", r"\Z"))
    for value in _CORPUS:
        assert ids.is_caller_decision_id(value) == (pattern.fullmatch(value) is not None), value
