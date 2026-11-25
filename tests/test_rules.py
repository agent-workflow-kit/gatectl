"""``rules.py``: the closed rule evaluator and the linear glob matcher (interface: Rule checks)."""

from __future__ import annotations

import ast
import math
import random
import re
import time
from pathlib import Path
from typing import Any

import pytest

from gatectl import rules
from gatectl.config_models import Condition, RuleCheck, tokenize_glob
from gatectl.rules import GlobMatcher, evaluate


def cond(path: str, op: str, **kw: Any) -> Condition:
    return Condition.model_validate({"path": path, "op": op, **kw})


def run(conds: list[Condition], obj: Any) -> tuple[str, str | None]:
    result = evaluate(conds, obj)
    return result.outcome, result.detail


def one(path: str, op: str, obj: Any, **kw: Any) -> tuple[str, str | None]:
    return run([cond(path, op, **kw)], obj)


def glob(pattern: str, subject: str) -> bool:
    return GlobMatcher(tokenize_glob(pattern)).matches(subject)


# --- glob matcher ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "subject", "expected"),
    [
        ("abc", "abc", True),
        ("abc", "abd", False),
        ("abc", "ab", False),
        ("abc", "abcd", False),  # anchored at the end
        ("abc", "xabc", False),  # anchored at the start
        ("ABC", "abc", False),  # case sensitive
        ("*", "", True),
        ("*", "abc", True),
        ("*", "a/b", False),
        ("**", "a/b/c", True),
        ("**", "", True),
        ("***", "a/b", True),  # three stars are one **
        ("?", "a", True),
        ("?", "", False),
        ("?", "/", False),
        ("?", "ab", False),
        ("a?c", "a/c", False),
        ("a*c", "abbbc", True),
        ("a*c", "a/c", False),
        ("a**c", "a/b/c", True),
        ("pr=**", "pr=github.com/org/repo#3", True),
        ("pr=*", "pr=github.com/org/repo#3", False),
        ("hold*", "hold", True),
        ("*/*", "a/b", True),
        ("*/*", "a/b/c", False),
        ("**/x", "a/b/x", True),
        ("**/x", "x", False),
        ("a*?", "a", False),
        ("a*?", "ab", True),
        ("[ab]", "a", False),  # no other metacharacters
        ("[ab]", "[ab]", True),
        ("a.c", "abc", False),
        ("\\d", "5", False),
        ("a+", "aa", False),
        ("é?", "éü", True),  # ? is one character, not one byte
        ("?", "😀", True),
        ("a\nb", "a\nb", True),
        ("*", "a\nb", True),
    ],
)
def test_glob_semantics(pattern: str, subject: str, expected: bool) -> None:
    assert glob(pattern, subject) is expected


def _reference_regex(pattern: str) -> re.Pattern[str]:
    out: list[str] = []
    for token in tokenize_glob(pattern):
        out.append({"*": "[^/]*", "**": ".*", "?": "[^/]"}.get(token) or re.escape(token))
    return re.compile("".join(out), re.DOTALL)


def test_matcher_agrees_with_a_reference_regex_on_short_random_strings() -> None:
    rng = random.Random(1717)
    pattern_alphabet = ["a", "b", "/", "*", "**", "?", "*", "a", "b"]
    subject_alphabet = "ab/"
    for _ in range(1500):
        pattern = "".join(rng.choice(pattern_alphabet) for _ in range(rng.randint(1, 7)))
        reference = _reference_regex(pattern)
        for _ in range(6):
            subject = "".join(rng.choice(subject_alphabet) for _ in range(rng.randint(0, 8)))
            assert glob(pattern, subject) == (reference.fullmatch(subject) is not None), (
                pattern,
                subject,
            )


def test_adversarial_pattern_is_fast_on_a_4_kib_subject() -> None:
    matcher = GlobMatcher(tokenize_glob("**a**a**a**a**b"))
    started = time.perf_counter()
    assert matcher.matches("a" * 4096) is False
    assert time.perf_counter() - started < 0.5  # the issue says 100 ms; generous for CI


@pytest.mark.parametrize("pattern", ["**a**a**a**a**b", "*a*a*a*a*b", "*a*a*a*a*a*a*a*a*a*a*b"])
def test_matcher_cost_is_bounded_by_subject_length(pattern: str) -> None:
    tokens = tokenize_glob(pattern)
    for size in (256, 1024, 4096):
        matcher = GlobMatcher(tokens)
        assert matcher.matches("a" * size) is False
        # One step per subject character, each step a fixed number of bit-set operations.
        assert matcher.steps <= size
    matcher = GlobMatcher(tokens)
    matcher.matches("a" * 4096)
    small = GlobMatcher(tokens)
    small.matches("a" * 2048)
    assert matcher.steps <= 2 * small.steps  # linear, not quadratic or exponential


def test_state_set_never_exceeds_the_pattern_positions() -> None:
    tokens = tokenize_glob("*a*a*a*a*b")
    matcher = GlobMatcher(tokens)
    matcher.matches("a" * 1000)
    assert matcher.max_state_bits <= len(tokens) + 1


def test_matcher_stops_early_when_no_position_is_live() -> None:
    matcher = GlobMatcher(tokenize_glob("abc"))
    assert matcher.matches("x" + "a" * 4000) is False
    assert matcher.steps <= 2


def test_matcher_does_not_use_re() -> None:
    source = (Path(rules.__file__)).read_text()
    imports = [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Import | ast.ImportFrom)]
    names = {a.name for n in imports for a in n.names} | {
        n.module for n in imports if isinstance(n, ast.ImportFrom) and n.module
    }
    assert "re" not in names and "fnmatch" not in names and "glob" not in names


# --- the import boundary -------------------------------------------------------------------


_BANNED_IMPORTS = {
    "os",
    "posix",
    "sys",
    "time",
    "datetime",
    "subprocess",
    "socket",
    "random",
    "secrets",
    "gatectl.clock",
    "gatectl.gateway",
    "gatectl.runner",
    "gatectl.procinfo",
}


def _banned_imports(source: str) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module)
            found |= {f"{node.module}.{a.name}" for a in node.names}
    top_level = _BANNED_IMPORTS - {"gatectl"}
    return {f for f in found if f in _BANNED_IMPORTS or f.split(".")[0] in top_level}


def test_rules_imports_no_process_environment_or_clock_module() -> None:
    assert not _banned_imports(Path(rules.__file__).read_text())


@pytest.mark.parametrize(
    "source",
    [
        "import os",
        "import time as t",
        "from os import environ",
        "from gatectl import clock",
        "import gatectl.gateway",
    ],
)
def test_the_import_boundary_check_flags_an_offending_source(source: str) -> None:
    assert _banned_imports(source)


def test_importing_rules_loads_no_gateway_runner_clock_or_subprocess_module(tmp_path: Path) -> None:
    import subprocess
    import sys

    code = (
        "import sys\n"
        "import gatectl.rules\n"
        "mods = set(sys.modules)\n"
        "bad = {'subprocess', 'gatectl.gateway', 'gatectl.runner', 'gatectl.clock'}\n"
        "print(sorted(bad & mods))\n"
    )
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", code],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        env={"LC_ALL": "C", "HOME": str(tmp_path), "XDG_CONFIG_HOME": str(tmp_path / ".config")},
        timeout=60,
        check=True,
    )
    assert out.stdout.strip() == "[]"


# --- glob conditions: limits ---------------------------------------------------------------


def test_glob_condition_matches_a_string() -> None:
    assert one("a", "glob", {"a": "hold-1"}, value="hold*") == ("true", None)
    assert one("a", "glob", {"a": "go"}, value="hold*") == ("false", None)


def test_glob_condition_matches_any_list_element() -> None:
    obj = {"labels": ["x", "hold-1", "y"]}
    assert one("labels", "glob", obj, value="hold*") == ("true", None)
    assert one("labels", "glob", {"labels": ["x"]}, value="hold*") == ("false", None)
    assert one("labels", "glob", {"labels": []}, value="hold*") == ("false", None)


def test_glob_list_with_a_non_string_element_is_a_type_error() -> None:
    assert one("l", "glob", {"l": ["hold", 1]}, value="*") == ("error", "l: type")
    assert one("l", "glob", {"l": [["hold"]]}, value="*") == ("error", "l: type")
    assert one("l", "glob", {"l": [None]}, value="*") == ("error", "l: type")


def test_glob_subject_limits() -> None:
    assert one("a", "glob", {"a": "x" * 4096}, value="**")[0] == "true"
    assert one("a", "glob", {"a": "x" * 4097}, value="**") == ("error", "a: too large")
    # 4 KiB is a byte limit: 2049 two-byte characters are 4098 bytes.
    assert one("a", "glob", {"a": "é" * 2049}, value="**") == ("error", "a: too large")
    assert one("a", "glob", {"a": "é" * 2048}, value="**")[0] == "true"


def test_glob_list_limits() -> None:
    assert one("l", "glob", {"l": ["x"] * 256}, value="y")[0] == "false"
    assert one("l", "glob", {"l": ["x"] * 257}, value="x") == ("error", "l: too large")
    four = ["x" * 4096] * 4  # exactly 16 KiB
    assert one("l", "glob", {"l": four}, value="y")[0] == "false"
    assert one("l", "glob", {"l": [*four, "x"]}, value="y") == ("error", "l: too large")


def test_adversarial_pattern_on_an_oversized_subject_is_too_large() -> None:
    result = one("a", "glob", {"a": "a" * 100_000}, value="**a**a**a**a**b")
    assert result == ("error", "a: too large")


def test_adversarial_pattern_on_a_4_kib_subject_through_the_evaluator() -> None:
    started = time.perf_counter()
    result = one("a", "glob", {"a": "a" * 4096}, value="**a**a**a**a**b")
    assert result == ("false", None)
    assert time.perf_counter() - started < 0.5


def test_a_pattern_compiled_once_serves_every_list_element() -> None:
    obj = {"l": ["a" * 4096] * 4}
    assert one("l", "glob", obj, value="*a*a*a*b") == ("false", None)


# --- paths -----------------------------------------------------------------------------------


def test_dotted_paths_and_indexes() -> None:
    obj = {"a": {"b": [{"c": 5}, {"c": 6}]}, "0": "key"}
    assert one("a.b.1.c", "eq", obj, value=6) == ("true", None)
    assert one("a.b.0.c", "eq", obj, value=6) == ("false", None)
    assert one("0", "eq", obj, value="key") == ("true", None)  # a numeric segment is a key
    assert one("a.b.2.c", "eq", obj, value=1) == ("error", "a.b.2.c: missing")
    assert one("a.b.x", "eq", obj, value=1) == ("error", "a.b.x: missing")


@pytest.mark.parametrize("segment", ["01", "00", "-1", "9" * 5000, "1" + "0" * 40])
def test_non_canonical_or_huge_indexes_are_missing(segment: str) -> None:
    obj = {"a": [1, 2, 3]}
    assert one(f"a.{segment}", "exists", obj) == ("false", None)
    assert one(f"a.{segment}", "absent", obj) == ("true", None)
    assert one(f"a.{segment}", "eq", obj, value=1)[0] == "error"


def test_paths_through_scalars_and_null_are_missing() -> None:
    assert one("a.b", "eq", {"a": 5}, value=1) == ("error", "a.b: missing")
    assert one("a.b", "eq", {"a": None}, value=1) == ("error", "a.b: missing")
    assert one("a.b", "exists", {"a": "str"}) == ("false", None)
    assert one("a.0", "exists", {"a": "str"}) == ("false", None)  # a string is not indexable


def test_exists_and_absent() -> None:
    assert one("a", "exists", {"a": None}) == ("true", None)
    assert one("a", "absent", {"a": None}) == ("false", None)
    assert one("a", "exists", {}) == ("false", None)
    assert one("a", "absent", {}) == ("true", None)
    assert one("a.b", "absent", {"a": {}}) == ("true", None)
    assert one("a", "exists", {"a": 0}) == ("true", None)


# --- comparison operators: errors ------------------------------------------------------------


@pytest.mark.parametrize(
    ("op", "kw"),
    [
        ("eq", {"value": 1}),
        ("ne", {"value": 1}),
        ("in", {"value": [1]}),
        ("not_in", {"value": [1]}),
        ("lt", {"value": 1}),
        ("le", {"value": 1}),
        ("gt", {"value": 1}),
        ("ge", {"value": 1}),
        ("glob", {"value": "*"}),
    ],
)
def test_missing_path_is_an_error_for_every_comparison(op: str, kw: dict[str, Any]) -> None:
    assert one("ci.state", op, {"ci": {}}, **kw) == ("error", "ci.state: missing")
    assert one("ci.state", op, {}, **kw) == ("error", "ci.state: missing")


@pytest.mark.parametrize(
    ("op", "kw"),
    [
        ("eq", {"value": 1}),
        ("ne", {"value": "x"}),
        ("in", {"value": [1, "x"]}),
        ("not_in", {"value": ["x"]}),
        ("lt", {"value": 1}),
        ("le", {"value": 1}),
        ("gt", {"value": 1}),
        ("ge", {"value": 1}),
        ("glob", {"value": "*"}),
    ],
)
def test_null_is_an_error_unless_null_can_be_compared(op: str, kw: dict[str, Any]) -> None:
    assert one("k", op, {"k": None}, **kw) == ("error", "k: null")


def test_null_compares_as_a_value_for_eq_ne_in_not_in() -> None:
    null_obj = {"k": None}
    assert one("k", "eq", null_obj, value=None) == ("true", None)
    assert one("k", "ne", null_obj, value=None) == ("false", None)
    assert one("k", "in", null_obj, value=["a", None]) == ("true", None)
    assert one("k", "not_in", null_obj, value=["a", None]) == ("false", None)
    # a non-null path value against a null value is just unequal
    assert one("k", "eq", {"k": 0}, value=None) == ("false", None)
    assert one("k", "ne", {"k": ""}, value=None) == ("true", None)
    assert one("k", "in", {"k": 0}, value=[None]) == ("false", None)
    assert one("k", "not_in", {"k": 0}, value=[None]) == ("true", None)


@pytest.mark.parametrize("op", ["lt", "le", "gt", "ge"])
@pytest.mark.parametrize("bad", ["5", True, False, [1], {"a": 1}, [], float("nan"), math.inf])
def test_ordering_needs_a_real_number(op: str, bad: Any) -> None:
    assert one("k", op, {"k": bad}, value=1) == ("error", "k: type")


def test_ordering() -> None:
    assert one("k", "lt", {"k": 1}, value=2) == ("true", None)
    assert one("k", "lt", {"k": 2}, value=2) == ("false", None)
    assert one("k", "le", {"k": 2}, value=2) == ("true", None)
    assert one("k", "gt", {"k": 2.5}, value=2) == ("true", None)
    assert one("k", "ge", {"k": 2}, value=2.0) == ("true", None)
    assert one("k", "ge", {"k": -1}, value=0) == ("false", None)
    assert one("k", "lt", {"k": 10**400}, value=1.5) == ("false", None)
    assert one("k", "gt", {"k": 10**400}, value=1.5) == ("true", None)


@pytest.mark.parametrize("bad", [["a"], {"a": 1}, [], {}])
@pytest.mark.parametrize("op", ["in", "not_in"])
def test_in_needs_a_scalar_path_value(op: str, bad: Any) -> None:
    assert one("k", op, {"k": bad}, value=["a"]) == ("error", "k: type")


def test_glob_needs_a_string_or_a_list() -> None:
    for bad in (1, True, {"a": "b"}, 1.5):
        assert one("k", "glob", {"k": bad}, value="*") == ("error", "k: type")


# --- equality ----------------------------------------------------------------------------------


def test_booleans_never_equal_numbers() -> None:
    assert one("k", "eq", {"k": True}, value=1) == ("false", None)
    assert one("k", "eq", {"k": 1}, value=True) == ("false", None)
    assert one("k", "eq", {"k": False}, value=0) == ("false", None)
    assert one("k", "eq", {"k": 0.0}, value=False) == ("false", None)
    assert one("k", "ne", {"k": True}, value=1) == ("true", None)
    assert one("k", "in", {"k": True}, value=[1, 0]) == ("false", None)
    assert one("k", "in", {"k": 1}, value=[True]) == ("false", None)
    assert one("k", "not_in", {"k": 0}, value=[False]) == ("true", None)
    assert one("k", "eq", {"k": True}, value=True) == ("true", None)
    assert one("k", "eq", {"k": [True]}, value=[1]) == ("false", None)
    assert one("k", "eq", {"k": {"a": 1}}, value={"a": True}) == ("false", None)


def test_numbers_compare_by_value_across_int_and_float() -> None:
    assert one("k", "eq", {"k": 1}, value=1.0) == ("true", None)
    assert one("k", "eq", {"k": 2**70}, value=float(2**70)) == ("true", None)
    assert one("k", "eq", {"k": 2**70 + 1}, value=float(2**70)) == ("false", None)


def test_eq_and_ne_compare_arrays_and_objects_whole() -> None:
    obj = {"k": {"a": [1, {"b": None}], "c": "x"}}
    assert one("k", "eq", obj, value={"c": "x", "a": [1, {"b": None}]}) == ("true", None)
    assert one("k", "eq", obj, value={"a": [1, {"b": None}]}) == ("false", None)
    assert one("k", "eq", obj, value={"a": [1, {"b": 0}], "c": "x"}) == ("false", None)
    assert one("k", "ne", obj, value=[1]) == ("true", None)
    assert one("k", "eq", {"k": [1, 2]}, value=[2, 1]) == ("false", None)
    assert one("k", "eq", {"k": []}, value={}) == ("false", None)
    assert one("k", "eq", {"k": "1"}, value=1) == ("false", None)


def test_nan_is_never_equal_and_never_raises() -> None:
    nan = float("nan")
    assert one("k", "eq", {"k": nan}, value=1) == ("false", None)
    assert one("k", "eq", {"k": nan}, value=1.5) == ("false", None)
    assert one("k", "ne", {"k": nan}, value=1)[0] == "true"
    assert one("k", "in", {"k": nan}, value=[1, None]) == ("false", None)
    assert one("k", "not_in", {"k": nan}, value=[1, None]) == ("true", None)


def test_a_glob_condition_that_skipped_validation_still_evaluates_without_raising() -> None:
    built = Condition.model_construct(path="k", op="glob", value="a*")
    assert run([built], {"k": "abc"}) == ("true", None)
    assert run([built], {"k": "xbc"}) == ("false", None)


@pytest.mark.parametrize("value", [None, 5, ["a"], "", "x" * 129])
def test_an_unusable_glob_value_on_an_unvalidated_condition_escalates(value: Any) -> None:
    built = Condition.model_construct(path="k", op="glob", value=value)
    assert run([built], {"k": "abc"}) == ("error", "k: type")


@pytest.mark.parametrize("op", ["in", "not_in"])
@pytest.mark.parametrize("value", [None, "abc", 5, True, {"a": 1}])
@pytest.mark.parametrize("found", ["abc", 5, None])
def test_in_with_a_non_list_value_on_an_unvalidated_condition_escalates(
    op: str, value: Any, found: Any
) -> None:
    built = Condition.model_construct(path="k", op=op, value=value)
    assert run([built], {"k": found}) == ("error", "k: type")


@pytest.mark.parametrize("op", ["in", "not_in"])
def test_in_with_non_scalar_list_elements_does_not_raise(op: str) -> None:
    built = Condition.model_construct(path="k", op=op, value=[{"a": 1}, [1], "x"])
    assert run([built], {"k": "x"})[0] == ("true" if op == "in" else "false")
    assert run([built], {"k": "y"})[0] == ("false" if op == "in" else "true")


@pytest.mark.parametrize("op", ["lt", "le", "gt", "ge"])
@pytest.mark.parametrize("value", [None, "a", [1], {"a": 1}, True])
def test_ordering_with_a_non_number_value_on_an_unvalidated_condition_escalates(
    op: str, value: Any
) -> None:
    built = Condition.model_construct(path="k", op=op, value=value)
    assert run([built], {"k": 3}) == ("error", "k: type")


@pytest.mark.parametrize("op", ["eq", "ne"])
@pytest.mark.parametrize("value", [None, "a", [1], {"a": 1}, object()])
def test_equality_on_an_unvalidated_condition_never_raises(op: str, value: Any) -> None:
    built = Condition.model_construct(path="k", op=op, value=value)
    assert run([built], {"k": 3})[0] in ("true", "false", "error")


@pytest.mark.parametrize("op", ["bogus", "", None, 5])
def test_an_unknown_op_on_an_unvalidated_condition_escalates(op: Any) -> None:
    built = Condition.model_construct(path="k", op=op, value=1)
    assert run([built], {"k": 3}) == ("error", "k: type")


def test_deeply_nested_equality_does_not_recurse() -> None:
    deep_a: Any = "leaf"
    deep_b: Any = "leaf"
    for _ in range(5000):
        deep_a = [deep_a]
        deep_b = [deep_b]
    assert one("k", "eq", {"k": deep_a}, value=deep_b) == ("true", None)
    deep_c: Any = "other"
    for _ in range(5000):
        deep_c = [deep_c]
    assert one("k", "eq", {"k": deep_a}, value=deep_c) == ("false", None)


def test_in_and_not_in_membership() -> None:
    assert one("k", "in", {"k": "a"}, value=["a", "b"]) == ("true", None)
    assert one("k", "in", {"k": "c"}, value=["a", "b"]) == ("false", None)
    assert one("k", "not_in", {"k": "c"}, value=["a", "b"]) == ("true", None)
    assert one("k", "not_in", {"k": "a"}, value=["a", "b"]) == ("false", None)
    assert one("k", "in", {"k": 2}, value=[2.0]) == ("true", None)
    assert one("k", "in", {"k": "a"}, value=[]) == ("false", None)
    assert one("k", "not_in", {"k": "a"}, value=[]) == ("true", None)


# --- short-circuit, guard idiom, verdicts ------------------------------------------------------


def test_all_true_is_true_and_the_first_false_stops() -> None:
    assert run([cond("a", "eq", value=1), cond("b", "eq", value=2)], {"a": 1, "b": 2}) == (
        "true",
        None,
    )
    # b is missing, but the first condition is already false: no error
    assert run([cond("a", "eq", value=1), cond("b", "eq", value=2)], {"a": 9}) == ("false", None)


def test_the_first_error_stops_before_a_later_false_or_error() -> None:
    conds = [cond("a", "eq", value=1), cond("b", "eq", value=2), cond("c", "eq", value=3)]
    assert run(conds, {"b": 9}) == ("error", "a: missing")
    assert run(conds, {"a": 1, "c": 1}) == ("error", "b: missing")
    assert run(conds, {"a": 1, "b": 9}) == ("false", None)


def test_the_guard_idiom() -> None:
    guarded = [cond("labels", "exists"), cond("labels", "glob", value="hold*")]
    assert run(guarded, {}) == ("false", None)
    assert run(guarded, {"labels": ["hold-me"]}) == ("true", None)
    assert run(guarded, {"labels": ["go"]}) == ("false", None)
    unguarded = [cond("labels", "glob", value="hold*")]
    assert run(unguarded, {}) == ("error", "labels: missing")
    nullable = [cond("x", "ne", value=None), cond("x", "eq", value="a")]
    assert run(nullable, {"x": None}) == ("false", None)


def _rule(**kw: Any) -> RuleCheck:
    doc = {"name": "r", "type": "rule", "when": [{"path": "k", "op": "eq", "value": 1}], **kw}
    return RuleCheck.model_validate(doc)


@pytest.mark.parametrize(
    ("obj", "then", "else_", "expected"),
    [
        ({"k": 1}, "deny", "allow", ("deny", None, None)),
        ({"k": 2}, "deny", "allow", ("allow", None, None)),
        ({"k": 2}, "allow", "escalate", ("escalate", None, None)),
        ({"k": 1}, "escalate", "deny", ("escalate", None, None)),
        ({}, "deny", "allow", ("escalate", "check_error", "k: missing")),
        ({"k": None}, "allow", "allow", ("escalate", "check_error", "k: null")),
        ({"k": [1]}, "deny", "deny", ("deny", None, None)),
    ],
)
def test_run_rule_verdicts(
    obj: Any, then: str, else_: str, expected: tuple[str, str | None, str | None]
) -> None:
    check = _rule(then=then, **{"else": else_})
    verdict = rules.run_rule(check, obj)
    assert (verdict.verdict, verdict.reason, verdict.detail) == expected


def test_else_defaults_to_allow() -> None:
    verdict = rules.run_rule(_rule(then="deny"), {"k": 0})
    assert verdict.verdict == "allow"


def test_applies_is_false_only_when_a_condition_is_false() -> None:
    conds = [cond("tool", "eq", value="Bash")]
    assert rules.applies(conds, {"tool": "Bash"}) is True
    assert rules.applies(conds, {"tool": "Edit"}) is False
    assert rules.applies(conds, {}) is True  # an error counts as applicable (fail closed)
    assert rules.applies(conds, {"tool": None}) is True
    assert rules.applies([cond("a", "exists"), cond("tool", "eq", value="x")], {}) is False


def test_rule_checks_take_no_deadline_parameter() -> None:
    import inspect

    assert set(inspect.signature(rules.run_rule).parameters) == {"check", "obj"}
    assert set(inspect.signature(rules.evaluate).parameters) == {"conditions", "obj"}
    assert set(inspect.signature(rules.applies).parameters) == {"conditions", "obj"}


def test_rule_checks_never_read_the_clock_or_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import os

    def boom(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("the evaluator consulted the clock or the environment")

    obj = {"a": 1, "s": "abc/d", "l": ["x", "y"], "n": None}
    conds = [
        cond("a", "exists"),
        cond("a", "lt", value=2),
        cond("a", "in", value=[1, 2]),
        cond("s", "glob", value="abc/*"),
        cond("l", "glob", value="y"),
        cond("n", "eq", value=None),
        cond("missing", "absent"),
    ]
    monkeypatch.setattr(time, "time", boom)
    monkeypatch.setattr(time, "monotonic", boom)
    monkeypatch.setattr(time, "perf_counter", boom)
    monkeypatch.setattr(os, "getenv", boom)
    assert evaluate(conds, obj).outcome == "true"
    assert rules.applies(conds, obj) is True
    when = [
        {"path": c.path, "op": c.op, **({} if c.op in ("exists", "absent") else {"value": c.value})}
        for c in conds
    ]
    check = RuleCheck.model_validate({"name": "r", "type": "rule", "when": when, "then": "deny"})
    assert rules.run_rule(check, obj).verdict == "deny"
    assert rules.run_rule(check, {"a": "x"}).verdict == "escalate"


# --- ticketctl-shaped payloads -----------------------------------------------------------------


def test_arrays_of_objects_and_nulls_are_matchable() -> None:
    obj = {
        "plan": {"assign": None},
        "sprints": [{"id": 7, "state": "active"}, {"id": 8, "state": "future"}],
        "ticket": {"assignee_is_me": False, "priority": "High"},
    }
    assert one("sprints.0.state", "eq", obj, value="active") == ("true", None)
    assert one("sprints.1.id", "in", obj, value=[8, 9]) == ("true", None)
    assert one("plan.assign", "eq", obj, value=None) == ("true", None)
    assert one("plan.assign", "in", obj, value=["me", "none", None]) == ("true", None)
    assert one("ticket.assignee_is_me", "eq", obj, value=False) == ("true", None)
    assert one("sprints", "eq", obj, value=[{"id": 7, "state": "active"}]) == ("false", None)


# --- hostile values: never raises ----------------------------------------------------------------


def _hostile_values(rng: random.Random, depth: int = 0) -> Any:
    kind = rng.randint(0, 11 if depth < 3 else 7)
    if kind == 0:
        return None
    if kind == 1:
        return rng.choice([True, False])
    if kind == 2:
        return rng.choice([0, 1, -1, 2**63, 10**400, -(10**400)])
    if kind == 3:
        return rng.choice([0.0, -0.0, 1.5, 1e308, float("nan"), math.inf, -math.inf])
    if kind == 4:
        return rng.choice(["", "a", "é", "a/b", "\x00", "\ud800", "😀" * 3, "a" * 5000])
    if kind == 5:
        return rng.choice(["*", "**", "?", "[", "\\"])
    if kind == 6:
        return ""
    if kind == 7:
        return rng.choice([[], {}])
    if kind <= 9:
        return [_hostile_values(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {
        rng.choice(["a", "b", "0", "1", "c-d"]): _hostile_values(rng, depth + 1)
        for _ in range(rng.randint(0, 4))
    }


def test_no_hostile_value_ever_raises_and_results_are_deterministic() -> None:
    rng = random.Random(20260101)
    paths = ["a", "b", "a.0", "a.b", "0", "a.1.b", "c-d", "a.99999999999999999999"]
    conditions: list[Condition] = []
    for path in paths:
        conditions.append(cond(path, "exists"))
        conditions.append(cond(path, "absent"))
        for op in ("eq", "ne"):
            for value in (None, 1, True, "a", [1], {"a": None}, 2.5):
                conditions.append(cond(path, op, value=value))
        for op in ("in", "not_in"):
            conditions.append(cond(path, op, value=[None, 1, "a", True]))
        for op in ("lt", "le", "gt", "ge"):
            conditions.append(cond(path, op, value=1))
        for pattern in ("*", "a*b", "**", "?", "a?*"):
            conditions.append(cond(path, "glob", value=pattern))
    for _ in range(120):
        obj = {
            rng.choice(["a", "b", "0", "c-d"]): _hostile_values(rng)
            for _ in range(rng.randint(0, 4))
        }
        for c in conditions:
            first = evaluate([c], obj)
            second = evaluate([c], obj)
            assert first == second
            assert first.outcome in ("true", "false", "error")
            if first.outcome == "error":
                assert first.detail is not None
                assert first.detail.rsplit(": ", 1)[1] in ("missing", "null", "type", "too large")
            else:
                assert first.detail is None


def test_the_input_is_never_mutated() -> None:
    obj = {"a": [1, {"b": "x"}], "l": ["x", "y"]}
    before = repr(obj)
    for c in (
        cond("a.1.b", "eq", value="x"),
        cond("l", "glob", value="*"),
        cond("a", "in", value=[1]),
    ):
        evaluate([c], obj)
    assert repr(obj) == before
