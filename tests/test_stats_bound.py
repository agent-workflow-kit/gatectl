"""The one-sided Clopper-Pearson upper bound (interface.md, Track records and recommendation).

Independent references, none of which use ``gatectl.stats``:

* ``exact_cdf`` and ``exact_bound`` below sum the binomial pmf with ``fractions.Fraction`` (exact
  rationals) and bisect on an exact ``Fraction`` probability; the pinned vectors were produced by
  that same procedure (45 bisection steps, printed to 9 decimals) in a separate script.
* ``k = 0`` has a closed form: ``U = 1 - (1 - confidence) ** (1 / n)``.
* For a large ``n`` and a small ``k`` the exact CDF is summed with ``decimal`` at 60 digits and the
  returned bound must bracket the root: the CDF there is at most ``1 - confidence`` and just below
  the bound (by two tolerances) it is above.
"""

from __future__ import annotations

import math
from decimal import Decimal, getcontext
from fractions import Fraction

import pytest

from gatectl import stats

TOL = 2e-9  # the bound is bisected to 1e-9 and rounded up, never down


def exact_cdf(k: int, n: int, p: Fraction) -> Fraction:
    q = 1 - p
    return sum((math.comb(n, i) * p**i * q ** (n - i) for i in range(k + 1)), Fraction(0))


def exact_bound(k: int, n: int, confidence: str) -> float:
    alpha = 1 - Fraction(confidence)
    if n == 0 or k == n:
        return 1.0
    lo, hi = Fraction(0), Fraction(1)
    for _ in range(45):
        mid = (lo + hi) / 2
        if exact_cdf(k, n, mid) > alpha:
            lo = mid
        else:
            hi = mid
    return float(hi)


# (k, n, confidence, bound) derived with exact_bound above and printed to 9 decimals.
PINNED = [
    (0, 10, "0.95", 0.258865551),
    (1, 10, "0.95", 0.394163302),
    (5, 100, "0.95", 0.102253378),
    (0, 59, "0.95", 0.049507610),
    (0, 58, "0.95", 0.050339338),
    (2, 20, "0.9", 0.244765317),
    (3, 50, "0.99", 0.187209256),
    (0, 1, "0.95", 0.95),
    (1, 2, "0.95", 0.974679434),
    (10, 30, "0.5", 0.351679544),
    (0, 100, "0.99", 0.045007414),
    (7, 40, "0.8", 0.245373594),
]


@pytest.mark.parametrize(("k", "n", "confidence", "expected"), PINNED)
def test_the_bound_matches_the_pinned_exact_vectors(
    k: int, n: int, confidence: str, expected: float
) -> None:
    got = stats.upper_bound(k, n, float(confidence))
    assert got == pytest.approx(expected, abs=TOL)
    assert got >= expected - 1e-12  # rounded up, never below the true bound


def test_the_golden_table_59_clean_cases_recommend_and_58_do_not() -> None:
    assert stats.upper_bound(0, 59, 0.95) <= 0.05
    assert stats.upper_bound(0, 58, 0.95) > 0.05
    assert round(stats.upper_bound(0, 58, 0.95), 4) == 0.0503


def test_no_cases_and_all_cases_are_one() -> None:
    assert stats.upper_bound(0, 0, 0.95) == 1.0
    assert stats.upper_bound(5, 5, 0.95) == 1.0
    assert stats.upper_bound(1, 1, 0.5) == 1.0


@pytest.mark.parametrize("n", [1, 2, 3, 7, 59, 1000, 100_000, 5_000_000])
@pytest.mark.parametrize("confidence", [0.5, 0.9, 0.95, 0.99, 0.999])
def test_zero_misses_match_the_closed_form(n: int, confidence: float) -> None:
    closed = -math.expm1(math.log1p(-confidence) / n)
    assert stats.upper_bound(0, n, confidence) == pytest.approx(closed, abs=TOL)


@pytest.mark.parametrize("k", range(0, 7))
def test_small_n_agrees_with_the_slow_exact_reference(k: int) -> None:
    for n in range(max(k, 1), 13):
        for confidence in ("0.8", "0.95", "0.99"):
            assert stats.upper_bound(k, n, float(confidence)) == pytest.approx(
                exact_bound(k, n, confidence), abs=TOL
            )


@pytest.mark.parametrize(("k", "n"), [(0, 100_000), (1, 100_000), (7, 123_457), (20, 1_000_000)])
def test_large_n_brackets_the_exact_root(k: int, n: int) -> None:
    getcontext().prec = 80
    confidence = 0.95

    def cdf(p: Decimal) -> Decimal:
        q = 1 - p
        return sum(
            (Decimal(math.comb(n, i)) * p**i * q ** (n - i) for i in range(k + 1)), Decimal(0)
        )

    bound = stats.upper_bound(k, n, confidence)
    alpha = Decimal(1) - Decimal(confidence)
    assert cdf(Decimal(bound)) <= alpha + Decimal("1e-12")
    assert cdf(Decimal(bound) - Decimal(TOL)) > alpha - Decimal("1e-12")


def test_large_n_with_many_misses_is_close_to_the_normal_approximation() -> None:
    # 50_000 misses in 100_000: the bound sits near 0.5 + 1.645 * 0.5 / sqrt(n).
    got = stats.upper_bound(50_000, 100_000, 0.95)
    assert got == pytest.approx(0.5 + 1.645 * 0.5 / math.sqrt(100_000), abs=2e-4)


def test_the_bound_grows_with_k_and_shrinks_with_n() -> None:
    by_k = [stats.upper_bound(k, 40, 0.95) for k in range(0, 41)]
    assert all(a < b for a, b in zip(by_k, by_k[1:], strict=False))
    by_n = [stats.upper_bound(2, n, 0.95) for n in range(2, 200)]
    assert all(a > b for a, b in zip(by_n, by_n[1:], strict=False))


def test_the_bound_grows_with_the_confidence() -> None:
    values = [stats.upper_bound(3, 30, c) for c in (0.5, 0.8, 0.9, 0.95, 0.99, 0.999)]
    assert values == sorted(values) and len(set(values)) == len(values)


def test_the_bound_stays_in_the_unit_interval() -> None:
    for k, n in [(0, 1), (0, 10**9), (1, 10**9), (10**9 - 1, 10**9), (3, 4)]:
        assert 0.0 <= stats.upper_bound(k, n, 0.95) <= 1.0


@pytest.mark.parametrize(
    ("k", "n", "confidence"),
    [(-1, 5, 0.95), (6, 5, 0.95), (0, -1, 0.95), (1, 0, 0.95), (0, 5, 0.0), (0, 5, 1.0)]
    + [(0, 5, float("nan")), (0, 5, float("inf")), (0, 5, -0.5)],
)
def test_impossible_arguments_are_refused(k: int, n: int, confidence: float) -> None:
    with pytest.raises(ValueError, match="bound"):
        stats.upper_bound(k, n, confidence)


def test_a_bool_is_not_a_count() -> None:
    with pytest.raises(ValueError, match="bound"):
        stats.upper_bound(True, 5, 0.95)  # type: ignore[arg-type]


# --- the recommendation ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("state", "bound", "expected"),
    [
        ("shadow", 0.05, "enforce"),
        ("off", 0.04, "enforce"),
        ("shadow", 0.0500001, "not_yet"),
        ("off", 1.0, "not_yet"),
        ("enforced", 0.05, "keep"),
        ("enforced", 0.0500001, "reconsider"),
        ("enforced", 1.0, "reconsider"),
    ],
)
def test_the_recommendation_table(state: str, bound: float, expected: str) -> None:
    assert stats.recommendation(state, bound, 0.05) == expected


def test_a_custom_miss_rate_changes_the_threshold() -> None:
    assert stats.recommendation("shadow", 0.09, 0.1) == "enforce"
    assert stats.recommendation("shadow", 0.11, 0.1) == "not_yet"
