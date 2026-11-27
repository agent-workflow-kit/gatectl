"""Track records and the recommendation: ``gatectl stats`` (interface.md, Track records).

This module holds the arithmetic (the one-sided Clopper-Pearson bound) and the recommendation
table; ``statscmd`` reads the records from ``state.db`` and prints them.

The bound ``U`` for ``k`` unsafe-miss cases in ``n`` cases at confidence ``c`` solves
``P(X <= k | n, U) = 1 - c`` for ``X ~ Binomial(n, U)``. The binomial CDF is the regularized
incomplete beta function, ``P(X <= k | n, p) = I_{1-p}(n - k, k + 1)``, evaluated with the standard
continued fraction (modified Lentz) in ``math.lgamma`` and ``math.log1p`` terms, so the bound
needs no dependency (scipy would be the only reason to add one) and costs a few hundred
operations per bisection step even for ``n`` in the millions. The CDF falls as ``p`` grows, so the
root is found by bisection to a width below ``BOUND_TOLERANCE`` and the **upper** end of the
bracket is returned: a float error can never make the bound smaller than the true one by more
than the tolerance, and the recommendation errs toward ``not_yet``. Tests pin the result against
an exact rational reference (``fractions``).
"""

from __future__ import annotations

import math

from gatectl.errors import InternalError

BOUND_TOLERANCE = 1e-9
_EPS = 1e-15
_TINY = 1e-300
_MAX_ITERATIONS = 200_000  # the continued fraction needs O(sqrt(n)) steps; n is a row count


def _invalid() -> ValueError:
    return ValueError("invalid arguments for the bound")


def _continued_fraction(a: float, b: float, x: float) -> float:
    """The continued fraction of the incomplete beta function (Lentz's method)."""
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > _TINY else _TINY)
    h = d
    for m in range(1, _MAX_ITERATIONS + 1):
        m2 = 2 * m
        step = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + step * d
        d = 1.0 / (d if abs(d) > _TINY else _TINY)
        c = 1.0 + step / c
        c = c if abs(c) > _TINY else _TINY
        h *= d * c
        step = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + step * d
        d = 1.0 / (d if abs(d) > _TINY else _TINY)
        c = 1.0 + step / c
        c = c if abs(c) > _TINY else _TINY
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _EPS:
            return h
    raise InternalError("the track record bound did not converge")


def binomial_cdf(k: int, n: int, p: float) -> float:
    """``P(X <= k)`` for ``X ~ Binomial(n, p)``, with ``0 <= k < n`` and ``0 < p < 1``."""
    a, b = float(n - k), float(k + 1)  # I_q(a, b) with q = 1 - p
    q = 1.0 - p
    log_front = (
        math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log1p(-p) + b * math.log(p)
    )
    front = math.exp(log_front)
    if q < (a + 1.0) / (a + b + 2.0):
        return min(1.0, front * _continued_fraction(a, b, q) / a)
    return max(0.0, 1.0 - front * _continued_fraction(b, a, p) / b)


def upper_bound(k: int, n: int, confidence: float) -> float:
    """The one-sided Clopper-Pearson upper bound of a miss rate, ``k`` misses in ``n`` cases.

    1 when ``n = 0`` or ``k = n``. Bisection to ``BOUND_TOLERANCE``; the upper end is returned.
    """
    if (
        isinstance(k, bool)
        or isinstance(n, bool)
        or not isinstance(k, int)
        or not isinstance(n, int)
        or not 0 <= k <= n
        or not isinstance(confidence, float | int)
        or not math.isfinite(confidence)
        or not 0.0 < confidence < 1.0
    ):
        raise _invalid()
    if n == 0 or k == n:
        return 1.0
    alpha = 1.0 - confidence
    low, high = 0.0, 1.0
    while high - low >= BOUND_TOLERANCE:
        mid = (low + high) / 2.0
        if binomial_cdf(k, n, mid) > alpha:
            low = mid
        else:
            high = mid
    return high


def printed_bound(bound: float) -> float:
    """The bound rounded **up** to 6 decimals, capped at 1. ``upper_bound`` overshoots the root by
    less than ``BOUND_TOLERANCE``; that is taken off first, so an exact value such as 0.95 does not
    print as 0.950001."""
    return min(1.0, math.ceil(round((bound - BOUND_TOLERANCE) * 1e6, 4)) / 1e6)


def recommendation(state: str, bound: float, max_miss_rate: float) -> str:
    """The advisory recommendation (interface.md): ``enforce`` or ``not_yet`` when the scope is
    not ``enforced``, ``keep`` or ``reconsider`` when it is."""
    # A bound of 1 is "no evidence" (n = 0) or "every case missed" (k = n): it never holds, even
    # with max_miss_rate = 1 (which the schema allows).
    holds = bound < 1.0 and bound <= max_miss_rate
    if state == "enforced":
        return "keep" if holds else "reconsider"
    return "enforce" if holds else "not_yet"
