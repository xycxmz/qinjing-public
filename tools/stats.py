#!/usr/bin/env python
# -*- coding: ascii -*-
"""Exact binomial confidence bounds for score disclosure (C11).

Zero-dependency Clopper-Pearson intervals via the regularized incomplete
beta function (Lanczos log-gamma + continued fraction + bisection), so a
rate computed on a small or zero-success denominator is never reported as
a point estimate with an implicit zero-width interval. The motivating case
is a 0-FP benign run: 0/120 still carries a one-sided 95% upper bound of
about 2.47%, not 0%.

Independence caveat (disclosed by the scorer, not assumed here): these
bounds assume independent Bernoulli trials. Corpus cases are correlated
(generated variants, single-family benign personas), so the true effective
sample size is smaller than the case count and the intervals are optimistic.
"""

import math


def _gammln(x):
    cof = [76.18009172947146, -86.50532032941677, 24.01409824083091,
           -1.231739572450155, 0.1208650973866179e-2, -0.5395239384953e-5]
    y = x
    tmp = x + 5.5
    tmp -= (x + 0.5) * math.log(tmp)
    ser = 1.000000000190015
    for c in cof:
        y += 1
        ser += c / y
    return -tmp + math.log(2.5066282746310005 * ser / x)


def _betacf(a, b, x):
    fpmin = 1e-300
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < fpmin:
        d = fpmin
    d = 1.0 / d
    h = d
    for m in range(1, 201):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < fpmin:
            d = fpmin
        c = 1.0 + aa / c
        if abs(c) < fpmin:
            c = fpmin
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 3e-12:
            break
    return h


def _ibeta(a, b, x):
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    bt = math.exp(_gammln(a + b) - _gammln(a) - _gammln(b)
                  + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def _beta_ppf(p, a, b):
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2.0
        if _ibeta(a, b, mid) < p:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def upper_bound(k, n, confidence=0.95):
    """One-sided Clopper-Pearson upper bound for k successes in n trials.

    >>> round(upper_bound(0, 120) * 100, 2)
    2.47
    >>> upper_bound(0, 1)
    0.95
    >>> upper_bound(5, 5)
    1.0
    >>> upper_bound(0, 0) is None
    True
    """
    if n <= 0:
        return None
    if k >= n:
        return 1.0
    return _beta_ppf(confidence, k + 1, n - k)


def exact_binomial_ci(k, n, confidence=0.95):
    """Two-sided Clopper-Pearson interval for k successes in n trials.

    >>> tuple(round(x, 3) for x in exact_binomial_ci(1, 1))
    (0.025, 1.0)
    >>> exact_binomial_ci(0, 5)[0]
    0.0
    >>> exact_binomial_ci(0, 0)
    (None, None)
    >>> lo, hi = exact_binomial_ci(3, 4)
    >>> 0.0 < lo < 0.75 < hi < 1.0
    True
    """
    if n <= 0:
        return (None, None)
    alpha = 1.0 - confidence
    lo = 0.0 if k == 0 else _beta_ppf(alpha / 2.0, k, n - k + 1)
    hi = 1.0 if k == n else _beta_ppf(1.0 - alpha / 2.0, k + 1, n - k)
    return (lo, hi)


if __name__ == "__main__":
    import doctest
    import sys
    result = doctest.testmod()
    sys.exit(1 if result.failed else 0)