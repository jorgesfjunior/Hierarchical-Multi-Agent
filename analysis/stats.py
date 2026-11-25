"""Small, dependency-free statistics for paired comparisons (numpy only).

scipy is not installed in this environment; these are textbook implementations,
checked in tests against published reference values.

* ``wilcoxon_signed_rank``: two-sided, zero differences dropped ("wilcox"
  method), average ranks for ties. Exact null distribution when n <= 25 and
  there are no ties; otherwise normal approximation with tie correction and
  continuity correction. Effect size: matched-pairs rank-biserial correlation
  r = (W+ - W-) / (W+ + W-) in [-1, 1] (positive = first sample larger).
  Returns ``None`` (test skipped) when fewer than ``MIN_PAIRS`` non-zero pairs
  remain: with n < 6 a two-sided exact p can never be < 0.05.
* ``holm``: Holm-Bonferroni step-down adjusted p-values.
* ``bootstrap_ci``: percentile bootstrap CI of the mean (fixed seed).
"""
from __future__ import annotations

import math
from typing import Optional, Sequence

import numpy as np

MIN_PAIRS = 6


def _ranks(values: np.ndarray) -> np.ndarray:
    order = np.argsort(values, kind="mergesort")
    ranks = np.empty(len(values))
    sorted_vals = values[order]
    i = 0
    while i < len(values):
        j = i
        while j + 1 < len(values) and sorted_vals[j + 1] == sorted_vals[i]:
            j += 1
        ranks[order[i : j + 1]] = (i + j) / 2.0 + 1.0
        i = j + 1
    return ranks


def _exact_two_sided(n: int, w_plus: float) -> float:
    # number of subsets of {1..n} with rank sum s
    max_sum = n * (n + 1) // 2
    counts = np.zeros(max_sum + 1)
    counts[0] = 1
    for k in range(1, n + 1):
        counts[k:] = counts[k:] + counts[:-k].copy()
    total = 2.0 ** n
    w = min(w_plus, max_sum - w_plus)
    p = counts[: int(math.floor(w)) + 1].sum() / total * 2.0
    return min(1.0, p)


def wilcoxon_signed_rank(x: Sequence[float], y: Optional[Sequence[float]] = None) -> Optional[dict]:
    d = np.asarray(x, dtype=float) - (np.asarray(y, dtype=float) if y is not None else 0.0)
    d = d[d != 0]
    n = len(d)
    if n < MIN_PAIRS:
        return None
    r = _ranks(np.abs(d))
    w_plus, w_minus = r[d > 0].sum(), r[d < 0].sum()
    ties = len(np.unique(np.abs(d))) < n
    if n <= 25 and not ties:
        p, method = _exact_two_sided(n, w_plus), "exact"
    else:
        mean = n * (n + 1) / 4.0
        _, counts = np.unique(np.abs(d), return_counts=True)
        var = n * (n + 1) * (2 * n + 1) / 24.0 - (counts ** 3 - counts).sum() / 48.0
        z = (abs(w_plus - mean) - 0.5) / math.sqrt(var) if var > 0 else 0.0
        p, method = math.erfc(max(z, 0.0) / math.sqrt(2.0)), "normal"
    return {
        "n": n,
        "statistic": float(min(w_plus, w_minus)),
        "w_plus": float(w_plus),
        "p": float(min(1.0, p)),
        "rank_biserial": float((w_plus - w_minus) / (w_plus + w_minus)),
        "method": method,
    }


def holm(pvalues: Sequence[float]) -> list[float]:
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: pvalues[i])
    adjusted = [0.0] * m
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * pvalues[i]))
        adjusted[i] = running
    return adjusted


def bootstrap_ci(values: Sequence[float], *, n_boot: int = 2000, alpha: float = 0.05, seed: int = 0) -> tuple[float, float]:
    v = np.asarray(values, dtype=float)
    if len(v) == 0:
        return (float("nan"), float("nan"))
    if len(v) == 1:
        return (float(v[0]), float(v[0]))
    rng = np.random.default_rng(seed)
    means = rng.choice(v, size=(n_boot, len(v)), replace=True).mean(axis=1)
    return (float(np.quantile(means, alpha / 2)), float(np.quantile(means, 1 - alpha / 2)))
