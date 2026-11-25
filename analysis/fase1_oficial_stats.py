"""Tests of the Fase 1 official run (docs/fase1/08_preregistro_oficial.md §7), numpy only.

* ``cluster_bootstrap``: resamples clusters (seeds) with replacement; the statistic is the pooled
  mean of the unit values in the drawn clusters (sum / count). 10 000 draws, ``default_rng(0)``.
* ``mcnemar_exact_one_sided``: b = pairs where the first arm succeeds and the second fails, c = the
  reverse; p = P(X >= b), X ~ Binomial(b + c, 1/2); p = 1 when b + c = 0.
* ``logit_cluster``: logistic regression by Newton-Raphson (IRLS) with the cluster-robust sandwich
  (CR1: G/(G-1) * (N-1)/(N-K), the statsmodels default for GLM cov_type="cluster").
"""
from __future__ import annotations

import math
from typing import Hashable, Sequence

import numpy as np

N_BOOT, BOOT_SEED = 10_000, 0


def _cluster_sums(clusters: Sequence[Hashable], values: Sequence[float]) -> tuple[np.ndarray, np.ndarray]:
    index: dict[Hashable, int] = {}
    for c in clusters:
        index.setdefault(c, len(index))
    g = np.fromiter((index[c] for c in clusters), dtype=np.int64, count=len(clusters))
    v = np.asarray(values, dtype=float)
    return np.bincount(g, weights=v, minlength=len(index)), np.bincount(g, minlength=len(index)).astype(float)


def cluster_bootstrap(clusters: Sequence[Hashable], values: Sequence[float], *, n_boot: int = N_BOOT,
                      seed: int = BOOT_SEED) -> np.ndarray:
    """Bootstrap distribution of the pooled mean, resampling whole clusters."""
    s, n = _cluster_sums(clusters, values)
    idx = np.random.default_rng(seed).integers(0, len(s), size=(n_boot, len(s)))
    return s[idx].sum(axis=1) / n[idx].sum(axis=1)


def ci95(draws: np.ndarray) -> tuple[float, float]:
    return float(np.quantile(draws, 0.025)), float(np.quantile(draws, 0.975))


def mcnemar_exact_one_sided(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    return sum(math.comb(n, k) for k in range(b, n + 1)) / 2 ** n


def logit_cluster(X: np.ndarray, y: np.ndarray, clusters: Sequence[Hashable], *, tol: float = 1e-10,
                  max_iter: int = 100) -> tuple[np.ndarray, np.ndarray]:
    """Returns (coefficients, cluster-robust covariance)."""
    X, y = np.asarray(X, dtype=float), np.asarray(y, dtype=float)
    beta = np.zeros(X.shape[1])
    for _ in range(max_iter):
        mu = 1.0 / (1.0 + np.exp(-(X @ beta)))
        hess = X.T @ (X * (mu * (1.0 - mu))[:, None])
        step = np.linalg.solve(hess, X.T @ (y - mu))
        beta = beta + step
        if np.max(np.abs(step)) < tol:
            break
    mu = 1.0 / (1.0 + np.exp(-(X @ beta)))
    bread = np.linalg.inv(X.T @ (X * (mu * (1.0 - mu))[:, None]))
    index: dict[Hashable, int] = {}
    for c in clusters:
        index.setdefault(c, len(index))
    g = np.fromiter((index[c] for c in clusters), dtype=np.int64, count=len(clusters))
    scores = np.zeros((len(index), X.shape[1]))
    np.add.at(scores, g, X * (y - mu)[:, None])
    n, k, n_g = X.shape[0], X.shape[1], len(index)
    corr = n_g / (n_g - 1) * (n - 1) / (n - k)
    return beta, corr * bread @ (scores.T @ scores) @ bread


def normal_sf(z: float) -> float:
    return 0.5 * math.erfc(z / math.sqrt(2.0))
