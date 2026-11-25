"""Fase 1 official run (docs/fase1/08_preregistro_oficial.md): precondition R (c), F2 levels, seeds and
the statistics of §7.

R (c): the official driver reproduces the frozen Fase 1b pilot (results/fase1b_pilot/pilot_rows_*.csv)
exactly, seed 1000 of every family x h x condition. R (a) and R (b) are
tests/test_fase1_phase8_regression.py and tests/test_fase1b.py.
"""
from __future__ import annotations

import csv
import math
import tempfile

import numpy as np
import pytest

from analysis.fase1_oficial_stats import cluster_bootstrap, logit_cluster, mcnemar_exact_one_sided
from simulation import fase1_experiments as F
from simulation import fase1_oficial_experiments as O
from simulation import fase1b_experiments as B
from simulation.fase1 import P_PRE
from tests.phase8_regression import canonical


@pytest.fixture(autouse=True)
def _tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))


# --- R (c): Fase 1b pilot reproduced by the official driver ----------------------------------------
@pytest.mark.parametrize("family", B.FAMILIES)
@pytest.mark.parametrize("h", [0, 1])
@pytest.mark.parametrize("condition", ["oracle", "restricted"])
def test_fase1b_pilot_reproduced_exactly_by_official_driver(family, h, condition):
    rows = canonical(O.job((family, 1000, h, condition, F.load_thresholds(), P_PRE, "evaluation", F.ARMS, "EXPLORATORY")))
    with open(f"results/fase1b_pilot/pilot_rows_h{h}_{condition}.csv", encoding="utf-8") as fh:
        ref = canonical(r for r in csv.DictReader(fh) if r["family"] == family and r["seed"] == "1000")
    assert ref and rows == ref


# --- F2 levels and seeds -----------------------------------------------------------------------------
def test_f2_levels_change_only_the_batch_window():
    assert O.CONDITIONS["oracle"] is F.CONDITIONS["oracle"] and O.CONDITIONS["restricted"] is F.CONDITIONS["restricted"]
    r = F.CONDITIONS["restricted"]
    assert (r.latency_s, r.batch_s, r.bandwidth_bytes_per_s) == (10.0, 60.0, 32 * 1024)
    for name, batch in (("batch5m", 300.0), ("batch15m", 900.0)):
        b = O.CONDITIONS[name]
        assert (b.latency_s, b.batch_s, b.bandwidth_bytes_per_s) == (r.latency_s, batch, r.bandwidth_bytes_per_s)
    assert O.LEVELS == ("oracle", "restricted", "batch5m", "batch15m")


def test_seeds_are_disjoint_from_every_previous_range():
    previous = set(range(0, 400)) | set(B.EVALUATION_SEEDS) | {s for v in B.SWEEP.values() for s in v} | {7, 42}
    assert O.SEEDS == tuple(range(5000, 5500)) and not previous & set(O.SEEDS)


def test_block_grid_matches_the_preregistration():
    bl = O.blocks()
    assert len(bl) == 20 + 10 + 3 + 3 * 2  # campaign_multihost h = 1 (restricted, 5 min, 15 min) in 3 parts
    parts = [n for n in bl if n.startswith("main_h1_restricted_campaign_multihost_part")]
    assert sum((O.block_seeds(bl[n], False) for n in parts), ()) == O.SEEDS
    assert sum(O.stage(n) == "pre" for n in bl) == 11
    assert {b["condition"] for b in bl.values() if b["set"] == "fronteira"} == {"batch5m", "batch15m"}
    assert all(b["h"] == 1 for b in bl.values() if b["set"] != "principal")
    assert {b["arms"] for b in bl.values() if b["set"].startswith("p_pre")} == {("SN", "B2L")}


# --- statistics ----------------------------------------------------------------------------------------
def test_mcnemar_exact_one_sided():
    assert mcnemar_exact_one_sided(5, 0) == 1 / 32
    assert mcnemar_exact_one_sided(0, 0) == 1.0
    assert mcnemar_exact_one_sided(3, 3) == 42 / 64
    assert mcnemar_exact_one_sided(0, 4) == 1.0


def test_cluster_bootstrap_is_deterministic_and_pools_by_cluster():
    cl, v = [1, 1, 2, 3], [1.0, 1.0, 0.0, 1.0]
    a, b = cluster_bootstrap(cl, v, n_boot=500), cluster_bootstrap(cl, v, n_boot=500)
    assert np.array_equal(a, b)
    assert np.all(cluster_bootstrap([1, 2, 3], [0.5, 0.5, 0.5], n_boot=50) == 0.5)
    assert abs(a.mean() - 0.75) < 0.05  # pooled: cluster 1 carries 2 units


def test_logit_cluster_recovers_saturated_log_odds():
    # 2 x 2 design: p(x=0, g=0) = 0.5, p(1, 0) = 0.8, p(0, 1) = 0.25, p(1, 1) = 0.9
    cells = {(0, 0): (5, 10), (1, 0): (8, 10), (0, 1): (5, 20), (1, 1): (18, 20)}
    X, y, cl = [], [], []
    for (x, g), (k, n) in cells.items():
        for i in range(n):
            X.append([1.0, x, g, x * g])
            y.append(1.0 if i < k else 0.0)
            cl.append(len(cl))
    beta, cov = logit_cluster(np.array(X), np.array(y), cl)
    lo = lambda p: math.log(p / (1 - p))
    assert np.allclose(beta, [lo(0.5), lo(0.8) - lo(0.5), lo(0.25) - lo(0.5),
                              lo(0.9) - lo(0.25) - lo(0.8) + lo(0.5)], atol=1e-8)
    assert np.allclose(cov, cov.T) and np.all(np.diag(cov) > 0)
