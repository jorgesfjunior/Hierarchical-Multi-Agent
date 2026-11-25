"""Fase 1, caminho A (docs/fase1/14_preregistro_A.md): driver de E1 (ablação confirmatória) e E2 (multiplicador).

Golden: o driver novo reproduz byte a byte (texto CSV) linhas já publicadas da ablação (seed 7000) e da
fase oficial (seed 5000, m = 1,0). Nenhuma seed de 8000-8699 ou 9000+ é rodada aqui.
"""
from __future__ import annotations

import csv
import os

import pytest

from simulation import fase1_A_experiments as X
from simulation import fase1_experiments as F
from simulation import fase1b_experiments as B

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DROP = {"status", "set", "multiplier"}


def _as_csv(rows, tmp_path):
    path = tmp_path / "rows.csv"
    B.write_csv(str(path), rows)
    with open(path, encoding="utf-8") as fh:
        return [{k: v for k, v in r.items() if k not in DROP} for r in csv.DictReader(fh)]


def _published(path, seed, arms):
    with open(path, encoding="utf-8") as fh:
        return [{k: v for k, v in r.items() if k not in DROP} for r in csv.DictReader(fh)
                if r["seed"] == str(seed) and r["arm"] in arms]


def _sorted(rows):
    """A column absent from a row is written as an empty field by the CSV writer (union of the block's keys)."""
    return sorted(({k: v for k, v in r.items() if v != ""} for r in rows), key=lambda r: (r["arm"], r["incident"]))


def test_e1_reproduces_the_ablation_rows(tmp_path):
    rows, recs = X.job(("E1", "interleaved", 7000, "restricted", None, False))
    mine = _as_csv(rows, tmp_path)
    ref = _published(os.path.join(ROOT, "results", "fase1_ablacao", "raw", "restricted_interleaved.csv"), 7000, X.E1_ARMS)
    assert ref and _sorted(mine) == _sorted(ref)
    assert {r["arm"] for r in recs} == set(X.E1_ARMS)


def test_e2_multiplier_one_reproduces_the_official_rows(tmp_path):
    rows, _ = X.job(("E2", "campaign_e1_e2", 5000, "restricted", 1.0, False))
    mine = [r for r in _as_csv(rows, tmp_path) if r["arm"] in ("SN", "U1", "B2L")]
    ref = _published(os.path.join(ROOT, "results", "fase1_oficial", "raw", "main_h1_restricted_campaign_e1_e2.csv"),
                     5000, ("SN", "U1", "B2L"))
    assert ref and _sorted(mine) == _sorted(ref)
    assert {r["arm"] for r in rows} == set(X.E2_ARMS)


def test_multiplier_one_is_the_frozen_table():
    th = F.load_thresholds()
    assert X.scaled_table(th, 1.0) == F.profile_table(th, 1)
    for key, const in X.CONSTANTS.items():  # the scaling rule itself is the identity at m = 1
        for v in {const} | {row[key] for row in F.profile_table(th, 1).values() if key in row}:
            assert X.scale(key, v, 1.0) == v


def test_multiplier_is_monotone_and_stays_on_the_scale():
    th = F.load_thresholds()
    tables = [X.scaled_table(th, m) for m in X.MULTIPLIERS]
    for p in ("E1", "E2", "E3"):
        for key, const in X.CONSTANTS.items():
            vals = [t[p].get(key, const) for t in tables]
            assert vals == sorted(vals), (p, key, vals)
            assert min(vals) > 0
            if key in X.BOUNDED_MAX:
                assert max(vals) < X.BOUNDED_MAX[key]
            if key == "min_corroborating":
                assert max(vals) <= X.CORROBORATORS


def test_seeds_are_new_and_disjoint():
    used = set(range(0, 5500)) | set(range(7000, 7100)) | {7, 42}
    e1, e2, pilot = set(X.E1_SEEDS), set(X.E2_SEEDS), set(X.PILOT_SEEDS)
    assert (min(e1), max(e1), min(e2), max(e2), min(pilot), max(pilot)) == (8000, 8499, 8500, 8699, 9000, 9019)
    assert not (e1 | e2 | pilot) & used
    assert not e1 & e2 and not (e1 | e2) & pilot


@pytest.mark.parametrize("pilot", [False, True])
def test_blocks_cover_the_grid_once(pilot):
    seen = []
    for spec in X.blocks(pilot).values():
        key = spec["condition"] if spec["exp"] == "E1" else spec["multiplier"]
        seen += [(spec["exp"], key, spec["family"], s) for s in spec["seeds"]]
    s1, s2 = (X.PILOT_SEEDS, X.PILOT_SEEDS) if pilot else (X.E1_SEEDS, X.E2_SEEDS)
    want = [("E1", c, f, s) for c in X.E1_LEVELS for f in X.FAMILIES for s in s1]
    want += [("E2", m, f, s) for m in X.MULTIPLIERS for f in X.FAMILIES for s in s2]
    assert sorted(seen, key=str) == sorted(want, key=str)


# --- análise (analysis/fase1_A.py) ----------------------------------------------------------------
def test_tost_zero_difference_gives_the_smallest_p():
    import numpy as np
    from analysis import fase1_A as AN
    t = AN.tost(np.zeros(AN.N_BOOT), 0.01)
    assert t["p_tost"] == 1 / (AN.N_BOOT + 1) and t["equivalent"] and t["reading"] == "equivalente"


def test_tost_readings_in_both_directions():
    import numpy as np
    from analysis import fase1_A as AN
    rng = np.random.default_rng(1)
    assert AN.tost(rng.normal(-0.05, 0.002, AN.N_BOOT), 0.01)["reading"] == "A3 protege menos"
    assert AN.tost(rng.normal(+0.05, 0.002, AN.N_BOOT), 0.01)["reading"] == "A3 protege mais"
    t = AN.tost(rng.normal(0.0, 0.01, AN.N_BOOT), 0.01)
    assert t["reading"] == "inconclusivo" and not t["equivalent"]


def test_paired_bootstrap_pools_units_by_cluster():
    import numpy as np
    from analysis import fase1_A as AN
    d = AN.paired_bootstrap([1, 1, 2], [1.0, 1.0, 0.0])
    assert set(np.round(d, 6)) <= {0.0, 1.0, round(2 / 3, 6), 0.5}  # 2 units of cluster 1, 1 of cluster 2
    assert AN.paired_bootstrap([1, 2, 3], [0.0, 0.0, 0.0]).max() == 0.0


def test_mcnemar_two_sided():
    from analysis import fase1_A as AN
    assert AN.mcnemar_two_sided(0, 0) == 1.0
    assert AN.mcnemar_two_sided(5, 0) == 2 / 32
    assert AN.mcnemar_two_sided(3, 3) == 1.0
