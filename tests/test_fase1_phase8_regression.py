"""Fase 1 guard: with every new knob at its default, the simulator must reproduce the Phase 8 pilot
EXACTLY (seeds 0-2; units and fixture provenance in ``tests/phase8_regression.py``).

Each unit re-runs one Phase 8 job function (P1-P5) and compares its canonical rows with the rows the
EXPLORATORY pilot wrote to ``results/phase8_pilot/exp_*.csv``. About 10 s in total.
"""
from __future__ import annotations

import json
import tempfile

import pytest

from tests.phase8_regression import FIXTURE_PATH, canonical, digest, job

with open(FIXTURE_PATH, encoding="utf-8") as _fh:
    FIXTURE = json.load(_fh)


def test_fixture_covers_every_phase8_experiment_and_three_seeds():
    assert FIXTURE["seeds"] == [0, 1, 2]
    assert {u["exp"] for u in FIXTURE["units"]} == {"p1", "p2", "p3", "p4", "p5"}
    assert all(u["n_rows"] > 0 for u in FIXTURE["units"])


@pytest.mark.parametrize("unit", FIXTURE["units"], ids=[u["id"] for u in FIXTURE["units"]])
def test_phase8_unit_reproduces_pilot_exactly(unit, tmp_path, monkeypatch):
    # run_generated() writes each run's log to tempfile.mkdtemp() and never removes it.
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    rows = canonical(job(unit["exp"])(tuple(unit["args"])))
    if "rows" in unit:
        expected = unit["rows"]
        missing = [r for r in expected if r not in rows]
        extra = [r for r in rows if r not in expected]
        assert not missing and not extra, (
            f"{unit['id']}: {len(missing)} pilot row(s) not reproduced, {len(extra)} new row(s).\n"
            f"first missing: {missing[:1]}\nfirst new:     {extra[:1]}")
    assert len(rows) == unit["n_rows"], f"{unit['id']}: {len(rows)} rows, pilot had {unit['n_rows']}"
    assert digest(rows) == unit["sha256"], f"{unit['id']}: rows differ from the Phase 8 pilot"
