"""Etapa 3b (docs/fase1/11_ablacao.md): the SN-hierarchy ablation knobs.

Seed 1000 (Fase 1b pilot range) only: the ablation pilot seeds 7000-7099 are not touched by tests.
"""
from __future__ import annotations

import pytest

from graph.build_sn_graph import SN_LAYERS_KEY, build_sn_graph
from simulation import fase1_ablacao_experiments as A
from simulation import fase1_experiments as F
from simulation import fase1_oficial_experiments as O
from simulation import fase1b_experiments as B
from simulation.damage_model import segment_of
from simulation.experiment import load_config
from simulation.transport import Transport

FAM, SEED = "campaign_e1_e2", 1000


@pytest.fixture(scope="module")
def runs():
    f1 = B.scenario(FAM, SEED, 1)
    table = F.profile_table(F.load_thresholds(), 1)
    return f1, {arm: A.run_arm(arm, f1, "restricted", table) for arm in ("SN", "A1", "A2", "A3")}


def _evaluate(f1, logs, tr):
    params = B.damage_params(f1)
    extra = {**F.instrumentation(f1, logs, params), "crossings_boundary": tr.crossings.get("boundary", 0),
             "crossing_bytes_boundary": tr.crossing_bytes.get("boundary", 0)}
    return B.evaluate(f1, logs, params, {"arm": "SN", **extra})


def test_sn_arm_equals_the_official_sn_arm(runs):
    f1, by_arm = runs
    table = F.profile_table(F.load_thresholds(), 1)
    assert _evaluate(f1, *by_arm["SN"]) == _evaluate(f1, *O.run_arm("SN", f1, "restricted", table))


def _layers(logs):
    return {r["layer"] for r in logs}


def _labels(logs, layer=None):
    return {a.split("(")[0] for r in logs if r["event_type"] == "action_dispatched" and (layer is None or r["layer"] == layer)
            for a in r["payload"]["actions"]}


def test_sn_has_strategic_only_actions(runs):
    _, by_arm = runs
    logs = by_arm["SN"][0]
    assert {"trigger_backup_restore", "segment_network"} <= _labels(logs, "strategic")
    assert not {"trigger_backup_restore", "segment_network"} & (_labels(logs, "specialist") | _labels(logs, "coordinator"))


@pytest.mark.parametrize("arm", ["A1", "A2", "A3"])
def test_no_strategic_and_its_actions_disappear(runs, arm):
    _, by_arm = runs
    logs, tr = by_arm[arm]
    assert "strategic" not in _layers(logs)
    assert not {"trigger_backup_restore", "segment_network"} & _labels(logs)
    assert tr.crossings.get("site", 0) == 0


@pytest.mark.parametrize("arm", ["A2", "A3"])
def test_coordinator_dispatches_nothing(runs, arm):
    _, by_arm = runs
    logs, _ = by_arm[arm]
    assert not [r for r in logs if r["event_type"] == "action_dispatched" and r["layer"] == "coordinator"]
    assert [r for r in logs if r["event_type"] == "advisory"]  # the advisories still work


def test_a2_keeps_the_coordinator_and_the_telemetry_uplink(runs):
    _, by_arm = runs
    logs, tr = by_arm["A2"]
    assert "coordinator" in _layers(logs)
    assert tr.crossings["boundary"] == by_arm["SN"][1].crossings["boundary"]


def test_a3_only_advisories_cross_the_boundary(runs):
    f1, by_arm = runs
    logs, tr = by_arm["A3"]
    params = B.damage_params(f1)
    assert _layers(logs) <= {"specialist"}
    cross = [r for r in logs if r["event_type"] == "advisory"
             and segment_of(r["payload"]["from_host"], params) != segment_of(r["payload"]["to_host"], params)]
    assert cross and tr.crossings["boundary"] == 2 * len(cross)  # up to the relay, down to the specialist
    assert not [r for r in logs if r["event_type"] == "message_sent" and r["layer"] != "specialist"]


def test_a2_and_a3_advise_the_same_hosts(runs):
    _, by_arm = runs
    key = lambda logs: sorted((r["payload"]["from_host"], r["payload"]["to_host"]) for r in logs  # noqa: E731
                              if r["event_type"] == "advisory")
    assert key(by_arm["A2"][0]) == key(by_arm["A3"][0]) == key(by_arm["SN"][0])


def test_graph_and_transport_must_agree():
    from instrumentation.metrics import MetricsLogger
    from knowledge.repository import KnowledgePolicyRepository
    import tempfile, os  # noqa: E401

    f1 = B.scenario(FAM, SEED, 1)
    cfg = load_config(F.SN_CONFIG)
    segs = {h: 0 for h in f1.host_profiles}
    tr = Transport("sn", cfg, F.INTRA, boundary=O.CONDITIONS["restricted"], host_segments=segs,
                   sn_routing=lambda e: ("x", "y"), sn_layers="full")
    repo = KnowledgePolicyRepository()
    repo.update_policy(SN_LAYERS_KEY, "specialist_only", updated_by="test")
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(ValueError):
            build_sn_graph(cfg, repo, MetricsLogger(os.path.join(d, "e.jsonl")), tr, host_profiles=f1.host_profiles)
    with pytest.raises(ValueError):
        Transport("sn", cfg, F.INTRA, boundary=O.CONDITIONS["restricted"], host_segments=segs,
                  sn_routing=lambda e: ("x", "y"), sn_layers="nope")


def test_seeds_are_disjoint_from_every_previous_range():
    previous = (set(range(0, 120)) | set(range(200, 210)) | set(range(300, 400)) | set(range(1000, 1200))
                | set(range(2000, 2200)) | set(range(3000, 3200)) | set(range(4000, 4200)) | set(O.SEEDS) | {7, 42})
    assert A.SEEDS == tuple(range(7000, 7100)) and not previous & set(A.SEEDS)


def test_blocks_cover_the_grid_once():
    cells = [(b["condition"], b["family"], s) for b in A.blocks().values() for s in b["seeds"]]
    assert len(cells) == len(set(cells)) == len(A.LEVELS) * len(A.FAMILIES) * len(A.SEEDS)
