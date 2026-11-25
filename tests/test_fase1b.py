"""Fase 1b (docs/fase1/06_preregistro_1b.md): regression R, mechanisms, determinism, identical knowledge.

R (Fase 8): tests/test_fase1_phase8_regression.py. R (Fase 1): below, a subset of the frozen Fase 1
pilot (results/fase1_pilot/pilot_rows.csv) re-run with every Fase 1b knob at its default.
Diagnostic seeds 300-305 only (never the evaluation seeds 1000-1199 or the sweep seeds).
"""
from __future__ import annotations

import csv
import tempfile

import pytest

from agents.campaign_links import CampaignLinker
from detection.methods import DETECTOR_THRESHOLDS_KEY, HOST_PROFILES_KEY
from simulation import fase1_experiments as F
from simulation import fase1b_experiments as B
from simulation.damage_model import segment_of, simulate
from simulation.fase1 import CAMPAIGN_E1_E2, generate_campaign_e1_e2
from tests.phase8_regression import canonical

PILOT_ROWS = "results/fase1_pilot/pilot_rows.csv"


@pytest.fixture(autouse=True)
def _tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))


# --- R: the frozen Fase 1 pilot is reproduced with every 1b knob at its default --------------------
with open(PILOT_ROWS, encoding="utf-8") as _fh:
    _PILOT = list(csv.DictReader(_fh))


@pytest.mark.parametrize("family", F.FAMILIES)
@pytest.mark.parametrize("h", [0, 1])
@pytest.mark.parametrize("condition", list(F.CONDITIONS))
def test_fase1_pilot_reproduced_exactly(family, h, condition):
    th = F.load_thresholds()
    rows = canonical(F.job_pilot((family, 200, h, condition, th)))
    ref = canonical(r for r in _PILOT if r["family"] == family and r["seed"] == "200" and r["h"] == str(h)
                    and r["condition"] == condition)
    assert ref and rows == ref


# --- mechanisms ----------------------------------------------------------------------------------
def test_link_rule_keeps_named_peers_until_the_source_has_a_signal():
    lk = CampaignLinker()
    ev = lambda peers=(): {"source": "a", "payload": {"peer_hosts": list(peers)}}
    assert lk.observe(ev(["b"]), source_has_signal=False) == []
    assert lk.observe(ev(), source_has_signal=True) == [("a", "b")]
    assert lk.observe(ev(["b"]), source_has_signal=True) == []  # one advisory per link
    assert lk.observe(ev(["c"]), source_has_signal=False) == [("a", "c")]  # a already signalled


def test_campaign_e1_e2_pins_profiles_hides_logon_and_shares_draws_across_h():
    s0, p0 = generate_campaign_e1_e2(300, 0.5, 0)
    s1, p1 = generate_campaign_e1_e2(300, 0.5, 1)
    assert sorted(p0.values()) == ["E1", "E2"] and p0 == p1
    assert len(s0.unobserved) == len(s1.unobserved) == 2
    assert s0.params["t_impact"] == s1.params["t_impact"] and s0.params["precursor"] == s1.params["precursor"]
    assert {e["type"] for e in s1.events} - {e["type"] for e in s0.events} == {"lateral_movement_signature"}
    assert generate_campaign_e1_e2(300, 0.5, 1)[0].events == s1.events


def _run(arm, family, seed, h, condition):
    f1 = B.scenario(family, seed, h)
    logs, tr = B.run_arm(arm, f1, condition, F.profile_table(F.load_thresholds(), h))
    return f1, logs, tr


def test_sn_coordinator_no_longer_acts_on_unflagged_escalations():
    f1, logs, _ = _run("SN", "split_visibility_late_confirm", 301, 1, "restricted")
    coord = [r for r in logs if r["event_type"] == "action_dispatched" and r["payload"]["node"].startswith("coordinator::")]
    assert all(r["payload"]["on_flagged_verdict"] for r in coord)


def test_advisory_crosses_the_boundary_in_sn_and_u1_but_not_b2l():
    for arm in ("SN", "U1"):
        _, logs, _ = _run(arm, CAMPAIGN_E1_E2, 301, 1, "restricted")
        adv = [r for r in logs if r["event_type"] == "advisory"]
        assert adv, arm
        disp = [r for r in logs if r["event_type"] == "action_dispatched" and r["incident_id"] == adv[0]["incident_id"]
                and r["payload"]["event_id"] == adv[0]["payload"]["event_id"]]
        assert disp and disp[0]["payload"]["sim_delay_s"] >= 20.0  # >= 10 s up + 10 s down
    _, logs, _ = _run("B2L", CAMPAIGN_E1_E2, 301, 1, "restricted")
    assert not [r for r in logs if r["event_type"] == "advisory"]


def test_oracle_advisory_costs_only_local_service():
    _, logs, _ = _run("SN", CAMPAIGN_E1_E2, 301, 1, "oracle")
    adv = [r for r in logs if r["event_type"] == "advisory"]
    disp = [r for r in logs if r["event_type"] == "action_dispatched" and r["incident_id"] == adv[0]["incident_id"]
            and r["payload"]["event_id"] == adv[0]["payload"]["event_id"]]
    assert disp[0]["payload"]["sim_delay_s"] < 1.0


def test_no_advisory_and_no_link_at_h0():
    for arm in F.ARMS:
        _, logs, _ = _run(arm, CAMPAIGN_E1_E2, 302, 0, "restricted")
        assert not [r for r in logs if r["event_type"] == "advisory"]


def test_segment_network_is_scoped_and_released():
    for seed in range(300, 306):
        f1, logs, _ = _run("U1", "campaign_multihost", seed, 1, "restricted")
        labels = [a for r in logs if r["event_type"] == "action_dispatched" for a in r["payload"]["actions"]
                  if a.startswith("segment_network(")]
        if labels:
            break
    assert labels and all(a.startswith("segment_network(segment@") for a in labels)
    params = B.damage_params(f1)
    _, net = simulate(f1.scenario, logs, params)
    ivs = [iv for (n, k), v in net.prev.items() if n == "segment_network" for iv in v]
    assert ivs and all(k != "network" for (n, k) in net.prev if n == "segment_network")
    assert all(en <= st + params.segment_network_cap_s + 1e-6 for st, en in ivs)


# --- determinism and identical knowledge -----------------------------------------------------------
def test_same_seed_same_output():
    th = F.load_thresholds()
    a = B.job((CAMPAIGN_E1_E2, 303, 1, "restricted", th, 0.5, "t"))
    b = B.job((CAMPAIGN_E1_E2, 303, 1, "restricted", th, 0.5, "t"))
    assert a and canonical(a) == canonical(b)


@pytest.mark.parametrize("h", [0, 1])
def test_arms_share_thresholds_profiles_and_1b_knobs(h):
    f1 = B.scenario(CAMPAIGN_E1_E2, 300, h)
    table = F.profile_table(F.load_thresholds(), h)
    pol = {arm: B.arm_policies(arm, f1, table) for arm in F.ARMS}
    for key in (DETECTOR_THRESHOLDS_KEY, HOST_PROFILES_KEY, "segment_network_scope", "campaign_links"):
        assert pol["SN"][key] == pol["U1"][key] == pol["B2L"][key]
    assert pol["SN"]["coordinator_precaution"] == "none"


def test_h0_sanity_on_diagnostic_seeds():
    th = F.load_thresholds()
    d = []
    for seed in range(300, 303):
        for fam in B.FAMILIES:
            rows = B.job((fam, seed, 1, "oracle", th, 0.5, "t"))
            by = {(r["incident"], r["arm"]): r["contained_before_impact"] for r in rows}
            d += [by[(i, "SN")] != by[(i, "U1")] for (i, a) in by if a == "SN"]
    assert d and sum(d) == 0
