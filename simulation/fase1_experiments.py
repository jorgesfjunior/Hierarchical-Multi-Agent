"""Fase 1 driver: arms SN / U1 / B2-SSL-local x heterogeneity x boundary constraint (EXPLORATORY).

Pre-registration (frozen): docs/fase1/02_preregistro.md, docs/fase1/02_preregistro.freeze.json.

    python3 simulation/fase1_experiments.py calibrate     # seeds 100-119 -> config/fase1/thresholds_by_profile.yaml
    python3 simulation/fase1_experiments.py pilot         # seeds 200-209 -> results/fase1_pilot/
    python3 simulation/fase1_experiments.py analyze       # table + decision per the frozen rule

All three arms read the detector thresholds from the SAME table (policy
``detector_thresholds_by_profile``, loaded from ``THRESHOLDS_PATH``) and the same host-profile map.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from multiprocessing import Pool
from typing import Any, Optional

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

import yaml  # noqa: E402

from agents.mape import DELEGATED  # noqa: E402
from agents.mitigation import PREVENTIVE_ACTIONS, parse_action_label  # noqa: E402
from baselines.mape_k_monolithic.loop import SINGLE_SIGNAL_KEY  # noqa: E402
from detection.methods import DETECTOR_THRESHOLDS_KEY, HOST_PROFILES_KEY  # noqa: E402
from graph.build_sn_graph import sn_router  # noqa: E402
from simulation.damage_model import scenario_clock, segment_of  # noqa: E402
from simulation.experiment import add_keep_tmp_arg, apply_keep_tmp_arg, load_config, run_generated  # noqa: E402
from simulation.fase1 import PROFILE_SEGMENT, PROFILES, Fase1Config, Fase1Scenario, apply  # noqa: E402
from simulation.phase8_experiments import evaluate, no_defense_rows, write_csv  # noqa: E402
from simulation.scenario_generator import generate  # noqa: E402
from simulation.transport import Boundary, CostModel, Transport  # noqa: E402

EXPLORATORY = "EXPLORATORY"
SN_CONFIG = "fase1/domains_sn"
THRESHOLDS_PATH = os.path.join(_BASE_DIR, "config", "fase1", "thresholds_by_profile.yaml")
ARMS = ("SN", "U1", "B2L")  # B2L = B2-SSL-local
ARCH = {"SN": "sn", "U1": "b1", "B2L": "b2local"}
CONDITIONS = {"oracle": Boundary(), "restricted": Boundary(latency_s=10.0, batch_s=60.0, bandwidth_bytes_per_s=32 * 1024)}
FAMILIES = ("encryption_stream", "campaign_multihost", "split_visibility_late_confirm", "interleaved")
CALIBRATION_SEEDS, EVALUATION_SEEDS = tuple(range(100, 120)), tuple(range(200, 210))
GRID = {
    "E1": {"entropy_high_bits": (7.0, 7.5, 7.8), "min_corroborating": (1, 2, 3)},
    "E2": {"entropy_high_bits": (7.0, 7.5, 7.8), "exposure_min_severity": (5.0, 7.0, 9.0)},
    "E3": {"recon_hosts_per_second": (0.25, 0.5, 1.0), "c2_min_beacons": (2, 3, 5)},
}
UNAVAILABILITY_CAP = 0.05
E_PRIMARY, R_INH_PRIMARY = 0.50, 0.43
INTRA = CostModel(local_latency_s=0.001, service_time_s=0.01)


# --- thresholds ----------------------------------------------------------------------------------
def load_thresholds(path: str = THRESHOLDS_PATH) -> dict[str, dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    return {k: dict(doc.get(k) or {}) for k in ("homogeneous",) + PROFILES}


def profile_table(thresholds: dict[str, dict[str, Any]], heterogeneity: int) -> dict[str, dict[str, Any]]:
    """h = 0: every profile uses the homogeneous row (the detector constants); h = 1: its own row."""
    return {p: dict(thresholds["homogeneous" if heterogeneity == 0 else p]) for p in PROFILES}


def arm_policies(arm: str, f1: Fase1Scenario, table: dict[str, dict[str, Any]]) -> dict[str, Any]:
    common = {"damage_model": True, "detection_method": "legacy_weighted", "playbook_version": 1,
              "preventive_actions": list(PREVENTIVE_ACTIONS),
              HOST_PROFILES_KEY: dict(f1.host_profiles), DETECTOR_THRESHOLDS_KEY: table}
    if arm == "SN":
        return {**common, **DELEGATED}
    return {**common, SINGLE_SIGNAL_KEY: True}  # U1 = B1-SSL, B2L = B2-SSL-local


def run_arm(arm: str, f1: Fase1Scenario, condition: str, table) -> list[dict[str, Any]]:
    arch = ARCH[arm]
    host_segments = {h: PROFILE_SEGMENT[p] for h, p in f1.host_profiles.items()}
    cfg = load_config(SN_CONFIG) if arm == "SN" else None
    tr = Transport(arch, cfg, INTRA, boundary=CONDITIONS[condition], host_segments=host_segments,
                   sn_routing=sn_router(cfg, f1.host_profiles) if arm == "SN" else None)
    _, logs, _ = run_generated(arch, f1.scenario, domain_config=cfg, policies=arm_policies(arm, f1, table),
                               transport=tr, return_logs=True, host_profiles=f1.host_profiles)
    return logs, tr


# --- item-9 instrumentation ------------------------------------------------------------------------
def instrumentation(f1: Fase1Scenario, logs: list[dict[str, Any]], params) -> dict[str, Any]:
    sc = f1.scenario
    _, true_t, clock = scenario_clock(sc)
    source = {e["event_id"]: e["source"] for e in sc.events}
    truth = sc.truth
    benign_keys = {i["incident_key"] for i in truth["incidents"].values() if not i["malicious"]}
    impact_by_host = defaultdict(lambda: float("inf"))
    for t in truth["events"]:
        if t["malicious"] and t["stage"] == "impact":
            h = truth["incidents"][t["true_incident_id"]]["host"]
            impact_by_host[h] = min(impact_by_host[h], true_t[t["event_id"]])
    campaign_of = {i["host"]: i.get("campaign", iid) for iid, i in truth["incidents"].items() if i["malicious"]}
    local = Counter()
    fp_hosts, cross, cross_before, cross_applicable = set(), 0, 0, 0
    for r in logs:
        if r["event_type"] != "action_dispatched":
            continue
        p = r["payload"]
        node = p.get("node", "")
        if node.startswith(("specialist::", "b2local::")):
            local[node] += 1
        if r["incident_id"] in benign_keys and p["actions"]:
            fp_hosts.add(r["incident_id"])
        trig = source.get(p["event_id"])
        if trig is None:
            continue
        arrival = clock[p["event_id"]] + float(p.get("sim_delay_s") or 0.0)
        seg = segment_of(trig, params)
        for label in p["actions"]:
            name, target = parse_action_label(label)
            covers = (name == "segment_network") or (target.startswith("segment@") and segment_of(target[8:], params) != seg)
            if not (covers and name in PREVENTIVE_ACTIONS):
                continue
            cross += 1
            others = [impact_by_host[h] for h, c in campaign_of.items()
                      if c == campaign_of.get(trig) and segment_of(h, params) != seg and impact_by_host[h] < float("inf")]
            if others:
                cross_applicable += 1
                cross_before += arrival < min(others)
    return {"local_decisions_total": sum(local.values()), "local_decisions": json.dumps(dict(sorted(local.items()))),
            "cross_segment_preventive": cross, "cross_segment_with_other_segment_impact": cross_applicable,
            "cross_segment_before_impact": cross_before, "fp_benign_hosts": len(fp_hosts),
            "benign_hosts": len(benign_keys)}


# --- jobs -----------------------------------------------------------------------------------------
def damage_params(f1: Fase1Scenario):
    return f1.damage_params(prevention_effectiveness=E_PRIMARY, inhibited_restorable_fraction=R_INH_PRIMARY)


def job_pilot(args) -> list[dict[str, Any]]:
    family, seed, h, condition, thresholds = args
    f1 = apply(generate(family, seed), Fase1Config(heterogeneity=h))
    params, table = damage_params(f1), profile_table(thresholds, h)
    head = {"status": EXPLORATORY, "family": family, "seed": seed, "h": h, "condition": condition}
    rows = no_defense_rows(f1.scenario, params, {**head, "arm": "NO-DEFENSE"}) if condition == "oracle" else []
    for arm in ARMS:
        logs, tr = run_arm(arm, f1, condition, table)
        extra = {**instrumentation(f1, logs, params), "crossings_boundary": tr.crossings.get("boundary", 0),
                 "crossing_bytes_boundary": tr.crossing_bytes.get("boundary", 0),
                 "messages_sent": sum(1 for r in logs if r["event_type"] == "message_sent")}
        rows += evaluate(f1.scenario, logs, params, {**head, "arm": arm, **extra})
    return rows


def job_calibrate(args) -> dict[str, Any]:
    profile, point, family, seed, thresholds = args
    table = profile_table(thresholds, 1)
    table[profile] = {**table[profile], **point}
    f1 = apply(generate(family, seed), Fase1Config(heterogeneity=1))
    params = damage_params(f1)
    logs, _ = run_arm("U1", f1, "oracle", table)
    rows = evaluate(f1.scenario, logs, params, {})
    unavail = rows[0]["unavailability_fraction"] if rows else None
    if unavail is None:  # no malicious campaign: availability still defined on the run
        from simulation.damage_model import availability, simulate

        outcomes, net = simulate(f1.scenario, logs, params)
        unavail = availability(net, outcomes, params, (0.0, params.horizon_s))["unavailability_fraction"]
    return {"profile": profile, "point": json.dumps(point, sort_keys=True), "family": family, "seed": seed,
            "losses": [r["data_loss_per_host"] for r in rows], "unavailability": unavail}


def calibrate(workers: int, out_path: str = THRESHOLDS_PATH) -> dict[str, Any]:
    base = {"homogeneous": {}, **{p: {} for p in PROFILES}}
    jobs = [(p, dict(zip(GRID[p], vals)), f, s, base) for p in PROFILES
            for vals in itertools.product(*GRID[p].values()) for f in FAMILIES for s in CALIBRATION_SEEDS]
    with Pool(workers) as pool:
        res = pool.map(job_calibrate, jobs, chunksize=4)
    chosen, report = {}, []
    for p in PROFILES:
        cands = []
        for point in sorted({r["point"] for r in res if r["profile"] == p}):
            rs = [r for r in res if r["profile"] == p and r["point"] == point]
            losses = [x for r in rs for x in r["losses"]]
            loss = sum(losses) / len(losses)
            unavail = sum(r["unavailability"] for r in rs) / len(rs)
            cands.append((point, loss, unavail))
            report.append({"profile": p, "point": point, "mean_data_loss_per_host": loss, "mean_unavailability": unavail})
        ok = [c for c in cands if c[2] <= UNAVAILABILITY_CAP] or cands
        best = min(ok, key=lambda c: (c[1], c[2]))
        chosen[p] = json.loads(best[0])
    header = (
        "# Fase 1 per-profile DETECTOR thresholds, read by every arm (SN, U1, B2-SSL-local).\n"
        "# GENERATED by: python3 simulation/fase1_experiments.py calibrate (do not edit by hand)\n"
        f"# Calibration: U1 (B1-SSL), heterogeneity 1, oracle; seeds {CALIBRATION_SEEDS[0]}-{CALIBRATION_SEEDS[-1]}; "
        f"families {', '.join(FAMILIES)}.\n"
        f"# Objective: min mean data_loss_per_host s.t. mean unavailability_fraction <= {UNAVAILABILITY_CAP}; "
        "ties -> lower unavailability.\n"
        "# 'homogeneous' (heterogeneity 0) = the detector constants. Keys not listed = the constants.\n"
    )
    doc = {"homogeneous": {}, **chosen}
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(header + yaml.safe_dump(doc, sort_keys=True))
    os.makedirs(os.path.join(_BASE_DIR, "results", "fase1_calibration"), exist_ok=True)
    write_csv(os.path.join(_BASE_DIR, "results", "fase1_calibration", "grid.csv"), report)
    with open(out_path, "rb") as fh:
        sha = hashlib.sha256(fh.read()).hexdigest()
    meta = {"command": "python3 simulation/fase1_experiments.py calibrate", "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "seeds": list(CALIBRATION_SEEDS), "families": list(FAMILIES), "grid": GRID, "chosen": chosen,
            "thresholds_sha256": sha}
    with open(os.path.join(_BASE_DIR, "results", "fase1_calibration", "meta.json"), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=1, sort_keys=True)
    return meta


def pilot(workers: int, out_dir: str) -> str:
    thresholds = load_thresholds()
    jobs = [(f, s, h, c, thresholds) for f in FAMILIES for s in EVALUATION_SEEDS for h in (0, 1) for c in CONDITIONS]
    with Pool(workers) as pool:
        rows = [r for chunk in pool.imap_unordered(job_pilot, jobs, chunksize=1) for r in chunk]
    rows.sort(key=lambda r: (r["family"], r["seed"], r["h"], r["condition"], r["arm"], r["incident"]))
    path = os.path.join(out_dir, "pilot_rows.csv")
    write_csv(path, rows)
    return path


# --- analysis (frozen decision rule, docs/fase1/02_preregistro.md §7) ------------------------------
M = 1000.0


def _f(x):
    return None if x in (None, "") else float(x)


def analyze(rows_path: str, out_dir: str) -> list[dict[str, Any]]:
    from analysis.stats import bootstrap_ci

    with open(rows_path, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    loss = {(r["family"], r["seed"], r["h"], r["condition"], r["arm"], r["incident"]): _f(r["data_loss_per_host"]) for r in rows}
    unav = {}
    for r in rows:
        unav.setdefault((r["family"], r["seed"], r["h"], r["condition"], r["arm"]), _f(r["unavailability_fraction"]))
    out = []
    for h in ("0", "1"):
        for cond in CONDITIONS:
            for arm in ARMS:
                v = [x for (f, s, hh, c, a, i), x in loss.items() if hh == h and c == cond and a == arm]
                lo, hi = bootstrap_ci(v)
                u = [x for (f, s, hh, c, a), x in unav.items() if hh == h and c == cond and a == arm]
                fp = [int(r["fp_benign_hosts"]) for r in rows if r["h"] == h and r["condition"] == cond and r["arm"] == arm]
                out.append({"status": EXPLORATORY, "kind": "arm", "h": h, "condition": cond, "arm": arm, "n": len(v),
                            "mean_data_loss_per_host": sum(v) / len(v), "ci_lo": lo, "ci_hi": hi,
                            "mean_unavailability": sum(u) / len(u), "mean_fp_benign_hosts_per_campaign_row": sum(fp) / len(fp)})
            for other, name in (("U1", "delta_U1_minus_SN"), ("B2L", "delta_B2L_minus_SN")):
                keys = [(f, s, hh, c, i) for (f, s, hh, c, a, i) in loss if hh == h and c == cond and a == "SN"]
                d = [loss[(f, s, hh, c, other, i)] - loss[(f, s, hh, c, "SN", i)] for (f, s, hh, c, i) in keys]
                du = [unav[(f, s, hh, c, "SN")] - unav[(f, s, hh, c, other)] for (f, s, hh, c) in
                      sorted({k[:4] for k in keys})]
                mean = sum(d) / len(d)
                lo, hi = bootstrap_ci(d)
                if mean >= M and lo > 0 and sum(du) / len(du) <= 0.05:
                    verdict = "SN ganhou"
                elif -M <= lo and hi <= M:
                    verdict = "empate"
                elif mean <= -M and hi < 0:
                    verdict = f"{other} ganhou"
                else:
                    verdict = "inconclusivo"
                out.append({"status": EXPLORATORY, "kind": name, "h": h, "condition": cond, "arm": f"{other} - SN",
                            "n": len(d), "mean_data_loss_per_host": mean, "ci_lo": lo, "ci_hi": hi,
                            "mean_unavailability": sum(du) / len(du), "verdict": verdict,
                            "nonzero_pairs": sum(1 for x in d if x != 0)})
    write_csv(os.path.join(out_dir, "pilot_table.csv"), out)
    return out


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("calibrate", "pilot", "analyze"):
        sp = sub.add_parser(name)
        sp.add_argument("--workers", type=int, default=os.cpu_count() or 1)
        sp.add_argument("--out", default=os.path.join(_BASE_DIR, "results", "fase1_pilot"))
        add_keep_tmp_arg(sp)
    args = parser.parse_args(argv)
    apply_keep_tmp_arg(args)
    os.makedirs(args.out, exist_ok=True)
    if args.cmd == "calibrate":
        print(json.dumps(calibrate(args.workers), indent=1))
    elif args.cmd == "pilot":
        print(pilot(args.workers, args.out))
    else:
        for r in analyze(os.path.join(args.out, "pilot_rows.csv"), args.out):
            print(r)


if __name__ == "__main__":
    main()
