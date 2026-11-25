"""Fase 1b driver: SN / U1 / B2-SSL-local with equal precaution, scoped segment_network and campaign
advisories, 4 Fase 1 families + campaign_e1_e2 (EXPLORATORY).

Pre-registration (frozen): docs/fase1/06_preregistro_1b.md, docs/fase1/06_preregistro_1b.freeze.json.

    python3 simulation/fase1b_experiments.py pilot --cell 1:restricted   # one condition per command
    python3 simulation/fase1b_experiments.py sweep                       # descriptive p_pre sweep
    python3 simulation/fase1b_experiments.py analyze

Thresholds: the SAME config/fase1/thresholds_by_profile.yaml as Fase 1 (no recalibration).
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import statistics
import sys
from collections import defaultdict
from multiprocessing import Pool
from typing import Any, Optional

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from agents.campaign_links import ADVISORY_EVENT  # noqa: E402
from agents.mitigation import parse_action_label  # noqa: E402
from graph.build_sn_graph import sn_router  # noqa: E402
from simulation import fase1_experiments as F  # noqa: E402
from simulation.damage_model import availability, prevention_outcomes, scenario_clock, segment_of, simulate  # noqa: E402
from simulation.experiment import add_keep_tmp_arg, apply_keep_tmp_arg, load_config, run_generated  # noqa: E402
from simulation.fase1 import CAMPAIGN_E1_E2, P_PRE, PROFILE_SEGMENT, Fase1Config, Fase1Scenario, apply, apply_campaign_e1_e2  # noqa: E402
from simulation.phase8_experiments import write_csv  # noqa: E402
from simulation.scenario_generator import generate  # noqa: E402
from simulation.transport import Transport  # noqa: E402

EXPLORATORY = "EXPLORATORY"
FAMILIES = F.FAMILIES + (CAMPAIGN_E1_E2,)
EVALUATION_SEEDS = tuple(range(1000, 1200))
SWEEP = {0.2: tuple(range(2000, 2200)), 0.5: tuple(range(3000, 3200)), 0.8: tuple(range(4000, 4200))}
KNOBS_1B = {"segment_network_scope": "incident_segments", "campaign_links": True}
SEGNET_CAP_S = 3600.0
MP, M, UNAV = 0.10, 1000.0, 0.05


def scenario(family: str, seed: int, h: int, p_pre: float = P_PRE) -> Fase1Scenario:
    cfg = Fase1Config(heterogeneity=h, admin_connections=True)
    if family == CAMPAIGN_E1_E2:
        return apply_campaign_e1_e2(seed, cfg, p_pre)
    return apply(generate(family, seed), cfg)


def arm_policies(arm: str, f1: Fase1Scenario, table) -> dict[str, Any]:
    pol = {**F.arm_policies(arm, f1, table), **KNOBS_1B}
    if arm == "SN":
        pol["coordinator_precaution"] = "none"
    return pol


def run_arm(arm: str, f1: Fase1Scenario, condition: str, table):
    arch = F.ARCH[arm]
    host_segments = {h: PROFILE_SEGMENT[p] for h, p in f1.host_profiles.items()}
    cfg = load_config(F.SN_CONFIG) if arm == "SN" else None
    tr = Transport(arch, cfg, F.INTRA, boundary=F.CONDITIONS[condition], host_segments=host_segments,
                   sn_routing=sn_router(cfg, f1.host_profiles) if arm == "SN" else None)
    _, logs, _ = run_generated(arch, f1.scenario, domain_config=cfg, policies=arm_policies(arm, f1, table),
                               transport=tr, return_logs=True, host_profiles=f1.host_profiles)
    return logs, tr


def damage_params(f1: Fase1Scenario):
    return f1.damage_params(prevention_effectiveness=F.E_PRIMARY, inhibited_restorable_fraction=F.R_INH_PRIMARY,
                            segment_network_release="containment", segment_network_cap_s=SEGNET_CAP_S)


def mechanism(f1: Fase1Scenario, logs, net, params) -> dict[str, Any]:
    """06_preregistro_1b.md §6 (on top of the Fase 1 counters)."""
    sc, truth = f1.scenario, f1.scenario.truth
    _, true_t, clock = scenario_clock(sc)
    benign_hosts = {i["host"] for i in truth["incidents"].values() if not i["malicious"]}
    impact = defaultdict(lambda: float("inf"))
    for t in truth["events"]:
        if t["malicious"] and t["stage"] == "impact":
            h = truth["incidents"][t["true_incident_id"]]["host"]
            impact[h] = min(impact[h], true_t[t["event_id"]])
    adv = [r for r in logs if r["event_type"] == ADVISORY_EVENT]
    keys = {(r["incident_id"], r["payload"]["event_id"]) for r in adv}
    arrivals = {}
    for r in logs:
        p = r["payload"]
        if r["event_type"] == "action_dispatched" and (r["incident_id"], p.get("event_id")) in keys and p["actions"] \
                and p["actions"][0].startswith("isolate_host("):
            arrivals.setdefault((r["incident_id"], p["event_id"]), (clock[p["event_id"]] + float(p.get("sim_delay_s") or 0.0),
                                                                    float(p.get("sim_delay_s") or 0.0)))
    crossed = before = after = no_impact = false = 0
    latencies = []
    for r in adv:
        a, b = r["payload"]["from_host"], r["payload"]["to_host"]
        crossed += segment_of(a, params) != segment_of(b, params)
        false += b in benign_hosts
        arr = arrivals.get((r["incident_id"], r["payload"]["event_id"]))
        if arr is None:
            continue
        latencies.append(arr[1])
        if impact[b] == float("inf"):
            no_impact += 1
        elif arr[0] < impact[b]:
            before += 1
        else:
            after += 1
    segnet = [(k, ivs) for (n, k), ivs in net.prev.items() if n == "segment_network"]
    durations = [min(en, params.horizon_s) - st for _, ivs in segnet for st, en in ivs]
    return {"advisories": len(adv), "advisories_crossing": crossed, "advisories_local": len(adv) - crossed,
            "advisories_false": false, "advisory_latency_mean_s": statistics.mean(latencies) if latencies else None,
            "advised_action_before_impact": before, "advised_action_after_impact": after,
            "advised_action_no_impact": no_impact, "segnet_keys": json.dumps(sorted(str(k) for k, _ in segnet)),
            "segnet_intervals": len(durations), "segnet_duration_s_total": sum(durations)}


def evaluate(f1: Fase1Scenario, logs, params, base) -> list[dict[str, Any]]:
    sc = f1.scenario
    outcomes, net = simulate(sc, logs, params)
    prev = prevention_outcomes(sc, logs, outcomes)
    avail = availability(net, outcomes, params, (0.0, params.horizon_s))
    mech = mechanism(f1, logs, net, params) if base.get("arm") != "NO-DEFENSE" else {}
    rows = []
    for key, o in outcomes.items():
        rows.append({**base, "incident": key.split("::")[-1], "impact_started": o.impact_started,
                     "contained_before_impact": not o.impact_started, "data_loss": o.data_loss,
                     "data_loss_per_host": o.data_loss / max(o.hosts_compromised, 1), "files_encrypted": o.files_encrypted,
                     "hosts_compromised": o.hosts_compromised, "observed_hosts": o.observed_hosts_compromised,
                     "prevented_moves": o.prevented_moves, "contained": o.contained, **prev[key], **avail, **mech})
    return rows


def job(args) -> list[dict[str, Any]]:
    family, seed, h, condition, thresholds, p_pre, tag = args
    f1 = scenario(family, seed, h, p_pre)
    params, table = damage_params(f1), F.profile_table(thresholds, h)
    head = {"status": EXPLORATORY, "set": tag, "family": family, "seed": seed, "h": h, "condition": condition, "p_pre": p_pre}
    rows = evaluate(f1, [], params, {**head, "arm": "NO-DEFENSE"}) if condition == "oracle" else []
    for arm in F.ARMS:
        logs, tr = run_arm(arm, f1, condition, table)
        extra = {**F.instrumentation(f1, logs, params), "crossings_boundary": tr.crossings.get("boundary", 0),
                 "crossing_bytes_boundary": tr.crossing_bytes.get("boundary", 0)}
        rows += evaluate(f1, logs, params, {**head, "arm": arm, **extra})
    return rows


def run_jobs(jobs, workers: int, path: str) -> str:
    with Pool(workers) as pool:
        rows = [r for chunk in pool.imap_unordered(job, jobs, chunksize=2) for r in chunk]
    rows.sort(key=lambda r: (r["family"], r["seed"], r["h"], r["condition"], r["arm"], r["incident"]))
    write_csv(path, rows)
    return path


# --- analysis (06_preregistro_1b.md §7) -------------------------------------------------------------
def _truthy(x) -> bool:
    return str(x) == "True"


def _load(paths):
    rows = []
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            rows += list(csv.DictReader(fh))
    return rows


def compare(rows, families, h, cond, other, metric="p") -> dict[str, Any]:
    from analysis.stats import bootstrap_ci

    sel = [r for r in rows if r["family"] in families and r["h"] == str(h) and r["condition"] == cond and r["arm"] != "NO-DEFENSE"]
    val = {}
    for r in sel:
        v = float(_truthy(r["contained_before_impact"])) if metric == "p" else float(r["data_loss_per_host"])
        val[(r["family"], r["seed"], r["incident"], r["arm"])] = v
    units = sorted({k[:3] for k in val})
    if metric == "p":  # Δ = p(SN) - p(other): positive = SN better
        d = [val[u + ("SN",)] - val[u + (other,)] for u in units]
    else:  # Δ = loss(other) - loss(SN): positive = SN better
        d = [val[u + (other,)] - val[u + ("SN",)] for u in units]
    unav = {}
    for r in sel:
        unav.setdefault((r["family"], r["seed"], r["arm"]), float(r["unavailability_fraction"]))
    runs = sorted({k[:2] for k in unav})
    du = [unav[k + ("SN",)] - unav[k + (other,)] for k in runs]
    mean = sum(d) / len(d)
    lo, hi = bootstrap_ci(d)
    margin = MP if metric == "p" else M
    mean_du = sum(du) / len(du)
    if mean >= margin and lo > 0 and mean_du <= UNAV:
        verdict = "SN ganhou"
    elif -margin <= lo and hi <= margin:
        verdict = "empate"
    elif mean <= -margin and hi < 0:
        verdict = f"{other} ganhou"
    else:
        verdict = "inconclusivo"
    p_sn = sum(val[u + ("SN",)] for u in units) / len(units)
    p_o = sum(val[u + (other,)] for u in units) / len(units)
    return {"families": "+".join(families) if len(families) > 1 else families[0], "h": h, "condition": cond,
            "comparison": f"SN vs {other}", "metric": "contained_before_impact" if metric == "p" else "data_loss_per_host",
            "n": len(d), "value_SN": p_sn, "value_other": p_o, "delta": mean, "ci_lo": lo, "ci_hi": hi,
            "discordant": sum(1 for x in d if x != 0), "delta_unav_SN_minus_other": mean_du, "verdict": verdict}


def analyze(out_dir: str) -> list[dict[str, Any]]:
    rows = _load([os.path.join(out_dir, f"pilot_rows_h{h}_{c}.csv") for h in (0, 1) for c in F.CONDITIONS])
    out = []
    for h in (0, 1):  # H0
        out.append({"test": "H0", **compare(rows, FAMILIES, h, "oracle", "U1", "p")})
        out.append({"test": "H0", **compare(rows, FAMILIES, h, "oracle", "U1", "loss")})
    out.append({"test": "C0", **compare(rows, (CAMPAIGN_E1_E2,), 0, "restricted", "B2L", "p")})
    out.append({"test": "H1b", **compare(rows, (CAMPAIGN_E1_E2,), 1, "restricted", "B2L", "p")})
    out.append({"test": "H1b-U1", **compare(rows, FAMILIES, 1, "restricted", "U1", "p")})
    for test, fams, h, cond, other, metric in (
            ("H1b (oráculo, descritivo)", (CAMPAIGN_E1_E2,), 1, "oracle", "B2L", "p"),
            ("H1b-U1 em campaign_e1_e2 (descritivo)", (CAMPAIGN_E1_E2,), 1, "restricted", "U1", "p"),
            ("H1b perda (secundária)", (CAMPAIGN_E1_E2,), 1, "restricted", "B2L", "loss"),
            ("H1b-U1 perda (secundária)", FAMILIES, 1, "restricted", "U1", "loss"),
            ("C0 perda (secundária)", (CAMPAIGN_E1_E2,), 0, "restricted", "B2L", "loss")):
        out.append({"test": test, **compare(rows, fams, h, cond, other, metric)})
    for fam in F.FAMILIES:
        out.append({"test": f"por família (descritivo): {fam}", **compare(rows, (fam,), 1, "restricted", "B2L", "p")})
    sweep_path = os.path.join(out_dir, "sweep_rows.csv")
    if os.path.exists(sweep_path):
        srows = _load([sweep_path])
        for p_pre in SWEEP:
            sub = [r for r in srows if float(r["p_pre"]) == p_pre]
            out.append({"test": f"varredura p_pre = {p_pre} (descritivo)", **compare(sub, (CAMPAIGN_E1_E2,), 1, "restricted", "B2L", "p")})
    write_csv(os.path.join(out_dir, "pilot_table.csv"), out)
    return out


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("pilot", "sweep", "analyze"):
        sp = sub.add_parser(name)
        sp.add_argument("--workers", type=int, default=os.cpu_count() or 1)
        sp.add_argument("--out", default=os.path.join(_BASE_DIR, "results", "fase1b_pilot"))
        sp.add_argument("--cell", default=None, help="h:condition, e.g. 1:restricted (pilot only)")
        add_keep_tmp_arg(sp)
    args = parser.parse_args(argv)
    apply_keep_tmp_arg(args)
    os.makedirs(args.out, exist_ok=True)
    th = F.load_thresholds()
    if args.cmd == "pilot":
        h, c = args.cell.split(":")
        jobs = [(f, s, int(h), c, th, P_PRE, "evaluation") for f in FAMILIES for s in EVALUATION_SEEDS]
        print(run_jobs(jobs, args.workers, os.path.join(args.out, f"pilot_rows_h{h}_{c}.csv")))
    elif args.cmd == "sweep":
        jobs = [(CAMPAIGN_E1_E2, s, 1, "restricted", th, p, f"sweep_{p}") for p, seeds in SWEEP.items() for s in seeds]
        print(run_jobs(jobs, args.workers, os.path.join(args.out, "sweep_rows.csv")))
    else:
        for r in analyze(args.out):
            print(r)


if __name__ == "__main__":
    main()
