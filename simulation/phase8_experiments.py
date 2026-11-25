"""Phase 8: preventive (hardening) actions. Hypotheses P1-P5 + amendment A1 (docs/hypotheses.md),
action specification docs/preventive_actions.md. Every output row is labelled EXPLORATORY (pilot)
or SMOKE (1-seed smoke: not a result).

Subcommands
  smoke    1 seed, encryption_stream + campaign_multihost, every arm: shows each action moves damage
           in the expected direction (SMOKE; also a "prevention-only" view with containment removed).
  checks   the registered informativeness checks (critical event not always first, signals split,
           latency nonzero, P5 recovery reached) on the families P1-P5 use. No damage computed.
  pilot    --exp p1|p2|p3|p4|p5: the EXPLORATORY 5-seed pilot of one hypothesis (not run yet).

One live run per (arm, scenario, condition) with EVERY preventive action ON; a subset of actions is
evaluated by filtering the dispatched action labels. This equals a live run with only that subset ON
because preventive actions never change a verdict or decision (tested: tests/test_phase8.py).
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from multiprocessing import Pool
from typing import Any, Optional

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from agents.mape import NON_DELEGATED  # noqa: E402
from agents.mitigation import PREVENTIVE_ACTIONS, parse_action_label  # noqa: E402
from agents.reconciliation import reconcile, reconciliation_metrics  # noqa: E402
from baselines.mape_k_monolithic.loop import SINGLE_SIGNAL_KEY  # noqa: E402
from graph.build_graph import _build_routing_table, _specialist_node_name  # noqa: E402
from simulation.damage_model import DamageParams, availability, prevention_outcomes, scenario_clock, simulate  # noqa: E402
from simulation.experiment import add_keep_tmp_arg, apply_keep_tmp_arg, load_config, run_generated  # noqa: E402
from simulation.phase3_experiments import cost_point  # noqa: E402
from agents.mitigation import DISCOVERY_PRIVILEGES_KEY  # noqa: E402
from simulation.scenario_generator import BENIGN_FAMILIES, LATE_CONFIRM_SUFFIX, Scenario, generate  # noqa: E402
from simulation.transport import CostModel, Fault, Transport  # noqa: E402

EXPLORATORY, SMOKE = "EXPLORATORY", "SMOKE"
SCHEMA = "domains_proactive_reactive"
P2_SCHEMA, P2_CONTROL = "domains_split_visibility", "domains_proactive_reactive"
SSL = {SINGLE_SIGNAL_KEY: True}
ARMS: dict[str, tuple[str, dict[str, Any]]] = {
    "B1": ("b1", {}), "B1-SSL": ("b1", SSL), "B2": ("b2", {}), "B2-SSL": ("b2", SSL),
    "MAS-D": ("mas", {}), "MAS": ("mas", NON_DELEGATED),  # MAS = non-delegated ablation
    "P2P": ("p2p", {}), "P2P-SSL": ("p2p", SSL),
    "P2P-direct": ("p2p", {}), "P2P-direct-SSL": ("p2p", SSL),  # A3-6: all-to-all sharing (sensitivity)
}
TRANSPORT_OPTS: dict[str, dict[str, Any]] = {"P2P-direct": {"p2p_sharing": "direct"}, "P2P-direct-SSL": {"p2p_sharing": "direct"}}
DEFAULT_FAMILIES = ["inorder_short", "partial_disorder", "cross_domain_spread", "encryption_stream", "split_visibility"]
LATERAL_FAMILY = "campaign_multihost"
LATERAL_ACTIONS = ("restrict_privileges", "segment_network")
IMPACT_FAMILIES = ["inorder_short", "partial_disorder", "encryption_stream", "split_visibility"]  # P5 cross-domain units
E_GRID, E_PRIMARY = (0.25, 0.50, 0.75), 0.50
R_INH_GRID, R_INH_PRIMARY = (0.25, 0.43, 0.75), 0.43
LEASES, LEASE_PRIMARY = (60.0, 300.0, 900.0, 3600.0), 300.0
W_FACTORS = (0.5, 1.0, 2.0)
BACKUP_W = (0.0, 0.05)
HORIZONS = (3600.0, 21600.0, 86400.0)
METHOD = "legacy_weighted"
# A3-2: the late-confirm variants are the primary units of P2, P3, P5 (base families secondary).
LC = LATE_CONFIRM_SUFFIX
P5_FAMILIES = ["campaign_multihost", "interleaved"]  # A3-3: events after t0 + D
P5_OUTAGES, P5_OUTAGE_PRIMARY = (300.0, 900.0), 300.0
DISCOVERY_VARIANT = "restrict_privileges@discovery"  # A3-4


def edge_cost() -> CostModel:
    """Latency rule (Phase 7b): the edge operating point is primary."""
    return cost_point("edge", 0.05, 0.01)


def strict_p4_cost() -> CostModel:
    """A1-e: P4 primary = flat 2 s latency (with 280 files/s in the damage model)."""
    return cost_point("flat", 2.0, 0.01)


def policies(arm: str, method: str = METHOD, prevention: bool = True, extra: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    return {"damage_model": True, "detection_method": method, "playbook_version": 1,
            "preventive_actions": list(PREVENTIVE_ACTIONS) if prevention else [], **ARMS[arm][1], **(extra or {})}


def run_logs(arm: str, sc: Scenario, cfg: dict[str, Any], cost: Optional[CostModel] = None,
             faults: tuple[Fault, ...] = (), method: str = METHOD,
             extra: Optional[dict[str, Any]] = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """One live run (prevention ON); for the MAS, plus the reconciliation records after any recovered fault."""
    arch = ARMS[arm][0]
    cost = cost if cost is not None else CostModel()
    _, logs, repo = run_generated(arch, sc, domain_config=cfg, policies=policies(arm, method, extra=extra),
                                  transport=Transport(arch, cfg, cost, faults, **TRANSPORT_OPTS.get(arm, {})), return_logs=True)
    recon: dict[str, Any] = {}
    if arch == "mas" and any(f.end_index is not None for f in faults):
        recs = reconcile(sc, logs, repo, faults, domain_config=cfg, center_latency_s=cost.center_latency_s,
                         service_time_s=cost.service_time_s)
        recon = reconciliation_metrics(sc, logs, recs, faults, domain_config=cfg)
        logs = logs + recs
    return logs, recon


def keep_actions(logs: list[dict[str, Any]], enabled: tuple[str, ...], containment: Any = True) -> list[dict[str, Any]]:
    """The run's records with only ``enabled`` preventive actions, plus the non-preventive actions:
    all of them (``containment=True``), none (False), or only those whose name is in a given set."""
    out = []
    for r in logs:
        if r["event_type"] != "action_dispatched":
            out.append(r)
            continue
        acts = [a for a in r["payload"]["actions"]
                if (parse_action_label(a)[0] in enabled) or (parse_action_label(a)[0] not in PREVENTIVE_ACTIONS and (
                    containment is True or (containment and parse_action_label(a)[0] in containment)))]
        out.append({**r, "payload": {**r["payload"], "actions": acts}})
    return out


def evaluate(sc: Scenario, logs: list[dict[str, Any]], params: DamageParams, base: dict[str, Any]) -> list[dict[str, Any]]:
    """One row per malicious campaign: damage (raw and per host), prevention timing, availability."""
    outcomes, net = simulate(sc, logs, params)
    prev = prevention_outcomes(sc, logs, outcomes)
    avail = availability(net, outcomes, params, (0.0, params.horizon_s))
    rows = []
    for key, o in outcomes.items():
        hosts = max(o.hosts_compromised, 1)
        rows.append({**base, "incident": key.split("::")[-1], "data_loss": o.data_loss, "data_loss_per_host": o.data_loss / hosts,
                     "files_encrypted": o.files_encrypted, "hosts_compromised": o.hosts_compromised,
                     "observed_hosts": o.observed_hosts_compromised, "prevented_moves": o.prevented_moves,
                     "contained": o.contained, **prev[key], **avail})
    return rows


def no_defense_rows(sc: Scenario, params: DamageParams, base: dict[str, Any]) -> list[dict[str, Any]]:
    return evaluate(sc, [], params, {**base, "arm": "NO-DEFENSE", "prevention": "none"})


# --- P1 ----------------------------------------------------------------------------------------
def job_p1(args) -> list[dict[str, Any]]:
    family, seed, status = args
    cfg, sc = load_config(SCHEMA), generate(family, seed)
    cost, rows = edge_cost(), []
    for arm in ("B1", "B2", "MAS-D", "B1-SSL", "B2-SSL", "MAS", "P2P"):
        logs, _ = run_logs(arm, sc, cfg, cost)
        for e in E_GRID:
            for r_inh in R_INH_GRID:
                for h in HORIZONS:
                    params = DamageParams(horizon_s=h, prevention_effectiveness=e, inhibited_restorable_fraction=r_inh)
                    for cond in ("none",) + PREVENTIVE_ACTIONS + ("all",):
                        enabled = () if cond == "none" else (PREVENTIVE_ACTIONS if cond == "all" else (cond,))
                        base = {"status": status, "exp": "p1", "family": family, "seed": seed, "arm": arm, "prevention": cond,
                                "e": e, "r_inh": r_inh, "horizon": h}
                        rows += evaluate(sc, keep_actions(logs, enabled), params, base)
        if family == LATERAL_FAMILY and arm in ("B1", "B2", "MAS-D", "B1-SSL", "B2-SSL", "P2P"):
            # A3-4: separate live run with the discovery trigger; only restrict_privileges kept
            dlogs, _ = run_logs(arm, sc, cfg, cost, extra={DISCOVERY_PRIVILEGES_KEY: True})
            for e in E_GRID:
                for h in HORIZONS:
                    params = DamageParams(horizon_s=h, prevention_effectiveness=e, inhibited_restorable_fraction=R_INH_PRIMARY)
                    base = {"status": status, "exp": "p1", "family": family, "seed": seed, "arm": arm,
                            "prevention": DISCOVERY_VARIANT, "e": e, "r_inh": R_INH_PRIMARY, "horizon": h}
                    rows += evaluate(sc, keep_actions(dlogs, ("restrict_privileges",)), params, base)
    for e in E_GRID:  # NO-DEFENSE reference (A3-5 relative margin), no arm involved
        for r_inh in R_INH_GRID:
            for h in HORIZONS:
                params = DamageParams(horizon_s=h, prevention_effectiveness=e, inhibited_restorable_fraction=r_inh)
                rows += no_defense_rows(sc, params, {"status": status, "exp": "p1", "family": family, "seed": seed,
                                                     "e": e, "r_inh": r_inh, "horizon": h})
    return rows


# --- P2 ----------------------------------------------------------------------------------------
def job_p2(args) -> list[dict[str, Any]]:
    seed, schema, family, status = args
    cfg, sc = load_config(schema), generate(family, seed)
    params = DamageParams(prevention_effectiveness=E_PRIMARY, inhibited_restorable_fraction=R_INH_PRIMARY)
    rows = no_defense_rows(sc, params, {"status": status, "exp": "p2", "schema": schema, "family": family, "seed": seed})
    for arm in ("MAS-D", "B1", "B2", "P2P", "P2P-direct", "B1-SSL", "B2-SSL", "P2P-SSL", "P2P-direct-SSL", "MAS"):
        logs, _ = run_logs(arm, sc, cfg, edge_cost())
        rows += evaluate(sc, logs, params, {"status": status, "exp": "p2", "schema": schema, "family": family,
                                            "seed": seed, "arm": arm, "prevention": "all", "e": E_PRIMARY})
    return rows


# --- P3 ----------------------------------------------------------------------------------------
P3_FAMILIES = DEFAULT_FAMILIES + ["interleaved"] + list(BENIGN_FAMILIES)  # registered: benign families + interleaved
P3_FAMILIES += [f + LC for f in ("inorder_short", "partial_disorder", "cross_domain_spread", "split_visibility", "interleaved")]


def job_p3(args) -> list[dict[str, Any]]:
    family, seed, status = args
    cfg, sc = load_config(SCHEMA), generate(family, seed)
    rows = []
    for arm in ("MAS-D", "B1-SSL", "B2-SSL", "MAS", "P2P-SSL", "P2P-direct-SSL", "B1"):
        logs, _ = run_logs(arm, sc, cfg, edge_cost())
        for prevention in (False, True):
            filt = keep_actions(logs, PREVENTIVE_ACTIONS if prevention else ())
            for e in E_GRID:
                for lease in LEASES:
                    for wf in W_FACTORS:
                        for wb in BACKUP_W:
                            params = DamageParams(prevention_effectiveness=e, inhibited_restorable_fraction=R_INH_PRIMARY,
                                                  prevention_lease_s=lease, availability_weight_factor=wf, protect_backup_weight=wb)
                            outcomes, net = simulate(sc, filt, params)
                            avail = availability(net, outcomes, params, (0.0, params.horizon_s))
                            loss = [o.data_loss / max(o.hosts_compromised, 1) for o in outcomes.values()]
                            rows.append({"status": status, "exp": "p3", "family": family, "seed": seed, "arm": arm,
                                         "prevention": prevention, "e": e, "lease": lease, "w_factor": wf, "w_backup": wb,
                                         "malicious_campaigns": len(loss), "data_loss_per_host_mean": (sum(loss) / len(loss)) if loss else None,
                                         **avail})
    return rows


# --- P4 ----------------------------------------------------------------------------------------
def proactive_down(arch: str, cfg: dict[str, Any]) -> tuple[Fault, ...]:
    """A1 / P4 fault ``domain_down(proactive)`` mapped to each architecture's components."""
    dom = next(d for d in cfg["domains"] if d["name"] == "proactive")
    if arch == "mas":
        return (Fault("coordinator_down", "proactive"),) + tuple(Fault("specialist_down", s["id"]) for s in dom["specialists"])
    if arch in ("b2", "p2p"):
        return (Fault("coordinator_down", "proactive"),)
    return (Fault("partition", "proactive"),)  # B1: the proactive domain's events never reach the center


def job_p4(args) -> list[dict[str, Any]]:
    family, seed, setting, status = args
    cfg, sc = load_config(SCHEMA), generate(family, seed)
    cost = strict_p4_cost() if setting == "strict" else edge_cost()
    rate = 280.0 if setting == "strict" else 38.3
    rows = []
    for arm in ("B1", "B2", "MAS-D", "P2P"):
        for cond in ("none", "proactive_down"):
            faults = proactive_down(ARMS[arm][0], cfg) if cond != "none" else ()
            logs, _ = run_logs(arm, sc, cfg, cost, faults)
            params = DamageParams(encryption_rate_files_per_s=rate, prevention_effectiveness=E_PRIMARY,
                                  inhibited_restorable_fraction=R_INH_PRIMARY)
            rows += evaluate(sc, logs, params, {"status": status, "exp": "p4", "setting": setting, "family": family,
                                                "seed": seed, "arm": arm, "fault": cond})
    return rows


# --- P5 ----------------------------------------------------------------------------------------
def recovery_index(sc: Scenario, after_s: float = 60.0) -> Optional[int]:
    """Registered P5 recovery: the first event after (last malicious event + 60 s); None if none exists."""
    _, true_t, _ = scenario_clock(sc)
    last = max(true_t[e["event_id"]] for e in sc.truth["events"] if e["malicious"])
    return next((i for i, e in enumerate(sc.events) if true_t[e["event_id"]] > last + after_s), None)


def outage_window(sc: Scenario, duration_s: float) -> Optional[tuple[int, int]]:
    """A3-3: (start, end) event indices of the outage [t0, t0 + D), t0 = true time of the first malicious
    (early-signal) event; end = the first event with true time > t0 + D (recovery). None if no such event."""
    _, true_t, _ = scenario_clock(sc)
    t0 = min(true_t[e["event_id"]] for e in sc.truth["events"] if e["malicious"])
    start = next(i for i, e in enumerate(sc.events) if true_t[e["event_id"]] >= t0)
    end = next((i for i, e in enumerate(sc.events) if i > start and true_t[e["event_id"]] > t0 + duration_s), None)
    return None if end is None else (start, end)


def job_p5(args) -> list[dict[str, Any]]:
    family, seed, status, duration = args
    cfg, sc = load_config(SCHEMA), generate(family, seed)
    window = outage_window(sc, duration)
    params = DamageParams(prevention_effectiveness=E_PRIMARY, inhibited_restorable_fraction=R_INH_PRIMARY)
    head = {"status": status, "exp": "p5", "family": family, "seed": seed, "outage_s": duration}
    if window is None:
        return [{**head, "arm": "", "excluded": "no event after t0 + D"}]
    start, end = window
    rows = no_defense_rows(sc, params, {**head, "fault": "", "target": ""})
    kinds = [("none", None), ("central_down", None)] + [("coordinator_down", d["name"]) for d in cfg["domains"]]
    for arm in ("MAS-D", "B1", "B2", "P2P", "P2P-direct", "B1-SSL", "B2-SSL", "P2P-SSL"):
        for kind, target in kinds:
            faults = () if kind == "none" else (Fault(kind, target, start, end),)
            logs, recon = run_logs(arm, sc, cfg, edge_cost(), faults)
            base = {**head, "arm": arm, "fault": kind, "target": target or "", "outage_start_index": start,
                    "recovery_index": end, **{f"recon_{k}": v for k, v in recon.items()}}
            rows += evaluate(sc, logs, params, base)
    return rows


# --- informativeness checks ---------------------------------------------------------------------
def check_critical_not_first(families, seeds) -> list[dict[str, Any]]:
    """Registered check 1, plus (A3-2) the confirming index: the first DETECTION-BACKED preventive
    dispatch counted in malicious events of its incident before it (must be >= 2 on the variants)."""
    rows = []
    cfg = load_config(SCHEMA)
    for family in families:
        firsts, confirms = [], []
        for seed in seeds:
            sc = generate(family, seed)
            idx = {e["event_id"]: i for i, e in enumerate(sc.events)}
            truth = {t["event_id"]: t for t in sc.truth["events"]}
            first = confirm = None
            for arm in ("MAS-D", "B1", "B2", "B1-SSL", "B2-SSL", "P2P", "P2P-SSL"):
                logs, _ = run_logs(arm, sc, cfg, CostModel())
                prev = [r for r in logs if r["event_type"] == "action_dispatched"
                        and any(parse_action_label(a)[0] in PREVENTIVE_ACTIONS for a in r["payload"]["actions"])]
                hits = [idx[r["payload"]["event_id"]] for r in prev]
                if hits:
                    first = min(hits) if first is None else min(first, min(hits))
                for r in prev:
                    if not r["payload"]["on_flagged_verdict"]:
                        continue
                    ev = truth[r["payload"]["event_id"]]
                    if not ev["malicious"]:  # a flag on a benign incident (false positive) is not a confirmation
                        continue
                    k = sum(1 for t in sc.truth["events"] if t["true_incident_id"] == ev["true_incident_id"]
                            and t["malicious"] and t["index"] < ev["index"])
                    confirm = k if confirm is None else min(confirm, k)
            firsts.append(first)
            confirms.append(confirm)
        defined = [f for f in firsts if f is not None]
        zero = sum(1 for f in defined if f == 0)
        cdef = [c for c in confirms if c is not None]
        rows.append({"check": "critical_event_not_always_first", "family": family, "units": len(firsts),
                     "units_with_prevention": len(defined), "first_is_event0": zero,
                     "pass": bool(defined) and zero < len(defined), "first_indices": firsts,
                     "confirm_prior_malicious": confirms,
                     "confirm_ge2_all": bool(cdef) and min(cdef) >= 2 if family.endswith(LC) else None})
    return rows


def critical_event_breakdown(families, seeds) -> list[dict[str, Any]]:
    """Diagnostic (not a registered check): first preventive-trigger index per arm, all vs detection-backed."""
    cfg, rows = load_config(SCHEMA), []
    for family in families:
        for arm in ("MAS-D", "B1", "B2", "B1-SSL", "B2-SSL", "P2P"):
            for flagged_only in (False, True):
                firsts = []
                for seed in seeds:
                    sc = generate(family, seed)
                    idx = {e["event_id"]: i for i, e in enumerate(sc.events)}
                    logs, _ = run_logs(arm, sc, cfg, CostModel())
                    hits = [idx[r["payload"]["event_id"]] for r in logs if r["event_type"] == "action_dispatched"
                            and (r["payload"]["on_flagged_verdict"] or not flagged_only)
                            and any(parse_action_label(a)[0] in PREVENTIVE_ACTIONS for a in r["payload"]["actions"])]
                    firsts.append(min(hits) if hits else None)
                rows.append({"check": "diagnostic_first_prevention_index", "family": family, "arm": arm,
                             "detection_backed_only": flagged_only, "first_indices": firsts})
    return rows


def check_signals_split(schema: str, seeds, family: str = "split_visibility") -> dict[str, Any]:
    cfg = load_config(schema)
    node_to = {_specialist_node_name(s["id"]): d["name"] for d in cfg["domains"] for s in d["specialists"]}
    route = {t: node_to[n] for t, n in _build_routing_table(cfg["domains"]).items()}
    early = {"network_enumeration", "privilege_escalation_attempt", "service_stop_attempt", "backup_recovery_tamper"}
    worst = 0
    for seed in seeds:
        sc = generate(family, seed)
        bad = {t["event_id"] for t in sc.truth["events"] if t["malicious"]}
        per = {}
        for e in sc.events:
            if e["type"] in early and e["event_id"] in bad:
                per.setdefault((e["source"], route[e["type"]]), set()).add(e["type"])
        worst = max([worst] + [len(v) for v in per.values()])
    return {"check": "signals_split", "schema": schema, "family": family, "max_early_types_per_domain": worst, "pass": worst <= 1}


def check_latency_nonzero(families, seeds) -> list[dict[str, Any]]:
    cfg, rows = load_config(SCHEMA), []
    for arm in ARMS:
        delays = []
        for family in families:
            for seed in seeds:
                logs, _ = run_logs(arm, generate(family, seed), cfg, edge_cost())
                delays += [r["payload"]["sim_delay_s"] for r in logs if r["event_type"] == "action_dispatched"]
        rows.append({"check": "latency_nonzero", "arm": arm, "dispatches": len(delays),
                     "min_sim_delay_s": min(delays) if delays else None, "pass": bool(delays) and min(delays) > 0})
    return rows


def check_p5_recovery(families, seeds) -> dict[str, Any]:
    missing = sum(1 for f in families for s in seeds if recovery_index(generate(f, s)) is None)
    total = len(families) * len(seeds)
    return {"check": "p5_recovery_reached", "units": total, "units_without_recovery_event": missing, "pass": missing == 0}


def check_p5_window(families, seeds, durations=P5_OUTAGES) -> list[dict[str, Any]]:
    """A3-3: units with an event after t0 + D (the recovery / reconciliation point exists)."""
    rows = []
    for f in families:
        for d in durations:
            ok = sum(1 for s in seeds if outage_window(generate(f, s), d) is not None)
            rows.append({"check": "p5_outage_window_reached", "family": f, "outage_s": d, "units": len(seeds),
                         "units_with_recovery": ok, "pass": ok > 0})
    return rows


# --- smoke ----------------------------------------------------------------------------------------
def smoke(seed: int = 0) -> list[dict[str, Any]]:
    cfg, rows = load_config(SCHEMA), []
    # encryption_stream + campaign_multihost as requested; inorder_short added because protect_backup can
    # only act where the T1490 host is in a protected segment and a restore follows (see the smoke notes).
    for family in ("encryption_stream", LATERAL_FAMILY, "inorder_short"):
        sc = generate(family, seed)
        params = DamageParams(prevention_effectiveness=E_PRIMARY, inhibited_restorable_fraction=R_INH_PRIMARY)
        rows += no_defense_rows(sc, params, {"status": SMOKE, "family": family, "seed": seed, "view": "full"})
        for arm in ARMS:
            logs, _ = run_logs(arm, sc, cfg, edge_cost())
            for view, containment in (("full", True), ("prevention-only", False),
                                      ("prevention+recovery", frozenset({"trigger_backup_restore"}))):
                for cond in ("none",) + PREVENTIVE_ACTIONS + ("all",):
                    enabled = () if cond == "none" else (PREVENTIVE_ACTIONS if cond == "all" else (cond,))
                    rows += evaluate(sc, keep_actions(logs, enabled, containment), params,
                                     {"status": SMOKE, "family": family, "seed": seed, "arm": arm, "view": view, "prevention": cond})
    return rows


def write_csv(path: str, rows: list[dict[str, Any]]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def pilot_jobs(exp: str, seeds: int) -> tuple[Any, list[tuple]]:
    s = range(seeds)
    if exp == "p1":
        return job_p1, [(f, i, EXPLORATORY) for f in DEFAULT_FAMILIES + [LATERAL_FAMILY] for i in s]
    if exp == "p2":
        return job_p2, [(i, sch, fam, EXPLORATORY) for sch in (P2_SCHEMA, P2_CONTROL)
                        for fam in ("split_visibility" + LC, "split_visibility") for i in s]
    if exp == "p3":
        return job_p3, [(f, i, EXPLORATORY) for f in P3_FAMILIES for i in s]
    if exp == "p4":
        return job_p4, [(f, i, st, EXPLORATORY) for f in DEFAULT_FAMILIES for i in s for st in ("strict", "default")]
    return job_p5, [(f, i, EXPLORATORY, d) for f in [x + LC for x in P5_FAMILIES] + P5_FAMILIES for i in s for d in P5_OUTAGES]


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("smoke")
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--out", default="results/phase8_smoke")
    c = sub.add_parser("checks")
    c.add_argument("--seeds", type=int, default=5)
    c.add_argument("--out", default="results/phase8_checks")
    q = sub.add_parser("pilot")
    q.add_argument("--exp", choices=["p1", "p2", "p3", "p4", "p5"], required=True)
    q.add_argument("--seeds", type=int, default=5)
    q.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    q.add_argument("--out", default="results/phase8_pilot")
    for sp in (p, c, q):
        add_keep_tmp_arg(sp)
    args = parser.parse_args(argv)
    apply_keep_tmp_arg(args)
    if args.cmd == "smoke":
        write_csv(os.path.join(args.out, "smoke.csv"), smoke(args.seed))
    elif args.cmd == "checks":
        seeds = range(args.seeds)
        variants = [f + LC for f in ("inorder_short", "partial_disorder", "cross_domain_spread", "split_visibility",
                                     LATERAL_FAMILY, "interleaved")]
        rows = check_critical_not_first(variants + DEFAULT_FAMILIES + [LATERAL_FAMILY, "interleaved"], seeds)
        rows += [check_signals_split(P2_SCHEMA, seeds), check_signals_split(P2_CONTROL, seeds),
                 check_signals_split(P2_SCHEMA, seeds, "split_visibility" + LC)]
        rows += check_latency_nonzero(DEFAULT_FAMILIES + [LATERAL_FAMILY] + variants, range(1))
        rows += check_p5_window([f + LC for f in P5_FAMILIES] + P5_FAMILIES, seeds)
        write_csv(os.path.join(args.out, "checks.csv"), rows)
        for r in rows:
            print(r)
    else:
        fn, jobs = pilot_jobs(args.exp, args.seeds)
        with Pool(args.workers) as pool:
            rows = [r for chunk in pool.imap_unordered(fn, jobs, chunksize=1) for r in chunk]
        write_csv(os.path.join(args.out, f"exp_{args.exp}.csv"), rows)


if __name__ == "__main__":
    main()
