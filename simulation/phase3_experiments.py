"""Phase 3 experiments A (latency), A-loss, B (faults), C (scale); D (overhead) is derived from them.

    python simulation/phase3_experiments.py all --out results/phase3 --workers 8

Every run uses the domains_by_system_area schema and ONE detection method for all
architectures. Architectures: B1, B2, MAS (default authority: only Strategic acts on
a flag) and MAS-D (MAS with dispatch_on_flag for specialists and coordinators).

Re-timing: with no loss and no faults the cost model changes timing but not
decisions, so experiments A and C run each (scenario, architecture, method) ONCE at
zero cost and re-time the logs for every cost point with the same Transport code
(``instrumentation.incident_metrics.retime``; equality with a live run is tested).
A-loss and B change what is delivered and are run live.
"""
from __future__ import annotations

import argparse
import csv
import math
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from multiprocessing import Pool
from typing import Any, Optional

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from instrumentation.incident_metrics import incident_frames, incident_outcomes, retime  # noqa: E402
from simulation.experiment import load_config, run_generated  # noqa: E402
from simulation.scenario_generator import Scenario, generate, incident_key  # noqa: E402
from simulation.transport import CostModel, Fault, Transport  # noqa: E402

CONFIG = "domains_by_system_area"
DELEGATED = {"dispatch_on_flag::specialist": True, "dispatch_on_flag::coordinator": True}
# Frozen arm definitions: "MAS" pins delegation OFF explicitly (the default became ON in Phase 8).
NON_DELEGATED = {"dispatch_on_flag::specialist": False, "dispatch_on_flag::coordinator": False}
ARCHS = {"B1": ("b1", {}), "B2": ("b2", {}), "MAS": ("mas", NON_DELEGATED), "MAS-D": ("mas", DELEGATED)}
FAMILIES = ["inorder_short", "partial_disorder", "cross_domain_spread", "encryption_stream"]
METHODS_A = ["legacy_weighted", "killchain_stage"]
LATENCIES = [0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0]
SERVICES = [0.001, 0.01, 0.05, 0.1, 0.5]
LOSSES = [0.0, 0.01, 0.02, 0.05]
RATES = [1, 2, 5, 10, 20, 50, 100, 200, 500]
FIXED_LATENCY, FIXED_SERVICE = 0.05, 0.01  # B, A-loss and C operating point (edge topology)
SEEDS = 30


def cost_point(topology: str, latency: float, service: float, **kw) -> CostModel:
    if topology == "zero":
        return CostModel(**kw)
    domain = 0.005 if topology == "edge" else latency
    return CostModel(local_latency_s=0.001, domain_latency_s=domain, center_latency_s=latency, service_time_s=service, **kw)


def grid_a() -> list[tuple[str, float, float]]:
    return [("zero", 0.0, 0.0)] + [(t, l, s) for t in ("edge", "flat") for l in LATENCIES for s in SERVICES]


def _rows(outcomes: dict, scenario: Scenario, base: dict[str, Any]) -> list[dict[str, Any]]:
    malicious = {i["incident_key"]: i["malicious"] for i in scenario.truth["incidents"].values()}
    rows = []
    for key, o in outcomes.items():
        d, c, a = o["first_detection"], o["first_containment"], o["first_any_containment"]
        rows.append({
            **base, "incident": key.split("::")[-1], "malicious": malicious.get(key),
            "det_t": d and d["time_s"], "det_idx": d and d["event_index"], "det_node": d and d["node"],
            "cont_t": c and c["time_s"], "cont_idx": c and c["event_index"], "cont_node": c and c["node"],
            "det_delay": d and d["delay_s"], "cont_delay": c and c["delay_s"],
            "any_cont_t": a and a["time_s"], "messages": o["messages_sent"], "message_bytes": o["message_bytes"],
        })
    return rows


def _center_bytes(logs: list[dict[str, Any]], arch: str, transport: Transport) -> tuple[int, int]:
    """(messages, bytes) crossing the center link: B1 = raw events host->central;
    MAS = coordinator->Strategic domain reports; B2 = none."""
    if arch == "b1":
        return transport.crossings["center"], transport.crossing_bytes["center"]
    if arch == "mas":
        sent = [r for r in logs if r["event_type"] == "message_sent" and r["layer"] == "coordinator"]
        return len(sent), sum(r["payload_size_bytes"] for r in sent)
    return 0, 0


# --- Experiment A (and D) -----------------------------------------------------------------
def job_a(args: tuple[str, int, str]) -> list[dict[str, Any]]:
    family, seed, method = args
    cfg, sc = load_config(CONFIG), generate(family, seed)
    frames = incident_frames(sc)
    rows = []
    for label, (arch, extra) in ARCHS.items():
        zero_tr = Transport(arch, cfg, CostModel())
        _, logs, _ = run_generated(arch, sc, domain_config=cfg, policies={"detection_method": method, **extra},
                                   transport=zero_tr, return_logs=True)
        center_msgs, center_bytes = _center_bytes(logs, arch, zero_tr)
        for topology, latency, service in grid_a():
            tr = Transport(arch, cfg, cost_point(topology, latency, service))
            for e in sc.events:
                tr.begin(e)
            base = {"exp": "A", "family": family, "seed": seed, "method": method, "arch": label,
                    "topology": topology, "latency": latency, "service": service,
                    "center_msgs": center_msgs, "center_bytes": center_bytes, "n_events": len(sc.events)}
            rows += _rows(incident_outcomes(retime(logs, tr.plans), frames), sc, base)
    return rows


def job_a_loss(args: tuple[str, int, float]) -> list[dict[str, Any]]:
    family, seed, loss = args
    cfg, sc = load_config(CONFIG), generate(family, seed)
    rows = []
    for label, (arch, extra) in ARCHS.items():
        tr = Transport(arch, cfg, cost_point("edge", FIXED_LATENCY, FIXED_SERVICE, loss=loss, seed=seed))
        _, logs, _ = run_generated(arch, sc, domain_config=cfg, policies=extra, transport=tr, return_logs=True)
        base = {"exp": "A-loss", "family": family, "seed": seed, "method": "legacy_weighted", "arch": label, "loss": loss,
                "lost_msgs": sum(1 for p in tr.plans if "lost" in p.dropped.values())}
        rows += _rows(incident_outcomes(logs, incident_frames(sc)), sc, base)
    return rows


# --- Experiment B -------------------------------------------------------------------------
def fault_conditions(cfg: dict[str, Any], scenario: Scenario) -> list[tuple[str, Optional[str]]]:
    probe = Transport("mas", cfg)
    domains = [d["name"] for d in cfg["domains"]]
    specialists = sorted({probe._route[e["type"]][1] for e in scenario.events})
    return ([("none", None), ("central_down", None)] + [("coordinator_down", d) for d in domains]
            + [("specialist_down", s) for s in specialists] + [("partition", d) for d in domains])


def _affects(arch: str, kind: str) -> bool:
    return {"none": True, "central_down": arch in ("mas", "b1"), "coordinator_down": arch in ("mas", "b2"),
            "specialist_down": arch == "mas", "partition": arch in ("mas", "b1")}[kind]


def job_b(args: tuple[str, int]) -> list[dict[str, Any]]:
    family, seed = args
    cfg, sc = load_config(CONFIG), generate(family, seed)
    frames = incident_frames(sc)
    rows = []
    for label, (arch, extra) in ARCHS.items():
        baseline = None
        for kind, target in fault_conditions(cfg, sc):
            base = {"exp": "B", "family": family, "seed": seed, "method": "legacy_weighted", "arch": label,
                    "fault": kind, "target": target or "", "applies": _affects(arch, kind)}
            if kind != "none" and not base["applies"]:
                rows += [{**r, **base} for r in baseline]  # no such component in this architecture: unaffected
                continue
            faults = () if kind == "none" else (Fault(kind, target),)
            tr = Transport(arch, cfg, cost_point("edge", FIXED_LATENCY, FIXED_SERVICE), faults)
            _, logs, _ = run_generated(arch, sc, domain_config=cfg, policies=extra, transport=tr, return_logs=True)
            out = _rows(incident_outcomes(logs, frames), sc, base)
            if kind == "none":
                baseline = out
            rows += out
    return rows


# --- Experiment C -------------------------------------------------------------------------
LOAD_MIX = ["inorder_short", "partial_disorder", "cross_domain_spread",
            "benign_admin_recon_restart", "benign_background", "benign_patch_window"]
LOAD_EVENTS = 1200


def load_stream(seed: int) -> Scenario:
    """~1200 events from many concurrent incidents (one host each), interleaved preserving
    each incident's order; timestamps are a Poisson process at 1 event/s (scaled per rate)."""
    rng = random.Random(f"load:{seed}")
    incidents, total, k = [], 0, 0
    while total < LOAD_EVENTS:
        sc = generate(rng.choice(LOAD_MIX), rng.randrange(10**6))
        host = f"h{k:04d}"
        evs = [{**e, "event_id": f"L{k:04d}-{j:04d}", "source": host} for j, e in enumerate(sc.events)]
        mal = sc.truth["malicious"]
        incidents.append((host, mal, evs))
        total += len(evs)
        k += 1
    queues = [list(evs) for _, _, evs in incidents]
    order = []
    while any(queues):
        q = rng.choice([q for q in queues if q])
        order.append(q.pop(0))
    t0, t = datetime(2026, 4, 1, tzinfo=timezone.utc), 0.0
    events = []
    for e in order:
        t += rng.expovariate(1.0)
        events.append({**e, "timestamp": (t0 + timedelta(seconds=t)).isoformat()})
    scenario_id = f"load-{seed}"
    truth = {"scenario_id": scenario_id, "family": "load_mix", "seed": seed, "malicious": True, "params": {"n_events": len(events)},
             "incidents": {f"inc-{i}": {"host": h, "malicious": m, "incident_key": f"{scenario_id}::{h}"}
                           for i, (h, m, _) in enumerate(incidents)},
             "events": []}
    return Scenario("load_mix", seed, events, truth)


def _scaled(scenario: Scenario, rate: float) -> tuple[Scenario, dict[str, str]]:
    t0 = datetime.fromisoformat(scenario.events[0]["timestamp"])
    ts = {e["event_id"]: (t0 + (datetime.fromisoformat(e["timestamp"]) - t0) / rate).isoformat() for e in scenario.events}
    return Scenario(scenario.family, scenario.seed, [{**e, "timestamp": ts[e["event_id"]]} for e in scenario.events],
                    scenario.truth), ts


def job_c(args: tuple[int]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    (seed,) = args
    cfg, sc = load_config(CONFIG), load_stream(seed)
    rows, queues = [], []
    for label, (arch, extra) in ARCHS.items():
        _, logs, _ = run_generated(arch, sc, domain_config=cfg, policies=extra, transport=Transport(arch, cfg), return_logs=True)
        for rate in RATES:
            scaled, ts = _scaled(sc, rate)
            shards = max(1, math.ceil(rate / 50))
            tr = Transport(arch, cfg, cost_point("edge", FIXED_LATENCY, FIXED_SERVICE, shards=shards))
            plans = [tr.begin(e) for e in scaled.events]
            relogged = [{**r, "payload": {**r["payload"], "event_ts": ts[r["payload"]["event_id"]]}}
                        if r["event_type"] in ("analysis", "action_dispatched") else r for r in logs]
            out = incident_outcomes(retime(relogged, plans), incident_frames(scaled))
            base = {"exp": "C", "seed": seed, "method": "legacy_weighted", "arch": label, "rate": rate, "shards": shards}
            rows += _rows(out, scaled, base)
            waits: dict[str, list[float]] = {}
            for p in plans:
                for node, t in p.timing.items():
                    waits.setdefault(node.split("::")[0], []).append(t.start - t.arrive)
            horizon = max(p.t_event for p in plans) or 1.0
            bins: dict[tuple[str, int], list[int]] = {}
            for node, arrive, q in tr.queue_samples:  # 25 time bins; per node class: max queue over replicas
                cls = node.split("::")[0]
                if cls in ("strategic", "central", "coordinator", "b2"):
                    bins.setdefault((cls, min(24, int(25 * arrive / horizon))), []).append(q)
            for (cls, b), qs in sorted(bins.items()):
                queues.append({"seed": seed, "arch": label, "rate": rate, "node_class": cls, "bin": b,
                               "t_mid": (b + 0.5) * horizon / 25, "qlen_mean": sum(qs) / len(qs), "qlen_max": max(qs)})
            for cls, w in waits.items():
                queues.append({"seed": seed, "arch": label, "rate": rate, "node_class": cls, "bin": -1,
                               "t_mid": -1, "qlen_mean": None, "qlen_max": None, "mean_wait_s": sum(w) / len(w),
                               "max_wait_s": max(w), "utilization_est": rate * FIXED_SERVICE})
    return rows, queues


# --- driver -------------------------------------------------------------------------------
def _write(path: str, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("which", choices=["A", "A-loss", "B", "C", "all"])
    parser.add_argument("--out", default="results/phase3")
    parser.add_argument("--seeds", type=int, default=SEEDS)
    parser.add_argument("--load-seeds", type=int, default=5)
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    args = parser.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    todo = ["A", "A-loss", "B", "C"] if args.which == "all" else [args.which]
    with Pool(args.workers) as pool:
        if "A" in todo:
            jobs = [(f, s, m) for f in FAMILIES for s in range(args.seeds) for m in METHODS_A]
            _write(os.path.join(args.out, "exp_a.csv"), [r for rs in pool.imap_unordered(job_a, jobs) for r in rs])
            print("A done", flush=True)
        if "A-loss" in todo:
            jobs = [(f, s, l) for f in FAMILIES for s in range(args.seeds) for l in LOSSES]
            _write(os.path.join(args.out, "exp_a_loss.csv"), [r for rs in pool.imap_unordered(job_a_loss, jobs) for r in rs])
            print("A-loss done", flush=True)
        if "B" in todo:
            jobs = [(f, s) for f in FAMILIES for s in range(args.seeds)]
            _write(os.path.join(args.out, "exp_b.csv"), [r for rs in pool.imap_unordered(job_b, jobs) for r in rs])
            print("B done", flush=True)
        if "C" in todo:
            results = pool.map(job_c, [(s,) for s in range(args.load_seeds)])
            _write(os.path.join(args.out, "exp_c.csv"), [r for rs, _ in results for r in rs])
            _write(os.path.join(args.out, "exp_c_queues.csv"), [q for _, qs in results for q in qs])
            print("C done", flush=True)


if __name__ == "__main__":
    main()
