"""Etapa 3b driver (EXPLORATORY): ablation of the SN hierarchy (docs/fase1/11_ablacao.md).

Arms: SN (unchanged), A1 (no Strategic), A2 (A1 + coordinators dispatch nothing), A3 (A2 + only the
advisories go up), plus U1 and B2L as references. h = 1, 5 families, boundary lote 60 s ("restricted")
and lote 15 min ("batch15m"), seeds 7000-7099. Every variant is a set of Knowledge policies plus the
matching ``Transport(sn_layers=...)``; the defaults leave every earlier run unchanged.

    python3 simulation/fase1_ablacao_experiments.py blocks
    python3 simulation/fase1_ablacao_experiments.py run --block restricted_campaign_e1_e2
    python3 simulation/fase1_ablacao_experiments.py run-all          # every block not yet checkpointed
    python3 simulation/fase1_ablacao_experiments.py analyze          # summary.json + figs

``run`` is checkpointed: a block whose raw file exists and matches the manifest sha256 is skipped.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import platform
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from multiprocessing import Pool
from typing import Any, Optional

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from agents.mitigation import parse_action_label  # noqa: E402
from analysis.fase1_etapa3_rerun import extras  # noqa: E402
from graph.build_sn_graph import SN_LAYERS_KEY, sn_router  # noqa: E402
from simulation import fase1_experiments as F  # noqa: E402
from simulation import fase1_oficial_experiments as O  # noqa: E402
from simulation import fase1b_experiments as B  # noqa: E402
from simulation.experiment import load_config, run_generated  # noqa: E402
from simulation.fase1 import P_PRE, PROFILE_SEGMENT  # noqa: E402
from simulation.transport import Transport  # noqa: E402

EXPLORATORY = "EXPLORATORY"
SEEDS = tuple(range(7000, 7100))
LEVELS = ("restricted", "batch15m")
FAMILIES = O.FAMILIES
VARIANTS: dict[str, dict[str, Any]] = {
    "SN": {},
    "A1": {SN_LAYERS_KEY: "no_strategic"},
    "A2": {SN_LAYERS_KEY: "no_strategic", "dispatch_on_flag::coordinator": False},
    "A3": {SN_LAYERS_KEY: "specialist_only", "dispatch_on_flag::coordinator": False},
}
ARMS = ("SN", "A1", "A2", "A3", "U1", "B2L")
OUT_DIR = os.path.join(_BASE_DIR, "results", "fase1_ablacao")


def blocks() -> dict[str, dict[str, Any]]:
    """One block per (level, family), <= 5 min each; campaign_multihost in 2 seed halves."""
    out = {}
    for cond in LEVELS:
        for fam in FAMILIES:
            if fam == "campaign_multihost":
                out[f"{cond}_{fam}_part1"] = {"condition": cond, "family": fam, "seeds": SEEDS[:50]}
                out[f"{cond}_{fam}_part2"] = {"condition": cond, "family": fam, "seeds": SEEDS[50:]}
            else:
                out[f"{cond}_{fam}"] = {"condition": cond, "family": fam, "seeds": SEEDS}
    return out


def run_arm(arm: str, f1, condition: str, table):
    if arm not in VARIANTS:
        return O.run_arm(arm, f1, condition, table)
    knobs = VARIANTS[arm]
    host_segments = {h: PROFILE_SEGMENT[p] for h, p in f1.host_profiles.items()}
    cfg = load_config(F.SN_CONFIG)
    tr = Transport("sn", cfg, F.INTRA, boundary=O.CONDITIONS[condition], host_segments=host_segments,
                   sn_routing=sn_router(cfg, f1.host_profiles), sn_layers=knobs.get(SN_LAYERS_KEY, "full"))
    _, logs, _ = run_generated("sn", f1.scenario, domain_config=cfg, policies={**B.arm_policies("SN", f1, table), **knobs},
                               transport=tr, return_logs=True, host_profiles=f1.host_profiles)
    return logs, tr


def job(args) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    family, seed, condition = args
    f1 = B.scenario(family, seed, 1, P_PRE)
    params, table = B.damage_params(f1), F.profile_table(F.load_thresholds(), 1)
    head = {"status": EXPLORATORY, "set": "ablacao", "family": family, "seed": seed, "h": 1, "condition": condition,
            "p_pre": P_PRE}
    rows, recs = [], []
    for arm in ARMS:
        logs, tr = run_arm(arm, f1, condition, table)
        extra = {**F.instrumentation(f1, logs, params), "crossings_boundary": tr.crossings.get("boundary", 0),
                 "crossing_bytes_boundary": tr.crossing_bytes.get("boundary", 0)}
        rows += B.evaluate(f1, logs, params, {**head, "arm": arm, **extra})
        names = Counter()
        for r in logs:
            if r["event_type"] == "action_dispatched":
                for label in r["payload"]["actions"]:
                    names[f"{r['layer']}|{parse_action_label(label)[0]}"] += 1
        recs.append({"level": condition, "family": family, "seed": seed, "arm": arm, "action_names": dict(names),
                     **extras(f1, logs, tr, params)})
    return rows, recs


# --- manifest / checkpoint (same scheme as the official driver) ----------------------------------
def load_manifest(out: str) -> dict[str, Any]:
    path = os.path.join(out, "manifest.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return {"preregistration": "docs/fase1/11_ablacao.md (EXPLORATORY)", "python": platform.python_version(),
            "platform": platform.platform(), "blocks": {}}


def run_block(name: str, out: str, workers: int, seeds_override: Optional[tuple[int, ...]] = None) -> str:
    spec = blocks()[name]
    seeds = seeds_override or spec["seeds"]
    raw = os.path.join(out, "raw", f"{name}.csv")
    ext = os.path.join(out, "extras", f"{name}.jsonl.gz")
    manifest = load_manifest(out)
    done = manifest["blocks"].get(name)
    if done and os.path.exists(raw) and O.sha256(raw) == done["sha256"] and os.path.exists(ext):
        return f"{name}: checkpoint ok, skipped"
    t0, started = time.time(), datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with Pool(workers) as pool:
        res = pool.map(job, [(spec["family"], s, spec["condition"]) for s in seeds], chunksize=1)
    rows = sorted((r for rs, _ in res for r in rs),
                  key=lambda r: (r["family"], r["seed"], r["h"], r["condition"], r["arm"], r["incident"]))
    recs = sorted((x for _, xs in res for x in xs), key=lambda x: (x["seed"], ARMS.index(x["arm"])))
    os.makedirs(os.path.dirname(raw), exist_ok=True)
    os.makedirs(os.path.dirname(ext), exist_ok=True)
    B.write_csv(raw + ".tmp", rows)
    os.replace(raw + ".tmp", raw)
    with gzip.open(ext + ".tmp", "wt", encoding="utf-8") as fh:
        for x in recs:
            fh.write(json.dumps(x, sort_keys=True) + "\n")
    os.replace(ext + ".tmp", ext)
    manifest = load_manifest(out)  # re-read: another block may have finished meanwhile
    manifest["blocks"][name] = {"file": os.path.relpath(raw, out), "sha256": O.sha256(raw), "rows": len(rows),
                                "extras": os.path.relpath(ext, out), "seeds": [seeds[0], seeds[-1]],
                                "condition": spec["condition"], "family": spec["family"], "arms": list(ARMS),
                                "commit": O.git_commit(), "python": platform.python_version(), "started_utc": started,
                                "elapsed_s": round(time.time() - t0, 1),
                                "command": f"python3 simulation/fase1_ablacao_experiments.py run --block {name}"}
    O.save_manifest(out, manifest)
    return f"{name}: {len(rows)} rows in {time.time() - t0:.0f} s"


def main(argv: Optional[list[str]] = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("blocks", "run", "run-all", "analyze"):
        sp = sub.add_parser(name)
        sp.add_argument("--out", default=OUT_DIR)
        if name in ("run", "run-all"):
            sp.add_argument("--workers", type=int, default=os.cpu_count() or 1)
        if name == "run":
            sp.add_argument("--block", required=True, choices=list(blocks()))
    a = ap.parse_args(argv)
    os.makedirs(a.out, exist_ok=True)
    if a.cmd == "blocks":
        print("\n".join(blocks()))
    elif a.cmd == "run":
        print(run_block(a.block, a.out, a.workers), flush=True)
    elif a.cmd == "run-all":
        for n in blocks():
            print(run_block(n, a.out, a.workers), flush=True)
    else:
        from analysis.fase1_ablacao import analyze

        analyze(a.out)


if __name__ == "__main__":
    main()
