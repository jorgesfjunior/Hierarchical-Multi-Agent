"""Fase 1 official (confirmatory) driver: SN / U1 / B2L with the Fase 1b configuration, F2 with two
more boundary levels (batch 5 min, 15 min), seeds 5000-5499.

Pre-registration (frozen): docs/fase1/08_preregistro_oficial.md, docs/fase1/08_preregistro_oficial.freeze.json.
No simulation code changes: every arm, scenario, damage and evaluation function is the Fase 1b one;
the new F2 levels are values of the same ``Boundary``.

    python3 simulation/fase1_oficial_experiments.py blocks --stage pre      # block names, in order
    python3 simulation/fase1_oficial_experiments.py run --block main_h1_oracle_interleaved
    python3 simulation/fase1_oficial_experiments.py check-pre               # H0, C0 (exit 1 on failure)
    python3 simulation/fase1_oficial_experiments.py analyze                 # H1-H4 (Holm) + descriptives

``run`` is checkpointed: a block whose raw file exists and matches the manifest sha256 is skipped.
``--smoke`` uses 2 seeds per cell (5000-5001), for testing the pipeline only.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from multiprocessing import Pool
from typing import Any, Optional

import numpy as np

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from analysis.fase1_oficial_stats import (ci95, cluster_bootstrap, logit_cluster, mcnemar_exact_one_sided,  # noqa: E402
                                          normal_sf)
from analysis.stats import holm  # noqa: E402
from graph.build_sn_graph import sn_router  # noqa: E402
from simulation import fase1_experiments as F  # noqa: E402
from simulation import fase1b_experiments as B  # noqa: E402
from simulation.experiment import add_keep_tmp_arg, apply_keep_tmp_arg, load_config, run_generated  # noqa: E402
from simulation.fase1 import CAMPAIGN_E1_E2, P_PRE, PROFILE_SEGMENT, Fase1Scenario  # noqa: E402
from simulation.transport import Boundary, Transport  # noqa: E402

CONFIRMATORY = "CONFIRMATORY"
FAMILIES = B.FAMILIES
SEEDS = tuple(range(5000, 5500))
SMOKE_SEEDS = SEEDS[:2]
_RESTRICTED = F.CONDITIONS["restricted"]
CONDITIONS = {**F.CONDITIONS,  # level index (H4): oracle 0, restricted 1, batch5m 2, batch15m 3
              "batch5m": Boundary(latency_s=_RESTRICTED.latency_s, batch_s=300.0,
                                  bandwidth_bytes_per_s=_RESTRICTED.bandwidth_bytes_per_s),
              "batch15m": Boundary(latency_s=_RESTRICTED.latency_s, batch_s=900.0,
                                   bandwidth_bytes_per_s=_RESTRICTED.bandwidth_bytes_per_s)}
LEVELS = ("oracle", "restricted", "batch5m", "batch15m")
P_PRE_LEVELS = (0.2, 0.5, 0.8)
MARGIN_EQ, MARGIN_NI, UNAV, ALPHA = 0.05, -0.05, 0.05, 0.05
OUT_DIR = os.path.join(_BASE_DIR, "results", "fase1_oficial")
FREEZE = os.path.join(_BASE_DIR, "docs", "fase1", "08_preregistro_oficial.freeze.json")


# --- blocks (08_preregistro_oficial.md §4) ----------------------------------------------------------
def blocks() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for cond in ("oracle", "restricted"):
        for h in (0, 1):
            for fam in FAMILIES:
                out.update(_split(f"main_h{h}_{cond}_{fam}", {"family": fam, "h": h, "condition": cond, "p_pre": P_PRE,
                                                              "arms": F.ARMS, "set": "principal"}))
    for cond in ("batch5m", "batch15m"):
        for fam in FAMILIES:
            out.update(_split(f"frontier_{cond}_{fam}", {"family": fam, "h": 1, "condition": cond, "p_pre": P_PRE,
                                                         "arms": F.ARMS, "set": "fronteira"}))
    for p in P_PRE_LEVELS:
        out[f"ppre_{p}"] = {"family": CAMPAIGN_E1_E2, "h": 1, "condition": "restricted", "p_pre": p,
                            "arms": ("SN", "B2L"), "set": f"p_pre_{p}"}
    return out


def _split(name: str, spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """campaign_multihost with h = 1 takes > 5 min per 500 seeds (the oracle block took 476 s): from the
    restricted cell on, it runs in 3 seed ranges (same jobs, same rows; deviation declared in the report)."""
    if spec["family"] != "campaign_multihost" or spec["h"] != 1 or spec["condition"] == "oracle":
        return {name: spec}
    return {f"{name}_part{i + 1}": {**spec, "part": (i, 3)} for i in range(3)}


def block_seeds(spec: dict[str, Any], smoke: bool) -> tuple[int, ...]:
    seeds = SMOKE_SEEDS if smoke else SEEDS
    if "part" not in spec:
        return seeds
    i, n = spec["part"]
    k = -(-len(seeds) // n)
    return seeds[i * k:(i + 1) * k]


def stage(name: str) -> str:
    """'pre' = the cells H0 and C0 need (run first), 'rest' = everything else."""
    b = blocks()[name]
    if b["set"] == "principal" and (b["condition"] == "oracle" or (b["h"] == 0 and b["family"] == CAMPAIGN_E1_E2)):
        return "pre"
    return "rest"


# --- one job = one (family, seed, h, condition, p_pre), every arm -----------------------------------
def run_arm(arm: str, f1: Fase1Scenario, condition: str, table):
    """B.run_arm with the boundary looked up in CONDITIONS (which adds the two F2 levels)."""
    arch = F.ARCH[arm]
    host_segments = {h: PROFILE_SEGMENT[p] for h, p in f1.host_profiles.items()}
    cfg = load_config(F.SN_CONFIG) if arm == "SN" else None
    tr = Transport(arch, cfg, F.INTRA, boundary=CONDITIONS[condition], host_segments=host_segments,
                   sn_routing=sn_router(cfg, f1.host_profiles) if arm == "SN" else None)
    _, logs, _ = run_generated(arch, f1.scenario, domain_config=cfg, policies=B.arm_policies(arm, f1, table),
                               transport=tr, return_logs=True, host_profiles=f1.host_profiles)
    return logs, tr


def job(args) -> list[dict[str, Any]]:
    """B.job with the arm list as an argument; same rows (status and set are labels)."""
    family, seed, h, condition, thresholds, p_pre, tag, arms, status = args
    f1 = B.scenario(family, seed, h, p_pre)
    params, table = B.damage_params(f1), F.profile_table(thresholds, h)
    head = {"status": status, "set": tag, "family": family, "seed": seed, "h": h, "condition": condition, "p_pre": p_pre}
    rows = B.evaluate(f1, [], params, {**head, "arm": "NO-DEFENSE"}) if condition == "oracle" else []
    for arm in arms:
        logs, tr = run_arm(arm, f1, condition, table)
        extra = {**F.instrumentation(f1, logs, params), "crossings_boundary": tr.crossings.get("boundary", 0),
                 "crossing_bytes_boundary": tr.crossing_bytes.get("boundary", 0)}
        rows += B.evaluate(f1, logs, params, {**head, "arm": arm, **extra})
    return rows


# --- manifest and checkpoint ------------------------------------------------------------------------
def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git_commit() -> Optional[str]:
    try:
        c = subprocess.run(["git", "-C", _BASE_DIR, "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        dirty = subprocess.run(["git", "-C", _BASE_DIR, "status", "--porcelain", "--untracked-files=no"],
                               capture_output=True, text=True, check=True).stdout.strip()
        return c.stdout.strip() + ("-dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return os.environ.get("REPRO_COMMIT")


def load_manifest(out: str) -> dict[str, Any]:
    path = os.path.join(out, "manifest.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    freeze = {}
    if os.path.exists(FREEZE):
        with open(FREEZE, encoding="utf-8") as fh:
            freeze = json.load(fh)
    return {"preregistration": "docs/fase1/08_preregistro_oficial.md", "freeze_utc": freeze.get("frozen_utc"),
            "freeze_commit": freeze.get("freeze_commit"), "python": platform.python_version(),
            "platform": platform.platform(), "blocks": {}}


def save_manifest(out: str, manifest: dict[str, Any]) -> None:
    tmp = os.path.join(out, "manifest.json.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, os.path.join(out, "manifest.json"))


def run_block(name: str, out: str, workers: int, smoke: bool, command: str) -> str:
    spec = blocks()[name]
    seeds = block_seeds(spec, smoke)
    raw = os.path.join(out, "raw", f"{name}.csv")
    manifest = load_manifest(out)
    done = manifest["blocks"].get(name)
    if done and os.path.exists(raw) and sha256(raw) == done["sha256"]:
        return f"{name}: checkpoint ok, skipped"
    th = F.load_thresholds()
    jobs = [(spec["family"], s, spec["h"], spec["condition"], th, spec["p_pre"], spec["set"], spec["arms"], CONFIRMATORY)
            for s in seeds]
    t0, started = time.time(), datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = []
    if jobs:  # a --smoke part can be empty
        with Pool(workers) as pool:
            rows = [r for chunk in pool.imap_unordered(job, jobs, chunksize=2) for r in chunk]
    rows.sort(key=lambda r: (r["family"], r["seed"], r["h"], r["condition"], r["arm"], r["incident"]))
    os.makedirs(os.path.dirname(raw), exist_ok=True)
    B.write_csv(raw + ".tmp", rows)
    os.replace(raw + ".tmp", raw)
    manifest = load_manifest(out)  # re-read: another block may have finished meanwhile
    manifest["blocks"][name] = {"file": os.path.relpath(raw, out), "sha256": sha256(raw), "rows": len(rows),
                                "seeds": [seeds[0], seeds[-1]] if seeds else [], "command": command, "commit": git_commit(),
                                "python": platform.python_version(), "started_utc": started,
                                "elapsed_s": round(time.time() - t0, 1), **{k: v for k, v in spec.items() if k != "arms"},
                                "arms": list(spec["arms"])}
    save_manifest(out, manifest)
    return f"{name}: {len(rows)} rows in {time.time() - t0:.0f} s -> {raw}"


# --- analysis (08_preregistro_oficial.md §6-§8) -----------------------------------------------------
def load_rows(out: str, names) -> list[dict[str, str]]:
    rows = []
    for n in names:
        with open(os.path.join(out, "raw", f"{n}.csv"), encoding="utf-8") as fh:
            rows += list(csv.DictReader(fh))
    return rows


class Data:
    """Indexes rows by (set, condition, h, arm) -> {unit: contained} and {run: unavailability}."""

    def __init__(self, rows: list[dict[str, str]]):
        self.y: dict[tuple, dict[tuple, float]] = {}
        self.unav: dict[tuple, dict[tuple, float]] = {}
        self.rows = rows
        for r in rows:
            key = (r["set"], r["condition"], int(r["h"]), r["arm"])
            self.y.setdefault(key, {})[(r["family"], int(r["seed"]), r["incident"])] = float(r["contained_before_impact"] == "True")
            self.unav.setdefault(key, {})[(r["family"], int(r["seed"]))] = float(r["unavailability_fraction"])

    def units(self, set_, cond, h, arm, families) -> dict[tuple, float]:
        return {u: v for u, v in self.y.get((set_, cond, h, arm), {}).items() if u[0] in families}

    def runs(self, set_, cond, h, arm, families) -> dict[tuple, float]:
        return {u: v for u, v in self.unav.get((set_, cond, h, arm), {}).items() if u[0] in families}


def _set_of(cond: str) -> str:
    return "principal" if cond in ("oracle", "restricted") else "fronteira"


def proportion(data: Data, cond, h, arm, families, set_=None) -> dict[str, Any]:
    y = data.units(set_ or _set_of(cond), cond, h, arm, families)
    keys = sorted(y)
    draws = cluster_bootstrap([k[1] for k in keys], [y[k] for k in keys])
    lo, hi = ci95(draws)
    return {"arm": arm, "condition": cond, "h": h, "families": list(families), "n": len(keys),
            "p": sum(y.values()) / len(keys), "ci_lo": lo, "ci_hi": hi}


def contrast(data: Data, cond, h, a, b, families, set_=None) -> dict[str, Any]:
    """Δ = p(a) - p(b), paired by campaign; cluster bootstrap CI; McNemar counts; Δ unavailability."""
    s = set_ or _set_of(cond)
    ya, yb = data.units(s, cond, h, a, families), data.units(s, cond, h, b, families)
    keys = sorted(ya)
    assert keys and keys == sorted(yb), (cond, h, a, b, families)
    d = [ya[k] - yb[k] for k in keys]
    draws = cluster_bootstrap([k[1] for k in keys], d)
    lo, hi = ci95(draws)
    ua, ub = data.runs(s, cond, h, a, families), data.runs(s, cond, h, b, families)
    du = [ua[k] - ub[k] for k in sorted(ua)]
    n_b = sum(1 for x in d if x > 0)
    n_c = sum(1 for x in d if x < 0)
    return {"comparison": f"{a} - {b}", "condition": cond, "h": h, "families": list(families), "n": len(keys),
            "p_a": sum(ya.values()) / len(keys), "p_b": sum(yb.values()) / len(keys), "delta": sum(d) / len(d),
            "ci_lo": lo, "ci_hi": hi, "ci_one_sided_lo": float(np.quantile(draws, 0.05)),
            "b": n_b, "c": n_c, "delta_unav": sum(du) / len(du), "unav_ok": sum(du) / len(du) <= UNAV,
            "_draws": draws}


def preconditions(data: Data) -> dict[str, Any]:
    out = {}
    for h in (0, 1):
        c = contrast(data, "oracle", h, "SN", "U1", FAMILIES)
        out[f"H0_h{h}"] = {**_public(c), "pass": -MARGIN_EQ <= c["ci_lo"] and c["ci_hi"] <= MARGIN_EQ}
    c = contrast(data, "restricted", 0, "SN", "B2L", (CAMPAIGN_E1_E2,))
    out["C0"] = {**_public(c), "pass": -MARGIN_EQ <= c["ci_lo"] and c["ci_hi"] <= MARGIN_EQ}
    return out


def _public(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if not k.startswith("_")}


def h4(data: Data) -> dict[str, Any]:
    X, y, cl, per_level = [], [], [], []
    for k, cond in enumerate(LEVELS):
        for arm in ("SN", "U1"):
            units = data.units(_set_of(cond), cond, 1, arm, FAMILIES)
            for u in sorted(units):
                sn = 1.0 if arm == "SN" else 0.0
                X.append([1.0, sn, float(k), sn * k])
                y.append(units[u])
                cl.append(u[1])
        per_level.append(_public(contrast(data, cond, 1, "SN", "U1", FAMILIES)))
    beta, cov = logit_cluster(np.array(X), np.array(y), cl)
    se = float(np.sqrt(cov[3, 3]))
    return {"beta": beta.tolist(), "se": np.sqrt(np.diag(cov)).tolist(), "beta3": float(beta[3]), "se3": se,
            "beta3_ci": [float(beta[3] - 1.959963984540054 * se), float(beta[3] + 1.959963984540054 * se)],
            "p": normal_sf(float(beta[3]) / se), "n": len(y), "per_level": per_level,
            "unav_ok": all(p["unav_ok"] for p in per_level)}


def analyze(out: str) -> dict[str, Any]:
    data = Data(load_rows(out, blocks()))
    pre = preconditions(data)
    fam_e = (CAMPAIGN_E1_E2,)
    c1 = contrast(data, "restricted", 1, "SN", "B2L", fam_e)
    c2 = contrast(data, "restricted", 1, "SN", "U1", FAMILIES)
    r4 = h4(data)
    tests = {
        "H1": {**_public(c1), "test": "McNemar exato unilateral", "p_raw": mcnemar_exact_one_sided(c1["b"], c1["c"])},
        "H2": {**_public(c2), "test": "não inferioridade, bootstrap de clusters (margem -0,05)",
               "p_raw": (1 + int(np.sum(c2["_draws"] <= MARGIN_NI))) / (len(c2["_draws"]) + 1)},
        "H3": {**_public(c2), "test": "McNemar exato unilateral", "p_raw": mcnemar_exact_one_sided(c2["b"], c2["c"])},
        "H4": {**r4, "test": "logística, interação braço x nível, EP robusto por seed", "p_raw": r4["p"]},
    }
    adj = holm([t["p_raw"] for t in tests.values()])
    for (name, t), p in zip(tests.items(), adj):
        t["p_holm"] = p
        t["confirmed"] = bool(p < ALPHA and t["unav_ok"])
    desc: dict[str, Any] = {"B2L_vs_U1": _public(contrast(data, "restricted", 1, "B2L", "U1", FAMILIES))}
    desc["per_family"] = {f: {"SN_vs_U1": _public(contrast(data, "restricted", 1, "SN", "U1", (f,))),
                              "SN_vs_B2L": _public(contrast(data, "restricted", 1, "SN", "B2L", (f,)))} for f in FAMILIES}
    desc["p_pre"] = {}
    for p in P_PRE_LEVELS:
        desc["p_pre"][str(p)] = {**_public(contrast(data, "restricted", 1, "SN", "B2L", fam_e, set_=f"p_pre_{p}")),
                                 "props": [proportion(data, "restricted", 1, a, fam_e, set_=f"p_pre_{p}") for a in ("SN", "B2L")]}
    ppre_same = data.units("p_pre_0.5", "restricted", 1, "SN", fam_e) == data.units("principal", "restricted", 1, "SN", fam_e) \
        and data.units("p_pre_0.5", "restricted", 1, "B2L", fam_e) == data.units("principal", "restricted", 1, "B2L", fam_e)
    desc["p_pre_0.5_reproduces_principal"] = ppre_same
    props = {}
    for name, cond, h, fams in (("all_h1_restricted", "restricted", 1, FAMILIES), ("e1e2_h1_restricted", "restricted", 1, fam_e),
                                ("e1e2_h0_restricted", "restricted", 0, fam_e)):
        props[name] = [proportion(data, cond, h, a, fams) for a in F.ARMS]
    for cond in LEVELS:
        props[f"levels_{cond}"] = [proportion(data, cond, 1, a, FAMILIES) for a in F.ARMS]
    for f in FAMILIES:
        props[f"family_{f}"] = [proportion(data, "restricted", 1, a, (f,)) for a in F.ARMS]
    desc["proportions"] = props
    desc["secondary"] = secondary(data)
    result = {"preconditions": pre, "tests": tests, "descriptive": desc}
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=1, ensure_ascii=False, default=float)
        fh.write("\n")
    return result


def secondary(data: Data) -> dict[str, Any]:
    """Per (cell, arm): unavailability (with a cluster CI), loss per host, advisories (one value per run)."""
    out = {}
    seen: dict[tuple, dict[tuple, dict[str, str]]] = {}
    for r in data.rows:
        seen.setdefault((r["set"], r["condition"], r["h"], r["arm"]), {}).setdefault((r["family"], r["seed"]), r)
    loss: dict[tuple, list[float]] = {}
    for r in data.rows:
        loss.setdefault((r["set"], r["condition"], r["h"], r["arm"]), []).append(float(r["data_loss_per_host"]))
    for key, runs in sorted(seen.items()):
        if key[3] == "NO-DEFENSE":
            continue
        rs = [runs[k] for k in sorted(runs)]
        unav = [float(r["unavailability_fraction"]) for r in rs]
        lo, hi = ci95(cluster_bootstrap([int(r["seed"]) for r in rs], unav))
        lat = [float(r["advisory_latency_mean_s"]) for r in rs if r.get("advisory_latency_mean_s")]
        out["|".join(key)] = {"runs": len(rs), "unavailability": sum(unav) / len(unav), "unav_ci": [lo, hi],
                              "data_loss_per_host": sum(loss[key]) / len(loss[key]),
                              "advisories": sum(float(r["advisories"]) for r in rs) / len(rs),
                              "advisories_false": sum(float(r["advisories_false"]) for r in rs) / len(rs),
                              "advisory_latency_mean_s": sum(lat) / len(lat) if lat else None}
    return out


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("blocks", "run", "check-pre", "analyze"):
        sp = sub.add_parser(name)
        sp.add_argument("--out", default=OUT_DIR)
        if name == "blocks":
            sp.add_argument("--stage", choices=("pre", "rest", "all"), default="all")
        if name == "run":
            sp.add_argument("--block", required=True, choices=list(blocks()))
            sp.add_argument("--workers", type=int, default=os.cpu_count() or 1)
            sp.add_argument("--smoke", action="store_true", help="2 seeds per cell (pipeline test only)")
            add_keep_tmp_arg(sp)
    args = parser.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    if args.cmd == "blocks":
        for n in blocks():
            if args.stage == "all" or stage(n) == args.stage:
                print(n)
    elif args.cmd == "run":
        apply_keep_tmp_arg(args)
        command = "python3 simulation/fase1_oficial_experiments.py run --block " + args.block + (" --smoke" if args.smoke else "")
        print(run_block(args.block, args.out, args.workers, args.smoke, command))
    elif args.cmd == "check-pre":
        data = Data(load_rows(args.out, [n for n in blocks() if stage(n) == "pre"]))
        pre = preconditions(data)
        with open(os.path.join(args.out, "preconditions.json"), "w", encoding="utf-8") as fh:
            json.dump(pre, fh, indent=1, ensure_ascii=False)
            fh.write("\n")
        for k, v in pre.items():
            print(f"{k}: delta={v['delta']:+.4f} IC95=[{v['ci_lo']:+.4f}; {v['ci_hi']:+.4f}] n={v['n']} "
                  f"b={v['b']} c={v['c']} -> {'PASSA' if v['pass'] else 'FALHA'}")
        sys.exit(0 if all(v["pass"] for v in pre.values()) else 1)
    else:
        res = analyze(args.out)
        for k, t in res["tests"].items():
            print(f"{k}: delta={t.get('delta', t.get('beta3')):+.4f} p={t['p_raw']:.3g} holm={t['p_holm']:.3g} "
                  f"unav_ok={t['unav_ok']} confirmed={t['confirmed']}")


if __name__ == "__main__":
    main()
