"""Fase 1, caminho A: análise de E1 (H5, confirmatória) e E2 (descritiva). Pré-registro: docs/fase1/14_preregistro_A.md.

    python3 analysis/fase1_A.py [--out results/fase1_A]

E1 (§3): Δ = p(A3) − p(SN) por campanha (5 famílias juntas), em cada nível de fronteira; TOST por bootstrap de
clusters (cluster = seed; 10 000; default_rng(0)): p_inf = (1 + #{Δ* <= −m}) / 10 001, p_sup = (1 + #{Δ* >= +m}) /
10 001, p_TOST = máx; H5 confirmada se p_TOST < 0,05 nos dois níveis com m = 1 pp (primária); m = 2 pp é a
verificação secundária. E2 (§4): curvas por braço e multiplicador, IC95 % por bootstrap de clusters; piso de FP.
Saída: <out>/summary.json e <out>/figs/E2_protecao_vs_isolados.{png,pdf}.
"""
from __future__ import annotations

import argparse
import csv
import glob
import gzip
import json
import math
import os
import sys
from collections import Counter, defaultdict
from typing import Any, Optional

import numpy as np

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from analysis.fase1_etapa3 import mean_ci, quant_ci, ratio_ci  # noqa: E402  (10 000 / 2 000, default_rng(0))

OUT = os.path.join(_BASE_DIR, "results", "fase1_A")
N_BOOT = 10_000
LEVELS = ("restricted", "batch15m")
FAMILIES = ("encryption_stream", "campaign_multihost", "split_visibility_late_confirm", "interleaved", "campaign_e1_e2")
MARGINS = {"primaria_1pp": 0.01, "secundaria_2pp": 0.02}
E1_ARMS, E2_ARMS = ("SN", "A3"), ("SN", "U1", "B2L")
MULTIPLIERS = (0.5, 0.75, 1.0, 1.25, 1.5, 2.0)
COLOR = {"SN": "#4A6FB0", "A3": "#22385F", "U1": "#6E6E6E", "B2L": "#9A9A9A"}
STYLE = {"SN": "-", "U1": "--", "B2L": ":"}
MARKER = {"SN": "o", "U1": "s", "B2L": "^"}
LABEL_OFFSET = {"SN": (7, 5, "left"), "U1": (7, -11, "left"), "B2L": (-7, 4, "right")}  # só posição dos rótulos
NAME = {"SN": "MAS proposto (SN)", "A3": "A3: só especialistas + avisos", "U1": "Controle central (MAPE-K)",
        "B2L": "Regras locais sem agentes"}
UNSCALED_EVENT = "privilege_escalation_attempt"  # detector sem limiar (14 §4.1, limitação 2)


def _truthy(x: str) -> bool:
    return str(x) == "True"


def _num(x) -> Optional[float]:
    return None if x in ("", None) else float(x)


# --- carga ----------------------------------------------------------------------------------------
def load(out: str, exp: str):
    rows, ext = [], []
    for p in sorted(glob.glob(os.path.join(out, "raw", f"{exp}_*.csv"))):
        with open(p, encoding="utf-8") as fh:
            rows += list(csv.DictReader(fh))
    for p in sorted(glob.glob(os.path.join(out, "extras", f"{exp}_*.jsonl.gz"))):
        with gzip.open(p, "rt", encoding="utf-8") as fh:
            ext += [json.loads(x) for x in fh]
    bad = {r["status"] for r in rows} - {"CONFIRMATORY" if exp == "E1" else "DESCRIPTIVE"}
    if bad:
        raise SystemExit(f"{exp}: linhas com status inesperado {bad}")
    return rows, ext


def units(rows, key: str, val, arm: str) -> dict[tuple, dict[str, str]]:
    return {(r["family"], int(r["seed"]), r["incident"]): r for r in rows if r[key] == val and r["arm"] == arm}


def runs(rows, key: str, val, arm: str) -> dict[tuple, dict[str, str]]:
    out = {}
    for r in rows:
        if r[key] == val and r["arm"] == arm:
            out.setdefault((r["family"], int(r["seed"])), r)
    return out


# --- E1: TOST por bootstrap de clusters ------------------------------------------------------------
def paired_bootstrap(clusters: list[int], diffs: list[float]) -> np.ndarray:
    """Δ* = (soma das diferenças nos clusters sorteados) / (número de unidades sorteadas) (08 §7)."""
    index: dict = {}
    g = np.array([index.setdefault(c, len(index)) for c in clusters])
    s, n = np.zeros(len(index)), np.zeros(len(index))
    np.add.at(s, g, np.asarray(diffs, dtype=float))
    np.add.at(n, g, 1.0)
    idx = np.random.default_rng(0).integers(0, len(index), size=(N_BOOT, len(index)))
    return s[idx].sum(axis=1) / n[idx].sum(axis=1)


def mcnemar_two_sided(b: int, c: int) -> float:
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def tost(draws: np.ndarray, margin: float) -> dict[str, Any]:
    p_inf = (1 + int((draws <= -margin).sum())) / (N_BOOT + 1)
    p_sup = (1 + int((draws >= margin).sum())) / (N_BOOT + 1)
    lo90, hi90 = float(np.quantile(draws, 0.05)), float(np.quantile(draws, 0.95))
    if -margin < lo90 and hi90 < margin:
        reading = "equivalente"
    elif hi90 <= -margin:
        reading = "A3 protege menos"
    elif lo90 >= margin:
        reading = "A3 protege mais"
    else:
        reading = "inconclusivo"
    return {"margin": margin, "p_inf": p_inf, "p_sup": p_sup, "p_tost": max(p_inf, p_sup), "ci90": [lo90, hi90],
            "equivalent": max(p_inf, p_sup) < 0.05, "reading": reading}


def e1_contrast(rows, lv: str, a: str = "A3", b: str = "SN") -> dict[str, Any]:
    ua, ub = units(rows, "condition", lv, a), units(rows, "condition", lv, b)
    keys = sorted(ub)
    if set(ua) != set(ub):
        raise SystemExit(f"E1 {lv}: campanhas não pareadas entre {a} e {b}")
    xa = [float(_truthy(ua[k]["contained_before_impact"])) for k in keys]
    xb = [float(_truthy(ub[k]["contained_before_impact"])) for k in keys]
    d = [p - q for p, q in zip(xa, xb)]
    clusters = [k[1] for k in keys]
    draws = paired_bootstrap(clusters, d)
    disc_plus = sum(1 for x in d if x > 0)
    disc_minus = sum(1 for x in d if x < 0)
    loss = [float(ua[k]["data_loss_per_host"]) - float(ub[k]["data_loss_per_host"]) for k in keys]
    return {"level": lv, "comparison": f"{a} - {b}", "n_campaigns": len(keys), "n_seeds": len(set(clusters)),
            "p_" + a: sum(xa) / len(xa), "p_" + b: sum(xb) / len(xb), "delta": sum(d) / len(d),
            "ci95": [float(np.quantile(draws, 0.025)), float(np.quantile(draws, 0.975))],
            "discordant_A3_contains_SN_not": disc_plus, "discordant_SN_contains_A3_not": disc_minus,
            "mcnemar_two_sided_p": mcnemar_two_sided(disc_plus, disc_minus),
            "tost": {name: tost(draws, m) for name, m in MARGINS.items()},
            "delta_data_loss_per_host": mean_ci(clusters, loss),
            "per_family": {f: {"delta": (sum(x for k, x in zip(keys, d) if k[0] == f) / max(1, sum(1 for k in keys if k[0] == f))),
                               "n": sum(1 for k in keys if k[0] == f)} for f in FAMILIES}}


def _ext_index(ext, key: str):
    return {(x[key], x["family"], x["seed"], x["arm"]): x for x in ext}


def e1_secondary(rows, ext) -> dict[str, Any]:
    idx = _ext_index(ext, "level")
    out = {}
    for lv in LEVELS:
        for arm in E1_ARMS:
            u = units(rows, "condition", lv, arm)
            rr = runs(rows, "condition", lv, arm)
            xs = [x for k, x in idx.items() if k[0] == lv and k[3] == arm]
            uc = [k[1] for k in u]
            rc = [k[1] for k in rr]
            xc = [x["seed"] for x in xs]
            fa = [(x["seed"], c["first_action_s"]) for x in xs for c in x["campaigns"] if c["first_action_s"] is not None]
            out[f"{lv}|{arm}"] = {
                "p": mean_ci(uc, [float(_truthy(r["contained_before_impact"])) for r in u.values()]),
                "data_loss_per_host": mean_ci(uc, [float(r["data_loss_per_host"]) for r in u.values()]),
                "unavailability": mean_ci(rc, [float(r["unavailability_fraction"]) for r in rr.values()]),
                "boundary_msgs_per_run": mean_ci(rc, [float(r["crossings_boundary"]) for r in rr.values()]),
                "boundary_bytes_per_run": mean_ci(rc, [float(r["crossing_bytes_boundary"]) for r in rr.values()]),
                "all_link_msgs_per_run": mean_ci(xc, [float(sum(x["comm"]["crossings"].values())) for x in xs]),
                "agent_msgs_per_run": mean_ci(xc, [float(x["comm"]["agent_messages"]) for x in xs]),
                "first_action_median_s": quant_ci([s for s, _ in fa], [v for _, v in fa], 0.5),
                "first_action_p90_s": quant_ci([s for s, _ in fa], [v for _, v in fa], 0.9),
                "benign_isolated_per_run": mean_ci(xc, [float(sum(b["isolated"] for b in x["benign"].values())) for x in xs]),
                "advisories_per_run": mean_ci(rc, [float(r["advisories"]) for r in rr.values()]),
                "advisories_false_per_run": mean_ci(rc, [float(r["advisories_false"]) for r in rr.values()]),
                "strategic_only_labels": sum(v for x in xs for k, v in x["action_names"].items()
                                             if k.split("|")[1] in ("trigger_backup_restore", "segment_network")),
                "n_runs": len(rr), "n_campaigns": len(u)}
        # razões A3/SN (somas por seed)
        sn = {(x["family"], x["seed"]): x for k, x in idx.items() if k[0] == lv and k[3] == "SN"}
        a3 = {(x["family"], x["seed"]): x for k, x in idx.items() if k[0] == lv and k[3] == "A3"}
        ks = sorted(sn)
        rsn, ra3 = runs(rows, "condition", lv, "SN"), runs(rows, "condition", lv, "A3")
        out[f"{lv}|ratio_A3_SN"] = {
            "boundary_msgs": ratio_ci([k[1] for k in ks], [float(ra3[k]["crossings_boundary"]) for k in ks],
                                      [float(rsn[k]["crossings_boundary"]) for k in ks]),
            "all_link_msgs": ratio_ci([k[1] for k in ks], [float(sum(a3[k]["comm"]["crossings"].values())) for k in ks],
                                      [float(sum(sn[k]["comm"]["crossings"].values())) for k in ks]),
            "agent_msgs": ratio_ci([k[1] for k in ks], [float(a3[k]["comm"]["agent_messages"]) for k in ks],
                                   [float(sn[k]["comm"]["agent_messages"]) for k in ks])}
    return out


# --- E2 -------------------------------------------------------------------------------------------
def e2_curves(rows, ext) -> dict[str, Any]:
    idx = _ext_index(ext, "multiplier")
    out = {}
    for m in MULTIPLIERS:
        ms = repr(m)
        for arm in E2_ARMS:
            u = units(rows, "multiplier", ms, arm)
            rr = runs(rows, "multiplier", ms, arm)
            xs = [x for k, x in idx.items() if k[0] == m and k[3] == arm]
            uc, rc, xc = [k[1] for k in u], [k[1] for k in rr], [x["seed"] for x in xs]
            cls = [x["classification"]["any_containment"] for x in xs]
            iso = [sum(b["isolated"] for b in x["benign"].values()) for x in xs]
            floor_hosts = [sum(1 for keys in x["benign_isolation_triggers"]["hosts"].values()
                               if any(k.endswith("|" + UNSCALED_EVENT) for k in keys)) for x in xs]
            disp = Counter()
            first_kind = Counter()
            for x in xs:
                disp.update(x["benign_isolation_triggers"]["dispatches"])
                for keys in x["benign_isolation_triggers"]["hosts"].values():
                    first_kind.update({k.split("|")[0] for k in keys})
            total = sum(disp.values())
            by_event = Counter()
            for k, v in disp.items():
                by_event[k.split("|")[1]] += v
            by_kind = Counter()
            for k, v in disp.items():
                by_kind[k.split("|")[0]] += v
            n_benign = [len(x["benign"]) for x in xs]
            out[f"{ms}|{arm}"] = {
                "multiplier": m, "arm": arm, "n_runs": len(rr), "n_campaigns": len(u),
                "p": mean_ci(uc, [float(_truthy(r["contained_before_impact"])) for r in u.values()]),
                "benign_isolated_per_run": mean_ci(xc, [float(v) for v in iso]),
                "benign_any_action_per_run": mean_ci(xc, [float(sum(b["any"] for b in x["benign"].values())) for x in xs]),
                "benign_hosts_per_run": sum(n_benign) / max(1, len(n_benign)),
                "precision_any_containment": ratio_ci(xc, [float(c["tp"]) for c in cls], [float(c["tp"] + c["fp"]) for c in cls]),
                "warning_precision": (ratio_ci(rc, [float(r["advisories"]) - float(r["advisories_false"]) for r in rr.values()],
                                               [float(r["advisories"]) for r in rr.values()]) if arm != "B2L" else None),
                "warnings_per_run": mean_ci(rc, [float(r["advisories"]) for r in rr.values()]),
                "unavailability": mean_ci(rc, [float(r["unavailability_fraction"]) for r in rr.values()]),
                "fp_floor": {
                    "benign_isolated_by_unscaled_detector_per_run": mean_ci(xc, [float(v) for v in floor_hosts]),
                    "share_of_benign_isolated": (sum(floor_hosts) / sum(iso)) if sum(iso) else None,
                    "isolation_dispatches_by_trigger_event": {k: v / total for k, v in sorted(by_event.items())} if total else {},
                    "isolation_dispatches_by_kind": {k: v / total for k, v in sorted(by_kind.items())} if total else {},
                    "isolated_hosts_with_kind": dict(sorted(first_kind.items())),
                    "isolation_dispatches_total": total}}
    return out


def figure(curves: dict[str, Any], figdir: str) -> list[str]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    os.makedirs(figdir, exist_ok=True)
    fig, ax = plt.subplots(figsize=(7.2, 4.8), dpi=200)
    for arm in E2_ARMS:
        pts = [curves[f"{m!r}|{arm}"] for m in MULTIPLIERS]
        x = [c["benign_isolated_per_run"]["mean"] for c in pts]
        y = [100 * c["p"]["mean"] for c in pts]
        xe = [[c["benign_isolated_per_run"]["mean"] - c["benign_isolated_per_run"]["ci"][0] for c in pts],
              [c["benign_isolated_per_run"]["ci"][1] - c["benign_isolated_per_run"]["mean"] for c in pts]]
        ye = [[100 * (c["p"]["mean"] - c["p"]["ci"][0]) for c in pts], [100 * (c["p"]["ci"][1] - c["p"]["mean"]) for c in pts]]
        ax.errorbar(x, y, xerr=xe, yerr=ye, color=COLOR[arm], linestyle=STYLE[arm], marker=MARKER[arm], markersize=5,
                    linewidth=1.6, elinewidth=0.8, capsize=2, label=NAME[arm])
        for m, xi, yi in zip(MULTIPLIERS, x, y):
            dx, dy, ha = LABEL_OFFSET[arm]
            ax.annotate(f"×{m:g}", (xi, yi), textcoords="offset points", xytext=(dx, dy), ha=ha, fontsize=7, color=COLOR[arm])
    ax.set_xlabel("Hosts legítimos isolados por execução (de 9)")
    ax.set_ylabel("Ataques contidos antes do impacto (%)")
    ax.set_title("Proteção × custo em falsos positivos, por multiplicador de limiares (lote 60 s)", fontsize=9)
    ax.grid(True, linewidth=0.4, alpha=0.5)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(fontsize=8, frameon=False, loc="lower right")
    fig.tight_layout()
    paths = []
    for ext in ("png", "pdf"):
        p = os.path.join(figdir, f"E2_protecao_vs_isolados.{ext}")
        fig.savefig(p)
        paths.append(p)
    plt.close(fig)
    return paths


def analyze(out: str = OUT) -> dict[str, Any]:
    summary: dict[str, Any] = {"preregistration": "docs/fase1/14_preregistro_A.md"}
    r1, x1 = load(out, "E1")
    if r1:
        h5 = {lv: e1_contrast(r1, lv) for lv in LEVELS}
        summary["E1"] = {
            "H5": {"per_level": h5,
                   "confirmed_primary_1pp": all(h5[lv]["tost"]["primaria_1pp"]["equivalent"] for lv in LEVELS),
                   "confirmed_secondary_2pp": all(h5[lv]["tost"]["secundaria_2pp"]["equivalent"] for lv in LEVELS)},
            "secondary": e1_secondary(r1, x1)}
    r2, x2 = load(out, "E2")
    if r2:
        curves = e2_curves(r2, x2)
        summary["E2"] = {"curves": curves, "figures": [os.path.relpath(p, _BASE_DIR) for p in figure(curves, os.path.join(out, "figs"))]}
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1, ensure_ascii=False, sort_keys=True)
    return summary


def main(argv: Optional[list[str]] = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args(argv)
    s = analyze(a.out)
    print(json.dumps({k: v for k, v in s.items() if k != "E2"}, indent=1, ensure_ascii=False)[:4000])


if __name__ == "__main__":
    main()
