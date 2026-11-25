"""Etapa 3b (EXPLORATORY): análise descritiva do piloto de ablação (docs/fase1/11_ablacao.md §2 e §4).

    python3 simulation/fase1_ablacao_experiments.py analyze     # ou: python3 analysis/fase1_ablacao.py

Sem testes de hipótese: médias, medianas, P90, IC95 % por bootstrap de clusters (seed) e os vereditos
da regra declarada antes de rodar.
"""
from __future__ import annotations

import csv
import glob
import gzip
import json
import os
import sys
from collections import defaultdict
from typing import Any, Optional

import numpy as np

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from analysis.fase1_etapa3 import boot_sums, grouped, mean_ci, quant_ci, ratio_ci  # noqa: E402

OUT = os.path.join(_BASE_DIR, "results", "fase1_ablacao")
ARMS = ("SN", "A1", "A2", "A3", "U1", "B2L")
VARIANTS = ("A1", "A2", "A3")
LEVELS = ("restricted", "batch15m")
FAMILIES = ("encryption_stream", "campaign_multihost", "split_visibility_late_confirm", "interleaved", "campaign_e1_e2")
LAYERS = ("specialist", "coordinator", "strategic", "monolithic")
STRATEGIC_ONLY = ("trigger_backup_restore", "segment_network")
MARGIN_PP, LOSS_MARGIN, TRAFFIC_CUT = 1.0, 1000.0, 0.50
COLOR = {"SN": "#4A6FB0", "A1": "#7A97CC", "A2": "#A9BBDD", "A3": "#22385F", "U1": "#6E6E6E", "B2L": "#B5B5B5"}
NAME = {"SN": "MAS proposto (completo)", "A1": "A1: sem estratégico", "A2": "A2: coordenador só repassa",
        "A3": "A3: só avisos sobem", "U1": "Controle central (MAPE-K)", "B2L": "Regras locais sem agentes"}
LEVEL_NAME = {"restricted": "Lote de 60 s", "batch15m": "Lote de 15 min"}


def load(out: str):
    rows, ext = [], []
    for p in sorted(glob.glob(os.path.join(out, "raw", "*.csv"))):
        with open(p, encoding="utf-8") as fh:
            rows += list(csv.DictReader(fh))
    for p in sorted(glob.glob(os.path.join(out, "extras", "*.jsonl.gz"))):
        with gzip.open(p, "rt", encoding="utf-8") as fh:
            ext += [json.loads(x) for x in fh]
    return rows, ext


def _units(rows, lv, arm, fams=FAMILIES):
    return {(r["family"], int(r["seed"]), r["incident"]): r for r in rows
            if r["condition"] == lv and r["arm"] == arm and r["family"] in fams}


def _runs(rows, lv, arm):
    out = {}
    for r in rows:
        if r["condition"] == lv and r["arm"] == arm:
            out.setdefault((r["family"], int(r["seed"])), r)
    return out


def per_arm(rows, ext) -> dict[str, Any]:
    res = {}
    for lv in LEVELS:
        for arm in ARMS:
            U = _units(rows, lv, arm)
            uk = sorted(U)
            cl = [k[1] for k in uk]
            R = _runs(rows, lv, arm)
            rk = sorted(R)
            rc = [k[1] for k in rk]
            E = sorted((e for e in ext if e["level"] == lv and e["arm"] == arm), key=lambda e: (e["family"], e["seed"]))
            ec = [e["seed"] for e in E]
            camp = [(e["seed"], c) for e in E for c in e["campaigns"]]
            acted = [(s, c["first_action_s"] / 60) for s, c in camp if c["first_action_s"] is not None]
            cross = [(s, c) for s, c in camp if c["cross_segment"]]
            f = lambda col: [float(R[k][col]) for k in rk]  # noqa: E731
            res[f"{lv}|{arm}"] = {
                "contained_pct": mean_ci(cl, [100.0 * (U[k]["contained_before_impact"] == "True") for k in uk]),
                "data_loss_per_host": mean_ci(cl, [float(U[k]["data_loss_per_host"]) for k in uk]),
                "unavailability": mean_ci(rc, f("unavailability_fraction")),
                "benign_hosts_hit": mean_ci(rc, f("fp_benign_hosts")),
                "advisories": mean_ci(rc, f("advisories")),
                "advisories_false": mean_ci(rc, f("advisories_false")),
                "advisory_recall": ratio_ci([s for s, _ in cross], [float(c["warned_before_impact"]) for _, c in cross],
                                            [1.0] * len(cross)),
                "boundary_messages": mean_ci(rc, f("crossings_boundary")),
                "boundary_kb": mean_ci(rc, [x / 1000 for x in f("crossing_bytes_boundary")]),
                "all_messages": mean_ci(ec, [float(sum(e["comm"]["crossings"].values())) for e in E]),
                "dispatches_per_layer": {ly: mean_ci(ec, [float(sum(v for k, v in e["layers"].items()
                                                                  if k.startswith(ly + "|") and k.endswith("|despachos")))
                                                       for e in E]) for ly in LAYERS},
                "first_action_min": {"median": quant_ci([s for s, _ in acted], [x for _, x in acted], 0.5),
                                     "p90": quant_ci([s for s, _ in acted], [x for _, x in acted], 0.9),
                                     "never": len(camp) - len(acted), "campaigns": len(camp)},
                "strategic_only_labels": {n: int(sum(v for e in E for k, v in e["action_names"].items()
                                                     if k.endswith("|" + n))) for n in STRATEGIC_ONLY},
                "units": len(uk), "runs": len(rk)}
    return res


def delta(rows, lv, a, b, fams=FAMILIES) -> dict[str, Any]:
    ua, ub = _units(rows, lv, a, fams), _units(rows, lv, b, fams)
    keys = sorted(ua)
    assert keys == sorted(ub), (lv, a, b)
    cl = [k[1] for k in keys]
    dp = [100.0 * ((ua[k]["contained_before_impact"] == "True") - (ub[k]["contained_before_impact"] == "True")) for k in keys]
    dl = [float(ua[k]["data_loss_per_host"]) - float(ub[k]["data_loss_per_host"]) for k in keys]
    ra, rb = _runs(rows, lv, a), _runs(rows, lv, b)
    rk = sorted(k for k in ra if k[0] in fams)
    du = [float(ra[k]["unavailability_fraction"]) - float(rb[k]["unavailability_fraction"]) for k in rk]
    p, lo, hi = boot_sums(cl, np.column_stack([dp, np.ones(len(dp))]), lambda s: s[:, 0] / s[:, 1])
    l_, llo, lhi = boot_sums(cl, np.column_stack([dl, np.ones(len(dl))]), lambda s: s[:, 0] / s[:, 1])
    return {"comparison": f"{a} - {b}", "level": lv, "families": list(fams), "n": len(keys),
            "delta_pp": p, "ci_pp": [lo, hi], "discordant": [sum(x > 0 for x in dp), sum(x < 0 for x in dp)],
            "delta_loss": l_, "ci_loss": [llo, lhi], "delta_unav": sum(du) / len(du)}


def verdict(d: dict[str, Any]) -> str:
    lo, hi = d["ci_pp"]
    if (d["delta_pp"] <= -MARGIN_PP and hi < 0) or d["delta_loss"] > LOSS_MARGIN:
        return "necessária"
    if -MARGIN_PP <= lo and hi <= MARGIN_PP and abs(d["delta_loss"]) <= LOSS_MARGIN:
        return "dispensável"
    return "ambíguo"


def analyze(out: str = OUT) -> dict[str, Any]:
    rows, ext = load(out)
    arms = per_arm(rows, ext)
    deltas, verdicts = {}, {}
    for v in VARIANTS:
        per = {}
        for lv in LEVELS:
            d = delta(rows, lv, v, "SN")
            d["verdict"] = verdict(d)
            deltas[f"{lv}|{v}-SN"] = d
            per[lv] = d["verdict"]
        vs = list(per.values())
        overall = "necessária" if "necessária" in vs else ("dispensável" if all(x == "dispensável" for x in vs) else "ambíguo")
        verdicts[v] = {"per_level": per, "overall": overall}
    traffic = {}
    for lv in LEVELS:
        R3, Rs = _runs(rows, lv, "A3"), _runs(rows, lv, "SN")
        keys = sorted(Rs)
        cl = [k[1] for k in keys]
        for col, name in (("crossings_boundary", "messages"), ("crossing_bytes_boundary", "bytes")):
            r = ratio_ci(cl, [float(R3[k][col]) for k in keys], [float(Rs[k][col]) for k in keys])
            traffic[f"{lv}|{name}"] = {**r, "reduction_pct": None if r["value"] is None else 100 * (1 - r["value"])}
        traffic[f"{lv}|verdict"] = ("redução relevante" if traffic[f"{lv}|messages"]["value"] <= TRAFFIC_CUT
                                    else "sem redução relevante")
    refs = {}
    for lv in LEVELS:
        for a, b in (("A3", "U1"), ("A3", "B2L"), ("SN", "U1"), ("SN", "B2L"), ("A3", "A2")):
            refs[f"{lv}|{a}-{b}|all"] = delta(rows, lv, a, b)
            refs[f"{lv}|{a}-{b}|campaign_e1_e2"] = delta(rows, lv, a, b, ("campaign_e1_e2",))
    summary = {"status": "EXPLORATORY", "label": "descritivo, piloto de ablação",
               "seeds": "7000-7099", "levels": list(LEVELS), "arms": list(ARMS),
               "rule": {"margin_pp": MARGIN_PP, "loss_margin_files_per_host": LOSS_MARGIN, "traffic_cut": TRAFFIC_CUT},
               "per_arm": arms, "deltas_vs_SN": deltas, "verdicts": verdicts, "traffic_A3_vs_SN": traffic,
               "references": refs}
    with open(os.path.join(out, "manifest.json"), encoding="utf-8") as fh:
        man = json.load(fh)
    summary["compute"] = {"blocks": len(man["blocks"]), "elapsed_s_sum": sum(b["elapsed_s"] for b in man["blocks"].values()),
                          "commits": sorted({b["commit"] for b in man["blocks"].values()})}
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    figures(summary, os.path.join(out, "figs"))
    return summary


TITLES = {  # written after reading summary.json (they state the result)
    "i": "Tirar camadas do MAS não muda quantos ataques são bloqueados",
    "ii": "Só com avisos subindo, o MAS quase não fala com a central",
}


def figures(s: dict[str, Any], figdir: str) -> None:
    os.makedirs(figdir, exist_ok=True)
    groups = [LEVEL_NAME[lv] for lv in LEVELS]
    xl = "Atraso para os dados chegarem à central"
    a = s["per_arm"]
    grouped(os.path.join(figdir, "i_ataques_bloqueados.png"), TITLES["i"],
            "Ataques bloqueados antes de cifrar (%)", xl, groups,
            {arm: [a[f"{lv}|{arm}"]["contained_pct"]["mean"] for lv in LEVELS] for arm in ARMS}, digits=1, ylim_top=110,
            colors=COLOR, names=NAME,
            note="Piloto exploratório, pós-execução. Seeds 7000–7099, 5 famílias, h = 1.")
    grouped(os.path.join(figdir, "ii_mensagens_central.png"), TITLES["ii"],
            "Mensagens enviadas à central por execução\n(média)", xl, groups,
            {arm: [a[f"{lv}|{arm}"]["boundary_messages"]["mean"] for lv in LEVELS] for arm in ARMS}, digits=1,
            colors=COLOR, names=NAME,
            note="Piloto exploratório, pós-execução. Mensagens que cruzam a fronteira do segmento; seeds 7000–7099.")


if __name__ == "__main__":
    analyze()
