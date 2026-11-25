"""Etapa 3 — análise DESCRITIVA, pós-execução, da execução oficial da Fase 1 (sem testes de hipótese).

Fontes:
* ``results/fase1_oficial/raw/`` (seeds 5000-5499, todas as métricas que já estão nos CSVs);
* ``results/fase1_oficial/etapa3/rerun/extras.jsonl.gz`` (seeds 5000-5099, reexecução instrumentada com
  linhas verificadas idênticas ao raw por ``analysis/fase1_etapa3_rerun.py``).

Recorte: h = 1, 5 famílias, braços SN / U1 / B2L, 4 níveis de fronteira. Só médias, medianas,
percentis e IC95 % por bootstrap de clusters (cluster = seed; 10 000 reamostragens para médias e
razões, 2 000 para medianas e P90; ``default_rng(0)``).

    python3 analysis/fase1_etapa3.py            # summary.json + figs/
"""
from __future__ import annotations

import csv
import glob
import gzip
import json
import os
import sys
from collections import defaultdict
from multiprocessing import Pool
from typing import Any, Callable, Optional

import numpy as np

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

OUT = os.path.join(_BASE_DIR, "results", "fase1_oficial", "etapa3")
RAW = os.path.join(_BASE_DIR, "results", "fase1_oficial", "raw")
ARMS = ("SN", "U1", "B2L")
LEVELS = ("oracle", "restricted", "batch5m", "batch15m")
FAMILIES = ("encryption_stream", "campaign_multihost", "split_visibility_late_confirm", "interleaved", "campaign_e1_e2")
SEEDS_ALL = tuple(range(5000, 5500))
LABEL = "descritivo, pós-execução"
NETS = (100, 1000, 10000)
SEGMENT_SHARE = {"E1": 0.70, "E2": 0.20, "E3": 0.10}
N_BOOT, N_BOOT_Q = 10_000, 2_000
DAY = 86_400.0


# --- bootstrap (cluster = seed) ---------------------------------------------------------------------
def boot_sums(clusters: list, cols: np.ndarray, stat: Callable[[np.ndarray], np.ndarray], n_boot: int = N_BOOT):
    """``cols``: (units x k) values; resample seeds, sum each column over the drawn units, apply ``stat``
    to the (n_boot x k) sums. Returns (point, lo, hi)."""
    index: dict = {}
    g = np.array([index.setdefault(c, len(index)) for c in clusters])
    cols = np.asarray(cols, dtype=float).reshape(len(clusters), -1)
    s = np.zeros((len(index), cols.shape[1]))
    np.add.at(s, g, cols)
    idx = np.random.default_rng(0).integers(0, len(index), size=(n_boot, len(index)))
    draws = stat(s[idx].sum(axis=1))
    point = stat(s.sum(axis=0, keepdims=True))[0]
    with np.errstate(invalid="ignore"):
        lo, hi = np.nanquantile(draws, 0.025), np.nanquantile(draws, 0.975)
    return _f(point), _f(lo), _f(hi)


def _f(x) -> Optional[float]:
    x = float(x)
    return None if np.isnan(x) else x


def mean_ci(clusters, values) -> dict[str, Any]:
    if not values:
        return {"mean": None, "ci": [None, None], "n": 0}
    m, lo, hi = boot_sums(clusters, np.column_stack([values, np.ones(len(values))]), lambda s: s[:, 0] / s[:, 1])
    return {"mean": m, "ci": [lo, hi], "n": len(values)}


def ratio_ci(clusters, num, den, scale: float = 1.0) -> dict[str, Any]:
    if not num or sum(den) == 0:
        return {"value": None, "ci": [None, None], "num": float(sum(num)), "den": float(sum(den))}

    def stat(s):
        with np.errstate(invalid="ignore", divide="ignore"):
            return scale * s[:, 0] / s[:, 1]
    v, lo, hi = boot_sums(clusters, np.column_stack([num, den]), stat)
    return {"value": v, "ci": [lo, hi], "num": float(sum(num)), "den": float(sum(den))}


def quant_ci(clusters, values, q: float) -> dict[str, Any]:
    if not values:
        return {"value": None, "ci": [None, None], "n": 0}
    by: dict = defaultdict(list)
    for c, v in zip(clusters, values):
        by[c].append(v)
    groups = [np.array(v) for v in by.values()]
    rng = np.random.default_rng(0)
    draws = []
    for _ in range(N_BOOT_Q):
        pick = rng.integers(0, len(groups), size=len(groups))
        draws.append(np.quantile(np.concatenate([groups[i] for i in pick]), q))
    return {"value": float(np.quantile(values, q)), "ci": [float(np.quantile(draws, 0.025)), float(np.quantile(draws, 0.975))],
            "n": len(values)}


# --- data -----------------------------------------------------------------------------------------
def load_raw() -> dict[tuple, list[dict[str, str]]]:
    """(level, arm) -> rows (one per campaign), h = 1 only."""
    out: dict[tuple, list] = defaultdict(list)
    for path in sorted(glob.glob(os.path.join(RAW, "*.csv"))):
        name = os.path.basename(path)
        if not (name.startswith("main_h1_") or name.startswith("frontier_")):
            continue
        with open(path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r["h"] == "1" and r["arm"] in ARMS:
                    out[(r["condition"], r["arm"])].append(r)
    return out


def runs_of(rows) -> list[dict[str, str]]:
    seen = {}
    for r in rows:
        seen.setdefault((r["family"], r["seed"]), r)
    return [seen[k] for k in sorted(seen)]


def _meta(args):
    from simulation import fase1b_experiments as B
    from analysis.fase1_etapa3_rerun import window

    family, seed = args
    sc = B.scenario(family, seed, 1).scenario
    lo, hi = window(sc)
    return family, seed, hi - lo, len({e.get("source") for e in sc.events})


def scenario_meta() -> dict[tuple, tuple[float, int]]:
    """(family, seed) -> (benign window s, hosts with telemetry); cached in etapa3/scenario_meta.csv."""
    path = os.path.join(OUT, "scenario_meta.csv")
    if not os.path.exists(path):
        jobs = [(f, s) for f in FAMILIES for s in SEEDS_ALL]
        with Pool(os.cpu_count() or 1) as pool:
            res = sorted(pool.map(_meta, jobs, chunksize=10))
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["family", "seed", "window_s", "event_hosts"])
            w.writerows(res)
    with open(path, encoding="utf-8") as fh:
        return {(r["family"], int(r["seed"])): (float(r["window_s"]), int(r["event_hosts"])) for r in csv.DictReader(fh)}


def load_extras() -> list[dict[str, Any]]:
    with gzip.open(os.path.join(OUT, "rerun", "extras.jsonl.gz"), "rt", encoding="utf-8") as fh:
        return [json.loads(x) for x in fh]


def num(x: str) -> Optional[float]:
    return None if x in ("", None) else float(x)


# --- items ----------------------------------------------------------------------------------------
def item1(raw, ext, meta) -> dict[str, Any]:
    out: dict[str, Any] = {"label": LABEL, "a_classification": {}, "b_benign_hosts": {}, "c_advisories": {},
                           "d_per_day": {}}
    for lv in LEVELS:
        for arm in ARMS:
            key = f"{lv}|{arm}"
            E = [e for e in ext if e["level"] == lv and e["arm"] == arm]
            cl = [e["seed"] for e in E]
            # a) precisão / revocação / F1 por base
            a = {}
            for basis in ("any_containment", "flagged_containment", "detection"):
                m = np.array([[e["classification"][basis][k] for k in ("tp", "fp", "fn", "tn")] for e in E], dtype=float)
                tot = m.sum(axis=0)

                def prec(s):
                    with np.errstate(invalid="ignore", divide="ignore"):
                        return s[:, 0] / (s[:, 0] + s[:, 1])

                def rec(s):
                    with np.errstate(invalid="ignore", divide="ignore"):
                        return s[:, 0] / (s[:, 0] + s[:, 2])

                def f1(s):
                    p, r = prec(s), rec(s)
                    with np.errstate(invalid="ignore", divide="ignore"):
                        return 2 * p * r / (p + r)
                a[basis] = {"tp": int(tot[0]), "fp": int(tot[1]), "fn": int(tot[2]), "tn": int(tot[3]),
                            **{name: dict(zip(("value", "lo", "hi"), boot_sums(cl, m, fn)))
                               for name, fn in (("precision", prec), ("recall", rec), ("f1", f1))}}
            out["a_classification"][key] = {"seeds": "5000-5099", "runs": len(E), **a}
            # b) hosts benignos com ação por run (raw, 500 seeds) e isolados (subconjunto)
            R = runs_of(raw[(lv, arm)])
            rc = [int(r["seed"]) for r in R]
            fp = [float(r["fp_benign_hosts"]) for r in R]
            iso = [sum(h["isolated"] for h in e["benign"].values()) for e in E]
            anyb = [sum(h["any"] for h in e["benign"].values()) for e in E]
            out["b_benign_hosts"][key] = {
                "per_run_any_action_raw": mean_ci(rc, fp),
                "per_run_any_action_subset": mean_ci(cl, anyb),
                "per_run_isolated_subset": mean_ci(cl, iso),
                "per_run_restricted_only_subset": mean_ci(cl, [x - y for x, y in zip(anyb, iso)]),
                "benign_hosts_per_run": 9, "runs_raw": len(R), "runs_subset": len(E)}
            # c) avisos: raw (totais por run) + subconjunto (entre segmentos, revocação por campanha)
            adv = [float(r["advisories"]) for r in R]
            advf = [float(r["advisories_false"]) for r in R]
            advx = [float(r["advisories_crossing"]) for r in R]
            xs = [[a_ for a_ in e["advisories"] if a_["cross"]] for e in E]
            xt = [sum(not a_["false"] for a_ in x) for x in xs]
            xf = [sum(a_["false"] for a_ in x) for x in xs]
            camp = [(e["seed"], c) for e in E for c in e["campaigns"] if c["cross_segment"]]
            out["c_advisories"][key] = {
                "raw_per_run": {"total": mean_ci(rc, adv), "true": mean_ci(rc, [x - y for x, y in zip(adv, advf)]),
                                "false": mean_ci(rc, advf), "cross_segment": mean_ci(rc, advx),
                                "precision": ratio_ci(rc, [x - y for x, y in zip(adv, advf)], adv),
                                "totals": {"total": sum(adv), "false": sum(advf), "cross_segment": sum(advx)}},
                "cross_segment_subset": {"total": int(sum(len(x) for x in xs)), "true": int(sum(xt)), "false": int(sum(xf)),
                                         "precision": ratio_ci(cl, xt, [len(x) for x in xs])},
                "recall_subset": {"campaigns_crossing_segments": len(camp),
                                  "warned_before_impact": int(sum(c["warned_before_impact"] for _, c in camp)),
                                  **ratio_ci([s for s, _ in camp], [float(c["warned_before_impact"]) for _, c in camp],
                                             [1.0] * len(camp))}}
            # d) por dia, extrapolação linear com taxa constante por host
            win_d = [meta[(r["family"], int(r["seed"]))][0] / DAY for r in R]
            hosts = [meta[(r["family"], int(r["seed"]))][1] for r in R]
            d = {"benign_blocked": {}, "benign_blocked_profile_weighted": {}, "advisories_total": {},
                 "advisories_false": {}, "advisories_true": {}}
            rate_b = ratio_ci(rc, fp, [9 * w for w in win_d])  # por host benigno-dia
            rate_af = ratio_ci(rc, advf, [9 * w for w in win_d])
            rate_at = ratio_ci(rc, adv, [h * w for h, w in zip(hosts, win_d)])
            rate_av = ratio_ci(rc, [x - y for x, y in zip(adv, advf)], [h * w for h, w in zip(hosts, win_d)])
            # ponderado por perfil (70/20/10), subconjunto
            wsub = [e["window_s"] / DAY for e in E]
            prof = {}
            for p in SEGMENT_SHARE:
                n_ = [sum(h["any"] for h in e["benign"].values() if h["profile"] == p) for e in E]
                prof[p] = ratio_ci(cl, n_, [3 * w for w in wsub])
            weighted = sum(SEGMENT_SHARE[p] * (prof[p]["value"] or 0.0) for p in SEGMENT_SHARE) if E else None
            for n_hosts in NETS:
                d["benign_blocked"][n_hosts] = _scaled(rate_b, n_hosts)
                d["advisories_false"][n_hosts] = _scaled(rate_af, n_hosts)
                d["advisories_total"][n_hosts] = _scaled(rate_at, n_hosts)
                d["advisories_true"][n_hosts] = _scaled(rate_av, n_hosts)
                d["benign_blocked_profile_weighted"][n_hosts] = None if weighted is None else weighted * n_hosts
            d["per_profile_rate_per_benign_host_day_subset"] = {p: prof[p]["value"] for p in prof}
            d["window_min_mean"] = float(np.mean(win_d) * 1440)
            d["hosts_with_telemetry_mean"] = float(np.mean(hosts))
            out["d_per_day"][key] = d
    out["d_per_day"]["_note"] = ("ILUSTRATIVO: extrapolação linear que assume taxas constantes por host e ao longo do dia. "
                                 "A taxa vem da janela de atividade benigna do run (span do ataque ± 300 s, não 24 h) e "
                                 "dos hosts com telemetria (9 benignos para bloqueios e avisos falsos; todos os hosts com "
                                 "eventos para avisos totais/verdadeiros).")
    return out


def _scaled(rate: dict[str, Any], n_hosts: int) -> dict[str, Any]:
    f = lambda x: None if x is None else x * n_hosts  # noqa: E731
    return {"value": f(rate["value"]), "ci": [f(rate["ci"][0]), f(rate["ci"][1])]}


def item2(raw, ext) -> dict[str, Any]:
    out: dict[str, Any] = {"label": LABEL, "first_action_subset": {}, "first_preventive_raw": {}}
    for lv in LEVELS:
        for arm in ARMS:
            key = f"{lv}|{arm}"
            C = [(e["seed"], c) for e in ext if e["level"] == lv and e["arm"] == arm for c in e["campaigns"]]
            acted = [(s, c) for s, c in C if c["first_action_s"] is not None]
            t = [c["first_action_s"] / 60 for _, c in acted]
            lead = [(s, (c["impact_s"] - c["first_action_s"]) / 60) for s, c in acted if c["impact_s"] is not None]
            out["first_action_subset"][key] = {
                "campaigns": len(C), "not_contained": len(C) - len(acted), "no_impact_in_truth": sum(c["impact_s"] is None for _, c in C),
                "time_to_first_action_min": {"median": quant_ci([s for s, _ in acted], t, 0.5),
                                             "p90": quant_ci([s for s, _ in acted], t, 0.9)},
                "lead_time_min": {"median": quant_ci([s for s, _ in lead], [x for _, x in lead], 0.5),
                                  "p90": quant_ci([s for s, _ in lead], [x for _, x in lead], 0.9),
                                  "n": len(lead), "action_after_impact": sum(x <= 0 for _, x in lead)}}
            R = raw[(lv, arm)]
            pr = [(int(r["seed"]), num(r["first_prevention_s_any"]), num(r["impact_time_s"])) for r in R]
            got = [(s, f, i) for s, f, i in pr if f is not None]
            ld = [(s, (i - f) / 60) for s, f, i in got if i is not None]
            out["first_preventive_raw"][key] = {
                "campaigns": len(pr), "never_prevented": len(pr) - len(got),
                "time_to_first_preventive_min": {"median": quant_ci([s for s, *_ in got], [f / 60 for _, f, _ in got], 0.5),
                                                 "p90": quant_ci([s for s, *_ in got], [f / 60 for _, f, _ in got], 0.9)},
                "lead_time_min": {"median": quant_ci([s for s, _ in ld], [x for _, x in ld], 0.5),
                                  "p90": quant_ci([s for s, _ in ld], [x for _, x in ld], 0.9),
                                  "n": len(ld), "after_impact": sum(x <= 0 for _, x in ld)}}
    return out


def item3(raw, ext, meta) -> dict[str, Any]:
    out: dict[str, Any] = {"label": LABEL, "per_run": {}}
    for lv in LEVELS:
        for arm in ARMS:
            key = f"{lv}|{arm}"
            R = runs_of(raw[(lv, arm)])
            rc = [int(r["seed"]) for r in R]
            cb = [float(r["crossings_boundary"]) for r in R]
            by = [float(r["crossing_bytes_boundary"]) for r in R]
            win_d = [meta[(r["family"], int(r["seed"]))][0] / DAY for r in R]
            hosts = [meta[(r["family"], int(r["seed"]))][1] for r in R]
            E = [e for e in ext if e["level"] == lv and e["arm"] == arm]
            cl = [e["seed"] for e in E]
            tot = [float(sum(e["comm"]["crossings"].values())) for e in E]
            links = sorted({k for e in E for k in e["comm"]["crossings"]})
            rate = ratio_ci(rc, cb, [h * w for h, w in zip(hosts, win_d)])
            out["per_run"][key] = {
                "boundary_messages_raw": mean_ci(rc, cb), "boundary_bytes_raw": mean_ci(rc, by),
                "all_link_messages_subset": mean_ci(cl, tot),
                "by_link_subset": {k: mean_ci(cl, [float(e["comm"]["crossings"].get(k, 0)) for e in E]) for k in links},
                "agent_messages_subset": mean_ci(cl, [float(e["comm"]["agent_messages"]) for e in E]),
                "boundary_messages_per_day": {n: _scaled(rate, n) for n in NETS}}
    for lv in LEVELS:
        sn, u1 = out["per_run"][f"{lv}|SN"], out["per_run"][f"{lv}|U1"]
        out["per_run"][f"{lv}|SN/U1"] = {
            "boundary_messages_ratio": sn["boundary_messages_raw"]["mean"] / u1["boundary_messages_raw"]["mean"],
            "boundary_bytes_ratio": sn["boundary_bytes_raw"]["mean"] / u1["boundary_bytes_raw"]["mean"],
            "all_link_messages_ratio": sn["all_link_messages_subset"]["mean"] / u1["all_link_messages_subset"]["mean"]}
    return out


LAYERS = ("specialist", "coordinator", "strategic")


def item4(ext) -> dict[str, Any]:
    out: dict[str, Any] = {"label": LABEL, "arm": "SN", "seeds": "5000-5099", "per_level": {}}
    for lv in LEVELS:
        E = [e for e in ext if e["level"] == lv and e["arm"] == "SN"]
        cl = [e["seed"] for e in E]
        res = {}
        for layer in LAYERS:
            row = {}
            for kind in ("precaucao", "confirmado"):
                for tgt in ("malicioso", "benigno"):
                    vals = [sum(v for k, v in e["layers"].items()
                                if k.startswith(f"{layer}|{kind}|{tgt}|") and k.endswith("|despachos")) for e in E]
                    acts = [sum(v for k, v in e["layers"].items()
                                if k.startswith(f"{layer}|{kind}|{tgt}|") and k.endswith("|acoes")) for e in E]
                    row[f"{kind}|{tgt}"] = {"dispatches_per_run": mean_ci(cl, vals), "actions_per_run": sum(acts) / len(E),
                                            "dispatches_total": int(sum(vals))}
            tot = [sum(v for k, v in e["layers"].items() if k.startswith(layer + "|") and k.endswith("|despachos")) for e in E]
            crs = [sum(v for k, v in e["layers"].items() if k.startswith(layer + "|") and "|cruzou|" in k and k.endswith("|despachos"))
                   for e in E]
            row["total"] = {"dispatches_per_run": mean_ci(cl, tot), "dispatches_total": int(sum(tot))}
            row["crossed_boundary"] = ratio_ci(cl, crs, tot)
            res[layer] = row
        alltot = [sum(v for k, v in e["layers"].items() if k.endswith("|despachos")) for e in E]
        allcrs = [sum(v for k, v in e["layers"].items() if "|cruzou|" in k and k.endswith("|despachos")) for e in E]
        res["all_layers_crossed_boundary"] = ratio_ci(cl, allcrs, alltot)
        out["per_level"][lv] = res
    return out


# --- figures --------------------------------------------------------------------------------------
COLOR = {"SN": "#4A6FB0", "U1": "#6E6E6E", "B2L": "#B5B5B5"}
NAME = {"SN": "MAS proposto", "U1": "Controle central (MAPE-K)", "B2L": "Regras locais sem agentes"}
LEVEL_NAME = {"oracle": "Sem atraso\n(oráculo)", "restricted": "Lote de 60 s", "batch5m": "Lote de 5 min",
              "batch15m": "Lote de 15 min"}
INK, MUTED, GRID = "#222222", "#555555", "#E6E6E6"


def br(x: float, d: int = 1) -> str:
    s = f"{x:,.{d}f}"
    return s.replace(",", "X").replace(".", ",").replace("X", ".")


def _axes(ax, ylabel: str, xlabel: str):
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(MUTED)
    ax.tick_params(colors=MUTED, labelsize=9)
    ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_ylabel(ylabel, color=INK, fontsize=10)
    ax.set_xlabel(xlabel, color=INK, fontsize=10)


def grouped(path: str, title: str, ylabel: str, xlabel: str, groups: list[str], series: dict[str, list[Optional[float]]],
            digits: int = 1, note: Optional[str] = None, colors=None, names=None, ylim_top: Optional[float] = None,
            absent: Optional[dict[str, str]] = None):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.patches import Patch

    colors, names = colors or COLOR, names or NAME
    fig, ax = plt.subplots(figsize=(8.4, 4.8), dpi=200)
    keys = list(series)
    n = len(keys)
    width = 0.8 / n
    x = np.arange(len(groups))
    top = max((v for vs in series.values() for v in vs if v is not None), default=1.0) or 1.0
    for i, k in enumerate(keys):
        pos = x - 0.4 + width * (i + 0.5)
        vals = series[k]
        for p, v in zip(pos, vals):
            if v is None:
                continue
            ax.bar(p, v, width * 0.92, color=colors[k], edgecolor="white", linewidth=1.0)
            ax.text(p, v + top * 0.015, br(v, digits), ha="center", va="bottom", fontsize=8, color=INK)
    ax.set_xticks(x)
    ax.set_xticklabels(groups)
    _axes(ax, ylabel, xlabel)
    ax.set_ylim(0, ylim_top if ylim_top is not None else top * 1.15)
    ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: br(v, 0 if top >= 10 else 1)))
    handles = [Patch(color=colors[k], label=names[k]) for k in keys]
    for k, txt in (absent or {}).items():
        handles.append(Patch(facecolor="white", edgecolor=colors[k], label=f"{names[k]} ({txt})"))
    ax.legend(handles=handles, frameon=False, fontsize=8.5, loc="upper left", bbox_to_anchor=(0, -0.16),
              ncol=3 if len(handles) <= 3 else 2)
    ax.set_title(title, color=INK, fontsize=12, loc="left", pad=10)
    if note:
        fig.text(0.01, 0.005, note, fontsize=7.5, color=MUTED, ha="left", va="bottom")
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    fig.savefig(path, dpi=200)
    plt.close(fig)


def figures(s: dict[str, Any], figdir: str, titles: dict[str, str]) -> list[str]:
    os.makedirs(figdir, exist_ok=True)
    groups = [LEVEL_NAME[lv] for lv in LEVELS]
    xl = "Atraso para os dados chegarem à central"
    made = []
    d = s["item1"]["d_per_day"]
    p = os.path.join(figdir, "i_legitimos_bloqueados.png")
    grouped(p, titles["i"], "Bloqueios de computadores legítimos por dia\n(rede de 100 computadores)", xl, groups,
            {a: [d[f"{lv}|{a}"]["benign_blocked"][100]["value"] for lv in LEVELS] for a in ARMS}, digits=0,
            note="Descritivo, pós-execução. Extrapolação ilustrativa: taxa por computador constante ao longo do dia.")
    made.append(p)
    c = s["item1"]["c_advisories"]
    p = os.path.join(figdir, "ii_precisao_avisos.png")
    grouped(p, titles["ii"], "Avisos que apontavam um computador\nrealmente atacado (%)", xl, groups,
            {a: [100 * c[f"{lv}|{a}"]["raw_per_run"]["precision"]["value"] for lv in LEVELS] for a in ("SN", "U1")},
            digits=1, ylim_top=110, absent={"B2L": "não envia avisos"},
            note="Descritivo, pós-execução. Seeds 5000–5499, 5 famílias, h = 1.")
    made.append(p)
    t = s["item2"]["first_action_subset"]
    p = os.path.join(figdir, "iii_tempo_contencao.png")
    grouped(p, titles["iii"], "Tempo até a primeira ação contra o ataque\n(min, mediana)", xl, groups,
            {a: [t[f"{lv}|{a}"]["time_to_first_action_min"]["median"]["value"] for lv in LEVELS] for a in ARMS},
            note="Descritivo, pós-execução. Seeds 5000–5099 (reexecução instrumentada). Campanhas sem nenhuma ação ficam fora da mediana.")
    made.append(p)
    m = s["item3"]["per_run"]
    p = os.path.join(figdir, "iv_mensagens_fronteira.png")
    grouped(p, titles["iv"], "Mensagens enviadas à central por dia\n(rede de 100 computadores, milhares)", xl, groups,
            {a: [m[f"{lv}|{a}"]["boundary_messages_per_day"][100]["value"] / 1000 for lv in LEVELS] for a in ARMS},
            note="Descritivo, pós-execução. Extrapolação ilustrativa: taxa por computador constante ao longo do dia.")
    made.append(p)
    L = s["item4"]["per_level"]["restricted"]
    cats = {"precaucao|malicioso": "Precaução (sinal fraco), computador atacado", "precaucao|benigno": "Precaução (sinal fraco), computador legítimo",
            "confirmado|malicioso": "Detecção positiva, computador atacado",
            "confirmado|benigno": "Detecção positiva, computador legítimo"}
    ccol = {"precaucao|malicioso": "#A9BBDD", "precaucao|benigno": "#D3DCEE", "confirmado|malicioso": "#4A6FB0",
            "confirmado|benigno": "#22385F"}
    p = os.path.join(figdir, "v_acoes_por_camada.png")
    grouped(p, titles["v"], "Ações enviadas por execução (média)", "Camada do MAS proposto",
            ["Especialista\n(no segmento)", "Coordenador", "Estratégico"],
            {k: [L[layer][k]["dispatches_per_run"]["mean"] for layer in LAYERS] for k in cats}, colors=ccol, names=cats,
            note="Descritivo, pós-execução. Só o MAS proposto; lote de 60 s; seeds 5000–5099; 5 famílias.")
    made.append(p)
    return made


TITLES = {  # written after reading summary.json (they state the result)
    "i": "Os três braços bloqueiam computadores legítimos no mesmo ritmo",
    "ii": "Só 4 em cada 10 avisos apontam um computador realmente atacado",
    "iii": "Só o controle central demora mais quando a fronteira fica lenta",
    "iv": "O MAS envia à central o mesmo volume que o controle central",
    "v": "Quatro em cada cinco ações do MAS atingem computadores legítimos",
}


def main() -> None:
    raw = load_raw()
    ext = load_extras()
    meta = scenario_meta()
    with open(os.path.join(OUT, "rerun", "verify.json"), encoding="utf-8") as fh:
        verify = json.load(fh)
    s = {"label": LABEL, "scope": {"h": 1, "families": list(FAMILIES), "arms": list(ARMS), "levels": list(LEVELS),
                                   "seeds_raw": "5000-5499", "seeds_rerun": "5000-5099"},
         "bootstrap": {"cluster": "seed", "n_boot_means_ratios": N_BOOT, "n_boot_quantiles": N_BOOT_Q, "rng": "default_rng(0)"},
         "rerun_verification": verify,
         "scenario": {"benign_window_min_mean": float(np.mean([v[0] for v in meta.values()]) / 60),
                      "benign_window_min_range": [min(v[0] for v in meta.values()) / 60, max(v[0] for v in meta.values()) / 60],
                      "benign_hosts_per_run": 9, "hosts_with_telemetry_mean": float(np.mean([v[1] for v in meta.values()])),
                      "damage_horizon_s": DAY, "network_hosts_damage_model": 100}}
    s["item1"] = item1(raw, ext, meta)
    s["item2"] = item2(raw, ext)
    s["item3"] = item3(raw, ext, meta)
    s["item4"] = item4(ext)
    with open(os.path.join(OUT, "summary.json"), "w", encoding="utf-8") as fh:
        json.dump(s, fh, indent=1, ensure_ascii=False)
        fh.write("\n")
    for p in figures(s, os.path.join(OUT, "figs"), TITLES):
        print(p)


if __name__ == "__main__":
    main()
