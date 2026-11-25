"""Figures of the Fase 1 official run (docs/fase1/08_preregistro_oficial.md §9), from summary.json.

    python3 analysis/fase1_oficial_figs.py [--out results/fase1_oficial]

Absolute proportion per arm (0-100 %), 95 % CI (cluster bootstrap by seed) as error bars, value on
top of each bar; SN blue, comparators gray; one short title; 200 dpi PNG and PDF in <out>/figs/.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COLOR = {"SN": "#4A6FB0", "U1": "#6E6E6E", "B2L": "#A0A0A0"}
LABEL = {"SN": "SN (MAS)", "U1": "U1 (monolito)", "B2L": "B2L (sem agentes)"}
LEVEL_LABEL = {"oracle": "oráculo", "restricted": "restrita (lote 60 s)", "batch5m": "lote 5 min", "batch15m": "lote 15 min"}
FAMILY_LABEL = {"encryption_stream": "encryption\nstream", "campaign_multihost": "campaign\nmultihost",
                "split_visibility_late_confirm": "split visibility\nlate confirm", "interleaved": "interleaved",
                "campaign_e1_e2": "campaign\ne1_e2"}
INK, MUTED, GRID = "#222222", "#555555", "#E6E6E6"

# Titles state the result; written after the official run (they describe summary.json of results/fase1_oficial).
TITLES = {
    "1_agentico_vs_sem_agentes": "O MAS contém mais ataques que regras sem agentes",
    "2_distribuido_vs_monolito": "O MAS contém um pouco mais que o monolito",
    "3_sem_coordenacao_vs_monolito": "Sem coordenação, o distribuído contém um pouco menos",
    "4_custo_de_fronteira": "Com a fronteira mais lenta, só o monolito perde contenção",
    "5_heterogeneidade": "Sem heterogeneidade, o MAS e as regras sem agentes empatam",
    "6_familia_de_ataque": "Em nenhuma família o MAS contém menos que os outros",
    "7_p_pre": "O ganho do MAS cai quando o precursor no servidor é comum",
    "8_indisponibilidade": "A indisponibilidade é quase igual nos três braços",
}


def pct(x: float) -> str:
    return f"{100 * x:.1f}".replace(".", ",") + "%"


def _axes(title: str, figsize=(6.4, 4.2)):
    fig, ax = plt.subplots(figsize=figsize, dpi=200)
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")
    ax.set_title(title, fontsize=12, color=INK, loc="left", pad=12)
    ax.set_ylim(0, 108)
    ax.set_yticks(range(0, 101, 20))
    ax.set_yticklabels([f"{v}%" for v in range(0, 101, 20)], color=MUTED, fontsize=9)
    ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color("#BBBBBB")
    ax.tick_params(axis="x", colors=INK, labelsize=9, length=0)
    ax.tick_params(axis="y", length=0)
    return fig, ax


def _bar(ax, x, p, lo, hi, arm, width):
    ax.bar(x, 100 * p, width=width, color=COLOR[arm], edgecolor="white", linewidth=1.5, zorder=2)
    ax.errorbar(x, 100 * p, yerr=[[100 * (p - lo)], [100 * (hi - p)]], fmt="none", ecolor=INK, elinewidth=0.9,
                capsize=3, zorder=3)
    ax.text(x, 100 * hi + 1.5, pct(p), ha="center", va="bottom", fontsize=8.5 if width >= 0.3 else 7, color=INK, zorder=4)


def simple(name: str, props: list[dict], out: str) -> None:
    """One bar per arm."""
    fig, ax = _axes(TITLES[name], figsize=(6.4, 4.2))
    for i, p in enumerate(props):
        _bar(ax, i, p["p"], p["ci_lo"], p["ci_hi"], p["arm"], 0.6)
    ax.set_xticks(range(len(props)))
    ax.set_xticklabels([LABEL[p["arm"]] for p in props])
    ax.set_xlim(-0.6, len(props) - 0.4)
    save(fig, name, out)


def grouped(name: str, groups: list[tuple[str, list[dict]]], out: str, figsize=(7.2, 4.4)) -> None:
    """Bars grouped by level; arms in a fixed order, legend above the plot."""
    fig, ax = _axes(TITLES[name], figsize=figsize)
    arms = [p["arm"] for p in groups[0][1]]
    w = 0.8 / len(arms)
    for g, (_, props) in enumerate(groups):
        for i, p in enumerate(props):
            _bar(ax, g + (i - (len(arms) - 1) / 2) * w, p["p"], p["ci_lo"], p["ci_hi"], p["arm"], w * 0.92)
    ax.set_xticks(range(len(groups)))
    ax.set_xticklabels([g for g, _ in groups])
    handles = [plt.Rectangle((0, 0), 1, 1, color=COLOR[a]) for a in arms]
    ax.legend(handles, [LABEL[a] for a in arms], loc="lower left", bbox_to_anchor=(0, 1.0), ncol=len(arms),
              frameon=False, fontsize=8.5, handlelength=1.2, borderaxespad=0.2)
    ax.set_title(TITLES[name], fontsize=12, color=INK, loc="left", pad=26)
    save(fig, name, out)


def save(fig, name: str, out: str) -> None:
    fig.tight_layout()
    d = os.path.join(out, "figs")
    os.makedirs(d, exist_ok=True)
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(d, f"{name}.{ext}"), dpi=200, facecolor="white")
    plt.close(fig)


def pick(props: list[dict], arms) -> list[dict]:
    by = {p["arm"]: p for p in props}
    return [by[a] for a in arms]


def main(argv=None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(_BASE_DIR, "results", "fase1_oficial"))
    args = ap.parse_args(argv)
    with open(os.path.join(args.out, "summary.json"), encoding="utf-8") as fh:
        s = json.load(fh)
    P = s["descriptive"]["proportions"]
    simple("1_agentico_vs_sem_agentes", pick(P["e1e2_h1_restricted"], ("SN", "B2L")), args.out)
    simple("2_distribuido_vs_monolito", pick(P["all_h1_restricted"], ("SN", "U1")), args.out)
    simple("3_sem_coordenacao_vs_monolito", pick(P["all_h1_restricted"], ("B2L", "U1")), args.out)
    grouped("4_custo_de_fronteira", [(LEVEL_LABEL[c], pick(P[f"levels_{c}"], ("SN", "U1")))
                                     for c in ("oracle", "restricted", "batch5m", "batch15m")], args.out)
    grouped("5_heterogeneidade", [("h = 0", pick(P["e1e2_h0_restricted"], ("SN", "B2L"))),
                                  ("h = 1", pick(P["e1e2_h1_restricted"], ("SN", "B2L")))], args.out, figsize=(5.6, 4.4))
    grouped("6_familia_de_ataque", [(FAMILY_LABEL[f], pick(P[f"family_{f}"], ("SN", "U1", "B2L")))
                                    for f in FAMILY_LABEL], args.out, figsize=(10.0, 4.6))
    grouped("7_p_pre", [(f"p_pre = {k.replace('.', ',')}", v["props"]) for k, v in s["descriptive"]["p_pre"].items()],
            args.out, figsize=(6.4, 4.4))
    sec = s["descriptive"]["secondary"]
    unav = []
    for arm in ("SN", "U1", "B2L"):
        runs = [v for k, v in sec.items() if k.startswith("principal|restricted|1|") and k.endswith("|" + arm)]
        v = runs[0]
        unav.append({"arm": arm, "p": v["unavailability"], "ci_lo": v["unav_ci"][0], "ci_hi": v["unav_ci"][1]})
    simple("8_indisponibilidade", unav, args.out)
    print(os.path.join(args.out, "figs"))


if __name__ == "__main__":
    sys.exit(main())
