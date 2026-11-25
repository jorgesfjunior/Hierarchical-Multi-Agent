"""Fig. 2 (two panels):
(a) protection rate vs batching interval to the centre (Q2/Q3), read from the official run,
    results/fase1_oficial/summary.json -> descriptive.proportions.levels_{oracle,restricted,batch5m,batch15m}
    (h = 1, all 5 families; p, ci_lo, ci_hi per arm);
(b) protection rate vs detection-threshold multiplier (E2 sweep), read from
    results/fase1_A/summary.json -> E2.curves["<m>|<arm>"].p.{mean,ci}.

Usage: make_results_fig.py <fase1_A summary.json> <out dir> [<fase1_oficial summary.json>]
The third argument defaults to results/fase1_oficial/summary.json in this repository."""
import json, os, sys
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
e2 = json.load(open(sys.argv[1]))["E2"]["curves"]; out = sys.argv[2]
OFICIAL = sys.argv[3] if len(sys.argv) > 3 else os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results", "fase1_oficial", "summary.json")
props = json.load(open(OFICIAL))["descriptive"]["proportions"]
LEVELS = ["oracle", "restricted", "batch5m", "batch15m"]  # 0, 60 s, 5 min, 15 min
SN, U1, B2L = "#2a78d6", "#eb6834", "#1baf7a"
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e4e3df"
ARMS = [("U1", "Central MAPE-K", U1, "s", "--", 1.2, 2), ("B2L", "Distributed rules", B2L, "^", ":", 1.4, 3),
        ("SN", "Multi-agent (proposed)", SN, "o", "-", 1.6, 4)]
plt.rcParams.update({"font.family": "serif", "font.size": 8, "axes.labelsize": 8, "xtick.labelsize": 7.5,
    "ytick.labelsize": 7.5, "legend.fontsize": 7.5, "axes.titlesize": 8, "axes.edgecolor": MUTED,
    "axes.labelcolor": INK, "xtick.color": MUTED, "ytick.color": MUTED, "axes.spines.top": False,
    "axes.spines.right": False, "pdf.fonttype": 42})
fig, (a, b) = plt.subplots(1, 2, figsize=(4.8, 2.05))
def _level(level, arm):
    r = next(r for r in props[f"levels_{level}"] if r["arm"] == arm)
    return (100 * r["p"], 100 * r["ci_lo"], 100 * r["ci_hi"])
delay = {code: [_level(lv, code) for lv in LEVELS] for code in ("SN", "U1", "B2L")}
for code, pts in delay.items():
    print(code, " ".join(f"{p:.1f} [{lo:.1f}, {hi:.1f}]" for p, lo, hi in pts))
x = range(4)
for code, name, col, mk, ls, lw, z in ARMS:
    pts = delay[code]
    a.fill_between(x, [v[1] for v in pts], [v[2] for v in pts], color=col, alpha=0.18, linewidth=0)
    a.plot(x, [v[0] for v in pts], color=col, linestyle=ls, linewidth=lw, marker=mk, markersize=3.8,
           markeredgecolor="white", markeredgewidth=0.5, label=name, zorder=z)
a.set_xticks(list(x)); a.set_xticklabels(["0", "60 s", "5 min", "15 min"])
a.set_xlabel("Batching interval to the centre"); a.set_ylabel("Protection rate (%)")
a.set_ylim(40, 100); a.set_title("(a) Delay to the centre", loc="left")
M = ["0.5", "0.75", "1.0", "1.25", "1.5", "2.0"]
for code, name, col, mk, ls, lw, z in ARMS:
    xs = [float(m) for m in M]; ys = [100 * e2[f"{m}|{code}"]["p"]["mean"] for m in M]
    lo = [y - 100 * e2[f"{m}|{code}"]["p"]["ci"][0] for m, y in zip(M, ys)]
    hi = [100 * e2[f"{m}|{code}"]["p"]["ci"][1] - y for m, y in zip(M, ys)]
    b.errorbar(xs, ys, yerr=[lo, hi], color=col, linestyle=ls, linewidth=lw, marker=mk, markersize=3.8,
               markeredgecolor="white", markeredgewidth=0.5, elinewidth=0.6, capsize=1.2, zorder=z)
b.axvline(1.0, color=MUTED, linewidth=0.6, linestyle=(0, (2, 2)), zorder=1)
b.text(1.04, 99.5, "calibrated", fontsize=7, color=MUTED, va="top")
b.set_xticks([0.5, 1, 1.5, 2]); b.set_xticklabels(["0.5", "1", "1.5", "2"])
b.set_xlabel("Detection threshold (× calibrated)"); b.set_ylim(74, 100.5)
b.set_title("(b) Detection threshold", loc="left")
for ax in (a, b):
    ax.yaxis.grid(True, color=GRID, linewidth=0.6); ax.set_axisbelow(True)
h, l = a.get_legend_handles_labels()
fig.legend(h[::-1], l[::-1], loc="upper center", ncol=3, frameon=False, bbox_to_anchor=(0.5, 1.02))
fig.tight_layout(rect=(0, 0, 1, 0.9), w_pad=1.2)
fig.savefig(f"{out}/fig_results.pdf"); fig.savefig(f"{out}/fig_results.png", dpi=200)
print("ok")
