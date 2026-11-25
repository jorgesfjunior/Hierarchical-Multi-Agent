# Hierarchical Multi-Agent Self-Protection Against Ransomware — replication package

Jorge Soares, Nelson Rosa, Fernando Aires. Submitted to AINA 2027 (under review).

This repository holds the code, frozen pre-registrations, raw results and analysis scripts behind the
paper. The proposed architecture places a MAPE-K specialist in each network segment (proactive and
reactive modes); coordinators relay warnings between segments, and a central coordinator sets policy,
takes cross-segment actions and handles recovery. It is compared, in a discrete-event ransomware
simulation, with a central MAPE-K controller and with distributed rules without coordination
(research questions Q1–Q4), and with an ablated variant that keeps only the specialists (Q5). A sweep
over the detection threshold completes the evaluation.

## Layout

```
agents/          specialists, coordinators, central coordinator (MAPE-K stages, mitigation, warnings)
graph/           builds the multi-agent graph (build_sn_graph.py)
baselines/       central MAPE-K controller and distributed rules without agents
detection/       detectors shared by all architectures
knowledge/       shared knowledge and policy repository
simulation/      scenario generator, damage model, transport; experiment drivers (fase1_*_experiments.py)
instrumentation/ event and incident metrics
analysis/        statistics and figures for each run
config/          domain and threshold configurations (config/fase1/ is the frozen one)
tests/           regression and driver tests (+ fixtures)
docs/fase1/      pre-registrations (frozen) and reports — in Portuguese
results/         raw rows, manifests (SHA-256 per block), summary.json files, figures
paper/           Fig. 1 (fig_architecture.tex) and Fig. 2 (make_results_fig.py)
replication/     one-command script for the official run, Dockerfile, seeds, reference copies
```

## Install

Python **3.9.6** (the version used for every run):

```bash
python3.9 -m venv .venv && . .venv/bin/activate
pip install -r requirements.lock
```

A Docker image is described in `replication/environment/Dockerfile`.

## Quick checks (minutes)

```bash
python -m pytest -q tests/test_fase1_phase8_regression.py tests/test_fase1b.py tests/test_fase1_oficial.py  # the 87 regression tests
python -m pytest -q tests/test_fase1_A.py tests/test_fase1_ablacao.py
replication/scripts/reproduce_official.sh --smoke     # whole official pipeline, 2 seeds per cell (~3 min)
python simulation/fase1_oficial_experiments.py analyze --out results/fase1_oficial   # rewrites summary.json from raw/
python analysis/fase1_A.py                                                         # rewrites results/fase1_A/summary.json and figs/
python paper/make_results_fig.py results/fase1_A/summary.json paper/              # Fig. 2
```

## Full runs (reference machine: MacBook Air M4, 16 GB, 10 processes)

- **Official run, Q1–Q4** (pre-registration `docs/fase1/08_preregistro_oficial.md`; seeds 5000–5499, 500
  per cell): `replication/scripts/reproduce_official.sh` → `results/fase1_oficial_repro/`, about 70 min (4 077 s of blocks).
  It runs the regression precondition, the 39 blocks, the preconditions H0/C0, the Holm-corrected
  tests H1–H4 and the figures, then compares each block's SHA-256 with `results/fase1_oficial/manifest.json`.
- **Ablation (Q5) and threshold sweep** (pre-registration `docs/fase1/14_preregistro_A.md`; E1 seeds
  8000–8499, E2 seeds 8500–8699), about 70 min (E1 ≈ 32 min, E2 ≈ 37 min). Repeat the first command until it no longer
  prints "budget reached" (finished blocks are checkpointed), then analyse:

  ```bash
  python simulation/fase1_A_experiments.py run-all --out results/fase1_A_repro --budget-s 200
  python analysis/fase1_A.py --out results/fase1_A_repro
  ```

## Where the paper's numbers come from

| Paper | File | Key |
|---|---|---|
| Q1–Q4 | `results/fase1_oficial/summary.json` | `tests.H1`–`tests.H4`, `descriptive` |
| Fig. 2 (a) | same | `descriptive.proportions.levels_{oracle,restricted,batch5m,batch15m}` |
| Descriptive results | `results/fase1_oficial/etapa3/summary.json` | (report `docs/fase1/10_etapa3_descritiva.md`) |
| Q5 | `results/fase1_A/summary.json` | `E1.H5` (report `docs/fase1/15_relatorio_A.md`) |
| Threshold sweep, Fig. 2 (b) | same | `E2.curves` |
| Exploratory ablation behind Q5 | `results/fase1_ablacao/summary.json` | (report `docs/fase1/11_ablacao.md`) |

`docs/fase1/` is in Portuguese. `02`, `06`, `08` and `14` are pre-registrations; each `*.freeze.json`
records the freeze time (UTC), the commit and the SHA-256 of the frozen files (`shasum -a 256 <file>`
to check). `results/fase1_pilot/` and `results/fase1b_pilot/` are kept only as references for the
regression tests; `results/fase1_A_pilot/` is the pilot cited in pre-registration 14.

## Checks run on this package (Python 3.9.6, fresh venv)

- 87/87 regression tests pass; `test_fase1_A.py` (11) and `test_fase1_ablacao.py` (13) pass.
- Re-running 8 official blocks for seeds 5000–5001 and 8 fase1_A (block, seed) pairs reproduces the
  published raw rows (and the fase1_A extras records) exactly.
- From the included raw data, `results/fase1_oficial/summary.json`, `preconditions.json`,
  `results/fase1_A/summary.json`, `results/fase1_ablacao/summary.json` and
  `results/fase1_oficial/etapa3/summary.json` regenerate byte-identical.

## Integrity notes

1. `simulation/transport.py` differs from the hash in `08_preregistro_oficial.freeze.json`: an opt-in
   option (`sn_layers`, default unchanged) was added after the official run for the ablation. It matches
   the hash in `14_preregistro_A.freeze.json`, and the official rows still reproduce exactly (above).
2. `analysis/fase1_A.py` differs from the hash in `14_preregistro_A.freeze.json`: after the run, only
   the label positions of the sweep figure were changed (3 lines); no statistic is affected.
3. Commits cited in the manifests and freeze files (e.g. `d7e27df`, `dca68d7`, `54aa848`) belong to the
   private development history; this repository starts from a fresh history.
4. The frozen documents cite files of earlier phases that are not included here; they were not edited.
5. `results/fase1_oficial/R_pytest.txt`: the absolute `rootdir` path was replaced with `<repo>`.
6. `paper/make_results_fig.py` now reads panel (a) from `results/fase1_oficial/summary.json` instead
   of hard-coded values; the plotted values are the same (unrounded instead of rounded to 0.1).

Limitations: synthetic events, a single network topology and a fixed attacker model.

## License and citation

MIT (`LICENSE`). To cite, see `CITATION.cff`.
