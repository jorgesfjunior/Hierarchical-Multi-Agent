"""Etapa 3 (DESCRITIVA, pós-execução): reexecução instrumentada de um SUBCONJUNTO da execução oficial.

Reexecuta, com o driver oficial e sem mudar nenhum módulo de simulação, as células h = 1 dos 4 níveis
de fronteira (oráculo, restrita, lote 5 min, lote 15 min) x 5 famílias, seeds 5000-5099, nos braços
SN, U1 e B2L. Para cada job:

1. gera as MESMAS linhas que ``simulation/fase1_oficial_experiments.job`` e as compara, campo a campo
   (como texto CSV), com as linhas de ``results/fase1_oficial/raw/``; qualquer diferença aborta;
2. só então extrai, dos logs do run, as métricas extras (registro, não comportamento): classificação
   por incidente, hosts benignos com ação, avisos, tempo até a primeira ação por campanha, mensagens
   por classe de enlace e ações do SN por camada.

    python3 analysis/fase1_etapa3_rerun.py [--seeds 5000-5099] [--workers 10]

Saída: results/fase1_oficial/etapa3/rerun/extras.jsonl.gz (um registro por run x braço) e verify.json.
"""
from __future__ import annotations

import argparse
import csv
import glob
import gzip
import json
import os
import sys
import time
from collections import Counter, defaultdict
from multiprocessing import Pool
from typing import Any

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from agents.campaign_links import ADVISORY_EVENT  # noqa: E402
from agents.mitigation import parse_action_label  # noqa: E402
from instrumentation.incident_metrics import classification, incident_frames, incident_outcomes, scenario_truth  # noqa: E402
from simulation import fase1_experiments as F  # noqa: E402
from simulation import fase1_oficial_experiments as O  # noqa: E402
from simulation import fase1b_experiments as B  # noqa: E402
from simulation.damage_model import dispatch_arrivals, scenario_clock, segment_of, simulate  # noqa: E402
from simulation.fase1 import P_PRE, PROFILE_SEGMENT  # noqa: E402

OUT = os.path.join(_BASE_DIR, "results", "fase1_oficial", "etapa3", "rerun")
RAW = os.path.join(_BASE_DIR, "results", "fase1_oficial", "raw")
INF = float("inf")


def _s(v: Any) -> str:
    return "" if v is None else str(v)  # what csv.DictWriter writes


def window(sc) -> tuple[float, float]:
    """Janela do fundo benigno (simulation/fase1.py: span do ataque +/- 300 s), em s desde a época."""
    ts = [t["t"] for t in sc.truth["events"] if not str(t["true_incident_id"]).startswith("bg-")]
    return min(ts) - 300.0, max(ts) + 300.0


def extras(f1, logs, tr, params) -> dict[str, Any]:
    sc = f1.scenario
    truth = sc.truth
    _, true_t, clock = scenario_clock(sc)
    source = {e["event_id"]: e.get("source", "") for e in sc.events}
    inc_by_key = {i["incident_key"]: i for i in truth["incidents"].values()}
    benign_keys = {k for k, i in inc_by_key.items() if not i["malicious"]}
    host_of = {k: i["host"] for k, i in inc_by_key.items()}
    impact = defaultdict(lambda: INF)
    for t in truth["events"]:
        if t["malicious"] and t["stage"] == "impact":
            impact[truth["incidents"][t["true_incident_id"]]["host"]] = min(
                impact[truth["incidents"][t["true_incident_id"]]["host"]], true_t[t["event_id"]])

    # 1a classificação (instrumentation.incident_metrics.classification), negativos = fundo benigno
    cls = classification(incident_outcomes(logs, incident_frames(sc)), scenario_truth(sc))
    cls = {b: {k: v[k] for k in ("tp", "fp", "fn", "tn")} for b, v in cls.items()}

    # 1b hosts benignos com ação (qualquer, isolamento, só restrição) e por perfil
    acted: dict[str, set] = defaultdict(set)
    for r in logs:
        if r["event_type"] == "action_dispatched" and r["incident_id"] in benign_keys and r["payload"]["actions"]:
            for label in r["payload"]["actions"]:
                acted[host_of[r["incident_id"]]].add(parse_action_label(label)[0])
    benign = {}
    for k in sorted(benign_keys):
        h = host_of[k]
        names = acted.get(h, set())
        benign[h] = {"profile": f1.host_profiles[h], "any": bool(names), "isolated": "isolate_host" in names}

    # 1c avisos (mesmas definições de fase1b_experiments.mechanism) + segmentos
    adv = [r for r in logs if r["event_type"] == ADVISORY_EVENT]
    keys = {(r["incident_id"], r["payload"]["event_id"]) for r in adv}
    arrivals = {}
    for r in logs:
        p = r["payload"]
        if r["event_type"] == "action_dispatched" and (r["incident_id"], p.get("event_id")) in keys and p["actions"] \
                and p["actions"][0].startswith("isolate_host("):
            arrivals.setdefault((r["incident_id"], p["event_id"]), clock[p["event_id"]] + float(p.get("sim_delay_s") or 0.0))
    benign_hosts = {host_of[k] for k in benign_keys}
    advisories = []
    for r in adv:
        a, b = r["payload"]["from_host"], r["payload"]["to_host"]
        arr = arrivals.get((r["incident_id"], r["payload"]["event_id"]))
        advisories.append({"from": a, "to": b, "cross": segment_of(a, params) != segment_of(b, params),
                           "false": b in benign_hosts, "arrival": arr,
                           "before_impact": None if arr is None else arr < impact[b]})

    # 2 tempo até a primeira ação por campanha (+ 1c revocação do aviso)
    outcomes, _ = simulate(sc, logs, params)
    disp, _ = dispatch_arrivals(sc, logs)
    first_action = {}
    for t, inc, *_ in disp:
        first_action[inc] = min(first_action.get(inc, INF), t)
    campaigns = []
    for key, o in outcomes.items():
        incs = set(o.campaign_incidents) or {key}
        hosts = {host_of[k] for k in incs}
        segs = {segment_of(h, params) for h in hosts}
        fa = min((first_action.get(k, INF) for k in incs), default=INF)
        onset, t_imp = o._onset, o._t_impact_truth
        warned = any(x["arrival"] is not None and x["to"] in hosts and segment_of(x["from"], params) != segment_of(x["to"], params)
                     and x["arrival"] < impact[x["to"]] for x in advisories)
        campaigns.append({"incident": key.split("::")[-1], "n_hosts": len(hosts), "cross_segment": len(segs) > 1,
                          "first_action_s": None if fa == INF else fa - onset,
                          "impact_s": None if t_imp is None else t_imp - onset,
                          "impact_started": o.impact_started, "warned_before_impact": warned})

    # 3 mensagens por classe de enlace (transport) e mensagens entre agentes (message_sent)
    sent = [r for r in logs if r["event_type"] == "message_sent"]
    comm = {"crossings": dict(tr.crossings), "crossing_bytes": dict(tr.crossing_bytes),
            "agent_messages": len(sent), "agent_message_bytes": sum(int(r.get("payload_size_bytes") or 0) for r in sent)}

    # 4 despachos por camada (todos os braços; o relatório usa o SN)
    layers = Counter()
    for r in logs:
        if r["event_type"] != "action_dispatched" or not r["payload"]["actions"]:
            continue
        p = r["payload"]
        target = host_of.get(r["incident_id"], "")
        trig = source.get(p["event_id"], "")
        node = p.get("node", "")
        outside = node.split("::")[0] in ("coordinator", "strategic", "central")
        crossed = outside or (bool(trig) and bool(target) and segment_of(trig, params) != segment_of(target, params))
        k = "|".join((r["layer"], "confirmado" if p.get("on_flagged_verdict", True) else "precaucao",
                      "benigno" if r["incident_id"] in benign_keys else "malicioso", "cruzou" if crossed else "local"))
        layers[k + "|despachos"] += 1
        layers[k + "|acoes"] += len(p["actions"])

    lo, hi = window(sc)
    return {"window_s": hi - lo, "event_hosts": len({e.get("source") for e in sc.events}), "classification": cls,
            "benign": benign, "advisories": [{k: v for k, v in a.items() if k != "arrival"} for a in advisories],
            "campaigns": campaigns, "comm": comm, "layers": dict(layers)}


def job(args):
    level, family, seed = args
    f1 = B.scenario(family, seed, 1, P_PRE)
    params, table = B.damage_params(f1), F.profile_table(F.load_thresholds(), 1)
    set_ = "principal" if level in ("oracle", "restricted") else "fronteira"
    head = {"status": O.CONFIRMATORY, "set": set_, "family": family, "seed": seed, "h": 1, "condition": level, "p_pre": P_PRE}
    rows = B.evaluate(f1, [], params, {**head, "arm": "NO-DEFENSE"}) if level == "oracle" else []
    out = []
    for arm in F.ARMS:
        logs, tr = O.run_arm(arm, f1, level, table)
        extra = {**F.instrumentation(f1, logs, params), "crossings_boundary": tr.crossings.get("boundary", 0),
                 "crossing_bytes_boundary": tr.crossing_bytes.get("boundary", 0)}
        rows += B.evaluate(f1, logs, params, {**head, "arm": arm, **extra})
        out.append({"level": level, "family": family, "seed": seed, "arm": arm, **extras(f1, logs, tr, params)})
    rows.sort(key=lambda r: (r["family"], r["seed"], r["h"], r["condition"], r["arm"], r["incident"]))
    return (level, family, seed), [{k: _s(v) for k, v in r.items()} for r in rows], out


def raw_index(level: str) -> dict[tuple, list[dict[str, str]]]:
    pref = f"main_h1_{level}_" if level in ("oracle", "restricted") else f"frontier_{level}_"
    idx: dict[tuple, list] = defaultdict(list)
    for path in sorted(glob.glob(os.path.join(RAW, pref + "*.csv"))):
        with open(path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                idx[(r["family"], int(r["seed"]))].append(r)
    return idx


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seeds", default="5000-5099")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args(argv)
    lo, hi = (int(x) for x in a.seeds.split("-"))
    seeds = range(lo, hi + 1)
    os.makedirs(a.out, exist_ok=True)
    raw = {lv: raw_index(lv) for lv in O.LEVELS}
    jobs = [(lv, f, s) for lv in O.LEVELS for f in O.FAMILIES for s in seeds]
    t0 = time.time()
    n_rows, mismatches, records = 0, [], []
    with Pool(a.workers) as pool:
        for (lv, f, s), rows, recs in pool.imap_unordered(job, jobs, chunksize=1):
            ref = raw[lv][(f, s)]
            # DictWriter writes '' for a column a row lacks (NO-DEFENSE rows): same canonical text
            same = lambda x, y: set(x) <= set(y) and all(x.get(k, "") == y[k] for k in y)  # noqa: E731
            if len(ref) != len(rows) or not all(same(x, y) for x, y in zip(rows, ref)):
                diff = [k for x, y in zip(rows, ref) for k in set(x) | set(y) if x.get(k, "") != y.get(k)]
                mismatches.append({"level": lv, "family": f, "seed": s, "rows": [len(rows), len(ref)], "fields": sorted(set(diff))})
            n_rows += len(rows)
            records += recs
    records.sort(key=lambda r: (O.LEVELS.index(r["level"]), r["family"], r["seed"], F.ARMS.index(r["arm"])))
    verify = {"seeds": [lo, hi], "jobs": len(jobs), "rows_compared": n_rows, "mismatched_jobs": len(mismatches),
              "mismatches": mismatches[:50], "identical": not mismatches, "elapsed_s": round(time.time() - t0, 1),
              "command": "python3 analysis/fase1_etapa3_rerun.py --seeds " + a.seeds}
    with open(os.path.join(a.out, "verify.json"), "w", encoding="utf-8") as fh:
        json.dump(verify, fh, indent=1)
        fh.write("\n")
    if mismatches:
        print(f"DIVERGÊNCIA: {len(mismatches)} jobs com linhas diferentes do raw; extras NÃO gravados. Ver verify.json")
        sys.exit(1)
    with gzip.open(os.path.join(a.out, "extras.jsonl.gz"), "wt", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, sort_keys=True) + "\n")
    print(f"ok: {n_rows} linhas idênticas ao raw em {len(jobs)} jobs; {len(records)} registros extras ({verify['elapsed_s']} s)")


if __name__ == "__main__":
    main()
