"""Fase 1, caminho A (docs/fase1/14_preregistro_A.md): E1 = ablação CONFIRMATÓRIA das camadas de cima;
E2 = varredura DESCRITIVA de um multiplicador de limiares.

E1: braços SN e A3 (exatamente os da ablação, ``simulation/fase1_ablacao_experiments.py``);
    5 famílias, h = 1, fronteira lote 60 s (``restricted``) e lote 15 min (``batch15m``); seeds 8000-8499.
E2: braços SN, U1, B2L; multiplicador m em ``MULTIPLIERS`` aplicado igualmente a todos os braços e
    segmentos (``scaled_table``); 5 famílias, h = 1, ``restricted``; seeds 8500-8699.
Piloto (EXPLORATORY, só funcionamento e tempo): as mesmas grades com seeds 9000-9019.

    python3 simulation/fase1_A_experiments.py blocks [--pilot]
    python3 simulation/fase1_A_experiments.py run --block <nome> [--pilot]
    python3 simulation/fase1_A_experiments.py run-all --only <prefixo> [--pilot]

``run`` tem checkpoint: um bloco cujo arquivo bruto existe e confere com o sha256 do manifest é pulado.
Nenhum módulo de simulação, agente, baseline ou detecção muda; m = 1,0 usa a tabela congelada sem alteração.
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

from agents.campaign_links import ADVISORY_EVENT  # noqa: E402
from agents.mitigation import parse_action_label  # noqa: E402
from analysis.fase1_etapa3_rerun import extras  # noqa: E402
from detection import early_signals as ES  # noqa: E402
from detection import late_signals as LS  # noqa: E402
from simulation import fase1_ablacao_experiments as A  # noqa: E402
from simulation import fase1_experiments as F  # noqa: E402
from simulation import fase1_oficial_experiments as O  # noqa: E402
from simulation import fase1b_experiments as B  # noqa: E402
from simulation.fase1 import P_PRE, PROFILES  # noqa: E402

E1_SEEDS = tuple(range(8000, 8500))
E2_SEEDS = tuple(range(8500, 8700))
PILOT_SEEDS = tuple(range(9000, 9020))
E1_ARMS = ("SN", "A3")  # escopo reduzido (14 §3): U1/B2L já estão na rodada oficial; A1/A2 não entram no artigo
E2_ARMS = ("SN", "U1", "B2L")  # escopo reduzido (14 §4): A3 toma as mesmas decisões do SN
E1_LEVELS = ("restricted", "batch15m")
E2_LEVEL = "restricted"
MULTIPLIERS = (0.5, 0.75, 1.0, 1.25, 1.5, 2.0)
FAMILIES = O.FAMILIES
OUT = {False: os.path.join(_BASE_DIR, "results", "fase1_A"), True: os.path.join(_BASE_DIR, "results", "fase1_A_pilot")}
# Seeds por bloco (cada bloco <= 5 min). Tempos do piloto (20 seeds, 10 processos), pior caso por seed:
# campaign_multihost 3,2 s (E1, lote 15 min), campaign_e1_e2 0,9 s, demais <= 0,55 s.
CHUNK = {"campaign_multihost": 50, "campaign_e1_e2": 125}
DEFAULT_CHUNK = 250

# --- multiplicador de limiares (14_preregistro_A.md §4.2) ------------------------------------------
# Todo limiar numérico que a tabela por perfil aceita. m > 1 = mais exigente; m < 1 = mais sensível.
LINEAR_FLOAT = ("recon_hosts_per_second", "file_access_rate", "overwrite_ratio", "rename_rate", "mass_rate_multiplier")
LINEAR_INT = ("c2_min_beacons", "lateral_min_new_peers", "min_directories")
BOUNDED_MAX = {"entropy_high_bits": 8.0, "exposure_min_severity": 10.0}  # escore limitado: escala a folga até o máximo
CORROBORATORS = 3  # detect_encryption_entropy_signal tem 3 corroboradores
CONSTANTS = {
    "recon_hosts_per_second": ES.RECON_HOSTS_PER_SECOND_THRESHOLD, "file_access_rate": ES.FILE_ACCESS_RATE_THRESHOLD,
    "overwrite_ratio": ES.OVERWRITE_RATIO_THRESHOLD, "rename_rate": ES.RENAME_RATE_THRESHOLD,
    "mass_rate_multiplier": LS.MASS_MODIFICATION_RATE_MULTIPLIER, "c2_min_beacons": ES.C2_MIN_BEACONS,
    "lateral_min_new_peers": ES.LATERAL_MIN_NEW_PEERS, "min_directories": LS.MIN_DIRECTORIES_FOR_MASS_SPREAD,
    "entropy_high_bits": LS.ENTROPY_HIGH_THRESHOLD_BITS_PER_BYTE, "exposure_min_severity": ES.EXPOSURE_MIN_SEVERITY,
    "min_corroborating": LS.MIN_CORROBORATING_BEHAVIORAL_SIGNALS,
}


def _round_half_up(x: float) -> int:
    return int(x + 0.5 + 1e-9)


def scale(key: str, value: float, m: float):
    if key in LINEAR_FLOAT:
        return round(value * m, 6)
    if key in LINEAR_INT:
        return max(1, _round_half_up(value * m))
    if key in BOUNDED_MAX:
        top = BOUNDED_MAX[key]
        return round(top - (top - value) / m, 6)
    if key == "min_corroborating":
        return min(CORROBORATORS, max(1, _round_half_up(value * m)))
    raise KeyError(key)


def scaled_table(thresholds: dict[str, dict[str, Any]], m: float) -> dict[str, dict[str, Any]]:
    """Tabela h = 1 com o multiplicador m. m = 1,0 devolve a tabela congelada sem alteração (golden)."""
    frozen = F.profile_table(thresholds, 1)
    if m == 1.0:
        return frozen
    out = {}
    for p in PROFILES:
        row = dict(frozen[p])
        for key, const in CONSTANTS.items():
            row[key] = scale(key, row.get(key, const), m)
        out[p] = row
    return out


# --- blocos ---------------------------------------------------------------------------------------
def _chunks(seeds: tuple[int, ...], family: str, pilot: bool) -> list[tuple[int, ...]]:
    if pilot:
        return [seeds]
    k = CHUNK.get(family, DEFAULT_CHUNK)
    return [seeds[i:i + k] for i in range(0, len(seeds), k)]


def _mtag(m: float) -> str:
    return f"m{int(round(m * 100)):03d}"


def blocks(pilot: bool = False) -> dict[str, dict[str, Any]]:
    out = {}
    s1, s2 = (PILOT_SEEDS, PILOT_SEEDS) if pilot else (E1_SEEDS, E2_SEEDS)
    for cond in E1_LEVELS:
        for fam in FAMILIES:
            parts = _chunks(s1, fam, pilot)
            for i, seeds in enumerate(parts):
                name = f"E1_{cond}_{fam}" + (f"_part{i + 1}" if len(parts) > 1 else "")
                out[name] = {"exp": "E1", "condition": cond, "family": fam, "seeds": seeds, "multiplier": None}
    for m in MULTIPLIERS:
        for fam in FAMILIES:
            parts = _chunks(s2, fam, pilot)
            for i, seeds in enumerate(parts):
                name = f"E2_{_mtag(m)}_{fam}" + (f"_part{i + 1}" if len(parts) > 1 else "")
                out[name] = {"exp": "E2", "condition": E2_LEVEL, "family": fam, "seeds": seeds, "multiplier": m}
    return out


# --- piso de FP (14 §4.3): o que disparou cada isolamento de host benigno ------------------------------
def benign_isolation_triggers(f1, logs) -> dict[str, Any]:
    """Para cada despacho com ``isolate_host`` num incidente benigno: tipo (aviso / veredito positivo /
    precaução por 1 sinal) e tipo do evento que o disparou. Por host benigno isolado: o conjunto de
    (tipo, evento) de todos os seus isolamentos."""
    sc = f1.scenario
    etype = {e["event_id"]: e.get("type") for e in sc.events}
    benign = {i["incident_key"]: i["host"] for i in sc.truth["incidents"].values() if not i["malicious"]}
    adv = {(r["incident_id"], r["payload"].get("event_id")) for r in logs if r["event_type"] == ADVISORY_EVENT}
    per_host: dict[str, set] = {}
    counts = Counter()
    for r in logs:
        p = r["payload"]
        if r["event_type"] != "action_dispatched" or r["incident_id"] not in benign:
            continue
        if not any(parse_action_label(a)[0] == "isolate_host" for a in p["actions"]):
            continue
        kind = "aviso" if (r["incident_id"], p.get("event_id")) in adv else (
            "veredito" if p.get("on_flagged_verdict", True) else "precaucao")
        key = f"{kind}|{etype.get(p.get('event_id'), '?')}"
        counts[key] += 1
        per_host.setdefault(benign[r["incident_id"]], set()).add(key)
    return {"dispatches": dict(sorted(counts.items())), "hosts": {h: sorted(v) for h, v in sorted(per_host.items())}}


# --- job ------------------------------------------------------------------------------------------
def status(exp: str, pilot: bool) -> str:
    return "EXPLORATORY" if pilot else ("CONFIRMATORY" if exp == "E1" else "DESCRIPTIVE")


def job(args) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    exp, family, seed, condition, m, pilot = args
    f1 = B.scenario(family, seed, 1, P_PRE)
    thresholds = F.load_thresholds()
    params = B.damage_params(f1)
    table = scaled_table(thresholds, m) if exp == "E2" else F.profile_table(thresholds, 1)
    head = {"status": status(exp, pilot), "set": f"fase1_A_{exp}", "family": family, "seed": seed, "h": 1,
            "condition": condition, "p_pre": P_PRE}
    if exp == "E2":
        head["multiplier"] = m
    rows, recs = [], []
    for arm in (E1_ARMS if exp == "E1" else E2_ARMS):
        logs, tr = A.run_arm(arm, f1, condition, table)
        extra = {**F.instrumentation(f1, logs, params), "crossings_boundary": tr.crossings.get("boundary", 0),
                 "crossing_bytes_boundary": tr.crossing_bytes.get("boundary", 0)}
        rows += B.evaluate(f1, logs, params, {**head, "arm": arm, **extra})
        names = Counter()
        for r in logs:
            if r["event_type"] == "action_dispatched":
                for label in r["payload"]["actions"]:
                    names[f"{r['layer']}|{parse_action_label(label)[0]}"] += 1
        recs.append({"exp": exp, "level": condition, "multiplier": m, "family": family, "seed": seed, "arm": arm,
                     "action_names": dict(names), "benign_isolation_triggers": benign_isolation_triggers(f1, logs),
                     **extras(f1, logs, tr, params)})
    return rows, recs


# --- manifest / checkpoint ------------------------------------------------------------------------
def load_manifest(out: str) -> dict[str, Any]:
    path = os.path.join(out, "manifest.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    return {"preregistration": "docs/fase1/14_preregistro_A.md", "python": platform.python_version(),
            "platform": platform.platform(), "blocks": {}}


def run_block(name: str, out: str, workers: int, pilot: bool) -> str:
    spec = blocks(pilot)[name]
    raw = os.path.join(out, "raw", f"{name}.csv")
    ext = os.path.join(out, "extras", f"{name}.jsonl.gz")
    done = load_manifest(out)["blocks"].get(name)
    if done and os.path.exists(raw) and O.sha256(raw) == done["sha256"] and os.path.exists(ext):
        return f"{name}: checkpoint ok, skipped"
    arms = E1_ARMS if spec["exp"] == "E1" else E2_ARMS
    t0, started = time.time(), datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    jobs = [(spec["exp"], spec["family"], s, spec["condition"], spec["multiplier"], pilot) for s in spec["seeds"]]
    with Pool(workers) as pool:
        res = pool.map(job, jobs, chunksize=1)
    rows = sorted((r for rs, _ in res for r in rs),
                  key=lambda r: (r["family"], r["seed"], r["h"], r["condition"], r["arm"], r["incident"]))
    recs = sorted((x for _, xs in res for x in xs), key=lambda x: (x["seed"], arms.index(x["arm"])))
    os.makedirs(os.path.dirname(raw), exist_ok=True)
    os.makedirs(os.path.dirname(ext), exist_ok=True)
    B.write_csv(raw + ".tmp", rows)
    os.replace(raw + ".tmp", raw)
    with gzip.open(ext + ".tmp", "wt", encoding="utf-8") as fh:
        for x in recs:
            fh.write(json.dumps(x, sort_keys=True) + "\n")
    os.replace(ext + ".tmp", ext)
    elapsed = time.time() - t0
    manifest = load_manifest(out)
    manifest["blocks"][name] = {"file": os.path.relpath(raw, out), "sha256": O.sha256(raw), "rows": len(rows),
                                "extras": os.path.relpath(ext, out), "seeds": [spec["seeds"][0], spec["seeds"][-1]],
                                "n_seeds": len(spec["seeds"]), "exp": spec["exp"], "condition": spec["condition"],
                                "family": spec["family"], "multiplier": spec["multiplier"], "arms": list(arms),
                                "status": status(spec["exp"], pilot), "commit": O.git_commit(),
                                "python": platform.python_version(), "workers": workers, "started_utc": started,
                                "elapsed_s": round(elapsed, 1),
                                "command": f"python3 simulation/fase1_A_experiments.py run --block {name}"
                                           + (" --pilot" if pilot else "")}
    O.save_manifest(out, manifest)
    return f"{name}: {len(rows)} rows in {elapsed:.0f} s"


def main(argv: Optional[list[str]] = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("blocks", "run", "run-all"):
        sp = sub.add_parser(name)
        sp.add_argument("--pilot", action="store_true", help="seeds 9000-9019, EXPLORATORY, results/fase1_A_pilot")
        sp.add_argument("--out", default=None)
        if name in ("run", "run-all"):
            sp.add_argument("--workers", type=int, default=os.cpu_count() or 1)
        if name == "run":
            sp.add_argument("--block", required=True)
        if name == "run-all":
            sp.add_argument("--only", default="", help="prefixo do nome dos blocos (ex.: E1_, E2_m050_)")
            sp.add_argument("--budget-s", type=float, default=None,
                            help="não começa um bloco novo depois deste tempo (para cada comando ficar <= 5 min)")
    a = ap.parse_args(argv)
    out = a.out or OUT[a.pilot]
    if a.cmd == "blocks":
        print("\n".join(blocks(a.pilot)))
        return
    os.makedirs(out, exist_ok=True)
    if a.cmd == "run":
        if a.block not in blocks(a.pilot):
            raise SystemExit(f"bloco desconhecido: {a.block}")
        print(run_block(a.block, out, a.workers, a.pilot), flush=True)
    else:
        t0 = time.time()
        for n in blocks(a.pilot):
            if not n.startswith(a.only):
                continue
            if a.budget_s is not None and time.time() - t0 > a.budget_s:
                print("budget reached; rerun to continue", flush=True)
                break
            print(run_block(n, out, a.workers, a.pilot), flush=True)


if __name__ == "__main__":
    main()
