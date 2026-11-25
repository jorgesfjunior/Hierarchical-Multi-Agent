"""Drives one generated scenario through one architecture (shared by all three runners).

Incidents are keyed by the observable correlation key
``scenario_generator.incident_key`` (one incident per source host); ground
truth is written to its own file and never given to any architecture.

Per event, ``drive`` returns ``{"index", "event_id", "incident_key", "flagged",
"stage", "method", "decision"}`` where ``flagged`` is the architecture's verdict
for that incident after seeing the event: B1 over the incident's whole prefix,
B2 in the one instance the event was routed to, the MAS at Strategic
(incident-wide; ``flagged_any_layer`` adds specialist and coordinator).
``decision`` is the last decision recorded while processing the event.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

import yaml

from baselines.distributed_non_agentic.runner import DistributedNonAgenticBaseline
from baselines.mape_k_monolithic.loop import MAPEKLoop
from baselines.p2p.runner import PeerToPeerBaseline
from graph.build_graph import build_graph
from instrumentation.metrics import MetricsLogger
from knowledge.repository import KnowledgePolicyRepository
from simulation.scenario_generator import Scenario, incident_key

ARCHITECTURES = ("mas", "b1", "b2")  # the Phase 1-7b set (sanity runs iterate it)
ALL_ARCHITECTURES = ARCHITECTURES + ("p2p",)  # Phase 8 adds the flat peer-to-peer arm
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_config(name_or_path: str) -> dict[str, Any]:
    path = name_or_path
    if not os.path.isabs(path):
        path = os.path.join(_BASE_DIR, "config", path if path.endswith(".yaml") else f"{path}.yaml")
        if not os.path.exists(path):
            path = os.path.join(_BASE_DIR, name_or_path)
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def fresh_run_dir(log_dir: str, tag: str) -> str:
    """A NEW directory under ``<log_dir>/generated/``; never reuses (so never appends to) old logs."""
    root = os.path.join(log_dir, "generated")
    os.makedirs(root, exist_ok=True)
    while True:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        path = os.path.join(root, f"{stamp}_{tag}")
        try:
            os.makedirs(path, exist_ok=False)
            return path
        except FileExistsError:
            continue


def _new_decisions(repo: KnowledgePolicyRepository, before: int) -> Optional[str]:
    recorded = repo.all_decisions()[before:]
    return recorded[-1]["decision"] if recorded else None


def drive(
    arch: str,
    scenario: Scenario,
    repository: KnowledgePolicyRepository,
    metrics: MetricsLogger,
    domain_config: Optional[dict[str, Any]] = None,
    transport: Any = None,
    host_profiles: Optional[dict[str, str]] = None,
) -> list[dict[str, Any]]:
    """Feeds ``scenario.events`` (arrival order) to one architecture; see module docstring.

    With a ``simulation.transport.Transport`` the architecture only processes
    what is delivered to it; ``flagged`` is None for an event its deciding node
    never received.
    """
    out: list[dict[str, Any]] = []
    unobserved = getattr(scenario, "unobserved", frozenset())
    if unobserved:  # Fase 1: events no sensor reports never reach any node (no transport, no analysis)
        from dataclasses import replace

        observed = [e for e in scenario.events if e["event_id"] not in unobserved]
        index = {e["event_id"]: i for i, e in enumerate(scenario.events)}
        rows = drive(arch, replace(scenario, events=observed, unobserved=frozenset()), repository, metrics,
                     domain_config, transport, host_profiles)
        for r in rows:
            r["index"] = index[r["event_id"]]
        return rows
    if arch in ("mas", "sn"):
        if arch == "sn":  # Fase 1: segment specialists (graph/build_sn_graph.py)
            from graph.build_sn_graph import build_sn_graph

            graph = build_sn_graph(domain_config, repository, metrics, transport, host_profiles=host_profiles)
        else:
            graph = build_graph(domain_config, repository, metrics, transport)
        for i, ev in enumerate(scenario.events):
            key, before = incident_key(scenario.scenario_id, ev), len(repository.all_decisions())
            st = graph.invoke({"event": ev, "incident_id": key, "evidence_chain": []})
            sv = st.get("strategic_verdict")
            layers = [st.get("specialist_report"), st.get("coordinator_verdict"), sv]
            any_layer = any(v and v.get("is_ransomware_activity") for v in layers)
            out.append({"index": i, "event_id": ev["event_id"], "incident_key": key,
                        "flagged": None if sv is None else sv["is_ransomware_activity"],
                        "flagged_any_layer": any_layer, "stage": sv and sv["stage"], "method": sv and sv["method"],
                        "decision": _new_decisions(repository, before), "dropped": st.get("dropped")})
    elif arch in ("b1", "b2"):
        if arch == "b1":
            loop, prefixes = MAPEKLoop(repository, metrics), {}
        else:
            b2 = DistributedNonAgenticBaseline(domain_config, repository, metrics)
        for i, ev in enumerate(scenario.events):
            key = incident_key(scenario.scenario_id, ev)
            node = "central" if arch == "b1" else f"b2::{b2.route(ev)}"
            sim = None
            if transport is not None:
                sim = transport.begin(ev).sim(node)
                if sim is None:  # never delivered: the node emits nothing
                    out.append({"index": i, "event_id": ev["event_id"], "incident_key": key, "flagged": None,
                                "stage": None, "method": None, "decision": None, "dropped": node})
                    continue
            metrics.sim = sim
            try:
                if arch == "b1":
                    prefixes.setdefault(key, []).append(ev)
                    r = loop.run_incident(key, list(prefixes[key]))
                else:
                    r = b2.process_event(key, ev)
            finally:
                metrics.sim = None
            v = r["verdict"]
            out.append({"index": i, "event_id": ev["event_id"], "incident_key": key, "flagged": v.is_ransomware_activity,
                        "stage": v.stage, "method": v.method, "decision": r["decision"], "dropped": None,
                        **({"domain": r["domain"]} if arch == "b2" else {})})
    elif arch == "b2local":  # Fase 1: one B2-SSL instance inside each segment
        from baselines.segment_local.runner import SegmentLocalBaseline
        from simulation.fase1 import PROFILE_SEGMENT

        b2l = SegmentLocalBaseline({h: PROFILE_SEGMENT[p] for h, p in host_profiles.items()}, repository, metrics)
        for i, ev in enumerate(scenario.events):
            key = incident_key(scenario.scenario_id, ev)
            node = f"b2local::{b2l.route(ev)}"
            sim = None
            if transport is not None:
                sim = transport.begin(ev).sim(node)
                if sim is None:
                    out.append({"index": i, "event_id": ev["event_id"], "incident_key": key, "flagged": None,
                                "stage": None, "method": None, "decision": None, "dropped": node})
                    continue
            metrics.sim = sim
            try:
                r = b2l.process_event(key, ev)
            finally:
                metrics.sim = None
            v = r["verdict"]
            out.append({"index": i, "event_id": ev["event_id"], "incident_key": key, "flagged": v.is_ransomware_activity,
                        "stage": v.stage, "method": v.method, "decision": r["decision"], "dropped": None,
                        "segment": r["segment"]})
    elif arch == "p2p":
        p2p = PeerToPeerBaseline(domain_config, repository, metrics)
        for i, ev in enumerate(scenario.events):
            key = incident_key(scenario.scenario_id, ev)
            node = f"p2p::{p2p.route(ev)}"
            sim = t_now = visible = None
            if transport is not None:
                plan = transport.begin(ev)
                sim = plan.sim(node)
                if sim is None:  # the peer is down / never received it: nothing analysed or shared
                    out.append({"index": i, "event_id": ev["event_id"], "incident_key": key, "flagged": None,
                                "stage": None, "method": None, "decision": None, "dropped": node})
                    continue
                t_now, visible = plan.timing[node].start, transport.peer_visible_at(plan, node)
            metrics.sim = sim
            try:
                r = p2p.process_event(key, ev, t_now=t_now, visible_at=visible)
            finally:
                metrics.sim = None
            v = r["verdict"]
            out.append({"index": i, "event_id": ev["event_id"], "incident_key": key, "flagged": v.is_ransomware_activity,
                        "stage": v.stage, "method": v.method, "decision": r["decision"], "dropped": None,
                        "domain": r["domain"]})
    else:
        raise ValueError(f"unknown architecture {arch!r}; expected one of {ALL_ARCHITECTURES}")
    return out


def run_generated(
    arch: str,
    scenario: Scenario,
    *,
    domain_config: Optional[dict[str, Any]],
    policies: dict[str, Any],
    run_dir: Optional[str] = None,
    log_prefix: str = "run",
    transport: Any = None,
    return_logs: bool = False,
    keep_tmp: Optional[bool] = None,
    host_profiles: Optional[dict[str, str]] = None,
):
    """``drive`` with fresh repository/metrics; logs (and ground truth) go to ``run_dir`` if given.

    Without ``run_dir`` the event log goes to a temporary directory that is removed when the run
    ends (also on error), unless ``keep_tmp`` is True; None = ``keep_tmp_enabled()`` (environment
    variable ``KEEP_TMP_ENV``, set by ``--keep-tmp`` so it also reaches worker processes)."""
    import shutil
    import tempfile

    temporary = not run_dir
    target = run_dir or tempfile.mkdtemp()
    try:
        metrics = MetricsLogger(os.path.join(target, f"{log_prefix}_events.jsonl"))
        repository = KnowledgePolicyRepository(log_path=os.path.join(target, f"{log_prefix}_decisions.jsonl") if run_dir else None)
        for k, v in policies.items():
            repository.update_policy(k, v, updated_by="cli")
        try:
            records = drive(arch, scenario, repository, metrics, domain_config, transport, host_profiles)
        finally:
            metrics.close()
        if run_dir:
            with open(os.path.join(run_dir, "ground_truth.json"), "w", encoding="utf-8") as fh:
                json.dump(scenario.truth, fh, indent=1)
            with open(os.path.join(run_dir, f"{log_prefix}_per_event.jsonl"), "w", encoding="utf-8") as fh:
                for r in records:
                    fh.write(json.dumps(r) + "\n")
        if return_logs:
            with open(metrics.log_path, encoding="utf-8") as fh:
                logs = [json.loads(line) for line in fh]
            return records, logs, repository
        return records
    finally:
        if temporary and not (keep_tmp_enabled() if keep_tmp is None else keep_tmp):
            shutil.rmtree(target, ignore_errors=True)


KEEP_TMP_ENV = "MAS_KEEP_TMP"


def keep_tmp_enabled() -> bool:
    """Debugging: keep each run's temporary log directory (``--keep-tmp`` / ``MAS_KEEP_TMP=1``)."""
    return os.environ.get(KEEP_TMP_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def add_keep_tmp_arg(parser) -> None:
    parser.add_argument("--keep-tmp", action="store_true",
                        help=f"Keep each run's temporary log directory for debugging (sets {KEEP_TMP_ENV}=1).")


def apply_keep_tmp_arg(args) -> None:
    """Exports the flag to the environment, so multiprocessing workers inherit it."""
    if getattr(args, "keep_tmp", False):
        os.environ[KEEP_TMP_ENV] = "1"


def add_generated_args(parser) -> None:
    from simulation.scenario_generator import FAMILIES

    parser.add_argument("--family", choices=sorted(FAMILIES), help="--scenario generated: scenario family.")
    parser.add_argument("--scenario-seed", type=int, default=0, help="--scenario generated: scenario seed.")


def run_generated_cli(arch: str, args, repository_policies: dict[str, Any], domain_config, scheme: str, log_dir: str) -> str:
    """Entry point used by the three runners for ``--scenario generated``. Returns the run dir."""
    from simulation.scenario_generator import generate

    if not args.family:
        raise SystemExit("--scenario generated requires --family")
    scenario = generate(args.family, args.scenario_seed)
    method = repository_policies.get("detection_method", "legacy_weighted")
    run_dir = fresh_run_dir(log_dir, f"{arch}_{scheme}_{args.family}_s{args.scenario_seed}_{method.replace('+', '-')}")
    records = run_generated(arch, scenario, domain_config=domain_config, policies=repository_policies,
                            run_dir=run_dir, log_prefix=scheme)
    flags = [r["index"] for r in records if r["flagged"]]
    print(f"{arch} / {scheme} / {args.family} seed={args.scenario_seed} method={method}: "
          f"{len(records)} events, first flag at {flags[0] if flags else 'never'}")
    for r in records:
        print(f"  #{r['index']:<4} {r['incident_key'][-8:]} flagged={r['flagged']!s:<5} decision={r['decision']}")
    print(f"logs + ground truth: {run_dir}")
    return run_dir
