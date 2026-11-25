"""Baseline 2: N independent, non-communicating MAPE-K loops, one per domain.

Isolates "distribution" from "agency": the SAME domain partitioning the
multi-agent system uses, but each partition runs its own unmodified copy of
Baseline 1's ``MAPEKLoop`` and NOTHING connects them. There is no
Coordinator->Strategic equivalent, no shared evidence log, no messaging.

Composition, not a fork
-----------------------
``baselines.mape_k_monolithic.loop.MAPEKLoop`` is used as-is. Two gaps are
bridged from the outside, without touching that class:

  * ``MAPEKLoop`` hardcodes ``layer="monolithic"`` / ``agent_id`` in its
    ``record_decision`` / ``emit`` calls. Each instance is handed a thin
    per-domain adapter (`_DomainRepository`, `_DomainMetrics`) that rewrites
    those two fields to ``layer="baseline_distributed_<domain>"`` and
    ``agent_id=<domain>`` and forwards to the shared repository/metrics
    (so decisions.jsonl stays schema-identical). The adapters expose ONLY
    the two methods ``MAPEKLoop`` calls; in particular they expose no read
    access, so an instance cannot see anything another instance recorded.
  * ``MAPEKLoop.run_incident`` analyzes one whole window per call and keeps
    no history. Each domain instance therefore keeps ITS OWN per-incident
    history of events routed to it (`_DomainInstance._history`) and calls
    ``run_incident`` with that domain-local list on every new event -- the
    same per-event cadence the MAS uses.

Routing reuses the MAS graph's own rule (``graph.build_graph._build_routing_table``:
first declaration wins on duplicate ``handles``) and maps the resulting
specialist to its domain from the config; no second routing table exists.

Decision vocabulary is whatever ``MAPEKLoop.plan_action`` produces
(no_action / local_containment / global_containment_directive). Note that
``plan_action`` maps a flagged EARLY verdict to ``local_containment``, never
to ``global_containment_directive`` -- see README "Comparability caveat".

Single-signal local policy (SSL, Phase 4 comparator for H-F3; default OFF)
--------------------------------------------------------------------------
With Knowledge policy ``single_signal_containment`` ON, each instance ALSO
dispatches ``local_containment`` -- the playbook's containment-phase actions
(``agents.mitigation.baseline_actions``) for the observed technique on the
event's host -- whenever the event it just received yields >= 1 detection
signal on its own (``assess_with_policies([event], <run method>)``, the same
call and the same method the MAS specialist uses at event scope) and the
loop itself did not dispatch containment for it. The rule lives in
``MAPEKLoop.single_signal`` (shared with B1-SSL); the decision is recorded
(layer of this instance, evidence "single-signal local policy") and the
dispatch is logged with ``on_flagged_verdict=False``. OFF: nothing changes.

Usage:

    python baselines/distributed_non_agentic/runner.py --scenario both   # default config: domains_proactive_reactive
    python baselines/distributed_non_agentic/runner.py --config config/domains_by_system_area.yaml   # sensitivity
    # --scenario: attack | benign | cross_domain | both (attack+benign, default) | all
"""
from __future__ import annotations

import argparse
import os
import sys
import uuid
from typing import Any, Optional

import yaml

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from baselines.mape_k_monolithic.loop import SINGLE_SIGNAL_KEY, MAPEKLoop  # noqa: E402,F401  (re-exported)
from graph.build_graph import _build_routing_table, _specialist_node_name  # noqa: E402
from instrumentation.metrics import MetricsLogger  # noqa: E402
from detection.methods import DETECTION_METHODS  # noqa: E402
from knowledge.repository import KnowledgePolicyRepository, apply_cli_policies  # noqa: E402
from simulation.mock_managed_system import generate_attack_sequence, generate_benign_activity_stream  # noqa: E402


def layer_name(domain_name: str) -> str:
    return f"baseline_distributed_{domain_name}"


class _DomainRepository:
    """Write-only view of the shared repository for ONE domain instance.

    Rewrites ``layer``/``agent_id``. The only read is ``get_policy``: run
    configuration (the ``detection_method`` flag and its parameters), written
    before the run and never written by any instance. Decisions and events
    recorded by other instances stay unreadable.
    """

    def __init__(self, repository: KnowledgePolicyRepository, domain_name: str):
        self._repository = repository
        self._domain_name = domain_name

    def record_decision(self, **kwargs: Any) -> dict[str, Any]:
        kwargs["layer"] = layer_name(self._domain_name)
        kwargs["agent_id"] = self._domain_name
        return self._repository.record_decision(**kwargs)

    def get_policy(self, key: str, default: Any = None) -> Any:
        return self._repository.get_policy(key, default)


class _DomainMetrics:
    """``MetricsLogger.emit`` adapter that tags records with this domain's identity."""

    def __init__(self, metrics: MetricsLogger, domain_name: str):
        self._metrics = metrics
        self._domain_name = domain_name

    def emit(self, **kwargs: Any) -> dict[str, Any]:
        kwargs["layer"] = layer_name(self._domain_name)
        kwargs["agent_id"] = self._domain_name
        payload = kwargs.get("payload")
        if isinstance(payload, dict) and payload.get("node") == "central":
            kwargs["payload"] = {**payload, "node": f"b2::{self._domain_name}"}
        return self._metrics.emit(**kwargs)

    @property
    def sim(self) -> Any:  # cost-model timing set by the transport on the shared logger
        return getattr(self._metrics, "sim", None)


class _DomainInstance:
    """One independent MAPE-K loop plus its private, domain-scoped event history."""

    def __init__(self, domain_name: str, repository: KnowledgePolicyRepository, metrics: MetricsLogger):
        self.domain_name = domain_name
        self.loop = MAPEKLoop(_DomainRepository(repository, domain_name), _DomainMetrics(metrics, domain_name))
        self._history: dict[str, list[dict[str, Any]]] = {}  # incident_id -> events routed HERE only

    def handle(self, incident_id: str, raw_event: dict[str, Any]) -> dict[str, Any]:
        history = self._history.setdefault(incident_id, [])
        history.append(raw_event)
        return self.loop.run_incident(incident_id, list(history))  # SSL rule (if ON) runs inside the loop

    def events_seen(self, incident_id: str) -> int:
        return len(self._history.get(incident_id, []))


class DistributedNonAgenticBaseline:
    """N isolated ``MAPEKLoop`` instances, one per configured domain."""

    def __init__(self, domain_config: dict[str, Any], repository: KnowledgePolicyRepository, metrics: MetricsLogger):
        domains = domain_config["domains"]
        routing = _build_routing_table(domains)  # event type -> "specialist__<id>" (MAS rule)
        if not routing:
            raise ValueError("Domain config declares no specialist 'handles' event types.")
        node_to_domain = {
            _specialist_node_name(s["id"]): d["name"] for d in domains for s in d["specialists"]
        }
        self._type_to_domain = {etype: node_to_domain[node] for etype, node in routing.items()}
        self.instances: dict[str, _DomainInstance] = {
            d["name"]: _DomainInstance(d["name"], repository, metrics) for d in domains
        }

    def route(self, raw_event: dict[str, Any]) -> str:
        etype = raw_event.get("type")
        domain = self._type_to_domain.get(etype)
        if domain is None:
            raise ValueError(
                f"No domain in the loaded config handles event type '{etype}'. "
                f"Declared types: {sorted(self._type_to_domain)}"
            )
        return domain

    def process_event(self, incident_id: str, raw_event: dict[str, Any]) -> dict[str, Any]:
        """Routes the event to exactly one instance; no other instance is invoked."""
        domain = self.route(raw_event)
        result = self.instances[domain].handle(incident_id, raw_event)
        return {"domain": domain, **result}

    def process_stream(self, incident_id: str, raw_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.process_event(incident_id, e) for e in raw_events]


def cross_domain_pair(seed: int = 7) -> list[dict[str, Any]]:
    """The exact T1018 + T1490 pair used by the MAS's cross-domain proactive test."""
    sequence = generate_attack_sequence(seed=seed)
    return [
        next(e for e in sequence if e["type"] == "network_enumeration"),
        next(e for e in sequence if e["type"] == "backup_recovery_tamper"),
    ]


def _cli_policy_values(args) -> dict:
    """The policies the CLI would write, as plain values (rejects per-domain overrides)."""
    scratch = KnowledgePolicyRepository()
    apply_cli_policies(scratch, args.policy, args.detection_method)
    return {k: v["value"] for k, v in scratch.policies.items()}


def _print_results(label: str, incident_id: str, results: list[dict[str, Any]]) -> None:
    print(f"\n--- {label}: incident {incident_id[:8]} ---")
    for i, r in enumerate(results):
        v = r["verdict"]
        print(
            f"  #{i} -> domain={r['domain']:<18} decision={r['decision']:<28} "
            f"confidence={v.confidence:.2f} flagged={v.is_ransomware_activity} stage={v.stage} "
            f"mitre={list(v.mitre_technique_ids())}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Baseline 2 (distributed, non-agentic MAPE-K loops).")
    parser.add_argument("--config", default="config/domains_proactive_reactive.yaml")
    parser.add_argument("--scenario", choices=["attack", "benign", "cross_domain", "both", "all", "generated"], default="both")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--attack-seed", type=int, default=7)
    parser.add_argument(
        "--detection-method",
        choices=DETECTION_METHODS,
        default=None,
        help="Run-wide detection method (Knowledge policy 'detection_method'); same flag for all three architectures.",
    )
    parser.add_argument("--policy", action="append", default=[], metavar="KEY=VALUE", help="Write a Knowledge policy (repeatable). Per-domain detection_method::<domain> overrides are rejected "
        "(mixed-method runs are not allowed in the experiment path; use --detection-method).")
    parser.add_argument("--log-dir", default="logs")
    from simulation.experiment import add_generated_args, run_generated_cli

    add_generated_args(parser)
    args = parser.parse_args()

    config_path = args.config if os.path.isabs(args.config) else os.path.join(_BASE_DIR, args.config)
    with open(config_path, encoding="utf-8") as fh:
        domain_config = yaml.safe_load(fh)
    scheme = os.path.splitext(os.path.basename(config_path))[0]
    log_dir = args.log_dir if os.path.isabs(args.log_dir) else os.path.join(_BASE_DIR, args.log_dir)
    os.makedirs(log_dir, exist_ok=True)
    if args.scenario == "generated":  # fresh run dir under <log-dir>/generated/, never appends
        run_generated_cli("b2", args, _cli_policy_values(args), domain_config, f"baseline_distributed_{scheme}", log_dir)
        return
    events_log = os.path.join(log_dir, f"baseline_distributed_{scheme}_events.jsonl")
    decisions_log = os.path.join(log_dir, f"baseline_distributed_{scheme}_decisions.jsonl")

    metrics = MetricsLogger(events_log)
    repository = KnowledgePolicyRepository(log_path=decisions_log)
    apply_cli_policies(repository, args.policy, args.detection_method)
    baseline = DistributedNonAgenticBaseline(domain_config, repository, metrics)
    print(f"Baseline 2: distributed non-agentic ({scheme}); domains={list(baseline.instances)}")

    def run(label: str, events: list[dict[str, Any]]) -> None:
        iid = str(uuid.uuid4())
        _print_results(label, iid, baseline.process_stream(iid, events))

    if args.scenario in ("attack", "both", "all"):
        run("attack", generate_attack_sequence(seed=args.attack_seed))
    if args.scenario in ("benign", "both", "all"):
        run("benign", generate_benign_activity_stream(count=8, seed=args.seed))
    if args.scenario in ("cross_domain", "all"):
        run("cross_domain (T1018 + T1490)", cross_domain_pair(args.attack_seed))
    metrics.close()
    print(f"\nLogs: {events_log}\n      {decisions_log}")


if __name__ == "__main__":
    main()
