"""P2P baseline (Phase 8, amendment A1-b): flat peer-to-peer MAPE-K, no hierarchy, no Strategic.

One peer per configured domain; each peer is the SAME ``MAPEKLoop`` the other baselines use
(same detector, same playbook incl. ``prevent_*``, same effectors; every phase in authority).
Routing is the MAS rule (``handles``). A peer that receives an event:

  1. analyses the incident at incident scope over its VIEW: the events routed to it plus every
     event other peers have shared with it by the time it starts (zero cost: all of them);
  2. dispatches exactly as B1 would on that view (and the single-signal rule if
     ``single_signal_containment`` is ON: P2P-SSL);
  3. shares the event and its verdict with EVERY other peer (one ``message_sent`` per peer, the
     same accounting as the MAS: count + ``payload_size_bytes``).

With a ``Transport`` (arch ``"p2p"``) a peer's share reaches the others at its analysis-done
time + one center-link hop (``Transport.peer_visible_at``); a down peer (``coordinator_down``
on its domain) receives nothing and shares nothing. Lease confirmation: any peer confirms any
peer (they share verdicts), see ``simulation.damage_model.confirms``.

    python baselines/p2p/runner.py --scenario generated --family split_visibility --scenario-seed 0
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Optional

import yaml

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _BASE_DIR not in sys.path:
    sys.path.insert(0, _BASE_DIR)

from baselines.mape_k_monolithic.loop import MAPEKLoop  # noqa: E402
from detection.methods import DETECTION_METHODS  # noqa: E402
from graph.build_graph import _build_routing_table, _specialist_node_name  # noqa: E402
from instrumentation.metrics import MetricsLogger  # noqa: E402
from knowledge.repository import KnowledgePolicyRepository, apply_cli_policies  # noqa: E402

NODE_PREFIX = "p2p::"


def layer_name(domain_name: str) -> str:
    return f"p2p_{domain_name}"


class _PeerRepository:
    """Write view of the shared repository for ONE peer (rewrites layer/agent_id; reads policies only)."""

    def __init__(self, repository: KnowledgePolicyRepository, domain_name: str):
        self._repository, self._domain_name = repository, domain_name

    def record_decision(self, **kwargs: Any) -> dict[str, Any]:
        kwargs["layer"], kwargs["agent_id"] = layer_name(self._domain_name), f"peer::{self._domain_name}"
        return self._repository.record_decision(**kwargs)

    def get_policy(self, key: str, default: Any = None) -> Any:
        return self._repository.get_policy(key, default)


class _PeerMetrics:
    """Tags records with this peer's identity; the loop's node ``central`` becomes ``p2p::<domain>``."""

    def __init__(self, metrics: MetricsLogger, domain_name: str):
        self._metrics, self._domain_name = metrics, domain_name

    def emit(self, **kwargs: Any) -> dict[str, Any]:
        kwargs["layer"], kwargs["agent_id"] = layer_name(self._domain_name), f"peer::{self._domain_name}"
        payload = kwargs.get("payload")
        if isinstance(payload, dict) and payload.get("node") == "central":
            kwargs["payload"] = {**payload, "node": f"{NODE_PREFIX}{self._domain_name}"}
        return self._metrics.emit(**kwargs)

    @property
    def sim(self) -> Any:
        return getattr(self._metrics, "sim", None)


class PeerToPeerBaseline:
    """N peers, one per domain, sharing every event and verdict with every other peer."""

    def __init__(self, domain_config: dict[str, Any], repository: KnowledgePolicyRepository, metrics: MetricsLogger):
        domains = domain_config["domains"]
        routing = _build_routing_table(domains)
        if not routing:
            raise ValueError("Domain config declares no specialist 'handles' event types.")
        node_to_domain = {_specialist_node_name(s["id"]): d["name"] for d in domains for s in d["specialists"]}
        self._type_to_domain = {etype: node_to_domain[node] for etype, node in routing.items()}
        self.domains = [d["name"] for d in domains]
        self.metrics = metrics
        self.loops = {d: MAPEKLoop(_PeerRepository(repository, d), _PeerMetrics(metrics, d)) for d in self.domains}
        # incident -> [(order, owner peer, visible-to-others time or None = immediately, event)]
        self._shared: dict[str, list[tuple[int, str, Optional[float], dict[str, Any]]]] = {}
        self._order = 0
        self.messages = 0

    def route(self, raw_event: dict[str, Any]) -> str:
        domain = self._type_to_domain.get(raw_event.get("type"))
        if domain is None:
            raise ValueError(f"No domain in the loaded config handles event type {raw_event.get('type')!r}.")
        return domain

    def view(self, incident_id: str, peer: str, t_now: Optional[float]) -> list[dict[str, Any]]:
        """Events of the incident this peer has: its own, plus shares received by ``t_now``."""
        return [e for _, owner, vis, e in self._shared.get(incident_id, [])
                if owner == peer or t_now is None or vis is None or vis <= t_now]

    def process_event(self, incident_id: str, raw_event: dict[str, Any], *, t_now: Optional[float] = None,
                      visible_at: Optional[float] = None) -> dict[str, Any]:
        peer = self.route(raw_event)
        events = self.view(incident_id, peer, t_now) + [raw_event]
        result = self.loops[peer].run_incident(incident_id, events)
        self._shared.setdefault(incident_id, []).append((self._order, peer, visible_at, raw_event))
        self._order += 1
        v = result["verdict"]
        share = {"event": raw_event, "verdict": {"is_ransomware_activity": v.is_ransomware_activity, "stage": v.stage,
                                                 "confidence": v.confidence, "decision": result["decision"]}}
        for other in self.domains:
            if other != peer:
                self.messages += 1
                self.metrics.emit(event_type="message_sent", incident_id=incident_id, layer=layer_name(peer),
                                  agent_id=f"peer::{peer}", payload={"to": f"{NODE_PREFIX}{other}", **share})
        return {"domain": peer, **result}


def main() -> None:
    from simulation.experiment import add_generated_args, run_generated_cli

    parser = argparse.ArgumentParser(description="Run the P2P baseline (flat peer-to-peer MAPE-K).")
    parser.add_argument("--config", default="config/domains_proactive_reactive.yaml")
    parser.add_argument("--scenario", choices=["generated"], default="generated")
    parser.add_argument("--detection-method", choices=DETECTION_METHODS, default=None)
    parser.add_argument("--policy", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--log-dir", default="logs")
    add_generated_args(parser)
    args = parser.parse_args()
    path = args.config if os.path.isabs(args.config) else os.path.join(_BASE_DIR, args.config)
    with open(path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh)
    scratch = KnowledgePolicyRepository()
    apply_cli_policies(scratch, args.policy, args.detection_method)
    policies = {k: v["value"] for k, v in scratch.policies.items()}
    log_dir = args.log_dir if os.path.isabs(args.log_dir) else os.path.join(_BASE_DIR, args.log_dir)
    run_generated_cli("p2p", args, policies, cfg, os.path.splitext(os.path.basename(path))[0], log_dir)


if __name__ == "__main__":
    main()
