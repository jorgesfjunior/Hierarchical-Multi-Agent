"""Assembles the LangGraph state graph from a domain configuration.

This is the ONLY place that knows how to turn a domain-partitioning scheme
into a concrete set of nodes and edges. Neither the Strategic Governance
Agent nor the Operational Specialist Agent classes contain any knowledge
of a specific scheme (a/b/c from the research design, or any other one a
researcher invents later) -- swapping schemes means pointing
``build_graph`` at a different YAML file, nothing else.

Graph shape (fixed regardless of scheme):

    dispatch --(route by event type)--> specialist__<id>
    specialist__<id> --(always reports up)--> coordinator__<domain>
    coordinator__<domain> --(always)--> strategic
    strategic --> END

Both upward edges are UNCONDITIONAL, so Strategic Governance sees every
event and can correlate early signals across domains. This intentionally
raises inter-layer message volume (see agents/domain_coordinator.py).
"""
from __future__ import annotations

from typing import Any, Optional, TypedDict

from langgraph.graph import END, StateGraph

from agents.domain_coordinator import DomainCoordinatorAgent
from agents.operational_specialist import OperationalSpecialistAgent
from agents.strategic_governance import StrategicGovernanceAgent
from instrumentation.metrics import MetricsLogger
from knowledge.repository import KnowledgePolicyRepository


class IncidentState(TypedDict, total=False):
    """Per-incident state threaded through the graph.

    Each node returns only the keys it updates; LangGraph merges them into
    this dict (plain overwrite semantics -- no custom reducers are needed
    since no two nodes write the same key concurrently in this scaffold).
    """

    event: dict[str, Any]
    incident_id: str
    domain_name: str
    specialist_id: str
    specialist_report: dict[str, Any]
    domain_report: dict[str, Any]
    strategic_decision: dict[str, Any]
    coordinator_verdict: dict[str, Any]
    strategic_verdict: dict[str, Any]
    escalate_to_strategic: bool
    evidence_chain: list[dict[str, Any]]
    dropped: str  # transport only: node at which this event's flow stopped (fault/loss/partition)


def _specialist_node_name(specialist_id: str) -> str:
    # LangGraph reserves "::" (and "|") in node names, so "__" separates the
    # role prefix from the config-supplied id here.
    return f"specialist__{specialist_id}"


def _coordinator_node_name(domain_name: str) -> str:
    return f"coordinator__{domain_name}"


def _build_routing_table(domains: list[dict[str, Any]]) -> dict[str, str]:
    """Maps each declared event type ("handles") to its owning specialist node.

    First declaration wins on duplicates -- config authors are expected to
    keep ``handles`` disjoint across specialists for deterministic routing
    in this scaffold; a real system would need an explicit conflict policy.
    """
    routing: dict[str, str] = {}
    for domain in domains:
        for specialist_cfg in domain["specialists"]:
            node_name = _specialist_node_name(specialist_cfg["id"])
            for event_type in specialist_cfg.get("handles", []):
                routing.setdefault(event_type, node_name)
    return routing


def _transported(node_id: str, fn, transport, metrics):
    """Wraps a node so the transport (simulation/transport.py) decides delivery and
    sets the simulated timing; agent logic is untouched. A node that does not
    receive the event (failed, partitioned, lost link, or upstream dropped)
    runs nothing and emits nothing."""

    def run(state):
        if state.get("dropped"):
            return {}
        sim = transport.current.sim(node_id)
        if sim is None:
            return {"dropped": node_id}
        metrics.sim = sim
        try:
            return fn(state)
        finally:
            metrics.sim = None

    return run


def build_graph(
    domain_config: dict[str, Any],
    repository: KnowledgePolicyRepository,
    metrics: MetricsLogger,
    transport: Any = None,
):
    """Builds and compiles the hierarchical MAS graph for one domain scheme.

    Args:
        domain_config: parsed YAML/dict with the ``domains`` list (see any
            file under ``config/`` for the expected shape).
        repository: shared Global Knowledge & Policy Repository instance.
        metrics: shared instrumentation logger instance.
        transport: optional ``simulation.transport.Transport`` (cost model and
            faults). None (default) = the original graph, unchanged.
    """
    wrap = (lambda node_id, fn: _transported(node_id, fn, transport, metrics)) if transport else (lambda node_id, fn: fn)
    domains = domain_config["domains"]
    routing_table = _build_routing_table(domains)
    if not routing_table:
        raise ValueError("Domain config declares no specialist 'handles' event types.")

    graph = StateGraph(IncidentState)

    def dispatch(state: IncidentState) -> dict[str, Any]:
        # Pure routing waypoint: the actual node selection happens in the
        # conditional-edge function below, which receives the same state.
        if transport is not None:
            transport.begin(state["event"])  # delivery + timing for this event, decided up front
        return {}

    graph.add_node("dispatch", dispatch)
    graph.set_entry_point("dispatch")

    specialist_node_names: list[str] = []
    for domain in domains:
        domain_name = domain["name"]
        coord_node_name = _coordinator_node_name(domain_name)

        for specialist_cfg in domain["specialists"]:
            node_name = _specialist_node_name(specialist_cfg["id"])
            agent = OperationalSpecialistAgent(domain, specialist_cfg, repository, metrics)
            graph.add_node(node_name, wrap(f"specialist::{specialist_cfg['id']}", agent))
            graph.add_edge(node_name, coord_node_name)
            specialist_node_names.append(node_name)

        coordinator_agent = DomainCoordinatorAgent(domain, repository, metrics)
        graph.add_node(coord_node_name, wrap(f"coordinator::{domain_name}", coordinator_agent))

        graph.add_edge(coord_node_name, "strategic")

    strategic_agent = StrategicGovernanceAgent(domain_config, repository, metrics)
    graph.add_node("strategic", wrap("strategic", strategic_agent))
    graph.add_edge("strategic", END)

    def route_from_dispatch(state: IncidentState) -> str:
        event_type = state["event"].get("type")
        node_name = routing_table.get(event_type)
        if node_name is None:
            raise ValueError(
                f"No specialist in the loaded domain config handles event type "
                f"'{event_type}'. Declared types: {sorted(routing_table)}"
            )
        return node_name

    graph.add_conditional_edges(
        "dispatch", route_from_dispatch, {name: name for name in specialist_node_names}
    )

    return graph.compile()
