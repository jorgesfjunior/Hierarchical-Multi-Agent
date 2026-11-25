"""Fase 1, arm SN: segment specialists inside their segments, the current coordinators and Strategic
outside (docs/fase1/02_preregistro.md §2; config/fase1/domains_sn.yaml).

    dispatch --(profile of the source host)--> specialist__<id>
    specialist__<id> --(kill-chain phase of the event type)--> coordinator__<domain>
    coordinator__<domain> --> strategic --> END

The coordinators (``DomainCoordinatorAgent``) and Strategic (``StrategicGovernanceAgent``) are the
existing classes, unchanged. With a transport (arch ``"sn"``) every node is wrapped exactly as in
``graph/build_graph.py``.
"""
from __future__ import annotations

from typing import Any, Callable

from langgraph.graph import END, StateGraph

from agents.domain_coordinator import DomainCoordinatorAgent
from agents.segment_specialist import SegmentSpecialistAgent
from agents.strategic_governance import StrategicGovernanceAgent
from graph.build_graph import IncidentState, _coordinator_node_name, _specialist_node_name, _transported


def phase_of_type(config: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for d in config["domains"]:
        for etype in d.get("handles", []):
            out.setdefault(etype, d["name"])
    return out


def sn_router(config: dict[str, Any], host_profiles: dict[str, str]) -> Callable[[dict[str, Any]], tuple[str, str]]:
    """event -> (specialist id of the source host's segment, coordinator domain of the event type)."""
    by_profile = {s["profile"]: s["id"] for s in config["segment_specialists"]}
    phases = phase_of_type(config)

    def route(event: dict[str, Any]) -> tuple[str, str]:
        etype = event.get("type")
        if etype not in phases:
            raise ValueError(f"No SN coordinator handles event type {etype!r}. Declared: {sorted(phases)}")
        return by_profile[host_profiles[event["source"]]], phases[etype]

    return route


ADVISORY_BYTES = 256  # size of an advisory message on the uplink (SM)


def advisory_timing(transport):
    """Fase 1b: simulated delays of an advisory from the specialist that processed the current event
    to the specialist of the advised host. Same segment: local hop. Other segment: the source
    segment's uplink (batch, bandwidth, latency; shared FIFO, so it queues with telemetry), the
    coordinator's service, the downlink latency, then the advised specialist's service."""
    def timing(event, source_specialist: str, advised_host: str):
        plan = transport.current
        t_src = plan.timing.get(f"specialist::{source_specialist}")
        if t_src is None:
            return None
        cost, b = transport.cost, transport.boundary
        seg_a = transport.host_segments.get(event.get("source", ""))
        seg_b = transport.host_segments.get(advised_host)
        if seg_a == seg_b:
            at = t_src.done + cost.local_latency_s + cost.service_time_s
        else:
            up = transport._uplink(event, t_src.done, ADVISORY_BYTES)
            transport.crossings["boundary"] += 2
            transport.crossing_bytes["boundary"] += 2 * ADVISORY_BYTES
            at = up + cost.service_time_s + b.latency_s + cost.service_time_s
        return {"analysis_delay": at - plan.t_event, "dispatch_delay": at + cost.local_latency_s - plan.t_event}
    return timing


SN_LAYERS_KEY = "sn_layers"  # Etapa 3b ablation (docs/fase1/11_ablacao.md); default "full" = unchanged
SN_LAYERS = ("full", "no_strategic", "specialist_only")


def sn_layers(get_policy) -> str:
    value = get_policy(SN_LAYERS_KEY, "full")
    if value not in SN_LAYERS:
        raise ValueError(f"unknown {SN_LAYERS_KEY} {value!r}; expected one of {SN_LAYERS}")
    return value


def build_sn_graph(config: dict[str, Any], repository, metrics, transport: Any = None, *, host_profiles: dict[str, str]):
    """Policy ``sn_layers`` (Etapa 3b, default "full"): "no_strategic" = no Strategic node (coordinators
    end the flow); "specialist_only" = no coordinator and no Strategic (specialists end the flow;
    advisories still pass the boundary, see ``advisory_timing``). The transport must use the same value."""
    layers = sn_layers(repository.get_policy)
    if transport is not None and getattr(transport, "sn_layers", "full") != layers:
        raise ValueError(f"policy {SN_LAYERS_KEY}={layers!r} but transport.sn_layers={transport.sn_layers!r}")
    if layers != "full":
        return _build_ablated(config, repository, metrics, transport, host_profiles, layers)
    wrap = (lambda node_id, fn: _transported(node_id, fn, transport, metrics)) if transport else (lambda node_id, fn: fn)
    phases = phase_of_type(config)
    route = sn_router(config, host_profiles)
    graph = StateGraph(IncidentState)

    def dispatch(state):
        if transport is not None:
            transport.begin(state["event"])
        return {}

    graph.add_node("dispatch", dispatch)
    graph.set_entry_point("dispatch")
    specialist_nodes, coordinator_nodes, peers = [], [], {}
    timing = advisory_timing(transport) if transport is not None else None
    for s in config["segment_specialists"]:
        name = _specialist_node_name(s["id"])
        agent = SegmentSpecialistAgent(s, phases, repository, metrics, peers=peers, advisory_timing=timing)
        peers[s["profile"]] = agent
        graph.add_node(name, wrap(f"specialist::{s['id']}", agent))
        specialist_nodes.append(name)
    for d in config["domains"]:
        name = _coordinator_node_name(d["name"])
        graph.add_node(name, wrap(f"coordinator::{d['name']}", DomainCoordinatorAgent(d, repository, metrics)))
        graph.add_edge(name, "strategic")
        coordinator_nodes.append(name)
    graph.add_node("strategic", wrap("strategic", StrategicGovernanceAgent(config, repository, metrics)))
    graph.add_edge("strategic", END)

    graph.add_conditional_edges("dispatch", lambda st: _specialist_node_name(route(st["event"])[0]),
                                {n: n for n in specialist_nodes})

    def to_coordinator(state) -> str:  # a dropped flow is routed too; the wrapped nodes then skip
        return _coordinator_node_name(route(state["event"])[1])

    for n in specialist_nodes:
        graph.add_conditional_edges(n, to_coordinator, {c: c for c in coordinator_nodes})
    return graph.compile()


def _build_ablated(config: dict[str, Any], repository, metrics, transport, host_profiles: dict[str, str], layers: str):
    """Etapa 3b (docs/fase1/11_ablacao.md): the same specialists (and, for "no_strategic", the same
    coordinators) as ``build_sn_graph``; only the upper layers and their edges are removed."""
    wrap = (lambda node_id, fn: _transported(node_id, fn, transport, metrics)) if transport else (lambda node_id, fn: fn)
    phases = phase_of_type(config)
    route = sn_router(config, host_profiles)
    graph = StateGraph(IncidentState)

    def dispatch(state):
        if transport is not None:
            transport.begin(state["event"])
        return {}

    graph.add_node("dispatch", dispatch)
    graph.set_entry_point("dispatch")
    specialist_nodes, coordinator_nodes, peers = [], [], {}
    timing = advisory_timing(transport) if transport is not None else None
    for s in config["segment_specialists"]:
        name = _specialist_node_name(s["id"])
        agent = SegmentSpecialistAgent(s, phases, repository, metrics, peers=peers, advisory_timing=timing)
        peers[s["profile"]] = agent
        graph.add_node(name, wrap(f"specialist::{s['id']}", agent))
        specialist_nodes.append(name)
    graph.add_conditional_edges("dispatch", lambda st: _specialist_node_name(route(st["event"])[0]),
                                {n: n for n in specialist_nodes})
    if layers == "specialist_only":
        for n in specialist_nodes:
            graph.add_edge(n, END)
        return graph.compile()
    for d in config["domains"]:  # "no_strategic"
        name = _coordinator_node_name(d["name"])
        graph.add_node(name, wrap(f"coordinator::{d['name']}", DomainCoordinatorAgent(d, repository, metrics)))
        graph.add_edge(name, END)
        coordinator_nodes.append(name)

    def to_coordinator(state) -> str:
        return _coordinator_node_name(route(state["event"])[1])

    for n in specialist_nodes:
        graph.add_conditional_edges(n, to_coordinator, {c: c for c in coordinator_nodes})
    return graph.compile()
