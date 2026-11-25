"""Simulated-time transport: link latency, node queues, message loss and faults (Phase 3).

Applied at architecture BOUNDARIES, outside every agent's decision logic: it
decides, before an event is processed, which nodes will receive it (faults,
partitions, losses) and when each receiving node finishes its analysis and
when an action it dispatches reaches the host. Agents are then invoked only
on the nodes that receive the event; they never read the transport.

Default OFF: with no ``Transport`` the architectures run exactly as before
(``tests/legacy_golden.py``). A ``Transport`` with ``CostModel()`` (all zeros)
is the zero-cost corner: every delay is 0.

Topology (node ids are the ``node`` field of ``analysis`` / ``action_dispatched``)
-------------------------------------------------------------------------------
  MAS : host --local--> specialist::<id> --domain--> coordinator::<domain> --center--> strategic
        dispatch back to the host: specialist +local, coordinator +domain, strategic +center
  B1  : host --center--> central ; dispatch central --center--> host
        (every B1 action is routed through the central node)
  B2  : host --local--> b2::<domain> ; dispatch +local  (domain-local, like specialists)
  P2P : host --local--> p2p::<domain> ; dispatch +local ; each peer shares the event and its
        verdict with every other peer over the center (cross-site) link (Phase 8; the runner
        uses ``peer_visible_at`` to decide what a peer has received by the time it analyses)

Every ANALYSING node (specialists, coordinators, Strategic, B1 central, B2
instances) is a single FIFO server with ``service_time_s`` per event and its
own queue; a node serves events in event order (in-order delivery per node,
like a TCP stream), so a later event cannot overtake an earlier one at the
same node. With ``shards > 1`` (scalability experiment) every domain-level
node (specialist, coordinator, B2 instance) is replicated ``shards`` times
and hosts are hashed across the replicas; ``strategic`` and ``central`` stay
single nodes.

Loss (``loss``) applies to inter-node COLLECTION links only (``domain`` and
``center``); host-local links and dispatch return paths are lossless. The
draw for an event on a link class is keyed by ``(seed, event index, link
class)``, so B1's and the MAS's center links lose the same events (paired).

Faults (``Fault``), active for event indices ``start_index <= i < end_index``:
  central_down       MAS ``strategic`` / B1 ``central`` drop their input (B2: no such node)
  coordinator_down   MAS ``coordinator::<target>`` / B2 ``b2::<target>`` / P2P ``p2p::<target>`` drop input (B1: none)
  specialist_down    MAS ``specialist::<target>`` drops input (no B1/B2 counterpart)
  partition          traffic crossing between domain ``<target>`` and the center is
                     blocked: MAS coordinator->strategic for that domain's events,
                     B1 host->central for that domain's events. Intra-domain traffic
                     (host<->specialist<->coordinator, B2) is untouched.
A dropped input is gone: the failed node and everything downstream of it emit
nothing for that event, and it is not replayed on recovery.
"""
from __future__ import annotations

import json
import math
import random
import zlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

from graph.build_graph import _build_routing_table, _specialist_node_name

LINKS = ("local", "domain", "center")
FAULT_KINDS = ("central_down", "coordinator_down", "specialist_down", "partition")


@dataclass(frozen=True)
class CostModel:
    local_latency_s: float = 0.0
    domain_latency_s: float = 0.0
    center_latency_s: float = 0.0
    service_time_s: float = 0.0
    loss: float = 0.0
    seed: int = 0
    shards: int = 1

    def latency(self, link: str) -> float:
        return {"local": self.local_latency_s, "domain": self.domain_latency_s, "center": self.center_latency_s}[link]


@dataclass(frozen=True)
class Fault:
    kind: str
    target: Optional[str] = None
    start_index: int = 0
    end_index: Optional[int] = None

    def __post_init__(self):
        if self.kind not in FAULT_KINDS:
            raise ValueError(f"unknown fault kind {self.kind!r}; expected one of {FAULT_KINDS}")

    def active(self, index: int) -> bool:
        return index >= self.start_index and (self.end_index is None or index < self.end_index)


@dataclass(frozen=True)
class Failover:
    """Coordinator (and specialist) failover for the MAS (Phase 7b; flag ``coordinator_failover``,
    default OFF = no ``Failover`` passed). A failed coordinator's role runs on the sibling coordinator
    (next domain in config order, cyclic; Strategic if there is only one domain), a failed
    specialist's on its domain coordinator, from fault onset + ``timeout_s`` on. Rerouted coordinator
    hops use the center link both ways (cross-site), rerouted specialist hops the domain link. Events
    before onset + timeout are lost as without failover. Heartbeats every ``heartbeat_s``. A partition
    also triggers the declaration (false failover / split-brain): counted, no rerouting possible."""

    timeout_s: float = 30.0
    heartbeat_s: float = 10.0


@dataclass(frozen=True)
class Boundary:
    """Fase 1 segment-boundary cost (docs/fase1/02_preregistro.md §4; Transport(boundary=None) = OFF).

    Applies to every message that crosses a segment boundary, identically for every architecture:
    UP (host telemetry to an outside node; an SN specialist's report to its coordinator) waits for the
    end of its segment's ``batch_s`` window, then for the segment's FIFO uplink at
    ``bandwidth_bytes_per_s`` (size = the event's JSON bytes), then ``latency_s``; DOWN (an action from an
    outside node back to the host) pays ``latency_s``. ``Boundary()`` (all zero/None) = the oracle."""

    latency_s: float = 0.0
    batch_s: Optional[float] = None
    bandwidth_bytes_per_s: Optional[float] = None


@dataclass
class NodeTiming:
    node: str
    arrive: float
    start: float
    done: float
    dispatch_at: float
    queue_len: int

    def sim(self, t_event: float) -> dict[str, float]:
        return {"analysis_delay": self.done - t_event, "dispatch_delay": self.dispatch_at - t_event}


@dataclass
class EventPlan:
    index: int
    event_id: Optional[str]
    t_event: float
    domain: str
    timing: dict[str, NodeTiming] = field(default_factory=dict)
    dropped: dict[str, str] = field(default_factory=dict)  # node -> reason
    gated: bool = False  # escalation gating: the event was not forwarded to the center
    failover: dict[str, str] = field(default_factory=dict)  # failed node -> node hosting its role

    def sim(self, node: str) -> Optional[dict[str, float]]:
        t = self.timing.get(node)
        return None if t is None else t.sim(self.t_event)


_RETURN_LINK = {"specialist": "local", "coordinator": "domain", "strategic": "center", "central": "center", "b2": "local",
                "p2p": "local"}


_SN_DEPTH = {"full": 3, "no_strategic": 2, "specialist_only": 1}


class Transport:
    """Deterministic simulated-time transport for one run of one architecture."""

    def __init__(self, arch: str, domain_config: Optional[dict[str, Any]], cost: Optional[CostModel] = None,
                 faults: tuple[Fault, ...] = (), *, service: Optional[Callable[[str, dict[str, Any]], float]] = None,
                 center_gate: Optional[Callable[[dict[str, Any]], bool]] = None, failover: Optional[Failover] = None,
                 p2p_sharing: str = "via_center", boundary: Optional[Boundary] = None,
                 host_segments: Optional[dict[str, int]] = None, sn_routing: Optional[Callable[[dict[str, Any]], tuple[str, str]]] = None,
                 sn_layers: str = "full"):
        """``service(node, event)`` (Phase 7a staged costs; default None = ``cost.service_time_s``
        everywhere) and ``center_gate(event)`` (MAS escalation gating; default None = every event
        is forwarded to Strategic; False = the event stops at its coordinator, which is not a drop)."""
        """Fase 1: ``boundary`` + ``host_segments`` ({host: segment}) put a segment boundary between hosts
        and every node outside their segment; arch ``"sn"`` (needs ``sn_routing(event) -> (specialist id,
        coordinator domain)``: specialist inside the segment, coordinator and Strategic outside) and
        ``"b2local"`` (one instance inside each segment). Default None = no boundary, unchanged."""
        if arch not in ("mas", "b1", "b2", "p2p", "sn", "b2local"):
            raise ValueError(f"unknown architecture {arch!r}")
        self.arch, self.cost, self.faults = arch, cost or CostModel(), tuple(faults)
        self.service, self.center_gate, self.failover = service, center_gate, failover
        if p2p_sharing not in ("via_center", "direct"):
            raise ValueError(f"unknown p2p_sharing {p2p_sharing!r}; expected 'via_center' or 'direct'")
        self.p2p_sharing = p2p_sharing
        if arch in ("sn", "b2local") and (boundary is None or host_segments is None):
            raise ValueError(f"arch {arch!r} needs a boundary (Boundary() = oracle) and host_segments")
        if arch == "sn" and sn_routing is None:
            raise ValueError("arch 'sn' needs sn_routing")
        # Etapa 3b ablation (docs/fase1/11_ablacao.md; default "full" = unchanged): the SN path stops at
        # the coordinator ("no_strategic") or at the specialist ("specialist_only").
        if sn_layers not in _SN_DEPTH:
            raise ValueError(f"unknown sn_layers {sn_layers!r}; expected one of {sorted(_SN_DEPTH)}")
        self.sn_layers = sn_layers
        self.boundary, self.host_segments, self.sn_routing = boundary, host_segments or {}, sn_routing
        self._uplink_free: dict[int, float] = defaultdict(float)
        self._domains: list[str] = [d["name"] for d in domain_config["domains"]] if domain_config else []
        self._spec_domain: dict[str, str] = ({s["id"]: d["name"] for d in domain_config["domains"] for s in d["specialists"]}
                                             if domain_config else {})
        self._onset: dict[int, float] = {}  # fault position -> simulated onset time
        self._last_t = 0.0
        self.fo_rerouted = 0
        self.fo_lost_in_timeout = 0
        self._route: dict[str, tuple[str, str]] = {}
        if domain_config is not None:
            domains = domain_config["domains"]
            node_to = {_specialist_node_name(s["id"]): (d["name"], s["id"]) for d in domains for s in d["specialists"]}
            self._route = {etype: node_to[n] for etype, n in _build_routing_table(domains).items()}
        self._epoch: Optional[datetime] = None
        self._index = 0
        self._free: dict[str, float] = defaultdict(float)
        self._busy: dict[str, deque] = defaultdict(deque)  # node -> done-times of jobs not yet finished
        self.plans: list[EventPlan] = []
        self.current: Optional[EventPlan] = None
        self.queue_samples: list[tuple[str, float, int]] = []  # (queue node, arrival time, jobs ahead)
        self.crossings: dict[str, int] = defaultdict(int)  # link class -> messages that crossed it
        self.crossing_bytes: dict[str, int] = defaultdict(int)

    # --- helpers ----------------------------------------------------------------
    def _t(self, event: dict[str, Any]) -> float:
        ts = event["timestamp"]
        ts = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
        if self._epoch is None:
            self._epoch = ts
        return (ts - self._epoch).total_seconds()

    def _queue_key(self, node: str, host: str) -> str:
        if self.cost.shards <= 1 or node in ("strategic", "central"):
            return node
        return f"{node}#{zlib.crc32(host.encode()) % self.cost.shards}"

    def _down(self, node: str, index: int, domain: str) -> Optional[str]:
        for f in self.faults:
            if not f.active(index):
                continue
            if f.kind == "central_down" and node in ("strategic", "central"):
                return "down"
            if f.kind == "coordinator_down" and node in (f"coordinator::{f.target}", f"b2::{f.target}", f"p2p::{f.target}"):
                return "down"
            if f.kind == "specialist_down" and node == f"specialist::{f.target}":
                return "down"
        return None

    def _down_fault(self, node: str, index: int) -> Optional[int]:
        for k, f in enumerate(self.faults):
            if f.active(index) and ((f.kind == "coordinator_down" and node == f"coordinator::{f.target}")
                                    or (f.kind == "specialist_down" and node == f"specialist::{f.target}")):
                return k
        return None

    def _failover_host(self, node: str) -> tuple[str, str]:
        """(node hosting the failed role, link class used to reach it and to dispatch from it)."""
        base, name = node.split("::", 1)
        if base == "specialist":
            return f"coordinator::{self._spec_domain[name]}", "domain"
        if len(self._domains) < 2:
            return "strategic", "center"
        i = self._domains.index(name)
        return f"coordinator::{self._domains[(i + 1) % len(self._domains)]}", "center"

    def failover_stats(self) -> dict[str, Any]:
        """Cost and side effects of failover for this run (all zero when it is OFF)."""
        if self.failover is None:
            return {"heartbeat_messages": 0, "rerouted_events": 0, "lost_in_timeout": 0, "false_failovers": 0, "dual_ownership_s": 0.0}
        span = self._last_t
        false, dual = 0, 0.0
        for k, f in enumerate(self.faults):
            if f.kind == "partition" and k in self._onset and self._onset[k] + self.failover.timeout_s <= span:
                false += 1
                dual += span - (self._onset[k] + self.failover.timeout_s)
        return {"heartbeat_messages": len(self._domains) * int(span // self.failover.heartbeat_s),
                "rerouted_events": self.fo_rerouted, "lost_in_timeout": self.fo_lost_in_timeout,
                "false_failovers": false, "dual_ownership_s": dual}

    def _partitioned(self, node: str, index: int, domain: str) -> bool:
        return node in ("strategic", "central") and any(
            f.kind == "partition" and f.target == domain and f.active(index) for f in self.faults
        )

    def _lost(self, index: int, link: str) -> bool:
        if self.cost.loss <= 0 or link == "local":
            return False
        return random.Random(f"{self.cost.seed}:{index}:{link}").random() < self.cost.loss

    def path(self, event: dict[str, Any]) -> tuple[str, list[tuple[str, str]]]:
        """(domain, [(node, inbound link), ...]) for this architecture."""
        domain, specialist = self._route.get(event.get("type"), ("-", "-"))
        if self.arch == "mas":
            return domain, [(f"specialist::{specialist}", "local"), (f"coordinator::{domain}", "domain"), ("strategic", "center")]
        if self.arch == "b1":
            return domain, [("central", "boundary" if self.boundary is not None else "center")]
        if self.arch == "p2p":
            return domain, [(f"p2p::{domain}", "local")]
        if self.arch == "sn":
            specialist, coord = self.sn_routing(event)
            hops = [(f"specialist::{specialist}", "local"), (f"coordinator::{coord}", "boundary"), ("strategic", "site")]
            return coord, hops[:_SN_DEPTH[self.sn_layers]]
        if self.arch == "b2local":
            return domain, [(f"b2local::{self._segment(event)}", "local")]
        return domain, [(f"b2::{domain}", "local")]

    # --- Fase 1 segment boundary -----------------------------------------------------
    def _segment(self, event: dict[str, Any]) -> int:
        return self.host_segments[event.get("source", "")]

    def _latency(self, link: str) -> float:
        if link == "site":  # between nodes outside the segments (coordinator -> Strategic): no boundary
            return self.cost.local_latency_s
        return self.cost.latency(link)

    def _uplink(self, event: dict[str, Any], ready: float, size: int) -> float:
        b, seg = self.boundary, self._segment(event)
        t = ready
        if b.batch_s:
            t = math.ceil(t / b.batch_s - 1e-9) * b.batch_s
        if b.bandwidth_bytes_per_s:
            t = max(t, self._uplink_free[seg]) + size / b.bandwidth_bytes_per_s
            self._uplink_free[seg] = t
        return t + b.latency_s

    def _return_latency(self, base: str, host_link: Optional[str]) -> float:
        if host_link is not None:
            return self.cost.latency(host_link)
        if self.boundary is not None and base in ("central", "coordinator", "strategic") and self.arch in ("b1", "sn"):
            return self.boundary.latency_s  # an action from outside the segment crosses it (DOWN)
        if base == "b2local":
            return self.cost.local_latency_s
        return self.cost.latency(_RETURN_LINK[base])

    def peer_visible_at(self, plan: "EventPlan", node: str) -> Optional[float]:
        """P2P: simulated time at which OTHER peers have received ``node``'s share of this event
        (its analysis done + one center-link hop); None if the peer never received the event.
        ``p2p_sharing="direct"`` (A3-6, P2P-direct): all-to-all over the domain link instead."""
        t = plan.timing.get(node)
        return None if t is None else t.done + self.cost.latency("domain" if self.p2p_sharing == "direct" else "center")

    # --- main entry ---------------------------------------------------------------
    def begin(self, event: dict[str, Any]) -> EventPlan:
        """Decides delivery and timing for the next event (call once per event, in order)."""
        index, t_event = self._index, self._t(event)
        self._index += 1
        self._last_t = max(self._last_t, t_event)
        for k, f in enumerate(self.faults):
            if k not in self._onset and f.active(index):
                self._onset[k] = t_event
        domain, hops = self.path(event)
        plan = EventPlan(index, event.get("event_id"), t_event, domain)
        size = len(json.dumps(event, default=str).encode("utf-8"))
        ready = t_event
        for node, link in hops:
            if node == "strategic" and self.center_gate is not None and not self.center_gate(event):
                plan.gated = True  # not escalated: never sent to Strategic (not a fault)
                break
            reason = self._down(node, index, domain)
            host_node, host_link = node, None
            if reason == "down" and self.failover is not None and self.arch == "mas":
                k = self._down_fault(node, index)
                if k is not None:
                    if t_event >= self._onset[k] + self.failover.timeout_s:
                        host_node, host_link = self._failover_host(node)
                        if self._down(host_node, index, domain) is None:
                            reason = None
                            plan.failover[node] = host_node
                            self.fo_rerouted += 1
                    else:
                        self.fo_lost_in_timeout += 1
            if reason is None and self._partitioned(node, index, domain):
                reason = "partition"
            if reason is None and self._lost(index, link):
                reason = "lost"
            if reason is not None:
                plan.dropped[node] = reason
                break
            if host_link is not None:
                link = host_link  # rerouted role: reached over the host's link
            self.crossings[link] += 1
            self.crossing_bytes[link] += size if (node == hops[0][0] or link == "boundary") else 0  # raw-event bytes
            arrive = self._uplink(event, ready, size) if link == "boundary" else ready + self._latency(link)
            key = self._queue_key(host_node, event.get("source", ""))
            busy = self._busy[key]
            while busy and busy[0] <= arrive:
                busy.popleft()
            start = max(arrive, self._free[key])
            done = start + (self.cost.service_time_s if self.service is None else self.service(node, event))
            self._free[key] = done
            self.queue_samples.append((key, arrive, len(busy)))
            busy.append(done)
            base = node.split("::")[0]
            dispatch_at = done + self._return_latency(base, host_link)
            plan.timing[node] = NodeTiming(node, arrive, start, done, dispatch_at, len(busy) - 1)
            ready = done
        self.plans.append(plan)
        self.current = plan
        return plan
