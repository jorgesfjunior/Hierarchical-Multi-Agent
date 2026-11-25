"""Fase 1 segment specialist (arm SN; docs/fase1/02_preregistro.md §3).

One specialist per segment (= host profile E1 / E2 / E3), located INSIDE its segment. It owns the
segment-local decisions (delegated authority of MAS-D: act first, then escalate):

  Monitor  ingest the event; keep the incident's history in the segment's LOCAL knowledge (free);
           record it in the shared Knowledge for the coordinators (that write crosses the boundary:
           the outside nodes only read what has reached them, see ``mark_seen``).
  Analyze  the run's detector (``assess_with_policies``, thresholds of the host's profile) over the
           incident's local history -- the same content U1 analyses centrally, since an incident is
           one host and a host is in one segment.
  Plan     flagged -> the same decision U1 would take (``plan_action``) with the LOCAL authority
           ``LOCAL_PHASES`` (no recovery, no global action: those escalate); not flagged but the event
           alone yields >= 1 signal -> the precaution rule (same rule and phases as SSL).
  Execute  mitigate, record the decision, and ALWAYS report up to the coordinator of the event's
           kill-chain phase (escalation for correlation, recovery and global actions).

Unlike ``OperationalSpecialistAgent``, the escalation threshold never moves a decision away from
the segment (J5): the specialist acts and also escalates.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from agents.campaign_links import ADVISORY_EVENT, CampaignLinker, advised_incident, advisory_actions, links_enabled
from agents.mape import seed_policies
from agents.mitigation import SimulatedMitigator, baseline_actions, enabled_preventive, resolve_playbook
from baselines.mape_k_monolithic.loop import plan_action
from detection.methods import HOST_PROFILES_KEY, assess_with_policies, run_method
from instrumentation.metrics import CONTAINMENT_DECISIONS, MetricsLogger, append_evidence, emit_action_dispatched, emit_analysis
from knowledge.repository import KnowledgePolicyRepository

# Local authority of a segment specialist (and of a B2-SSL-local instance): every phase that acts on
# the segment itself. Recovery (trigger_backup_restore) and prevent_global stay with Strategic.
LOCAL_PHASES = ("containment", "eradication", "prevent_host", "prevent_segment")
PRECAUTION_PHASES = ("containment",)  # + prevent_host when preventive actions are ON (SSL rule)


def _severity(confidence: float) -> int:
    return max(0, min(5, round(confidence * 5)))


class SegmentSpecialistAgent:
    def __init__(self, specialist_cfg: dict[str, Any], phase_of_type: dict[str, str],
                 repository: KnowledgePolicyRepository, metrics: MetricsLogger, *,
                 peers: Optional[dict[str, "SegmentSpecialistAgent"]] = None,
                 advisory_timing: Optional[Callable[[dict[str, Any], str, str], Optional[dict[str, float]]]] = None):
        """Fase 1b: ``peers`` ({profile: specialist}) and ``advisory_timing(event, source specialist id,
        advised host)`` (simulated delays of an advisory) are used only with policy campaign_links."""
        self.peers, self.advisory_timing = peers if peers is not None else {}, advisory_timing
        self.linker = CampaignLinker()
        self.agent_id = specialist_cfg["id"]
        self.profile = specialist_cfg["profile"]
        self.managed_element = specialist_cfg.get("managed_element")
        self.node = f"specialist::{self.agent_id}"
        self.phase_of_type = phase_of_type
        self.repository, self.metrics = repository, metrics
        self.mitigator = SimulatedMitigator(metrics)
        self._history: dict[str, list[dict[str, Any]]] = {}  # segment-local knowledge (no boundary)
        seed_policies(repository, updated_by="config")

    def receive_advisory(self, incident_id: str, event: dict[str, Any], a: str, b: str,
                         sim: Optional[dict[str, float]]) -> None:
        """Fase 1b: host ``b`` of THIS segment was reached by compromised host ``a``: apply the
        precaution rule to ``b``. ``sim`` = the advisory's simulated delays (boundary paid)."""
        get_policy = self.repository.get_policy
        target = advised_incident(incident_id, b)
        saved = getattr(self.metrics, "sim", None)
        self.metrics.sim = sim
        try:
            actions = advisory_actions(b, get_policy)
            for act in actions:
                self.mitigator.execute(act, incident_id=target, layer="specialist", agent_id=self.agent_id)
            self.metrics.emit(event_type=ADVISORY_EVENT, incident_id=target, layer="specialist", agent_id=self.agent_id,
                              payload={"node": self.node, "from_host": a, "to_host": b, "event_id": event.get("event_id")})
            emit_action_dispatched(self.metrics, incident_id=target, layer="specialist", agent_id=self.agent_id,
                                   node=self.node, event=event, decision="local_containment",
                                   actions=[x.label() for x in actions], on_flagged_verdict=False)
        finally:
            self.metrics.sim = saved

    def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        event, incident_id = state["event"], state["incident_id"]
        get_policy = self.repository.get_policy
        domain = self.phase_of_type[event["type"]]
        host = event.get("source", "unknown")
        # --- Monitor
        self.metrics.emit(event_type="signal_received", incident_id=incident_id, layer="specialist", agent_id=self.agent_id,
                          payload={"event_type": event.get("type"), "source": host})
        history = self._history.setdefault(incident_id, [])
        history.append(event)
        self.repository.record_event(incident_id=incident_id, domain_name=domain, specialist_id=self.agent_id, event=event)
        # --- Analyze
        method = run_method(get_policy)
        verdict = assess_with_policies(list(history), method, get_policy)
        emit_analysis(self.metrics, incident_id=incident_id, layer="specialist", agent_id=self.agent_id, node=self.node,
                      event=event, is_ransomware_activity=verdict.is_ransomware_activity, stage=verdict.stage,
                      confidence=verdict.confidence, method=verdict.method, scope="incident_local",
                      events_analyzed=len(history), latched=False)
        # --- Plan
        playbook = resolve_playbook(get_policy)
        flagged, decision, actions, basis = verdict.is_ransomware_activity, None, (), verdict
        if flagged:
            decision = plan_action(verdict)
            actions = baseline_actions(decision=decision, stage=verdict.stage, techniques=verdict.technique_ids,
                                       hosts=(host,), incident_id=incident_id, phases=LOCAL_PHASES, playbook=playbook)
        else:
            single = assess_with_policies([event], method, get_policy)
            if single.signal_count >= 1:
                decision, basis = "local_containment", single
                phases = PRECAUTION_PHASES + (("prevent_host",) if enabled_preventive(get_policy) else ())
                actions = baseline_actions(decision=decision, stage=single.stage, techniques=single.technique_ids,
                                           hosts=(host,), incident_id=incident_id, phases=phases, playbook=playbook)
        # --- Execute
        effects = [self.mitigator.execute(a, incident_id=incident_id, layer="specialist", agent_id=self.agent_id)
                   for a in actions]
        chain = list(state.get("evidence_chain", []))
        append_evidence(chain, agent_id=self.agent_id, layer="specialist",
                        summary=(f"segment {self.profile}: {basis.signal_count} signal(s) {list(basis.technique_ids)} on "
                                 f"'{event.get('type')}' from {host}; flagged={flagged}; decision={decision or 'no_action'}; "
                                 f"actions={[e['action'] + '(' + e['target'] + ')' for e in effects]}"),
                        based_on=[])
        if decision in CONTAINMENT_DECISIONS:
            self.repository.record_decision(incident_id=incident_id, layer="specialist", agent_id=self.agent_id,
                                            decision=decision, severity=_severity(basis.confidence),
                                            evidence_chain=chain, escalated=True)
            emit_action_dispatched(self.metrics, incident_id=incident_id, layer="specialist", agent_id=self.agent_id,
                                   node=self.node, event=event, decision=decision, actions=[a.label() for a in actions],
                                   on_flagged_verdict=flagged)
        report = {
            "specialist_id": self.agent_id, "domain_name": domain, "managed_element": self.managed_element,
            "event": event, "action": decision or "no_action",
            "escalate": bool(flagged or basis.signal_count),  # acts AND escalates (J5)
            "confidence": verdict.confidence, "is_ransomware_activity": flagged, "stage": verdict.stage,
            "mitre_technique_ids": list(verdict.technique_ids),
        }
        self.metrics.emit(event_type="message_sent", incident_id=incident_id, layer="specialist", agent_id=self.agent_id,
                          payload={"to": f"coordinator::{domain}", "report": report})
        if links_enabled(get_policy):  # Fase 1b: advise the specialist of every newly linked host
            profiles = get_policy(HOST_PROFILES_KEY, {}) or {}
            for a, b in self.linker.observe(event, verdict.signal_count >= 1):
                target = self.peers.get(profiles.get(b))
                if target is None:
                    continue
                self.repository.link_hosts(a, b)  # the advisory passes the coordinator (outside)
                sim = self.advisory_timing(event, self.agent_id, b) if self.advisory_timing else None
                target.receive_advisory(incident_id, event, a, b, sim)
        return {"specialist_report": report, "evidence_chain": chain, "domain_name": domain, "specialist_id": self.agent_id}
