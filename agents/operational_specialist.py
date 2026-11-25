"""Generic Operational Specialist Agent.

A single class implements every Operational Specialist in the system. Its
behavior (which managed element it watches, which event types it handles,
and its escalation threshold) is entirely parameterized by the domain
configuration loaded at graph-build time -- nothing here is specific to any
one domain-partitioning scheme.

Responsibility: perceive an event on the managed element it owns and act
immediately if the event is within its delegated authority; otherwise flag
it for escalation to its Domain Coordinator. A report is always forwarded
upward (for aggregation), whether or not escalation was required.

Analysis is now real: this class calls ``detection.classifier.classify()``
-- the same, architecture-agnostic detection module used by
``baselines/mape_k_monolithic/``. The old `severity > self.max_severity`
stub (operating on a random 1-5 placeholder from the event generator) has
been removed entirely. Escalation is now driven by the detection Verdict's
``confidence`` and ``is_ransomware_activity``, compared against a
per-specialist ``escalation_confidence_threshold`` read from
``escalation_policy`` in the domain config (renamed from the old
``max_severity`` -- see config/*.yaml).

MAPE-K structure (see ``agents/mape.py``): ``__call__`` runs, in order,
``monitor`` (ingest + record the raw event in Knowledge), ``analyze``
(classify() over the history selected by policy ``analysis_scope::specialist``,
default ``"event"``), ``plan`` (escalate vs. contain locally, as an
``ActionPlan``; the escalation threshold is read from Knowledge policy
``escalation_threshold::<id>``, seeded from this agent's config), and
``execute`` (simulated mitigation, record decision, message the coordinator).

KNOWN LIMITATION -- partial evidence per invocation
----------------------------------------------------
The current graph structure (``graph/build_graph.py``) invokes a specialist
with exactly ONE synthetic event per incident; there is no accumulation of
a rolling event history for a given incident_id across multiple
invocations of the same specialist node. ``classify()`` is therefore
called here on a single-event list.

``detection.classifier``'s own design requires >= 2 *distinct* early-signal
types to correlate before flagging pre-encryption (early) activity as
ransomware (see ``detection/classifier.py``). A specialist observing a
single early-stage event (one recon event, one privilege-escalation
attempt, etc.) can therefore essentially NEVER produce
``is_ransomware_activity=True`` from that signal type alone -- it can only
ever contribute a partial, lower-confidence data point (still forwarded
upward via ``escalation_confidence_threshold`` if that alone clears the
bar). Late-stage (T1486) signals are largely self-contained within a
single event's payload and are NOT affected by this limitation: a
specialist observing one high-entropy, multi-corroborated ``file_write``
event does get a real, high-confidence positive verdict from that one
event alone.

This single-event view is kept ON PURPOSE: it is a characteristic of
specialization, not the bug. The bug was that evidence died here. Each
specialist now also records every event it observes (regardless of its own
local decision) into the shared incident evidence log via
``repository.record_event``, and the Domain Coordinator / Strategic
Governance layers run ``classify()`` over the accumulated events (see
those modules). Cross-event correlation therefore happens upstream, not
in this class.
"""
from __future__ import annotations

from typing import Any

from agents.mape import (
    ActionPlan,
    Analysis,
    Observation,
    analyze_history,
    dispatch_on_flag,
    mitigation_suffix,
    plan_mitigations,
    run_method,
    seed_policies,
)
from agents.mitigation import SimulatedMitigator
from instrumentation.metrics import (
    CONTAINMENT_DECISIONS,
    MetricsLogger,
    append_evidence,
    emit_action_dispatched,
    emit_analysis,
)
from knowledge.repository import KnowledgePolicyRepository

DEFAULT_ESCALATION_CONFIDENCE_THRESHOLD = 0.35


def _confidence_to_legacy_severity(confidence: float) -> int:
    """Maps a 0.0-1.0 confidence score onto the repository's 0-5 integer
    ``severity`` field.

    Kept ONLY for schema compatibility with
    ``KnowledgePolicyRepository.record_decision``, using the exact same
    mapping as ``baselines/mape_k_monolithic/loop.py`` so decisions.jsonl
    stays value-comparable across architectures. Duplicated here rather
    than imported: ``agents/`` and ``baselines/`` are meant to be
    independent implementations sharing only ``detection/``, ``knowledge/``
    and ``instrumentation/`` -- not silently coupled through a shared
    helper that could diverge unnoticed.
    """
    return max(0, min(5, round(confidence * 5)))


class OperationalSpecialistAgent:
    """Perceives and acts directly on one element of the managed system."""

    def __init__(
        self,
        domain_cfg: dict[str, Any],
        specialist_cfg: dict[str, Any],
        repository: KnowledgePolicyRepository,
        metrics: MetricsLogger,
    ):
        self.domain_cfg = domain_cfg
        self.specialist_cfg = specialist_cfg
        self.repository = repository
        self.metrics = metrics
        self.agent_id = specialist_cfg["id"]
        self.domain_name = domain_cfg["name"]
        self.escalation_confidence_threshold = specialist_cfg.get("escalation_policy", {}).get(
            "escalation_confidence_threshold", DEFAULT_ESCALATION_CONFIDENCE_THRESHOLD
        )
        self.mitigator = SimulatedMitigator(metrics)
        seed_policies(
            repository,
            updated_by="config",
            extra={
                f"escalation_threshold::{self.agent_id}": self.escalation_confidence_threshold,
                # Seeded from the run-wide ``detection_method`` (written before
                # the graph is built), so one flag selects the method everywhere.
                f"detection_method::{self.domain_name}": run_method(repository.get_policy),
            },
        )

    def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        observation = self.monitor(state)
        analysis = self.analyze(observation)
        plan = self.plan(analysis, observation)
        return self.execute(plan, analysis, observation, state)

    # --- Monitor: ingest only, no interpretation ---
    def monitor(self, state: dict[str, Any]) -> Observation:
        event = state["event"]
        incident_id = state["incident_id"]

        self.metrics.emit(
            event_type="signal_received",
            incident_id=incident_id,
            layer="specialist",
            agent_id=self.agent_id,
            payload={"event_type": event.get("type"), "source": event.get("source")},
        )
        # Unconditional evidence recording: whatever this specialist decides
        # locally, the raw event joins the incident's shared evidence pool so
        # the coordinator/strategic layers can correlate it with other events.
        self.repository.record_event(
            incident_id=incident_id, domain_name=self.domain_name, specialist_id=self.agent_id, event=event
        )
        return Observation(incident_id=incident_id, source=self.agent_id, domain_name=self.domain_name, payload=event)

    # --- Analyze: correlate against Knowledge history (scope from policy) ---
    def analyze(self, observation: Observation) -> Analysis:
        return analyze_history(
            self.repository,
            layer="specialist",
            incident_id=observation.incident_id,
            domain_name=self.domain_name,
            current_event=observation.payload,
        )

    # --- Plan: decide what to do (does nothing yet) ---
    def plan(self, analysis: Analysis, observation: Observation) -> ActionPlan:
        threshold = self.repository.get_policy(
            f"escalation_threshold::{self.agent_id}", self.escalation_confidence_threshold
        )
        escalate = analysis.is_ransomware_activity or analysis.confidence >= threshold
        detected_something = analysis.signal_count > 0
        decision = "escalation_required" if escalate else ("local_containment" if detected_something else "no_action")
        # Beyond its authority -> hand up, take no local action.
        actions = ()
        if decision == "local_containment":
            actions = plan_mitigations(
                self.repository,
                layer="specialist",
                decision=decision,
                analysis=analysis,
                incident_id=observation.incident_id,
                domain_name=self.domain_name,
            )
        if escalate and analysis.is_ransomware_activity and dispatch_on_flag(self.repository, "specialist"):
            # Delegated authority (policy dispatch_on_flag::specialist): contain
            # locally NOW within authority_phases, and still escalate.
            return ActionPlan(
                decision=decision,
                escalate=True,
                rationale=f"threshold={threshold}; dispatch_on_flag",
                actions=plan_mitigations(
                    self.repository,
                    layer="specialist",
                    decision="local_containment",
                    analysis=analysis,
                    incident_id=observation.incident_id,
                    domain_name=self.domain_name,
                ),
                record_decision=True,
                record_escalated=True,
                extra={"dispatch": "local_containment"},
            )
        return ActionPlan(
            decision=decision,
            escalate=escalate,
            rationale=f"threshold={threshold}",
            actions=actions,
            record_decision=not escalate,
            record_escalated=False,
        )

    # --- Execute: mitigate, record, message upward ---
    def execute(
        self, plan: ActionPlan, analysis: Analysis, observation: Observation, state: dict[str, Any]
    ) -> dict[str, Any]:
        event = observation.payload
        incident_id = observation.incident_id
        mitre_technique_ids = list(analysis.mitre_technique_ids)

        effects = [
            self.mitigator.execute(a, incident_id=incident_id, layer="specialist", agent_id=self.agent_id)
            for a in plan.actions
        ]

        evidence_chain = list(state.get("evidence_chain", []))
        append_evidence(
            evidence_chain,
            agent_id=self.agent_id,
            layer="specialist",
            summary=(
                f"detection.classify() on '{event.get('type')}' from {event.get('source')} via "
                f"{self.specialist_cfg.get('managed_element')}: confidence={analysis.confidence:.2f}, "
                f"stage={analysis.stage}, mitre={mitre_technique_ids or 'none'}; action={plan.decision}. "
                f"{analysis.rationale}" + mitigation_suffix(effects)
            ),
            based_on=[],
        )

        report = {
            "specialist_id": self.agent_id,
            "domain_name": self.domain_name,
            "managed_element": self.specialist_cfg.get("managed_element"),
            "event": event,
            "action": plan.decision,
            "escalate": plan.escalate,
            "confidence": analysis.confidence,
            "is_ransomware_activity": analysis.is_ransomware_activity,
            "stage": analysis.stage,
            "mitre_technique_ids": mitre_technique_ids,
        }

        node = f"specialist::{self.agent_id}"
        emit_analysis(
            self.metrics, incident_id=incident_id, layer="specialist", agent_id=self.agent_id, node=node, event=event,
            is_ransomware_activity=analysis.is_ransomware_activity, stage=analysis.stage,
            confidence=analysis.confidence, method=analysis.method, scope=analysis.scope,
            events_analyzed=analysis.events_analyzed, latched=analysis.latched,
        )
        dispatched = plan.extra.get("dispatch") or (plan.decision if plan.decision in CONTAINMENT_DECISIONS else None)
        if plan.record_decision:
            self.repository.record_decision(
                incident_id=incident_id,
                layer="specialist",
                agent_id=self.agent_id,
                decision=dispatched or plan.decision,
                severity=_confidence_to_legacy_severity(analysis.confidence),
                evidence_chain=evidence_chain,
                escalated=plan.record_escalated,
            )
            if not plan.escalate:
                self.metrics.emit(
                    event_type="alert_consolidated",
                    incident_id=incident_id,
                    layer="specialist",
                    agent_id=self.agent_id,
                    payload={"decision": plan.decision, "confidence": analysis.confidence},
                )
        if dispatched:
            emit_action_dispatched(
                self.metrics, incident_id=incident_id, layer="specialist", agent_id=self.agent_id, node=node,
                event=event, decision=dispatched, actions=[a.label() for a in plan.actions],
                on_flagged_verdict=analysis.is_ransomware_activity,
            )

        # The specialist->coordinator edge is unconditional (every event is
        # forwarded), so the handoff is counted on every event.
        self.metrics.emit(
            event_type="message_sent",
            incident_id=incident_id,
            layer="specialist",
            agent_id=self.agent_id,
            payload={"to": f"coordinator::{self.domain_name}", "report": report},
        )

        return {
            "specialist_report": report,
            "evidence_chain": evidence_chain,
            "domain_name": self.domain_name,
            "specialist_id": self.agent_id,
        }
