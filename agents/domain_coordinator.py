"""Generic Domain Coordinator Agent.

A single class implements every Domain Coordinator, regardless of which
domain-partitioning scheme is loaded (reactive/adaptive, per-threat-type,
or per-system-area). Its identity, delegated authority, and domain name
come entirely from the domain configuration passed in at graph-build time.

Responsibility: translate the global goal into domain-local objectives
(implicitly, via its escalation threshold), aggregate reports from the
Operational Specialists in its domain, and escalate to the Strategic
Governance Agent whatever exceeds its delegated authority.

The old `severity > self.max_severity` stub has been removed. This
coordinator now reads the real detection ``confidence`` and
``is_ransomware_activity`` fields the specialist's Verdict already computed
(see ``agents/operational_specialist.py``) and compares them against its
own ``escalation_confidence_threshold`` (renamed from ``max_severity`` --
see config/*.yaml) to decide whether to contain at the domain level or
escalate further.

MAPE-K structure (see ``agents/mape.py``): ``monitor`` ingests the
specialist report, ``analyze`` runs classify() over the domain-scoped history
(policy ``analysis_scope::coordinator``), ``plan`` decides escalate vs. domain
containment (threshold from Knowledge policy ``escalation_threshold::<id>``)
and which containment/eradication actions apply, ``execute`` performs the
simulated mitigation, records the decision and forwards to Strategic.

Domain-level evidence aggregation
---------------------------------
On EVERY invocation this coordinator runs ``detection.classifier.classify()``
over the events accumulated for this incident within its own domain
(``repository.events_for_incident(incident_id, domain_name=...)``) -- the
same entry point, and the same corroboration rule, the monolithic baseline
uses over its full event list. Specialists still see one event each; the
correlation happens here. Its escalation decision is driven by that
aggregated verdict, not by the triggering specialist_report alone.

The coordinator's OWN decision stays meaningful (it still records
domain-level ``local_containment`` when warranted), but its edge to
Strategic Governance is now UNCONDITIONAL: every event's domain_report
reaches Strategic, whether or not this coordinator escalated.

MESSAGE-VOLUME NOTE: because of that, the coordinator->strategic handoff
(``message_sent`` with ``to="strategic"``) is now emitted on every event
instead of only for events that already looked severe locally. This
deliberately and visibly raises the "overhead of coordination" metric. It is
the price of letting the one layer that sees across domains correlate early
signals that different domains observe separately (e.g. by_system_area);
message count is not minimized here on purpose.
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
    verdict_state,
)
from agents.mitigation import SimulatedMitigator
from instrumentation.metrics import MetricsLogger, append_evidence, emit_action_dispatched, emit_analysis
from knowledge.repository import KnowledgePolicyRepository

DEFAULT_ESCALATION_CONFIDENCE_THRESHOLD = 0.50


def _confidence_to_legacy_severity(confidence: float) -> int:
    """Maps a 0.0-1.0 confidence score onto the repository's 0-5 integer
    ``severity`` field -- see the identical helper (and its rationale) in
    ``agents/operational_specialist.py``."""
    return max(0, min(5, round(confidence * 5)))


class DomainCoordinatorAgent:
    """Aggregates specialist reports for one domain and arbitrates escalation."""

    def __init__(
        self,
        domain_cfg: dict[str, Any],
        repository: KnowledgePolicyRepository,
        metrics: MetricsLogger,
    ):
        self.domain_cfg = domain_cfg
        self.repository = repository
        self.metrics = metrics
        self.domain_name = domain_cfg["name"]
        coordinator_cfg = domain_cfg.get("coordinator", {})
        self.agent_id = coordinator_cfg.get("id", f"coordinator::{self.domain_name}")
        self.escalation_confidence_threshold = coordinator_cfg.get("escalation_policy", {}).get(
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

    # --- Monitor: ingest the specialist report, uninterpreted ---
    def monitor(self, state: dict[str, Any]) -> Observation:
        report = state["specialist_report"]
        incident_id = state["incident_id"]
        self.metrics.emit(
            event_type="report_received",
            incident_id=incident_id,
            layer="coordinator",
            agent_id=self.agent_id,
            payload={
                "from": report["specialist_id"],
                "confidence": report["confidence"],
                "escalate": report["escalate"],
            },
        )
        self.repository.mark_seen(incident_id, report["event"].get("event_id"), f"coordinator::{self.domain_name}")
        return Observation(incident_id=incident_id, source=report["specialist_id"], domain_name=self.domain_name, payload=report)

    # --- Analyze: classify() over this domain's accumulated history ---
    def analyze(self, observation: Observation) -> Analysis:
        return analyze_history(
            self.repository,
            layer="coordinator",
            incident_id=observation.incident_id,
            domain_name=self.domain_name,
            current_event=observation.payload["event"],
        )

    # --- Plan: escalate vs. domain-level containment (does nothing yet) ---
    def plan(self, analysis: Analysis, observation: Observation) -> ActionPlan:
        report = observation.payload
        threshold = self.repository.get_policy(
            f"escalation_threshold::{self.agent_id}", self.escalation_confidence_threshold
        )
        escalate_up = analysis.is_ransomware_activity or analysis.confidence >= threshold
        actions = ()
        record = False
        if escalate_up:
            decision = "escalate_to_strategic"
            if analysis.is_ransomware_activity and dispatch_on_flag(self.repository, "coordinator"):
                # Delegated authority (policy dispatch_on_flag::coordinator): contain
                # at domain level NOW within authority_phases, and still escalate.
                return ActionPlan(
                    decision=decision,
                    escalate=True,
                    rationale=f"threshold={threshold}; dispatch_on_flag",
                    actions=plan_mitigations(
                        self.repository,
                        layer="coordinator",
                        decision="local_containment",
                        analysis=analysis,
                        incident_id=observation.incident_id,
                        domain_name=self.domain_name,
                    ),
                    record_decision=True,
                    record_escalated=True,
                    extra={"dispatch": "local_containment"},
                )
        elif report["escalate"] and self.repository.get_policy("coordinator_precaution", "domain") != "none":
            # (Fase 1b: coordinator_precaution = "none" -> an UNFLAGGED escalation is not turned into
            # domain-level containment; the specialist already applied the precaution rule.)
            # Domain-level containment: the specialist escalated, the
            # domain-wide picture stays inside this coordinator's authority.
            decision = "local_containment"
            record = True
            actions = plan_mitigations(
                self.repository,
                layer="coordinator",
                decision=decision,
                analysis=analysis,
                incident_id=observation.incident_id,
                domain_name=self.domain_name,
            )
        else:
            # Specialist made a terminal decision (and already recorded and
            # executed it); the domain-wide picture does not change it.
            decision = report["action"]
        return ActionPlan(
            decision=decision,
            escalate=escalate_up,
            rationale=f"threshold={threshold}",
            actions=actions,
            record_decision=record,
            record_escalated=False,
        )

    # --- Execute: mitigate, record, forward to Strategic (unconditional) ---
    def execute(
        self, plan: ActionPlan, analysis: Analysis, observation: Observation, state: dict[str, Any]
    ) -> dict[str, Any]:
        report = observation.payload
        incident_id = observation.incident_id
        confidence = analysis.confidence
        mitre_technique_ids = list(analysis.mitre_technique_ids)

        effects = [
            self.mitigator.execute(a, incident_id=incident_id, layer="coordinator", agent_id=self.agent_id)
            for a in plan.actions
        ]

        evidence_chain = list(state.get("evidence_chain", []))
        append_evidence(
            evidence_chain,
            agent_id=self.agent_id,
            layer="coordinator",
            summary=(
                f"Aggregated {analysis.events_analyzed} event(s) for this incident in domain '{self.domain_name}' "
                f"(triggered by {report['specialist_id']}): confidence={confidence:.2f}, stage={analysis.stage}, "
                f"mitre={mitre_technique_ids or 'none'}, against domain authority "
                f"({plan.rationale}); decision={plan.decision}." + mitigation_suffix(effects)
            ),
            based_on=[report["specialist_id"]],
        )

        domain_report = {
            "coordinator_id": self.agent_id,
            "domain_name": self.domain_name,
            "decision": plan.decision,
            "escalate": plan.escalate,
            "confidence": confidence,
            "is_ransomware_activity": analysis.is_ransomware_activity,
            "mitre_technique_ids": mitre_technique_ids,
            "events_aggregated": analysis.events_analyzed,
        }

        node = f"coordinator::{self.domain_name}"
        emit_analysis(
            self.metrics, incident_id=incident_id, layer="coordinator", agent_id=self.agent_id, node=node,
            event=report["event"], is_ransomware_activity=analysis.is_ransomware_activity, stage=analysis.stage,
            confidence=confidence, method=analysis.method, scope=analysis.scope,
            events_analyzed=analysis.events_analyzed, latched=analysis.latched,
        )
        dispatched = plan.extra.get("dispatch") or ("local_containment" if plan.record_decision else None)
        if dispatched:
            emit_action_dispatched(
                self.metrics, incident_id=incident_id, layer="coordinator", agent_id=self.agent_id, node=node,
                event=report["event"], decision=dispatched, actions=[a.label() for a in plan.actions],
                on_flagged_verdict=analysis.is_ransomware_activity,
            )
        if plan.record_decision:
            self.repository.record_decision(
                incident_id=incident_id,
                layer="coordinator",
                agent_id=self.agent_id,
                decision=dispatched or plan.decision,
                severity=_confidence_to_legacy_severity(confidence),
                evidence_chain=evidence_chain,
                escalated=plan.record_escalated,
            )
        # else: nothing new to record here (specialist already did, or the
        # decision is a hand-up recorded by Strategic).
        if not plan.escalate:
            self.metrics.emit(
                event_type="alert_consolidated",
                incident_id=incident_id,
                layer="coordinator",
                agent_id=self.agent_id,
                payload={"decision": plan.decision},
            )

        # UNCONDITIONAL handoff to Strategic (see module docstring: raises
        # message volume on purpose).
        self.metrics.emit(
            event_type="message_sent",
            incident_id=incident_id,
            layer="coordinator",
            agent_id=self.agent_id,
            payload={"to": "strategic", "domain_report": domain_report},
        )

        return {
            "domain_report": domain_report,
            "coordinator_verdict": verdict_state(analysis),  # graph-state only, not in the message payload
            "evidence_chain": evidence_chain,
            "escalate_to_strategic": plan.escalate,
        }
