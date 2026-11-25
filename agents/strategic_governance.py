"""Strategic Governance Agent (single top-layer agent).

Defines/revises global goals and policies, arbitrates cross-domain
conflicts, and is the layer explicitly responsible for guaranteeing that
every released decision is auditable. It is the primary reader/writer of
the Global Knowledge & Policy Repository.

There is exactly one instance of this agent regardless of how many domains
the intermediate layer is partitioned into.

The old fixed ``GLOBAL_CONTAINMENT_SEVERITY_THRESHOLD = 5`` (operating on a
random 1-5 event-severity placeholder) has been replaced by
``GLOBAL_CONTAINMENT_CONFIDENCE_THRESHOLD`` compared against the real
detection confidence propagated up from
``agents/operational_specialist.py`` via ``agents/domain_coordinator.py``.

Decision vocabulary is deliberately aligned with
``baselines/mape_k_monolithic/loop.py:plan_action`` where the two
architectures describe the same real-world action:
``"global_containment_directive"`` is the exact same string both
architectures use for "encryption confirmed / act globally", so
decisions.jsonl stays value-comparable, not just schema-comparable.
``"cross_domain_policy_update"`` has no equivalent in the monolithic
baseline -- it only exists here because this layer's reason for existing
is arbitrating an escalation that already crossed a domain boundary, a
distinction a single-loop baseline has no structural need for.

MAPE-K structure (see ``agents/mape.py``): ``monitor`` ingests the domain
report, ``analyze`` runs classify() over the incident-wide history (policy
``analysis_scope::strategic``), ``plan`` picks the decision (threshold from
Knowledge policy ``global_containment_confidence_threshold``, seeded from
``GLOBAL_CONTAINMENT_CONFIDENCE_THRESHOLD``) and lays out containment,
eradication and recovery actions as distinct phases, ``execute`` performs the
simulated mitigation, records the decision and updates policy.

Incident-wide aggregation (proactive escalation)
------------------------------------------------
This agent is now invoked on EVERY event (the coordinator->strategic edge
is unconditional). On each invocation it runs ``classify()`` over the FULL
incident-wide accumulated event history across ALL domains
(``repository.events_for_incident(incident_id)``), not just the triggering
domain_report. That is the only place early signals observed by DIFFERENT
domains (e.g. recon on the network domain + backup tampering on the backup
domain under by_system_area) can be correlated, so it can issue a
``global_containment_directive`` from early-stage evidence alone, before any
T1486 encryption event exists.

Decision rule per invocation:
  - aggregated verdict flagged as ransomware AND confidence >=
    GLOBAL_CONTAINMENT_CONFIDENCE_THRESHOLD -> "global_containment_directive"
  - else, if the triggering coordinator itself escalated ->
    "cross_domain_policy_update" (as before: arbitrating an escalation)
  - else -> NO decision is recorded; the event was only forwarded for
    visibility. (Recording a decision for every forwarded event would flag
    benign noise as escalated.)

Detection method: the incident-wide analysis honours the run-wide Knowledge
policy ``detection_method`` (default ``legacy_weighted``), the same flag that
seeds the domain layers and that both baselines read -- so under
``killchain_stage`` this layer scores stage progression over the incident-wide
history, and under ``entropy_based`` / ``legacy+entropy`` it runs temporal
entropy onset over every per-file write sample any domain recorded. Per-domain
overrides (``detection_method::<domain>``) do NOT affect this layer.

Known consequence: once an incident is above threshold, each later event of
that incident produces another directive (no de-duplication yet).

MESSAGE-VOLUME NOTE: invoking this agent on every event is an intentional,
measurable increase in inter-layer traffic ("overhead of coordination").
"""
from __future__ import annotations

from typing import Any

from agents.mape import (
    GLOBAL_CONTAINMENT_THRESHOLD_KEY,
    ActionPlan,
    Analysis,
    Observation,
    analyze_history,
    mitigation_suffix,
    plan_mitigations,
    seed_policies,
    verdict_state,
)
from agents.mitigation import SimulatedMitigator
from instrumentation.metrics import MetricsLogger, append_evidence, emit_action_dispatched, emit_analysis
from knowledge.repository import KnowledgePolicyRepository

# Documented heuristic (not empirically calibrated -- see
# detection/README.md "Known limitations", which this inherits): chosen so
# that all three T1486 late-signal event types recognized by
# detection/late_signals.py individually cross it when evaluated by a
# single specialist observing one event, for the concrete values used in
# simulation.mock_managed_system.generate_attack_sequence (the lowest of
# the three, mass file modification, computes to ~0.59 confidence there).
GLOBAL_CONTAINMENT_CONFIDENCE_THRESHOLD = 0.5


class StrategicGovernanceAgent:
    """Top-of-hierarchy governance, conflict arbitration, and audit guarantor."""

    def __init__(
        self,
        domain_config: dict[str, Any],
        repository: KnowledgePolicyRepository,
        metrics: MetricsLogger,
        agent_id: str = "strategic-governance",
    ):
        self.domain_config = domain_config
        self.repository = repository
        self.metrics = metrics
        self.agent_id = agent_id
        self.mitigator = SimulatedMitigator(metrics)
        seed_policies(
            repository,
            updated_by="config",
            extra={GLOBAL_CONTAINMENT_THRESHOLD_KEY: GLOBAL_CONTAINMENT_CONFIDENCE_THRESHOLD},
        )

    def __call__(self, state: dict[str, Any]) -> dict[str, Any]:
        observation = self.monitor(state)
        analysis = self.analyze(observation, state)
        plan = self.plan(analysis, observation)
        return self.execute(plan, analysis, observation, state)

    # --- Monitor: ingest the domain report, uninterpreted ---
    def monitor(self, state: dict[str, Any]) -> Observation:
        domain_report = state["domain_report"]
        incident_id = state["incident_id"]
        self.metrics.emit(
            event_type="escalation_received",
            incident_id=incident_id,
            layer="strategic",
            agent_id=self.agent_id,
            payload={
                "from": domain_report["coordinator_id"],
                "domain": domain_report["domain_name"],
                "confidence": domain_report["confidence"],
                "mitre_technique_ids": domain_report["mitre_technique_ids"],
            },
        )
        self.repository.mark_seen(incident_id, state["specialist_report"]["event"].get("event_id"), "strategic")
        return Observation(
            incident_id=incident_id,
            source=domain_report["coordinator_id"],
            domain_name=domain_report["domain_name"],
            payload=domain_report,
        )

    # --- Analyze: classify() over the incident-wide, all-domain history ---
    def analyze(self, observation: Observation, state: dict[str, Any]) -> Analysis:
        return analyze_history(
            self.repository,
            layer="strategic",
            incident_id=observation.incident_id,
            domain_name=observation.domain_name,
            current_event=state["specialist_report"]["event"],
        )

    # --- Plan: pick the decision and phase the mitigations (does nothing yet) ---
    def plan(self, analysis: Analysis, observation: Observation) -> ActionPlan:
        threshold = self.repository.get_policy(GLOBAL_CONTAINMENT_THRESHOLD_KEY, GLOBAL_CONTAINMENT_CONFIDENCE_THRESHOLD)
        if analysis.is_ransomware_activity and analysis.confidence >= threshold:
            decision = "global_containment_directive"
            actions = plan_mitigations(
                self.repository,
                layer="strategic",
                decision=decision,
                analysis=analysis,
                incident_id=observation.incident_id,
                domain_name=observation.domain_name,
            )
        elif observation.payload["escalate"]:
            decision, actions = "cross_domain_policy_update", ()
        else:
            # Visibility only; nothing to decide or record.
            return ActionPlan(decision=None, escalate=False, rationale=f"threshold={threshold}")
        return ActionPlan(
            decision=decision,
            escalate=True,
            rationale=f"threshold={threshold}",
            actions=actions,
            record_decision=True,
            record_escalated=True,
        )

    # --- Execute: mitigate, record, update policy ---
    def execute(
        self, plan: ActionPlan, analysis: Analysis, observation: Observation, state: dict[str, Any]
    ) -> dict[str, Any]:
        # Graph-state only (never logged): lets analysis read the verdict this
        # layer acted on without replaying classify().
        verdict = verdict_state(analysis)
        event = state["specialist_report"]["event"]
        emit_analysis(
            self.metrics, incident_id=observation.incident_id, layer="strategic", agent_id=self.agent_id,
            node="strategic", event=event, is_ransomware_activity=analysis.is_ransomware_activity,
            stage=analysis.stage, confidence=analysis.confidence, method=analysis.method, scope=analysis.scope,
            events_analyzed=analysis.events_analyzed, latched=analysis.latched,
        )
        if plan.decision is None:
            return {"strategic_verdict": verdict}
        incident_id = observation.incident_id
        domain_report = observation.payload
        confidence = analysis.confidence
        mitre_technique_ids = list(analysis.mitre_technique_ids)

        effects = [
            self.mitigator.execute(a, incident_id=incident_id, layer="strategic", agent_id=self.agent_id)
            for a in plan.actions
        ]
        if plan.decision == "global_containment_directive":
            emit_action_dispatched(
                self.metrics, incident_id=incident_id, layer="strategic", agent_id=self.agent_id, node="strategic",
                event=event, decision=plan.decision, actions=[a.label() for a in plan.actions],
                on_flagged_verdict=analysis.is_ransomware_activity,
            )

        evidence_chain = list(state.get("evidence_chain", []))
        append_evidence(
            evidence_chain,
            agent_id=self.agent_id,
            layer="strategic",
            summary=(
                f"Aggregated {analysis.events_analyzed} incident-wide event(s) across domains {list(analysis.domains)} "
                f"(triggered by domain '{domain_report['domain_name']}'): confidence={confidence:.2f}, "
                f"stage={analysis.stage}, mitre={mitre_technique_ids or 'none'}; decision={plan.decision}. "
                f"{analysis.rationale}" + mitigation_suffix(effects)
            ),
            based_on=[domain_report["coordinator_id"]],
        )

        self.repository.record_decision(
            incident_id=incident_id,
            layer="strategic",
            agent_id=self.agent_id,
            decision=plan.decision,
            severity=max(0, min(5, round(confidence * 5))),
            evidence_chain=evidence_chain,
            escalated=plan.record_escalated,
        )
        self.repository.update_policy(
            f"last_directive::{domain_report['domain_name']}", plan.decision, updated_by=self.agent_id
        )

        self.metrics.emit(
            event_type="alert_consolidated",
            incident_id=incident_id,
            layer="strategic",
            agent_id=self.agent_id,
            payload={"decision": plan.decision, "confidence": confidence},
        )

        return {
            "strategic_decision": {"agent_id": self.agent_id, "decision": plan.decision, "confidence": confidence},
            "strategic_verdict": verdict,
            "evidence_chain": evidence_chain,
        }
