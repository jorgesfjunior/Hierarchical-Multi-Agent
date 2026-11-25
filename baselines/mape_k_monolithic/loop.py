"""Baseline 1: monolithic, single-loop MAPE-K controller.

Deliberately the SIMPLEST possible architecture in this research design: one
process, one class, no agents, no hierarchy, no message passing between
components, no domain decomposition. Every incident is handled by a single
sequential call through all four MAPE-K stages:

    Monitor  -> Analyze              -> Plan          -> Execute
    (ingest)    (detection.classify)    (map Verdict     (record decision +
                                          to an action)    log consolidation)

This module reuses, and does not fork or duplicate, the exact same building
blocks the multi-agent skeleton uses (or will use once it is wired to real
detection):

  - ``detection.methods.assess`` -- identical detection logic. The method
    (``legacy_weighted`` = plain ``classify()`` by default, or
    ``killchain_stage`` / ``entropy_based`` / ``legacy+entropy``) is read from
    the run-wide Knowledge policy ``detection_method`` -- the same flag the MAS
    honours at every layer -- with the same parameter policies
    (``killchain_stage_map``, ``killchain_params``, ``entropy_params``).
  - ``knowledge.repository.KnowledgePolicyRepository`` -- identical audit
    trail schema (``ts``/``incident_id``/``layer``/``agent_id``/``decision``/
    ``severity``/``escalated``/``evidence_chain``).
  - ``instrumentation.metrics.MetricsLogger`` / ``append_evidence`` --
    identical structured-event schema.

Only ``layer``/``agent_id`` differ (both fixed to a baseline-specific value
below) so logs from this baseline are distinguishable from the multi-agent
skeleton's logs without needing a different schema -- the point of this
whole exercise is that later cross-architecture analysis code does not need
to know which architecture produced a given log line.

See ``baselines/mape_k_monolithic/README.md`` for the full stage mapping and
an explicit list of the structural capabilities this baseline lacks by
design (that absence is itself the research counterfactual, not a bug).
"""
from __future__ import annotations

from typing import Any, Optional

from agents.campaign_links import ADVISORY_EVENT, CampaignLinker, advised_incident, advisory_actions, links_enabled
from agents.mitigation import PHASES, SEGNET_SCOPE_KEY, SimulatedMitigator, baseline_actions, damage_model_enabled, enabled_preventive, node_phases, resolve_playbook
from detection.methods import (
    DEFAULT_DETECTION_METHOD,
    MethodVerdict,
    apply_latch,
    assess_with_policies,
    run_method,
    sticky_enabled,
)
from detection.signals import Event, Verdict
from instrumentation.metrics import (
    CONTAINMENT_DECISIONS,
    MetricsLogger,
    append_evidence,
    emit_action_dispatched,
    emit_analysis,
)
from knowledge.repository import KnowledgePolicyRepository

# Shared single-signal precautionary rule (Phase 4: B2-SSL; Phase 4b: B1-SSL). Default OFF.
SINGLE_SIGNAL_KEY = "single_signal_containment"


def _flag(value: Any) -> bool:
    return value.strip().lower() in ("true", "1", "yes", "on") if isinstance(value, str) else bool(value)


# Single fixed identity for the whole loop -- there is exactly one
# "component" in this architecture, by design.
AGENT_ID = "baseline_mape_k_monolithic"
LAYER = "monolithic"


def plan_action(verdict: Verdict | MethodVerdict) -> str:
    """Plan stage: maps a detection Verdict to one action decision.

    Uses the SAME decision vocabulary value the multi-agent skeleton's
    ``agents/strategic_governance.py`` already uses for its high-severity
    case (``"global_containment_directive"``), so a comparison across
    architectures is value-for-value, not just schema-for-schema:

      - no positive verdict                 -> "no_action"
      - flagged, stage == "early" (pre-encryption, proactive)
                                             -> "local_containment"
      - flagged, stage == "late" (encryption in progress, reactive)
                                             -> "global_containment_directive"
    """
    if not verdict.is_ransomware_activity:
        return "no_action"
    if verdict.stage == "late":
        return "global_containment_directive"
    return "local_containment"


def _confidence_to_legacy_severity(confidence: float) -> int:
    """Maps Verdict.confidence (0.0-1.0) onto the repository's 0-5 integer
    ``severity`` field.

    This exists ONLY for schema compatibility with
    ``KnowledgePolicyRepository.record_decision`` (which the multi-agent
    skeleton's agents also call with an integer severity derived from the
    synthetic mock event's ``severity`` field, itself just a random 1-5
    placeholder today). Once real detection is wired into the MAS too, both
    architectures will derive this the same way; until then, treat this
    field as a schema-compatibility artifact, not an independently
    meaningful measurement -- see README "Known limitations".
    """
    return max(0, min(5, round(confidence * 5)))


class MAPEKLoop:
    """The entire control loop for one incident: Monitor -> Analyze -> Plan -> Execute.

    No distributed state: everything below is local variables and two
    shared, already-existing collaborators (``repository``, ``metrics``)
    that the multi-agent skeleton also writes to -- there is no
    inter-component message passing internal to this class.
    """

    def __init__(self, repository: KnowledgePolicyRepository, metrics: MetricsLogger, phases: Optional[tuple[str, ...]] = None):
        """``phases`` (Fase 1, B2-SSL-local): the action phases a detection-backed dispatch may use.
        None (default) = every phase (``node_phases``), unchanged."""
        self.repository = repository
        self.metrics = metrics
        self.phases = phases
        # Fase 1b (policy campaign_links, default OFF): node-local campaign links / advisories.
        # ``advisory_scope(host)`` limits which advised hosts this node may act on (None = any:
        # B1 sees every host; a B2-SSL-local instance only its own segment).
        self.linker = None
        self.advisory_scope = None
        # Sticky-flag latch (policy ``sticky_incident_flag``, default off): last
        # flagged verdict per incident, private to this loop instance.
        self._latch: dict[str, MethodVerdict] = {}
        # Effectors, used only with policy ``damage_model`` ON (see agents/mitigation.py).
        self.mitigator = SimulatedMitigator(metrics)

    def run_incident(self, incident_id: str, events_raw: list[dict[str, Any]]) -> dict[str, Any]:
        """Runs one full MAPE-K cycle over the given incident's raw event window.

        ``events_raw`` is the complete set of telemetry events belonging to
        one incident (e.g. a full realistic attack sequence, or a batch of
        independent benign events being checked for false positives) --
        this baseline analyzes the whole window in one shot per call, it
        does not incrementally re-analyze on every new tick (a documented
        simplification vs. a continuously-running production MAPE-K loop;
        see README).
        """
        # --- Monitor: ingest the event stream for this incident ---
        events = [Event.from_raw(raw) for raw in events_raw]
        if not events:
            raise ValueError("MAPEKLoop.run_incident requires at least one event.")
        first_event = min(events, key=lambda e: e.timestamp)

        self.metrics.emit(
            event_type="signal_received",
            incident_id=incident_id,
            layer=LAYER,
            agent_id=AGENT_ID,
            payload={
                "event_count": len(events),
                "first_event_type": first_event.type,
                "first_event_source": first_event.source,
            },
        )

        # --- Analyze: the exact same detection logic (and method flag) the MAS uses ---
        get_policy = getattr(self.repository, "get_policy", lambda key, default=None: default)
        verdict = assess_with_policies(events_raw, run_method(get_policy), get_policy)
        if sticky_enabled(get_policy):
            verdict, held = apply_latch(verdict, self._latch.get(incident_id))
            if held is not None:
                self._latch[incident_id] = held

        # --- Plan: map the verdict to one action decision ---
        decision = plan_action(verdict)
        severity = _confidence_to_legacy_severity(verdict.confidence)

        # --- Execute: record the decision and close out instrumentation ---
        # Evidence chain provenance is flat (based_on always empty): there is
        # no agent-to-agent handoff in a monolithic loop for evidence to be
        # attributed to -- every signal was produced by the same single
        # Analyze call. This is intentional, not a missing feature; contrast
        # with the MAS's chained evidence (specialist -> coordinator ->
        # strategic), which reflects real hand-offs between components.
        evidence_chain: list[dict[str, Any]] = []
        for signal in verdict.signals:
            append_evidence(
                evidence_chain,
                agent_id=AGENT_ID,
                layer=LAYER,
                summary=f"[{signal.mitre_technique_id} {signal.mitre_technique_name}] {signal.summary}",
                based_on=(),
            )
        if not evidence_chain:
            append_evidence(evidence_chain, agent_id=AGENT_ID, layer=LAYER, summary=verdict.rationale, based_on=())
        elif verdict.method != DEFAULT_DETECTION_METHOD or verdict.latched:
            # A non-legacy method overrode the score: record why (absent under legacy, so
            # default-behaviour decisions are unchanged).
            append_evidence(evidence_chain, agent_id=AGENT_ID, layer=LAYER, summary=verdict.rationale, based_on=())

        self.repository.record_decision(
            incident_id=incident_id,
            layer=LAYER,
            agent_id=AGENT_ID,
            decision=decision,
            severity=severity,
            evidence_chain=evidence_chain,
            escalated=(decision == "global_containment_directive"),
        )

        # Phase 3 instrumentation: the one analysis this loop performed, and the
        # containment it dispatched (every B1 action goes through this central node).
        trigger = events_raw[-1]
        emit_analysis(
            self.metrics, incident_id=incident_id, layer=LAYER, agent_id=AGENT_ID, node="central", event=trigger,
            is_ransomware_activity=verdict.is_ransomware_activity, stage=verdict.stage,
            confidence=verdict.confidence, method=verdict.method, scope="incident",
            events_analyzed=len(events_raw), latched=verdict.latched,
        )
        if decision in CONTAINMENT_DECISIONS:
            actions = ()
            if damage_model_enabled(get_policy):
                # Same playbook as the MAS, every phase in authority (one loop, no layers).
                actions = baseline_actions(
                    decision=decision, stage=verdict.stage, techniques=verdict.technique_ids,
                    hosts=dict.fromkeys(e.get("source", "unknown") for e in events_raw), incident_id=incident_id,
                    phases=node_phases(get_policy, PHASES) if self.phases is None else self.phases,
                    playbook=resolve_playbook(get_policy),
                    segnet_scope=get_policy(SEGNET_SCOPE_KEY, "global"),
                    segnet_hosts=self._campaign_of(e.get("source", "unknown") for e in events_raw),
                )
                for a in actions:
                    self.mitigator.execute(a, incident_id=incident_id, layer=LAYER, agent_id=AGENT_ID)
            emit_action_dispatched(
                self.metrics, incident_id=incident_id, layer=LAYER, agent_id=AGENT_ID, node="central", event=trigger,
                decision=decision, actions=[a.label() for a in actions], on_flagged_verdict=verdict.is_ransomware_activity,
            )

        # NOTE on coordination overhead: no "message_sent" event is emitted
        # anywhere in this class, deliberately. A monolithic loop has no
        # inter-component messages to log -- coordination overhead for this
        # baseline's incidents is zero by construction, not an omission. See
        # README "What this baseline lacks by design".
        self.metrics.emit(
            event_type="alert_consolidated",
            incident_id=incident_id,
            layer=LAYER,
            agent_id=AGENT_ID,
            payload={"decision": decision, "confidence": verdict.confidence, "stage": verdict.stage},
        )

        if decision not in CONTAINMENT_DECISIONS and _flag(get_policy(SINGLE_SIGNAL_KEY, False)):
            self.single_signal(incident_id, events_raw[-1], get_policy)
        if links_enabled(get_policy):
            self.campaign_advisories(incident_id, events_raw[-1], verdict.signal_count >= 1, get_policy)

        return {"incident_id": incident_id, "verdict": verdict, "decision": decision, "severity": severity}

    def _campaign_of(self, hosts) -> tuple:
        hosts = tuple(dict.fromkeys(hosts))
        if self.linker is None:
            return hosts
        return tuple(dict.fromkeys(hosts + tuple(b for (a, b) in sorted(self.linker._linked) if a in hosts)
                                    + tuple(a for (a, b) in sorted(self.linker._linked) if b in hosts)))

    def campaign_advisories(self, incident_id: str, raw_event: dict[str, Any], has_signal: bool, get_policy) -> None:
        """Fase 1b: the precaution rule applied to every host newly linked to this incident's host
        (``agents/campaign_links.py``), dispatched by this node on the triggering event."""
        if self.linker is None:
            self.linker = CampaignLinker()
        for a, b in self.linker.observe(raw_event, has_signal):
            if self.advisory_scope is not None and not self.advisory_scope(b):
                continue  # an isolated instance cannot act outside its segment
            target = advised_incident(incident_id, b)
            actions = advisory_actions(b, get_policy) if damage_model_enabled(get_policy) else ()
            for act in actions:
                self.mitigator.execute(act, incident_id=target, layer=LAYER, agent_id=AGENT_ID)
            self.metrics.emit(event_type=ADVISORY_EVENT, incident_id=target, layer=LAYER, agent_id=AGENT_ID,
                              payload={"node": "central", "from_host": a, "to_host": b,
                                       "event_id": raw_event.get("event_id")})
            emit_action_dispatched(self.metrics, incident_id=target, layer=LAYER, agent_id=AGENT_ID, node="central",
                                   event=raw_event, decision="local_containment", actions=[x.label() for x in actions],
                                   on_flagged_verdict=False)

    def single_signal(self, incident_id: str, raw_event: dict[str, Any], get_policy) -> None:
        """Shared single-signal precautionary rule (policy ``single_signal_containment``).

        When the event just received yields >= 1 detection signal ON ITS OWN (same
        detection method as the run) and this loop did not dispatch containment for
        it: dispatch the playbook's containment-phase actions on that event's host,
        logged with ``on_flagged_verdict=False``. Used unchanged by B1-SSL (this loop)
        and B2-SSL (each B2 instance is this loop). With preventive actions ON (Phase 8) the rule
        also applies the host-scope ``prevent_host`` actions, like the MAS specialist precaution."""
        v = assess_with_policies([raw_event], run_method(get_policy), get_policy)
        if v.signal_count < 1:
            return
        decision = "local_containment"
        actions = baseline_actions(decision=decision, stage=v.stage, techniques=v.technique_ids,
                                   hosts=(raw_event.get("source", "unknown"),), incident_id=incident_id,
                                   phases=("containment",) + (("prevent_host",) if enabled_preventive(get_policy) else ()),
                                   playbook=resolve_playbook(get_policy))
        for a in actions:
            self.mitigator.execute(a, incident_id=incident_id, layer=LAYER, agent_id=AGENT_ID)
        chain: list[dict[str, Any]] = []
        append_evidence(chain, agent_id=AGENT_ID, layer=LAYER,
                        summary=f"single-signal local policy: {v.signal_count} signal(s) {list(v.technique_ids)} "
                                f"on '{raw_event.get('type')}'; actions={[a.label() for a in actions]}")
        self.repository.record_decision(incident_id=incident_id, layer=LAYER, agent_id=AGENT_ID, decision=decision,
                                        severity=_confidence_to_legacy_severity(v.confidence),
                                        evidence_chain=chain, escalated=False)
        emit_action_dispatched(self.metrics, incident_id=incident_id, layer=LAYER, agent_id=AGENT_ID, node="central",
                               event=raw_event, decision=decision, actions=[a.label() for a in actions],
                               on_flagged_verdict=False)
