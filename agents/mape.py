"""Shared MAPE-K building blocks for the Specialist, Coordinator and Strategic agents.

Each agent implements the four named stages as methods, called in sequence
from ``__call__``:

  monitor(state)          -> Observation    ingest only; no interpretation
  analyze(obs)            -> Analysis       correlate against Knowledge history
  plan(analysis, obs)     -> ActionPlan     decide WHAT to do; does nothing
  execute(plan, ...)      -> state update   mitigate, record, message upward

Knowledge (``knowledge.repository.KnowledgePolicyRepository``) supplies both
the historical evidence (``events_for_incident``) and the policies analyze/
plan consult (``get_policy``): thresholds, analysis scope, layer authority
and the mitigation playbook. Agents seed defaults at construction
(``seed_policies``) without overwriting anything already present, and read
them at decision time, so a policy written to Knowledge takes effect.

Literature grounding
--------------------
* Kephart & Chess (2003), "The Vision of Autonomic Computing", IEEE
  Computer 36(1): the Monitor-Analyze-Plan-Execute loop over shared Knowledge.
* NIST incident-response lifecycle. ANALYZE corresponds to "detection and
  analysis": indicators are correlated OVER TIME from accumulated evidence
  (``analysis_scope`` policy), not judged from an isolated event -- except at
  the Specialist, whose single-event scope is a deliberate, documented
  limitation of specialization (policy ``analysis_scope::specialist="event"``).
  PLAN corresponds to "containment, eradication and recovery", kept as
  logically distinct phases inside ``ActionPlan`` (a layer only plans the
  phases its authority allows). NOTE: NIST SP 800-61r2 names these phases;
  SP 800-61r3 (2025) reorganizes incident response around CSF 2.0 functions
  and NISTIR 8374 uses the CSF Detect/Respond/Recover functions, so cite the
  phase names to r2 (or map them to Detect/Respond/Recover) in the paper.

Thresholds inside ``detection/`` (e.g. the >=2 distinct early-signal
corroboration rule) are deliberately NOT centralized here: that module is
shared unchanged with both baselines, and moving them would break the
validated comparability. Only the MAS-layer thresholds live in Knowledge.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from agents.mitigation import (  # noqa: F401  (PHASES / DEFAULT_* re-exported)
    DEFAULT_PLAYBOOK,
    DEFAULT_RECOVERY_MIN_STAGE,
    PHASES,
    PLAYBOOKS,
    PREVENT_AUTHORITY,
    playbook_version,
    MitigationAction,
    enabled_preventive,
    playbook_actions,
    SEGNET_SCOPE_KEY,
    preventive_targets,
    with_prevention,
)
from detection.methods import (  # noqa: F401  (re-exported)
    DEFAULT_DETECTION_METHOD,
    DEFAULT_ENTROPY_PARAMS,
    DEFAULT_KILLCHAIN_PARAMS,
    DEFAULT_KILLCHAIN_STAGE_MAP,
    DETECTION_METHOD_KEY,
    DETECTION_METHODS,
    STICKY_FLAG_KEY,
    MethodVerdict,
    apply_latch,
    assess_with_policies,
    run_method,
    sticky_enabled,
    validate_method,
)
from knowledge.repository import KnowledgePolicyRepository

# PHASES, DEFAULT_RECOVERY_MIN_STAGE and DEFAULT_PLAYBOOK live in agents/mitigation.py
# (shared with the baselines' effectors) and are re-exported from here.
GLOBAL_CONTAINMENT_THRESHOLD_KEY = "global_containment_confidence_threshold"
DEFAULT_ANALYSIS_SCOPE = {"specialist": "event", "coordinator": "domain", "strategic": "incident"}
DEFAULT_AUTHORITY_PHASES = {
    "specialist": ["containment"],
    "coordinator": ["containment", "eradication"],
    "strategic": ["containment", "eradication", "recovery"],
}


# --- Detection method (controlled factor; definitions live in detection/methods.py) ---
# Re-exported so existing imports keep working. Every layer resolves its method
# from Knowledge: domain-scoped layers (specialist, coordinator) read
# ``detection_method::<domain>``, seeded from the run-wide ``detection_method``
# policy; Strategic reads ``detection_method`` itself. Default: legacy_weighted.
DOMAIN_METHOD_LAYERS = ("specialist", "coordinator")
KILLCHAIN_LAYERS = DOMAIN_METHOD_LAYERS  # backwards-compatible alias
# Layers whose verdict is about the INCIDENT (accumulated history) and may be
# latched by policy ``sticky_incident_flag``. Specialists judge one event, so a
# per-incident latch does not apply to them.
LATCH_LAYERS = ("coordinator", "strategic")
# Delegated containment authority on a FLAGGED verdict (Phase 3). True = a flagged
# specialist/coordinator ALSO dispatches the containment it is authorized for
# (``authority_phases::<layer>``) immediately, then still escalates. Default True
# for both layers since Phase 8: the multi-agent arm is MAS-D. False = the original
# (Phase 1-7b "MAS") behaviour, kept only as an ablation arm (``NON_DELEGATED``).
DISPATCH_ON_FLAG_LAYERS = ("specialist", "coordinator")
DISPATCH_ON_FLAG_DEFAULT = True
DELEGATED = {f"dispatch_on_flag::{layer}": True for layer in DISPATCH_ON_FLAG_LAYERS}
NON_DELEGATED = {f"dispatch_on_flag::{layer}": False for layer in DISPATCH_ON_FLAG_LAYERS}


def dispatch_on_flag(repository: KnowledgePolicyRepository, layer: str) -> bool:
    value = repository.get_policy(f"dispatch_on_flag::{layer}", DISPATCH_ON_FLAG_DEFAULT)
    return value.strip().lower() in ("true", "1", "yes", "on") if isinstance(value, str) else bool(value)


def seed_policies(repository: KnowledgePolicyRepository, *, updated_by: str, extra: Optional[dict[str, Any]] = None) -> None:
    """Writes default policies into Knowledge unless a value already exists."""
    defaults: dict[str, Any] = {
        "recovery_min_stage": DEFAULT_RECOVERY_MIN_STAGE,
        # playbook_version (default 1) selects which playbook is seeded; v1 = DEFAULT_PLAYBOOK.
        "mitigation_playbook": PLAYBOOKS[playbook_version(repository.get_policy)],
        "killchain_stage_map": DEFAULT_KILLCHAIN_STAGE_MAP,
        "killchain_params": DEFAULT_KILLCHAIN_PARAMS,
        "entropy_params": DEFAULT_ENTROPY_PARAMS,
        DETECTION_METHOD_KEY: DEFAULT_DETECTION_METHOD,
        STICKY_FLAG_KEY: False,
        **{f"dispatch_on_flag::{layer}": DISPATCH_ON_FLAG_DEFAULT for layer in DISPATCH_ON_FLAG_LAYERS},
    }
    for layer in DEFAULT_ANALYSIS_SCOPE:
        defaults[f"analysis_scope::{layer}"] = DEFAULT_ANALYSIS_SCOPE[layer]
        defaults[f"authority_phases::{layer}"] = DEFAULT_AUTHORITY_PHASES[layer]
    defaults.update(extra or {})
    for key, value in defaults.items():
        if repository.get_policy(key) is None:
            repository.update_policy(key, value, updated_by=updated_by)


# --- Stage data types -------------------------------------------------------------
@dataclass(frozen=True)
class Observation:
    """Monitor output: what was ingested, uninterpreted."""

    incident_id: str
    source: str  # agent/element that produced the payload
    domain_name: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class Analysis:
    """Analyze output: structured verdict over the history in scope."""

    is_ransomware_activity: bool
    stage: str
    confidence: float
    mitre_technique_ids: tuple[str, ...]
    signal_count: int
    events_analyzed: int
    scope: str
    rationale: str
    hosts: tuple[str, ...] = ()
    method: str = DEFAULT_DETECTION_METHOD
    legacy_confidence: Optional[float] = None  # set only when another method overrode the legacy score
    domains: tuple[str, ...] = ()
    latched: bool = False  # flag held by the sticky-flag latch (policy sticky_incident_flag)


@dataclass(frozen=True)
class ActionPlan:
    """Plan output: what to do. Nothing has been done yet."""

    decision: Optional[str]  # existing vocabulary label; None = nothing to decide/record
    escalate: bool
    rationale: str
    actions: tuple[MitigationAction, ...] = ()
    record_decision: bool = False
    record_escalated: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    def phase(self, name: str) -> tuple[MitigationAction, ...]:
        return tuple(a for a in self.actions if a.phase == name)

    @property
    def containment(self) -> tuple[MitigationAction, ...]:
        return self.phase("containment")

    @property
    def eradication(self) -> tuple[MitigationAction, ...]:
        return self.phase("eradication")

    @property
    def recovery(self) -> tuple[MitigationAction, ...]:
        return self.phase("recovery")


# --- Shared analyze / plan helpers ----------------------------------------------
def analyze_events(
    repository: KnowledgePolicyRepository,
    raw_events: list[dict[str, Any]],
    *,
    method: str,
    scope: str,
    domains: tuple[str, ...],
) -> Analysis:
    """``detection.methods.assess`` over ``raw_events`` with parameters from Knowledge.

    The same entry point both baselines call; see ``detection/methods.py`` for
    what each method does and when it falls back to the legacy result. Public
    so methods can be compared side by side on the same event list.
    """
    v = assess_with_policies(raw_events, method, repository.get_policy)
    return _analysis(v, raw_events, scope=scope, domains=domains)


def _analysis(v: MethodVerdict, raw_events: list[dict[str, Any]], *, scope: str, domains: tuple[str, ...]) -> Analysis:
    return Analysis(
        is_ransomware_activity=v.is_ransomware_activity,
        stage=v.stage,
        confidence=v.confidence,
        mitre_technique_ids=v.technique_ids,
        signal_count=v.signal_count,
        events_analyzed=len(raw_events),
        scope=scope,
        rationale=v.rationale,
        hosts=tuple(dict.fromkeys(e.get("source", "unknown") for e in raw_events)),
        method=v.method,
        legacy_confidence=v.legacy_confidence,
        domains=domains,
        latched=v.latched,
    )


def analyze_history(
    repository: KnowledgePolicyRepository,
    *,
    layer: str,
    incident_id: str,
    domain_name: str,
    current_event: dict[str, Any],
) -> Analysis:
    """Analyze: classify() over the history selected by the layer's ``analysis_scope`` policy.

    Domain-scoped layers (specialist, coordinator) honour the per-domain policy
    ``detection_method::<domain_name>`` (seeded from the run-wide
    ``detection_method``); Strategic honours ``detection_method`` itself.
    """
    scope = repository.get_policy(f"analysis_scope::{layer}", DEFAULT_ANALYSIS_SCOPE[layer])
    # What this layer has actually RECEIVED (see KnowledgePolicyRepository.mark_seen).
    seen_by = {"coordinator": f"coordinator::{domain_name}", "strategic": "strategic"}.get(layer)
    if scope == "event":
        raw_events = [current_event]
    elif scope == "domain":
        raw_events = repository.events_for_incident(incident_id, domain_name=domain_name, seen_by=seen_by)
    else:
        raw_events = repository.events_for_incident(incident_id, seen_by=seen_by)
    if not raw_events:
        raw_events = [current_event]

    if layer in DOMAIN_METHOD_LAYERS:
        key = f"{DETECTION_METHOD_KEY}::{domain_name}"
        method = validate_method(repository.get_policy(key, run_method(repository.get_policy)), key=key)
    else:
        method = run_method(repository.get_policy)
    domains = tuple(repository.domains_for_incident(incident_id, seen_by=seen_by)) if scope == "incident" else (domain_name,)
    v = assess_with_policies(raw_events, method, repository.get_policy)
    if layer in LATCH_LAYERS and sticky_enabled(repository.get_policy):
        view = "strategic" if layer == "strategic" else f"{layer}::{domain_name}"
        v, held = apply_latch(v, repository.get_incident_latch(incident_id, view))
        repository.set_incident_latch(incident_id, view, held)
    return _analysis(v, raw_events, scope=scope, domains=domains)


def verdict_state(analysis: Analysis) -> dict[str, Any]:
    """Compact verdict for graph state (not written to any log)."""
    return {
        "method": analysis.method,
        "is_ransomware_activity": analysis.is_ransomware_activity,
        "stage": analysis.stage,
        "confidence": analysis.confidence,
        "mitre_technique_ids": list(analysis.mitre_technique_ids),
        "events_analyzed": analysis.events_analyzed,
        "latched": analysis.latched,
    }


def plan_mitigations(
    repository: KnowledgePolicyRepository,
    *,
    layer: str,
    decision: str,
    analysis: Analysis,
    incident_id: str,
    domain_name: str,
) -> tuple[MitigationAction, ...]:
    """Containment -> eradication -> recovery actions this layer may take for ``decision``.

    Filters: the decision must be one the action maps to; the phase must be in
    the layer's ``authority_phases`` policy; recovery additionally needs the
    analysis to have reached ``recovery_min_stage``.
    """
    playbook = repository.get_policy("mitigation_playbook", DEFAULT_PLAYBOOK)
    allowed = repository.get_policy(f"authority_phases::{layer}", DEFAULT_AUTHORITY_PHASES[layer])
    recovery_stage = repository.get_policy("recovery_min_stage", DEFAULT_RECOVERY_MIN_STAGE)
    # Phase 8 preventive actions (policy ``preventive_actions``, default OFF): the enabled rows join
    # the playbook and the layer's prevent_* phases join its authority (PREVENT_AUTHORITY).
    enabled = enabled_preventive(repository.get_policy)
    if enabled:
        playbook = with_prevention(playbook, enabled)
        allowed = list(allowed) + PREVENT_AUTHORITY[layer]

    segments = analysis.domains or (domain_name,)
    # The telemetry never identifies the OFFENDING process (e.g. a
    # service_stop_attempt's ``process_name`` is the VICTIM service the attacker
    # stopped -- killing it would kill the defense), so kill_process targets the
    # host with an explicitly unresolved process id.
    targets = {
        "isolate_host": analysis.hosts,
        "block_network_segment": segments,
        "kill_process": tuple(f"unresolved@{h}" for h in analysis.hosts),
        "trigger_backup_restore": (incident_id,),
        "lock_account": tuple(f"accounts@{h}" for h in analysis.hosts),
        # Fase 1b: segment-scoped segment_network covers the campaign known to Knowledge (links).
        **preventive_targets(analysis.hosts, repository.get_policy(SEGNET_SCOPE_KEY, "global"),
                            repository.campaign_hosts(analysis.hosts)),
    }

    return playbook_actions(
        playbook,
        phases=allowed,
        decision=decision,
        stage=analysis.stage,
        recovery_min_stage=recovery_stage,
        techniques=analysis.mitre_technique_ids,
        targets=targets,
    )


def mitigation_suffix(effects: list[dict[str, Any]]) -> str:
    if not effects:
        return ""
    body = ", ".join(f"{e['action']}({e['target']})[{e['d3fend_id']}]:{e['status']}" for e in effects)
    return f" mitigation=[{body}]"
