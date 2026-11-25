"""Selectable detection METHOD: one pure entry point shared by all three architectures.

The detection method is a CONTROLLED FACTOR of the experiment: the MAS
(every layer), Baseline 1 and Baseline 2 all call :func:`assess` (via
:func:`assess_with_policies`) with the same method name and the same
parameters, so a difference between architectures on the same visible
evidence cannot come from the classifier. Nothing here imports LangGraph,
``agents.*`` or ``baselines.*``; parameters are passed in (callers read them
from Knowledge policies via a ``get_policy(key, default)`` callable).

Methods
-------
``legacy_weighted`` (default)
    ``classifier.classify()`` unchanged.
``killchain_stage``
    For non-late verdicts with at least one stage-mapped signal, confidence and
    flag come from ``detection.killchain.killchain_stage_confidence``; late
    verdicts and unmapped evidence keep the legacy result.
``entropy_based``
    A legacy verdict that is already FLAGGED (late-stage T1486 evidence, or a
    corroborated early verdict) passes through unchanged -- the entropy method
    can never remove a flag. Where legacy is silent (not flagged) and the
    events contain ``file_write`` content samples, confidence and flag come
    from ``detection.entropy.entropy_onset_confidence`` (stage ``"early"`` if
    flagged, else ``"none"``), so entropy may only ADD an early-stage flag.
    Without write samples, legacy is kept. (Phase 1 replaced even a flagged
    legacy verdict, which un-flagged the single-sample attack at its first
    encrypted write.)
``legacy+entropy``
    Flag if EITHER legacy or entropy onset fires. Legacy wins when it fires
    (its stage/rationale are kept; confidence is the max of the two when both
    fire). If only entropy fires, the entropy result is used exactly as under
    ``entropy_based``. If neither fires, the legacy verdict is returned
    unchanged (the non-flagging entropy score is NOT used, so this method can
    never escalate by confidence alone where legacy would not).

``MethodVerdict.method`` names the method that actually produced the result
(``legacy_weighted`` when another method fell back), as ``Analysis.method``
always has in ``agents/mape.py``.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable, Optional

from detection.classifier import classify
from detection.entropy import EntropyParams, entropy_onset_confidence
from detection.killchain import KillChainParams, killchain_stage_confidence
from detection.signals import Event, Signal, Verdict

DETECTION_METHOD_KEY = "detection_method"  # Knowledge policy: the run-wide method
DETECTION_METHODS = ("legacy_weighted", "killchain_stage", "entropy_based", "legacy+entropy")
DEFAULT_DETECTION_METHOD = "legacy_weighted"

DEFAULT_KILLCHAIN_STAGE_MAP: dict[str, Any] = {
    "provenance": (
        "Project design, NOT taken from NISTIR 8374 (nor 8374r1): neither publication defines an attack-stage "
        "taxonomy (they are CSF profiles). Technique->stage assignments follow MITRE ATT&CK tactics as published "
        "in attack-stix-data, except that T1489/T1490 (ATT&CK tactic: Impact) are grouped with 'inhibit recovery' "
        "as a deliberate project choice. The stage ORDER is a heuristic ordering, not an ATT&CK-defined sequence."
    ),
    "stage_order": [
        "initial_access",
        "discovery",
        "privilege_escalation",
        "defense_evasion_inhibit_recovery",
        "impact",
    ],
    "technique_stage": {
        "T1018": "discovery",  # ATT&CK: discovery
        "T1135": "discovery",  # ATT&CK: discovery
        "T1083": "discovery",  # ATT&CK: discovery
        "T1068": "privilege_escalation",  # ATT&CK: privilege-escalation
        "T1078": "privilege_escalation",  # ATT&CK: also initial-access/persistence/stealth; detector emits it for privesc events
        "T1489": "defense_evasion_inhibit_recovery",  # ATT&CK: impact
        "T1490": "defense_evasion_inhibit_recovery",  # ATT&CK: impact
        "T1486": "impact",  # ATT&CK: impact
    },
}
DEFAULT_KILLCHAIN_PARAMS = {
    "max_gap_seconds": 300.0,
    "single_weight": 0.5,
    "step": 0.2,
    "order_penalty": 0.1,
    "gap_penalty": 0.05,
    "cap": 0.9,
    "flag_threshold": 0.5,
}
DEFAULT_ENTROPY_PARAMS = {
    "entropy_threshold_bits": 7.5,
    "window_seconds": 10.0,
    "baseline_seconds": 60.0,
    "min_writes_in_window": 8,
    "proportion_threshold": 0.5,
    "min_rise": 0.3,
    "cap": 0.95,
}


def validate_method(method: str, *, key: str = DETECTION_METHOD_KEY) -> str:
    if method not in DETECTION_METHODS:
        raise ValueError(f"{key}={method!r}; expected one of {DETECTION_METHODS}")
    return method


@dataclass(frozen=True)
class MethodVerdict:
    """Verdict-compatible result (same attribute names as ``signals.Verdict``)."""

    is_ransomware_activity: bool
    confidence: float
    stage: str
    signals: tuple[Signal, ...]  # the legacy detectors' signals (evidence), whatever the method
    rationale: str
    technique_ids: tuple[str, ...]
    signal_count: int
    method: str  # method that produced this result (legacy_weighted on fallback)
    requested_method: str
    legacy_confidence: Optional[float]  # set only when another method overrode the legacy score
    latched: bool = False  # True -> flag held by the sticky-flag latch, not by the current evidence

    def mitre_technique_ids(self) -> tuple[str, ...]:
        return self.technique_ids


def _entropy(raw_events: list[dict[str, Any]], params: EntropyParams):
    writes = [
        (Event.from_raw(e).timestamp, e["payload"]["content_sample"])
        for e in raw_events
        if e.get("type") == "file_write" and e.get("payload", {}).get("content_sample")
    ]
    return entropy_onset_confidence(writes, params)


def assess(
    raw_events: list[dict[str, Any]],
    method: str = DEFAULT_DETECTION_METHOD,
    *,
    killchain_stage_map: Optional[dict[str, Any]] = None,
    killchain_params: Optional[dict[str, Any]] = None,
    entropy_params: Optional[dict[str, Any]] = None,
    detector_params: Optional[dict[str, Any]] = None,
) -> MethodVerdict:
    """Applies ``method`` to ``raw_events`` (see module docstring). ``detector_params`` (Fase 1;
    None = the detector constants) overrides detector thresholds for these events."""
    validate_method(method)
    verdict: Verdict = classify([Event.from_raw(e) for e in raw_events], detector_params)
    flagged, confidence, stage, rationale = (
        verdict.is_ransomware_activity, verdict.confidence, verdict.stage, verdict.rationale,
    )
    technique_ids = tuple(verdict.mitre_technique_ids())
    signal_count = len(verdict.signals)
    used, legacy_confidence = DEFAULT_DETECTION_METHOD, None

    if method == "killchain_stage" and verdict.stage != "late":
        stage_map = killchain_stage_map or DEFAULT_KILLCHAIN_STAGE_MAP
        result = killchain_stage_confidence(
            verdict.signals,
            stage_map["stage_order"],
            stage_map["technique_stage"],
            KillChainParams.from_mapping(killchain_params or DEFAULT_KILLCHAIN_PARAMS),
        )
        if result.mapped:
            used, legacy_confidence = method, verdict.confidence
            confidence, flagged, rationale = result.confidence, result.flagged, f"[killchain_stage] {result.explanation}"

    if method in ("entropy_based", "legacy+entropy"):
        result = _entropy(raw_events, EntropyParams.from_mapping(entropy_params or DEFAULT_ENTROPY_PARAMS))
        silent = not verdict.is_ransomware_activity
        take_entropy = result.assessed and silent and (method == "entropy_based" or result.flagged)
        if take_entropy:
            used, legacy_confidence = method, verdict.confidence
            confidence, flagged, rationale = result.confidence, result.flagged, f"[{method}] {result.explanation}"
            stage = "early" if result.flagged else "none"  # onset = early warning, not "encryption complete"
            if result.flagged and "T1486" not in technique_ids:
                technique_ids += ("T1486",)  # what the entropy method asserts
            signal_count = max(signal_count, 1 if result.flagged else 0)
        elif method == "legacy+entropy" and result.flagged:  # both fired: keep legacy, max confidence
            used, legacy_confidence = method, verdict.confidence
            confidence = max(confidence, result.confidence)
            rationale = f"[legacy+entropy] legacy: {verdict.rationale} | entropy: {result.explanation}"

    return MethodVerdict(
        is_ransomware_activity=flagged,
        confidence=confidence,
        stage=stage,
        signals=verdict.signals,
        rationale=rationale,
        technique_ids=technique_ids,
        signal_count=signal_count,
        method=used,
        requested_method=method,
        legacy_confidence=legacy_confidence,
    )


# Fase 1 (default OFF): per-profile detector thresholds. Both policies must be set: ``host_profiles``
# ({host: profile}) and ``detector_thresholds_by_profile`` ({profile: {param: value}}). The profile of
# the events' source host (an incident is one host) selects the row; without both, nothing changes.
HOST_PROFILES_KEY = "host_profiles"
DETECTOR_THRESHOLDS_KEY = "detector_thresholds_by_profile"


def profile_params(raw_events: list[dict[str, Any]], get_policy: Callable[[str, Any], Any]) -> Optional[dict[str, Any]]:
    table = get_policy(DETECTOR_THRESHOLDS_KEY, None)
    profiles = get_policy(HOST_PROFILES_KEY, None)
    if not table or not profiles or not raw_events:
        return None
    profile = profiles.get(raw_events[-1].get("source"))
    return None if profile is None else table.get(profile)


def assess_with_policies(
    raw_events: list[dict[str, Any]], method: str, get_policy: Callable[[str, Any], Any]
) -> MethodVerdict:
    """:func:`assess` with parameters read from Knowledge through ``get_policy(key, default)``."""
    return assess(
        raw_events,
        method,
        killchain_stage_map=get_policy("killchain_stage_map", DEFAULT_KILLCHAIN_STAGE_MAP),
        killchain_params=get_policy("killchain_params", DEFAULT_KILLCHAIN_PARAMS),
        entropy_params=get_policy("entropy_params", DEFAULT_ENTROPY_PARAMS),
        detector_params=profile_params(raw_events, get_policy),
    )


def run_method(get_policy: Callable[[str, Any], Any]) -> str:
    """The run-wide method from Knowledge (``detection_method``), validated."""
    return validate_method(get_policy(DETECTION_METHOD_KEY, DEFAULT_DETECTION_METHOD))


# --- Optional per-incident latch (sticky flag) ----------------------------------
STICKY_FLAG_KEY = "sticky_incident_flag"  # Knowledge policy; default OFF


def sticky_enabled(get_policy: Callable[[str, Any], Any]) -> bool:
    """Reads the latch policy; accepts a bool or a CLI string ("true"/"1"/"yes"/"on")."""
    value = get_policy(STICKY_FLAG_KEY, False)
    if isinstance(value, str):
        return value.strip().lower() in ("true", "1", "yes", "on")
    return bool(value)


def apply_latch(
    current: MethodVerdict, previous: Optional[MethodVerdict]
) -> tuple[MethodVerdict, Optional[MethodVerdict]]:
    """Once a view has flagged an incident it stays flagged for that incident.

    ``previous`` is the last FLAGGED verdict this view produced for the
    incident (None if never). Returns ``(verdict_to_act_on, new_previous)``: a
    flagged current verdict is used as-is and becomes the new latch; an
    unflagged one is replaced by the latched verdict (flag, stage, confidence,
    techniques), marked ``latched=True``. Pure: the caller owns the state, one
    entry per (view, incident) -- the same rule in every architecture.
    """
    if current.is_ransomware_activity:
        return current, current
    if previous is None:
        return current, None
    held = replace(
        previous,
        signals=current.signals,
        signal_count=max(previous.signal_count, current.signal_count),
        rationale=f"[latched: incident already flagged; current evidence: {current.rationale}] {previous.rationale}",
        latched=True,
    )
    return held, previous
