"""Combines early/late signals into a single incident verdict.

This is the function a future task will call from wherever the
architectures under comparison currently do a placeholder
``severity > self.max_severity`` check (see the integration note in
``detection/README.md``). ``classify()`` has no knowledge of which
architecture is calling it -- it takes a plain list of
:class:`detection.signals.Event` and returns a plain
:class:`detection.signals.Verdict`.

Combination rule (documented, not empirically calibrated -- see
``detection/README.md`` -> "Known limitations"):

  - Any LATE signal (T1486 encryption-in-progress, already internally
    corroborated -- see ``late_signals.py``) is decisive: the incident is
    flagged as active ransomware activity, stage="late", supporting a
    REACTIVE response. Confidence is boosted slightly if more than one
    independent late-signal type fired, or if early kill-chain signals
    (recon/privesc/service-stop/backup-tamper) preceded it -- corroborating
    the overall narrative.
  - With no LATE signal, EARLY signals alone can still trigger a positive,
    lower-confidence verdict (stage="early", supporting a PROACTIVE
    response) -- but only if at least ``EARLY_MIN_DISTINCT_SIGNAL_TYPES``
    (default 2) *distinct* early-signal types are present. A single early
    indicator (e.g. one discovery event) is common enough in benign admin
    activity that it is reported for visibility but does not, by itself,
    flip the verdict to positive.
  - No signals at all -> stage="none", not flagged.
"""
from __future__ import annotations

from detection.early_signals import detect_all_early_signals
from detection.late_signals import detect_all_late_signals
from detection.signals import Event, Signal, Verdict

EARLY_MIN_DISTINCT_SIGNAL_TYPES = 2
LATE_MULTI_SIGNAL_CONFIDENCE_BOOST = 0.1
EARLY_CORROBORATION_CONFIDENCE_BOOST_PER_TYPE = 0.05
EARLY_CORROBORATION_MAX_BOOST_TYPES = 3


def _distinct_signal_types(signals: list[Signal]) -> set[str]:
    return {s.signal_type for s in signals}


def classify(events: list[Event], params=None) -> Verdict:
    """Classifies a time-ordered (or unordered) list of events into a Verdict.

    Architecture-agnostic by construction: takes/returns only the plain
    dataclasses in ``detection.signals``, with no dependency on LangGraph,
    any agent class, or graph state. ``params`` (Fase 1; default None = the module constants):
    per-profile detector thresholds, see ``detection.early_signals.Params``.
    """
    ordered_events = sorted(events, key=lambda e: e.timestamp)
    early_signals = detect_all_early_signals(ordered_events, params)
    late_signals = detect_all_late_signals(ordered_events, params)
    all_signals = tuple(sorted(early_signals + late_signals, key=lambda s: s.ts))

    if late_signals:
        confidence = max(s.confidence for s in late_signals)
        if len(_distinct_signal_types(late_signals)) > 1:
            confidence = min(0.99, confidence + LATE_MULTI_SIGNAL_CONFIDENCE_BOOST)
        if early_signals:
            boost_types = min(len(_distinct_signal_types(early_signals)), EARLY_CORROBORATION_MAX_BOOST_TYPES)
            confidence = min(0.99, confidence + EARLY_CORROBORATION_CONFIDENCE_BOOST_PER_TYPE * boost_types)

        technique_ids = sorted({s.mitre_technique_id for s in late_signals})
        rationale = (
            f"{len(late_signals)} late-stage signal(s) ({', '.join(technique_ids)}) indicate encryption "
            f"in progress"
            + (f", corroborated by {len(early_signals)} earlier kill-chain signal(s)" if early_signals else "")
            + "."
        )
        return Verdict(
            is_ransomware_activity=True,
            confidence=confidence,
            stage="late",
            signals=all_signals,
            rationale=rationale,
        )

    distinct_early_types = _distinct_signal_types(early_signals)
    if len(distinct_early_types) >= EARLY_MIN_DISTINCT_SIGNAL_TYPES:
        confidence = min(0.9, 0.3 + 0.15 * len(distinct_early_types))
        technique_ids = sorted({s.mitre_technique_id for s in early_signals})
        rationale = (
            f"{len(distinct_early_types)} distinct early-stage signal types "
            f"({', '.join(technique_ids)}) correlate across the kill chain, "
            f"consistent with pre-encryption ransomware staging."
        )
        return Verdict(
            is_ransomware_activity=True,
            confidence=confidence,
            stage="early",
            signals=all_signals,
            rationale=rationale,
        )

    if early_signals:
        # A single early indicator is reported for visibility/traceability but
        # is not, on its own, treated as sufficient corroboration to flag.
        confidence = max(s.confidence for s in early_signals) * 0.5
        rationale = (
            f"Only {len(distinct_early_types)} early-stage signal type present "
            f"(need >= {EARLY_MIN_DISTINCT_SIGNAL_TYPES} distinct types to flag); "
            "insufficient corroboration."
        )
        return Verdict(
            is_ransomware_activity=False,
            confidence=confidence,
            stage="early",
            signals=all_signals,
            rationale=rationale,
        )

    return Verdict(
        is_ransomware_activity=False,
        confidence=0.0,
        stage="none",
        signals=(),
        rationale="No early or late ransomware-related signals detected.",
    )
