"""Shared, architecture-agnostic data structures for the detection module.

``Event`` is the input contract; ``Signal`` and ``Verdict`` are the output
contract. Nothing here depends on LangGraph, on any ``agents.*`` class, or
on the "specialist"/"coordinator"/"strategic" vocabulary used elsewhere in
this repository -- that separation is deliberate (see the module docstring
in ``detection/__init__.py`` and ``detection/README.md``).

A ``Signal`` carries enough fields (``ts``, ``source``, ``signal_type``,
``mitre_technique_id``, ``confidence``, ``raw_features``) to be dropped
directly into the evidence-chain shape already used elsewhere in this
repository (``instrumentation/metrics.py:append_evidence``, which records
``agent_id``/``layer``/``summary``/``based_on``) once a future task wires
this module into the agents -- see the integration note in
``detection/README.md``. This module does not perform that wiring itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class SignalCategory(str, Enum):
    """Whether a signal supports proactive or reactive intervention.

    EARLY signals precede file encryption and are the basis for proactive
    adaptation (act before data is lost). LATE signals indicate encryption
    is already in progress and are the basis for reactive adaptation
    (contain/respond after the fact). This mirrors the reactive-vs-proactive
    distinction the research design studies across all three architectures.
    """

    EARLY = "early"
    LATE = "late"


@dataclass(frozen=True)
class Event:
    """One raw telemetry event from the (real or simulated) managed system.

    Shape mirrors the dicts already produced by
    ``simulation/mock_managed_system.py`` (``event_id``, ``timestamp``,
    ``type``, ``source``, ``payload``), so callers can convert with
    :meth:`from_raw` without restructuring an existing generator.

    ``type`` here is a *raw telemetry* event type in this module's own
    vocabulary (e.g. ``"service_stop_attempt"``, ``"file_write"``) -- a
    separate vocabulary from the domain-config ``handles`` used to route
    events to Operational Specialists in the multi-agent skeleton. This
    module has no knowledge of that routing layer, by design.
    """

    event_id: str
    timestamp: datetime
    type: str
    source: str
    payload: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "Event":
        """Builds an Event from a plain dict (e.g. as emitted by mock_managed_system)."""
        ts = raw["timestamp"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        return cls(
            event_id=raw.get("event_id", ""),
            timestamp=ts,
            type=raw["type"],
            source=raw.get("source", "unknown"),
            payload=dict(raw.get("payload", {})),
        )


@dataclass(frozen=True)
class Signal:
    """One piece of detected evidence, traceable to a named MITRE ATT&CK technique.

    ``confidence`` is a heuristic strength score in [0, 1] for this single
    signal in isolation -- it is NOT a calibrated probability (see
    ``detection/README.md`` "Known limitations"). ``raw_features`` carries
    the computed inputs (e.g. entropy value, rate, counts) that produced
    the signal, for auditability/traceability.
    """

    ts: datetime
    source: str
    signal_type: str
    category: SignalCategory
    mitre_technique_id: str
    mitre_technique_name: str
    confidence: float
    summary: str
    raw_features: dict[str, Any] = field(default_factory=dict)
    contributing_event_ids: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Verdict:
    """Incident-level conclusion returned by ``classifier.classify()``.

    ``stage`` is ``"none"``, ``"early"`` (proactive-intervention territory)
    or ``"late"`` (reactive-response territory, encryption believed
    in-progress). ``is_ransomware_activity`` is the boolean gate a caller
    would use where today's stub does ``severity > self.max_severity``
    (see the integration note in ``detection/README.md``).
    """

    is_ransomware_activity: bool
    confidence: float
    stage: str
    signals: tuple[Signal, ...]
    rationale: str

    def mitre_technique_ids(self) -> tuple[str, ...]:
        """Distinct MITRE ATT&CK technique IDs contributing to this verdict, in order."""
        seen: list[str] = []
        for s in self.signals:
            if s.mitre_technique_id not in seen:
                seen.append(s.mitre_technique_id)
        return tuple(seen)
