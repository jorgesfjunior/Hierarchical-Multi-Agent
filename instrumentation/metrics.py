"""Structured instrumentation for the hierarchical MAS scaffold.

This module does not compute any statistics itself. It only guarantees that
the raw events needed to *later* compute the comparison metrics are emitted
in a structured, machine-readable form (JSON Lines):

  - Time-to-detect (TTD): pair "signal_received" (first touch of a raw event)
    with "alert_consolidated" (first layer that produced a terminal decision
    for that incident), matched by ``incident_id``.
  - Coordination overhead: count and total payload size of "message_sent"
    events per ``incident_id`` (inter-agent handoffs only; receipt-side
    events such as "report_received" are informational and should not be
    double-counted).
  - Consensus latency: timestamp delta between "signal_received" and the
    "alert_consolidated" event whose ``layer`` is the final decision layer
    for that incident.
  - Traceability: see :func:`append_evidence`, which builds the chained
    evidence log carried inside the incident state and mirrored into the
    Global Knowledge & Policy Repository.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class MetricsLogger:
    """Appends structured JSON Lines events to a log file.

    One logger instance is shared across every agent node in a scenario run
    so that all instrumentation for a run lands in a single, chronologically
    ordered file.
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        directory = os.path.dirname(log_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._fh = open(log_path, "a", encoding="utf-8")
        # Set by a transport/cost model (simulation/transport.py) around each node
        # invocation: {"analysis_delay": s, "dispatch_delay": s}. None = zero cost.
        self.sim: Optional[dict[str, Any]] = None

    def emit(
        self,
        *,
        event_type: str,
        incident_id: str,
        layer: str,
        agent_id: str,
        payload: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Emit one instrumentation record.

        ``payload_size_bytes`` is precomputed so coordination-overhead
        analysis does not need to re-serialize every payload later.
        """
        payload = payload or {}
        record = {
            "ts": _utc_now_iso(),
            "event_type": event_type,
            "incident_id": incident_id,
            "layer": layer,
            "agent_id": agent_id,
            "payload": payload,
            "payload_size_bytes": len(json.dumps(payload, default=str).encode("utf-8")),
        }
        self._fh.write(json.dumps(record, default=str) + "\n")
        self._fh.flush()
        return record

    def close(self) -> None:
        self._fh.close()

    def __enter__(self) -> "MetricsLogger":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def append_evidence(
    evidence_chain: list[dict[str, Any]],
    *,
    agent_id: str,
    layer: str,
    summary: str,
    based_on: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Append one chained evidence entry (mutates and returns the entry).

    ``based_on`` names the agent_id(s) whose prior evidence this entry
    relies on, so a decision's full provenance can be reconstructed by
    walking the chain backwards -- this is the traceability requirement.
    """
    entry = {
        "agent_id": agent_id,
        "layer": layer,
        "summary": summary,
        "timestamp": _utc_now_iso(),
        "based_on": based_on or [],
    }
    evidence_chain.append(entry)
    return entry


# --- Phase 3: log-based detection / containment instrumentation ------------------
#
# Two event types, emitted identically by all three architectures:
#
#   "analysis"           one per analysis a node performs (MAS specialist,
#                        coordinator and Strategic; B1's loop; each B2 instance),
#                        with the verdict that analysis produced.
#   "action_dispatched"  one per containment decision that is actually carried
#                        out (``local_containment`` / ``global_containment_directive``),
#                        separate from the detection/decision event, so
#                        time-to-detect and time-to-containment are distinct.
#
# Both carry ``node`` (transport-level node id: ``specialist::<id>``,
# ``coordinator::<domain>``, ``strategic``, ``central`` for B1, ``b2::<domain>``),
# the triggering ``event_id`` / ``event_ts`` (scenario time of the event that
# caused this analysis) and ``sim_delay_s``: simulated seconds between that
# event occurring and this analysis completing / this dispatch reaching its
# target. Without a cost model (default) ``sim_delay_s`` is 0.0, i.e. the
# zero-cost corner. ``instrumentation/incident_metrics.py`` turns these records
# into per-incident first-detection / first-containment times.

ANALYSIS_EVENT = "analysis"
ACTION_DISPATCHED_EVENT = "action_dispatched"
CONTAINMENT_DECISIONS = frozenset({"local_containment", "global_containment_directive"})


def _sim(metrics: Any) -> dict[str, Any]:
    return getattr(metrics, "sim", None) or {}


def _event_ts(event: dict[str, Any]) -> Optional[str]:
    ts = event.get("timestamp")
    return ts.isoformat() if hasattr(ts, "isoformat") else ts


def emit_analysis(
    metrics: Any,
    *,
    incident_id: str,
    layer: str,
    agent_id: str,
    node: str,
    event: dict[str, Any],
    is_ransomware_activity: bool,
    stage: str,
    confidence: float,
    method: str,
    scope: str,
    events_analyzed: int,
    latched: bool = False,
) -> dict[str, Any]:
    return metrics.emit(
        event_type=ANALYSIS_EVENT,
        incident_id=incident_id,
        layer=layer,
        agent_id=agent_id,
        payload={
            "node": node,
            "event_id": event.get("event_id"),
            "event_ts": _event_ts(event),
            "is_ransomware_activity": bool(is_ransomware_activity),
            "stage": stage,
            "confidence": confidence,
            "method": method,
            "scope": scope,
            "events_analyzed": events_analyzed,
            "latched": latched,
            "sim_delay_s": _sim(metrics).get("analysis_delay", 0.0),
        },
    )


def emit_action_dispatched(
    metrics: Any,
    *,
    incident_id: str,
    layer: str,
    agent_id: str,
    node: str,
    event: dict[str, Any],
    decision: str,
    actions: list[str],
    on_flagged_verdict: bool,
) -> dict[str, Any]:
    """``on_flagged_verdict``: the dispatching analysis had is_ransomware_activity=True.
    Primary containment metrics use only these; precautionary dispatches on
    unflagged evidence (MAS specialist/coordinator ``local_containment``) are secondary."""
    return metrics.emit(
        event_type=ACTION_DISPATCHED_EVENT,
        incident_id=incident_id,
        layer=layer,
        agent_id=agent_id,
        payload={
            "node": node,
            "event_id": event.get("event_id"),
            "event_ts": _event_ts(event),
            "decision": decision,
            "actions": actions,
            "on_flagged_verdict": bool(on_flagged_verdict),
            "sim_delay_s": _sim(metrics).get("dispatch_delay", 0.0),
        },
    )
