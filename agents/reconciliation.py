"""Audit reconciliation after an outage (Phase 8; docs/preventive_actions.md "Audit reconciliation").

When Strategic (end of ``central_down``) or a coordinator (end of ``coordinator_down``) recovers,
Strategic runs one MAPE-K cycle over Knowledge:

  Monitor  the local decisions taken while their supervising node was down. They were written
           to Knowledge when taken; any write the transport could not deliver is queued at the
           issuing node and flushed now. In this simulation Knowledge is never unavailable, so
           the queue is exactly the set of local ``action_dispatched`` records in the outage.
  Analyze  each decision's incident at incident scope (``analyze_events``, the Strategic method
           over every event in Knowledge for that incident up to the recovery event).
  Plan     ``confirmed`` if the incident-wide verdict flags, else ``revoked``.
  Execute  writes a ``reconciliation`` record (log + Knowledge decision, with evidence) and, for a
           revocation, releases the decision's reversible actions (containment that can be undone
           and every preventive action) at the reconciliation time.

It runs AFTER the run, replaying the cycle at the recovery index. That is equivalent to running it
live, because (a) it reads Knowledge only up to the recovery event and (b) no agent reads action
state (the damage model is open loop), so a release cannot change any later decision.
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

from agents.mape import analyze_events
from agents.mitigation import PREVENTIVE_ACTIONS, parse_action_label
from detection.methods import run_method
from instrumentation.metrics import ACTION_DISPATCHED_EVENT
from knowledge.repository import KnowledgePolicyRepository

AGENT_ID = "strategic-governance::reconciliation"
RECONCILIATION_EVENT = "reconciliation"
RELEASABLE = frozenset({"isolate_host", "block_network_segment"}) | frozenset(PREVENTIVE_ACTIONS)
LOCAL_LAYERS = ("specialist", "coordinator")


def _supervised(record: dict[str, Any], fault: Any, spec_domain: dict[str, str]) -> bool:
    """Was this local dispatch taken while ITS supervising node was down?"""
    node = record["payload"].get("node", "")
    if fault.kind == "central_down":
        return node.startswith(("specialist::", "coordinator::"))
    if fault.kind == "coordinator_down":
        return node.startswith("specialist::") and spec_domain.get(node.split("::", 1)[1]) == fault.target
    return False


def reconcile(scenario, logs: Iterable[dict[str, Any]], repository: KnowledgePolicyRepository, faults: Iterable[Any],
              *, domain_config: dict[str, Any], center_latency_s: float = 0.0, service_time_s: float = 0.0,
              metrics: Optional[Any] = None) -> list[dict[str, Any]]:
    """Reconciliation records (log format) for every recovered central/coordinator fault of a MAS run."""
    from simulation.damage_model import scenario_clock  # local: simulation imports agents

    logs = list(logs)
    _, _, clock = scenario_clock(scenario)
    index = {e["event_id"]: i for i, e in enumerate(scenario.events)}
    spec_domain = {s["id"]: d["name"] for d in domain_config["domains"] for s in d["specialists"]}
    out: list[dict[str, Any]] = []
    for fault in faults:
        end = getattr(fault, "end_index", None)
        if fault.kind not in ("central_down", "coordinator_down") or end is None or end >= len(scenario.events):
            continue
        recovery_event = scenario.events[end]
        t_recovery = clock[recovery_event["event_id"]]
        t_reconciled = t_recovery + center_latency_s + service_time_s
        queue = [r for r in logs if r["event_type"] == ACTION_DISPATCHED_EVENT and r["layer"] in LOCAL_LAYERS
                 and fault.start_index <= index.get(r["payload"]["event_id"], -1) < end and _supervised(r, fault, spec_domain)]
        for r in queue:
            inc = r["incident_id"]
            known = [e for e in repository.events_for_incident(inc) if index.get(e.get("event_id"), end) < end]
            analysis = (analyze_events(repository, known, method=run_method(repository.get_policy), scope="incident",
                                       domains=tuple(repository.domains_for_incident(inc))) if known else None)
            # No evidence in Knowledge for the incident: nothing supports the decision, so it is revoked.
            outcome = "confirmed" if analysis is not None and analysis.is_ransomware_activity else "revoked"
            released = [a for a in r["payload"]["actions"] if outcome == "revoked" and parse_action_label(a)[0] in RELEASABLE]
            payload = {
                "event_id": recovery_event["event_id"],
                "fault": f"{fault.kind}:{fault.target or ''}",
                "decision_ref": {"incident_id": inc, "event_id": r["payload"]["event_id"], "node": r["payload"]["node"],
                                 "decision": r["payload"]["decision"]},
                "outcome": outcome,
                "t_recovery": t_recovery,
                "t_reconciled": t_reconciled,
                "time_to_reconcile_s": t_reconciled - t_recovery,
                "released_actions": released,
                "events_analyzed": len(known),
                "confidence": analysis.confidence if analysis else 0.0,
            }
            rec = {"event_type": RECONCILIATION_EVENT, "incident_id": inc, "layer": "strategic", "agent_id": AGENT_ID,
                   "payload": payload}
            if metrics is not None:
                rec = metrics.emit(**rec)
            repository.record_decision(
                incident_id=inc, layer="strategic", agent_id=AGENT_ID, decision=f"reconciliation_{outcome}",
                severity=max(0, min(5, round((analysis.confidence if analysis else 0.0) * 5))), escalated=False,
                evidence_chain=[{"agent_id": AGENT_ID, "layer": "strategic", "based_on": [r["agent_id"]],
                                 "summary": f"reconciled {r['payload']['decision']} by {r['payload']['node']} on "
                                            f"{len(known)} incident-wide event(s): {analysis.rationale if analysis else 'no evidence'}"}],
            )
            out.append(rec)
    return out


def reconciliation_metrics(scenario, logs: Iterable[dict[str, Any]], records: list[dict[str, Any]], faults: Iterable[Any],
                           *, domain_config: dict[str, Any]) -> dict[str, Any]:
    """P5 metrics: fraction reconciled (must be 1.0), revocation correctness, time to reconcile."""
    logs = list(logs)
    index = {e["event_id"]: i for i, e in enumerate(scenario.events)}
    spec_domain = {s["id"]: d["name"] for d in domain_config["domains"] for s in d["specialists"]}
    malicious = {info["incident_key"]: info["malicious"] for info in scenario.truth["incidents"].values()}
    local = set()
    for fault in faults:
        end = getattr(fault, "end_index", None)
        if fault.kind not in ("central_down", "coordinator_down") or end is None or end >= len(scenario.events):
            continue
        local |= {(r["incident_id"], r["payload"]["event_id"], r["payload"]["node"]) for r in logs
                  if r["event_type"] == ACTION_DISPATCHED_EVENT and r["layer"] in LOCAL_LAYERS
                  and fault.start_index <= index.get(r["payload"]["event_id"], -1) < end and _supervised(r, fault, spec_domain)}
    done = {(p["decision_ref"]["incident_id"], p["decision_ref"]["event_id"], p["decision_ref"]["node"]): p
            for p in (r["payload"] for r in records)}
    revoked = [ref for ref, p in done.items() if p["outcome"] == "revoked"]
    confirmed = [ref for ref, p in done.items() if p["outcome"] == "confirmed"]
    times = sorted(p["time_to_reconcile_s"] for p in done.values())
    return {
        "local_decisions": len(local),
        "reconciled": len(local & set(done)),
        "fraction_reconciled": (len(local & set(done)) / len(local)) if local else None,
        "revoked": len(revoked),
        "confirmed": len(confirmed),
        "revoked_true_fp_share": (sum(1 for r in revoked if not malicious.get(r[0], True)) / len(revoked)) if revoked else None,
        "confirmed_true_tp_share": (sum(1 for r in confirmed if malicious.get(r[0], False)) / len(confirmed)) if confirmed else None,
        "time_to_reconcile_median_s": times[len(times) // 2] if times else None,
        "time_to_reconcile_max_s": times[-1] if times else None,
    }
