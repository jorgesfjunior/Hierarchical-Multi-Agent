"""Global Knowledge & Policy Repository.

This is NOT an agent. It is the shared state/memory that is visible
top-down across the hierarchy (Strategic Governance reads and writes it
directly; Domain Coordinators and Operational Specialists also record their
own local decisions into it so that every released decision -- at any
layer -- is auditable end to end).

In this scaffold the repository is a simple in-memory store with an
optional JSON Lines audit log on disk. Real persistence, concurrency
control, and access policy enforcement are out of scope for the skeleton.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Optional


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class KnowledgePolicyRepository:
    """Shared, hierarchically-visible store of policies and audited decisions."""

    def __init__(
        self,
        initial_policies: Optional[dict[str, Any]] = None,
        log_path: Optional[str] = None,
    ):
        self.policies: dict[str, Any] = dict(initial_policies or {})
        self._decisions: list[dict[str, Any]] = []
        # Incident-keyed evidence log: every raw event any Operational
        # Specialist observed, recorded UNCONDITIONALLY (see record_event).
        # In-memory only -- deliberately not written to ``log_path``, so the
        # decisions.jsonl schema/contents stay identical to what was
        # validated against baselines/mape_k_monolithic/.
        self._events: dict[str, list[dict[str, Any]]] = {}
        # Sticky-flag latch state (policy ``sticky_incident_flag``): last flagged
        # verdict per (incident, view). In-memory only, never logged.
        self._latches: dict[tuple[str, str], Any] = {}
        # Fase 1b campaign links ({host: campaign root}); empty = every incident is its own host.
        self._campaign: dict[str, str] = {}
        self.log_path = log_path
        if log_path:
            directory = os.path.dirname(log_path)
            if directory:
                os.makedirs(directory, exist_ok=True)

    def record_decision(
        self,
        *,
        incident_id: str,
        layer: str,
        agent_id: str,
        decision: str,
        severity: int,
        evidence_chain: list[dict[str, Any]],
        escalated: bool,
    ) -> dict[str, Any]:
        """Record one audited decision, with its full evidence chain attached.

        ``evidence_chain`` is stored as a snapshot (copy) so later mutation
        of the caller's list does not retroactively alter the audit trail.
        """
        entry = {
            "ts": _utc_now_iso(),
            "incident_id": incident_id,
            "layer": layer,
            "agent_id": agent_id,
            "decision": decision,
            "severity": severity,
            "escalated": escalated,
            "evidence_chain": list(evidence_chain),
        }
        self._decisions.append(entry)
        if self.log_path:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        return entry

    def update_policy(self, key: str, value: Any, *, updated_by: str) -> None:
        """Write/overwrite a global policy value (typically by Strategic Governance)."""
        self.policies[key] = {"value": value, "updated_by": updated_by, "ts": _utc_now_iso()}

    def get_policy(self, key: str, default: Any = None) -> Any:
        entry = self.policies.get(key)
        return entry["value"] if entry is not None else default

    def decisions_for_incident(self, incident_id: str) -> list[dict[str, Any]]:
        return [d for d in self._decisions if d["incident_id"] == incident_id]

    def all_decisions(self) -> list[dict[str, Any]]:
        return list(self._decisions)

    # --- Incident-scoped evidence accumulation -------------------------------
    #
    # Operational Specialists only ever analyze ONE event per invocation, so
    # on their own they can never satisfy detection.classifier.classify()'s
    # >=2-distinct-early-signal-types corroboration rule. Every specialist
    # therefore records what it saw here, whether or not its own local
    # decision was no_action / local_containment / escalation_required, and
    # higher layers read the accumulated list back and hand it to the SAME
    # classify() entry point the monolithic baseline uses.

    def record_event(
        self,
        *,
        incident_id: str,
        domain_name: str,
        specialist_id: str,
        event: dict[str, Any],
    ) -> None:
        """Append one raw event to the incident's shared evidence log.

        Must be called for every event a specialist observes, regardless of
        the specialist's own decision. Re-recording an event with the same
        non-empty ``event_id`` for the same incident is a no-op, so retries
        cannot inflate the evidence.
        """
        entries = self._events.setdefault(incident_id, [])
        event_id = event.get("event_id")
        if event_id and any(e["event"].get("event_id") == event_id for e in entries):
            return
        entries.append(
            {
                "domain_name": domain_name,
                "specialist_id": specialist_id,
                "event": dict(event),  # shallow snapshot; payload values are not mutated by callers
                "seen_by": set(),
            }
        )

    def mark_seen(self, incident_id: str, event_id: Optional[str], node: str) -> None:
        """Records that ``node`` has RECEIVED this event (its monitor stage ran on it).

        Higher layers read history through ``events_for_incident(..., seen_by=node)``
        so that, under a transport with losses/faults/partitions
        (``simulation/transport.py``), shared Knowledge never shows a layer an
        event that was never delivered to it. With full delivery (the default)
        every layer marks every event and the result is unchanged."""
        if not event_id:
            return
        for e in self._events.get(incident_id, []):
            if e["event"].get("event_id") == event_id:
                e["seen_by"].add(node)

    def events_for_incident(
        self, incident_id: str, *, domain_name: Optional[str] = None, seen_by: Optional[str] = None
    ) -> list[dict[str, Any]]:
        """Raw event dicts accumulated for ``incident_id`` (arrival order).

        With ``domain_name`` only events observed by that domain's
        specialists are returned; without it, the incident-wide history
        across all domains. The result is directly usable as
        ``[Event.from_raw(e) for e in ...]`` input to ``classify()``.
        """
        return [
            dict(e["event"])
            for e in self._events.get(incident_id, [])
            if (domain_name is None or e["domain_name"] == domain_name)
            and (seen_by is None or not e["event"].get("event_id") or seen_by in e["seen_by"])
        ]

    # --- Fase 1b: campaign links (written when an advisory reaches the outside nodes) -------------
    def _root(self, h: str) -> str:
        while self._campaign.get(h, h) != h:
            h = self._campaign[h]
        return h

    def link_hosts(self, a: str, b: str) -> None:
        ra, rb = self._root(a), self._root(b)
        self._campaign.setdefault(ra, ra)
        self._campaign.setdefault(rb, rb)
        if ra != rb:
            self._campaign[max(ra, rb)] = min(ra, rb)

    def campaign_hosts(self, hosts) -> tuple:
        """``hosts`` plus every host linked to them (``hosts`` unchanged without links)."""
        hosts = tuple(hosts)
        if not self._campaign:
            return hosts
        roots = {self._root(h) for h in hosts}
        return tuple(dict.fromkeys(hosts + tuple(sorted(h for h in self._campaign if self._root(h) in roots))))

    def get_incident_latch(self, incident_id: str, view: str) -> Any:
        return self._latches.get((incident_id, view))

    def set_incident_latch(self, incident_id: str, view: str, verdict: Any) -> None:
        if verdict is None:
            self._latches.pop((incident_id, view), None)
        else:
            self._latches[(incident_id, view)] = verdict

    def domains_for_incident(self, incident_id: str, *, seen_by: Optional[str] = None) -> list[str]:
        """Distinct domain names that have observed events for this incident (first-seen order)."""
        seen: list[str] = []
        for e in self._events.get(incident_id, []):
            if seen_by is not None and e["event"].get("event_id") and seen_by not in e["seen_by"]:
                continue
            if e["domain_name"] not in seen:
                seen.append(e["domain_name"])
        return seen


def apply_cli_policies(
    repository: KnowledgePolicyRepository, overrides: list[str], detection_method: Optional[str] = None
) -> None:
    """Writes CLI ``KEY=VALUE`` overrides (and ``--detection-method``) before any agent/loop is built.

    Shared by all three runners so the method flag reaches every architecture
    through the same policy key (``detection_method``). Per-domain overrides
    (``detection_method::<domain>``) are REJECTED here: the runners are the
    experiment path, and a mixed-method run would confound architecture with
    classifier. Tests may still write such keys directly on a repository.
    """
    for override in overrides:
        key, _, value = override.partition("=")
        if key.startswith("detection_method::"):
            raise ValueError(
                f"--policy {key}=... is a per-domain detection-method override; experiment runs must use ONE "
                "method for every architecture and layer. Use --detection-method <value> instead."
            )
        repository.update_policy(key, value, updated_by="cli")
    if detection_method:
        repository.update_policy("detection_method", detection_method, updated_by="cli")
