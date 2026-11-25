"""Fase 1b campaign links and advisories (docs/fase1/05_desenho_1b.md A2; policy ``campaign_links``,
default OFF).

Link rule (node-local; only what the node has received): a node remembers the internal hosts named
(``payload.peer_hosts``) by the events of host A it has processed; A and B become one campaign the
first time both hold: B was named by an event of A, and A's incident has >= 1 detection signal in the
node's view. Each new link yields ONE advisory: the advised host's segment applies the SAME
precaution rule to B (containment + prevent_host: ``isolate_host(B)``, ``restrict_share_write(B)``).
``block_network_segment`` is left out: the damage model maps it to the segment of the host whose
event triggered the dispatch (A), not the advised one.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable

from agents.mitigation import MitigationAction, enabled_preventive, make_action

CAMPAIGN_LINKS_KEY = "campaign_links"
ADVISORY_EVENT = "advisory"


def links_enabled(get_policy: Callable[[str, Any], Any]) -> bool:
    value = get_policy(CAMPAIGN_LINKS_KEY, False)
    return value.strip().lower() in ("true", "1", "yes", "on") if isinstance(value, str) else bool(value)


class CampaignLinker:
    def __init__(self):
        self._named: dict[str, set[str]] = defaultdict(set)
        self._signalled: set[str] = set()
        self._linked: set[tuple[str, str]] = set()

    def observe(self, event: dict[str, Any], source_has_signal: bool) -> list[tuple[str, str]]:
        """New (A, B) links after processing ``event`` of host A."""
        a = event.get("source", "")
        peers = (event.get("payload") or {}).get("peer_hosts") or ()
        self._named[a].update(p for p in peers if p and p != a)
        if source_has_signal:
            self._signalled.add(a)
        if a not in self._signalled:
            return []
        new = [(a, b) for b in sorted(self._named[a]) if (a, b) not in self._linked]
        self._linked.update(new)
        return new


def advisory_actions(host: str, get_policy: Callable[[str, Any], Any]) -> tuple[MitigationAction, ...]:
    actions = [make_action("isolate_host", host)]
    if enabled_preventive(get_policy):
        actions.append(make_action("restrict_share_write", host))
    return tuple(actions)


def advised_incident(incident_id: str, host: str) -> str:
    return f"{incident_id.rsplit('::', 1)[0]}::{host}"
