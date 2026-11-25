"""Simulated mitigation (the "Execute" effectors of the MAPE-K loop).

No real infrastructure is touched: each function represents an action and
LOGS ITS EFFECT (``mitigation_executed`` in the instrumentation log). What the
action DOES to the simulated system is not decided here: the attacker model in
``simulation/damage_model.py`` reads the actions listed on ``action_dispatched``
records (with their arrival time at the host) and applies them to the attack's
state, identically for every architecture. Each
action maps to the existing decision vocabulary and to a MITRE D3FEND
technique (IDs and labels checked against the published D3FEND ontology,
https://d3fend.mitre.org/ontologies/d3fend.json).

Action -> decision(s) it may accompany -> D3FEND technique -> plan phase
  isolate_host(host)           local_containment, global_containment_directive
                               D3-NI  Network Isolation            containment
  block_network_segment(seg)   local_containment, global_containment_directive
                               D3-NTF Network Traffic Filtering    containment
  kill_process(process_id)     local_containment, global_containment_directive
                               D3-PT  Process Termination          eradication
  trigger_backup_restore(inc)  global_containment_directive
                               D3-RF  Restore File                 recovery
  lock_account(accounts@host)  local_containment, global_containment_directive   (playbook v2 only)
                               D3-AL  Account Locking              eradication

Playbooks (Knowledge policy ``playbook_version``; default 1 = ``DEFAULT_PLAYBOOK``,
unchanged). Version 2 (``PLAYBOOK_V2``) adds entries for the two techniques the
detectors report but v1 has no entry for (Phase 4 pilot: every action-less
dispatch). Sources: D3FEND ontology v1.6.0 (d3fend.json) and ATT&CK T1078 / T1135
pages; see docs/damage_model.md "Playbook v2":
  T1078 Valid Accounts          eradication: lock_account (D3-AL). Ontology link:
                                T1078 ``uses`` UserAccount; D3-AL ``disables``
                                UserAccount; D3-AL is a Credential Eviction
                                technique (tactic Evict -> eradication, like D3-PT).
                                ATT&CK M1018 User Account Management.
  T1135 Network Share Discovery containment: block_network_segment (D3-NTF). NO
                                ontology link (T1135 has no artifact relations in
                                v1.6.0); by analogy with v1's T1018 entry and the
                                ATT&CK detection guidance (bursts of SMB/RPC to many
                                hosts). Weaker justification.
The same playbook is used by every architecture.

Decisions that carry NO mitigation: no_action, escalation_required,
escalate_to_strategic (a hand-off, not an action) and
cross_domain_policy_update (a Knowledge write, not a mitigation).

Repeating an action on the same (incident, action, target) is logged with
``status="already_applied"`` rather than silently dropped, so re-issued
directives stay visible in the raw log.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional

from instrumentation.metrics import MetricsLogger

PHASES = ("containment", "eradication", "recovery")
DEFAULT_RECOVERY_MIN_STAGE = "late"  # restore only once encryption has actually happened
# technique -> phase -> action names. Techniques are the chain T1018 -> T1068 -> T1489 -> T1490 -> T1486.
DEFAULT_PLAYBOOK: dict[str, dict[str, list[str]]] = {
    "T1018": {"containment": ["block_network_segment"]},
    "T1068": {"containment": ["isolate_host"], "eradication": ["kill_process"]},
    "T1489": {"containment": ["isolate_host"], "eradication": ["kill_process"]},
    "T1490": {"containment": ["isolate_host"], "recovery": ["trigger_backup_restore"]},
    "T1486": {
        "containment": ["isolate_host", "block_network_segment"],
        "eradication": ["kill_process"],
        "recovery": ["trigger_backup_restore"],
    },
    # Fase 1 techniques (docs/fase1/01_especializacoes.md §5): only reported by detectors whose event
    # types no generator emits unless Fase 1 heterogeneity is ON, so earlier plans are unchanged.
    # Capabilities map to EXISTING effectors (no new damage effect): pre-encryption file access (E1),
    # exposed service (E2: patch/disable ~ isolate), C&C and lateral movement (E3: quarantine ~
    # isolate, flow block ~ segment block).
    "T1083": {"containment": ["isolate_host"], "eradication": ["kill_process"]},
    "T1190": {"containment": ["isolate_host"]},
    "T1071": {"containment": ["isolate_host", "block_network_segment"]},
    "T1021": {"containment": ["isolate_host", "block_network_segment"]},
}

PLAYBOOK_V2: dict[str, dict[str, list[str]]] = {
    **DEFAULT_PLAYBOOK,
    "T1078": {"eradication": ["lock_account"]},
    "T1135": {"containment": ["block_network_segment"]},
}
PLAYBOOKS = {1: DEFAULT_PLAYBOOK, 2: PLAYBOOK_V2}
PLAYBOOK_VERSION_KEY = "playbook_version"

# --- Preventive (hardening) actions, Phase 8 (docs/preventive_actions.md) -------------------
# Knowledge policy ``preventive_actions`` (default [] = OFF): the enabled action names. When
# non-empty, the PREVENTIVE_PLAYBOOK rows of the enabled actions are merged into whichever
# playbook is in use, and the prevent_* phases join each node's authority (MAS: per layer,
# PREVENT_AUTHORITY; B1/B2/P2P: all three). OFF = no prevent row, so plans are unchanged.
PREVENTIVE_ACTIONS_KEY = "preventive_actions"
PREVENT_PHASES = ("prevent_host", "prevent_segment", "prevent_global")
PREVENTIVE_ACTIONS = ("restrict_share_write", "protect_backup", "restrict_privileges", "segment_network")
PREVENT_AUTHORITY = {
    "specialist": ["prevent_host"],  # local reversible precaution
    "coordinator": ["prevent_host", "prevent_segment"],  # domain hardening
    "strategic": list(PREVENT_PHASES),  # global hardening
}
_DISCOVERY = {"prevent_host": ["restrict_share_write"], "prevent_segment": ["protect_backup"],
              "prevent_global": ["segment_network"]}
_PRIVILEGE = {"prevent_host": ["restrict_share_write"], "prevent_segment": ["restrict_privileges", "protect_backup"]}
# No protect_backup on T1490 (the tie rule makes it useless against the step that triggered it);
# nothing on T1486 (after impact the reactive containment / recovery actions apply).
PREVENTIVE_PLAYBOOK: dict[str, dict[str, list[str]]] = {
    "T1018": _DISCOVERY,
    "T1135": _DISCOVERY,
    "T1068": _PRIVILEGE,
    "T1078": _PRIVILEGE,
    "T1489": _PRIVILEGE,
    "T1490": {"prevent_host": ["restrict_share_write"]},
    # Fase 1 (inactive unless their detectors fire): E1 pre-encryption access; E2 exposed service
    # (backup protection / snapshot ~ protect_backup).
    "T1083": {"prevent_host": ["restrict_share_write"]},
    "T1190": {"prevent_segment": ["protect_backup"]},
}


def enabled_preventive(get_policy: Callable[[str, Any], Any]) -> tuple[str, ...]:
    """Enabled preventive actions: a list, or a CLI string ("all", "a,b", JSON list); () = OFF."""
    value = get_policy(PREVENTIVE_ACTIONS_KEY, None)
    if not value:
        return ()
    if isinstance(value, str):
        text = value.strip()
        if text.startswith("["):
            import json

            value = json.loads(text)
        elif text.lower() in ("all", "true", "on"):
            value = list(PREVENTIVE_ACTIONS)
        elif text.lower() in ("", "none", "off", "false"):
            value = []
        else:
            value = [v.strip() for v in text.split(",") if v.strip()]
    names = tuple(dict.fromkeys(value))
    unknown = [n for n in names if n not in PREVENTIVE_ACTIONS]
    if unknown:
        raise ValueError(f"unknown preventive action(s) {unknown}; expected a subset of {PREVENTIVE_ACTIONS}")
    return names


# Phase 8 amendment A3-4 (default OFF): restrict_privileges also on discovery (T1018/T1135), so it
# can arrive before patient zero escalates. A separate variant; OFF leaves PREVENTIVE_PLAYBOOK as is.
DISCOVERY_PRIVILEGES_KEY = "restrict_privileges_on_discovery"
_DISCOVERY_WITH_PRIVILEGES = {**_DISCOVERY, "prevent_segment": ["restrict_privileges", "protect_backup"]}


def with_prevention(playbook: Mapping[str, Mapping[str, list[str]]],
                    enabled: Iterable[str], *, discovery_privileges: bool = False) -> Mapping[str, Mapping[str, list[str]]]:
    """``playbook`` plus the PREVENTIVE_PLAYBOOK rows of ``enabled`` actions (unchanged if none)."""
    enabled = set(enabled)
    if not enabled:
        return playbook
    merged = {t: dict(rows) for t, rows in playbook.items()}
    source = PREVENTIVE_PLAYBOOK if not discovery_privileges else {
        **PREVENTIVE_PLAYBOOK, "T1018": _DISCOVERY_WITH_PRIVILEGES, "T1135": _DISCOVERY_WITH_PRIVILEGES}
    for technique, rows in source.items():
        for phase, names in rows.items():
            keep = [n for n in names if n in enabled]
            if keep:
                merged.setdefault(technique, {})[phase] = keep
    return merged


def playbook_version(get_policy: Callable[[str, Any], Any]) -> int:
    value = int(get_policy(PLAYBOOK_VERSION_KEY, 1))
    if value not in PLAYBOOKS:
        raise ValueError(f"unknown playbook_version {value!r}; expected one of {sorted(PLAYBOOKS)}")
    return value


def resolve_playbook(get_policy: Callable[[str, Any], Any]) -> Mapping[str, Mapping[str, list[str]]]:
    """An explicit ``mitigation_playbook`` policy wins; otherwise the ``playbook_version`` playbook."""
    explicit = get_policy("mitigation_playbook", None)
    playbook = explicit if explicit is not None else PLAYBOOKS[playbook_version(get_policy)]
    return with_prevention(playbook, enabled_preventive(get_policy),
                           discovery_privileges=bool(get_policy(DISCOVERY_PRIVILEGES_KEY, False)))


# Knowledge policy (default OFF). ON: the baselines (B1, B2), which otherwise only
# log ``action_dispatched`` with ``actions=[]``, plan their actions from the SAME
# playbook as the MAS (every phase in authority: they have no layers) and execute
# them, so the damage model can act on every architecture's dispatches. Decisions
# are unchanged either way; OFF leaves every log exactly as before.
DAMAGE_MODEL_KEY = "damage_model"


def damage_model_enabled(get_policy: Callable[[str, Any], Any]) -> bool:
    value = get_policy(DAMAGE_MODEL_KEY, False)
    return value.strip().lower() in ("true", "1", "yes", "on") if isinstance(value, str) else bool(value)


@dataclass(frozen=True)
class MitigationSpec:
    name: str
    phase: str  # "containment" | "eradication" | "recovery" | "prevent_host" | "prevent_segment" | "prevent_global"
    decisions: frozenset[str]
    d3fend_id: str
    d3fend_name: str
    effect: str


MITIGATION_CATALOG: dict[str, MitigationSpec] = {
    "isolate_host": MitigationSpec(
        "isolate_host", "containment",
        frozenset({"local_containment", "global_containment_directive"}),
        "D3-NI", "Network Isolation", "host removed from the network",
    ),
    "block_network_segment": MitigationSpec(
        "block_network_segment", "containment",
        frozenset({"local_containment", "global_containment_directive"}),
        "D3-NTF", "Network Traffic Filtering", "east-west traffic on the segment blocked",
    ),
    "kill_process": MitigationSpec(
        "kill_process", "eradication",
        frozenset({"local_containment", "global_containment_directive"}),
        "D3-PT", "Process Termination", "offending process terminated",
    ),
    "trigger_backup_restore": MitigationSpec(
        "trigger_backup_restore", "recovery",
        frozenset({"global_containment_directive"}),
        "D3-RF", "Restore File", "affected files restored from last good backup",
    ),
    "lock_account": MitigationSpec(
        "lock_account", "eradication",
        frozenset({"local_containment", "global_containment_directive"}),
        "D3-AL", "Account Locking", "accounts used on the host disabled",
    ),
    # Phase 8 preventive actions (docs/preventive_actions.md; D3FEND IDs checked against d3fend.json v1.6.0).
    "restrict_share_write": MitigationSpec(
        "restrict_share_write", "prevent_host",
        frozenset({"local_containment", "global_containment_directive"}),
        "D3-RFAM", "Remote File Access Mediation", "write access to the host's file shares restricted",
    ),
    "protect_backup": MitigationSpec(
        "protect_backup", "prevent_segment",
        frozenset({"local_containment", "global_containment_directive"}),
        "UNVERIFIED", "UNVERIFIED (no D3FEND technique relates to backup/snapshot artifacts)",
        "backup copies of the segment locked against deletion",
    ),
    "restrict_privileges": MitigationSpec(
        "restrict_privileges", "prevent_segment",
        frozenset({"local_containment", "global_containment_directive"}),
        "D3-UAP", "User Account Permissions", "privileged operations restricted on the segment's hosts",
    ),
    "segment_network": MitigationSpec(
        "segment_network", "prevent_global",
        frozenset({"local_containment", "global_containment_directive"}),
        "D3-BDI", "Broadcast Domain Isolation", "host-to-host paths restricted network-wide",
    ),
}


@dataclass(frozen=True)
class MitigationAction:
    """One planned (not yet executed) mitigation."""

    name: str
    target: str
    phase: str
    d3fend_id: str
    d3fend_name: str

    def label(self) -> str:
        return f"{self.name}({self.target})[{self.d3fend_id}]"


def make_action(name: str, target: str) -> MitigationAction:
    spec = MITIGATION_CATALOG[name]
    return MitigationAction(name, target, spec.phase, spec.d3fend_id, spec.d3fend_name)


_LABEL = re.compile(r"^(?P<name>\w+)\((?P<target>.*)\)\[(?P<d3fend>[^\]]*)\]$")


def parse_action_label(label: str) -> tuple[str, str]:
    """Inverse of :meth:`MitigationAction.label`: ``"isolate_host(h)[D3-NI]"`` -> ``("isolate_host", "h")``."""
    m = _LABEL.match(label)
    if m is None or m.group("name") not in MITIGATION_CATALOG:
        raise ValueError(f"not a mitigation action label: {label!r}")
    return m.group("name"), m.group("target")


def playbook_actions(
    playbook: Mapping[str, Mapping[str, list[str]]],
    *,
    phases: Iterable[str],
    decision: str,
    stage: str,
    recovery_min_stage: str,
    techniques: Iterable[str],
    targets: Mapping[str, Iterable[str]],
) -> tuple[MitigationAction, ...]:
    """Containment -> eradication -> recovery actions for ``decision`` (shared by every architecture).

    Filters: the phase must be in ``phases`` (the caller's authority); the
    decision must be one the action maps to; recovery additionally needs
    ``stage == recovery_min_stage``. ``targets`` maps each action name to the
    targets it applies to.
    """
    allowed = set(phases)
    techniques = tuple(techniques)
    actions: list[MitigationAction] = []
    for phase in PHASES + PREVENT_PHASES:
        if phase not in allowed:
            continue
        if phase == "recovery" and stage != recovery_min_stage:
            continue
        for technique in techniques:
            for name in playbook.get(technique, {}).get(phase, []):
                if decision not in MITIGATION_CATALOG[name].decisions:
                    continue
                for target in targets[name]:
                    action = make_action(name, target)
                    if action not in actions:
                        actions.append(action)
    return tuple(actions)


def baseline_actions(
    *,
    decision: str,
    stage: str,
    techniques: Iterable[str],
    hosts: Iterable[str],
    incident_id: str,
    phases: Iterable[str] = PHASES,
    playbook: Optional[Mapping[str, Mapping[str, list[str]]]] = None,
    segnet_scope: str = "global",
    segnet_hosts: Optional[Iterable[str]] = None,
) -> tuple[MitigationAction, ...]:
    """Actions for a B1/B2 dispatch: the MAS playbook, ``phases`` in authority (all by default).

    No telemetry names a network segment, so ``block_network_segment`` targets
    ``segment@<host>`` (the segment the observed host sits on); the MAS uses its
    domain labels there. The damage model maps either form to the segment of
    the host whose event triggered the dispatch.
    """
    hosts = tuple(hosts)
    targets = {
        "isolate_host": hosts,
        "block_network_segment": tuple(f"segment@{h}" for h in hosts),
        "kill_process": tuple(f"unresolved@{h}" for h in hosts),
        "trigger_backup_restore": (incident_id,),
        "lock_account": tuple(f"accounts@{h}" for h in hosts),
        **preventive_targets(hosts, segnet_scope, segnet_hosts),
    }
    return playbook_actions(
        DEFAULT_PLAYBOOK if playbook is None else playbook,
        phases=phases,
        decision=decision,
        stage=stage,
        recovery_min_stage=DEFAULT_RECOVERY_MIN_STAGE,
        techniques=techniques,
        targets=targets,
    )


SEGNET_SCOPE_KEY = "segment_network_scope"  # Fase 1b: "global" (default) | "incident_segments"


def preventive_targets(hosts: Iterable[str], segnet_scope: str = "global",
                       segnet_hosts: Optional[Iterable[str]] = None) -> dict[str, tuple[str, ...]]:
    """Targets of the preventive actions (same form for every architecture): host scope names the
    host, segment scope ``segment@<host>`` (the damage model maps it to that host's segment),
    global scope ``network``. Fase 1b ``segnet_scope="incident_segments"``: segment_network targets
    ``segment@<h>`` for every host of the campaign known at decision time (``segnet_hosts``,
    default the incident's hosts) instead of the whole network."""
    hosts = tuple(hosts)
    if segnet_scope not in ("global", "incident_segments"):
        raise ValueError(f"unknown segment_network scope {segnet_scope!r}")
    scoped = tuple(dict.fromkeys(tuple(segnet_hosts) if segnet_hosts is not None else hosts))
    return {
        "restrict_share_write": hosts,
        "protect_backup": tuple(f"segment@{h}" for h in hosts),
        "restrict_privileges": tuple(f"segment@{h}" for h in hosts),
        "segment_network": ("network",) if segnet_scope == "global" else tuple(f"segment@{h}" for h in scoped),
    }


def node_phases(get_policy: Callable[[str, Any], Any], phases: Iterable[str]) -> tuple[str, ...]:
    """``phases`` plus every prevent_* phase when preventive actions are enabled (B1/B2/P2P nodes)."""
    phases = tuple(phases)
    return phases + PREVENT_PHASES if enabled_preventive(get_policy) else phases


class SimulatedMitigator:
    """Carries out planned actions in simulation and logs each effect."""

    def __init__(self, metrics: MetricsLogger):
        self.metrics = metrics
        self._applied: set[tuple[str, str, str]] = set()

    # The four effectors. Each represents the action and logs its effect.
    def isolate_host(self, host: str, *, incident_id: str, layer: str, agent_id: str) -> dict[str, Any]:
        return self._apply("isolate_host", host, incident_id, layer, agent_id)

    def block_network_segment(self, segment: str, *, incident_id: str, layer: str, agent_id: str) -> dict[str, Any]:
        return self._apply("block_network_segment", segment, incident_id, layer, agent_id)

    def kill_process(self, process_id: str, *, incident_id: str, layer: str, agent_id: str) -> dict[str, Any]:
        return self._apply("kill_process", process_id, incident_id, layer, agent_id)

    def lock_account(self, accounts: str, *, incident_id: str, layer: str, agent_id: str) -> dict[str, Any]:
        return self._apply("lock_account", accounts, incident_id, layer, agent_id)

    def trigger_backup_restore(self, restore_incident_id: str, *, incident_id: str, layer: str, agent_id: str) -> dict[str, Any]:
        return self._apply("trigger_backup_restore", restore_incident_id, incident_id, layer, agent_id)

    def execute(self, action: MitigationAction, *, incident_id: str, layer: str, agent_id: str) -> dict[str, Any]:
        """Dispatches a planned action to its effector (preventive actions share one generic effector)."""
        if action.name in PREVENTIVE_ACTIONS:
            return self._apply(action.name, action.target, incident_id, layer, agent_id)
        return getattr(self, action.name)(action.target, incident_id=incident_id, layer=layer, agent_id=agent_id)

    def _apply(self, name: str, target: str, incident_id: str, layer: str, agent_id: str) -> dict[str, Any]:
        spec = MITIGATION_CATALOG[name]
        key = (incident_id, name, target)
        status = "already_applied" if key in self._applied else "applied"
        self._applied.add(key)
        effect = {
            "action": name,
            "target": target,
            "phase": spec.phase,
            "d3fend_id": spec.d3fend_id,
            "d3fend_name": spec.d3fend_name,
            "effect": spec.effect,
            "status": status,
            "simulated": True,
        }
        self.metrics.emit(
            event_type="mitigation_executed", incident_id=incident_id, layer=layer, agent_id=agent_id, payload=effect
        )
        return effect
