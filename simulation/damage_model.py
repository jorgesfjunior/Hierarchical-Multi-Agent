"""Attack-progress (damage) model: what a mitigation DOES to the simulated system (Phase 4).

Applied at architecture BOUNDARIES, like ``simulation/transport.py``: no agent
reads it, so it cannot change any decision. Input: one generated
``Scenario`` (its ground truth gives the attacker's own timeline) and the
``action_dispatched`` records of ONE run of ONE architecture (the actions they
list and when each reaches its host). Output: per-incident attacker state over
simulated time. Parameters, ranges and their justification:
``docs/damage_model.md``. Metric definitions built on it:
``instrumentation/incident_metrics.py`` (``damage_outcomes``).

Open loop. Mitigations change the ATTACKER's state, never the telemetry: every
architecture sees the identical event stream, so runs stay paired and the
Phase 3 re-timing stays valid.

Attacker (per malicious campaign; its first host is "patient zero", h0)
----------------------------------------------------------------------
A campaign is the set of truth incidents sharing a ``campaign`` id
(``campaign_multihost``: one per observed host); any other malicious incident
is a campaign of one, for which everything below reduces to a single host.
* Observed lateral moves: each other host of a campaign is reached at its first
  malicious truth event, if at that moment some foothold is active with an
  unblocked segment, the target's segment is not blocked and the target is not
  isolated; otherwise the move is prevented (counted) and that host's truth
  events no longer advance the timeline.
* Kill-chain timeline: the truth events of the campaign's reached hosts (``stage``, timestamp).
  The stage reached at time t is the furthest stage (``STAGES`` order) among
  them with timestamp <= t, as long as the attacker still holds an active
  foothold; once no foothold is active the timeline stops for good.
* Footholds: h0 from the first malicious event; then one new host per
  lateral-spread tick. Ticks start ``breakout_s`` after the attacker first
  reaches ``lateral_start_stage`` (or later) and repeat every
  ``lateral_interval_s``. Each hop leaves from the most recently compromised
  eligible foothold (active, segment not blocked) to a fresh host in the same
  segment, except every ``cross_segment_every``-th hop, which goes to the next
  segment; if that segment is blocked or full the other option is tried, else
  the tick is lost. Hosts are spread over ``n_segments`` segments of
  ``segment_size`` hosts; h0's segment is a hash of its name.
* Impact: at the first impact-stage truth event (if the timeline reaches it),
  every active foothold starts encrypting; a foothold compromised later starts
  when compromised. Encryption runs at ``encryption_rate_files_per_s`` until
  ``files_per_host`` is reached or a ``kill_process`` reaches the host.

Mitigations (arrival time at the host = processing clock of the triggering
event + the record's ``sim_delay_s``):
* ``isolate_host(h)``           h stops being a foothold: no spread to/from it,
                                no detonation on it afterwards. Encryption
                                already running on it continues (it is local).
* ``kill_process(..@h)``        stops (or prevents) encryption on h and removes
                                the foothold.
* ``block_network_segment(.)``  no hop from or into the segment of the host whose
                                event triggered the dispatch (no telemetry names
                                a segment; MAS targets are domain labels). Global
                                to the scenario: a block dispatched in one
                                incident also stops spread in another.
* ``lock_account(accounts@h)``  (playbook v2) the accounts used on h are disabled:
                                h can no longer be the SOURCE of a lateral move
                                (credential-based movement). Local progression and
                                encryption on h are unaffected.
* ``trigger_backup_restore(i)`` a restore job on incident i's observed host
                                completes ``restore_delay_s`` after arrival and
                                restores ``restorable_fraction`` of the files
                                encrypted there by then. A request arriving while
                                a job runs joins it. Unobserved hosts reached by
                                lateral spread are never restored.

Preventive actions (Phase 8; ``docs/preventive_actions.md``; OFF unless
``prevention_effectiveness`` is set and the run dispatched them). e =
``prevention_effectiveness``; a "draw" is the common-random-number
``crn(action, key) = crc32("<action>|<key>") / 2**32`` (identical for every
architecture; removed sets are nested as e grows). Each is active on its
(start, end] intervals (leased if precautionary, ``prevention_lease_s``):
* ``restrict_share_write(h)``   while active, encryption on h stops at
                                max(already encrypted, (1 - e) x files_per_host).
* ``protect_backup(segment@h)`` with recovery inhibition ON
                                (``inhibited_restorable_fraction`` = r_inh), the
                                attacker's inhibit_recovery step on an observed host
                                drops its restorable fraction to r_inh, or to
                                r_inh + e (restorable_fraction - r_inh) if a
                                protect_backup covers its segment at that step.
* ``restrict_privileges(segment@h)`` a host of the segment with draw < e that has
                                not reached ``lateral_start_stage`` while it is active
                                never becomes a lateral-move source (the escalation is
                                attempted once, when the host reaches that stage; a
                                modelled host reaches it when compromised).
* ``segment_network(network)``  while active, a hop src -> dst with draw < e is blocked
                                (a modelled hop tries the other option, as for a block).

Ties: an attacker step at time t is prevented only by an action that arrived
strictly before t (a containment triggered by an event cannot undo that event).

Processing clock: a node cannot act on an event before it ARRIVES. Events are
in arrival order but carry their true timestamp, so an event delivered late
(``delayed_signals``) is clocked at the latest timestamp seen so far in the
stream, not at its own (earlier) timestamp.

Not modelled (``docs/damage_model.md`` "Limits"): re-encryption of restored
files, data exfiltration, backup age (RPO), events dropped by the generator
(no truth entry), scenarios without truth events (the Phase 3 load stream).
"""
from __future__ import annotations

import functools
import heapq
import math
import zlib
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional

from agents.mitigation import PREVENTIVE_ACTIONS, parse_action_label
from instrumentation.metrics import ACTION_DISPATCHED_EVENT

STAGES = ("none", "discovery", "privilege_escalation", "defense_evasion", "inhibit_recovery", "impact")
_RANK = {s: i for i, s in enumerate(STAGES)}
INF = math.inf
EPS = 1e-6  # a released host is usable again just after its release time
LEASED_ACTIONS = frozenset({"isolate_host", "block_network_segment"})  # reversible containment
REVERSIBLE_ACTIONS = LEASED_ACTIONS | frozenset(PREVENTIVE_ACTIONS)  # released by a reconciliation revocation
HOST_SCOPE, SEGMENT_SCOPE = frozenset({"restrict_share_write"}), frozenset({"protect_backup", "restrict_privileges"})


def crn(action: str, key: str) -> float:
    """Common-random-number draw in [0, 1) for ``action`` on ``key`` (a host, or "src|dst")."""
    return zlib.crc32(f"{action}|{key}".encode("utf-8")) / 2**32


@dataclass(frozen=True)
class DamageParams:
    """Defaults and ranges: ``docs/damage_model.md`` (fixed before any Phase 4 run)."""

    encryption_rate_files_per_s: float = 38.3
    files_per_host: int = 100_000
    lateral_start_stage: str = "privilege_escalation"
    breakout_s: float = 2880.0
    lateral_interval_s: float = 2880.0
    segment_size: int = 25
    n_segments: int = 4
    cross_segment_every: int = 3
    restore_delay_s: float = 3600.0
    restorable_fraction: float = 1.0
    horizon_s: float = 86_400.0
    # Tiered response (Phase 4c; None = OFF): precautionary containment is a lease of this many
    # seconds, released unless a detection-backed containment confirms it (see module docstring).
    lease_s: Optional[float] = None
    # Phase 8 preventive actions (docs/preventive_actions.md; every value None/neutral = OFF).
    prevention_effectiveness: Optional[float] = None  # e: fraction of the covered attack surface removed
    inhibited_restorable_fraction: Optional[float] = None  # recovery inhibition (0.43 primary; A1-g sweep)
    prevention_lease_s: Optional[float] = None  # lease of PRECAUTIONARY preventive actions (None = permanent)
    availability_weight_factor: float = 1.0  # w = factor x e for share-write / privileges / segmentation (A1-d)
    protect_backup_weight: float = 0.0  # availability weight of protect_backup (A1-d sensitivity: 0.05)
    # Fase 1 (docs/fase1/01_especializacoes.md §6; None = OFF, the crc32 % n_segments layout above):
    # ``host_segments`` maps observed hosts to their segment (= host profile); ``segment_sizes`` gives
    # each segment's real size and then defines the number of segments. Damage parameters stay
    # identical across segments (declared limitation).
    host_segments: Optional[tuple[tuple[str, int], ...]] = None
    segment_sizes: Optional[tuple[int, ...]] = None
    # Fase 1b (docs/fase1/05_desenho_1b.md A1; None = OFF, permanent): a SEGMENT-scoped
    # ``segment_network(segment@h)`` is released once every host named by its dispatch is contained
    # (isolate_host / kill_process arrival), at the latest ``segment_network_cap_s`` after it arrived.
    # The global form ``segment_network(network)`` is never released (unchanged).
    segment_network_release: Optional[str] = None
    segment_network_cap_s: float = 3600.0

    def __post_init__(self):
        if self.lateral_start_stage not in STAGES[1:]:
            raise ValueError(f"lateral_start_stage must be one of {STAGES[1:]}")
        if not 0.0 <= self.restorable_fraction <= 1.0:
            raise ValueError("restorable_fraction must be in [0, 1]")
        if min(self.encryption_rate_files_per_s, self.files_per_host, self.segment_size, self.n_segments,
               self.cross_segment_every, self.lateral_interval_s) <= 0:
            raise ValueError("rates, sizes and intervals must be > 0")
        if min(self.breakout_s, self.restore_delay_s, self.horizon_s) < 0:
            raise ValueError("delays must be >= 0")
        if self.lease_s is not None and self.lease_s <= 0:
            raise ValueError("lease_s must be > 0 (or None = tiered response OFF)")
        if self.prevention_effectiveness is not None and not 0.0 < self.prevention_effectiveness <= 1.0:
            raise ValueError("prevention_effectiveness must be in (0, 1] (or None = OFF)")
        if self.inhibited_restorable_fraction is not None and not 0.0 <= self.inhibited_restorable_fraction <= self.restorable_fraction:
            raise ValueError("inhibited_restorable_fraction must be in [0, restorable_fraction] (or None = OFF)")
        if self.prevention_lease_s is not None and self.prevention_lease_s <= 0:
            raise ValueError("prevention_lease_s must be > 0 (or None = permanent)")
        if self.availability_weight_factor < 0 or self.protect_backup_weight < 0:
            raise ValueError("availability weights must be >= 0")
        if self.segment_sizes is not None and (not self.segment_sizes or min(self.segment_sizes) <= 0):
            raise ValueError("segment_sizes must be non-empty and > 0 (or None = segment_size each)")
        if self.segment_network_release not in (None, "containment"):
            raise ValueError("segment_network_release must be None or 'containment'")
        if self.host_segments is not None and any(not 0 <= s < self.segments_count for _, s in self.host_segments):
            raise ValueError("host_segments must map hosts to segments in range(number of segments)")

    @property
    def segments_count(self) -> int:
        return len(self.segment_sizes) if self.segment_sizes is not None else self.n_segments

    def size_of(self, segment: int) -> int:
        return self.segment_sizes[segment] if self.segment_sizes is not None else self.segment_size

    @property
    def total_hosts(self) -> int:
        return sum(self.segment_sizes) if self.segment_sizes is not None else self.n_segments * self.segment_size


@functools.lru_cache(maxsize=256)
def _segment_map(host_segments: tuple[tuple[str, int], ...]) -> dict[str, int]:
    return dict(host_segments)


def segment_of(host: str, params: DamageParams) -> int:
    if params.host_segments is not None:
        seg = _segment_map(params.host_segments).get(host)
        if seg is not None:
            return seg
    return zlib.crc32(host.encode("utf-8")) % params.segments_count


# --- network state (mitigations), shared by every incident of a scenario ----------------------
def _merge(intervals: list[list[float]]) -> list[list[float]]:
    out: list[list[float]] = []
    for st, en in sorted(intervals):
        if out and st <= out[-1][1]:
            out[-1][1] = max(out[-1][1], en)
        else:
            out.append([st, en])
    return out


def _covering(intervals, t: float):
    """The (start, end] interval containing t, or None."""
    return next((iv for iv in intervals if iv[0] < t <= iv[1]), None)


@dataclass
class NetworkState:
    """Mitigations in seconds since the scenario epoch.

    Isolation and segment blocks are kept as merged (start, end] intervals (end = INF:
    permanent). Without tiered response every interval is permanent and ``isolated`` /
    ``blocked`` (earliest start) say everything, exactly as in Phase 4/4b."""

    isolated: dict[str, float] = field(default_factory=dict)  # host -> earliest isolation start
    killed: dict[str, float] = field(default_factory=dict)  # host -> t
    blocked: dict[int, float] = field(default_factory=dict)  # segment -> earliest block start
    locked: dict[str, float] = field(default_factory=dict)  # host whose accounts were locked -> t
    restores: dict[str, list[float]] = field(default_factory=dict)  # observed host -> request times
    iso: dict[str, list[list[float]]] = field(default_factory=dict)  # host -> merged intervals
    blk: dict[int, list[list[float]]] = field(default_factory=dict)  # segment -> merged intervals
    actions_applied: int = 0
    dispatches_without_actions: int = 0
    leases: int = 0  # precautionary containment actions given a lease
    confirmed_leases: int = 0  # ... of which confirmed in time (permanent)
    # Phase 8: (action, scope key) -> merged (start, end] intervals; key = host / segment / "network".
    prev: dict[tuple[str, Any], list[list[float]]] = field(default_factory=dict)
    prevention_leases: int = 0
    prevention_confirmed: int = 0
    revoked_actions: int = 0  # reversible actions cut short by a reconciliation revocation

    def _set(self, d: dict, key: Any, t: float) -> None:
        d[key] = min(t, d.get(key, INF))

    def is_isolated(self, host: str, t: float) -> bool:  # prevents attacker steps at t
        return _covering(self.iso.get(host, ()), t) is not None

    def is_killed(self, host: str, t: float) -> bool:
        return self.killed.get(host, INF) < t

    def is_blocked(self, segment: int, t: float) -> bool:
        return _covering(self.blk.get(segment, ()), t) is not None

    def is_locked(self, host: str, t: float) -> bool:
        return self.locked.get(host, INF) < t

    def permanent_isolation(self, host: str) -> float:
        """Start of the isolation that is never released (INF if none)."""
        ivs = self.iso.get(host, ())
        return ivs[-1][0] if ivs and ivs[-1][1] == INF else INF

    def isolation_end(self, host: str, t: float) -> Optional[float]:
        """End of the isolation covering t (INF if permanent), None if not isolated at t."""
        iv = _covering(self.iso.get(host, ()), t)
        return None if iv is None else iv[1]

    def releases(self, host: str, until: float = INF) -> list[float]:
        return [en for _, en in self.iso.get(host, ()) if en < INF and en <= until]

    def prevention_active(self, action: str, key: Any, t: float) -> bool:
        return _covering(self.prev.get((action, key), ()), t) is not None

    def downtime(self, host: str, start: float, end: float) -> float:
        """Seconds isolated within [start, end]."""
        return sum(max(0.0, min(en, end) - max(st, start)) for st, en in self.iso.get(host, ()))

    def apply(self, name: str, target: str, t: float, trigger_host: str, params: DamageParams, until: float = INF) -> None:
        self.actions_applied += 1
        if name == "isolate_host":
            self._set(self.isolated, target, t)
            self.iso.setdefault(target, []).append([t, until])
        elif name == "kill_process":
            self._set(self.killed, target.split("@", 1)[-1], t)
        elif name == "block_network_segment":
            seg = segment_of(trigger_host, params)
            self._set(self.blocked, seg, t)
            self.blk.setdefault(seg, []).append([t, until])
        elif name == "lock_account":
            self._set(self.locked, target.split("@", 1)[-1], t)
        elif name == "trigger_backup_restore":
            self.restores.setdefault(target.rsplit("::", 1)[-1], []).append(t)
        elif name in HOST_SCOPE:
            self.prev.setdefault((name, target), []).append([t, until])
        elif name in SEGMENT_SCOPE:
            host = target.split("@", 1)[1] if target.startswith("segment@") else trigger_host
            self.prev.setdefault((name, segment_of(host, params)), []).append([t, until])
        elif name == "segment_network":  # global ("network"), or Fase 1b segment scope ("segment@<host>")
            key = segment_of(target.split("@", 1)[1], params) if target.startswith("segment@") else "network"
            self.prev.setdefault((name, key), []).append([t, until])

    def finalize(self) -> "NetworkState":
        self.iso = {k: _merge(v) for k, v in self.iso.items()}
        self.blk = {k: _merge(v) for k, v in self.blk.items()}
        self.prev = {k: _merge(v) for k, v in self.prev.items()}
        return self


def confirms(confirmer_node: str, issuer_node: str) -> bool:
    """Tiered response: may a detection-backed dispatch from ``confirmer_node`` confirm a precaution
    issued by ``issuer_node``? B2 instances share nothing (only the issuing instance itself);
    any other node (MAS layers, B1 central) confirms within its own architecture."""
    if issuer_node.startswith("b2::"):
        return confirmer_node == issuer_node
    return not confirmer_node.startswith("b2::")


def _seconds(ts: Any, epoch: datetime) -> float:
    ts = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
    return (ts - epoch).total_seconds()


def scenario_clock(scenario) -> tuple[datetime, dict[str, float], dict[str, float]]:
    """(epoch, event_id -> true time, event_id -> processing clock), seconds since epoch."""
    times = [datetime.fromisoformat(e["timestamp"]) if isinstance(e["timestamp"], str) else e["timestamp"]
             for e in scenario.events]
    epoch = min(times)
    true_t, clock, latest = {}, {}, -INF
    for e, ts in zip(scenario.events, times):
        t = (ts - epoch).total_seconds()
        latest = max(latest, t)
        true_t[e["event_id"]], clock[e["event_id"]] = t, latest
    return epoch, true_t, clock


RECONCILIATION_EVENT = "reconciliation"


def dispatch_arrivals(scenario, records: Iterable[dict[str, Any]]) -> tuple[list[tuple], int]:
    """([(arrival t, incident_id, node, on_flagged, actions, trigger host, event_id)], dispatches without actions)."""
    _, _, clock = scenario_clock(scenario)
    source = {e["event_id"]: e.get("source", "unknown") for e in scenario.events}
    out, empty = [], 0
    for r in records:
        if r["event_type"] != ACTION_DISPATCHED_EVENT:
            continue
        p = r["payload"]
        if p["event_id"] not in clock:
            continue
        if not p["actions"]:
            empty += 1
            continue
        t = clock[p["event_id"]] + float(p.get("sim_delay_s") or 0.0)
        out.append((t, r["incident_id"], p.get("node", ""), bool(p.get("on_flagged_verdict", True)), p["actions"],
                    source[p["event_id"]], p["event_id"]))
    return out, empty


def revocations(scenario, records: Iterable[dict[str, Any]]) -> dict[tuple[str, str, str], float]:
    """(incident_id, event_id, node) of a revoked local dispatch -> release time (Phase 8 reconciliation)."""
    _, _, clock = scenario_clock(scenario)
    out: dict[tuple[str, str, str], float] = {}
    for r in records:
        if r["event_type"] != RECONCILIATION_EVENT or r["payload"].get("outcome") != "revoked":
            continue
        p = r["payload"]
        ref = p["decision_ref"]
        out[(ref["incident_id"], ref["event_id"], ref["node"])] = float(p["t_reconciled"])
    return out


def _containment_times(dispatches) -> dict[str, float]:
    """Fase 1b: earliest arrival of an isolate_host(h) / kill_process(..@h) per host."""
    out: dict[str, float] = {}
    for t, _, _, _, actions, _, _ in dispatches:
        for label in actions:
            name, target = parse_action_label(label)
            if name in ("isolate_host", "kill_process"):
                h = target.split("@", 1)[-1]
                out[h] = min(t, out.get(h, INF))
    return out


def network_state(scenario, records: Iterable[dict[str, Any]], params: DamageParams) -> NetworkState:
    """Applies every action listed on the run's ``action_dispatched`` records at its arrival time.

    Tiered response (``params.lease_s``): the reversible containment actions of a PRECAUTIONARY
    dispatch (``on_flagged_verdict=False``) last ``lease_s`` seconds unless a detection-backed
    dispatch for the same incident from a confirming node (``confirms``) arrives by then. Preventive
    actions follow the same rule with ``params.prevention_lease_s``. A reconciliation revocation
    (Phase 8) releases the revoked dispatch's reversible actions at the reconciliation time."""
    records = list(records)
    dispatches, empty = dispatch_arrivals(scenario, records)
    revoked = revocations(scenario, records)
    net = NetworkState()
    net.dispatches_without_actions = empty
    flagged = defaultdict(list)
    for t, inc, node, flag, _, _, _ in dispatches:
        if flag:
            flagged[inc].append((t, node))
    contained_at = _containment_times(dispatches) if params.segment_network_release else {}
    for t, inc, node, flag, actions, src, eid in dispatches:
        segnet_hosts = [parse_action_label(a)[1].split("@", 1)[1] for a in actions
                        if a.startswith("segment_network(segment@")] if params.segment_network_release else []
        for label in actions:
            name, target = parse_action_label(label)
            until = INF
            if segnet_hosts and name == "segment_network" and target.startswith("segment@"):
                cap = t + params.segment_network_cap_s
                done = [max(t, contained_at.get(h, INF)) for h in segnet_hosts]
                until = min(cap, max(done))
            lease = params.prevention_lease_s if name in PREVENTIVE_ACTIONS else params.lease_s
            if lease is not None and not flag and (name in LEASED_ACTIONS or name in PREVENTIVE_ACTIONS):
                if name in PREVENTIVE_ACTIONS:
                    net.prevention_leases += 1
                else:
                    net.leases += 1
                deadline = t + lease
                if any(ct <= deadline and confirms(cn, node) for ct, cn in flagged[inc]):
                    if name in PREVENTIVE_ACTIONS:
                        net.prevention_confirmed += 1
                    else:
                        net.confirmed_leases += 1
                else:
                    until = deadline
            release = revoked.get((inc, eid, node))
            if release is not None and name in REVERSIBLE_ACTIONS and release < until:
                until = max(t, release)
                net.revoked_actions += 1
            net.apply(name, target, t, src, params, until)
    return net.finalize()


# --- attacker ------------------------------------------------------------------------------------
@dataclass
class Foothold:
    host: str
    segment: int
    compromised_at: float
    observed: bool
    enc_start: Optional[float] = None
    enc_end: Optional[float] = None  # when encryption stopped (kill / all files / horizon)
    caps: list = field(default_factory=list)  # restrict_share_write (start, end] intervals (Phase 8)
    cap_files: float = 0.0  # encryptable files while a cap is active: (1 - e) x files_per_host

    def files(self, t: float, params: DamageParams) -> float:
        if self.enc_start is None or t <= self.enc_start:
            return 0.0
        tend = min(t, self.enc_end)
        if not self.caps:
            return min(float(params.files_per_host), params.encryption_rate_files_per_s * (tend - self.enc_start))
        points = sorted({self.enc_start, tend} | {x for iv in self.caps for x in iv if self.enc_start < x < tend})
        n = 0.0
        for a, b in zip(points, points[1:]):
            mid = (a + b) / 2
            cap = self.cap_files if any(st < mid <= en for st, en in self.caps) else float(params.files_per_host)
            if n < cap:
                n = min(cap, n + params.encryption_rate_files_per_s * (b - a))
        return n


@dataclass
class AttackOutcome:
    """Attacker state of one malicious campaign; times in seconds since its onset.

    A campaign is the set of truth incidents sharing ``campaign`` (Phase 4
    ``campaign_multihost``); any other malicious incident is a campaign of one.
    Keyed by patient zero's incident (the earliest onset)."""

    incident_key: str
    host: str
    contained: bool  # every observed foothold isolated or its process killed before the horizon
    containment_time: Optional[float]  # negative = patient zero was contained before the attack began
    stage_at_containment: str  # stage reached at containment (at the horizon if never contained)
    stage_reached: str  # by the horizon
    impact_started: bool
    files_encrypted_before_containment: float
    files_encrypted: float  # by the horizon, every host
    frac_encrypted_before_containment: float  # / (files_per_host x hosts_compromised)
    frac_encrypted: float  # files_encrypted / (files_per_host x hosts_compromised)
    files_restored: float
    data_loss: float  # encrypted and not restored by the horizon
    hosts_compromised: int  # observed + reached by modelled spread
    evicted: bool  # no active foothold left before the horizon
    attacker_dwell_time: float  # onset -> eviction (censored at the horizon if not evicted; 0 if evicted before onset)
    time_to_restore: Optional[float]  # impact -> every encrypted observed host restored after its encryption stopped; None if never
    restore_completed: list[float] = field(default_factory=list)
    campaign_incidents: list[str] = field(default_factory=list)  # incident keys of every observed host in the campaign
    observed_hosts_compromised: int = 1
    prevented_moves: int = 0  # scripted lateral moves (observed hosts) stopped by a mitigation
    deferred_steps: int = 0  # attacker steps postponed to a release (tiered response only)
    releases: int = 0  # releases of an isolation on this campaign's observed hosts, within the horizon
    wrongful_releases: int = 0  # ... while the attacker was not evicted
    re_isolations: int = 0  # isolations of those hosts that start after an earlier release

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def campaigns(scenario) -> dict[tuple[str, str], list[str]]:
    """Malicious truth incidents grouped by ``campaign`` (an incident without one is its own campaign)."""
    groups: dict[tuple[str, str], list[str]] = {}
    for iid, info in scenario.truth["incidents"].items():
        if info["malicious"]:
            key = ("campaign", info["campaign"]) if info.get("campaign") else ("incident", iid)
            groups.setdefault(key, []).append(iid)
    return groups


def _timeline(scenario, iids, true_t: dict[str, float]) -> list[tuple[float, str, str]]:
    """(time, stage, truth incident) of the malicious truth events of ``iids``, in time order."""
    iids = {iids} if isinstance(iids, str) else set(iids)
    return sorted((true_t[e["event_id"]], e["stage"], e["true_incident_id"]) for e in scenario.truth["events"]
                  if e["true_incident_id"] in iids and e["malicious"] and e["stage"] in _RANK)


def _stage_at(timeline, t: float) -> str:
    reached = [e[1] for e in timeline if e[0] <= t]
    return max(reached, key=_RANK.__getitem__) if reached else "none"


def simulate_incident(scenario, iid: str, net: NetworkState, params: DamageParams,
                      true_t: Optional[dict[str, float]] = None) -> Optional[AttackOutcome]:
    """Attacker state for the campaign of truth incident ``iid``; None if benign or without a truth timeline."""
    info = scenario.truth["incidents"][iid]
    if not info["malicious"]:
        return None
    group = next(g for g in campaigns(scenario).values() if iid in g)
    return simulate_campaign(scenario, group, net, params, true_t)


def simulate_campaign(scenario, iids: list[str], net: NetworkState, params: DamageParams,
                      true_t: Optional[dict[str, float]] = None) -> Optional[AttackOutcome]:
    """Attacker state for one campaign (see module docstring); None if it has no truth timeline.

    Event-driven over kill-chain steps, observed lateral moves and modelled spread ticks. A step
    or move that falls while the attacker holds no active foothold is DEFERRED to the next moment
    it holds one (a release; tiered response only) or dropped / prevented if that never happens.
    With permanent isolation nothing is ever deferred (Phase 4/4b behaviour)."""
    if true_t is None:
        _, true_t, _ = scenario_clock(scenario)
    incidents = scenario.truth["incidents"]
    timeline = _timeline(scenario, iids, true_t)
    if not timeline:
        return None
    onset, end = timeline[0][0], timeline[0][0] + params.horizon_s
    pz = timeline[0][2]
    h0 = incidents[pz]["host"]
    feet = [Foothold(h0, segment_of(h0, params), onset, observed=True)]
    host_of = {i: incidents[i]["host"] for i in iids}
    reached = {pz}
    prevented = deferred = 0

    def active(f: Foothold, t: float) -> bool:
        return f.compromised_at <= t and not net.is_isolated(f.host, t) and not net.is_killed(f.host, t)

    def leaves(f: Foothold) -> float:  # from when f is never an active foothold again
        return min(net.permanent_isolation(f.host), net.killed.get(f.host, INF))

    def next_active(f: Foothold, t: float) -> float:
        """First time >= t at which f is an active foothold (INF if never)."""
        t = max(t, f.compromised_at)
        while True:
            if net.is_killed(f.host, t):
                return INF
            e = net.isolation_end(f.host, t)
            if e is None:
                return t
            if e == INF:
                return INF
            t = e + EPS

    def reactivation(t: float) -> float:
        return min((next_active(f, t) for f in feet), default=INF)

    e = params.prevention_effectiveness or 0.0
    priv_blocked: set[str] = set()  # restrict_privileges: hosts that can never be a lateral source
    reached_lat: set[str] = set()

    def sources(t: float) -> list[Foothold]:
        return [f for f in reversed(feet) if active(f, t) and not net.is_blocked(f.segment, t) and not net.is_locked(f.host, t)
                and f.host not in priv_blocked]

    def hop_blocked(src: str, dst: str, t: float, src_seg: Optional[int] = None, dst_seg: Optional[int] = None) -> bool:
        """segment_network: global, or (Fase 1b) on a segment the hop leaves or enters."""
        if e <= 0:
            return False
        active = net.prevention_active("segment_network", "network", t) or any(
            s is not None and net.prevention_active("segment_network", s, t) for s in (src_seg, dst_seg))
        return active and crn("segment_network", f"{src}|{dst}") < e

    def try_escalate(host: str, seg: int, t: float) -> None:  # restrict_privileges, once per host
        if host in reached_lat:
            return
        reached_lat.add(host)
        if e > 0 and net.prevention_active("restrict_privileges", seg, t) and crn("restrict_privileges", host) < e:
            priv_blocked.add(host)

    # Queue: (time, priority, seq, kind, payload); at equal times moves, then steps, then ticks.
    queue: list = []
    seq = 0
    move_time: dict[str, float] = {}
    for other in iids:
        if other != pz:
            move_time[other] = min(t for t, _, i in timeline if i == other)
            queue.append((move_time[other], 0, seq, "move", other))
            seq += 1
    for t, stage, i in timeline:
        queue.append((t, 1, seq, "step", (stage, i)))
        seq += 1
    heapq.heapify(queue)
    blocked_moves: set[str] = set()
    effective: list[tuple[float, str, str]] = []
    lat_rank = _RANK[params.lateral_start_stage]
    next_tick, k = None, 1

    while queue or next_tick is not None:
        if queue and (next_tick is None or queue[0][0] <= next_tick):
            t, prio, sq, kind, payload = heapq.heappop(queue)
        else:
            t, prio, sq, kind, payload = next_tick, 2, -1, "tick", None
        if t > end:  # beyond the horizon: nothing happens (and nothing is counted)
            if kind == "tick":
                next_tick = None
            continue
        if kind == "tick":
            if all(leaves(f) < t for f in feet):  # evicted for good: no more spread
                next_tick = None
                continue
            if len(feet) < params.total_hosts:
                src = sources(t)
                if src:
                    same, nxt = src[0].segment, (src[0].segment + 1) % params.segments_count
                    options = (nxt, same) if k % params.cross_segment_every == 0 else (same, nxt)
                    for seg in options:
                        used = sum(1 for f in feet if f.segment == seg)
                        name = f"{h0}>seg{seg}.{used}"
                        if not net.is_blocked(seg, t) and used < params.size_of(seg) and not hop_blocked(src[0].host, name, t, src[0].segment, seg):
                            feet.append(Foothold(name, seg, t, observed=False))
                            try_escalate(name, seg, t)
                            break
            next_tick, k = t + params.lateral_interval_s, k + 1
            continue
        if not any(active(f, t) for f in feet):  # attacker has no hands on the network right now
            r = reactivation(t)
            if r <= end:
                deferred += 1
                if kind == "move":
                    move_time[payload] = r
                heapq.heappush(queue, (r, prio, sq, kind, payload))
            elif kind == "move":
                prevented += 1
                blocked_moves.add(payload)
            continue
        if kind == "move":
            host = host_of[payload]
            seg = segment_of(host, params)
            if (any(not hop_blocked(f.host, host, t, f.segment, seg) for f in sources(t)) and not net.is_blocked(seg, t)
                    and not net.is_isolated(host, t)):
                feet.append(Foothold(host, seg, t, observed=True))
                reached.add(payload)
            else:
                prevented += 1
                blocked_moves.add(payload)
            continue
        stage, i = payload
        if i not in reached:
            if i not in blocked_moves and move_time.get(i, -INF) > t:  # its move was deferred: follow it
                heapq.heappush(queue, (move_time[i], 1, sq, kind, payload))
            continue
        effective.append((t, stage, i))
        if _RANK[stage] >= lat_rank:
            try_escalate(host_of[i], segment_of(host_of[i], params), t)
        if next_tick is None and _RANK[stage] >= lat_rank and k == 1 and host_of[i] not in priv_blocked:
            next_tick = t + params.breakout_s

    # Eviction: the first time no foothold is ever active again.
    exits = sorted(x for x in (leaves(f) for f in feet) if x < end)
    evict = next((x for x in exits if all(leaves(f) <= x or f.compromised_at > x for f in feet)), INF)
    reachable = sorted(e for e in effective if e[0] <= end)

    # Impact / encryption: each foothold detonates the first moment it is active at or after impact.
    t_impact = next((t for t, s, _ in reachable if s == "impact"), None)
    if t_impact is not None:
        for f in feet:
            start = next_active(f, max(t_impact, f.compromised_at))
            if start > end:
                continue
            f.enc_start = start
            stop = net.killed.get(f.host, INF)
            if e > 0 and ("restrict_share_write", f.host) in net.prev:
                f.caps, f.cap_files = net.prev[("restrict_share_write", f.host)], (1.0 - e) * params.files_per_host
                f.enc_end = min(stop if stop >= start else start, end)  # a cap can be released: no early finish
            else:
                f.enc_end = min(stop if stop >= start else start, start + params.files_per_host / params.encryption_rate_files_per_s, end)

    # Containment = every observed foothold permanently isolated or killed.
    observed = [f for f in feet if f.observed]
    c = max(leaves(f) for f in observed)
    contained = c < end
    c_eval = c if contained else end
    files_before = sum(f.files(c_eval, params) for f in feet)
    files_total = sum(f.files(end, params) for f in feet)

    # Recovery inhibition (Phase 8): the attacker's inhibit_recovery step on an observed host.
    inhibit_at = {}
    for t_s, stage, i in reachable:
        if stage == "inhibit_recovery":
            inhibit_at.setdefault(host_of[i], t_s)

    def _restorable(f: Foothold, done: float) -> float:
        t_i = inhibit_at.get(f.host)
        r_inh = params.inhibited_restorable_fraction
        if r_inh is None or t_i is None or t_i >= done:
            return params.restorable_fraction
        if e > 0 and net.prevention_active("protect_backup", f.segment, t_i):
            return r_inh + e * (params.restorable_fraction - r_inh)
        return r_inh

    # Restores on observed hosts.
    restored, completed, recovered_at = 0.0, [], []
    for f in observed:
        last_done, job_end, full = None, -INF, None
        for r in sorted(net.restores.get(f.host, [])):
            if r < job_end:  # joins the running job
                continue
            job_end = r + params.restore_delay_s
            if job_end > end:
                break
            last_done = job_end
            completed.append(job_end - onset)
            if full is None and f.enc_end is not None and f.enc_end <= job_end:
                full = job_end  # encryption had stopped: this job restored everything encrypted here
        if last_done is not None:
            restored += _restorable(f, last_done) * f.files(last_done, params)
        if f.files(end, params) > 0:
            recovered_at.append(full)
    rto = None
    if t_impact is not None and recovered_at and all(x is not None for x in recovered_at):
        rto = max(recovered_at) - t_impact

    # Releases on the campaign's observed hosts.
    rel = [r for h in set(host_of.values()) for r in net.releases(h, end)]
    re_iso = sum(sum(1 for st, _ in net.iso.get(h, ())[1:] if st <= end) for h in set(host_of.values()))

    outcome = AttackOutcome(
        incident_key=incidents[pz]["incident_key"],
        host=h0,
        contained=contained,
        containment_time=(c - onset) if contained else None,
        stage_at_containment=_stage_at(reachable, c_eval),
        stage_reached=_stage_at(reachable, end),
        impact_started=t_impact is not None,
        files_encrypted_before_containment=files_before,
        files_encrypted=files_total,
        frac_encrypted_before_containment=files_before / (params.files_per_host * len(feet)),
        frac_encrypted=files_total / (params.files_per_host * len(feet)),
        files_restored=restored,
        data_loss=files_total - restored,
        hosts_compromised=len(feet),
        evicted=evict < INF,
        attacker_dwell_time=max(0.0, (evict if evict < INF else end) - onset),
        time_to_restore=rto,
        restore_completed=completed,
        campaign_incidents=[incidents[i]["incident_key"] for i in sorted(iids, key=lambda i: (i != pz, i))],
        observed_hosts_compromised=len(observed),
        prevented_moves=prevented,
        deferred_steps=deferred,
        releases=len(rel),
        wrongful_releases=sum(1 for r in rel if r < evict),
        re_isolations=re_iso,
    )
    # Phase 8 extras, kept OUT of the dataclass fields so ``as_dict`` rows stay byte-identical:
    # foothold intervals (availability accounting) and the truth impact time (lead time).
    outcome._footholds = [(f.host, f.segment, f.compromised_at, min(leaves(f), end)) for f in feet]
    outcome._t_impact_truth = next((t_s for t_s, s, _ in timeline if s == "impact"), None)
    outcome._onset = onset
    outcome._priv_blocked = len(priv_blocked)
    return outcome


def simulate(scenario, records: list[dict[str, Any]], params: Optional[DamageParams] = None) -> tuple[dict[str, AttackOutcome], NetworkState]:
    """{patient-zero incident_key: AttackOutcome} per malicious campaign with a truth timeline, and the network state."""
    params = params or DamageParams()
    net = network_state(scenario, records, params)
    _, true_t, _ = scenario_clock(scenario)
    out = {}
    for group in campaigns(scenario).values():
        o = simulate_campaign(scenario, group, net, params, true_t)
        if o is not None:
            out[o.incident_key] = o
    return out, net


# --- Phase 8 metrics: prevention lead time and availability cost ----------------------------------
def _is_preventive(label: str) -> bool:
    return parse_action_label(label)[0] in PREVENTIVE_ACTIONS


def prevention_outcomes(scenario, records: Iterable[dict[str, Any]],
                        outcomes: dict[str, AttackOutcome]) -> dict[str, dict[str, Any]]:
    """Per campaign (patient-zero key): first preventive action arrival and lead time to impact.

    Times in seconds since the campaign onset. ``lead_time_s`` = truth impact time - arrival of the
    first preventive action, if that action arrived before impact, else 0 (P2: ranked last).
    ``..._flagged`` counts only detection-backed dispatches (the P2 primary metric)."""
    dispatches, _ = dispatch_arrivals(scenario, records)
    prev = [(t, inc, flag) for t, inc, _, flag, actions, _, _ in dispatches if any(_is_preventive(a) for a in actions)]
    out = {}
    for key, o in outcomes.items():
        keys = set(o.campaign_incidents) or {key}
        onset, t_imp = o._onset, o._t_impact_truth
        row: dict[str, Any] = {"impact_time_s": None if t_imp is None else t_imp - onset}
        for label, sel in (("any", lambda f: True), ("flagged", lambda f: f)):
            ts = sorted(t for t, inc, f in prev if inc in keys and sel(f))
            first = ts[0] if ts else None
            before = first is not None and t_imp is not None and first < t_imp
            row[f"first_prevention_s_{label}"] = None if first is None else first - onset
            row[f"prevented_before_impact_{label}"] = before
            row[f"lead_time_s_{label}"] = (t_imp - first) if before else 0.0
            row[f"preventive_dispatches_{label}"] = len(ts)
        out[key] = row
    return out


def _overlap(intervals, start: float, end: float) -> float:
    return sum(max(0.0, min(en, end) - max(st, start)) for st, en in intervals)


def availability(net: NetworkState, outcomes: dict[str, AttackOutcome], params: DamageParams,
                 window: tuple[float, float]) -> dict[str, Any]:
    """Availability cost to legitimate users over ``window`` (seconds since the scenario epoch).

    Weighted host-seconds on hosts that are not attacker footholds at the time (isolation w = 1;
    restrict_share_write / restrict_privileges / segment_network w = availability_weight_factor x e;
    protect_backup w = protect_backup_weight), and the unavailability fraction = total /
    (n_segments x segment_size x window length). See docs/preventive_actions.md."""
    lo, hi = window
    n_hosts = params.total_hosts
    e = params.prevention_effectiveness or 0.0
    feet = [fh for o in outcomes.values() for fh in getattr(o, "_footholds", [])]
    by_host = defaultdict(list)
    for host, seg, st, en in feet:
        by_host[host].append((st, en))

    def compromised(intervals, hosts_filter) -> float:
        total = 0.0
        for host, seg, st, en in feet:
            if hosts_filter(host, seg):
                total += sum(max(0.0, min(en, b, hi) - max(st, a, lo)) for a, b in intervals)
        return total

    weights = {"restrict_share_write": params.availability_weight_factor * e,
               "restrict_privileges": params.availability_weight_factor * e,
               "segment_network": params.availability_weight_factor * e,
               "protect_backup": params.protect_backup_weight if e > 0 else 0.0}
    cost: dict[str, float] = defaultdict(float)
    for (name, key), ivs in net.prev.items():
        w = weights[name]
        if w <= 0:
            continue
        if name in HOST_SCOPE:
            raw, comp = _overlap(ivs, lo, hi), compromised(ivs, lambda h, s: h == key)
        elif name in SEGMENT_SCOPE or (name == "segment_network" and key != "network"):
            raw, comp = params.size_of(key) * _overlap(ivs, lo, hi), compromised(ivs, lambda h, s: s == key)
        else:
            raw, comp = n_hosts * _overlap(ivs, lo, hi), compromised(ivs, lambda h, s: True)
        cost[name] += w * max(0.0, raw - comp)
    for host, ivs in net.iso.items():
        cost["isolation"] += max(0.0, _overlap(ivs, lo, hi) - sum(
            max(0.0, min(en, b, hi) - max(st, a, lo)) for a, b in ivs for st, en in by_host.get(host, ())))
    total = sum(cost.values())
    span = max(hi - lo, 1e-9)
    return {"weighted_host_seconds": total, "unavailability_fraction": total / (n_hosts * span),
            **{f"cost_{k}": v for k, v in sorted(cost.items())}}
