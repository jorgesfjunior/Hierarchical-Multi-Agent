"""Seed-driven, parameterized scenario generator (Phase 2).

Every scenario is a pure function of ``(family, seed)``: the seed drives event
ORDER, TYPES, COUNTS and TIMING (not just random bytes), and ground truth is
returned SEPARATELY from the events (``Scenario.truth``) -- nothing that
reveals maliciousness, the family, the true incident or the kill-chain stage is
ever placed in an event (event ids are neutral, payloads carry only the
detector-contract fields of ``detection/early_signals.py`` / ``late_signals.py``).

The existing generators (``mock_managed_system``, ``file_write_stream``) and
scenario names are unchanged; encryption streams are built by calling
``file_write_stream.generate_encryption_stream`` with varied parameters.

Correlation key
---------------
Architectures are told nothing about incidents. Runners key incidents by the
OBSERVABLE ``source`` host (``incident_key``): every incident in a scenario
happens on its own host, so two interleaved incidents get distinct incident
ids, exactly as the truth file says, without the truth leaking into events.

Kill-chain stages used by the attack families (``agents/mape.py`` stage map):
  discovery (recon T1018/T1135) -> privilege_escalation (T1068/T1078)
  -> defense_evasion (service stop T1489) -> inhibit_recovery (T1490)
  -> impact (T1486: encrypted write / mass modification / ransom note)
T1489 and T1490 share one kill-chain stage in the stage map.

Families (see ``FAMILIES``; parameters are drawn from the seed and recorded in
``truth["params"]``):

  attack, kill-chain variants (one incident, then impact unless dropped)
    inorder_short        in order, gaps 20-200 s
    partial_disorder     one adjacent pair of early stages swapped
    inverted             early stages fully reversed
    skipped_stages       1-2 early stages removed
    dropped_signals      each early event lost w.p. 0.4, each impact event w.p. 0.3
    delayed_signals      1-2 early events DELIVERED late (true timestamp kept,
                         arrival delayed by d below [60,250] or above [350,900] s
                         the 300 s kill-chain window)
    gap_short / gap_boundary / gap_long
                         in order; every inter-stage gap in [20,200] /
                         [280,320] (straddles the 300 s window) / [400,1500] s
    cross_domain_spread  early stages only (no impact): 3-4 distinct early
                         techniques, or (30%) exactly one cross-domain pair
    interleaved          two concurrent incidents on two hosts: an attack plus
                         either a second attack or a benign two-signal incident
    encryption_stream    file_write_stream with ramp x variant drawn from the
                         seed and varied background/burst sizes and rates
    split_visibility     (Phase 5b) discovery -> one of privesc / defense evasion ->
                         T1490 -> impact, one event per early stage, gaps 60-300 s;
                         the three early-signal types are in different domains
                         under domains_split_visibility and domains_by_system_area
    campaign_multihost   (Phase 4) realistic timescales across several hosts:
                         patient zero does discovery then privilege escalation
                         (5-20 min apart); the attacker then moves to 2-4 more
                         hosts, 5-25 min apart, each showing one activity drawn
                         from discovery / defense_evasion / inhibit_recovery /
                         privilege_escalation (so telemetry spans several
                         domains); impact 10-30 min after the last move on
                         patient zero and 1-2 of the other hosts. Every host is
                         its own truth incident (incidents are keyed by host);
                         truth links them with ``campaign`` / ``lateral_from``.
  benign (no malicious event)
    benign_admin_recon_restart   admin inventory scan + backup-agent/AV restart
    benign_patch_window          admin privilege change + AV/EDR stop for patching
    benign_slow_lookalike        recon -> privesc -> service stop, gaps 600-3600 s
    benign_out_of_order_lookalike service stop -> privesc -> recon, short gaps
    benign_cold_start_burst      compressed-file burst from idle (backup job)
    benign_background            single-type indicators, plaintext and a few
                                 compressed writes (should never flag)
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from simulation.file_write_stream import _WriteStream, generate_encryption_stream
from simulation.mock_managed_system import _high_entropy_bytes

BASE_TIME = datetime(2026, 3, 1, tzinfo=timezone.utc)
KILLCHAIN_WINDOW_SECONDS = 300.0  # DEFAULT_KILLCHAIN_PARAMS["max_gap_seconds"]; for gap regimes only
EARLY_STAGES = ("discovery", "privilege_escalation", "defense_evasion", "inhibit_recovery")
GAP_REGIMES = {"short": (20.0, 200.0), "boundary": (280.0, 320.0), "long": (400.0, 1500.0)}

_SECURITY_PROCESSES = {
    "av": ["MsMpEng.exe", "avp.exe", "SavService.exe"],
    "edr": ["CSFalconService.exe", "SentinelAgent.exe", "cb.exe"],
    "backup_agent": ["BackupAgentService", "VeeamTransportSvc", "AcronisAgent"],
}
_BENIGN_SERVICES = ["UpdateService", "PrintSpooler", "SearchIndexer", "wuauserv"]
_T1490_COMMANDS = [
    "vssadmin delete shadows /all /quiet",
    "wbadmin delete catalog -quiet",
    "bcdedit /set {default} recoveryenabled no",
    "wmic shadowcopy delete",
]
_NOTE_NAMES = ["README_TO_DECRYPT.txt", "HOW_TO_RESTORE_FILES.html", "DECRYPT_INSTRUCTIONS.txt", "RESTORE_MY_FILES.txt"]


@dataclass
class Scenario:
    family: str
    seed: int
    events: list[dict[str, Any]]  # ARRIVAL order
    truth: dict[str, Any]  # ground truth -- never inside ``events``
    params: dict[str, Any] = field(default_factory=dict)
    # Fase 1: event ids that NO sensor reports (e.g. host telemetry of an IoT host). They stay in
    # ``events`` and ``truth`` (the attacker timeline), but no architecture receives them. Empty =
    # every event is observed (every earlier phase).
    unobserved: frozenset = frozenset()

    @property
    def scenario_id(self) -> str:
        return self.truth["scenario_id"]


def incident_key(scenario_id: str, event: dict[str, Any]) -> str:
    """Observable correlation key used by the runners (one incident per source host)."""
    return f"{scenario_id}::{event['source']}"


# --- builder -------------------------------------------------------------------------
class _Builder:
    """Collects (event, truth) pairs for one scenario; neutralizes ids at the end."""

    def __init__(self, family: str, seed: int):
        self.family, self.seed = family, seed
        self.rng = random.Random(f"{family}:{seed}")
        self.t0 = BASE_TIME + timedelta(seconds=self.rng.uniform(0, 86_400))
        self.items: list[dict[str, Any]] = []  # {"event", "arrival", "truth"}
        self.params: dict[str, Any] = {}
        self.incidents: dict[str, dict[str, Any]] = {}
        self._hosts: set[str] = set()

    def host(self) -> str:
        while True:
            h = f"host-{self.rng.randint(10, 99)}"
            if h not in self._hosts:
                self._hosts.add(h)
                return h

    def incident(self, host: str, malicious: bool) -> str:
        iid = f"inc-{len(self.incidents)}"
        self.incidents[iid] = {"host": host, "malicious": malicious}
        return iid

    def add(self, iid: str, etype: str, t: float, payload: dict[str, Any], *, malicious: bool, stage: str,
            delay: float = 0.0, encrypted: Optional[bool] = None) -> None:
        host = self.incidents[iid]["host"]
        event = {"timestamp": (self.t0 + timedelta(seconds=t)).isoformat(), "type": etype, "source": host, "payload": payload}
        truth = {"true_incident_id": iid, "malicious": malicious, "stage": stage, "t": t}
        if encrypted is not None:
            truth["encrypted_write"] = encrypted
        self.items.append({"event": event, "arrival": t + delay, "truth": truth})

    def build(self) -> Scenario:
        order = sorted(range(len(self.items)), key=lambda i: (self.items[i]["arrival"], i))
        digest = hashlib.sha1(f"{self.family}:{self.seed}".encode()).hexdigest()[:8]
        scenario_id = f"gen-{digest}"
        events, truth_events = [], []
        for n, i in enumerate(order):
            ev = dict(self.items[i]["event"])
            ev["event_id"] = f"{digest}-{n:04d}"
            events.append(ev)
            truth_events.append({"index": n, "event_id": ev["event_id"], **self.items[i]["truth"]})
        incidents = {}
        for iid, info in self.incidents.items():
            mine = [t for t in truth_events if t["true_incident_id"] == iid]
            bad = [t for t in mine if t["malicious"]]
            impact = [t for t in bad if t["stage"] == "impact" and t.get("encrypted_write", True)]
            first_bad = min(bad, key=lambda t: t["t"]) if bad else None
            first_impact = min(impact, key=lambda t: t["t"]) if impact else None
            incidents[iid] = {
                **info,
                "incident_key": f"{scenario_id}::{info['host']}",
                "n_events": len(mine),
                "true_onset_time": None if first_bad is None else (self.t0 + timedelta(seconds=first_bad["t"])).isoformat(),
                "true_onset_event_id": None if first_bad is None else first_bad["event_id"],
                "impact_onset_time": None if first_impact is None else (self.t0 + timedelta(seconds=first_impact["t"])).isoformat(),
                "impact_onset_event_id": None if first_impact is None else first_impact["event_id"],
            }
        truth = {
            "scenario_id": scenario_id,
            "family": self.family,
            "seed": self.seed,
            "malicious": any(i["malicious"] for i in self.incidents.values()),
            "params": self.params,
            "incidents": incidents,
            "events": truth_events,
        }
        return Scenario(self.family, self.seed, events, truth, self.params)


# --- event payloads (detector contract) ---------------------------------------------------
def _recon(rng: random.Random, *, sweep: bool = True) -> dict[str, Any]:
    window = rng.choice([30, 45, 60, 90])
    hosts = rng.randint(int(window * 0.7) + 1, window * 3) if sweep else rng.randint(1, max(1, int(window * 0.4)))
    shares = rng.randint(hosts + 1, hosts * 2) if sweep and rng.random() < 0.25 else rng.randint(0, 5)
    return {"hosts_touched": hosts, "shares_touched": shares, "window_seconds": window}


def _privesc(rng: random.Random, *, admin: bool = False) -> dict[str, Any]:
    if admin:
        return {"technique": "valid_account_runas", "target_account": rng.choice(["DOMAIN\\it_admin", "DOMAIN\\patch_svc"]), "success": True}
    return {
        "technique": rng.choice(["token_impersonation", "kernel_exploit", "valid_account_abuse", "uac_bypass"]),
        "target_account": rng.choice(["DOMAIN\\svc_backup", "DOMAIN\\Administrator", "NT AUTHORITY\\SYSTEM"]),
        "success": rng.random() < 0.8,
    }


def _svc_stop(rng: random.Random, category: str, method: Optional[str] = None) -> dict[str, Any]:
    name = rng.choice(_SECURITY_PROCESSES[category]) if category in _SECURITY_PROCESSES else rng.choice(_BENIGN_SERVICES)
    return {"process_name": name, "process_category": category,
            "method": method or rng.choice(["taskkill /F", "net stop", "sc stop", "sc config start= disabled"])}


def _t1490(rng: random.Random) -> dict[str, Any]:
    cmd = rng.choice(_T1490_COMMANDS)
    target = "backup_catalog" if "wbadmin" in cmd else ("recovery_boot_config" if "bcdedit" in cmd else "shadow_copies")
    return {"command": cmd, "target": target}


def _impact_events(b: _Builder, iid: str, t: float, *, drop_p: float = 0.0) -> float:
    """1-3 impact (T1486) events in random order; returns the last time used."""
    rng = b.rng
    files = rng.randint(200, 2000)
    window = rng.choice([30, 45, 60, 120])
    dirs = rng.randint(4, 20)
    kinds = ["file_write", "mass_file_modification", "ransom_note_creation"]
    rng.shuffle(kinds)
    kinds = kinds[: rng.randint(1, 3)]
    dropped = []
    for kind in kinds:
        if rng.random() < drop_p:
            dropped.append(kind)
            continue
        t += rng.uniform(2, 60)
        if kind == "file_write":
            ext = rng.choice([".docx", ".xlsx", ".pdf", ".jpg"])
            payload = {"content_sample": _high_entropy_bytes(rng), "original_extension": ext,
                       "new_extension": rng.choice([".locked", ".enc", ".crypt", ext + ".rnsm"]),
                       "files_changed": files, "window_seconds": window, "unique_directories": dirs}
        elif kind == "mass_file_modification":
            payload = {"files_changed": files, "window_seconds": window, "unique_directories": dirs,
                       "rename_count": rng.randint(files // 2, files)}
        else:
            payload = {"file_names": rng.sample(_NOTE_NAMES, rng.randint(1, 3)),
                       "directories": [f"C:\\Users\\u{i}\\Documents" for i in range(rng.randint(3, 8))]}
        b.add(iid, kind, t, payload, malicious=True, stage="impact", encrypted=(kind == "file_write"))
    b.params.setdefault("impact_kinds", []).append(kinds)
    if dropped:
        b.params.setdefault("impact_dropped", []).append(dropped)
    return t


def _stage_events(b: _Builder, stage: str) -> list[tuple[str, dict[str, Any]]]:
    rng = b.rng
    if stage == "discovery":
        return [("network_enumeration", _recon(rng))]
    if stage == "privilege_escalation":
        return [("privilege_escalation_attempt", _privesc(rng))]
    if stage == "defense_evasion":
        cats = rng.sample(["av", "edr", "backup_agent"], rng.randint(1, 2))
        return [("service_stop_attempt", _svc_stop(rng, c)) for c in cats]
    return [("backup_recovery_tamper", _t1490(rng))]


def _chain(b: _Builder, iid: str, stages: list[str], gaps: Callable[[], float], t: float = 0.0,
           delays: Optional[dict[int, float]] = None, drop_p: float = 0.0) -> float:
    """Emits ``stages`` in the given (time) order; returns the last timestamp."""
    delays = delays or {}
    k = 0
    for si, stage in enumerate(stages):
        if si:
            t += gaps()
        for j, (etype, payload) in enumerate(_stage_events(b, stage)):
            tt = t + j * b.rng.uniform(1, 20)
            if b.rng.random() < drop_p:
                b.params.setdefault("dropped_events", []).append(etype)
                continue
            b.add(iid, etype, tt, payload, malicious=True, stage=stage, delay=delays.get(k, 0.0))
            k += 1
        t = max(t, tt)
    return t


def _gap_fn(b: _Builder, regime: str) -> Callable[[], float]:
    lo, hi = GAP_REGIMES[regime]
    return lambda: round(b.rng.uniform(lo, hi), 1)


# --- attack families ---------------------------------------------------------------------
def _attack_variant(kind: str, gap_regime: str = "short"):
    def gen(b: _Builder) -> None:
        rng = b.rng
        iid = b.incident(b.host(), malicious=True)
        stages = list(EARLY_STAGES)
        drop_p = impact_drop = 0.0
        delays: dict[int, float] = {}
        if kind == "partial_disorder":
            i = rng.randrange(len(stages) - 1)
            stages[i], stages[i + 1] = stages[i + 1], stages[i]
        elif kind == "inverted":
            stages.reverse()
        elif kind == "skipped_stages":
            for s in rng.sample(stages, rng.randint(1, 2)):
                stages.remove(s)
        elif kind == "dropped_signals":
            drop_p, impact_drop = 0.4, 0.3
        elif kind == "delayed_signals":
            for k in rng.sample(range(4), rng.randint(1, 2)):  # k-th early event delivered late
                regime = rng.choice(["below_window", "above_window"])
                d = rng.uniform(60, 250) if regime == "below_window" else rng.uniform(350, 900)
                delays[k] = round(d, 1)
                b.params.setdefault("delays", []).append({"early_event": k, "regime": regime, "seconds": delays[k]})
        b.params.update({"stage_order": stages, "gap_regime": gap_regime})
        t = _chain(b, iid, stages, _gap_fn(b, gap_regime), delays=delays, drop_p=drop_p)
        _impact_events(b, iid, t + _gap_fn(b, gap_regime)(), drop_p=impact_drop)
    return gen


def _cross_domain_spread(b: _Builder) -> None:
    rng = b.rng
    iid = b.incident(b.host(), malicious=True)
    if rng.random() < 0.3:
        stages = rng.choice([["discovery", "inhibit_recovery"], ["privilege_escalation", "inhibit_recovery"],
                             ["discovery", "defense_evasion"]])
        b.params["pair_only"] = True
    else:
        stages = sorted(rng.sample(list(EARLY_STAGES), rng.randint(3, 4)), key=EARLY_STAGES.index)
        b.params["pair_only"] = False
    b.params.update({"stage_order": stages, "gap_regime": "short", "impact": False})
    _chain(b, iid, stages, _gap_fn(b, "short"))


def _interleaved(b: _Builder) -> None:
    rng = b.rng
    a = b.incident(b.host(), malicious=True)
    t = _chain(b, a, list(EARLY_STAGES), _gap_fn(b, "short"))
    _impact_events(b, a, t + rng.uniform(20, 200))
    second = rng.choice(["attack", "benign"])
    offset = round(rng.uniform(0, 400), 1)
    b.params.update({"second_incident": second, "second_offset_seconds": offset})
    if second == "attack":
        c = b.incident(b.host(), malicious=True)
        stages = sorted(rng.sample(list(EARLY_STAGES), rng.randint(2, 4)), key=EARLY_STAGES.index)
        b.params["second_stage_order"] = stages
        t2 = _chain(b, c, stages, _gap_fn(b, "short"), t=offset)
        if rng.random() < 0.5:
            _impact_events(b, c, t2 + rng.uniform(20, 200))
    else:
        c = b.incident(b.host(), malicious=False)
        _benign_two_signal(b, c, offset)


def _encryption_stream(b: _Builder) -> None:
    rng = b.rng
    host = b.host()
    iid = b.incident(host, malicious=True)
    p = {
        "ramp": rng.choice(["abrupt", "gradual"]),
        "variant": rng.choice(["rich", "inplace", "bare"]),
        "n_background": rng.randint(15, 40),
        "background_interval": round(rng.uniform(1.0, 3.0), 2),
        "burst_writes": rng.randint(40, 100),
        "burst_rate": rng.choice([2.0, 4.0, 8.0]),
        "t1490_command": rng.choice(_T1490_COMMANDS),
    }
    p["burst_start"] = round(5 + p["n_background"] * p["background_interval"] + rng.uniform(5, 30), 1)
    b.params.update(p)
    events, encrypted = generate_encryption_stream(seed=rng.randrange(10**6), start=b.t0, host=host, **p)
    for ev, enc in zip(events, encrypted):
        t = (datetime.fromisoformat(ev["timestamp"]) - b.t0).total_seconds()
        if ev["type"] == "backup_recovery_tamper":
            b.add(iid, ev["type"], t, ev["payload"], malicious=True, stage="inhibit_recovery")
        elif t >= p["burst_start"]:  # the whole burst is the attacker's process, encrypted or not
            b.add(iid, ev["type"], t, ev["payload"], malicious=True, stage="impact", encrypted=enc)
        else:
            b.add(iid, ev["type"], t, ev["payload"], malicious=False, stage="background")


CAMPAIGN_STAGE_GAP = (300.0, 1200.0)  # patient zero: discovery -> privilege_escalation
CAMPAIGN_MOVE_GAP = (300.0, 1500.0)  # between lateral moves
CAMPAIGN_IMPACT_GAP = (600.0, 1800.0)  # last move -> impact
_CAMPAIGN_ROLES = ("discovery", "defense_evasion", "inhibit_recovery", "privilege_escalation")


def _campaign_multihost(b: _Builder) -> None:
    rng = b.rng
    h0 = b.host()
    first = b.incident(h0, malicious=True)
    b.incidents[first]["campaign"] = "c0"
    t = 0.0
    for etype, payload in _stage_events(b, "discovery"):
        b.add(first, etype, t, payload, malicious=True, stage="discovery")
    t += round(rng.uniform(*CAMPAIGN_STAGE_GAP), 1)
    for etype, payload in _stage_events(b, "privilege_escalation"):
        b.add(first, etype, t, payload, malicious=True, stage="privilege_escalation")
    n_lateral = rng.randint(2, 4)
    roles = list(_CAMPAIGN_ROLES[:3])
    rng.shuffle(roles)
    if n_lateral == 4:
        roles.append("privilege_escalation")
    iids, prev = [first], h0
    for role in roles[:n_lateral]:
        t += round(rng.uniform(*CAMPAIGN_MOVE_GAP), 1)
        host = b.host()
        iid = b.incident(host, malicious=True)
        b.incidents[iid].update({"campaign": "c0", "lateral_from": prev})
        for j, (etype, payload) in enumerate(_stage_events(b, role)):
            b.add(iid, etype, t + j * rng.uniform(1, 20), payload, malicious=True, stage=role)
        iids.append(iid)
        prev = host
    t += round(rng.uniform(*CAMPAIGN_IMPACT_GAP), 1)
    impact_iids = [first] + rng.sample(iids[1:], rng.randint(1, 2))
    for iid in impact_iids:
        _impact_events(b, iid, t + rng.uniform(0, 120))
    b.params.update({"n_lateral": n_lateral, "roles": roles[:n_lateral],
                     "impact_hosts": [b.incidents[i]["host"] for i in impact_iids], "span_seconds": round(t, 1)})


SPLIT_GAP = (60.0, 300.0)


def _split_visibility(b: _Builder) -> None:
    """Phase 5b (H-S1): discovery -> ONE of privilege escalation / defense evasion -> inhibit
    recovery -> impact, one event per early stage. The three early-signal types never share a
    domain under domains_split_visibility or domains_by_system_area."""
    rng = b.rng
    iid = b.incident(b.host(), malicious=True)
    middle = rng.choice(["privilege_escalation", "defense_evasion"])
    stages = ["discovery", middle, "inhibit_recovery"]
    t = 0.0
    for k, stage in enumerate(stages):
        if k:
            t += round(rng.uniform(*SPLIT_GAP), 1)
        etype, payload = _stage_events(b, stage)[0]  # exactly one event per stage
        b.add(iid, etype, t, payload, malicious=True, stage=stage)
    b.params.update({"stage_order": stages, "gap_range": list(SPLIT_GAP)})
    _impact_events(b, iid, t + round(rng.uniform(*SPLIT_GAP), 1))


# --- benign families ---------------------------------------------------------------------
def _benign_noise(b: _Builder, iid: str, t_end: float) -> None:
    """0-4 plaintext writes / non-security service restarts sprinkled over [0, t_end]."""
    rng = b.rng
    for _ in range(rng.randint(0, 4)):
        t = rng.uniform(0, max(t_end, 30))
        if rng.random() < 0.5:
            b.add(iid, "service_stop_attempt", t, _svc_stop(rng, "other", "sc stop"), malicious=False, stage="benign")
        else:
            b.add(iid, "file_write", t, {"content_sample": (b"meeting notes " * 300)[:4096], "original_extension": ".txt",
                                          "new_extension": ".txt", "files_changed": 1, "window_seconds": 5,
                                          "unique_directories": 1}, malicious=False, stage="benign")


def _benign_two_signal(b: _Builder, iid: str, t: float = 0.0) -> None:
    rng = b.rng
    kind = rng.choice(["recon_restart", "patch_window"])
    b.params.setdefault("benign_kinds", []).append(kind)
    if kind == "recon_restart":
        first = [("network_enumeration", _recon(rng)), ("service_stop_attempt", _svc_stop(rng, rng.choice(["backup_agent", "av"]), "Restart-Service"))]
    else:
        first = [("privilege_escalation_attempt", _privesc(rng, admin=True)), ("service_stop_attempt", _svc_stop(rng, rng.choice(["av", "edr"]), "sc stop"))]
    if rng.random() < 0.5:
        first.reverse()
    for etype, payload in first:
        t += rng.uniform(10, 240)
        b.add(iid, etype, t, payload, malicious=False, stage="benign")
    _benign_noise(b, iid, t)


def _benign_admin_recon_restart(b: _Builder) -> None:
    rng = b.rng
    iid = b.incident(b.host(), malicious=False)
    scan_first = rng.random() < 0.5
    b.params["order"] = "scan_then_restart" if scan_first else "restart_then_scan"
    evs = [("network_enumeration", _recon(rng)),
           ("service_stop_attempt", _svc_stop(rng, rng.choice(["backup_agent", "av"]), rng.choice(["Restart-Service", "sc stop"])))]
    if not scan_first:
        evs.reverse()
    t = 0.0
    for etype, payload in evs:
        t += rng.uniform(10, 280)
        b.add(iid, etype, t, payload, malicious=False, stage="benign")
    _benign_noise(b, iid, t)


def _benign_patch_window(b: _Builder) -> None:
    rng = b.rng
    iid = b.incident(b.host(), malicious=False)
    t = rng.uniform(5, 60)
    b.add(iid, "privilege_escalation_attempt", t, _privesc(rng, admin=True), malicious=False, stage="benign")
    n_stops = rng.randint(1, 3)
    b.params["n_service_stops"] = n_stops
    for _ in range(n_stops):
        t += rng.uniform(5, 200)
        b.add(iid, "service_stop_attempt", t, _svc_stop(rng, rng.choice(["av", "edr", "other"]), "sc stop"), malicious=False, stage="benign")
    _benign_noise(b, iid, t)


def _benign_lookalike(order: str):
    def gen(b: _Builder) -> None:
        rng = b.rng
        iid = b.incident(b.host(), malicious=False)
        evs = [("network_enumeration", _recon(rng)), ("privilege_escalation_attempt", _privesc(rng, admin=True)),
               ("service_stop_attempt", _svc_stop(rng, rng.choice(["av", "edr", "backup_agent"]), "sc stop"))]
        lo, hi = (600.0, 3600.0) if order == "slow" else (20.0, 200.0)
        if order == "out_of_order":
            evs.reverse()
        b.params.update({"order": order, "gap_range": [lo, hi]})
        t = 0.0
        for etype, payload in evs:
            t += rng.uniform(lo, hi)
            b.add(iid, etype, t, payload, malicious=False, stage="benign")
        _benign_noise(b, iid, t)
    return gen


def _benign_cold_start_burst(b: _Builder) -> None:
    rng = b.rng
    host = b.host()
    iid = b.incident(host, malicious=False)
    n, rate = rng.randint(20, 100), rng.choice([2.0, 4.0, 8.0])
    idle = round(rng.uniform(0, 30), 1)
    b.params.update({"burst_writes": n, "burst_rate": rate, "idle_before": idle})
    s = _WriteStream(b.t0, "rich", rng.randrange(10**6), "x", host=host)
    for i in range(n):
        s.write(idle + i / rate, compressed_or_encrypted=True, encrypted_truth=False, ext=rng.choice([".zip", ".7z", ".gz"]))
    for ev in s.events:
        b.add(iid, ev["type"], (datetime.fromisoformat(ev["timestamp"]) - b.t0).total_seconds(), ev["payload"],
              malicious=False, stage="benign")


def _benign_background(b: _Builder) -> None:
    rng = b.rng
    host = b.host()
    iid = b.incident(host, malicious=False)
    t = 0.0
    single = rng.choice(["network_enumeration", "privilege_escalation_attempt", "service_stop_attempt", "none"])
    b.params["single_indicator"] = single
    n_writes = rng.randint(10, 40)
    s = _WriteStream(b.t0, "rich", rng.randrange(10**6), "x", host=host)
    for i in range(n_writes):
        t += rng.uniform(0.5, 6.0)
        s.write(t, compressed_or_encrypted=rng.random() < 0.15, encrypted_truth=False, ext=rng.choice([".docx", ".zip", ".txt"]))
    for ev in s.events:
        b.add(iid, ev["type"], (datetime.fromisoformat(ev["timestamp"]) - b.t0).total_seconds(), ev["payload"],
              malicious=False, stage="benign")
    if single != "none":
        payload = {"network_enumeration": lambda: _recon(rng),
                   "privilege_escalation_attempt": lambda: _privesc(rng, admin=True),
                   "service_stop_attempt": lambda: _svc_stop(rng, rng.choice(["av", "backup_agent"]), "Restart-Service")}[single]()
        b.add(iid, single, rng.uniform(0, t), payload, malicious=False, stage="benign")
    _benign_noise(b, iid, t)


FAMILIES: dict[str, Callable[[_Builder], None]] = {
    "inorder_short": _attack_variant("inorder"),
    "partial_disorder": _attack_variant("partial_disorder"),
    "inverted": _attack_variant("inverted"),
    "skipped_stages": _attack_variant("skipped_stages"),
    "dropped_signals": _attack_variant("dropped_signals"),
    "delayed_signals": _attack_variant("delayed_signals"),
    "gap_short": _attack_variant("inorder", "short"),
    "gap_boundary": _attack_variant("inorder", "boundary"),
    "gap_long": _attack_variant("inorder", "long"),
    "cross_domain_spread": _cross_domain_spread,
    "interleaved": _interleaved,
    "encryption_stream": _encryption_stream,
    "campaign_multihost": _campaign_multihost,
    "split_visibility": _split_visibility,
    "benign_admin_recon_restart": _benign_admin_recon_restart,
    "benign_patch_window": _benign_patch_window,
    "benign_slow_lookalike": _benign_lookalike("slow"),
    "benign_out_of_order_lookalike": _benign_lookalike("out_of_order"),
    "benign_cold_start_burst": _benign_cold_start_burst,
    "benign_background": _benign_background,
}
BENIGN_FAMILIES = tuple(f for f in FAMILIES if f.startswith("benign_"))
ATTACK_FAMILIES = tuple(f for f in FAMILIES if f not in BENIGN_FAMILIES)

# Phase 8 amendment A3-2: ``<base>_late_confirm`` = the base scenario (same seed, same base RNG
# stream: the attack is identical) shifted by a lead-in, with on every malicious host 2-3 background
# events (no signal) before the chain and a repeat of that host's first early-signal event, so the
# confirming (second distinct early type) event is preceded by >= 2 early signals. Not in FAMILIES:
# the registered family lists (and every earlier output) are unchanged.
LATE_CONFIRM_SUFFIX = "_late_confirm"
LATE_CONFIRM_BASES = ("inorder_short", "partial_disorder", "cross_domain_spread", "split_visibility",
                      "campaign_multihost", "interleaved")
LATE_CONFIRM_FAMILIES = tuple(f + LATE_CONFIRM_SUFFIX for f in LATE_CONFIRM_BASES)
LATE_CONFIRM_LEAD_S = (60.0, 180.0)
LATE_CONFIRM_REPEAT_GAP_S = (2.0, 15.0)
_EARLY_TYPES = ("network_enumeration", "privilege_escalation_attempt", "service_stop_attempt", "backup_recovery_tamper")


def _late_confirm(b: _Builder, base: str) -> None:
    FAMILIES[base](b)
    rng = random.Random(f"{base}{LATE_CONFIRM_SUFFIX}:{b.seed}:lead-in")
    lead = round(rng.uniform(*LATE_CONFIRM_LEAD_S), 1)
    for it in b.items:  # shift the base scenario by the lead-in
        it["arrival"] += lead
        it["truth"]["t"] += lead
        it["event"]["timestamp"] = (b.t0 + timedelta(seconds=it["truth"]["t"])).isoformat()
    repeats = []
    for iid, info in b.incidents.items():
        if not info["malicious"]:
            continue
        mine = sorted((it for it in b.items if it["truth"]["true_incident_id"] == iid and it["truth"]["malicious"]
                       and it["event"]["type"] in _EARLY_TYPES), key=lambda it: it["truth"]["t"])
        if not mine:
            continue
        start = mine[0]["truth"]["t"]
        n_bg = rng.randint(2, 3)
        for k in range(n_bg):
            t = round(start - lead + (k + 1) * lead / (n_bg + 1) - 1.0, 1)
            if k == 0:  # a non-security service restart, then plaintext writes: no detector signal
                b.add(iid, "service_stop_attempt", t, _svc_stop(rng, "other", "sc stop"), malicious=False, stage="background")
            else:
                b.add(iid, "file_write", t, {"content_sample": (b"quarterly report " * 300)[:4096], "original_extension": ".txt",
                                              "new_extension": ".txt", "files_changed": 1, "window_seconds": 5,
                                              "unique_directories": 1}, malicious=False, stage="background")
        first = mine[0]
        t_rep = round(first["truth"]["t"] + rng.uniform(*LATE_CONFIRM_REPEAT_GAP_S), 1)
        b.add(iid, first["event"]["type"], t_rep, dict(first["event"]["payload"]), malicious=True, stage=first["truth"]["stage"],
              delay=first["arrival"] - first["truth"]["t"])
        repeats.append({"incident": iid, "type": first["event"]["type"], "background_events": n_bg})
    b.params.update({"late_confirm": {"base": base, "lead_in_s": lead, "repeats": repeats}})


def generate(family: str, seed: int) -> Scenario:
    """The scenario for ``(family, seed)``; identical inputs give identical output."""
    if family in LATE_CONFIRM_FAMILIES:
        base = family[: -len(LATE_CONFIRM_SUFFIX)]
        b = _Builder(base, seed)  # the base family's RNG stream: the attack itself is identical
        _late_confirm(b, base)
        b.family = family
        return b.build()
    if family not in FAMILIES:
        raise ValueError(f"unknown scenario family {family!r}; expected one of {sorted(FAMILIES)}")
    b = _Builder(family, seed)
    FAMILIES[family](b)
    return b.build()
