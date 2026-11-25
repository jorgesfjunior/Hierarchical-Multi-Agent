"""Fase 1 scenario layer: host profiles (E1 workstation / E2 server / E3 IoT), heterogeneity and
benign background (docs/fase1/01_especializacoes.md; pre-registration docs/fase1/02_preregistro.md).

Nothing here runs unless a Fase 1 driver calls :func:`apply`; every earlier phase is unchanged.
``apply`` post-processes a generated Scenario WITHOUT touching the scenario RNG: profile assignment
and per-profile signatures draw from the named stream ``"profiles"``, the benign background from
``"benign"`` (``simulation/rng_streams.py``), both scoped by family.

* Profiles (B1): every observed host gets a profile (70/20/10 %); the profile is the host's segment
  in the damage model (``damage_params``), segment sizes 70/20/10.
* Heterogeneity (B2), ``heterogeneity = 1``:
  - E3 (IoT) hosts have no host telemetry: their host-type events stay in the truth (the attacker
    progresses) but go into ``Scenario.unobserved`` (no sensor reports them);
  - E2 servers: an exposed vulnerable service precedes the chain (p = 0.8); encryption hits a few
    large VM/config files (20-200 files, 2-6 directories);
  - E1 workstations: a read-then-overwrite ``file_access_burst`` just before impact;
  - C&C beacons to an unprofiled destination (p = 0.3 / 0.3 / 0.9 for E1 / E2 / E3) and, in
    campaigns, a ``lateral_movement_signature`` on the source host of every lateral move.
  Added attacker events never advance the attacker's kill-chain stage (they carry the stage the host
  had already reached) and never precede the host's first malicious event, so the damage-model
  timeline and onset are those of the base scenario.
* Benign background (J3): ``benign_hosts_per_profile`` benign hosts per profile, over the scenario
  span +/- 300 s. ``heterogeneity = 0``: one generic generator for all (existing event types only);
  ``1``: the per-profile generators.
Numbers are modelling assumptions unless the design doc cites a reference for their direction.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any, Optional

from simulation.rng_streams import stream
from simulation.scenario_generator import Scenario

PROFILES = ("E1", "E2", "E3")
PROFILE_SEGMENT = {"E1": 0, "E2": 1, "E3": 2}
SEGMENT_SIZES = (70, 20, 10)
PROPORTIONS = (0.70, 0.20, 0.10)
NETWORK_TYPES = frozenset({"network_enumeration", "c2_beacon_match", "lateral_movement_signature"})
NEW_TYPES = frozenset({"file_access_burst", "c2_beacon_match", "lateral_movement_signature", "vulnerable_service_exposure"})
C2_PROB = {"E1": 0.3, "E2": 0.3, "E3": 0.9}
EXPOSURE_PROB = 0.8
BENIGN_MARGIN_S = 300.0
_STAGE_RANK = {s: i for i, s in enumerate(("none", "discovery", "privilege_escalation", "defense_evasion",
                                            "inhibit_recovery", "impact"))}


@dataclass(frozen=True)
class Fase1Config:
    heterogeneity: int = 0
    benign_hosts_per_profile: int = 3
    # Fase 1b (06_preregistro_1b.md §3; default OFF): benign E1 hosts open admin connections to
    # benign servers (lateral_movement_signature with peer_hosts, 0.2/h), h = 1 only.
    admin_connections: bool = False

    def __post_init__(self):
        if self.heterogeneity not in (0, 1):
            raise ValueError("heterogeneity must be 0 or 1")


@dataclass
class Fase1Scenario:
    scenario: Scenario
    host_profiles: dict[str, str]
    config: Fase1Config

    @property
    def host_segments(self) -> tuple[tuple[str, int], ...]:
        return tuple(sorted((h, PROFILE_SEGMENT[p]) for h, p in self.host_profiles.items()))

    def damage_params(self, **kw):
        from simulation.damage_model import DamageParams

        return DamageParams(host_segments=self.host_segments, segment_sizes=SEGMENT_SIZES, **kw)


# --- payload helpers -------------------------------------------------------------------------------
def _sample_with_entropy(rng: random.Random, target_bits: float, n: int = 4096) -> bytes:
    """Bytes whose Shannon entropy is close to ``target_bits``: uniform over round(2**target) symbols
    (log2 of the alphabet, minus a small finite-sample bias)."""
    alphabet = max(2, min(256, int(round(2 ** target_bits))))
    return bytes(rng.randrange(alphabet) for _ in range(n))


def _file_write(rng, *, compressed: bool, entropy: float, files: int = 1, window: int = 5, dirs: int = 1,
                ext_changed: bool = False) -> dict[str, Any]:
    ext = rng.choice([".docx", ".xlsx", ".pdf"])
    sample = _sample_with_entropy(rng, entropy) if compressed else (b"meeting notes " * 300)[:4096]
    return {"content_sample": sample, "original_extension": ext, "new_extension": ".zip" if ext_changed else ext,
            "files_changed": files, "window_seconds": window, "unique_directories": dirs}


# --- apply -----------------------------------------------------------------------------------------
def apply(sc: Scenario, cfg: Fase1Config = Fase1Config(), *, fixed_profiles: Optional[dict[str, str]] = None,
          attack_transforms: bool = True) -> Fase1Scenario:
    """Fase 1b: ``fixed_profiles`` pins the profile of given attacker hosts (campaign_e1_e2);
    ``attack_transforms=False`` keeps the scenario's own attacker observables (the family defines
    them); ``sc.unobserved`` is carried over."""
    prof_rng = stream(sc.seed, "profiles", scope=sc.family)
    ben_rng = stream(sc.seed, "benign", scope=sc.family)
    t0 = datetime.fromisoformat(sc.events[0]["timestamp"]) - timedelta(
        seconds=next(t["t"] for t in sc.truth["events"] if t["event_id"] == sc.events[0]["event_id"]))
    truth_by_id = {t["event_id"]: t for t in sc.truth["events"]}
    incidents = sc.truth["incidents"]
    hosts = [info["host"] for _, info in sorted(incidents.items(), key=lambda kv: int(kv[0].split("-")[1]))]
    profiles = {h: prof_rng.choices(PROFILES, weights=PROPORTIONS)[0] for h in hosts}
    profiles.update(fixed_profiles or {})

    new: list[tuple[dict[str, Any], dict[str, Any]]] = []  # (event, truth)
    edited: dict[str, dict[str, Any]] = {}  # event_id -> replacement payload (E2 VM encryption)
    unobserved: set[Any] = set(sc.unobserved)

    def add(host: str, iid: str, etype: str, t: float, payload: dict[str, Any], *, malicious: bool, stage: str):
        ev = {"timestamp": (t0 + timedelta(seconds=t)).isoformat(), "type": etype, "source": host, "payload": payload}
        new.append((ev, {"true_incident_id": iid, "malicious": malicious, "stage": stage, "t": t}))

    if cfg.heterogeneity and attack_transforms:
        by_inc: dict[str, list[dict[str, Any]]] = {}
        for t in sc.truth["events"]:
            by_inc.setdefault(t["true_incident_id"], []).append(t)
        for iid, info in sorted(incidents.items(), key=lambda kv: int(kv[0].split("-")[1])):
            host, p = info["host"], profiles[info["host"]]
            evs = sorted(by_inc.get(iid, []), key=lambda t: t["t"])
            bad = [t for t in evs if t["malicious"]]
            if p == "E3":
                unobserved.update(t["event_id"] for t in evs
                                  if next(e for e in sc.events if e["event_id"] == t["event_id"])["type"] not in NETWORK_TYPES)
            if not bad:
                continue
            t_first = bad[0]["t"]

            def stage_at(t: float) -> str:
                reached = [x["stage"] for x in bad if x["t"] <= t and x["stage"] in _STAGE_RANK]
                return max(reached, key=_STAGE_RANK.get) if reached else bad[0]["stage"]

            impact = [t for t in bad if t["stage"] == "impact"]
            if p == "E2":
                if prof_rng.random() < EXPOSURE_PROB:
                    add(host, iid, "vulnerable_service_exposure", t_first - prof_rng.uniform(60, 600),
                        {"service": prof_rng.choice(["OpenSLP", "SMBv1", "RDP", "vCenter"]), "exposed": True,
                         "patched": False, "severity": round(prof_rng.uniform(7.5, 9.8), 1)},
                        malicious=False, stage="background")
                for t in impact:
                    ev = next(e for e in sc.events if e["event_id"] == t["event_id"])
                    if ev["type"] in ("file_write", "mass_file_modification"):
                        pl = dict(ev["payload"])
                        pl["files_changed"] = prof_rng.randint(20, 200)
                        pl["unique_directories"] = prof_rng.randint(2, 6)
                        if ev["type"] == "file_write":
                            pl["original_extension"] = prof_rng.choice([".vmdk", ".vmx", ".cfg"])
                        edited[ev["event_id"]] = pl
            if p == "E1" and impact:
                t_imp = impact[0]["t"]
                t = max(t_first + 1.0, t_imp - prof_rng.uniform(5, 30))
                files = prof_rng.randint(200, 1500)
                win = prof_rng.randint(20, 60)
                add(host, iid, "file_access_burst", t,
                    {"files_touched": files, "window_seconds": win,
                     "read_then_overwrite_count": int(files * prof_rng.uniform(0.4, 0.9)),
                     "rename_count": prof_rng.randint(0, files // 2), "unique_directories": prof_rng.randint(3, 20)},
                    malicious=True, stage=stage_at(t))
            if prof_rng.random() < C2_PROB[p]:
                t = t_first + prof_rng.uniform(10, 120)
                add(host, iid, "c2_beacon_match", t,
                    {"destination": f"203.0.113.{prof_rng.randint(1, 254)}", "known_destination": False,
                     "beacon_count": prof_rng.randint(2, 8), "interval_s": prof_rng.choice([30, 60, 300])},
                    malicious=True, stage=stage_at(t))
        for iid, info in sorted(incidents.items(), key=lambda kv: int(kv[0].split("-")[1])):
            src = info.get("lateral_from")
            if not src:
                continue
            src_iid = next(i for i, x in incidents.items() if x["host"] == src)
            src_bad = sorted((t for t in by_inc.get(src_iid, []) if t["malicious"]), key=lambda t: t["t"])
            dst_first = min(t["t"] for t in by_inc[iid] if t["malicious"])
            t = max(src_bad[0]["t"] + 1.0, dst_first - prof_rng.uniform(5, 60))
            stage = max((x["stage"] for x in src_bad if x["t"] <= t), key=_STAGE_RANK.get, default=src_bad[0]["stage"])
            add(src, src_iid, "lateral_movement_signature", t,
                {"new_internal_peers": prof_rng.randint(2, 6), "window_seconds": 60, "protocol": prof_rng.choice(["smb", "rdp", "wmi"])},
                malicious=True, stage=stage)

    # --- benign background (all Fase 1 conditions) ----------------------------------------------------
    ts = [t["t"] for t in sc.truth["events"]] + [x[1]["t"] for x in new]
    lo, hi = min(ts) - BENIGN_MARGIN_S, max(ts) + BENIGN_MARGIN_S
    benign_incidents: dict[str, dict[str, Any]] = {}
    for p in PROFILES:
        for k in range(cfg.benign_hosts_per_profile):
            host = f"bg-{p.lower()}-{k}"
            iid = f"bg-{p}-{k}"
            profiles[host] = p
            benign_incidents[iid] = {"host": host, "malicious": False}
            before = len(new)
            _benign_host(ben_rng, add, host, iid, p if cfg.heterogeneity else "generic", lo, hi)
    if cfg.heterogeneity and cfg.admin_connections:  # Fase 1b: separate pass, so Fase 1 draws are unchanged
        servers = [f"bg-e2-{k}" for k in range(cfg.benign_hosts_per_profile)]
        for k in range(cfg.benign_hosts_per_profile):
            host, iid = f"bg-e1-{k}", f"bg-E1-{k}"
            for t in _poisson_times(ben_rng, 0.2, lo, hi):
                peers = ben_rng.sample(servers, min(len(servers), ben_rng.randint(1, 2)))
                add(host, iid, "lateral_movement_signature", t,
                    {"new_internal_peers": len(peers), "window_seconds": 60, "protocol": ben_rng.choice(["rdp", "smb"]),
                     "peer_hosts": peers}, malicious=False, stage="benign")
            if cfg.heterogeneity and p == "E3":
                unobserved.update(_pending_ids(new, before))  # placeholder ids resolved after merge

    return _merge(sc, new, edited, unobserved, benign_incidents, profiles, cfg)


def _pending_ids(new, start):
    return {("new", i) for i in range(start, len(new)) if new[i][0]["type"] not in NETWORK_TYPES}


def _poisson_times(rng: random.Random, rate_per_h: float, lo: float, hi: float) -> list[float]:
    out, t = [], lo
    if rate_per_h <= 0:
        return out
    while True:
        t += rng.expovariate(rate_per_h / 3600.0)
        if t > hi:
            return out
        out.append(t)


def _benign_host(rng: random.Random, add, host: str, iid: str, kind: str, lo: float, hi: float) -> None:
    """Normal behaviour of one benign host (01_especializacoes.md §3; numbers are SM)."""
    def b(etype, t, payload):
        add(host, iid, etype, t, payload, malicious=False, stage="benign")

    if kind in ("generic", "E1", "E2"):
        if kind == "E1":
            rate, hi_frac = rng.uniform(30, 300), 0.10
        elif kind == "E2":
            rate, hi_frac = 40.0, 0.40
        else:
            rate, hi_frac = 35.0, 0.10
        for t in _poisson_times(rng, rate, lo, hi):
            if rng.random() < hi_frac:  # archive / backup job: compressed, sometimes corroborated
                b("file_write", t, _file_write(rng, compressed=True, entropy=rng.uniform(7.0, 7.95),
                                               files=rng.randint(20, 600), window=rng.randint(30, 60),
                                               dirs=rng.randint(1, 6), ext_changed=rng.random() < 0.5))
            else:
                b("file_write", t, _file_write(rng, compressed=False, entropy=0.0))
        admin_rate = {"generic": 0.5, "E1": 0.5, "E2": 0.3}[kind]
        for t in _poisson_times(rng, admin_rate, lo, hi):
            b("privilege_escalation_attempt", t, {"technique": "valid_account_runas", "success": True,
                                                  "target_account": rng.choice(["DOMAIN\\it_admin", "DOMAIN\\patch_svc"])})
        for t in _poisson_times(rng, 1.0, lo, hi):
            cat = "backup_agent" if kind == "E2" and rng.random() < 0.2 else "other"
            b("service_stop_attempt", t, {"process_name": rng.choice(["UpdateService", "BackupAgentService", "wuauserv"]),
                                          "process_category": cat, "method": "Restart-Service"})
        if kind in ("E1", "E2"):
            for t in _poisson_times(rng, 0.2 if kind == "E1" else 0.05, lo, hi):  # admin inventory scan
                window = rng.choice([60, 90])
                b("network_enumeration", t, {"hosts_touched": int(window * rng.uniform(0.2, 1.5)), "shares_touched": 0,
                                             "window_seconds": window})
        if kind == "E1":
            for t in _poisson_times(rng, 1.0, lo, hi):  # indexing / backup read bursts, no overwrite
                files = rng.randint(100, 2000)
                b("file_access_burst", t, {"files_touched": files, "window_seconds": rng.randint(20, 120),
                                           "read_then_overwrite_count": int(files * rng.uniform(0.0, 0.35)),
                                           "rename_count": rng.randint(0, 20), "unique_directories": rng.randint(1, 30)})
        if kind == "E2":
            if rng.random() < 0.5 * (hi - lo) / 86400.0:  # backup software rotating its own copies
                b("backup_recovery_tamper", rng.uniform(lo, hi), {"command": "vssadmin delete shadows /oldest /quiet",
                                                                  "target": "shadow_copies"})
            b("vulnerable_service_exposure", rng.uniform(lo, hi),
              {"service": rng.choice(["OpenSLP", "SMBv1", "RDP", "vCenter"]), "exposed": rng.random() < 0.5,
               "patched": rng.random() < 0.7, "severity": round(rng.uniform(0.0, 10.0), 1)})
    if kind == "E3":
        dests = [f"10.20.{rng.randint(0, 255)}.{rng.randint(1, 254)}" for _ in range(rng.randint(2, 5))]
        for t in _poisson_times(rng, 12.0, lo, hi):  # periodic beacons to the profiled destinations
            unknown = rng.random() < 0.02
            b("c2_beacon_match", t, {"destination": f"198.51.100.{rng.randint(1, 254)}" if unknown else rng.choice(dests),
                                     "known_destination": not unknown, "beacon_count": rng.randint(1, 4) if unknown else 1,
                                     "interval_s": 300})


def _merge(sc: Scenario, new, edited, unobserved, benign_incidents, profiles, cfg) -> Fase1Scenario:
    digest = sc.scenario_id.split("-", 1)[1]
    times = [datetime.fromisoformat(e["timestamp"]) for e in sc.events]
    keyed, latest = [], None
    for i, (e, ts) in enumerate(zip(sc.events, times)):
        latest = ts if latest is None or ts > latest else latest  # processing clock: existing order kept
        ev = dict(e)
        if e["event_id"] in edited:
            ev["payload"] = edited[e["event_id"]]
        keyed.append(((latest, 0, i), ev, None))
    for j, (e, tr) in enumerate(new):
        keyed.append(((datetime.fromisoformat(e["timestamp"]), 1, j), e, tr))
    keyed.sort(key=lambda x: x[0])
    truth_by_id = {t["event_id"]: t for t in sc.truth["events"]}
    events, truth_events, resolved_unobs = [], [], set()
    for n, (key, e, tr) in enumerate(keyed):
        if tr is not None:
            e = {**e, "event_id": f"{digest}-f1-{key[2]:05d}"}
            if ("new", key[2]) in unobserved:
                resolved_unobs.add(e["event_id"])
            t = {"index": n, "event_id": e["event_id"], **tr}
        else:
            t = {**truth_by_id[e["event_id"]], "index": n}
            if e["event_id"] in unobserved:
                resolved_unobs.add(e["event_id"])
        events.append(e)
        truth_events.append(t)
    incidents = {k: dict(v) for k, v in sc.truth["incidents"].items()}
    for iid, info in benign_incidents.items():
        incidents[iid] = {**info, "incident_key": f"{sc.scenario_id}::{info['host']}", "n_events": None,
                          "true_onset_time": None, "true_onset_event_id": None, "impact_onset_time": None,
                          "impact_onset_event_id": None}
    truth = {**sc.truth, "incidents": incidents, "events": truth_events,
             "fase1": {"heterogeneity": cfg.heterogeneity, "benign_hosts_per_profile": cfg.benign_hosts_per_profile,
                       "host_profiles": dict(sorted(profiles.items()))}}
    out = replace(sc, events=events, truth=truth, unobserved=frozenset(resolved_unobs))
    return Fase1Scenario(out, dict(sorted(profiles.items())), cfg)


# --- Fase 1b family: campaign_e1_e2 (docs/fase1/05_desenho_1b.md A3) ----------------------------------
CAMPAIGN_E1_E2 = "campaign_e1_e2"
P_PRE = 0.5  # frozen value of H1b (direction p_pre < 1: [16]; value SM)


def generate_campaign_e1_e2(seed: int, p_pre: float = P_PRE, heterogeneity: int = 1) -> tuple[Scenario, dict[str, str]]:
    """Initial access on a workstation (E1), lateral move to a server (E2), impact on the server.

    Every draw comes from the named stream ``"profiles"`` (scope ``campaign_e1_e2``), never from a
    scenario RNG. Returns the scenario and the pinned profiles {E1 host: "E1", E2 host: "E2"}.
    The initial access and the server logon are truth-only (``unobserved``): the logon is
    indistinguishable from a legitimate admin logon [17], so no detector sees a signal. With
    heterogeneity 0 the lateral_movement_signature (a Fase 1 event type) is not emitted (control C0)."""
    from simulation.scenario_generator import _Builder, _recon, _t1490
    from simulation.mock_managed_system import _high_entropy_bytes

    b = _Builder(CAMPAIGN_E1_E2, seed)
    rng = b.rng = stream(seed, "profiles", scope=CAMPAIGN_E1_E2)
    b.t0 = datetime(2026, 3, 1, tzinfo=b.t0.tzinfo) + timedelta(seconds=rng.uniform(0, 86_400))
    b._hosts.clear()
    h1, h2 = b.host(), b.host()
    i1, i2 = b.incident(h1, malicious=True), b.incident(h2, malicious=True)
    b.incidents[i1]["campaign"] = b.incidents[i2]["campaign"] = "c0"
    b.incidents[i2]["lateral_from"] = h1
    hidden = []

    def add(iid, etype, t, payload, stage, *, unobserved=False, encrypted=None):
        b.add(iid, etype, t, payload, malicious=True, stage=stage, encrypted=encrypted)
        if unobserved:
            hidden.append(len(b.items) - 1)

    add(i1, "privilege_escalation_attempt", 0.0, {"technique": "valid_account_runas", "target_account": "DOMAIN\\user",
                                                  "success": True}, "discovery", unobserved=True)  # initial access
    t1 = round(rng.uniform(60, 600), 1)
    add(i2, "privilege_escalation_attempt", t1, {"technique": "valid_account_runas", "target_account": "DOMAIN\\it_admin",
                                                 "success": True}, "privilege_escalation", unobserved=True)  # server logon
    t_sig = t1 + round(rng.uniform(1, 5), 1)  # host sensor of the source workstation [19]; delay SM
    sig = {"new_internal_peers": rng.randint(1, 4), "window_seconds": 60, "protocol": rng.choice(["smb", "rdp", "wmi"]),
           "peer_hosts": [h2]}
    if heterogeneity:  # drawn either way, so h = 0 (control C0) and h = 1 differ only by this event
        add(i1, "lateral_movement_signature", t_sig, sig, "privilege_escalation")
    add(i1, "network_enumeration", t1 + round(rng.uniform(60, 300), 1), _recon(rng), "discovery")
    t_imp = t1 + round(rng.uniform(600, 1800), 1)
    pre = rng.random() < p_pre
    if pre:
        add(i2, "backup_recovery_tamper", t_imp - round(rng.uniform(5, 60), 1), _t1490(rng), "inhibit_recovery")
    files, dirs = rng.randint(20, 200), rng.randint(2, 6)
    window = rng.choice([30, 60, 120])
    add(i2, "file_write", t_imp, {"content_sample": _high_entropy_bytes(rng), "original_extension": rng.choice([".vmdk", ".vmx", ".cfg"]),
                                  "new_extension": rng.choice([".locked", ".enc", ".args"]), "files_changed": files,
                                  "window_seconds": window, "unique_directories": dirs}, "impact", encrypted=True)
    add(i2, "mass_file_modification", t_imp + round(rng.uniform(2, 30), 1),
        {"files_changed": files, "window_seconds": window, "unique_directories": dirs, "rename_count": files}, "impact",
        encrypted=False)
    b.params.update({"p_pre": p_pre, "precursor": pre, "t_move": t1, "t_impact": t_imp, "heterogeneity": heterogeneity})
    marked = {id(b.items[i]) for i in hidden}
    sc = b.build()
    order = sorted(range(len(b.items)), key=lambda i: (b.items[i]["arrival"], i))
    unobs = frozenset(sc.events[n]["event_id"] for n, i in enumerate(order) if id(b.items[i]) in marked)
    return replace(sc, unobserved=unobs), {h1: "E1", h2: "E2"}


def apply_campaign_e1_e2(seed: int, cfg: Fase1Config, p_pre: float = P_PRE) -> Fase1Scenario:
    sc, pinned = generate_campaign_e1_e2(seed, p_pre, cfg.heterogeneity)
    return apply(sc, cfg, fixed_profiles=pinned, attack_transforms=False)
