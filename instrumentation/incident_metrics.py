"""ONE shared, log-based definition of the Phase 3 metrics, applied identically to
every architecture (MAS, B1, B2). Input: the parsed ``events.jsonl`` records.

Primary metrics, per incident (offsets from the incident's start, both in
scenario seconds and in event index within the incident; ``delay_s`` is the
system's response delay after the triggering event, used for load analysis):

  first detection
      the earliest ``analysis`` record with ``is_ransomware_activity=True`` at
      ANY node of the architecture, ordered by completion time
      ``event_ts + sim_delay_s`` (ties: log order). Reported: time offset,
      index of the triggering event, node.
  first containment dispatched
      the earliest ``action_dispatched`` record with ``on_flagged_verdict=True``
      (a containment the architecture carried out BECAUSE it had detected),
      ordered by arrival at the host ``event_ts + sim_delay_s``.
      ``first_any_containment`` (secondary) also counts precautionary
      dispatches on unflagged evidence (MAS specialist/coordinator
      ``local_containment`` on a single weak signal) -- these exist only in the
      MAS's vocabulary, so they are NOT comparable and never primary.

Overhead (per incident): only ``message_sent`` records are counted (never
``report_received`` / ``escalation_received``, which are the receiving side of
the same message); ``payload_size_bytes`` is summed separately. B1 and B2 emit
no ``message_sent`` by construction (no inter-agent messages); transport-level
link crossings are reported separately by ``simulation/transport.py``.

Damage / protection (Phase 4; ``damage_outcomes``), per malicious campaign (keyed by
its patient-zero incident; a single-host incident is a campaign of one), from
the attacker model ``simulation/damage_model.py`` driven by the actions listed on
the run's ``action_dispatched`` records (every action counts, flagged or
precautionary: damage depends on what was done, not why). Needs runs with policy
``damage_model`` ON (B1/B2 list no actions otherwise; counted in
``dispatches_without_actions``). Times in seconds from the incident's onset:

  files_encrypted_before_containment  files encrypted on every host of the incident
      by containment (every observed foothold isolated or its process killed;
      patient zero alone for a single-host incident), or by the horizon if never
  files_encrypted                      by the horizon (encryption that outlives an
      isolation, and on hosts reached by lateral spread, counts here)
  data_loss                            files encrypted and not restored by the horizon
  stage_at_containment                 kill-chain stage reached at containment
  hosts_compromised                    footholds by the horizon (patient zero included)
  attacker_dwell_time                  onset -> no active foothold (censored at the horizon)
  time_to_restore (RTO)                impact onset -> every encrypted observed host
      restored after its encryption stopped (None if never)
  frac_encrypted[_before_containment]  the file counts / (files_per_host x hosts_compromised)
  <metric>_pct_nodef                   100 x the metric / the NO-DEFENSE arm's value for the
      same incident, parameters and horizon (``no_defense_outcomes``; None if that is 0)
Per run: ``benign_hosts_isolated`` (distinct hosts of benign truth incidents that
received ``isolate_host``: self-inflicted unavailability) and the Phase 4c isolation
metrics of ``run_isolation_metrics`` (``benign_host_downtime``, ``releases``,
``wrongful_releases``, ``re_isolations``). ``classification``:
incident-level precision / recall / F1 for three bases ("detection": a flagged
analysis anywhere; "flagged_containment"; "any_containment": any dispatch).

Decision-label counts (``decision_label_counts``) are SECONDARY and NOT
comparable across architectures: the same verdict maps to different labels
(e.g. B1 ``local_containment`` vs MAS ``global_containment_directive`` for an
early flagged verdict; see ``instrumentation/proactive_metric.py``).
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any, Iterable, Optional

from instrumentation.metrics import ACTION_DISPATCHED_EVENT, ANALYSIS_EVENT


def load_records(path: str) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


def record_time(record: dict[str, Any]) -> datetime:
    """Completion (analysis) or arrival-at-host (dispatch) time of a record."""
    p = record["payload"]
    from datetime import timedelta

    return _ts(p["event_ts"]) + timedelta(seconds=float(p.get("sim_delay_s") or 0.0))


def incident_frames(scenario) -> dict[str, dict[str, Any]]:
    """{incident_key: {"start": iso, "index": {event_id: index within incident}}} from a generated Scenario."""
    from simulation.scenario_generator import incident_key

    frames: dict[str, dict[str, Any]] = {}
    for ev in scenario.events:
        f = frames.setdefault(incident_key(scenario.scenario_id, ev), {"start": ev["timestamp"], "index": {}})
        f["index"][ev["event_id"]] = len(f["index"])
        if _ts(ev["timestamp"]) < _ts(f["start"]):
            f["start"] = ev["timestamp"]
    return frames


def _frames_from_logs(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    frames: dict[str, dict[str, Any]] = {}
    for r in records:
        if r["event_type"] not in (ANALYSIS_EVENT, ACTION_DISPATCHED_EVENT):
            continue
        p = r["payload"]
        f = frames.setdefault(r["incident_id"], {"start": p["event_ts"], "index": {}})
        f["index"].setdefault(p["event_id"], len(f["index"]))
        if _ts(p["event_ts"]) < _ts(f["start"]):
            f["start"] = p["event_ts"]
    return frames


def _first(records: Iterable[tuple[int, dict[str, Any]]], frame: dict[str, Any]) -> Optional[dict[str, Any]]:
    best = min(records, key=lambda ir: (record_time(ir[1]), ir[0]), default=None)
    if best is None:
        return None
    r = best[1]
    return {
        "time_s": (record_time(r) - _ts(frame["start"])).total_seconds(),
        "event_index": frame["index"].get(r["payload"]["event_id"]),
        "event_id": r["payload"]["event_id"],
        "node": r["payload"]["node"],
        "layer": r["layer"],
        # response delay: from the triggering event occurring to this analysis completing /
        # this dispatch reaching the host (0 at zero cost). Load-sensitive, scenario-independent.
        "delay_s": float(r["payload"].get("sim_delay_s") or 0.0),
    }


def incident_outcomes(
    records: list[dict[str, Any]], frames: Optional[dict[str, dict[str, Any]]] = None
) -> dict[str, dict[str, Any]]:
    """Per-incident first detection / first containment / overhead (see module docstring).

    ``frames`` (incident start and per-incident event index, e.g. from
    ``incident_frames(scenario)``) should come from the scenario, not the logs,
    so that events an architecture never received still count in the index.
    """
    frames = frames or _frames_from_logs(records)
    by_incident: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    for i, r in enumerate(records):
        by_incident[r["incident_id"]].append((i, r))
    out = {}
    for incident, frame in frames.items():
        rs = by_incident.get(incident, [])
        flagged = [(i, r) for i, r in rs if r["event_type"] == ANALYSIS_EVENT and r["payload"]["is_ransomware_activity"]]
        dispatched = [(i, r) for i, r in rs if r["event_type"] == ACTION_DISPATCHED_EVENT]
        sent = [r for _, r in rs if r["event_type"] == "message_sent"]
        out[incident] = {
            "first_detection": _first(flagged, frame),
            "first_containment": _first([(i, r) for i, r in dispatched if r["payload"]["on_flagged_verdict"]], frame),
            "first_any_containment": _first(dispatched, frame),
            "messages_sent": len(sent),
            "message_bytes": sum(r["payload_size_bytes"] for r in sent),
            "n_analyses": sum(1 for _, r in rs if r["event_type"] == ANALYSIS_EVENT),
            "n_dispatches": len(dispatched),
        }
    return out


def decision_label_counts(decisions: Iterable[dict[str, Any]]) -> Counter:
    """SECONDARY, not comparable across architectures (see module docstring)."""
    return Counter(d["decision"] for d in decisions)


def retime(records: list[dict[str, Any]], plans) -> list[dict[str, Any]]:
    """Copies of ``records`` with ``sim_delay_s`` recomputed from transport ``plans``.

    Valid ONLY when the run that produced ``records`` delivered every event to
    every node (no loss, no faults): then the cost model changes timing but not
    decisions, so one zero-cost run can be re-timed for any latency/service
    point. ``tests/test_phase3.py`` checks this equals a live run."""
    timing = {(p.event_id, node): p.sim(node) for p in plans for node in p.timing}
    out = []
    for r in records:
        if r["event_type"] in (ANALYSIS_EVENT, ACTION_DISPATCHED_EVENT):
            p = r["payload"]
            sim = timing[(p["event_id"], p["node"])]
            key = "analysis_delay" if r["event_type"] == ANALYSIS_EVENT else "dispatch_delay"
            r = {**r, "payload": {**p, "sim_delay_s": sim[key]}}
        out.append(r)
    return out


# --- Phase 4: damage / protection ----------------------------------------------------------
DAMAGE_FIELDS = (
    "files_encrypted_before_containment", "files_encrypted", "data_loss", "stage_at_containment",
    "hosts_compromised", "attacker_dwell_time", "time_to_restore",
    "frac_encrypted_before_containment", "frac_encrypted",
)
# Damage metrics expressed relative to the NO-DEFENSE arm (same incident, parameters, horizon).
PCT_FIELDS = ("files_encrypted_before_containment", "files_encrypted", "data_loss", "hosts_compromised",
              "attacker_dwell_time", "frac_encrypted")
CLASSIFICATION_BASES = ("detection", "flagged_containment", "any_containment")


RUN_FIELDS = ("benign_hosts_isolated", "benign_host_downtime", "releases", "benign_releases", "wrongful_releases",
              "re_isolations", "leases", "confirmed_leases")


def run_isolation_metrics(scenario, net, attacks, params) -> dict[str, Any]:
    """Per-run isolation metrics (Phase 4c tiered response; also defined with it OFF).

    ``benign_host_downtime``: simulated seconds each benign host is isolated within [its incident's
    first event, + horizon], summed over benign hosts. ``releases``: isolation releases on any host
    within its window; ``benign_releases`` the benign ones; ``wrongful_releases``: releases on a
    malicious campaign's hosts while its attacker was not evicted; ``re_isolations``: isolations that
    start after an earlier release of the same host. ``leases`` / ``confirmed_leases``: precautionary
    containment actions given a lease / confirmed in time."""
    from simulation.damage_model import scenario_clock

    _, true_t, _ = scenario_clock(scenario)
    first: dict[str, float] = {}
    for e in scenario.events:
        first[e["source"]] = min(first.get(e["source"], float("inf")), true_t[e["event_id"]])
    benign = {i["host"] for i in scenario.truth["incidents"].values() if not i["malicious"]}
    hosts = set(first)
    window = {h: (first[h], first[h] + params.horizon_s) for h in hosts}
    releases = {h: len(net.releases(h, window[h][1])) for h in hosts}
    return {
        "benign_hosts_isolated": len(benign & set(net.isolated)),
        "benign_host_downtime": sum(net.downtime(h, *window[h]) for h in benign if h in window),
        "releases": sum(releases.values()),
        "benign_releases": sum(releases[h] for h in benign if h in releases),
        "wrongful_releases": sum(a.wrongful_releases for a in attacks.values()),
        "re_isolations": sum(sum(1 for st, _ in net.iso.get(h, ())[1:] if st <= window[h][1]) for h in hosts),
        "leases": net.leases,
        "confirmed_leases": net.confirmed_leases,
    }


def damage_outcomes(records: list[dict[str, Any]], scenario, params=None) -> dict[str, Any]:
    """``{"incidents": {incident_key: AttackOutcome dict}, "run": {...}}`` (see module docstring)."""
    from simulation.damage_model import DamageParams, simulate

    params = params or DamageParams()
    attacks, net = simulate(scenario, records, params)
    benign_hosts = {i["host"] for i in scenario.truth["incidents"].values() if not i["malicious"]}
    return {
        "incidents": {k: o.as_dict() for k, o in attacks.items()},
        "run": {
            **run_isolation_metrics(scenario, net, attacks, params),
            "benign_hosts": len(benign_hosts),
            "actions_applied": net.actions_applied,
            "dispatches_without_actions": net.dispatches_without_actions,
        },
    }


def no_defense_outcomes(scenario, params=None) -> dict[str, dict[str, Any]]:
    """The NO-DEFENSE arm: the damage model with no mitigation at all (architecture-independent)."""
    from simulation.damage_model import simulate

    attacks, _ = simulate(scenario, [], params)
    return {k: o.as_dict() for k, o in attacks.items()}


def pct_of_no_defense(outcome: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Optional[float]]:
    """``<metric>_pct_nodef`` = 100 x arm / no-defense for the same incident (None when no-defense is 0).
    Protection (damage avoided) = 100 - pct."""
    out = {}
    for m in PCT_FIELDS:
        base = baseline.get(m)
        out[f"{m}_pct_nodef"] = None if not base else 100.0 * outcome[m] / base
    return out


def _ratio(num: int, den: int) -> Optional[float]:
    return num / den if den else None


def classification(outcomes: dict[str, dict[str, Any]], truth: dict[str, bool]) -> dict[str, dict[str, Any]]:
    """Incident-level confusion counts and precision / recall / F1 per basis.

    ``outcomes``: ``incident_outcomes(...)``; ``truth``: {incident_key: malicious}
    over every incident to score (an incident with no records is a negative
    prediction). Undefined ratios (0/0) are None.
    """
    predicted = {
        "detection": lambda o: o["first_detection"] is not None,
        "flagged_containment": lambda o: o["first_containment"] is not None,
        "any_containment": lambda o: o["first_any_containment"] is not None,
    }
    out = {}
    for basis, pred in predicted.items():
        c = Counter()
        for key, malicious in truth.items():
            o = outcomes.get(key)
            p = bool(o) and pred(o)
            c[("tp" if malicious else "fp") if p else ("fn" if malicious else "tn")] += 1
        precision, recall = _ratio(c["tp"], c["tp"] + c["fp"]), _ratio(c["tp"], c["tp"] + c["fn"])
        f1 = None if precision is None or recall is None else (2 * precision * recall / (precision + recall) if precision + recall else 0.0)
        out[basis] = {"tp": c["tp"], "fp": c["fp"], "fn": c["fn"], "tn": c["tn"],
                      "precision": precision, "recall": recall, "f1": f1}
    return out


def scenario_truth(scenario) -> dict[str, bool]:
    """{incident_key: malicious} from a generated Scenario's ground truth."""
    return {i["incident_key"]: i["malicious"] for i in scenario.truth["incidents"].values()}
