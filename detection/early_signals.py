"""Pre-encryption (proactive) ransomware precursor detectors.

Each function inspects a time-ordered list of :class:`detection.signals.Event`
and returns zero or more :class:`detection.signals.Signal` instances. All
thresholds are module-level constants, explicitly documented as heuristic
scaffold defaults -- they are NOT empirically calibrated against real
incident data (there is none in this repository; see
``detection/README.md`` -> "Known limitations").

Event-type contract expected in ``event.type`` / ``event.payload`` (this is
this module's own vocabulary, independent of the domain-config ``handles``
used elsewhere in the repo for graph routing):

  "network_enumeration"        payload: hosts_touched, shares_touched (opt),
                                         window_seconds
  "privilege_escalation_attempt" payload: technique, target_account, success
  "service_stop_attempt"       payload: process_name, process_category
                                         ("av" | "edr" | "backup_agent" | other),
                                         method
  "backup_recovery_tamper"     payload: command, target
                                         ("shadow_copies" | "backup_catalog" |
                                          "recovery_boot_config")
  "file_access_burst"          payload: files_touched, window_seconds,
                                         read_then_overwrite_count, rename_count,
                                         unique_directories

MITRE ATT&CK mapping notes:
  - T1489 (Service Stop) and T1490 (Inhibit System Recovery) were specified
    explicitly in the task brief and are used as-is.
  - T1018 (Remote System Discovery), T1135 (Network Share Discovery),
    T1068 (Exploitation for Privilege Escalation) and T1083 (File and
    Directory Discovery) are this module's own mapping choices, made from
    general MITRE ATT&CK familiarity because the task brief did not pin
    exact IDs for these four indicators. Cross-check these four against any
    literature review already compiled outside this repository before
    treating them as final for a publication.
"""
from __future__ import annotations

from typing import Any, Mapping, Optional

from detection.signals import Event, Signal, SignalCategory

# Fase 1: optional per-profile detector parameters (``params``, a mapping keyed by the names in
# ``DETECTOR_PARAM_DEFAULTS``). None (the default everywhere) = the module constants below, unchanged.
Params = Optional[Mapping[str, Any]]


def _p(params: Params, key: str, default: Any) -> Any:
    return default if not params or key not in params else params[key]

# --- Reconnaissance / lateral-movement enumeration -------------------------
# Heuristic: legitimate admin/inventory tooling touches hosts/shares far more
# slowly than a script sweeping a network prior to lateral movement.
RECON_HOSTS_PER_SECOND_THRESHOLD = 0.5  # > 30 hosts/minute is treated as a sweep

# --- Security-tool kill/disable (T1489) -------------------------------------
SECURITY_RELEVANT_PROCESS_CATEGORIES = {"av", "edr", "backup_agent"}

# --- Backup / recovery tamper (T1490) ---------------------------------------
# Command substrings consistently cited in CISA #StopRansomware guidance and
# general ransomware-lifecycle literature as recovery-inhibition precursors.
KNOWN_RECOVERY_INHIBITION_COMMAND_PATTERNS = (
    "vssadmin delete shadows",
    "wbadmin delete catalog",
    "bcdedit",  # e.g. "bcdedit /set {default} recoveryenabled no"
    "wmic shadowcopy delete",
)

# --- Anomalous pre-encryption file access (T1083) ---------------------------
FILE_ACCESS_RATE_THRESHOLD = 5.0  # files/second sustained access, single source
OVERWRITE_RATIO_THRESHOLD = 0.3  # fraction of touched files that were read-then-overwritten
RENAME_RATE_THRESHOLD = 2.0  # renames/second


def _events_of_type(events: list[Event], type_name: str) -> list[Event]:
    return [e for e in events if e.type == type_name]


def detect_reconnaissance_signals(events: list[Event], params: Params = None) -> list[Signal]:
    """Flags rapid enumeration across hosts or shares (lateral-movement recon)."""
    signals: list[Signal] = []
    for event in _events_of_type(events, "network_enumeration"):
        hosts_touched = event.payload.get("hosts_touched", 0)
        shares_touched = event.payload.get("shares_touched", 0)
        window_seconds = max(event.payload.get("window_seconds", 1.0), 0.001)
        rate = hosts_touched / window_seconds

        if rate <= _p(params, "recon_hosts_per_second", RECON_HOSTS_PER_SECOND_THRESHOLD):
            continue

        share_dominant = shares_touched > hosts_touched
        technique_id = "T1135" if share_dominant else "T1018"
        technique_name = "Network Share Discovery" if share_dominant else "Remote System Discovery"
        confidence = min(0.7, 0.35 + rate / 20.0)

        signals.append(
            Signal(
                ts=event.timestamp,
                source=event.source,
                signal_type="reconnaissance",
                category=SignalCategory.EARLY,
                mitre_technique_id=technique_id,
                mitre_technique_name=technique_name,
                confidence=confidence,
                summary=(
                    f"Rapid enumeration: {hosts_touched} hosts / {shares_touched} shares "
                    f"in {window_seconds:.1f}s ({rate:.2f} hosts/s) from {event.source}."
                ),
                raw_features={"hosts_touched": hosts_touched, "shares_touched": shares_touched, "rate": rate},
                contributing_event_ids=(event.event_id,),
            )
        )
    return signals


def detect_privilege_escalation_signals(events: list[Event], params: Params = None) -> list[Signal]:
    """Flags privilege-escalation attempts (rare/high-signal by nature)."""
    signals: list[Signal] = []
    for event in _events_of_type(events, "privilege_escalation_attempt"):
        technique = event.payload.get("technique", "")
        success = bool(event.payload.get("success", False))
        target_account = event.payload.get("target_account", "unknown")

        technique_id = "T1078" if "valid_account" in technique else "T1068"
        technique_name = "Valid Accounts" if technique_id == "T1078" else "Exploitation for Privilege Escalation"
        confidence = 0.6 if success else 0.4

        signals.append(
            Signal(
                ts=event.timestamp,
                source=event.source,
                signal_type="privilege_escalation",
                category=SignalCategory.EARLY,
                mitre_technique_id=technique_id,
                mitre_technique_name=technique_name,
                confidence=confidence,
                summary=(
                    f"Privilege escalation attempt against '{target_account}' via "
                    f"'{technique}' (success={success}) on {event.source}."
                ),
                raw_features={"technique": technique, "success": success, "target_account": target_account},
                contributing_event_ids=(event.event_id,),
            )
        )
    return signals


def detect_service_stop_signals(events: list[Event], params: Params = None) -> list[Signal]:
    """Flags T1489 (Service Stop) attempts against security-relevant processes.

    Only processes categorized as AV/EDR/backup-agent are flagged -- stopping
    an arbitrary, non-security-relevant service is common benign admin
    activity and is not itself a ransomware precursor.
    """
    signals: list[Signal] = []
    relevant = [
        e
        for e in _events_of_type(events, "service_stop_attempt")
        if e.payload.get("process_category") in _p(params, "security_process_categories", SECURITY_RELEVANT_PROCESS_CATEGORIES)
    ]
    distinct_categories = {e.payload.get("process_category") for e in relevant}

    for event in relevant:
        process_name = event.payload.get("process_name", "unknown")
        category = event.payload.get("process_category")
        method = event.payload.get("method", "unknown")
        confidence = 0.6 + (0.1 * (len(distinct_categories) - 1))

        signals.append(
            Signal(
                ts=event.timestamp,
                source=event.source,
                signal_type="service_stop",
                category=SignalCategory.EARLY,
                mitre_technique_id="T1489",
                mitre_technique_name="Service Stop",
                confidence=min(0.9, confidence),
                summary=(
                    f"Attempt to stop security-relevant process '{process_name}' "
                    f"(category={category}) via '{method}' on {event.source}."
                ),
                raw_features={"process_name": process_name, "process_category": category, "method": method},
                contributing_event_ids=(event.event_id,),
            )
        )
    return signals


def detect_backup_tamper_signals(events: list[Event], params: Params = None) -> list[Signal]:
    """Flags T1490 (Inhibit System Recovery): shadow-copy/backup deletion or tampering.

    One of the most consistently cited ransomware precursors in CISA
    #StopRansomware guidance -- commands like `vssadmin delete shadows` or
    `wbadmin delete catalog` are essentially always malicious in this
    context, so presence alone is treated as high-confidence.
    """
    signals: list[Signal] = []
    for event in _events_of_type(events, "backup_recovery_tamper"):
        command = event.payload.get("command", "")
        target = event.payload.get("target", "unknown")
        matches_known_pattern = any(p in command.lower() for p in KNOWN_RECOVERY_INHIBITION_COMMAND_PATTERNS)
        confidence = 0.85 if matches_known_pattern else 0.6

        signals.append(
            Signal(
                ts=event.timestamp,
                source=event.source,
                signal_type="backup_recovery_tamper",
                category=SignalCategory.EARLY,
                mitre_technique_id="T1490",
                mitre_technique_name="Inhibit System Recovery",
                confidence=confidence,
                summary=f"Recovery-inhibition command targeting {target} on {event.source}: '{command}'.",
                raw_features={"command": command, "target": target, "matches_known_pattern": matches_known_pattern},
                contributing_event_ids=(event.event_id,),
            )
        )
    return signals


def detect_file_access_anomaly_signals(events: list[Event], params: Params = None) -> list[Signal]:
    """Flags anomalous pre-encryption file-access patterns (T1083-adjacent).

    Requires an elevated access RATE *and* an elevated overwrite or rename
    ratio -- rate alone is not used, since legitimate backup/indexing jobs
    can also produce high raw file-access counts without the
    read-then-overwrite or mass-rename pattern typical of a ransomware
    binary walking a directory tree just before encrypting it.
    """
    signals: list[Signal] = []
    for event in _events_of_type(events, "file_access_burst"):
        files_touched = event.payload.get("files_touched", 0)
        window_seconds = max(event.payload.get("window_seconds", 1.0), 0.001)
        overwrite_count = event.payload.get("read_then_overwrite_count", 0)
        rename_count = event.payload.get("rename_count", 0)

        access_rate = files_touched / window_seconds
        overwrite_ratio = overwrite_count / files_touched if files_touched else 0.0
        rename_rate = rename_count / window_seconds

        rate_high = access_rate > _p(params, "file_access_rate", FILE_ACCESS_RATE_THRESHOLD)
        overwrite_high = overwrite_ratio > _p(params, "overwrite_ratio", OVERWRITE_RATIO_THRESHOLD)
        rename_high = rename_rate > _p(params, "rename_rate", RENAME_RATE_THRESHOLD)

        if not (rate_high and (overwrite_high or rename_high)):
            continue

        confidence = 0.4 + (0.15 if overwrite_high else 0.0) + (0.15 if rename_high else 0.0)

        signals.append(
            Signal(
                ts=event.timestamp,
                source=event.source,
                signal_type="file_access_anomaly",
                category=SignalCategory.EARLY,
                mitre_technique_id="T1083",
                mitre_technique_name="File and Directory Discovery",
                confidence=min(0.7, confidence),
                summary=(
                    f"Anomalous file access on {event.source}: {files_touched} files in "
                    f"{window_seconds:.1f}s ({access_rate:.1f}/s), overwrite_ratio="
                    f"{overwrite_ratio:.2f}, rename_rate={rename_rate:.2f}/s."
                ),
                raw_features={
                    "files_touched": files_touched,
                    "access_rate": access_rate,
                    "overwrite_ratio": overwrite_ratio,
                    "rename_rate": rename_rate,
                },
                contributing_event_ids=(event.event_id,),
            )
        )
    return signals


# --- Fase 1 network / exposure detectors (01_especializacoes.md, table 2(b)) -------------------
# They only fire on event types that no generator emits unless Fase 1 heterogeneity is ON
# (``c2_beacon_match``, ``lateral_movement_signature``, ``vulnerable_service_exposure``), so every
# earlier result is unchanged. Thresholds are modelling assumptions; ATT&CK IDs are internal labels.
C2_MIN_BEACONS = 3  # periodic connections to a destination outside the host's learned network profile
LATERAL_MIN_NEW_PEERS = 3  # new internal peers contacted within the event's window
EXPOSURE_MIN_SEVERITY = 7.0  # 0-10 scale, exposed and unpatched service


def detect_c2_beacon_signals(events: list[Event], params: Params = None) -> list[Signal]:
    """Beaconing to a destination the host's network profile has never used (profile deviation)."""
    signals: list[Signal] = []
    for event in _events_of_type(events, "c2_beacon_match"):
        beacons = event.payload.get("beacon_count", 0)
        known = bool(event.payload.get("known_destination", True))
        if known or beacons < _p(params, "c2_min_beacons", C2_MIN_BEACONS):
            continue
        signals.append(Signal(
            ts=event.timestamp, source=event.source, signal_type="c2_beacon", category=SignalCategory.EARLY,
            mitre_technique_id="T1071", mitre_technique_name="Application Layer Protocol", confidence=0.6,
            summary=f"{beacons} beacons to unprofiled destination {event.payload.get('destination')} from {event.source}.",
            raw_features={"beacon_count": beacons, "destination": event.payload.get("destination")},
            contributing_event_ids=(event.event_id,),
        ))
    return signals


def detect_lateral_movement_signals(events: list[Event], params: Params = None) -> list[Signal]:
    """Connections to several internal peers the host has not contacted before."""
    signals: list[Signal] = []
    for event in _events_of_type(events, "lateral_movement_signature"):
        peers = event.payload.get("new_internal_peers", 0)
        if peers < _p(params, "lateral_min_new_peers", LATERAL_MIN_NEW_PEERS):
            continue
        signals.append(Signal(
            ts=event.timestamp, source=event.source, signal_type="lateral_movement", category=SignalCategory.EARLY,
            mitre_technique_id="T1021", mitre_technique_name="Remote Services", confidence=0.6,
            summary=f"{peers} new internal peers via {event.payload.get('protocol')} from {event.source}.",
            raw_features={"new_internal_peers": peers}, contributing_event_ids=(event.event_id,),
        ))
    return signals


def detect_vulnerable_exposure_signals(events: list[Event], params: Params = None) -> list[Signal]:
    """An exposed, unpatched service at or above the severity threshold (proactive server signal)."""
    signals: list[Signal] = []
    for event in _events_of_type(events, "vulnerable_service_exposure"):
        p = event.payload
        severity = float(p.get("severity", 0.0))
        if not p.get("exposed") or p.get("patched") or severity < _p(params, "exposure_min_severity", EXPOSURE_MIN_SEVERITY):
            continue
        signals.append(Signal(
            ts=event.timestamp, source=event.source, signal_type="vulnerable_exposure", category=SignalCategory.EARLY,
            mitre_technique_id="T1190", mitre_technique_name="Exploit Public-Facing Application", confidence=0.5,
            summary=f"Exposed unpatched service {p.get('service')} (severity {severity}) on {event.source}.",
            raw_features={"service": p.get("service"), "severity": severity}, contributing_event_ids=(event.event_id,),
        ))
    return signals


def detect_all_early_signals(events: list[Event], params: Params = None) -> list[Signal]:
    """Runs every early-signal detector and returns the combined, time-ordered list."""
    signals: list[Signal] = []
    signals.extend(detect_reconnaissance_signals(events, params))
    signals.extend(detect_privilege_escalation_signals(events, params))
    signals.extend(detect_service_stop_signals(events, params))
    signals.extend(detect_backup_tamper_signals(events, params))
    signals.extend(detect_file_access_anomaly_signals(events, params))
    signals.extend(detect_c2_beacon_signals(events, params))
    signals.extend(detect_lateral_movement_signals(events, params))
    signals.extend(detect_vulnerable_exposure_signals(events, params))
    signals.sort(key=lambda s: s.ts)
    return signals
