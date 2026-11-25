"""Synthetic event generator standing in for the real managed system.

No detection logic lives here -- events are plain synthetic dicts with a
random severity. ``generate_events`` (below, unchanged) draws its event
``type`` values directly from whatever domain config is loaded (the union
of every specialist's ``handles`` list), so it works unmodified no matter
which of the three domain-partitioning schemes is active: it never
hardcodes scheme-specific vocabulary. It is what ``scenario_runner.py``
uses today to exercise the multi-agent graph's routing/escalation.

Additionally, this module offers two generators in ``detection``'s own raw
event vocabulary (see ``detection/early_signals.py`` and
``detection/late_signals.py`` for the event-type/payload contract) -- these
are independent of any domain config, since they are not routed through the
LangGraph dispatch layer, but built to be converted via
``detection.signals.Event.from_raw`` and fed straight into
``detection.classifier.classify()``:

  - :func:`generate_attack_sequence` -- one time-ordered, realistic
    ransomware kill-chain (recon -> privilege escalation -> T1489 service
    stop -> T1490 backup/shadow-copy tamper -> T1486 mass encryption with
    rising entropy -> ransom note creation), meant to actually exercise the
    detection module's corroboration rules end to end.
  - :func:`generate_benign_activity_stream` -- fully random, independent
    benign events (including a deliberately high-entropy-but-benign event,
    e.g. a user zipping a folder) for false-positive testing: the detection
    module must NOT flag any of this as ransomware activity.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

_SOURCES = ["host-01", "host-02", "net-seg-3", "file-share-2", "backup-vault-1"]


def _collect_event_types(domain_config: dict[str, Any]) -> list[str]:
    types: set[str] = set()
    for domain in domain_config["domains"]:
        for specialist_cfg in domain["specialists"]:
            types.update(specialist_cfg.get("handles", []))
    return sorted(types)


def generate_events(
    domain_config: dict[str, Any],
    count: int = 6,
    seed: Optional[int] = 42,
) -> list[dict[str, Any]]:
    """Generates ``count`` synthetic events routable under ``domain_config``.

    The first and last event severities are pinned (1 and 5) so a scenario
    run deterministically exercises both the "handled locally" and the
    "escalated all the way to Strategic Governance" paths, regardless of
    the random seed.
    """
    event_types = _collect_event_types(domain_config)
    if not event_types:
        raise ValueError("Domain config declares no specialist 'handles' event types.")

    rng = random.Random(seed)
    now = datetime.now(timezone.utc)

    events = []
    for i in range(count):
        events.append(
            {
                "event_id": f"evt-{i:03d}",
                "timestamp": (now + timedelta(seconds=i)).isoformat(),
                "type": rng.choice(event_types),
                "source": rng.choice(_SOURCES),
                "severity": rng.randint(1, 5),
                "payload": {"synthetic": True, "sequence": i},
            }
        )

    if count >= 2:
        events[0]["severity"] = 1
        events[-1]["severity"] = 5

    return events


# ---------------------------------------------------------------------------
# Detection-module event streams (independent of domain config / graph
# routing -- see module docstring above).
# ---------------------------------------------------------------------------


def _low_entropy_bytes(length: int = 4096) -> bytes:
    """Plaintext-like bytes (repeated ASCII text), for a benign/ordinary file write."""
    text = "The quick brown fox jumps over the lazy dog. "
    repeated = (text * (length // len(text) + 1)).encode("ascii")
    return repeated[:length]


def _high_entropy_bytes(rng: random.Random, length: int = 4096) -> bytes:
    """Near-random bytes, standing in for ciphertext (or any compressed format)."""
    return rng.randbytes(length)


def generate_attack_sequence(seed: Optional[int] = 7) -> list[dict[str, Any]]:
    """Generates one time-ordered, realistic ransomware kill-chain.

    Stages (see ``detection/README.md`` for the full MITRE ATT&CK mapping):
      1. network_enumeration        -- reconnaissance / lateral-movement recon
      2. privilege_escalation_attempt
      3. service_stop_attempt (x2)  -- T1489, EDR + backup agent
      4. backup_recovery_tamper     -- T1490, shadow-copy deletion
      5. file_write + mass_file_modification -- T1486, rising entropy,
         extension change, high rate, multi-directory spread
      6. ransom_note_creation       -- T1486, characteristic filenames across
         multiple directories

    Severity/random-noise fields used by the multi-agent skeleton's routing
    (``type`` matching a domain config's ``handles``) are intentionally
    absent here -- these events are meant for
    ``detection.signals.Event.from_raw`` + ``detection.classifier.classify``,
    not for ``graph.build_graph``'s dispatcher.
    """
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    host = "host-07"

    def ts(offset_seconds: float) -> str:
        return (now + timedelta(seconds=offset_seconds)).isoformat()

    events: list[dict[str, Any]] = [
        {
            "event_id": "atk-000",
            "timestamp": ts(0),
            "type": "network_enumeration",
            "source": host,
            "payload": {"hosts_touched": 50, "shares_touched": 5, "window_seconds": 60},
        },
        {
            "event_id": "atk-001",
            "timestamp": ts(90),
            "type": "privilege_escalation_attempt",
            "source": host,
            "payload": {
                "technique": "token_impersonation",
                "target_account": "DOMAIN\\svc_backup",
                "success": True,
            },
        },
        {
            "event_id": "atk-002",
            "timestamp": ts(150),
            "type": "service_stop_attempt",
            "source": host,
            "payload": {"process_name": "MsMpEng.exe", "process_category": "edr", "method": "taskkill /F"},
        },
        {
            "event_id": "atk-003",
            "timestamp": ts(155),
            "type": "service_stop_attempt",
            "source": host,
            "payload": {
                "process_name": "BackupAgentService",
                "process_category": "backup_agent",
                "method": "net stop",
            },
        },
        {
            "event_id": "atk-004",
            "timestamp": ts(210),
            "type": "backup_recovery_tamper",
            "source": host,
            "payload": {"command": "vssadmin delete shadows /all /quiet", "target": "shadow_copies"},
        },
        {
            "event_id": "atk-005",
            "timestamp": ts(300),
            "type": "file_write",
            "source": host,
            "payload": {
                "content_sample": _high_entropy_bytes(rng),
                "original_extension": ".docx",
                "new_extension": ".locked",
                "files_changed": 800,
                "window_seconds": 45,
                "unique_directories": 12,
            },
        },
        {
            "event_id": "atk-006",
            "timestamp": ts(305),
            "type": "mass_file_modification",
            "source": host,
            "payload": {"files_changed": 800, "window_seconds": 45, "unique_directories": 12, "rename_count": 800},
        },
        {
            "event_id": "atk-007",
            "timestamp": ts(360),
            "type": "ransom_note_creation",
            "source": host,
            "payload": {
                "file_names": [
                    "README_TO_DECRYPT.txt",
                    "HOW_TO_RESTORE_FILES.html",
                    "DECRYPT_INSTRUCTIONS.txt",
                ],
                "directories": [
                    "C:\\Users\\alice\\Documents",
                    "C:\\Users\\bob\\Documents",
                    "D:\\Shared\\Finance",
                    "D:\\Shared\\HR",
                ],
            },
        },
    ]
    return events


def generate_benign_activity_stream(count: int = 8, seed: Optional[int] = 42) -> list[dict[str, Any]]:
    """Generates fully random, independent benign events for false-positive testing.

    Includes one deliberately high-entropy-but-benign ``file_write`` (a user
    zipping a folder: high entropy, but the extension does not change and
    there is no mass/multi-directory spread) -- this is the specific case
    that proves ``detection``'s corroboration rule is doing real work rather
    than triggering on entropy alone.
    """
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    events: list[dict[str, Any]] = []

    benign_process_names = ["UpdateService", "PrintSpooler", "SearchIndexer"]

    for i in range(count):
        events.append(
            {
                "event_id": f"benign-{i:03d}",
                "timestamp": (now + timedelta(seconds=i * 5)).isoformat(),
                "type": "service_stop_attempt",
                "source": rng.choice(_SOURCES),
                "payload": {
                    "process_name": rng.choice(benign_process_names),
                    "process_category": "other",
                    "method": "sc stop",
                },
            }
        )

    events.append(
        {
            "event_id": "benign-zip",
            "timestamp": (now + timedelta(seconds=(count + 1) * 5)).isoformat(),
            "type": "file_write",
            "source": rng.choice(_SOURCES),
            "payload": {
                "content_sample": _high_entropy_bytes(rng),  # genuinely high entropy, like a real zip
                "original_extension": ".zip",
                "new_extension": ".zip",  # unchanged: no extension-change corroborator
                "files_changed": 1,
                "window_seconds": 5,
                "unique_directories": 1,  # single directory: no mass-spread corroborator
            },
        }
    )

    events.append(
        {
            "event_id": "benign-doc",
            "timestamp": (now + timedelta(seconds=(count + 2) * 5)).isoformat(),
            "type": "file_write",
            "source": rng.choice(_SOURCES),
            "payload": {
                "content_sample": _low_entropy_bytes(),
                "original_extension": ".txt",
                "new_extension": ".txt",
                "files_changed": 1,
                "window_seconds": 5,
                "unique_directories": 1,
            },
        }
    )

    events.append(
        {
            "event_id": "benign-recon",
            "timestamp": (now + timedelta(seconds=(count + 3) * 5)).isoformat(),
            "type": "network_enumeration",
            "source": rng.choice(_SOURCES),
            "payload": {"hosts_touched": 3, "shares_touched": 0, "window_seconds": 60},
        }
    )

    return events
