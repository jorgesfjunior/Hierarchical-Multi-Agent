"""SYNTHETIC per-file write streams for the entropy-onset experiment.

The existing generators (``mock_managed_system``) carry exactly ONE
``file_write`` sample in the attack, so a proportion-over-a-window signal
cannot be computed on them. This module is a NEW, additive source of
per-file ``file_write`` events; nothing else in the repo is changed. Every
event here is invented by this generator: its outcomes depend on the choices
below (ramp shape, which auxiliary fields the sensor provides), so results
must be reported per variant, never as one number.

Variants
  ramp     "abrupt"  : every write after onset is encrypted
           "gradual" : probability of an encrypted write rises 0.15 -> 1.0
  variant  "rich"    : each write also carries the fields the LEGACY detector
                       uses for its corroboration (extension change, trailing-5s
                       ``files_changed``/``unique_directories``)
           "inplace" : like "rich" but the extension NEVER changes (in-place
                       encryption; the extension-change corroborator is absent)
           "bare"    : path + size + content_sample only (a raw write sensor)

Ground truth (which writes were really encrypted) is returned SEPARATELY and
never placed in an event payload.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from simulation.mock_managed_system import _high_entropy_bytes, _low_entropy_bytes

_DIRS = [f"C:\\Users\\u{i}\\Documents" for i in range(6)]
_HOST = "host-07"


class _WriteStream:
    def __init__(self, start: datetime, variant: str, seed: int, prefix: str, host: str = _HOST):
        self.start, self.variant, self.rng, self.prefix, self.host = start, variant, random.Random(seed), prefix, host
        self.events: list[dict[str, Any]] = []
        self.truth: list[bool] = []
        self._recent: list[tuple[float, str]] = []  # (t, dir) of writes, for trailing-5s aggregates

    def write(self, t: float, *, compressed_or_encrypted: bool, encrypted_truth: bool, ext: str, new_ext: Optional[str] = None) -> None:
        directory = _DIRS[len(self.events) % len(_DIRS)]
        self._recent = [(rt, d) for rt, d in self._recent if t - rt < 5.0] + [(t, directory)]
        content = _high_entropy_bytes(self.rng) if compressed_or_encrypted else _low_entropy_bytes()
        payload: dict[str, Any] = {"path": f"{directory}\\f{len(self.events):04d}{ext}", "size": len(content), "content_sample": content}
        if self.variant in ("rich", "inplace"):
            payload.update(
                original_extension=ext,
                new_extension=ext if self.variant == "inplace" else (new_ext or ext),
                files_changed=len(self._recent),
                window_seconds=5.0,
                unique_directories=len({d for _, d in self._recent}),
            )
        self.events.append(
            {
                "event_id": f"{self.prefix}-{len(self.events):04d}",
                "timestamp": (self.start + timedelta(seconds=t)).isoformat(),
                "type": "file_write",
                "source": self.host,
                "payload": payload,
            }
        )
        self.truth.append(encrypted_truth)


def generate_encryption_stream(
    *,
    ramp: str = "abrupt",
    variant: str = "rich",
    seed: int = 7,
    start: Optional[datetime] = None,
    n_background: int = 30,
    background_interval: float = 2.0,
    burst_writes: int = 80,
    burst_rate: float = 4.0,
    burst_start: float = 70.0,
    host: str = _HOST,
    t1490_command: str = "vssadmin delete shadows /all /quiet",
) -> tuple[list[dict[str, Any]], list[bool]]:
    """T1490 at t=0, 30 plaintext background writes (t=5..63s), then an 80-write
    encryption burst at 4 writes/s starting t=70s.

    The keyword parameters (defaults = the layout above, byte-for-byte) let
    ``simulation.scenario_generator`` vary the stream per seed."""
    assert ramp in ("abrupt", "gradual") and variant in ("rich", "bare", "inplace")
    start = start or datetime.now(timezone.utc)
    s = _WriteStream(start, variant, seed, f"enc-{ramp}-{variant}", host=host)
    s.events.append(
        {
            "event_id": "enc-t1490",
            "timestamp": start.isoformat(),
            "type": "backup_recovery_tamper",
            "source": host,
            "payload": {"command": t1490_command, "target": "shadow_copies"},
        }
    )
    s.truth.append(False)
    for i in range(n_background):
        s.write(5 + background_interval * i, compressed_or_encrypted=False, encrypted_truth=False, ext=".docx")
    n = burst_writes
    for i in range(n):
        p = 1.0 if ramp == "abrupt" else 0.15 + 0.85 * i / max(1, n - 1)
        enc = s.rng.random() < p
        s.write(burst_start + i / burst_rate, compressed_or_encrypted=enc, encrypted_truth=enc, ext=".docx", new_ext=".locked" if enc else ".docx")
    return s.events, s.truth


def generate_benign_lookalikes(*, seed: int = 11, start: Optional[datetime] = None) -> dict[str, list[dict[str, Any]]]:
    """Benign high-entropy activity. All use the 'rich' variant (the most
    legacy-favorable) with unchanged extensions, so legacy sees no corroborator."""
    start = start or datetime.now(timezone.utc)
    out: dict[str, list[dict[str, Any]]] = {}

    def background(s: _WriteStream) -> None:
        for i in range(30):
            s.write(5 + 2 * i, compressed_or_encrypted=False, encrypted_truth=False, ext=".docx")

    s = _WriteStream(start, "rich", seed, "lk-single"); background(s)
    s.write(70, compressed_or_encrypted=True, encrypted_truth=False, ext=".zip")  # one large already-compressed write
    out["single_large_compressed_write"] = s.events

    s = _WriteStream(start, "rich", seed, "lk-few"); background(s)
    for k in range(3):
        s.write(70 + 0.5 * k, compressed_or_encrypted=True, encrypted_truth=False, ext=".zip")  # three zips in a window
    out["few_compressed_files"] = s.events

    s = _WriteStream(start, "rich", seed, "lk-mixed")
    for i in range(240):  # steady mixed workload, ~20% compressed, 4 writes/s
        s.write(5 + 0.25 * i, compressed_or_encrypted=s.rng.random() < 0.2, encrypted_truth=False, ext=".dat")
    out["mixed_workload_20pct_compressed"] = s.events

    s = _WriteStream(start, "rich", seed, "lk-cold")
    for i in range(80):  # archive/backup job copying compressed files, starting from idle
        s.write(70 + 0.25 * i, compressed_or_encrypted=True, encrypted_truth=False, ext=".zip")
    out["cold_start_compressed_burst"] = s.events
    return out
