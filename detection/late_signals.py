"""Encryption-in-progress (reactive) ransomware detectors -- MITRE ATT&CK T1486
(Data Encrypted for Impact).

THE CENTRAL DESIGN RULE OF THIS MODULE: entropy alone never triggers a
signal. High Shannon entropy is a necessary but explicitly INSUFFICIENT
condition -- ordinary compressed/already-encoded formats (zip, jpg, mp4,
already-encrypted archives, TLS traffic captures, etc.) also sit near the
theoretical maximum of ~8 bits/byte, and using entropy as a sole trigger is
a well-documented false-positive source in ransomware-detection literature.

``detect_encryption_entropy_signal`` therefore requires real, correctly
computed Shannon entropy (:func:`shannon_entropy`, over actual byte
content -- never a faked/precomputed number) to be high AND at least
``MIN_CORROBORATING_BEHAVIORAL_SIGNALS`` (default 2) of the following three
independent behavioral indicators to also hold in the same event:

  1. the file's extension changed or was removed (ransomware binaries
     typically rewrite files with a new/foreign extension, or strip it)
  2. the file-modification RATE in the observation window is elevated
     versus an (illustrative, non-learned) baseline
  3. the change spans many files across many directories in a short window
     (a single high-entropy file, e.g. a user's zip archive, does not)

This mirrors the task brief's own example rule (entropy rising AND
extension changed AND high modification rate AND multi-directory spread),
relaxed from requiring all four to requiring entropy plus a documented
minimum of the three corroborators, so the detector still fires on
ransomware variants that skip exactly one of the three behaviors (e.g. some
families do not change the extension) while still rejecting a lone
high-entropy benign event. This 2-of-3 threshold is a documented design
choice, not an empirically calibrated one -- see
``detection/README.md`` -> "Known limitations".

Event-type contract expected in ``event.type`` / ``event.payload``:

  "file_write"              payload: content_sample (bytes), original_extension
                                      (str | None), new_extension (str | None),
                                      files_changed (int, optional window
                                      aggregate), window_seconds (float,
                                      optional), unique_directories (int,
                                      optional)
  "mass_file_modification"  payload: files_changed, window_seconds,
                                      unique_directories, rename_count
  "ransom_note_creation"    payload: file_names (list[str]), directories (list[str])
"""
from __future__ import annotations

import functools
import math
import re
from collections import Counter
from typing import Any

from detection.signals import Event, Signal, SignalCategory

# --- Shannon entropy ---------------------------------------------------------
# Near-random byte streams (ciphertext, already-compressed data) approach the
# theoretical maximum of 8.0 bits/byte for a byte-valued alphabet. This
# threshold is deliberately conservative (close to the max) precisely because
# entropy is only the FIRST of two required conditions below.
ENTROPY_HIGH_THRESHOLD_BITS_PER_BYTE = 7.5

# --- Corroborating behavioral signals for encryption-in-progress -----------
MIN_CORROBORATING_BEHAVIORAL_SIGNALS = 2

# Illustrative, non-learned baseline for "ordinary" background file
# modification activity on a single host. A production system would learn
# this per-host/per-share via a rolling window (e.g. an EWMA over historical
# telemetry) rather than hardcoding it -- see README "Known limitations".
BASELINE_FILES_PER_SECOND = 2.0
MASS_MODIFICATION_RATE_MULTIPLIER = 5.0  # anomalous if rate > multiplier * baseline
MIN_DIRECTORIES_FOR_MASS_SPREAD = 3

# Common ransom-note naming patterns cited across multiple ransomware
# families in public incident write-ups (illustrative, not an exhaustive or
# up-to-date signature list -- see README "Known limitations").
RANSOM_NOTE_FILENAME_PATTERN = re.compile(
    r"(?i)(read[_\-]?me|decrypt|how[_\-]?to[_\-]?(decrypt|restore|recover)|ransom|restore[_\-]?files)"
    r".*\.(txt|html?|hta)$"
)


def shannon_entropy(data: bytes) -> float:
    """Computes the Shannon entropy, in bits per byte, of ``data``.

    Real implementation over the actual byte content: builds a frequency
    table of the 256 possible byte values and applies
    H = -sum(p_i * log2(p_i)). Returns 0.0 for empty input. Maximum possible
    value is 8.0 (every byte value equally likely, e.g. true ciphertext).

    Memoized (performance only): the result is a pure function of the value of
    ``data``, and the architectures that re-analyse a whole incident prefix on
    every event recompute it for the same samples many times. Unhashable input
    (e.g. ``bytearray``) is computed directly. Equality with the uncached
    computation is tested (``tests/test_entropy_memo.py``).
    """
    try:
        return _shannon_entropy_cached(data)
    except TypeError:  # unhashable input, or not iterable (re-raised identically below)
        return _shannon_entropy_uncached(data)


def _shannon_entropy_uncached(data: bytes) -> float:
    """The original computation, unchanged."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


_shannon_entropy_cached = functools.lru_cache(maxsize=65536, typed=True)(_shannon_entropy_uncached)


def _p(params: Any, key: str, default: Any) -> Any:  # Fase 1 per-profile override; None = the constants
    return default if not params or key not in params else params[key]


def _events_of_type(events: list[Event], type_name: str) -> list[Event]:
    return [e for e in events if e.type == type_name]


def detect_encryption_entropy_signal(events: list[Event], params: Any = None) -> list[Signal]:
    """Flags T1486 encryption-in-progress: high entropy + behavioral corroboration.

    Never fires on entropy alone -- see module docstring. If a
    ``file_write`` event has high entropy but fewer than
    ``MIN_CORROBORATING_BEHAVIORAL_SIGNALS`` corroborators, this function
    deliberately emits NO signal for it (not even a low-confidence one),
    so a lone high-entropy benign event (e.g. a user zipping a folder)
    never contributes to a positive verdict.
    """
    signals: list[Signal] = []
    for event in _events_of_type(events, "file_write"):
        content_sample = event.payload.get("content_sample", b"")
        entropy = shannon_entropy(content_sample)
        entropy_high = entropy >= _p(params, "entropy_high_bits", ENTROPY_HIGH_THRESHOLD_BITS_PER_BYTE)
        if not entropy_high:
            continue

        original_extension = event.payload.get("original_extension")
        new_extension = event.payload.get("new_extension")
        extension_changed = original_extension is not None and new_extension != original_extension

        files_changed = event.payload.get("files_changed")
        window_seconds = event.payload.get("window_seconds")
        rate_high = (
            files_changed is not None
            and window_seconds
            and (files_changed / window_seconds) > (_p(params, "baseline_files_per_second", BASELINE_FILES_PER_SECOND)
                                                    * _p(params, "mass_rate_multiplier", MASS_MODIFICATION_RATE_MULTIPLIER))
        )

        unique_directories = event.payload.get("unique_directories", 0)
        multi_directory = unique_directories >= _p(params, "min_directories", MIN_DIRECTORIES_FOR_MASS_SPREAD)

        corroborators = [extension_changed, bool(rate_high), multi_directory]
        corroboration_count = sum(corroborators)

        if corroboration_count < _p(params, "min_corroborating", MIN_CORROBORATING_BEHAVIORAL_SIGNALS):
            continue

        confidence = min(0.95, 0.5 + 0.15 * corroboration_count)

        signals.append(
            Signal(
                ts=event.timestamp,
                source=event.source,
                signal_type="encryption_entropy",
                category=SignalCategory.LATE,
                mitre_technique_id="T1486",
                mitre_technique_name="Data Encrypted for Impact",
                confidence=confidence,
                summary=(
                    f"High-entropy file write on {event.source} "
                    f"(entropy={entropy:.2f} bits/byte, extension_changed={extension_changed}, "
                    f"rate_high={bool(rate_high)}, multi_directory={multi_directory}); "
                    f"{corroboration_count}/3 corroborating behavioral signals."
                ),
                raw_features={
                    "entropy_bits_per_byte": entropy,
                    "extension_changed": extension_changed,
                    "rate_high": bool(rate_high),
                    "multi_directory": multi_directory,
                    "corroboration_count": corroboration_count,
                },
                contributing_event_ids=(event.event_id,),
            )
        )
    return signals


def detect_mass_modification_signal(events: list[Event], params: Any = None) -> list[Signal]:
    """Flags T1486 via mass file modification/rename rate exceeding a baseline.

    Requires BOTH an elevated rate AND spread across multiple directories --
    a single large benign copy/move within one directory can also produce a
    high raw rate, but recursive, cross-directory modification in a short
    window is much more specific to a ransomware binary walking a filesystem
    tree.
    """
    signals: list[Signal] = []
    for event in _events_of_type(events, "mass_file_modification"):
        files_changed = event.payload.get("files_changed", 0)
        window_seconds = max(event.payload.get("window_seconds", 1.0), 0.001)
        unique_directories = event.payload.get("unique_directories", 0)

        rate = files_changed / window_seconds
        baseline = _p(params, "baseline_files_per_second", BASELINE_FILES_PER_SECOND)
        rate_threshold = baseline * _p(params, "mass_rate_multiplier", MASS_MODIFICATION_RATE_MULTIPLIER)
        rate_high = rate > rate_threshold
        multi_directory = unique_directories >= _p(params, "min_directories", MIN_DIRECTORIES_FOR_MASS_SPREAD)

        if not (rate_high and multi_directory):
            continue

        confidence = min(0.9, 0.5 + 0.05 * (rate / rate_threshold))

        signals.append(
            Signal(
                ts=event.timestamp,
                source=event.source,
                signal_type="mass_file_modification",
                category=SignalCategory.LATE,
                mitre_technique_id="T1486",
                mitre_technique_name="Data Encrypted for Impact",
                confidence=confidence,
                summary=(
                    f"Mass file modification on {event.source}: {files_changed} files across "
                    f"{unique_directories} directories in {window_seconds:.1f}s "
                    f"({rate:.1f} files/s, baseline={baseline}/s)."
                ),
                raw_features={"files_changed": files_changed, "rate": rate, "unique_directories": unique_directories},
                contributing_event_ids=(event.event_id,),
            )
        )
    return signals


def detect_ransom_note_signal(events: list[Event], params: Any = None) -> list[Signal]:
    """Flags T1486 via ransom-note file creation across multiple directories.

    A single matching filename in one directory could plausibly be an
    unrelated document; the same characteristic name(s) appearing across
    several directories at once is the specific, ransomware-typical pattern.
    """
    signals: list[Signal] = []
    for event in _events_of_type(events, "ransom_note_creation"):
        file_names = event.payload.get("file_names", [])
        directories = event.payload.get("directories", [])

        matching = [name for name in file_names if RANSOM_NOTE_FILENAME_PATTERN.search(name)]
        unique_directories = len(set(directories))

        if not matching or unique_directories < _p(params, "min_directories", MIN_DIRECTORIES_FOR_MASS_SPREAD):
            continue

        confidence = min(0.95, 0.7 + 0.05 * unique_directories)

        signals.append(
            Signal(
                ts=event.timestamp,
                source=event.source,
                signal_type="ransom_note_creation",
                category=SignalCategory.LATE,
                mitre_technique_id="T1486",
                mitre_technique_name="Data Encrypted for Impact",
                confidence=confidence,
                summary=(
                    f"Ransom-note-pattern file(s) {matching} created across "
                    f"{unique_directories} directories on {event.source}."
                ),
                raw_features={"matching_file_names": matching, "unique_directories": unique_directories},
                contributing_event_ids=(event.event_id,),
            )
        )
    return signals


def detect_all_late_signals(events: list[Event], params: Any = None) -> list[Signal]:
    """Runs every late-signal detector and returns the combined, time-ordered list."""
    signals: list[Signal] = []
    signals.extend(detect_encryption_entropy_signal(events, params))
    signals.extend(detect_mass_modification_signal(events, params))
    signals.extend(detect_ransom_note_signal(events, params))
    signals.sort(key=lambda s: s.ts)
    return signals
