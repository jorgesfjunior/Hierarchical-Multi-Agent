"""Entropy-based detection of mass-encryption ONSET over a stream of file writes.

New, pure file (no LangGraph / agents imports). ``classifier.py`` and
``late_signals.py`` are untouched, so both baselines are unaffected.

Background: high Shannon entropy (bits/byte, 0..8) marks encrypted or
compressed content (Scaife et al. 2016 "CryptoLock"; Continella et al. 2016
"ShieldFS"; Kharraz et al. 2016 "UNVEIL"). Entropy of ONE write is a weak
signal -- compressed archives, media and already-encrypted files are also
near 8 -- so this method looks at the PROPORTION of high-entropy writes in a
short window and whether that proportion is RISING versus the period before.
(``detection/late_signals.py`` already computes the same per-write entropy but
gates it on per-event behavioural corroborators, not on a proportion over time.)

The formula itself is NOT re-implemented: ``shannon_entropy`` is the single
existing implementation from ``late_signals`` (H = -sum p_i log2 p_i over the
256 byte values), re-exported here.

Definitions (all parameters in :class:`EntropyParams`, stored in Knowledge as
``entropy_params``):

  t_ref            time of the latest write in the trace
  recent window    writes with t_ref - window_seconds < ts <= t_ref
  baseline window  the ``baseline_seconds`` immediately BEFORE the recent window
  high-entropy     write whose sample entropy >= entropy_threshold_bits
  proportion(w)    (# high-entropy writes in w) / (# writes in w); an EMPTY
                   baseline counts as proportion 0 (idle before the burst)
  rise             proportion(recent) - proportion(baseline)

  onset (flag)  =  n_recent >= min_writes_in_window
                   and proportion(recent) >= proportion_threshold
                   and rise >= min_rise

  confidence       flagged : min(cap, 0.5 + 0.45 * proportion(recent))
                   else    : 0.4 * proportion(recent) * min(1, n_recent / min_writes_in_window)
                   (below the 0.5 flag scale, so a non-flag never escalates by confidence alone)

Consequences worth knowing: a single high-entropy write, or a few, can never
flag (min_writes); a sustained high-entropy stream that was ALREADY running
during the baseline window does not flag (no rise); but a high-entropy burst
starting from idle (e.g. a backup/archive job copying compressed files) is
indistinguishable from encryption onset by this signal alone -- a documented
false-positive class, see tests and the experiment report.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable, Mapping, Optional

from detection.late_signals import shannon_entropy  # single implementation, re-exported

__all__ = ["shannon_entropy", "EntropyParams", "EntropyResult", "entropy_onset_confidence"]


@dataclass(frozen=True)
class EntropyParams:
    entropy_threshold_bits: float = 7.5
    window_seconds: float = 10.0
    baseline_seconds: float = 60.0
    min_writes_in_window: int = 8
    proportion_threshold: float = 0.5
    min_rise: float = 0.3
    cap: float = 0.95

    @classmethod
    def from_mapping(cls, m: Optional[Mapping[str, Any]]) -> "EntropyParams":
        defaults = cls()
        if not m:
            return defaults
        return cls(**{f: type(getattr(defaults, f))(m.get(f, getattr(defaults, f))) for f in defaults.__dataclass_fields__})


@dataclass(frozen=True)
class EntropyResult:
    assessed: bool  # False -> no write samples at all; caller should fall back
    flagged: bool
    confidence: float
    n_recent: int = 0
    n_recent_high: int = 0
    recent_proportion: float = 0.0
    n_baseline: int = 0
    baseline_proportion: float = 0.0
    rise: float = 0.0
    max_entropy: float = 0.0
    explanation: str = ""


def _proportion(entropies: list[float], threshold: float) -> tuple[int, float]:
    if not entropies:
        return 0, 0.0
    high = sum(1 for h in entropies if h >= threshold)
    return high, high / len(entropies)


def entropy_onset_confidence(
    writes: Iterable[tuple[datetime, bytes]], params: Optional[EntropyParams] = None
) -> EntropyResult:
    """Detects encryption onset from ``(timestamp, content_sample)`` file writes."""
    params = params or EntropyParams()
    samples = sorted(((ts, shannon_entropy(data)) for ts, data in writes), key=lambda s: s[0])
    if not samples:
        return EntropyResult(False, False, 0.0, explanation="no file-write samples with content")

    t_ref = samples[-1][0]
    recent_start = t_ref - timedelta(seconds=params.window_seconds)
    baseline_start = recent_start - timedelta(seconds=params.baseline_seconds)
    recent = [h for ts, h in samples if recent_start < ts <= t_ref]
    baseline = [h for ts, h in samples if baseline_start < ts <= recent_start]

    n_recent_high, recent_prop = _proportion(recent, params.entropy_threshold_bits)
    _, baseline_prop = _proportion(baseline, params.entropy_threshold_bits)
    rise = recent_prop - baseline_prop

    flagged = (
        len(recent) >= params.min_writes_in_window
        and recent_prop >= params.proportion_threshold
        and rise + 1e-9 >= params.min_rise
    )
    if flagged:
        confidence = min(params.cap, 0.5 + 0.45 * recent_prop)
    else:
        confidence = 0.4 * recent_prop * min(1.0, len(recent) / params.min_writes_in_window)

    explanation = (
        f"{n_recent_high}/{len(recent)} writes >= {params.entropy_threshold_bits} bits/byte in last "
        f"{params.window_seconds:g}s (proportion={recent_prop:.2f}) vs baseline proportion={baseline_prop:.2f} "
        f"over {len(baseline)} write(s) (rise={rise:+.2f}); "
        + ("ENCRYPTION ONSET." if flagged else "no onset.")
    )
    return EntropyResult(
        True, flagged, confidence, len(recent), n_recent_high, recent_prop, len(baseline), baseline_prop,
        rise, max(h for _, h in samples), explanation,
    )
