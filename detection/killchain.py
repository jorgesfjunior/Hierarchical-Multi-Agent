"""Kill-chain-stage correlation: confidence as a function of stage PROGRESSION.

New file, purely additive: nothing in ``detection/classifier.py`` (shared
unchanged with both baselines) is modified, and nothing here imports LangGraph
or ``agents.*``. The stage map and parameters are INPUTS (the MAS reads them
from Knowledge); this module holds no policy of its own beyond the defaults in
:class:`KillChainParams`.

Idea
----
The legacy heuristic (``classifier.classify``) scores by how many DISTINCT
early-signal types are present, in any order and at any distance in time.
Here each detected technique is first mapped to a kill-chain stage, and
confidence rises only as stages are observed in the expected temporal order
within a bounded window; disorder and stale gaps are penalized, not ignored.

Formula (all parameters in :class:`KillChainParams`, stored in Knowledge as
``killchain_params``):

  observations : one per mapped stage = (earliest signal ts, max confidence).
                 Sorted by ts. Unmapped techniques are ignored.
  base         = single_weight * max(observation confidence)
                 (an isolated technique: identical to the legacy single-signal
                 score, so isolated behavior is unchanged)
  for each consecutive pair (prev, cur) in time order:
      cur.stage > prev.stage and gap <= max_gap_seconds -> IN_ORDER
      cur.stage > prev.stage and gap >  max_gap_seconds -> GAP
      cur.stage < prev.stage                            -> INVERSION
  confidence   = clamp( base
                        + step          * n_IN_ORDER
                        - gap_penalty   * n_GAP
                        - order_penalty * n_INVERSION , 0, cap )   
  flagged      = n_IN_ORDER >= 1 and confidence >= flag_threshold

So an in-order, in-window sequence gains ``step`` per stage; the same
techniques out of order or spread beyond the window gain nothing AND lose
confidence. A single technique can never flag (needs one IN_ORDER transition),
mirroring the legacy corroboration rule.

Stage mapping provenance: see ``agents/mape.py`` (``DEFAULT_KILLCHAIN_STAGE_MAP``).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

from detection.signals import Signal


@dataclass(frozen=True)
class KillChainParams:
    max_gap_seconds: float = 300.0
    single_weight: float = 0.5
    step: float = 0.2
    order_penalty: float = 0.1
    gap_penalty: float = 0.05
    cap: float = 0.9
    flag_threshold: float = 0.5

    @classmethod
    def from_mapping(cls, m: Optional[Mapping[str, Any]]) -> "KillChainParams":
        defaults = cls()
        if not m:
            return defaults
        return cls(**{f: type(getattr(defaults, f))(m.get(f, getattr(defaults, f))) for f in defaults.__dataclass_fields__})


@dataclass(frozen=True)
class StageObservation:
    stage: str
    stage_index: int
    ts: Any  # datetime
    confidence: float
    technique: str


@dataclass(frozen=True)
class KillChainResult:
    mapped: bool  # False -> no signal mapped to a stage; caller should fall back
    confidence: float
    flagged: bool
    n_in_order: int
    n_gap: int
    n_inversion: int
    observations: tuple[StageObservation, ...] = ()
    transitions: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    explanation: str = ""


def killchain_stage_confidence(
    signals: Iterable[Signal],
    stage_order: list[str],
    technique_stage: Mapping[str, str],
    params: Optional[KillChainParams] = None,
) -> KillChainResult:
    """Confidence from kill-chain stage progression (see module docstring)."""
    params = params or KillChainParams()
    index = {stage: i for i, stage in enumerate(stage_order)}

    per_stage: dict[str, list[Signal]] = {}
    for s in signals:
        stage = technique_stage.get(s.mitre_technique_id)
        if stage in index:
            per_stage.setdefault(stage, []).append(s)

    if not per_stage:
        return KillChainResult(False, 0.0, False, 0, 0, 0, explanation="no signal maps to a kill-chain stage")

    observations = []
    for stage, sigs in per_stage.items():
        first = min(sigs, key=lambda s: s.ts)
        observations.append(
            StageObservation(stage, index[stage], first.ts, max(s.confidence for s in sigs), first.mitre_technique_id)
        )
    observations.sort(key=lambda o: (o.ts, o.stage_index))

    n_in_order = n_gap = n_inv = 0
    transitions = []
    for prev, cur in zip(observations, observations[1:]):
        gap = (cur.ts - prev.ts).total_seconds()
        if cur.stage_index > prev.stage_index:
            kind = "in_order" if gap <= params.max_gap_seconds else "gap"
        else:
            kind = "inversion"
        n_in_order += kind == "in_order"
        n_gap += kind == "gap"
        n_inv += kind == "inversion"
        transitions.append({"from": prev.stage, "to": cur.stage, "gap_seconds": gap, "kind": kind})

    base = params.single_weight * max(o.confidence for o in observations)
    raw = base + params.step * n_in_order - params.gap_penalty * n_gap - params.order_penalty * n_inv
    confidence = max(0.0, min(params.cap, raw))
    flagged = n_in_order >= 1 and confidence + 1e-9 >= params.flag_threshold  # epsilon: float sums like 0.3+0.2

    sequence = " -> ".join(f"{o.stage}({o.technique})" for o in observations)
    explanation = (
        f"kill-chain stages observed: {sequence}; in_order={n_in_order} gap={n_gap} inversion={n_inv}; "
        f"confidence={confidence:.2f} (base={base:.2f})."
    )
    return KillChainResult(
        True, confidence, flagged, n_in_order, n_gap, n_inv, tuple(observations), tuple(transitions), explanation
    )
