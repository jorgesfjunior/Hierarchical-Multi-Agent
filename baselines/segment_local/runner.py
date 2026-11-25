"""Fase 1 arm B2-SSL-local (docs/fase1/02_preregistro.md §2): one B2-SSL instance per segment
(= host profile), INSIDE its segment, with no communication between instances.

Each instance is the unmodified ``MAPEKLoop`` with the single-signal precaution rule (policy
``single_signal_containment``) and the SAME local authority as an SN segment specialist
(``agents.segment_specialist.LOCAL_PHASES``: no recovery, no global action). Detector thresholds come
from the same per-profile table every Fase 1 arm reads. Node id: ``b2local::<segment>``.
"""
from __future__ import annotations

from typing import Any

from agents.segment_specialist import LOCAL_PHASES
from baselines.mape_k_monolithic.loop import MAPEKLoop
from instrumentation.metrics import MetricsLogger
from knowledge.repository import KnowledgePolicyRepository

NODE_PREFIX = "b2local::"


def layer_name(segment: int) -> str:
    return f"b2local_{segment}"


class _SegmentRepository:
    """Write view of the shared repository (layer/agent rewritten; reads run policies only)."""

    def __init__(self, repository: KnowledgePolicyRepository, segment: int):
        self._repository, self._segment = repository, segment

    def record_decision(self, **kwargs: Any) -> dict[str, Any]:
        kwargs["layer"], kwargs["agent_id"] = layer_name(self._segment), f"{NODE_PREFIX}{self._segment}"
        return self._repository.record_decision(**kwargs)

    def get_policy(self, key: str, default: Any = None) -> Any:
        return self._repository.get_policy(key, default)


class _SegmentMetrics:
    def __init__(self, metrics: MetricsLogger, segment: int):
        self._metrics, self._segment = metrics, segment

    def emit(self, **kwargs: Any) -> dict[str, Any]:
        kwargs["layer"], kwargs["agent_id"] = layer_name(self._segment), f"{NODE_PREFIX}{self._segment}"
        payload = kwargs.get("payload")
        if isinstance(payload, dict) and payload.get("node") == "central":
            kwargs["payload"] = {**payload, "node": f"{NODE_PREFIX}{self._segment}"}
        return self._metrics.emit(**kwargs)

    @property
    def sim(self) -> Any:
        return getattr(self._metrics, "sim", None)


class SegmentLocalBaseline:
    def __init__(self, host_segments: dict[str, int], repository: KnowledgePolicyRepository, metrics: MetricsLogger):
        self.host_segments = host_segments
        segments = sorted(set(host_segments.values()))
        self.loops = {s: MAPEKLoop(_SegmentRepository(repository, s), _SegmentMetrics(metrics, s), phases=LOCAL_PHASES)
                      for s in segments}
        for s, loop in self.loops.items():  # Fase 1b: an isolated instance acts only inside its segment
            loop.advisory_scope = (lambda seg: (lambda host: self.host_segments.get(host) == seg))(s)
        self._history: dict[tuple[int, str], list[dict[str, Any]]] = {}

    def route(self, raw_event: dict[str, Any]) -> int:
        return self.host_segments[raw_event["source"]]

    def process_event(self, incident_id: str, raw_event: dict[str, Any]) -> dict[str, Any]:
        seg = self.route(raw_event)
        history = self._history.setdefault((seg, incident_id), [])
        history.append(raw_event)
        return {"segment": seg, **self.loops[seg].run_incident(incident_id, list(history))}
