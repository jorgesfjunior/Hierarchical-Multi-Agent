"""Named random streams for every NEW source of randomness (Fase 1 onwards).

The scenario generator draws everything from ONE sequential ``random.Random(f"{family}:{seed}")``
(``simulation/scenario_generator.py``): a single extra draw from it would shift every later event
and break the Phase 8 regression guard (``tests/test_fase1_phase8_regression.py``). New randomness
(host profiles, observation constraints, ...) must therefore never touch that RNG, nor the global
``random`` module. It comes from a named stream instead:

    rng = stream(seed, "profiles", scope=family)      # random.Random
    gen = np_stream(seed, "constraints")             # numpy.random.Generator

A stream is a pure function of ``(seed, name, scope)``: independent of which other streams exist,
of the order they are created in and of how many draws any other stream (or the scenario RNG) made.
The seed material is a SHA-256 over a namespaced text (stable across processes, platforms and
``PYTHONHASHSEED``; Python's ``hash()`` is never used); numpy streams use the same material as a
``SeedSequence`` entropy. Names must be in ``STREAM_NAMES`` so a typo cannot silently create a new,
unregistered stream; add the name here (and say what draws from it) before using it.
"""
from __future__ import annotations

import hashlib
import random
from typing import Optional

NAMESPACE = "mas-hierarchical/rng-stream/v1"
# Registered stream names -> what draws from them. Add an entry before drawing from a new stream.
STREAM_NAMES: dict[str, str] = {
    "profiles": "Fase 1: host/segment profiles (segment assignment, per-profile baselines and signatures)",
    "constraints": "Fase 1: observation constraints on the central node (aggregation, delay, bandwidth, cost)",
    "benign": "Fase 1: benign background hosts per profile (normal behaviour)",
    "test": "tests only: draws that must not change any result",
}


def _material(seed: int, name: str, scope: Optional[str]) -> bytes:
    if name not in STREAM_NAMES:
        raise ValueError(f"unregistered RNG stream {name!r}; register it in STREAM_NAMES ({sorted(STREAM_NAMES)})")
    if not isinstance(seed, int) or isinstance(seed, bool):
        raise TypeError(f"seed must be an int, got {type(seed).__name__}")
    text = f"{NAMESPACE}|{name}|{'' if scope is None else scope}|{seed}"
    return hashlib.sha256(text.encode("utf-8")).digest()


def stream_seed(seed: int, name: str, scope: Optional[str] = None) -> int:
    """The 256-bit integer seed of stream ``name`` for run ``seed`` (and optional ``scope``, e.g. a family)."""
    return int.from_bytes(_material(seed, name, scope), "big")


def stream(seed: int, name: str, scope: Optional[str] = None) -> random.Random:
    """A fresh ``random.Random`` for stream ``name``; identical inputs give identical sequences."""
    return random.Random(stream_seed(seed, name, scope))


def np_stream(seed: int, name: str, scope: Optional[str] = None):
    """A fresh ``numpy.random.Generator`` (PCG64 over a ``SeedSequence``) for stream ``name``."""
    import numpy as np

    words = [int.from_bytes(_material(seed, name, scope)[i:i + 4], "big") for i in range(0, 32, 4)]
    return np.random.Generator(np.random.PCG64(np.random.SeedSequence(words)))
