"""Architecture-agnostic ransomware detection module.

Nothing in this package imports LangGraph, any ``agents.*`` class, or any
notion of "specialist" / "coordinator" / "strategic". It is meant to be
called identically from three different architectures under research
comparison: a monolithic MAPE-K loop, a distributed non-agentic system, and
the multi-agent skeleton in this repository. See ``detection/README.md``
for the detection logic, its MITRE ATT&CK grounding, and its limitations.
"""
