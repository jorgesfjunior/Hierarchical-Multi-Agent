"""Ensures the mas-hierarchical/ root is importable as the package root.

Pytest adds this file's directory to ``sys.path`` when collecting it, which
makes top-level packages (``agents``, ``graph``, ``knowledge``,
``simulation``, ``instrumentation``) importable from the test suite
regardless of the working directory pytest was invoked from.
"""
