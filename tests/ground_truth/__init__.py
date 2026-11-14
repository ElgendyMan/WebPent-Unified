# tests/ground_truth/__init__.py
"""WebPent V5 Sprint 7 — Ground-Truth Vulnerable Target.

This package contains an intentionally vulnerable FastAPI application
used by the automated evaluation harness (``scripts/evaluate_ground_truth.py``)
to validate that the WebPent framework correctly detects and confirms
vulnerabilities across all 13 security classes.

WARNING: This code is deliberately insecure. NEVER deploy it in
production or expose it to untrusted networks. It exists solely as a
deterministic test fixture for the framework's validation pipeline.
"""
