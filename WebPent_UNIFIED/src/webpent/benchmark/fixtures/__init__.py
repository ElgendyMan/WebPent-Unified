"""Vulnerable-app fixtures for the WebPent self-test harness (2026-10-25
proposals, Proposal 6 — Vulnerable-Apps Benchmark Harness).

The fixture apps are INTENTIONALLY vulnerable micro-targets served
locally by ``benchmark/fixtures/vulnbox_app.py`` and driven by
``benchmark/fixtures/runner.py`` through the REAL probe nodes and
canonical validators. Nothing here ships payloads for third parties:
the only consumer is WebPent's own campaign loop against localhost.
"""
from webpent.benchmark.fixtures.vulnbox_app import (
    VULNBOX_MODES,
    build_vulnbox_app,
)
from webpent.benchmark.fixtures.runner import (
    VulnboxBenchmarkReport,
    VulnboxTargetResult,
    run_vulnbox_campaign,
)

__all__ = [
    "VULNBOX_MODES",
    "VulnboxBenchmarkReport",
    "VulnboxTargetResult",
    "build_vulnbox_app",
    "run_vulnbox_campaign",
]
