# src/webpent/resume/__init__.py
"""Campaign resume (2026-10-25 Proposal 8).

Deterministic, fail-closed support for resuming interrupted campaign
tasks: checkpoint markers for the worker, a probe-execution ledger so a
resume never re-fires an already-executed probe, and bounded exponential
backoff for automatic requeue. Every entry point is inert unless the
``enable_campaign_resume`` setting is on.
"""
