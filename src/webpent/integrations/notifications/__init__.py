# src/webpent/integrations/notifications/__init__.py
"""Immediate per-platform notifications (PROPOSALS_ULTIMATE_V3 §4).

Formatters are pure (formatters/), dispatch owns every send behind the
flag gate + severity gate + request ledger, and daily_digest buffers
below-threshold findings for one summary pushed on demand. No timers,
no background daemon — the operator triggers the digest.
"""
