# src/webpent/secrets_scanner/__init__.py
"""Leaked-secrets scanner (PROPOSALS_ULTIMATE_V3 §7).

Scans in-scope response text, discovered JS and common backup paths
against a fixed library of official token prefixes, plus Shannon-entropy
analysis for context-marked candidates with no known prefix. Every
output carries a MASKED value only (first 4 + last 4 characters); the
full value never enters logs, reports, or this module's own objects —
it is handed, exactly once, to an injected evidence sink if one is
provided, and otherwise dropped.
"""
