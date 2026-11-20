"""UM-DR-40 RC-4 — per-campaign identity activation (production).

The 39 register's RC-4 acceptance: the identity-reasoning stack must
be enableable **per campaign** with the budget impact recorded — not
flipped globally, not silently. This module is that mechanism:

``identity_campaign_activation`` is a reversible context manager that
turns the four UM-DR-32 capability flags ON for exactly one campaign
run (through the process environment, which ``Settings`` reads by
field name), clears the settings cache on entry and exit so the
campaign's graph build sees the flags, and restores the previous
environment byte-for-byte — including on exceptions.

``activation_snapshot`` records what a campaign actually ran with
(the honest provenance of an enabled run), and
``budget_impact_record`` derives the measured cost/benefit delta
between a disabled (baseline) run and an enabled one — the recorded
budget impact RC-4 requires.

Fail-closed everywhere: if the activation context cannot guarantee
restoration, it raises rather than leaving flags on.
"""
from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator, Mapping

#: The four UM-DR-32 capability flags (settings field names; the
#: environment variables carry the same names, case-insensitive).
IDENTITY_CAPABILITY_FLAGS: tuple[str, ...] = (
    "enable_object_identity",
    "enable_alias_resolution",
    "enable_multi_identity_reasoning",
    "enable_composite_workflows",
)

#: Every capability on — the default activation profile.
ALL_CAPABILITIES: dict[str, bool] = {
    flag: True for flag in IDENTITY_CAPABILITY_FLAGS
}


def _clear_settings_cache() -> None:
    """Drop the lru_cache on get_settings so flag reads are live."""
    try:
        from webpent.config.settings import get_settings
        get_settings.cache_clear()
    except (ImportError, AttributeError):
        pass


def _effective_flags() -> dict[str, bool]:
    """The four capability flags as the process currently sees them."""
    from webpent.config.settings import get_settings
    settings = get_settings()
    return {flag: bool(getattr(settings, flag))
            for flag in IDENTITY_CAPABILITY_FLAGS}


def activation_snapshot() -> dict[str, Any]:
    """Record what a campaign actually runs with (provenance)."""
    return {
        "identity_capabilities": _effective_flags(),
        "activated_at_utc": datetime.now(timezone.utc).isoformat(),
    }


@contextmanager
def identity_campaign_activation(
        capabilities: Mapping[str, bool] = ALL_CAPABILITIES,
) -> Iterator[dict[str, Any]]:
    """Enable the identity capabilities for exactly one campaign.

    Sets only the four capability flags (never limits or unrelated
    settings), through the environment; the settings cache is
    cleared on entry and exit so the campaign's graph build reads
    the flags live. The previous environment values are restored
    even when the campaign raises.
    """
    unknown = set(capabilities) - set(IDENTITY_CAPABILITY_FLAGS)
    if unknown:
        raise ValueError(
            f"unknown identity capabilities: {sorted(unknown)}")
    saved: dict[str, str | None] = {}
    try:
        for flag, value in capabilities.items():
            saved[flag] = os.environ.get(flag)
            os.environ[flag] = "true" if value else "false"
        _clear_settings_cache()
        yield {
            "activated": dict(capabilities),
            "snapshot": activation_snapshot(),
        }
    finally:
        for flag, previous in saved.items():
            if previous is None:
                os.environ.pop(flag, None)
            else:
                os.environ[flag] = previous
        _clear_settings_cache()


def budget_impact_record(
        baseline_run: Mapping[str, Any],
        enabled_run: Mapping[str, Any],
) -> dict[str, Any]:
    """The measured cost/benefit delta of an enabled campaign.

    ``baseline_run`` / ``enabled_run`` are campaign result records
    (as the production campaign runner emits them). The delta is
    computed field-by-field; missing fields stay ``None`` rather
    than being invented.
    """
    def _num(rec: Mapping[str, Any], key: str) -> float | None:
        try:
            value = rec.get(key)
            return float(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    keys = (
        "lab_request_count", "requests_total",
        "elapsed_s", "duration_seconds",
        "findings_confirmed", "findings_pending",
    )
    deltas: dict[str, float | None] = {}
    for key in keys:
        base, enabled = _num(baseline_run, key), _num(enabled_run, key)
        deltas[key] = (enabled - base
                       if base is not None and enabled is not None
                       else None)

    def _identity_counts(rec: Mapping[str, Any]) -> dict[str, int]:
        counts: dict[str, int] = {}
        # 1. from a graph final state (the node's own channels)
        state = rec.get("final_state") or rec.get(
            "authoritative_final_state") or {}
        if isinstance(state, Mapping):
            registry = state.get("object_identity_registry") or {}
            inner = registry.get("registry", registry) if isinstance(
                registry, Mapping) else {}
            identities = inner.get("identities") if isinstance(
                inner, Mapping) else None
            if isinstance(identities, Mapping):
                counts["object_identities"] = len(identities)
            reasoning = state.get("multi_identity_reasoning") or {}
            if isinstance(reasoning, Mapping):
                principals = reasoning.get("principals")
                if isinstance(principals, list):
                    counts["principals_observed"] = len(principals)
                questions = reasoning.get("differential_questions")
                if isinstance(questions, list):
                    counts["differential_questions"] = len(questions)
        # 2. from a campaign run record (the production campaign
        #    runner's own vocabulary — the funnel measures the
        #    producer channels)
        if "principals_observed" not in counts:
            discrepancies = rec.get("measurement_discrepancies")
            funnel_principals = (
                discrepancies.get("funnel_principals_observed")
                if isinstance(discrepancies, Mapping) else None)
            if isinstance(funnel_principals, int):
                counts["principals_observed"] = funnel_principals
        identities_observed = rec.get("identities_observed")
        if isinstance(identities_observed, list):
            counts.setdefault(
                "identities_observed", len(identities_observed))
        relationships = rec.get("authorization_relationships")
        if isinstance(relationships, Mapping):
            questions = relationships.get("differential_questions")
            if isinstance(questions, int):
                counts["differential_questions"] = questions
        return counts

    return {
        "schema": "umdr40-identity-budget-impact/v1",
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "baseline_campaign_id": baseline_run.get("campaign_id"),
        "enabled_campaign_id": enabled_run.get("campaign_id"),
        "deltas": deltas,
        "baseline_identity_counts": _identity_counts(baseline_run),
        "enabled_identity_counts": _identity_counts(enabled_run),
        "note": "advisory identity layer: adds reasoning over already-"
                "collected observations; any request-budget delta is "
                "from the enabled node's own passes, recorded here "
                "per RC-4",
    }


__all__ = [
    "IDENTITY_CAPABILITY_FLAGS",
    "ALL_CAPABILITIES",
    "identity_campaign_activation",
    "activation_snapshot",
    "budget_impact_record",
]
