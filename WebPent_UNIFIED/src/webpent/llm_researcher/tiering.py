# src/webpent/llm_researcher/tiering.py
"""Model tiering (PROPOSALS_ULTIMATE_V2 §9, 2026-10-30).

A DETERMINISTIC task->tier table routes each LLM task class to the
operator's configured tier model: cheap exploration work
(crawler summaries, extraction, lightweight classification, recon
output analysis) goes to the ``fast`` tier; capability-critical work
(hypothesis generation, payload selection, exploit/PoC writing, error
fixing) goes to the ``strong`` tier. When a tier's model is not
configured (or is not available in the provider pool), resolution
FALLS BACK to the other tier's configured model — never to nothing and
never to an invented default: with both tiers unconfigured the
resolution is a hard refusal, and with the flag off the tiering router
refuses entirely (callers keep their existing provider behaviour).

Spend is recorded PER TIER in the spend governor, so the operator can
see exactly how many tokens each tier burned for an engagement and cap
them with the existing spend governor.

An UNKNOWN task name resolves to ``strong`` on purpose: tiering is a
cost optimization and silently downgrading a task we have not seen to
the cheap model would trade capability for tokens without anyone
deciding that trade.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

__all__ = [
    "TIER_FAST",
    "TIER_STRONG",
    "UNCLASSIFIED_TIER",
    "TierRoute",
    "ModelTieringError",
    "TASK_TIER_TABLE",
    "tier_for_task",
    "parse_tier_flag",
    "resolve_tier_model",
    "model_tier_of",
    "note_tiered_call",
]

TIER_FAST = "fast"
TIER_STRONG = "strong"
UNCLASSIFIED_TIER = "unclassified"


class ModelTieringError(ValueError):
    """Raised when tier resolution cannot proceed fail-closed."""


# Deterministic task->tier table, keyed by LLMTask.value
# (llm_researcher/task_router.py). fast = summarization / extraction /
# classification / recon-output reading. strong = reasoning about WHAT
# to test and HOW (hypothesis, payload choice, exploit code, fixes).
TASK_TIER_TABLE: dict[str, str] = {
    "recon_analyze_page": TIER_FAST,
    "web_recon_search": TIER_FAST,
    "endpoint_extract": TIER_FAST,
    "lightweight_classify": TIER_FAST,
    "output_analyze": TIER_FAST,
    "hypothesis_generate": TIER_STRONG,
    "payload_select": TIER_STRONG,
    "code_exploit_write": TIER_STRONG,
    "error_fix": TIER_STRONG,
}


def tier_for_task(task: str) -> str:
    """Resolve a task name to its tier; unknown tasks -> ``strong``."""
    return TASK_TIER_TABLE.get(str(task), TIER_STRONG)


def parse_tier_flag(value: str) -> "tuple[str, str] | None":
    """Parse a tier model flag: ``provider/model`` or bare ``model``.

    A bare name is routed to the ``openai`` provider (the OpenAI-
    compatible proxy surface). An empty/blank flag parses to ``None``
    — that tier is simply not configured.
    """
    text = str(value).strip()
    if not text:
        return None
    if "/" in text:
        provider, _, model = text.partition("/")
        provider = provider.strip() or "openai"
        return provider, model.strip()
    return "openai", text


@dataclass(frozen=True)
class TierRoute:
    """One deterministic tiering decision."""

    task: str
    tier: str
    provider: str
    model: str
    fell_back: bool = False
    reason: str = ""


def _available(route: "tuple[str, str] | None", pool: Any) -> bool:
    if route is None:
        return False
    if pool is None:
        return True
    provider, model = route
    try:
        return bool(pool.available(provider, model))
    except TypeError:
        # pool.available(model) single-argument pools are supported too.
        return bool(pool.available(model))  # type: ignore[call-arg]


def resolve_tier_model(
    task: str,
    *,
    enable_model_tiering: bool,
    model_tier_fast: str,
    model_tier_strong: str,
    pool: Any = None,
) -> TierRoute:
    """Resolve ``task`` to a tier model, with automatic tier fallback.

    Fail-closed refusals: the flag off, or BOTH tier flags empty (a
    fallback needs something real to fall back TO — an invented default
    model name would silently reroute spend). Resolution order:
    the task's own tier model first; if it is unconfigured or the
    (optional) provider pool says it is unavailable, the OTHER tier's
    configured model is used with ``fell_back=True``.
    """
    if not enable_model_tiering:
        raise ModelTieringError("model_tiering_flag_off")
    tier = tier_for_task(task)
    fast = parse_tier_flag(model_tier_fast)
    strong = parse_tier_flag(model_tier_strong)
    if fast is None and strong is None:
        raise ModelTieringError("model_tier_no_models_configured")
    primary, other = (fast, strong) if tier == TIER_FAST else (strong, fast)
    if _available(primary, pool):
        provider, model = primary
        return TierRoute(
            task=str(task), tier=tier, provider=provider, model=model,
            fell_back=False, reason="tier_model_configured",
        )
    assert other is not None  # at least one of the two is configured
    if not _available(other, pool):
        # Both tiers configured but the pool declares both unavailable:
        # refuse rather than route to a model that is known to be down.
        raise ModelTieringError("model_tier_no_models_available")
    provider, model = other
    other_tier = TIER_STRONG if tier == TIER_FAST else TIER_FAST
    return TierRoute(
        task=str(task),
        tier=tier,
        provider=provider,
        model=model,
        fell_back=True,
        reason=f"tier_model_absent_fell_back_to_{other_tier}",
    )


def model_tier_of(
    model: str, *, model_tier_fast: str, model_tier_strong: str
) -> str:
    """Classify a model NAME against the configured tier flags.

    Used by the provider funnel (no task context there): the model that
    matches ``model_tier_fast`` counts as ``fast``, the one matching
    ``model_tier_strong`` as ``strong``, anything else stays
    ``unclassified`` (and is spend-logged as such, never miscounted).
    """
    fast = parse_tier_flag(model_tier_fast)
    strong = parse_tier_flag(model_tier_strong)
    name = str(model)
    if fast is not None and fast[1] == name:
        return TIER_FAST
    if strong is not None and strong[1] == name:
        return TIER_STRONG
    return UNCLASSIFIED_TIER


def note_tiered_call(model: str, response: Any) -> str:
    """Record one provider call's spend under its tier (funnel hook).

    Called from the provider base funnel when ``enable_model_tiering``
    is on. Fail-soft by contract: a tiering bookkeeping error must
    never corrupt a real LLM response, so any failure is swallowed
    here (the funnel's own guard wraps it a second time).
    """
    try:
        from webpent.config.settings import get_settings
        from webpent.safety.spend_governor import record_tier_usage

        settings = get_settings()
        if not settings.enable_model_tiering:
            # Defense in depth: the funnel already gates on the flag;
            # here a flag-off call is a NO-OP (classified but never
            # recorded), so tier counters only exist while tiering is on.
            return UNCLASSIFIED_TIER
        tier = model_tier_of(
            model,
            model_tier_fast=settings.model_tier_fast,
            model_tier_strong=settings.model_tier_strong,
        )
        tokens = int(getattr(response, "tokens_used", 0) or 0)
        record_tier_usage(tier, tokens)
        return tier
    except Exception:
        return UNCLASSIFIED_TIER


def tier_breakdown(engagement_id: str | None = None) -> Mapping[str, int]:
    """Per-tier token snapshot for reporting (delegates to spend governor)."""
    from webpent.safety.spend_governor import tier_snapshot

    return tier_snapshot(engagement_id)
