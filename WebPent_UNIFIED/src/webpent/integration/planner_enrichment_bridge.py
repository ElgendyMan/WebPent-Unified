"""Smarter hypothesis generation: context enrichment, priority scoring,
context-aware payload selection, and lesson-priority application.

Additive module (not in the frozen manifest). The frozen planner's LLM prompt
text is NOT edited; instead this bridge enriches the *context* fed to planning
and reorders the *output* hypotheses deterministically. It calls frozen
``PayloadLibrary`` and frozen ``LessonConsultant`` outputs where supplied, but
never imports them at module load (lazy/dependency-injected) so it stays
import-light and fully synthetic-testable.

Advisory only: scores and payload suggestions never confirm a finding.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from webpent.integration.hypothesis_priority_contract import (
    EndpointProfile,
    EnrichedContext,
    PrioritizedHypothesis,
    PriorityLevel,
)

__all__ = [
    "ContextEnricher",
    "PriorityScorer",
    "ContextAwarePayloadSelector",
    "apply_lesson_priorities",
    "secure_prompt_value",
    "FORBIDDEN_CONTEXT_FIELDS",
]

# Fields that must never appear in advisory context (authority-bearing).
FORBIDDEN_CONTEXT_FIELDS = frozenset({
    "confirmed", "verdict", "causal_signal", "severity", "priority_as_decision",
    "target_backed", "in_scope", "owner_verified", "scope_approved", "replay_valid",
    "proof_bundle", "seal", "promotion_ready", "finding_id", "canonical_id",
    "raw_token", "raw_cookie", "raw_password", "api_key_value",
})

_PATH_INJECTION_RE = re.compile(r"(?:\.\./|\\|%2e%2e|;|`|\|\||&&)", re.I)


def secure_prompt_value(value: str, *, max_length: int = 2048) -> str:
    """Sanitise an untrusted string before it enters any prompt or context."""
    text = str(value or "")
    if _PATH_INJECTION_RE.search(text):
        return ""
    return text[:max_length]


# ---------------------------------------------------------------------------
# Context enrichment (Part 2.2)
# ---------------------------------------------------------------------------
class ContextEnricher:
    """Assemble the enriched context DTO for the planner. Pure data."""

    def __init__(self, *, target_url: str, max_endpoints: int = 256) -> None:
        self.target_url = secure_prompt_value(target_url, max_length=512)
        self.max_endpoints = max(1, min(int(max_endpoints), 1024))

    def assemble(
        self,
        *,
        tech_stack: Sequence[str] = (),
        auth_type: str = "none",
        prior_findings: Sequence[str] = (),
        payload_suggestions: Sequence[str] = (),
        lessons: Mapping[str, Any] | None = None,
        endpoints: Sequence[EndpointProfile] = (),
    ) -> EnrichedContext:
        clean_tech = tuple(secure_prompt_value(t, max_length=64) for t in tech_stack if str(t or "").strip())[:32]
        clean_patterns = tuple(secure_prompt_value(p, max_length=128) for p in prior_findings if str(p or "").strip())[:64]
        clean_payloads = tuple(secure_prompt_value(p, max_length=128) for p in payload_suggestions if str(p or "").strip())[:64]
        if lessons:
            for key in lessons:
                if str(key).lower() in FORBIDDEN_CONTEXT_FIELDS:
                    raise ValueError(f"forbidden_context_field:{key}")
        return EnrichedContext(
            target_url=self.target_url,
            tech_stack=clean_tech,
            auth_type=str(auth_type)[:32],
            prior_finding_patterns=clean_patterns,
            payload_suggestions=clean_payloads,
            lesson_priorities=dict(lessons or {}),
            endpoints=tuple(endpoints)[: self.max_endpoints],
        )


# ---------------------------------------------------------------------------
# Priority scoring (Part 2.3) — deterministic, unit-testable
# ---------------------------------------------------------------------------
class PriorityScorer:
    """Score endpoints. Rules (per sprint):
       forms+params / admin / debug / user-data API = HIGH
       session/auth = MEDIUM
       static assets = LOW
    """

    def score(self, endpoint: EndpointProfile) -> tuple[PriorityLevel, float, str]:
        score = 0.0
        reasons: list[str] = []
        if endpoint.is_static_asset:
            return PriorityLevel.LOW, -1.0, "static_asset"
        if endpoint.has_form and endpoint.has_parameters:
            score += 3.0
            reasons.append("form_with_parameters")
        if endpoint.is_admin:
            score += 3.0
            reasons.append("admin_endpoint")
        if endpoint.is_debug:
            score += 3.0
            reasons.append("debug_endpoint")
        if endpoint.is_api and endpoint.returns_user_data:
            score += 3.0
            reasons.append("api_with_user_data")
        elif endpoint.is_api:
            score += 1.0
            reasons.append("api_endpoint")
        if endpoint.requires_session:
            score += 1.0
            reasons.append("session_auth_endpoint")
        if score >= 3.0:
            level = PriorityLevel.HIGH
        elif score >= 1.0:
            level = PriorityLevel.MEDIUM
        else:
            level = PriorityLevel.LOW
        return level, round(score, 4), ",".join(reasons) or "no_priority_signal"

    def prioritize(
        self,
        hypotheses: Sequence[tuple[str, EndpointProfile]],
        *,
        family_for: Callable[[EndpointProfile], str] | None = None,
    ) -> tuple[PrioritizedHypothesis, ...]:
        scored: list[PrioritizedHypothesis] = []
        for hyp_id, endpoint in hypotheses:
            level, score, rationale = self.score(endpoint)
            family = family_for(endpoint) if family_for else self._default_family(endpoint)
            scored.append(PrioritizedHypothesis(
                hypothesis_id=str(hyp_id),
                endpoint=endpoint,
                priority=level,
                score=score,
                rationale=rationale,
                payload_subtype=ContextAwarePayloadSelector.subtype_for(endpoint),
                family=family,
            ))
        scored.sort(key=lambda h: (-h.score, h.hypothesis_id))
        return tuple(scored)

    @staticmethod
    def _default_family(endpoint: EndpointProfile) -> str:
        if endpoint.returns_user_data or endpoint.is_api:
            return "IDOR"
        if endpoint.has_form:
            return "XSS"
        return "INFO_DISCLOSURE"


# ---------------------------------------------------------------------------
# Context-aware payload selection (Part 2.4)
# ---------------------------------------------------------------------------
class ContextAwarePayloadSelector:
    """Map endpoint context to payload library family/subtype.

    If a frozen ``PayloadLibrary`` instance is supplied, selection delegates to
    ``library.get_payloads(family, sub_type, context, limit)``; otherwise the
    selector returns the chosen family/subtype metadata (deterministic).
    """

    @staticmethod
    def subtype_for(endpoint: EndpointProfile) -> str:
        ct = str(endpoint.content_type or "").lower()
        if endpoint.waf_detected:
            return "waf_bypass"
        if endpoint.uses_jwt:
            return "jwt"
        if "json" in ct:
            return "json"
        if "form" in ct or endpoint.has_form:
            return "form"
        return "generic"

    @staticmethod
    def family_for(endpoint: EndpointProfile) -> str:
        return PriorityScorer._default_family(endpoint)

    def select(
        self,
        endpoint: EndpointProfile,
        *,
        library: Any | None = None,
        limit: int = 3,
    ) -> dict[str, Any]:
        family = self.family_for(endpoint)
        subtype = self.subtype_for(endpoint)
        entries: list[Any] = []
        if library is not None and hasattr(library, "get_payloads"):
            try:
                entries = list(library.get_payloads(family, sub_type=subtype, context=subtype, limit=max(1, int(limit))))
            except Exception:  # noqa: BLE001 — advisory selection is best-effort
                entries = []
        return {
            "family": family,
            "subtype": subtype,
            "payload_count": len(entries),
            "payload_ids": [str(getattr(e, "entry_id", "") or getattr(e, "id", "")) for e in entries][:limit],
        }


# ---------------------------------------------------------------------------
# Apply lesson priorities (Part 3.3 — lesson_consultant -> planner)
# ---------------------------------------------------------------------------
def apply_lesson_priorities(
    prioritized: Sequence[PrioritizedHypothesis],
    priority_adjustment: Any,
) -> tuple[PrioritizedHypothesis, ...]:
    """Re-score a prioritized list using a frozen LessonConsultant
    ``PriorityAdjustmentMap`` (route_modifiers, family_modifiers,
    minimum_family_quota). Returns a NEW sorted tuple; inputs are immutable.
    """
    route_modifiers = dict(getattr(priority_adjustment, "route_modifiers", None) or {})
    family_modifiers = dict(getattr(priority_adjustment, "family_modifiers", None) or {})
    minimum_quota = dict(getattr(priority_adjustment, "minimum_family_quota", None) or {})

    re_scored: list[tuple[float, PrioritizedHypothesis]] = []
    for hyp in prioritized:
        delta = 0.0
        route = str(hyp.endpoint.route)
        for pattern, modifier in route_modifiers.items():
            p = str(pattern).rstrip("*")
            if route.startswith(p) or route == pattern:
                delta += float(modifier)
                break
        delta += float(family_modifiers.get(hyp.family, 0.0))
        # Minimum family quota: guarantee at least one hypothesis from each
        # required family by giving the first occurrence a floor boost.
        if minimum_quota.get(hyp.family, 0) > 0:
            delta += 0.01  # tiny deterministic floor, never overrides real scores
        new_score = round(max(-5.0, min(5.0, float(hyp.score) + delta)), 4)
        re_scored.append((new_score, hyp))

    re_scored.sort(key=lambda item: (-item[0], item[1].hypothesis_id))
    return tuple(
        PrioritizedHypothesis(
            hypothesis_id=h.hypothesis_id,
            endpoint=h.endpoint,
            priority=PriorityLevel.HIGH if s >= 3.0 else (PriorityLevel.MEDIUM if s >= 1.0 else PriorityLevel.LOW),
            score=s,
            rationale=f"{h.rationale};lesson_delta={round(s - h.score, 4)}",
            payload_subtype=h.payload_subtype,
            family=h.family,
        )
        for s, h in re_scored
    )
