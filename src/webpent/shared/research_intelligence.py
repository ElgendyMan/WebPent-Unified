"""Bounded research intelligence for Smart Autonomous Bug Hunter flows.

This module produces report-safe research proposals. It does not perform I/O,
authorize actions, confirm findings, or replace the existing proof engine.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from webpent.models.evidence import canonical_json, redact_sensitive


class GapKind(str, Enum):
    OWNERSHIP = "ownership"
    AUTHORIZATION = "authorization"
    WORKFLOW = "workflow"
    SURFACE = "surface"
    PARSER = "parser"
    IDENTITY_TENANT = "identity_tenant"
    ORACLE = "oracle"
    COVERAGE = "coverage"


class ActionClass(str, Enum):
    DISCOVERY = "discovery"
    IDENTITY_ACQUISITION = "identity_acquisition"
    WORKFLOW_REPLAY = "workflow_replay"
    BASELINE = "baseline"
    NEGATIVE_CONTROL = "negative_control"
    ACTIVE_PROBE = "active_probe"
    BROWSER_ACTION = "browser_action"
    PARSER_PROBE = "parser_probe"
    VALIDATOR_RETRY = "validator_retry"
    PROOF_REPLAY = "proof_replay"
    SAFE_STOP = "safe_stop"


class GapStatus(str, Enum):
    OPEN = "open"
    RESOLVED = "resolved"
    BLOCKED = "blocked"
    EXPIRED = "expired"


def _clean(value: Any, limit: int = 240) -> str:
    redacted, _ = redact_sensitive(str(value or ""))
    return " ".join(redacted.split())[:limit]


def _clean_items(values: Sequence[Any], limit: int = 12) -> tuple[str, ...]:
    return tuple(item for item in (_clean(value) for value in values[:limit]) if item)


def _bounded_number(value: Any, *, default: float, low: float = 0.0, high: float = 1.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return round(max(low, min(high, parsed)), 6)


@dataclass(frozen=True)
class InformationAction:
    """A safe information-acquisition proposal, not an execution request."""

    action_id: str
    action_class: ActionClass
    objective: str
    target_ref: str = ""
    method: str = "GET"
    identity_context: str = "anonymous"
    tenant_context: str = "unknown"
    workflow_state: str = "unknown"
    expected_information_gain: float = 0.0
    cost: float = 1.0
    failure_probability: float = 0.0
    scope_risk: float = 0.0
    rate_limit_cost: float = 0.0
    dependency_penalty: float = 0.0
    capability: str = "http_read"
    requires_approval: bool = False
    idempotency_key: str = ""
    justification: str = ""
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        payload = {
            "action_class": self.action_class.value,
            "target_ref": _clean(self.target_ref, 320),
            "method": _clean(self.method, 16).upper(),
            "identity_context": _clean(self.identity_context, 120),
            "tenant_context": _clean(self.tenant_context, 120),
            "workflow_state": _clean(self.workflow_state, 120),
            "capability": _clean(self.capability, 80),
            "idempotency_key": _clean(self.idempotency_key, 160),
        }
        return hashlib.sha256(canonical_json(payload).encode()).hexdigest()[:32]

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "action_id": _clean(self.action_id, 128),
                "action_class": self.action_class.value,
                "objective": _clean(self.objective),
                "target_ref": _clean(self.target_ref, 320),
                "method": _clean(self.method, 16).upper(),
                "identity_context": _clean(self.identity_context, 120),
                "tenant_context": _clean(self.tenant_context, 120),
                "workflow_state": _clean(self.workflow_state, 120),
                "expected_information_gain": self.expected_information_gain,
                "cost": self.cost,
                "failure_probability": self.failure_probability,
                "scope_risk": self.scope_risk,
                "rate_limit_cost": self.rate_limit_cost,
                "dependency_penalty": self.dependency_penalty,
                "capability": _clean(self.capability, 80),
                "requires_approval": self.requires_approval,
                "fingerprint": self.fingerprint(),
                "justification": _clean(self.justification),
                "metadata": dict(self.metadata),
            }
        )
        return clean


@dataclass(frozen=True)
class KnowledgeGap:
    """An explicit unknown fact and the bounded actions that can resolve it."""

    gap_id: str
    kind: GapKind
    objective: str
    unknown: str
    target_ref: str = ""
    affected_actor: str = "unknown"
    affected_object: str = "unknown"
    affected_tenant: str = "unknown"
    supporting_evidence: tuple[str, ...] = ()
    contradicting_evidence: tuple[str, ...] = ()
    candidate_actions: tuple[InformationAction, ...] = ()
    expected_information_gain: float = 0.0
    cost: float = 1.0
    risk: float = 0.0
    dependencies: tuple[str, ...] = ()
    stopping_condition: str = "fact_resolved_or_blocked"
    expires_at: str = ""
    invalidation_condition: str = "new_identity_or_workflow_state"
    status: GapStatus = GapStatus.OPEN

    def priority(self) -> float:
        denominator = max(0.05, self.cost * max(0.05, 1.0 + self.risk))
        return round(self.expected_information_gain / denominator, 6)

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "gap_id": _clean(self.gap_id, 128),
                "kind": self.kind.value,
                "objective": _clean(self.objective),
                "unknown": _clean(self.unknown),
                "target_ref": _clean(self.target_ref, 320),
                "affected_actor": _clean(self.affected_actor, 120),
                "affected_object": _clean(self.affected_object, 160),
                "affected_tenant": _clean(self.affected_tenant, 120),
                "supporting_evidence": list(self.supporting_evidence),
                "contradicting_evidence": list(self.contradicting_evidence),
                "candidate_actions": [action.as_dict() for action in self.candidate_actions],
                "expected_information_gain": self.expected_information_gain,
                "cost": self.cost,
                "risk": self.risk,
                "priority": self.priority(),
                "dependencies": list(self.dependencies),
                "stopping_condition": _clean(self.stopping_condition),
                "expires_at": _clean(self.expires_at, 64),
                "invalidation_condition": _clean(self.invalidation_condition),
                "status": self.status.value,
            }
        )
        return clean


class KnowledgeGapEngine:
    """Derive explicit gaps from observed state without inventing evidence."""

    def __init__(self, *, max_gaps: int = 24) -> None:
        self.max_gaps = max(1, min(100, int(max_gaps)))

    @staticmethod
    def _gap_id(kind: GapKind, target_ref: str, unknown: str) -> str:
        raw = f"{kind.value}|{_clean(target_ref, 320)}|{_clean(unknown)}"
        return f"gap:{hashlib.sha256(raw.encode()).hexdigest()[:24]}"

    @staticmethod
    def _object_route(url: str) -> bool:
        parts = [part for part in str(url).rstrip("/").split("/") if part]
        return bool(parts and parts[-1].isdigit())

    def _feedback_gaps(self, state: Mapping[str, Any]) -> list[KnowledgeGap]:
        """Convert explicit runtime failures into bounded research gaps."""
        raw_feedback = state.get("runtime_feedback") or {}
        if not isinstance(raw_feedback, Mapping):
            return []
        items: list[Mapping[str, Any]] = []
        for source in ("browser", "gmail", "validator"):
            raw_items = raw_feedback.get(source) or []
            if isinstance(raw_items, Mapping):
                raw_items = [raw_items]
            if isinstance(raw_items, (list, tuple)):
                items.extend(
                    {
                        **dict(item),
                        "source": source,
                    }
                    for item in raw_items
                    if isinstance(item, Mapping)
                )
        events = raw_feedback.get("events") or []
        if isinstance(events, (list, tuple)):
            items.extend(item for item in events if isinstance(item, Mapping))
        gaps: list[KnowledgeGap] = []
        known: set[str] = set()
        for item in items:
            source = _clean(item.get("source"), 40).lower()
            status = _clean(item.get("status") or item.get("event"), 80).lower()
            if status in {"", "completed", "executed", "success", "clean", "resolved"}:
                continue
            if source == "browser" and status in {
                "crash",
                "browser_crash",
                "session_crash",
                "safe_resume_failed",
            }:
                kind, objective, unknown, action_class = (
                    GapKind.WORKFLOW,
                    "prove browser crash recovery before workflow replay",
                    "browser session recovery after a crash",
                    ActionClass.BROWSER_ACTION,
                )
            elif source == "gmail" and status in {
                "delayed",
                "delayed_delivery",
                "duplicate",
                "duplicate_email",
                "expired_otp",
            }:
                kind, objective, unknown, action_class = (
                    GapKind.WORKFLOW,
                    "prove email/OTP workflow handling before identity use",
                    f"safe handling for {status}",
                    ActionClass.WORKFLOW_REPLAY,
                )
            elif source == "validator" and status in {
                "missing-validator",
                "missing_validator",
                "infrastructure_failure",
                "tool_unavailable",
                "inconclusive",
            }:
                kind, objective, unknown, action_class = (
                    GapKind.ORACLE,
                    "obtain a deterministic validator or stop safely",
                    f"validator feedback: {status}",
                    ActionClass.VALIDATOR_RETRY,
                )
            else:
                continue
            target = _clean(item.get("target_ref") or item.get("target_url"), 320)
            gap_id = self._gap_id(kind, target, unknown)
            if gap_id in known:
                continue
            known.add(gap_id)
            evidence = item.get("evidence_refs") or item.get("evidence_ref") or ()
            if isinstance(evidence, str):
                evidence = (evidence,)
            if not isinstance(evidence, (list, tuple)):
                evidence = ()
            action = InformationAction(
                action_id=f"{gap_id}:feedback",
                action_class=action_class,
                objective=objective,
                target_ref=target,
                expected_information_gain=0.7,
                cost=0.8,
                capability="control_plane_feedback",
                justification=f"explicit {source} runtime status requires a bounded follow-up",
                metadata={"source": source, "status": status},
            )
            gaps.append(
                KnowledgeGap(
                    gap_id=gap_id,
                    kind=kind,
                    objective=objective,
                    unknown=unknown,
                    target_ref=target,
                    affected_actor=source,
                    supporting_evidence=_clean_items(evidence),
                    candidate_actions=(action,),
                    expected_information_gain=0.7,
                    cost=0.8,
                    risk=0.05,
                )
            )
        return gaps

    def derive(self, state: Mapping[str, Any]) -> list[KnowledgeGap]:
        gaps: list[KnowledgeGap] = []
        gaps.extend(self._feedback_gaps(state))
        surface = state.get("crawled_data") or {}
        records = surface.get("surface_records", []) if isinstance(surface, Mapping) else []
        if not isinstance(records, list):
            records = []
        urls: list[str] = []
        for record in records:
            if isinstance(record, Mapping):
                url = str(record.get("url") or record.get("target_url") or "").strip()
                if url:
                    urls.append(url)
        for value in surface.get("urls", []) if isinstance(surface, Mapping) else []:
            if isinstance(value, str) and value.strip():
                urls.append(value.strip())
        seen: set[str] = set()
        has_ownership = bool(state.get("relational_evidence")) or bool(
            state.get("authorization_matrix")
        )
        for url in urls:
            if url in seen or not self._object_route(url) or has_ownership:
                continue
            seen.add(url)
            unknown = "owner and creator identity for discovered object"
            gap_id = self._gap_id(GapKind.OWNERSHIP, url, unknown)
            actions = (
                InformationAction(
                    action_id=f"{gap_id}:owner",
                    action_class=ActionClass.IDENTITY_ACQUISITION,
                    objective="acquire an authorized owner or creator context",
                    target_ref=url,
                    identity_context="owner_candidate",
                    expected_information_gain=0.9,
                    cost=1.0,
                    capability="http_read",
                    justification="object-like route has no verified ownership relationship",
                ),
                InformationAction(
                    action_id=f"{gap_id}:denial",
                    action_class=ActionClass.NEGATIVE_CONTROL,
                    objective="establish a foreign-identity denial baseline",
                    target_ref=url,
                    identity_context="foreign_candidate",
                    expected_information_gain=0.75,
                    cost=1.0,
                    capability="http_read",
                    justification="ownership question requires a denial control",
                ),
            )
            gaps.append(
                KnowledgeGap(
                    gap_id=gap_id,
                    kind=GapKind.OWNERSHIP,
                    objective="resolve object ownership before IDOR promotion",
                    unknown=unknown,
                    target_ref=url,
                    affected_object=url.rsplit("/", 1)[-1][:80],
                    affected_actor="owner_vs_foreign",
                    candidate_actions=actions,
                    expected_information_gain=0.9,
                    cost=1.0,
                    risk=0.0,
                    supporting_evidence=("discovered_object_route",),
                )
            )

        for raw in state.get("bac_coverage_gaps") or []:
            if not isinstance(raw, Mapping):
                continue
            target = str(raw.get("url") or raw.get("target_url") or "").strip()
            if not target:
                continue
            unknown = _clean(raw.get("reason") or "authorization behavior across identity contexts")
            gap_id = self._gap_id(GapKind.AUTHORIZATION, target, unknown)
            if any(gap.gap_id == gap_id for gap in gaps):
                continue
            gaps.append(
                KnowledgeGap(
                    gap_id=gap_id,
                    kind=GapKind.AUTHORIZATION,
                    objective="resolve an authorization coverage gap",
                    unknown=unknown,
                    target_ref=target,
                    affected_actor="identity_matrix",
                    candidate_actions=(
                        InformationAction(
                            action_id=f"{gap_id}:methods",
                            action_class=ActionClass.DISCOVERY,
                            objective="discover safe alternate methods and representations",
                            target_ref=target,
                            expected_information_gain=0.65,
                            cost=0.8,
                            justification=(
                                "authorization gap names a route but not its method surface"
                            ),
                        ),
                    ),
                    expected_information_gain=0.65,
                    cost=0.8,
                    risk=0.05,
                    supporting_evidence=("bac_coverage_gap",),
                )
            )
        deduplicated: dict[str, KnowledgeGap] = {}
        for gap in gaps:
            deduplicated.setdefault(gap.gap_id, gap)
        return sorted(
            deduplicated.values(), key=lambda gap: (-gap.priority(), gap.gap_id)
        )[: self.max_gaps]

    def choose(self, gaps: Sequence[KnowledgeGap]) -> KnowledgeGap | None:
        open_gaps = [gap for gap in gaps if gap.status == GapStatus.OPEN]
        return max(open_gaps, key=lambda gap: (gap.priority(), gap.gap_id), default=None)

    def resolve(
        self,
        gap: KnowledgeGap,
        *,
        supporting_evidence: Sequence[str] = (),
        contradicting_evidence: Sequence[str] = (),
        blocked: bool = False,
    ) -> KnowledgeGap:
        status = GapStatus.BLOCKED if blocked else GapStatus.RESOLVED
        return KnowledgeGap(
            **{
                **gap.__dict__,
                "supporting_evidence": _clean_items(
                    (*gap.supporting_evidence, *supporting_evidence)
                ),
                "contradicting_evidence": _clean_items(
                    (*gap.contradicting_evidence, *contradicting_evidence)
                ),
                "status": status,
            }
        )


@dataclass(frozen=True)
class RankedAction:
    action: InformationAction
    score: float
    reasons: tuple[str, ...]
    utility_trace: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.as_dict(),
            "score": self.score,
            "reasons": list(self.reasons),
            "utility_trace": dict(self.utility_trace),
        }


class SmartNextBestActionEngine:
    """Transparent utility ranking for research actions with anti-loop controls."""

    def __init__(self, *, weights: Mapping[str, float] | None = None) -> None:
        self.weights = {
            "likelihood": 1.0,
            "impact": 1.0,
            "evidence_potential": 1.0,
            "information_gain": 1.0,
            "novelty": 0.7,
            "coverage_value": 0.9,
            **dict(weights or {}),
        }

    def score(
        self,
        action: InformationAction,
        *,
        likelihood: float = 0.5,
        impact: float = 0.5,
        evidence_potential: float = 0.5,
        novelty: float = 0.5,
        coverage_value: float = 0.5,
        attempted_fingerprints: Sequence[str] = (),
        new_evidence: bool = False,
    ) -> RankedAction:
        reasons: list[str] = []
        values = {
            "likelihood": _bounded_number(likelihood, default=0.5),
            "impact": _bounded_number(impact, default=0.5),
            "evidence_potential": _bounded_number(evidence_potential, default=0.5),
            "information_gain": _bounded_number(action.expected_information_gain, default=0.0),
            "novelty": _bounded_number(novelty, default=0.5),
            "coverage_value": _bounded_number(coverage_value, default=0.5),
        }
        numerator = 1.0
        weighted_factors: dict[str, float] = {}
        for key, value in values.items():
            weighted_factors[key] = round(value * self.weights[key], 6)
            numerator *= max(0.01, value * self.weights[key])
        denominator = max(
            0.01,
            max(0.01, action.cost)
            * max(0.05, 1.0 + action.failure_probability)
            * max(0.05, 1.0 + action.scope_risk)
            * max(0.05, 1.0 + action.rate_limit_cost)
            * max(0.05, 1.0 + action.dependency_penalty),
        )
        base_score = numerator / denominator
        score = base_score
        penalties: list[str] = []
        if action.fingerprint() in set(attempted_fingerprints) and not new_evidence:
            score *= 0.05
            reasons.append("duplicate_without_new_evidence_penalty")
            penalties.append("duplicate_without_new_evidence:0.050000")
        if action.action_class == ActionClass.SAFE_STOP:
            score = min(score, 0.001)
            reasons.append("safe_stop_is_not_an_exploit_action")
            penalties.append("safe_stop_cap:0.001000")
        if action.requires_approval:
            reasons.append("approval_boundary_required")
        if values["information_gain"] >= 0.7:
            reasons.append("high_information_gain")
        if action.cost <= 1.0:
            reasons.append("low_cost")
        final_score = round(score, 8)
        utility_trace = {
            "version": "research-utility-v1",
            "status": "ranked",
            "factors": values,
            "weighted_factors": weighted_factors,
            "cost_terms": {
                "cost": round(max(0.0, min(100000.0, action.cost)), 6),
                "failure_probability": round(action.failure_probability, 6),
                "scope_risk": round(action.scope_risk, 6),
                "rate_limit_cost": round(action.rate_limit_cost, 6),
                "dependency_penalty": round(action.dependency_penalty, 6),
            },
            "base_score": round(base_score, 8),
            "penalties": penalties,
            "blocked_reasons": [],
            "final_score": final_score,
            "advisory_only": True,
        }
        return RankedAction(
            action=action,
            score=final_score,
            reasons=tuple(reasons),
            utility_trace=utility_trace,
        )

    def rank(self, actions: Sequence[InformationAction], **kwargs: Any) -> list[RankedAction]:
        return sorted(
            (self.score(action, **kwargs) for action in actions),
            key=lambda item: (-item.score, item.action.action_id),
        )


@dataclass
class PositiveEvidence:
    """Reusable supporting knowledge; never proof without validator ownership."""

    evidence_id: str
    hypothesis_id: str
    action_fingerprint: str
    identity_context: str
    tenant_context: str
    method: str
    workflow_state: str
    reason: str
    confidence: float
    reusable_if: tuple[str, ...] = ()
    expires_at: str = ""

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(self.__dict__)
        return clean


@dataclass
class NegativeEvidence:
    """Reusable negative knowledge; never proof that a whole family is absent."""

    evidence_id: str
    hypothesis_id: str
    action_fingerprint: str
    identity_context: str
    tenant_context: str
    method: str
    workflow_state: str
    reason: str
    confidence: float
    reusable_if: tuple[str, ...] = ()
    expires_at: str = ""
    client_id: str = ""
    engagement_id: str = ""
    scope: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(self.__dict__)
        return clean


class NegativeEvidenceLedger:
    """Bounded, scope-aware store for reusable failed paths.

    A negative observation is reusable only for the same client. Reuse across
    engagements additionally requires the explicit ``same_client_cross_engagement``
    policy marker and a non-expired record. Malformed expiry or missing client
    scope fails closed.
    """

    def __init__(self, *, max_entries: int = 500) -> None:
        self.max_entries = max(1, min(5000, int(max_entries)))
        self._entries: dict[str, NegativeEvidence] = {}

    @staticmethod
    def _key(evidence: NegativeEvidence) -> str:
        raw = "|".join(
            (
                evidence.hypothesis_id,
                evidence.action_fingerprint,
                evidence.identity_context,
                evidence.tenant_context,
                evidence.method,
                evidence.workflow_state,
            )
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    @staticmethod
    def _not_expired(evidence: NegativeEvidence) -> bool:
        if not evidence.expires_at:
            return True
        try:
            expiry = datetime.fromisoformat(evidence.expires_at.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return False
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=UTC)
        return expiry > datetime.now(UTC)

    def record(self, evidence: NegativeEvidence) -> bool:
        """Store a scoped negative observation; reject records without client scope."""
        if not isinstance(evidence, NegativeEvidence) or not _clean(evidence.client_id, 128):
            return False
        self._entries[self._key(evidence)] = evidence
        if len(self._entries) > self.max_entries:
            oldest = next(iter(self._entries))
            self._entries.pop(oldest, None)
        return True

    def reusable_for(
        self,
        *,
        action_fingerprint: str,
        client_id: str | None,
        engagement_id: str | None = None,
        hypothesis_id: str | None = None,
    ) -> list[NegativeEvidence]:
        """Return only currently reusable negative evidence in caller scope."""
        client = _clean(client_id, 128)
        engagement = _clean(engagement_id, 128)
        if not client:
            return []
        matches: list[NegativeEvidence] = []
        for evidence in self._entries.values():
            if not self._not_expired(evidence):
                continue
            if _clean(evidence.client_id, 128) != client:
                continue
            if _clean(evidence.action_fingerprint, 128) != _clean(action_fingerprint, 128):
                continue
            if hypothesis_id and _clean(evidence.hypothesis_id, 128) != _clean(hypothesis_id, 128):
                continue
            same_engagement = not engagement or _clean(evidence.engagement_id, 128) == engagement
            cross_engagement_allowed = "same_client_cross_engagement" in evidence.reusable_if
            if not same_engagement and not cross_engagement_allowed:
                continue
            matches.append(evidence)
        return matches

    def as_dict(self) -> dict[str, Any]:
        return {
            "count": len(self._entries),
            "entries": [entry.as_dict() for entry in self._entries.values()],
        }


_INLINE_SECRET_MARKER = re.compile(
    r"(?i)(?:api[_-]?key|token|cookie|password|secret|authorization)\s*[:=]"
)


@dataclass(frozen=True)
class ResearchLoopContract:
    """Checkpoint-safe contract for one bounded research-cycle projection.

    This is telemetry only: it cannot authorize an action, confirm a finding,
    or replace the validator/proof boundary.  All values are derived from
    already-redacted state and are deliberately bounded for resume safety.
    """

    schema_version: int = 1
    target_knowledge_version: int = 0
    target_knowledge_fingerprint: str = ""
    knowledge_gap_ids: tuple[str, ...] = ()
    selected_action_fingerprints: tuple[str, ...] = ()
    outcome_taxonomy: tuple[str, ...] = ()
    evidence_added: bool = False
    knowledge_updated: bool = False
    budget: Mapping[str, Any] = field(default_factory=dict)
    stop: Mapping[str, Any] = field(default_factory=dict)
    memory: Mapping[str, Any] = field(default_factory=dict)
    llm: Mapping[str, Any] = field(default_factory=dict)

    @staticmethod
    def _bounded_strings(values: Any, limit: int = 24) -> tuple[str, ...]:
        if not isinstance(values, (list, tuple, set, frozenset)):
            return ()
        cleaned_values: list[str] = []
        for value in values:
            redacted, _ = redact_sensitive(str(value or ""))
            text = _clean(redacted, 160)
            if _INLINE_SECRET_MARKER.search(text):
                text = "[REDACTED]"
            if text:
                cleaned_values.append(text)
        return tuple(cleaned_values[:limit])

    @classmethod
    def from_state(
        cls,
        state: Mapping[str, Any],
        *,
        target_knowledge: Mapping[str, Any] | None = None,
        gap_ids: Sequence[Any] = (),
        selected_actions: Sequence[Any] = (),
        outcomes: Sequence[Any] = (),
        evidence_added: bool = False,
        knowledge_updated: bool = False,
        llm_trace: Sequence[Any] = (),
    ) -> ResearchLoopContract:
        knowledge = dict(target_knowledge) if isinstance(target_knowledge, Mapping) else {}
        knowledge_json = canonical_json(knowledge)
        budget = state.get("action_budget")
        stop = state.get("stop_decision")
        budget_keys = (
            "limit",
            "spent",
            "remaining",
            "iterations",
            "iterations_limit",
            "replans",
            "replans_limit",
            "status",
        )
        safe_budget = {
            key: budget.get(key)
            for key in budget_keys
            if isinstance(budget, Mapping) and key in budget
        }
        safe_stop = {
            key: stop.get(key)
            for key in ("should_stop", "reason", "category", "safe_to_resume")
            if isinstance(stop, Mapping) and key in stop
        }
        raw_memory = state.get("memory_summary")
        memory_keys = (
            "records",
            "retrievals",
            "retrieval_items",
            "feedback_records",
            "retrieval_budget_remaining",
        )
        safe_memory = {
            key: raw_memory.get(key)
            for key in memory_keys
            if isinstance(raw_memory, Mapping) and key in raw_memory
        }
        statuses = {"accepted": 0, "needs_review": 0, "rejected": 0}
        if isinstance(llm_trace, (list, tuple)):
            for item in llm_trace[:24]:
                if isinstance(item, Mapping):
                    status = str(item.get("status") or "rejected")
                    if status in statuses:
                        statuses[status] += 1
        safe_llm = {
            "count": sum(statuses.values()),
            "accepted": statuses["accepted"],
            "needs_review": statuses["needs_review"],
            "rejected": statuses["rejected"],
        }
        outcome_values = []
        for value in outcomes:
            text = _clean(value, 80).lower()
            if text and text not in outcome_values:
                outcome_values.append(text)
        try:
            version = int(state.get("target_knowledge_version", 0))
        except (TypeError, ValueError):
            version = 0
        return cls(
            target_knowledge_version=max(0, version),
            target_knowledge_fingerprint=hashlib.sha256(
                knowledge_json.encode()
            ).hexdigest()[:32],
            knowledge_gap_ids=cls._bounded_strings(gap_ids),
            selected_action_fingerprints=cls._bounded_strings(selected_actions),
            outcome_taxonomy=tuple(outcome_values[:24]),
            evidence_added=bool(evidence_added),
            knowledge_updated=bool(knowledge_updated),
            budget=safe_budget,
            stop=safe_stop,
            memory=safe_memory,
            llm=safe_llm,
        )

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "schema_version": self.schema_version,
                "target_knowledge_version": self.target_knowledge_version,
                "target_knowledge_fingerprint": self.target_knowledge_fingerprint,
                "knowledge_gap_ids": list(self.knowledge_gap_ids),
                "selected_action_fingerprints": list(self.selected_action_fingerprints),
                "outcome_taxonomy": list(self.outcome_taxonomy),
                "evidence_added": self.evidence_added,
                "knowledge_updated": self.knowledge_updated,
                "budget": dict(self.budget),
                "stop": dict(self.stop),
                "memory": dict(self.memory),
                "llm": dict(self.llm),
            }
        )
        return clean


@dataclass
class ResearchSession:
    """Persistent, report-safe investigation context for bounded re-planning."""

    session_id: str
    engagement_id: str
    client_id: str
    objective: str = ""
    current_theory: str = ""
    supporting_evidence: list[str] = field(default_factory=list)
    contradicting_evidence: list[str] = field(default_factory=list)
    positive_evidence_ledger: list[dict[str, Any]] = field(default_factory=list)
    negative_evidence_ledger: list[dict[str, Any]] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    failed_paths: list[str] = field(default_factory=list)
    promising_paths: list[str] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)
    identity_context: dict[str, str] = field(default_factory=dict)
    causal_attack_graph: list[dict[str, Any]] = field(default_factory=list)
    next_best_actions: list[dict[str, Any]] = field(default_factory=list)
    stop_criteria: list[str] = field(default_factory=list)
    revisit_criteria: list[str] = field(default_factory=list)
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @classmethod
    def from_state(cls, state: Mapping[str, Any]) -> ResearchSession:
        existing = state.get("research_session")
        if isinstance(existing, Mapping):
            fields = {key: existing.get(key) for key in cls.__dataclass_fields__ if key in existing}
            return cls(
                session_id=_clean(fields.get("session_id") or "session:unknown", 128),
                engagement_id=_clean(
                    fields.get("engagement_id") or state.get("engagement_id"), 128
                ),
                client_id=_clean(fields.get("client_id") or state.get("client_id"), 128),
                **{
                    key: fields.get(key)
                    for key in cls.__dataclass_fields__
                    if key not in {"session_id", "engagement_id", "client_id"} and key in fields
                },
            )
        engagement_id = _clean(state.get("engagement_id") or "engagement:unknown", 128)
        client_id = _clean(state.get("client_id") or "client:unknown", 128)
        session_id = _clean(state.get("thread_id") or f"session:{engagement_id}", 128)
        return cls(
            session_id=session_id,
            engagement_id=engagement_id,
            client_id=client_id,
            objective="bounded autonomous research",
        )

    def record_action(self, ranked: RankedAction, *, outcome: str = "planned") -> None:
        self.next_best_actions.append(
            {
                "action_id": ranked.action.action_id,
                "fingerprint": ranked.action.fingerprint(),
                "action_class": ranked.action.action_class.value,
                "score": ranked.score,
                "outcome": _clean(outcome, 80),
                "reasons": list(ranked.reasons),
            }
        )
        self.next_best_actions = self.next_best_actions[-100:]
        self.updated_at = datetime.now(UTC).isoformat()

    def record_positive(self, evidence: PositiveEvidence) -> None:
        self.supporting_evidence.append(_clean(evidence.evidence_id, 128))
        self.positive_evidence_ledger.append(evidence.as_dict())
        self.positive_evidence_ledger = self.positive_evidence_ledger[-100:]
        self.promising_paths.append(_clean(evidence.action_fingerprint, 128))
        self.updated_at = datetime.now(UTC).isoformat()

    def record_negative(self, evidence: NegativeEvidence) -> None:
        self.contradicting_evidence.append(_clean(evidence.evidence_id, 128))
        self.negative_evidence_ledger.append(evidence.as_dict())
        self.negative_evidence_ledger = self.negative_evidence_ledger[-100:]
        self.failed_paths.append(_clean(evidence.action_fingerprint, 128))
        self.updated_at = datetime.now(UTC).isoformat()

    def as_dict(self) -> dict[str, Any]:
        clean, _ = redact_sensitive(
            {
                "session_id": _clean(self.session_id, 128),
                "engagement_id": _clean(self.engagement_id, 128),
                "client_id": _clean(self.client_id, 128),
                "objective": _clean(self.objective),
                "current_theory": _clean(self.current_theory),
                "supporting_evidence": [
                    _clean(item, 128) for item in self.supporting_evidence[-100:]
                ],
                "contradicting_evidence": [
                    _clean(item, 128) for item in self.contradicting_evidence[-100:]
                ],
                "positive_evidence_ledger": list(self.positive_evidence_ledger[-100:]),
                "negative_evidence_ledger": list(self.negative_evidence_ledger[-100:]),
                "open_questions": [_clean(item) for item in self.open_questions[-100:]],
                "failed_paths": [_clean(item, 128) for item in self.failed_paths[-100:]],
                "promising_paths": [_clean(item, 128) for item in self.promising_paths[-100:]],
                "coverage_gaps": [_clean(item, 128) for item in self.coverage_gaps[-100:]],
                "identity_context": dict(self.identity_context),
                "causal_attack_graph": list(self.causal_attack_graph[-100:]),
                "next_best_actions": list(self.next_best_actions[-100:]),
                "stop_criteria": [_clean(item) for item in self.stop_criteria],
                "revisit_criteria": [_clean(item) for item in self.revisit_criteria],
                "updated_at": self.updated_at,
            }
        )
        return clean


def default_session_expiry(days: int = 30) -> str:
    """Return an ISO expiry for reusable negative knowledge."""
    return (datetime.now(UTC) + timedelta(days=max(1, min(days, 365)))).isoformat()


__all__ = [
    "ActionClass",
    "GapKind",
    "GapStatus",
    "InformationAction",
    "KnowledgeGap",
    "KnowledgeGapEngine",
    "NegativeEvidence",
    "NegativeEvidenceLedger",
    "PositiveEvidence",
    "RankedAction",
    "ResearchLoopContract",
    "ResearchSession",
    "SmartNextBestActionEngine",
    "default_session_expiry",
]
