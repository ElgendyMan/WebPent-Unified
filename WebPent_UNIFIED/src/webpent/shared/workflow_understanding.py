"""Deterministic workflow understanding and bounded business-logic hypotheses.

This module is deliberately passive.  It inspects already-collected crawler,
form, API, and response metadata.  It does not send requests, mutate target
state, or infer a vulnerability without prerequisites and evidence references.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Iterable
from typing import Any
from urllib.parse import urljoin, urlparse

from webpent.models.evidence import canonical_json, redact_sensitive
from webpent.models.findings import VulnClass
from webpent.models.workflows import BusinessLogicHypothesisSpec, WorkflowObservation
from webpent.shared.confidence import EvidenceType, compute_confidence_score
from webpent.shared.llm import TaskType, with_prompt_cache_control

_SECRET_PARAM = re.compile(
    r"(?i)(?:token|secret|password|passwd|api[_-]?key|session|cookie|authorization|jwt)"
)
_OBJECT_PARAM = re.compile(
    r"(?i)(?:^|[_-])(id|user|account|owner|order|invoice|document|payment|resource)(?:[_-]|$)"
)
_STATE_WORDS = re.compile(
    r"(?i)(?:create|apply|approve|cancel|confirm|checkout|refund|delete|update|publish|draft|submit|login|logout|reset|verify|complete)"
)
_ROLE_KEYS = ("role", "actor_role", "user_role", "required_role", "authorization_scope")
_IDENTITY_KEYS = ("identity_ref", "actor_id", "user_id", "account_id", "owner_id", "subject_id")
_INTENT_WORDS = {
    "account": re.compile(r"(?i)(?:account|profile|user|member|signup|register|login|logout)"),
    "transaction": re.compile(r"(?i)(?:order|invoice|payment|checkout|refund|transfer)"),
    "content": re.compile(r"(?i)(?:draft|publish|comment|post|document|file|upload|export)"),
    "privileged": re.compile(r"(?i)(?:admin|moderator|staff|approve|delete|role|permission)"),
}


def build_workflow_understanding_prompt_messages(
    *, observation_count: int, workflow_count: int, question: str
) -> list[dict[str, Any]]:
    """Build a cache-marked static workflow schema prefix for optional LLM use."""
    messages: list[dict[str, Any]] = [
        {
            "role": "system",
            "content": "WebPent workflow-understanding schema v1; reason over bounded observations only.",
        },
        {
            "role": "user",
            "content": (
                f"Observed workflows={workflow_count}, transitions={observation_count}. "
                f"Question: {str(question)[:500]}"
            ),
        },
    ]
    return with_prompt_cache_control(
        messages, task_type=TaskType.ANALYSIS, static_index=0
    )


def _text(value: Any) -> str:
    if value is None:
        return ""
    clean, _ = redact_sensitive(str(value))
    return clean[:1000]


def _url(value: Any, *, base_url: str = "") -> str:
    raw = _text(value).strip()
    if not raw:
        return ""
    if base_url and not raw.startswith(("http://", "https://")):
        raw = urljoin(base_url, raw)
    parsed = urlparse(raw)
    if not parsed.scheme or not parsed.netloc:
        return raw[:1000]
    # Keep path and non-sensitive query keys only.  Values are never retained.
    pairs: list[str] = []
    for key in parsed.query.split("&") if parsed.query else []:
        name = key.split("=", 1)[0].strip()
        if name and not _SECRET_PARAM.search(name):
            pairs.append(f"{name}=[VALUE]")
    query = f"?{'&'.join(pairs)}" if pairs else ""
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}{query}"[:1000]


def _opaque_ref(prefix: str, value: Any) -> str | None:
    raw = _text(value).strip()
    if not raw:
        return None
    digest = hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def _identity_context(record: dict[str, Any]) -> tuple[str | None, list[str], list[str], str]:
    """Extract non-secret identity/subject context without retaining identifiers."""
    identity_ref = next(
        (ref for key in _IDENTITY_KEYS if (ref := _opaque_ref("identity", record.get(key)))),
        None,
    )
    context: list[str] = []
    if record.get("requires_auth") or record.get("authenticated") or identity_ref:
        context.append("authenticated")
    for key in _ROLE_KEYS:
        role_ref = _opaque_ref("role", record.get(key))
        if role_ref:
            context.append(role_ref)
    if record.get("cross_account") or record.get("different_identity"):
        context.append("cross_identity_signal")
    if record.get("authorization") or record.get("authorization_scope"):
        context.append("authorization_signal")

    parameters = record.get("parameters") or record.get("fields") or {}
    subject_refs = [
        f"subject:{str(key)[:60]}"
        for key in parameters
        if _OBJECT_PARAM.search(str(key))
    ] if isinstance(parameters, dict) else []
    subject_refs = list(dict.fromkeys(subject_refs))[:20]
    role_present = any(_opaque_ref("role", record.get(key)) for key in _ROLE_KEYS)
    if record.get("cross_account") or record.get("different_identity"):
        boundary = "cross_identity"
    elif role_present:
        boundary = "role_scoped"
    elif subject_refs:
        boundary = "object_scoped"
    elif context:
        boundary = "same_identity"
    else:
        boundary = "unknown"
    return identity_ref, list(dict.fromkeys(context))[:8], subject_refs, boundary


def _intent_tags(record: dict[str, Any], endpoint: str) -> list[str]:
    text = " ".join(
        _text(record.get(key))
        for key in (
            "url",
            "action",
            "title",
            "name",
            "operation",
            "workflow",
            "state",
            "next_state",
        )
    ) + f" {endpoint}"
    return [name for name, pattern in _INTENT_WORDS.items() if pattern.search(text)][:8]


def _method(value: Any) -> str:
    method = _text(value).upper() or "GET"
    return (
        method
        if method in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
        else "OTHER"
    )


def _iter_dicts(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                yield item


def _state_from_record(record: dict[str, Any]) -> str:
    for key in ("state", "status", "phase", "workflow_state", "current_state"):
        value = record.get(key)
        if value not in (None, ""):
            return _text(value).lower()[:120]
    text = " ".join(
        _text(record.get(key)) for key in ("url", "action", "title", "name", "operation")
    )
    match = _STATE_WORDS.search(text)
    return match.group(0).lower() if match else "unknown"


def _signals(record: dict[str, Any], *, form: bool = False) -> list[str]:
    signals: list[str] = ["form"] if form else []
    method = _method(record.get("method"))
    if method in {"POST", "PUT", "PATCH", "DELETE"}:
        signals.append("method_sequence")
    if record.get("redirect") or record.get("redirect_url") or record.get("location"):
        signals.append("redirect")
    if record.get("cookies_changed") or record.get("set_cookie") or record.get("cookie_changes"):
        signals.append("cookie_change")
    if record.get("csrf") or record.get("csrf_token") or record.get("csrf_changed"):
        signals.append("csrf_change")
    if record.get("token_changed") or record.get("response_token"):
        signals.append("token_change")
    if record.get("response_state") or record.get("response_status") or record.get("status"):
        signals.append("response_state")
    if record.get("api_sequence") or record.get("request_sequence"):
        signals.append("api_sequence")
    if (
        any(record.get(key) for key in (*_ROLE_KEYS, *_IDENTITY_KEYS))
        or record.get("requires_auth")
    ):
        signals.append("identity_context")
    if any(
        record.get(key)
        for key in (
            "authorization",
            "authorization_scope",
            "required_role",
            "cross_account",
            "different_identity",
        )
    ):
        signals.append("role_boundary")
    if _STATE_WORDS.search(
        _text(record.get("operation") or record.get("action") or record.get("title"))
    ):
        signals.append("workflow_intent")
    parameters = record.get("parameters")
    if isinstance(parameters, dict) and any(
        _OBJECT_PARAM.search(str(key)) for key in parameters
    ):
        signals.append("object_reference")
    return list(dict.fromkeys(signals))


def _prerequisites(record: dict[str, Any]) -> list[str]:
    prerequisites: list[str] = []
    if record.get("requires_auth") or record.get("authenticated") or record.get("identity_ref"):
        prerequisites.append("authenticated_identity")
    if record.get("csrf") or record.get("csrf_token") or record.get("csrf_changed"):
        prerequisites.append("current_csrf_context")
    parameters = record.get("parameters") or record.get("fields") or {}
    if isinstance(parameters, dict):
        for key in parameters:
            name = str(key)
            if _SECRET_PARAM.search(name):
                continue
            if _OBJECT_PARAM.search(name):
                prerequisites.append(f"object_parameter:{name[:60]}")
    if record.get("previous_step") or record.get("requires_previous"):
        prerequisites.append("preceding_workflow_step")
    if any(record.get(key) for key in (*_ROLE_KEYS, "authorization", "authorization_scope")):
        prerequisites.append("authorization_context")
    if record.get("cross_account") or record.get("different_identity"):
        prerequisites.append("second_identity_context")
    return list(dict.fromkeys(prerequisites))[:12]


def _fingerprint(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def extract_workflow_observations(
    crawled_data: dict[str, Any] | None,
    *,
    target_url: str = "",
    scope_checker: Any = None,
) -> list[WorkflowObservation]:
    """Extract unique, evidence-referenced workflow transitions passively."""
    data = crawled_data if isinstance(crawled_data, dict) else {}
    records: list[tuple[dict[str, Any], bool, str]] = []
    for form in _iter_dicts(data.get("forms")):
        records.append((form, True, "crawler:form"))
    for key in (
        "requests",
        "api_requests",
        "browser_requests",
        "sequences",
        "responses",
        "workflow_steps",
        "surface_records",
        "openapi_routes",
        "graphql_operations",
    ):
        for record in _iter_dicts(data.get(key)):
            records.append((record, False, f"crawler:{key}"))
    for endpoint in data.get("endpoints") or []:
        if isinstance(endpoint, dict):
            records.append((endpoint, False, "crawler:endpoint"))

    observations: list[WorkflowObservation] = []
    seen: set[str] = set()
    grouped: defaultdict[str, list[WorkflowObservation]] = defaultdict(list)
    for record, is_form, source_ref in records:
        endpoint = _url(
            record.get("action") or record.get("url") or record.get("endpoint"), base_url=target_url
        )
        if not endpoint:
            continue
        method = _method(record.get("method"))
        from_state = _state_from_record(record)
        to_state = (
            _text(
                record.get("to_state") or record.get("next_state") or record.get("redirect_state")
            )
            or from_state
        )
        signals = _signals(record, form=is_form)
        (
            identity_ref,
            identity_context,
            subject_refs,
            authorization_boundary,
        ) = _identity_context(record)
        intent_tags = _intent_tags(record, endpoint)
        tenant_ref = _text(
            record.get("tenant_ref") or record.get("tenant_id") or record.get("tenant")
        )[:200] or None
        if not signals:
            continue
        scope_decision = "unknown"
        if callable(scope_checker):
            try:
                scope_decision = "allowed" if bool(scope_checker(endpoint)) else "denied"
            except Exception:
                scope_decision = "unknown"
        payload = {
            "endpoint": endpoint,
            "method": method,
            "from_state": from_state,
            "to_state": to_state,
            "signals": signals,
            "identity_context": identity_context,
            "tenant_ref": tenant_ref,
            "authorization_boundary": authorization_boundary,
            "intent_tags": intent_tags,
            "source_ref": source_ref,
        }
        fingerprint = _fingerprint(payload)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        workflow_key = _text(
            record.get("workflow")
            or record.get("workflow_key")
            or f"{urlparse(endpoint).path}:{from_state}"
        )[:200]
        transition_key = f"{from_state}->{to_state}:{method}:{urlparse(endpoint).path}"[:200]
        evidence_ref = f"workflow:{fingerprint[:16]}"
        parameters = record.get("parameters")
        if not isinstance(parameters, dict):
            parameters = {}
        observation = WorkflowObservation(
            fingerprint=fingerprint,
            workflow_key=workflow_key,
            transition_key=transition_key,
            source_ref=source_ref,
            endpoint=endpoint,
            method=method,
            from_state=from_state,
            to_state=to_state,
            signals=signals,
            prerequisites=_prerequisites(record),
            identity_ref=identity_ref,
            tenant_ref=tenant_ref,
            identity_context=identity_context,
            subject_refs=subject_refs,
            authorization_boundary=authorization_boundary,
            intent_tags=intent_tags,
            object_refs=[
                f"object:{str(k)[:60]}"
                for k in parameters
                if _OBJECT_PARAM.search(str(k))
            ][:20],
            evidence_refs=[evidence_ref],
            confidence=min(0.95, 0.35 + 0.1 * len(signals) + 0.05 * len(_prerequisites(record))),
            scope_decision=scope_decision,
            destructive=method in {"POST", "PUT", "PATCH", "DELETE"},
        )
        observations.append(observation)
        grouped[workflow_key].append(observation)

    return observations


def generate_business_logic_hypotheses(
    observations: list[WorkflowObservation],
    *,
    target_url: str,
) -> list[BusinessLogicHypothesisSpec]:
    """Generate bounded, non-executing hypotheses only where prerequisites exist."""
    specs: list[BusinessLogicHypothesisSpec] = []
    seen: set[str] = set()
    for observation in observations:
        if observation.scope_decision == "denied":
            continue
        signals = set(observation.signals)
        prereqs = list(observation.prerequisites)
        candidates: list[tuple[str, str, str, list[str], str]] = []
        if observation.method in {"POST", "PUT", "PATCH", "DELETE"} and (
            "method_sequence" in signals or "form" in signals
        ):
            candidates.append(
                (
                    "replay",
                    (
                        f"The {observation.method} transition may accept a replay "
                        "after its expected state change."
                    ),
                    (
                        "The transition should reject a repeated request or "
                        "return an idempotent result."
                    ),
                    [
                        "one previously observed transition",
                        "same identity context",
                        "response comparison",
                    ],
                    "read_only_compare",
                )
            )
        if "object_reference" in signals and (
            "authenticated_identity" in prereqs or observation.identity_ref
        ):
            candidates.append(
                (
                    "cross_account_object",
                    (
                        "The object-referencing transition may not enforce "
                        "ownership for a different authorized identity."
                    ),
                    (
                        "A non-owner should receive a denial or a response "
                        "without owner-scoped data."
                    ),
                    [
                        "two locally authorized identities",
                        "object identifier evidence",
                        "differential response",
                    ],
                    "approval_required",
                )
            )
        if observation.authorization_boundary in {"cross_identity", "role_scoped"} or (
            "role_boundary" in signals and observation.identity_context
        ):
            candidates.append(
                (
                    "identity_boundary",
                    (
                        "The workflow may enforce an incomplete identity or role boundary "
                        "for this state-changing transition."
                    ),
                    (
                        "A non-equivalent identity or role should receive a denial and "
                        "should not observe or mutate protected workflow state."
                    ),
                    [
                        "redacted identity-context reference",
                        "role or authorization boundary evidence",
                        "differential denial response",
                    ],
                    "approval_required",
                )
            )
        if "csrf_change" in signals or "token_change" in signals:
            candidates.append(
                (
                    "state_confusion",
                    "The transition may rely on a stale CSRF or state token across workflow steps.",
                    "A stale token should be rejected and should not advance the workflow.",
                    [
                        "two observed token states",
                        "same workflow context",
                        "safe rejection evidence",
                    ],
                    "read_only_compare",
                )
            )
        if (
            observation.to_state != "unknown"
            and observation.from_state == observation.to_state
            and observation.method in {"POST", "PUT", "PATCH", "DELETE"}
        ):
            candidates.append(
                (
                    "missing_transition_authorization",
                    (
                        "The state-changing transition may be callable without "
                        "the prerequisite state transition."
                    ),
                    (
                        "The application should enforce the documented or "
                        "observed predecessor state."
                    ),
                    [
                        "observed state transition",
                        "read-only state check",
                        "authorization result",
                    ],
                    "approval_required",
                )
            )
        for kind, statement, expected, evidence_needed, action_type in candidates:
            from webpent.shared.evidence_contract import EvidenceContract
            confidence_score = compute_confidence_score(
                evidence_type=EvidenceType.HEURISTIC,
                evidence_signals={
                    "source_quality": min(1.0, 0.5 + 0.1 * len(signals)),
                    "reproducibility": min(1.0, 0.5 + 0.1 * len(evidence_needed)),
                    "identity_certainty": 1.0
                    if observation.identity_ref or observation.identity_context
                    else 0.5,
                    "oracle_strength": 1.0
                    if observation.authorization_boundary != "unknown"
                    else 0.5,
                    "deterministic_match": bool(observation.evidence_refs),
                },
            )
            contract = EvidenceContract.from_evidence_needed(
                evidence_needed,
                provenance=["business_logic", f"workflow:{kind}"],
                rationale="Workflow observation requires bounded replay/authorization evidence.",
            ).model_dump(mode="json")
            payload = {"kind": kind, "observation": observation.fingerprint, "target": target_url}
            fingerprint = _fingerprint(payload)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            specs.append(
                BusinessLogicHypothesisSpec(
                    fingerprint=fingerprint,
                    target_url=observation.endpoint or target_url,
                    statement=statement,
                    vuln_class=(
                        VulnClass.IDOR
                        if kind in {"cross_account_object", "identity_boundary"}
                        else VulnClass.UNKNOWN
                    ),
                    prerequisite=prereqs,
                    expected_behavior=expected,
                    action_type=action_type,
                    evidence_needed=evidence_needed,
                    evidence_contract=contract,
                    hint_provenance=["business_logic", f"workflow:{kind}"],
                    maximum_attempts=1,
                    request_budget=2 if action_type == "read_only_compare" else 0,
                    risk_level="high" if action_type == "approval_required" else "low",
                    evidence_refs=observation.evidence_refs,
                    origin_detail=f"workflow_understanding:{kind}",
                    confidence_score=confidence_score,
                )
            )
    return specs


def workflow_coverage_gaps(
    crawled_data: dict[str, Any] | None,
    observations: list[WorkflowObservation],
) -> list[dict[str, Any]]:
    """Return explicit gaps instead of treating missing metadata as a finding."""
    data = crawled_data if isinstance(crawled_data, dict) else {}
    gaps: list[dict[str, Any]] = []
    if not data.get("forms"):
        gaps.append(
            {
                "gap": "workflow_forms_missing",
                "reason": "No structured forms were supplied by discovery.",
                "status": "not_scanned",
            }
        )
    if not data.get("requests") and not data.get("api_requests") and not data.get("sequences"):
        gaps.append(
            {
                "gap": "workflow_sequence_missing",
                "reason": "No request sequence metadata was available.",
                "status": "not_scanned",
            }
        )
    if observations and not any("redirect" in item.signals for item in observations):
        gaps.append(
            {
                "gap": "redirect_state_missing",
                "reason": "No redirect/state-transition evidence was observed.",
                "status": "not_scanned",
            }
        )
    if observations and not any(
        item.identity_ref or "authenticated_identity" in item.prerequisites for item in observations
    ):
        gaps.append(
            {
                "gap": "identity_workflow_context_missing",
                "reason": "Workflow records lack an identity context.",
                "status": "needs_review",
            }
        )
    return gaps


__all__ = [
    "build_workflow_understanding_prompt_messages",
    "extract_workflow_observations",
    "generate_business_logic_hypotheses",
    "workflow_coverage_gaps",
]
