"""Passive surface-security coverage for evidence-first hunting.

The analyzer consumes already-collected crawl/form/header/JS metadata. It
never sends requests, executes JavaScript, mutates the target, or promotes an
observation into a Finding. Active validators and human approval remain
separate gates.
"""

# Existing report rationale strings intentionally preserve readable full sentences.
# E501 remains enforced on all other rules and all modified files.
# ruff: noqa: E501

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from webpent.models.surface_security import (
    SurfaceObservationStatus,
    SurfaceSecurityCategory,
    SurfaceSecurityObservation,
    SurfaceSecuritySummary,
)
from webpent.shared.application_intent_graph import build_application_intent_model
from webpent.shared.surface_evidence_graph import build_surface_evidence_graph
from webpent.shared.surface_influence_graph import (
    SurfaceInfluenceGraph,
    build_surface_influence_graph,
)

_MAX_ENDPOINTS = 250
_MAX_REFS = 12
_SECRET_KEY_RE = re.compile(
    r"(token|secret|password|passwd|api[_-]?key|cookie|authorization|jwt)", re.I
)
_PARAM_RE = re.compile(r"[?&]([^=&]+)")
_PATH_SIGNAL_RE = re.compile(
    r"/(?:api|graphql|graphiql|swagger|openapi|oauth|authorize|login|logout|signup|register|upload|file|download|export|import|admin|chat|prompt|completion|llm|ws|socket|websocket)(?:/|$)",
    re.I,
)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]


def _safe_url(value: Any) -> str:
    """Keep URL identity while replacing every query value and fragment."""
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
        query = "&".join(
            f"{key}=[REDACTED]" for key, _ in parse_qsl(parts.query, keep_blank_values=True)
        )
        return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))[:1200]
    except Exception:
        return raw.split("?", 1)[0][:1200]


def _endpoint_value(item: Any) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, Mapping):
        for key in ("url", "endpoint", "route", "target", "action"):
            if item.get(key):
                return str(item[key])
    return ""


def _records(value: Any) -> list[Mapping[str, Any]]:
    if isinstance(value, list):
        return [x for x in value if isinstance(x, Mapping)]
    if isinstance(value, Mapping):
        return [value]
    return []


def _text(value: Any) -> str:
    if isinstance(value, str):
        return value[:8000]
    if isinstance(value, Mapping):
        return " ".join(f"{k} {v}" for k, v in value.items())[:8000]
    if isinstance(value, list):
        return " ".join(_text(x) for x in value)[:8000]
    return str(value or "")[:8000]


def _param_names(url: str) -> set[str]:
    try:
        return {key.lower() for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)}
    except Exception:
        return {x.lower() for x in _PARAM_RE.findall(url)}


def _application_intent(data: Mapping[str, Any], endpoints: list[str]) -> list[str]:
    """Return bounded, explainable intent tags from already-collected metadata."""
    text = " ".join(
        [
            *endpoints,
            _text(data.get("forms")),
            _text(data.get("requests")),
            _text(data.get("api_requests")),
            _text(data.get("workflow_steps")),
        ]
    ).lower()
    rules = {
        "identity_and_account": ("login", "logout", "signup", "register", "profile", "account"),
        "transactional": ("order", "invoice", "payment", "checkout", "refund", "transfer"),
        "content_management": ("draft", "publish", "comment", "document", "upload", "export"),
        "privileged_administration": (
            "admin",
            "moderator",
            "staff",
            "approve",
            "permission",
            "role",
        ),
        "automation_or_ai": ("prompt", "completion", "chat", "webhook", "job", "workflow"),
    }
    return [name for name, needles in rules.items() if any(needle in text for needle in needles)][
        :20
    ]


def _opaque_context_refs(data: Mapping[str, Any]) -> list[str]:
    """Hash identity/role labels so graph links never retain account identifiers."""
    refs: list[str] = []
    for collection_key in ("forms", "requests", "api_requests", "workflow_steps", "endpoints"):
        for item in _records(data.get(collection_key)):
            for key in (
                "identity_ref",
                "actor_id",
                "user_id",
                "account_id",
                "owner_id",
                "role",
                "actor_role",
                "required_role",
            ):
                value = item.get(key)
                if value not in (None, ""):
                    refs.append(f"{key}:{_hash(str(value))}")
    return list(dict.fromkeys(refs))[:50]


def _workflow_refs(data: Mapping[str, Any]) -> list[str]:
    refs: list[str] = []
    for key in ("workflow_observations", "workflow_steps", "sequences"):
        for item in _records(data.get(key)):
            value = item.get("fingerprint") or item.get("evidence_ref") or item.get("workflow")
            if value:
                refs.append(f"workflow:{_hash(str(value))}")
    return list(dict.fromkeys(refs))[:50]


def _add(
    observations: list[SurfaceSecurityObservation],
    category: SurfaceSecurityCategory,
    status: SurfaceObservationStatus,
    title: str,
    reason: str,
    endpoints: Iterable[str] = (),
    signals: Iterable[str] = (),
    evidence: Iterable[str] = (),
    *,
    active: bool = False,
    human: bool = False,
    metadata: Mapping[str, Any] | None = None,
    limit: int = 500,
) -> None:
    if len(observations) >= limit:
        return
    refs = [_safe_url(x) for x in endpoints if _safe_url(x)]
    # Deduplicate and cap all report-facing references.
    refs = list(dict.fromkeys(refs))[:_MAX_REFS]
    sigs = list(dict.fromkeys(str(x)[:160] for x in signals if x))[:_MAX_REFS]
    evs = list(dict.fromkeys(str(x)[:160] for x in evidence if x))[:_MAX_REFS]
    observations.append(
        SurfaceSecurityObservation(
            category=category,
            status=status,
            title=title,
            reason=reason[:2000],
            endpoint_refs=refs,
            signal_refs=sigs,
            evidence_refs=evs,
            active_validation_required=active,
            human_review_required=human,
            metadata=dict(metadata or {}),
        )
    )


def analyze_security_surface(
    crawled_data: Mapping[str, Any] | None,
    target_url: str,
    *,
    javascript_intelligence: Mapping[str, Any] | None = None,
    max_observations: int = 100,
) -> dict[str, Any]:
    """Build a bounded passive coverage projection from collected metadata."""
    data = crawled_data if isinstance(crawled_data, Mapping) else {}
    observations: list[SurfaceSecurityObservation] = []
    endpoints = [_endpoint_value(x) for x in data.get("endpoints", [])]
    endpoints = [x for x in endpoints if x][:_MAX_ENDPOINTS]
    forms = _records(data.get("forms"))
    headers = data.get("response_headers") or data.get("headers") or data.get("responses") or []
    header_records = _records(headers)
    all_text = " ".join([*endpoints, _text(forms), _text(headers)])[:30000].lower()
    application_intent = _application_intent(data, endpoints)
    identity_context_refs = _opaque_context_refs(data)
    workflow_refs = _workflow_refs(data)
    path_names = " ".join(urlsplit(x).path.lower() for x in endpoints)
    params = set().union(*(_param_names(x) for x in endpoints)) if endpoints else set()
    methods = {str(f.get("method", "GET")).upper() for f in forms}
    form_inputs = " ".join(_text(f.get("inputs") or f.get("fields") or f) for f in forms).lower()
    js = (
        javascript_intelligence
        if isinstance(javascript_intelligence, Mapping)
        else data.get("javascript_intelligence") or {}
    )
    js_routes = _records(js.get("routes"))
    js_sinks = _records(js.get("sinks"))
    js_secrets = _records(js.get("secret_candidates"))
    js_text = _text(js_routes + js_sinks).lower()

    def has_path(*parts: str) -> bool:
        return any(part in path_names for part in parts)

    # Existing high-value surfaces and missing classes are all represented as
    # observations. The status is deliberately candidate/needs-validation
    # unless a structural fact itself is the finding (e.g. missing headers).
    if endpoints:
        _add(
            observations,
            SurfaceSecurityCategory.API,
            SurfaceObservationStatus.OBSERVED,
            "API surface observed",
            "Endpoint inventory is available for method-aware API testing.",
            endpoints,
            ["endpoint_inventory"],
            [f"surface:{_hash('api' + target_url)}"],
            active=True,
            limit=max_observations,
        )
    if has_path("/api", "/openapi", "/swagger"):
        _add(
            observations,
            SurfaceSecurityCategory.API,
            SurfaceObservationStatus.NEEDS_ACTIVE_VALIDATION,
            "API documentation or route surface",
            "API-like routes were collected; authentication, authorization, schema validation, rate limiting, and mass-assignment checks require validators.",
            endpoints,
            ["api_route"],
            active=True,
            limit=max_observations,
        )
    if (
        has_path("/graphql", "/graphiql")
        or "graphql" in js_text
        or "application/graphql" in all_text
    ):
        _add(
            observations,
            SurfaceSecurityCategory.GRAPHQL,
            SurfaceObservationStatus.NEEDS_ACTIVE_VALIDATION,
            "GraphQL surface candidate",
            "GraphQL route or client reference was observed; introspection, batching, authorization, depth, and resolver tests require bounded active validation.",
            endpoints + [str(r.get("route", "")) for r in js_routes if "graphql" in str(r).lower()],
            ["graphql_route"],
            active=True,
            limit=max_observations,
        )
    if (
        has_path("/oauth", "/authorize", "/openid")
        or "redirect_uri" in all_text
        or "client_id" in all_text
    ):
        _add(
            observations,
            SurfaceSecurityCategory.OAUTH,
            SurfaceObservationStatus.NEEDS_ACTIVE_VALIDATION,
            "OAuth surface candidate",
            "OAuth/OIDC route or parameter signal was observed; redirect, state, PKCE, token binding, and account-linking checks require controlled identities.",
            endpoints,
            ["oauth_route_or_parameter"],
            active=True,
            human=True,
            limit=max_observations,
        )
    if has_path("/login", "/logout", "/signin", "/signup", "/register", "/session") or methods - {
        "GET"
    }:
        _add(
            observations,
            SurfaceSecurityCategory.AUTHENTICATION,
            SurfaceObservationStatus.OBSERVED,
            "Authentication or state-changing surface",
            "Login/session/form signals were observed and should feed authentication and session-management validators.",
            endpoints,
            ["auth_or_state_change"],
            active=True,
            human=True,
            limit=max_observations,
        )
    if forms:
        _add(
            observations,
            SurfaceSecurityCategory.CSRF,
            SurfaceObservationStatus.NEEDS_ACTIVE_VALIDATION,
            "Form CSRF candidate",
            "HTML forms were discovered; token, SameSite, Origin/Referer, and state-transition validation is required per method and identity.",
            [str(f.get("action", "")) for f in forms],
            ["html_form"],
            active=True,
            human=True,
            limit=max_observations,
        )
    if (
        "type=file" in form_inputs
        or "file" in form_inputs
        or has_path("/upload", "/import", "/attachment")
    ):
        _add(
            observations,
            SurfaceSecurityCategory.FILE_UPLOAD,
            SurfaceObservationStatus.NEEDS_ACTIVE_VALIDATION,
            "File upload surface candidate",
            "A file input or upload/import route was observed; type, size, storage, execution, traversal, and authorization checks require a safe test file and approval for any executable behavior.",
            endpoints,
            ["file_input_or_upload_route"],
            active=True,
            human=True,
            limit=max_observations,
        )
    if has_path("/ws", "/socket", "/websocket") or "websocket" in all_text:
        _add(
            observations,
            SurfaceSecurityCategory.WEBSOCKETS,
            SurfaceObservationStatus.NEEDS_ACTIVE_VALIDATION,
            "WebSocket surface candidate",
            "WebSocket URL or client signal was observed; handshake authentication, origin, message authorization, injection, and lifecycle checks require a bounded client.",
            endpoints,
            ["websocket_signal"],
            active=True,
            human=True,
            limit=max_observations,
        )
    if any(x in params for x in {"filter", "selector", "where", "query", "mongo", "aggregate"}):
        _add(
            observations,
            SurfaceSecurityCategory.NOSQL_INJECTION,
            SurfaceObservationStatus.CANDIDATE,
            "NoSQL injection candidate",
            "Parameter names suggest a query/filter surface; no injection claim is made without controlled type-confusion and response-differential validation.",
            endpoints,
            ["query_like_parameter"],
            active=True,
            limit=max_observations,
        )
    if any(
        x in params
        for x in {"file", "path", "filename", "download", "template", "include", "resource"}
    ):
        _add(
            observations,
            SurfaceSecurityCategory.PATH_TRAVERSAL,
            SurfaceObservationStatus.CANDIDATE,
            "Path traversal candidate",
            "File/resource parameter names were observed; safe canonicalization and authorization validation is required.",
            endpoints,
            ["file_path_parameter"],
            active=True,
            limit=max_observations,
        )
    if any(x in params for x in {"cmd", "command", "exec", "ping", "host", "ip", "url"}):
        _add(
            observations,
            SurfaceSecurityCategory.COMMAND_INJECTION,
            SurfaceObservationStatus.CANDIDATE,
            "Command injection candidate",
            "Command/network parameter names were observed; confirmation requires non-destructive canary validation with explicit scope and approval.",
            endpoints,
            ["command_like_parameter"],
            active=True,
            human=True,
            limit=max_observations,
        )
    if any(
        x in params
        for x in {"url", "uri", "redirect", "next", "callback", "webhook", "feed", "image"}
    ):
        _add(
            observations,
            SurfaceSecurityCategory.SSRF,
            SurfaceObservationStatus.CANDIDATE,
            "SSRF or redirect candidate",
            "URL-bearing parameters were observed; server-side fetch behavior must be distinguished from client redirects using an approved canary.",
            endpoints,
            ["url_bearing_parameter"],
            active=True,
            human=True,
            limit=max_observations,
        )
    if "application/xml" in all_text or has_path("/xml", ".xml", "/soap"):
        _add(
            observations,
            SurfaceSecurityCategory.XXE,
            SurfaceObservationStatus.NEEDS_ACTIVE_VALIDATION,
            "XML parser surface candidate",
            "XML/SOAP content or routes were observed; external entity behavior requires a safe out-of-band or local-only validation plan.",
            endpoints,
            ["xml_surface"],
            active=True,
            human=True,
            limit=max_observations,
        )
    if any(x in params for x in {"template", "view", "render", "format", "expression"}):
        _add(
            observations,
            SurfaceSecurityCategory.SSTI,
            SurfaceObservationStatus.CANDIDATE,
            "Template expression candidate",
            "Template-like parameters were observed; engine-specific non-destructive differential testing is required.",
            endpoints,
            ["template_like_parameter"],
            active=True,
            limit=max_observations,
        )
    if (
        any(x in params for x in {"object", "data", "state", "deserialize", "serialized", "value"})
        or "application/x-java-serialized-object" in all_text
    ):
        _add(
            observations,
            SurfaceSecurityCategory.DESERIALIZATION,
            SurfaceObservationStatus.CANDIDATE,
            "Deserialization surface candidate",
            "State/object parameters or serialized content were observed; format identification and safe gadget-free validation are required.",
            endpoints,
            ["serialized_or_object_signal"],
            active=True,
            human=True,
            limit=max_observations,
        )
    if js_sinks:
        dom_sinks = [
            x
            for x in js_sinks
            if str(x.get("category", "")).lower()
            in {"dom_xss", "html_injection", "navigation", "message_handling"}
        ]
        if dom_sinks:
            _add(
                observations,
                SurfaceSecurityCategory.DOM,
                SurfaceObservationStatus.CANDIDATE,
                "DOM/client-side sink candidate",
                "Static JavaScript review found a client-side sink; source-to-sink data-flow and runtime proof are required.",
                [str(x.get("source_asset", "")) for x in dom_sinks],
                [str(x.get("category", "")) for x in dom_sinks],
                [str(x.get("evidence_ref", "")) for x in dom_sinks],
                active=True,
                limit=max_observations,
            )
    if js_secrets:
        # Secret candidates are already value-redacted by the JavaScript
        # intelligence layer. Keep this projection evidence-only: expose the
        # detector kind, source asset, and stable evidence reference, but never
        # copy a candidate value into report-facing metadata.
        secret_sources = [str(x.get("source_asset", "")) for x in js_secrets]
        secret_signals = [
            f"js_secret_kind:{str(x.get('kind') or 'unknown')[:100]}" for x in js_secrets
        ]
        secret_evidence = [
            str(x.get("evidence_ref", "")) for x in js_secrets if x.get("evidence_ref")
        ]
        confidence_counts: dict[str, int] = {}
        validation_counts: dict[str, int] = {}
        for candidate in js_secrets:
            confidence = str(candidate.get("confidence") or "unknown")
            validation = str(candidate.get("validation_status") or "unknown")
            confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1
            validation_counts[validation] = validation_counts.get(validation, 0) + 1
        _add(
            observations,
            SurfaceSecurityCategory.SECRETS_EXPOSURE,
            SurfaceObservationStatus.NEEDS_ACTIVE_VALIDATION,
            "JavaScript secret candidate observed",
            "JavaScript intelligence reported one or more redacted secret candidates. Verify ownership, exposure scope, rotation status, and exploitability through an approved human-reviewed workflow; this passive observation is not proof of a usable secret.",
            secret_sources,
            secret_signals,
            secret_evidence,
            active=True,
            human=True,
            metadata={
                "candidate_count": len(js_secrets),
                "confidence_counts": confidence_counts,
                "validation_status_counts": validation_counts,
                "values_redacted": True,
            },
            limit=max_observations,
        )
    if js_routes and any(str(x.get("discovery_kind", "")).lower() == "graphql" for x in js_routes):
        _add(
            observations,
            SurfaceSecurityCategory.GRAPHQL,
            SurfaceObservationStatus.NEEDS_ACTIVE_VALIDATION,
            "GraphQL client route candidate",
            "Static JavaScript route extraction found a GraphQL client reference.",
            [str(x.get("route", "")) for x in js_routes],
            ["js_graphql_route"],
            active=True,
            limit=max_observations,
        )
    if "__proto__" in js_text or "constructor.prototype" in js_text or "prototype[" in js_text:
        _add(
            observations,
            SurfaceSecurityCategory.PROTOTYPE_POLLUTION,
            SurfaceObservationStatus.CANDIDATE,
            "Prototype pollution candidate",
            "Static JavaScript review found prototype mutation/access patterns; exploitability depends on controllable source and a reachable gadget.",
            [str(x.get("source_asset", "")) for x in js_routes + js_sinks],
            ["prototype_mutation_pattern"],
            active=True,
            limit=max_observations,
        )
    if has_path("/chat", "/prompt", "/completion", "/llm", "/assistant", "/ai") or any(
        x in params for x in {"prompt", "system", "model", "messages", "completion"}
    ):
        _add(
            observations,
            SurfaceSecurityCategory.WEB_LLM,
            SurfaceObservationStatus.NEEDS_ACTIVE_VALIDATION,
            "Web LLM surface candidate",
            "Prompt/model/message endpoint signals were observed; model authorization, prompt injection, indirect injection, data exfiltration, tool/plugin boundaries, and cost controls require an approved test plan.",
            endpoints,
            ["llm_route_or_parameter"],
            active=True,
            human=True,
            limit=max_observations,
        )

    # Header-derived structural findings are safe to classify as observed
    # misconfiguration candidates, but not as exploit impact.
    header_text = _text(header_records or headers).lower()
    has_csp = "content-security-policy" in header_text
    has_frame = "x-frame-options" in header_text or "frame-ancestors" in header_text
    if not has_frame and endpoints:
        _add(
            observations,
            SurfaceSecurityCategory.CLICKJACKING,
            SurfaceObservationStatus.CANDIDATE,
            "Framing protection not observed",
            "Collected response metadata did not contain X-Frame-Options or CSP frame-ancestors; verify representative authenticated and unauthenticated responses before reporting.",
            endpoints,
            ["missing_frame_protection"],
            active=True,
            limit=max_observations,
        )
    if (
        "access-control-allow-origin: *" in header_text
        or "access-control-allow-credentials: true" in header_text
    ):
        _add(
            observations,
            SurfaceSecurityCategory.CORS,
            SurfaceObservationStatus.CANDIDATE,
            "Permissive CORS signal",
            "Collected response metadata contains permissive CORS headers; origin reflection, credential behavior, and sensitive response access require controlled browser validation.",
            endpoints,
            ["cors_header"],
            active=True,
            human=True,
            limit=max_observations,
        )
    if not has_csp and endpoints:
        _add(
            observations,
            SurfaceSecurityCategory.INFORMATION_DISCLOSURE,
            SurfaceObservationStatus.OBSERVED,
            "Security header coverage gap",
            "Content-Security-Policy was not observed in the supplied response metadata; this is a hardening observation, not proof of exploitability.",
            endpoints,
            ["missing_csp"],
            limit=max_observations,
        )
    if (
        "cache-control" in header_text
        or "age:" in header_text
        or "x-cache" in header_text
        or "via:" in header_text
    ):
        _add(
            observations,
            SurfaceSecurityCategory.CACHE_DECEPTION,
            SurfaceObservationStatus.NEEDS_ACTIVE_VALIDATION,
            "Cache behavior observed",
            "Cache-related response headers were observed; cache key, authorization variance, path confusion, and unkeyed input tests require a read-only differential plan.",
            endpoints,
            ["cache_header"],
            active=True,
            human=True,
            limit=max_observations,
        )
        _add(
            observations,
            SurfaceSecurityCategory.CACHE_POISONING,
            SurfaceObservationStatus.NEEDS_ACTIVE_VALIDATION,
            "Cache poisoning candidate surface",
            "A cache layer is visible; poisoning requires controlled harmless headers/parameters and cache isolation before any claim.",
            endpoints,
            ["cache_layer"],
            active=True,
            human=True,
            limit=max_observations,
        )
    if "host:" in header_text or "x-forwarded-host" in header_text or "forwarded:" in header_text:
        _add(
            observations,
            SurfaceSecurityCategory.HOST_HEADER,
            SurfaceObservationStatus.NEEDS_ACTIVE_VALIDATION,
            "Host header trust surface",
            "Forwarded host metadata was observed; password-reset, absolute URL, routing, and cache effects require controlled validation.",
            endpoints,
            ["host_forwarding_header"],
            active=True,
            human=True,
            limit=max_observations,
        )

    # Always expose explicit coverage gaps for classes that need active
    # capabilities not represented by the passive input, rather than silently
    # reporting them as clean.
    known = {str(x.category) for x in observations}
    gaps: list[str] = []
    for category in SurfaceSecurityCategory:
        if category.value not in known:
            gaps.append(f"{category.value}: no relevant passive signal in supplied collection")
    intent_model = build_application_intent_model(data, target_url=target_url)
    surface_graph = build_surface_evidence_graph(data, target_url=target_url)
    # Project Zero: the influence graph is designed to run alongside the
    # evidence graph on the same input (see
    # webpent.shared.surface_influence_graph). It is attached only when the
    # operator enabled it (default-off), is deterministic, and is advisory.
    influence_graph: SurfaceInfluenceGraph | None = None
    try:
        from webpent.config.settings import get_settings

        if bool(getattr(get_settings(), "enable_surface_influence_graph", False)):
            influence_graph = build_surface_influence_graph(data)
    except Exception:  # pragma: no cover - fail-soft, never blocks the summary
        influence_graph = None
    summary = SurfaceSecuritySummary(
        observations=observations[:max_observations],
        categories_scanned=[
            SurfaceSecurityCategory(x) for x in sorted({str(o.category) for o in observations})
        ],
        coverage_gaps=gaps[:100],
        application_intent=application_intent,
        identity_context_refs=identity_context_refs,
        workflow_refs=workflow_refs,
        application_intent_model=intent_model,
        surface_graph=surface_graph,
        surface_influence_graph=(
            influence_graph.as_dict() if influence_graph is not None else None
        ),
    )
    return summary.as_dict()


__all__ = ["analyze_security_surface"]
