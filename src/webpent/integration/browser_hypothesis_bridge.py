"""Browser-surface -> hypothesis generator bridge.

NEW MODULE (not frozen). Pure data transform: consumes a browser-observed
surface (SPA routes, forms with parameters, XHR/fetch endpoints, auth-flow
state transitions, JS-analysis secrets) and emits first-class
:class:`webpent.models.hypothesis.Hypothesis` objects through the normal
hypothesis path. It does NOT call the crawler or the hypothesis generator
(both frozen) — it produces the documented shapes they consume.

Design principles (carried forward from prior sprints):
  * Deterministic, no LLM. Hypothesis family is decided by a plain lookup
    table over parameter/endpoint type, not free speculation.
  * Fail-closed. Untrusted browser strings are sanitised through
    ``secure_prompt_value``; path-injection-shaped values are rejected;
    total hypothesis count is hard-capped.
  * Origin traceable. Every hypothesis carries origin=DEEP_RECON with
    origin_detail="browser_observed:<source>" so the decision trail from
    browser observation -> hypothesis -> candidate -> finding is auditable.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from webpent.models.findings import VulnClass
from webpent.models.hypothesis import Hypothesis, HypothesisOrigin, HypothesisStatus
from webpent.shared.untrusted_content import secure_prompt_value

MAX_HYPOTHESES_PER_SURFACE = 32
MAX_PARAMS_PER_FORM = 16
MAX_SECRETS = 8

# Parameter-name -> vuln family lookup. Deterministic table, not LLM.
_PARAM_FAMILY_HINTS: tuple[tuple[re.Pattern[str], tuple[VulnClass, ...]], ...] = (
    (re.compile(r"(^|[_-])(id|uid|userid|user_id|account|account_id|object|object_id|record|record_id|resource|resource_id|doc|doc_id|file|file_id|order|order_id|invoice|invoice_id|profile|profile_id)([_-]|$)", re.I), (VulnClass.IDOR,)),
    (re.compile(r"(^|[_-])(url|uri|link|href|redirect|return|return_to|next|dest|destination|callback|image|img|avatar|logo|fetch|proxy|feed)([_-]|$)", re.I), (VulnClass.SSRF, VulnClass.OPEN_REDIRECT)),
    (re.compile(r"(^|[_-])(q|query|search|s|keyword|name|username|email|comment|message|title|description|content|text)([_-]|$)", re.I), (VulnClass.XSS, VulnClass.SQLI)),
    (re.compile(r"(^|[_-])(role|is_admin|admin|privilege|permissions|scope|access_level|user_type|account_type)([_-]|$)", re.I), (VulnClass.MASS_ASSIGNMENT, VulnClass.AUTH_BYPASS)),
    (re.compile(r"(^|[_-])(file|path|filepath|template|page|view|include|lang|locale)([_-]|$)", re.I), (VulnClass.PATH_TRAVERSAL, VulnClass.LFI)),
)

# JS secret patterns -> info disclosure. Deterministic regex table.
_JS_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})"), "api_key"),
    (re.compile(r"(?i)(aws[_-]?access[_-]?key[_-]?id|aws_secret)\s*[:=]\s*['\"]?([A-Z0-9]{16,})"), "aws_credential"),
    (re.compile(r"(?i)(token|auth[_-]?token|bearer|jwt|session[_-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{16,})"), "hardcoded_token"),
    (re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{6,})['\"]"), "hardcoded_password"),
)

_PATH_INJECTION_RE = re.compile(r"[/\\?#]|\.\.|\r|\n")


@dataclass(frozen=True)
class BrowserForm:
    action: str
    method: str = "GET"
    inputs: tuple[Mapping[str, Any], ...] = ()
    source_route: str = ""


@dataclass(frozen=True)
class BrowserXhrEndpoint:
    url: str
    method: str = "GET"
    params: tuple[str, ...] = ()
    source_route: str = ""


@dataclass(frozen=True)
class BrowserStateTransition:
    from_route: str
    to_route: str
    requires_auth: bool = False
    principal_alias: str | None = None


@dataclass(frozen=True)
class BrowserSurface:
    """Normalised browser-observed surface. Mirrors SurfaceMap shape."""

    target_url: str
    routes: tuple[str, ...] = ()
    forms: tuple[BrowserForm, ...] = ()
    xhr_endpoints: tuple[BrowserXhrEndpoint, ...] = ()
    state_transitions: tuple[BrowserStateTransition, ...] = ()
    js_blobs: tuple[str, ...] = ()


def _sanitize(value: Any) -> str:
    cleaned = secure_prompt_value(value)
    text = str(cleaned or "").strip()
    if len(text) > 256:
        text = text[:256]
    return text


def _families_for_param(param_name: str) -> tuple[VulnClass, ...]:
    name = _sanitize(param_name)
    for pattern, families in _PARAM_FAMILY_HINTS:
        if pattern.search(name):
            return families
    return (VulnClass.API_ISSUE,)


def _hypothesis(target_url: str, statement: str, vuln_class: VulnClass, origin_detail: str, confidence: float = 0.35) -> Hypothesis:
    stmt = _sanitize(statement)
    if len(stmt) < 3:
        stmt = f"Browser-observed surface suggests {vuln_class.value} investigation."
    if len(stmt) > 500:
        stmt = stmt[:500]
    return Hypothesis(
        target_url=_sanitize(target_url),
        statement=stmt,
        vuln_class=vuln_class,
        status=HypothesisStatus.UNEXPLORED,
        confidence_score=max(0.0, min(1.0, confidence)),
        evidence_refs=[],
        origin=HypothesisOrigin.DEEP_RECON,
        origin_detail=f"browser_observed:{origin_detail}",
    )


def _normalize_surface(surface: Any) -> BrowserSurface:
    """Accept BrowserSurface, Mapping, or surface with dict members -> typed."""
    if isinstance(surface, Mapping):
        return _surface_from_dict(surface)
    if isinstance(surface, BrowserSurface):
        forms = tuple(f if isinstance(f, BrowserForm) else _form_from_dict(f) for f in (surface.forms or ()))
        xhr = tuple(e if isinstance(e, BrowserXhrEndpoint) else _xhr_from_dict(e) for e in (surface.xhr_endpoints or ()))
        trans = tuple(t if isinstance(t, BrowserStateTransition) else _transition_from_dict(t) for t in (surface.state_transitions or ()))
        return BrowserSurface(
            target_url=surface.target_url,
            routes=tuple(surface.routes or ()),
            forms=forms,
            xhr_endpoints=xhr,
            state_transitions=trans,
            js_blobs=tuple(surface.js_blobs or ()),
        )
    raise TypeError(f"unsupported surface type: {type(surface).__name__}")


def _form_from_dict(f: Mapping[str, Any]) -> BrowserForm:
    return BrowserForm(
        action=_sanitize((f or {}).get("action", "")),
        method=_sanitize((f or {}).get("method", "GET")).upper() or "GET",
        inputs=tuple((f or {}).get("inputs") or ()),
        source_route=_sanitize((f or {}).get("source_route", "")),
    )


def _xhr_from_dict(e: Mapping[str, Any]) -> BrowserXhrEndpoint:
    return BrowserXhrEndpoint(
        url=_sanitize((e or {}).get("url", "")),
        method=_sanitize((e or {}).get("method", "GET")).upper() or "GET",
        params=tuple(str(p) for p in ((e or {}).get("params") or ())),
        source_route=_sanitize((e or {}).get("source_route", "")),
    )


def _transition_from_dict(t: Mapping[str, Any]) -> BrowserStateTransition:
    return BrowserStateTransition(
        from_route=_sanitize((t or {}).get("from_route", "")),
        to_route=_sanitize((t or {}).get("to_route", "")),
        requires_auth=bool((t or {}).get("requires_auth")),
        principal_alias=_sanitize((t or {}).get("principal_alias")) or None,
    )


def hypotheses_from_forms(surface: Any) -> tuple[Hypothesis, ...]:
    """Forms with parameters -> IDOR/XSS/SQLI/SSRF/etc hypotheses per param."""
    surface = _normalize_surface(surface)
    out: list[Hypothesis] = []
    for form in surface.forms:
        action = _sanitize(form.action)
        for raw_input in form.inputs[:MAX_PARAMS_PER_FORM]:
            if len(out) >= MAX_HYPOTHESES_PER_SURFACE:
                break
            name = _sanitize((raw_input or {}).get("name") or (raw_input or {}).get("id") or "")
            if not name or _PATH_INJECTION_RE.search(name):
                continue  # fail-closed: reject injection-shaped param names
            families = _families_for_param(name)
            for fam in families:
                if len(out) >= MAX_HYPOTHESES_PER_SURFACE:
                    break
                out.append(_hypothesis(
                    surface.target_url,
                    f"Form {form.method} {action or surface.target_url} parameter '{name}' may be vulnerable to {fam.value}; browser-observed input surface.",
                    fam,
                    origin_detail=f"form_param:{name}",
                    confidence=0.4 if fam in (VulnClass.IDOR, VulnClass.XSS, VulnClass.SSRF) else 0.3,
                ))
    return tuple(out)


def hypotheses_from_xhr_endpoints(surface: Any) -> tuple[Hypothesis, ...]:
    """XHR/fetch endpoints -> API-surface hypotheses (SSRF if url param, IDOR if id param)."""
    surface = _normalize_surface(surface)
    out: list[Hypothesis] = []
    for ep in surface.xhr_endpoints:
        if len(out) >= MAX_HYPOTHESES_PER_SURFACE:
            break
        url = _sanitize(ep.url)
        params = [_sanitize(p) for p in ep.params][:MAX_PARAMS_PER_FORM]
        fams: set[VulnClass] = {VulnClass.API_ISSUE}
        for p in params:
            if _PATH_INJECTION_RE.search(p):
                continue
            fams.update(_families_for_param(p))
        for fam in fams:
            if len(out) >= MAX_HYPOTHESES_PER_SURFACE:
                break
            out.append(_hypothesis(
                surface.target_url,
                f"Browser-observed XHR {ep.method} {url} with params {params or '(none)'} suggests {fam.value} investigation on hidden API surface.",
                fam,
                origin_detail=f"xhr_endpoint:{urlsplit(url).path or url}",
                confidence=0.45,
            ))
    return tuple(out)


def hypotheses_from_auth_flow(surface: Any) -> tuple[Hypothesis, ...]:
    """State-graph transitions (login -> authenticated routes) -> principal context."""
    surface = _normalize_surface(surface)
    out: list[Hypothesis] = []
    authed_routes = [
        _sanitize(t.to_route)
        for t in surface.state_transitions
        if t.requires_auth and _sanitize(t.to_route)
    ]
    for route in authed_routes:
        if len(out) >= MAX_HYPOTHESES_PER_SURFACE:
            break
        principal = _sanitize(next((t.principal_alias for t in surface.state_transitions if t.requires_auth), "authenticated_user"))
        out.append(_hypothesis(
            surface.target_url,
            f"Authenticated route '{route}' (principal={principal}) discovered via browser state transition; test IDOR/auth-bypass with foreign principal.",
            VulnClass.IDOR,
            origin_detail=f"auth_transition:{route}",
            confidence=0.5,
        ))
    return tuple(out)


def hypotheses_from_js_secrets(surface: Any) -> tuple[Hypothesis, ...]:
    """JS analysis -> hardcoded secrets -> INFO_DISCLOSURE hypotheses."""
    surface = _normalize_surface(surface)
    out: list[Hypothesis] = []
    seen: set[str] = set()
    for blob in surface.js_blobs:
        text = str(blob or "")
        for pattern, kind in _JS_SECRET_PATTERNS:
            for match in pattern.finditer(text):
                if len(out) >= MAX_SECRETS or len(out) >= MAX_HYPOTHESES_PER_SURFACE:
                    break
                secret = _sanitize(match.group(2)[:16]) + "...(redacted)"
                key = f"{kind}:{secret}"
                if key in seen:
                    continue
                seen.add(key)
                out.append(_hypothesis(
                    surface.target_url,
                    f"JS analysis disclosed hardcoded {kind} in client-side code; information disclosure / credential exposure.",
                    VulnClass.INFO_DISCLOSURE,
                    origin_detail=f"js_secret:{kind}",
                    confidence=0.6,
                ))
    return tuple(out)


def browser_surface_to_hypotheses(surface: Any) -> tuple[Hypothesis, ...]:
    """Entry point: normalised browser surface -> deduplicated, capped hypotheses."""
    surface = _normalize_surface(surface)
    collected: list[Hypothesis] = []
    for generator in (hypotheses_from_forms, hypotheses_from_xhr_endpoints, hypotheses_from_auth_flow, hypotheses_from_js_secrets):
        if len(collected) >= MAX_HYPOTHESES_PER_SURFACE:
            break
        collected.extend(generator(surface))
    # deduplicate by (vuln_class, statement) preserving order
    seen: set[tuple[str, str]] = set()
    deduped: list[Hypothesis] = []
    for hyp in collected:
        key = (str(hyp.vuln_class), hyp.statement)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(hyp)
    return tuple(deduped[:MAX_HYPOTHESES_PER_SURFACE])


def _surface_from_dict(data: Mapping[str, Any]) -> BrowserSurface:
    forms = tuple(
        BrowserForm(
            action=_sanitize((f or {}).get("action", "")),
            method=_sanitize((f or {}).get("method", "GET")).upper() or "GET",
            inputs=tuple((f or {}).get("inputs") or ()),
            source_route=_sanitize((f or {}).get("source_route", "")),
        )
        for f in (data.get("forms") or ())
    )
    xhr = tuple(
        BrowserXhrEndpoint(
            url=_sanitize((e or {}).get("url", "")),
            method=_sanitize((e or {}).get("method", "GET")).upper() or "GET",
            params=tuple(str(p) for p in ((e or {}).get("params") or ())),
            source_route=_sanitize((e or {}).get("source_route", "")),
        )
        for e in (data.get("xhr_endpoints") or ())
    )
    transitions = tuple(
        BrowserStateTransition(
            from_route=_sanitize((t or {}).get("from_route", "")),
            to_route=_sanitize((t or {}).get("to_route", "")),
            requires_auth=bool((t or {}).get("requires_auth")),
            principal_alias=_sanitize((t or {}).get("principal_alias")) or None,
        )
        for t in (data.get("state_transitions") or ())
    )
    return BrowserSurface(
        target_url=_sanitize(data.get("target_url", "")),
        routes=tuple(_sanitize(r) for r in (data.get("routes") or ())),
        forms=forms,
        xhr_endpoints=xhr,
        state_transitions=transitions,
        js_blobs=tuple(str(b) for b in (data.get("js_blobs") or ())),
    )


__all__ = [
    "BrowserForm",
    "BrowserSurface",
    "BrowserStateTransition",
    "BrowserXhrEndpoint",
    "browser_surface_to_hypotheses",
    "hypotheses_from_auth_flow",
    "hypotheses_from_forms",
    "hypotheses_from_js_secrets",
    "hypotheses_from_xhr_endpoints",
]
