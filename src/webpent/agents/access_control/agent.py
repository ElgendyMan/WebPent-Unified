"""Evidence-first multi-identity access-control mapper.

The node remains in the existing LangGraph position, but its probe contract is
now explicit: it compares read-only responses across identities and only emits
a Tool-Confirmed IDOR when ownership provenance plus a reproducible foreign
access differential are both present.  A numeric URL permutation alone is
never treated as confirmation.
"""

from __future__ import annotations

import json
import logging
import os
import random
import re
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from langchain_core.messages import AIMessage

from webpent.models.findings import Finding, Severity, VulnClass
from webpent.shared.authorization_matrix import build_authorization_matrix
from webpent.shared.bac_identity_tester import (
    IdentityProfile,
    assess_access_control,
    build_relational_evidence,
    cookies_from_auth_state,
    extract_object_id,
    normalise_identity_profiles,
    profile_owns_resource,
    sanitise_probe_result,
    target_fingerprint,
)
from webpent.shared.target_package_context import package_continuity_kwargs
from webpent.shared.verifier import verify_replay_evidence
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("webpent.audit.access_control")

_ID_PATTERN = re.compile(
    r"/(?:"
            r"(?:users?|accounts?|orders?|baskets?|documents?|files?|downloads?|messages?|posts?|"
        r"items?|products?|invoices?|payments?|transactions?|user_profiles?|profiles?|"

    r"settings?|configs?|projects?|tasks?|tickets?|reports?)"
    r"/(\d+|[a-f0-9-]{8,}|[a-zA-Z0-9_-]{10,})"
    r")",
    re.IGNORECASE,
)
_ID_KEY_PATTERN = re.compile(r"^(?:id|.*[_-]id|.*Id)$", re.IGNORECASE)
_OWNERSHIP_HEADER_KEYS = frozenset(
    {"x-user-id", "x-owner-id", "x-account-id", "x-tenant-id", "x-actor-id"}
)
_MAX_IDENTIFIER_VALUES = 32


def _scalar_identifier(value: Any) -> str | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (str, int)):
        candidate = str(value).strip()
        return candidate[:200] if candidate else None
    return None


def _iter_id_like_values(payload: Any) -> list[tuple[str, str]]:
    """Return bounded id-like values from nested request metadata."""
    found: list[tuple[str, str]] = []

    def walk(value: Any, path: str = "") -> None:
        if len(found) >= _MAX_IDENTIFIER_VALUES:
            return
        if isinstance(value, dict):
            for key, child in list(value.items())[:_MAX_IDENTIFIER_VALUES]:
                key_text = str(key)
                child_path = f"{path}.{key_text}" if path else key_text
                scalar = _scalar_identifier(child)
                if _ID_KEY_PATTERN.match(key_text) and scalar is not None:
                    found.append((child_path, scalar))
                elif isinstance(child, (dict, list)):
                    walk(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value[:_MAX_IDENTIFIER_VALUES]):
                if isinstance(child, (dict, list)):
                    walk(child, f"{path}[{index}]")

    walk(payload)
    return found[:_MAX_IDENTIFIER_VALUES]


def _request_identifier_sources(record: dict[str, Any], url: str) -> list[tuple[str, str]]:
    """Collect redaction-safe source labels and id-like values from a record."""
    sources: list[tuple[str, str]] = []
    parsed = urlparse(url)
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        scalar = _scalar_identifier(value)
        if _ID_KEY_PATTERN.match(key) and scalar is not None:
            sources.append((f"query:{key}", scalar))

    for field in ("body", "request_data", "json_body", "data"):
        payload = record.get(field)
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except (TypeError, ValueError, json.JSONDecodeError):
                payload = None
        if isinstance(payload, (dict, list)):
            sources.extend(
                (f"{field}:{path}", value)
                for path, value in _iter_id_like_values(payload)
            )

    headers = record.get("headers") or record.get("request_headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).lower() not in _OWNERSHIP_HEADER_KEYS:
                continue
            scalar = _scalar_identifier(value)
            if scalar is not None:
                sources.append((f"header:{key}", scalar))
    return list(dict.fromkeys(sources))[:_MAX_IDENTIFIER_VALUES]


def _graphql_projection_records(javascript_intelligence: Any) -> list[dict[str, Any]]:
    """Bridge redacted GraphQL operation metadata into BAC records."""
    if hasattr(javascript_intelligence, "model_dump"):
        javascript_intelligence = javascript_intelligence.model_dump(mode="json")
    if not isinstance(javascript_intelligence, dict):
        return []
    operations: list[Any] = []
    for key in ("graphql_operations", "graphql_queries", "operations"):
        value = javascript_intelligence.get(key)
        if isinstance(value, list):
            operations.extend(value)
    for route in javascript_intelligence.get("routes") or []:
        if isinstance(route, dict) and str(route.get("discovery_kind", "")).lower() == "graphql":
            operations.append(route)
    records: list[dict[str, Any]] = []
    for operation in operations[:_MAX_IDENTIFIER_VALUES]:
        if not isinstance(operation, dict):
            continue
        url = operation.get("url") or operation.get("route") or operation.get("endpoint")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            continue
        variables = operation.get("variables") or operation.get("variable_values")
        variable_names = operation.get("variable_names") or operation.get("graphql_variables")
        identifiers = _iter_id_like_values(variables)
        if isinstance(variable_names, list):
            identifiers.extend(
                (f"graphql:{name}", str(name))
                for name in variable_names[:_MAX_IDENTIFIER_VALUES]
                if _ID_KEY_PATTERN.match(str(name))
            )
        if not identifiers:
            continue
        records.append(
            {
                "url": url,
                "method": str(operation.get("method") or "POST").upper(),
                "graphql_variables": [path for path, _ in identifiers[:_MAX_IDENTIFIER_VALUES]],
                "object_id": next(
                    (value for path, value in identifiers if not path.startswith("graphql:")),
                    None,
                ),
                "candidate_sources": [f"graphql:{path}" for path, _ in identifiers],
                "request_data": variables if isinstance(variables, dict) else None,
            }
        )
    return records


def _extract_candidate_records(
    crawled_data: Any,
    javascript_intelligence: Any = None,
) -> list[dict[str, Any]]:
    """Extract dynamic resource records from common crawler shapes.

    Structured crawler artifacts may provide ``owner_identity`` or
    ``object_id``.  Plain URLs remain supported for backward compatibility,
    but are deliberately treated as ownership-unknown later.
    """
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    values: list[Any] = []
    if isinstance(crawled_data, dict):
        for key in ("urls", "endpoints", "links", "pages", "resources"):
            value = crawled_data.get(key)
            if isinstance(value, list):
                values.extend(value)
        for key, value in crawled_data.items():
            if isinstance(key, str) and key.startswith("http"):
                if isinstance(value, dict):
                    values.append({"url": key, **value})
                else:
                    values.append(key)
    elif isinstance(crawled_data, list):
        values.extend(crawled_data)
    values.extend(_graphql_projection_records(javascript_intelligence))

    for value in values:
        if isinstance(value, dict):
            url = value.get("url") or value.get("href") or value.get("endpoint")
            if not isinstance(url, str):
                continue
            record = dict(value)
        else:
            url = str(value)
            record = {}
        if not url.startswith(("http://", "https://")):
            continue
        identifiers = _request_identifier_sources(record, url)
        has_path_id = bool(_ID_PATTERN.search(urlparse(url).path))
        if not has_path_id and not identifiers:
            continue
        record["url"] = url
        identifier_object_id = next(
            (value for source, value in identifiers if not source.startswith("header:")),
            None,
        )
        record["object_id"] = (
            record.get("object_id") or identifier_object_id or extract_object_id(url)
        )
        record["candidate_sources"] = list(
            dict.fromkeys(
                list(record.get("candidate_sources") or [])
                + [source for source, _ in identifiers]
                + (["path"] if has_path_id else [])
            )
        )
        if identifiers:
            record["candidate_identifiers"] = [value for _, value in identifiers]
        method = str(record.get("method") or record.get("http_method") or "GET").upper()
        record["method"] = method
        canonical = "|".join(
            (url.rstrip("/"), method, str(record.get("object_id") or ""))
        )
        if canonical in seen:
            continue
        seen.add(canonical)
        owner = (
            record.get("owner_identity")
            or record.get("owner")
            or record.get("owner_id")
            or (record.get("metadata") or {}).get("owner_identity")
            if isinstance(record.get("metadata") or {}, dict)
            else record.get("owner_identity")
        )
        if owner:
            record["owner_identity"] = str(owner)
        records.append(record)
    return records


def _extract_idor_candidates(
    crawled_data: dict[str, Any], javascript_intelligence: Any = None
) -> list[str]:
    """Backward-compatible URL-only candidate extractor."""
    return [
        str(record["url"])
        for record in _extract_candidate_records(crawled_data, javascript_intelligence)
    ]


def _enumerate_adjacent_ids(record: dict[str, Any], profile: Any) -> list[str]:
    """Return a bounded list of numeric neighboring IDs; UUIDs are skipped."""
    raw_id = str(record.get("object_id") or extract_object_id(str(record.get("url") or "")) or "")
    if not raw_id.isdigit():
        return []
    try:
        base = int(raw_id)
    except ValueError:
        return []
    configured = profile.get("max_neighbors", 5) if isinstance(profile, dict) else 5
    limit = max(1, min(int(configured), 10))
    neighbors: list[str] = []
    for delta in range(1, limit + 1):
        for candidate in (base - delta, base + delta):
            if candidate >= 0:
                neighbors.append(str(candidate))
    return neighbors[:limit]


def _replace_candidate_id(url: str, old_id: str, new_id: str) -> str:
    parsed = urlparse(url)
    path = parsed.path.replace(f"/{old_id}", f"/{new_id}", 1)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    changed = False
    replaced_query: list[tuple[str, str]] = []
    for key, value in query:
        if not changed and _ID_KEY_PATTERN.match(key) and value == old_id:
            replaced_query.append((key, new_id))
            changed = True
        else:
            replaced_query.append((key, value))
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            path,
            parsed.params,
            urlencode(replaced_query),
            parsed.fragment,
        )
    )


def _probe_url(
    url: str,
    cookies: dict[str, str] | None = None,
    timeout: float = 10.0,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    allow_state_changing: bool = False,
    target_scope: tuple[str, ...] = (),
    capture_observation: bool = False,
    identity_label: str | None = None,
    guard_redirects: bool = True,
) -> tuple[int, int] | dict[str, Any]:
    """Probe a URL and optionally return redacted transport provenance.

    GET/HEAD/OPTIONS are always read-only. State-changing methods are denied
    unless the caller explicitly opts in through the BAC safety gate. The
    default return remains the legacy tuple; strict BAC uses the observation
    form, which contains digests only and never raw cookies or response bodies.
    """
    method = str(method or "GET").upper()
    if method not in {"GET", "HEAD", "OPTIONS"} and not allow_state_changing:
        audit_logger.warning(
            "Blocked state-changing BAC probe method=%s url=%s without explicit approval",
            method,
            url,
        )
        return (
            {"status_code": 0, "content_length": 0, "target_backed": False}
            if capture_observation
            else (0, 0)
        )
    request_digest = None
    if capture_observation:
        safe_header_names = sorted(str(key).lower() for key in (headers or {}))
        request_material = "|".join(
            [str(identity_label or "unknown"), method, str(url), repr(safe_header_names)]
        )
        import hashlib

        request_digest = f"sha256:{hashlib.sha256(request_material.encode()).hexdigest()}"
    try:
        from webpent.config.settings import get_settings
        from webpent.shared.engagement_scope import (
            clear_engagement_target_hosts,
            set_engagement_target_hosts,
        )
        from webpent.shared.http import build_cookie_header, make_safe_httpx_client

        scope_token = None
        if target_scope:
            scope_token = set_engagement_target_hosts(*target_scope)
        parsed_url = urlparse(url)
        request_headers: dict[str, str] = {
            "User-Agent": os.getenv(
                "HTTP_USER_AGENT",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "Chrome/131.0.0.0 Safari/537.36",
            ),
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
        }
        if parsed_url.scheme and parsed_url.netloc:
            request_headers["Referer"] = f"{parsed_url.scheme}://{parsed_url.netloc}/"
        request_headers.update(headers or {})
        if cookies:
            request_headers["Cookie"] = build_cookie_header(cookies)
        allow_insecure_tls = bool(get_settings().allow_insecure_tls)
        if allow_insecure_tls:
            audit_logger.warning(
                "Access-control probe is using disabled TLS verification "
                "for an authorized lab target"
            )
        pacing_value = os.getenv("WEBPENT_HTTP_PACING_INTERVAL", "").strip()
        if pacing_value:
            try:
                pacing_interval = max(0.0, float(pacing_value))
            except ValueError:
                pacing_interval = 0.0
            if pacing_interval > 0.0:
                from webpent.shared.stealth import enforce_min_interval, extract_host

                enforce_min_interval(
                    True,
                    extract_host(url),
                    min_interval_override=pacing_interval,
                    jitter_max_override=max(2.0, pacing_interval * 2.5),
                )
        try:
            with make_safe_httpx_client(
                timeout=timeout,
                follow_redirects=False,
                verify=not allow_insecure_tls,
                guard_redirects=guard_redirects,
            ) as client:
                response = client.request(method, url, headers=request_headers)
            if not capture_observation:
                return response.status_code, len(response.content)
            import hashlib

            response_digest = f"sha256:{hashlib.sha256(bytes(response.content)).hexdigest()}"
            return {
                "status_code": int(response.status_code),
                "content_length": len(response.content),
                "response_headers": dict(response.headers),
                "body_hash": response_digest,
                "request_digest": request_digest,
                "response_digest": response_digest,
                "target_backed": True,
                "target_fingerprint": target_fingerprint(url),
            }
        finally:
            if scope_token is not None:
                clear_engagement_target_hosts(scope_token)
    except Exception as exc:
        logger.debug("BAC probe failed for %s: %s", url, exc)
        if capture_observation:
            return {
                "status_code": 0,
                "content_length": 0,
                "request_digest": request_digest,
                "target_backed": False,
                "target_fingerprint": target_fingerprint(url),
                "error_type": type(exc).__name__,
            }
        return 0, 0


def _coerce_probe_result(
    result: tuple[int, int] | dict[str, Any],
    *,
    url: str,
    profile: IdentityProfile,
) -> dict[str, Any]:
    """Convert real or legacy probe output into a sanitised observation."""
    if isinstance(result, dict):
        return sanitise_probe_result(
            profile=profile,
            url=url,
            status_code=int(result.get("status_code") or 0),
            content_length=int(result.get("content_length") or 0),
            response_headers=result.get("response_headers") or {},
            body_hash=result.get("body_hash"),
            request_digest=result.get("request_digest"),
            response_digest=result.get("response_digest"),
            target_backed=result.get("target_backed"),
            target_url=url,
            target_fingerprint_value=result.get("target_fingerprint"),
        )
    status_code, content_length = result
    return sanitise_probe_result(
        profile=profile,
        url=url,
        status_code=int(status_code),
        content_length=int(content_length),
        target_backed=False,
        target_url=url,
    )


def _create_idor_finding(
    url: str,
    status_code: int,
    content_length: int,
    auth_context: str,
    *,
    evidence: dict[str, Any] | None = None,
    confidence_level: str = "AI-Assessed",
    description_suffix: str = "",
    owner_role: str | None = None,
    foreign_role: str | None = None,
) -> Finding:
    """Create a finding while keeping the legacy four-argument contract."""
    path = urlparse(url).path or url
    known_roles = {
        str(role).strip().lower()
        for role in (owner_role, foreign_role)
        if role and str(role).strip().lower() not in {"unknown", "none"}
    }
    privilege_escalation = (
        len(known_roles) == 2
        and str(owner_role).strip().lower() != str(foreign_role).strip().lower()
    )
    severity = Severity.CRITICAL if privilege_escalation else Severity.HIGH
    vuln_class = VulnClass.AUTH_BYPASS.value if privilege_escalation else VulnClass.IDOR.value
    reasoning = (
        f"Privilege escalation via role differential: owner role={owner_role}, "
        f"foreign role={foreign_role}; {auth_context}; HTTP {status_code}, "
        f"{content_length} bytes."
        if privilege_escalation
        else f"Read-only access-control differential: {auth_context}; "
        f"HTTP {status_code}, {content_length} bytes."
    )
    return Finding(
        title=f"IDOR: Unauthorized access to {path}"[:120],
        description=(
            f"The endpoint {url} returned HTTP {status_code} with "
            f"{content_length} bytes of content when accessed {auth_context}. "
            "This observation requires authorization comparison against an "
            f"explicit resource owner. {description_suffix}"
        ).strip(),
        severity=severity,
        confidence="confirmed" if confidence_level == "Tool-Confirmed" else "tentative",
        confidence_level=confidence_level,
        evidence=evidence,
        vuln_class=vuln_class,
        url=url,
        tool_name="access_control_mapper",
        payload="",
        reasoning=reasoning,
    )


def _public_identity_rows(profiles: list[IdentityProfile]) -> dict[str, dict[str, Any]]:
    return {profile.name: profile.public_metadata for profile in profiles}


def _identity_profiles_from_state(state: PentestState) -> list[IdentityProfile]:
    raw = state.get("identity_profiles") or state.get("bac_identities") or state.get("identities")
    if not raw and state.get("identity_records"):
        from webpent.agents.authentication.agent import _profiles_from_identity_records

        raw = _profiles_from_identity_records(state)
    fallback = state.get("session_cookies") or None
    if not fallback:
        fallback = cookies_from_auth_state(state.get("auth_state")) or None
    return normalise_identity_profiles(raw, fallback_cookies=fallback)


def _wait_before_bac(url: str) -> float:
    """Optionally idle before BAC when a crawler just completed authentication.

    Some targets count authenticated requests made during discovery/login in the
    same rolling window as the ownership probe.  The default remains zero so
    existing engagements are unchanged; authorized lab runs can opt into a
    bounded idle window. Both the documented ``..._SECS`` spelling and the
    older ``..._SECONDS`` spelling are accepted for backward compatibility.
    """
    raw_cooldown = os.getenv("WEBPENT_BAC_INITIAL_COOLDOWN_SECS")
    if raw_cooldown is None:
        raw_cooldown = os.getenv("WEBPENT_BAC_INITIAL_COOLDOWN_SECONDS", "0")
    try:
        cooldown = min(90.0, max(0.0, float(raw_cooldown)))
    except ValueError:
        cooldown = 0.0
    if cooldown <= 0.0:
        return 0.0
    raw_jitter = os.getenv("WEBPENT_BAC_INITIAL_JITTER_MAX_SECONDS", "1.5")
    try:
        jitter_max = min(3.0, max(0.0, float(raw_jitter)))
    except ValueError:
        jitter_max = 1.5
    delay = cooldown + (random.uniform(0.0, jitter_max) if jitter_max else 0.0)
    logger.info("BAC initial cooldown: waiting %.2fs before probing %s", delay, url)
    time.sleep(delay)
    return delay


def _wait_after_throttle(url: str) -> float:
    """Wait through a bounded server throttle window before retrying.

    A server-side periodic-request detector may keep a 429 block briefly. A
    refresh/login performed immediately after the response can reproduce that
    block, so the retry path waits before trying again. The delay is bounded
    and configurable, a small random component avoids creating a fixed request
    cadence, and an expiry margin allows the server-side cache to clear.

    """
    raw_cooldown = os.getenv("WEBPENT_BAC_THROTTLE_COOLDOWN_SECONDS", "10")
    try:
        cooldown = min(30.0, max(0.0, float(raw_cooldown)))
    except ValueError:
        cooldown = 10.0
    raw_jitter = os.getenv("WEBPENT_BAC_THROTTLE_JITTER_MAX_SECONDS", "2.5")
    try:
        jitter_max = min(3.0, max(0.0, float(raw_jitter)))
    except ValueError:
        jitter_max = 2.5
    # The lab's detector keeps its timestamp cache for 12 seconds even
    # after the visible 10-second block expires. Add a bounded margin so the
    # retry does not immediately recreate or observe the same throttle.
    delay = cooldown + (random.uniform(0.0, jitter_max) if jitter_max else 0.0) + 3.5
    if delay > 0.0:
        logger.info(
            "BAC throttle cooldown: waiting %.2fs before retrying %s",
            delay,
            url,
        )
        time.sleep(delay)
    return delay


def _refresh_profile_after_throttle(
    state: PentestState,
    target: Any,
    profile: IdentityProfile,
) -> IdentityProfile | None:
    """Refresh one authenticated profile after a bounded throttle response.

    This is deliberately narrow: it runs only after a 429/503 response, uses
    credentials from the worker-only vault, performs one normal login through
    the authentication agent, and returns ``None`` when re-authentication is
    unavailable or unsuccessful. It never promotes a finding by itself.
    """
    if profile.name == "anonymous" or not profile.cookies:
        return None
    thread_id = str(state.get("thread_id") or "")
    if not thread_id:
        return None
    try:
        from webpent.agents.authentication.agent import _perform_login
        from webpent.auth.reauth_vault import (
            identity_vault_key,
            unseal_identity_profiles,
            unseal_reauth_secret,
        )
    except Exception as exc:
        logger.debug("BAC profile refresh unavailable: %s", exc)
        return None

    scoped_key = identity_vault_key(
        str(state.get("client_id") or ""),
        str(state.get("engagement_id") or ""),
    )
    raw_profiles = unseal_identity_profiles(scoped_key) if scoped_key else {}
    if not raw_profiles:
        raw_profiles = unseal_identity_profiles(thread_id)
    raw_profile: dict[str, Any] = {}
    if isinstance(raw_profiles, dict):
        for key, value in raw_profiles.items():
            if not isinstance(value, dict):
                continue
            candidate_name = str(value.get("name") or key)
            if candidate_name == profile.name or str(key) == profile.name:
                raw_profile = value
                break
    raw_credentials = raw_profile.get("credentials") if raw_profile else None
    username = ""
    password = ""
    if isinstance(raw_credentials, dict):
        username = str(raw_credentials.get("username") or "")
        password = str(raw_credentials.get("password") or "")
    if not password and profile.metadata.get("authenticated_primary") is True:
        state_credentials = state.get("credentials") or {}
        username = username or str(state_credentials.get("username") or profile.name)
        password = unseal_reauth_secret(thread_id)
    if not username or not password:
        return None

    target_url = str(getattr(target, "url", "") or "")
    if isinstance(target, dict):
        target_url = str(target.get("url") or target_url)
    if not target_url:
        return None
    additional_origins = [
        str(value).strip()
        for value in list(state.get("additional_target_origins") or [])
        if str(value).strip()
    ]
    try:
        cookies = _perform_login(
            target_url,
            username,
            password,
            additional_target_origins=additional_origins,
        )
    except Exception as exc:
        logger.debug("BAC profile refresh failed for %s: %s", profile.name, exc)
        return None
    if not cookies:
        return None
    refreshed_metadata = dict(profile.metadata)
    refreshed_metadata["session_refreshed_after_throttle"] = True
    return IdentityProfile(
        name=profile.name,
        role=profile.role,
        cookies=cookies,
        headers=dict(profile.headers),
        owned_object_ids=profile.owned_object_ids,
        owned_urls=profile.owned_urls,
        metadata=refreshed_metadata,
    )


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def access_control_node(state: PentestState) -> dict:
    """Compare resource access across anonymous and available identities."""
    target = state.get("target")

    # SCENARIO CONTRACT (step 9): probe the session before this heavy
    # authenticated phase; bounded re-login refresh applies to the node's
    # view of state so cross-principal probing uses live cookies only.
    _liveness_gate: dict[str, Any] = {}
    try:
        from webpent.shared.session_liveness import phase_liveness_update

        _liveness_gate = phase_liveness_update(state, phase="access_control")
        if _liveness_gate.get("session_cookies"):
            state = {**state, "session_cookies": {
                **(state.get("session_cookies") or {}),
                **_liveness_gate["session_cookies"],
            }}
    except Exception as _gate_exc:  # noqa: BLE001 — gate must never stop the phase
        logger.warning("Access-control session liveness gate skipped safely: %s", _gate_exc)
        _liveness_gate = {}

    findings: list[Finding] = list(state.get("findings") or [])
    crawled_data: Any = state.get("crawled_data") or {}
    javascript_intelligence = (
        state.get("javascript_intelligence")
        or state.get("js_intelligence")
        or {}
    )
    records = _extract_candidate_records(crawled_data, javascript_intelligence)
    target_url = str(getattr(target, "url", "") or "")
    if isinstance(target, dict):
        target_url = str(target.get("url") or target_url)
    if not records and target_url:
        direct_object_id = extract_object_id(target_url)
        records = [
            {
                "url": target_url,
                "object_id": direct_object_id,
                "method": "GET",
                "candidate_sources": ["declared_target_url"],
            }
        ]
        logger.info("Access Control Mapper: using declared target URL as bounded candidate")
    if not records:
        logger.info("Access Control Mapper: no IDOR candidates found")
        _no_candidates_update: dict[str, Any] = {
            "messages": [AIMessage(content="Access Control Mapper: no IDOR candidates found.")],
            "current_phase": "access_control_mapping",
        }
        for _gate_key in ("session_liveness", "session_cookies", "engagement_limitations"):
            if _liveness_gate and _gate_key in _liveness_gate:
                _no_candidates_update[_gate_key] = _liveness_gate[_gate_key]
        return _no_candidates_update

    profiles = _identity_profiles_from_state(state)
    # Anonymous is always tested, but never carries ownership metadata.
    probe_profiles = [IdentityProfile(name="anonymous", role="unauthenticated")] + profiles
    # A legacy single session remains useful, but the result is a coverage gap
    # rather than a claimed cross-user confirmation.
    max_candidates = int(state.get("bac_max_candidates") or 20)
    max_identities = int(state.get("bac_max_identities") or 8)
    probe_profiles = probe_profiles[: max(2, max_identities)]
    try:
        from webpent.config.settings import get_settings

        bac_settings = get_settings()
        enumeration_enabled = (
            bool(state.get("enable_idor_enumeration"))
            if "enable_idor_enumeration" in state
            else bool(bac_settings.enable_idor_enumeration)
        )
        enumeration_neighbors = int(
            state.get("idor_enumeration_neighbors")
            or bac_settings.idor_enumeration_neighbors
        )
    except Exception as exc:
        logger.debug("BAC enumeration settings unavailable: %s", exc)
        enumeration_enabled = False
        enumeration_neighbors = 0
    records = records[:max_candidates]
    try:
        from webpent.shared.engagement_scope import normalize_declared_origins

        scope_origins = (
            (target_url,) if target_url else ()
        ) + tuple(
            normalize_declared_origins(state.get("additional_target_origins") or [])
        )
    except Exception:
        scope_origins = (target_url,) if target_url else ()
    if enumeration_enabled and enumeration_neighbors > 0:
        enumerated_records: list[dict[str, Any]] = []
        for record in records:
            for neighbor in _enumerate_adjacent_ids(
                record,
                {"max_neighbors": enumeration_neighbors},
            ):
                clone = dict(record)
                source_url = str(record.get("url") or "")
                old_id = str(record.get("object_id") or extract_object_id(source_url) or "")
                clone["url"] = _replace_candidate_id(source_url, old_id, neighbor)
                clone["object_id"] = neighbor
                clone["candidate_sources"] = list(
                    dict.fromkeys(
                        list(record.get("candidate_sources") or [])
                        + ["bounded_adjacent_id"]
                    )
                )
                clone["enumerated_from"] = old_id
                enumerated_records.append(clone)
        remaining_capacity = max(0, max_candidates - len(records))
        records.extend(enumerated_records[:remaining_capacity])

    new_findings: list[Finding] = []
    observations_out: list[dict[str, Any]] = []
    gaps_out: list[dict[str, Any]] = []
    relational_out: list[dict[str, Any]] = []
    matrix_inputs: list[dict[str, Any]] = []
    proof_bundles_out: list[dict[str, Any]] = []
    confirmed_count = 0
    # Give an authorized lab target an optional bounded idle window after
    # discovery/authentication traffic and before the first ownership probe.
    # The helper is always called once for observability, but its default is
    # zero seconds, preserving existing engagements and test speed.
    if records:
        _wait_before_bac(str(records[0].get("url") or target.url))
    for record in records:

        url = str(record["url"])
        effective_profiles = list(probe_profiles)
        object_id = str(record.get("object_id") or extract_object_id(url) or "") or None
        owner_identity = str(record.get("owner_identity") or "").strip() or None
        if not owner_identity:
            owners = [
                profile.name
                for profile in profiles
                if profile_owns_resource(profile, url, object_id)
            ]
            if len(owners) == 1:
                owner_identity = owners[0]

        # Authenticated primary sessions are the provenance of resources
        # discovered during the owner crawl. This fallback is deliberately
        # narrow: it only applies when the crawler supplied no explicit owner,
        # exactly one validated primary profile exists, and the profile carries
        # the auth marker emitted by auth_node. Confirmation still requires a
        # successful foreign replay plus a denied foreign negative control.
        if not owner_identity:
            primary_owners = [
                profile.name
                for profile in profiles
                if profile.metadata.get("authenticated_primary") is True
                and profile.role.lower() == "owner"
                and bool(profile.cookies)
            ]
            if len(primary_owners) == 1:
                owner_identity = primary_owners[0]

        rows: list[dict[str, Any]] = []
        for profile_index, profile in enumerate(effective_profiles):
            requested_method = str(
                record.get("method") or record.get("http_method") or "GET"
            ).upper()
            probe_kwargs = {
                "cookies": profile.cookies or None,
                "headers": profile.headers or None,
                "method": requested_method,
                "allow_state_changing": bool(
                    state.get("auto_approve") is True
                    or state.get("bac_allow_state_changing_probes") is True
                ),
                "target_scope": scope_origins,
                "capture_observation": True,
                "identity_label": profile.name,
                "guard_redirects": False,
            }
            try:
                raw_probe = _probe_url(url, **probe_kwargs)
            except TypeError as exc:
                # Preserve compatibility with injected legacy probes that only
                # accept url/cookies/timeout/headers; their tuple result is
                # explicitly review-only and cannot satisfy strict proof.
                if "unexpected keyword argument" not in str(exc):
                    raise
                raw_probe = _probe_url(
                    url,
                    cookies=profile.cookies or None,
                    headers=profile.headers or None,
                )
            row = _coerce_probe_result(raw_probe, url=url, profile=profile)
            row["observation_role"] = (
                "baseline"
                if profile.name == owner_identity
                else "negative_control"
                if profile.name == "anonymous"
                else "candidate"
            )
            if int(row.get("status_code") or 0) in {429, 503}:
                # First retry with the already validated session after the
                # server-side cooldown. Re-authentication is intentionally
                # deferred until the bounded recovery path below.
                _wait_after_throttle(url)
                raw_probe = _probe_url(url, **probe_kwargs)
                row = _coerce_probe_result(raw_probe, url=url, profile=profile)
                row["observation_role"] = (
                    "baseline"
                    if profile.name == owner_identity
                    else "negative_control"
                    if profile.name == "anonymous"
                    else "candidate"
                )
                if int(row.get("status_code") or 0) in {429, 503} and state.get("thread_id"):
                    refreshed = _refresh_profile_after_throttle(state, target, profile)
                    if refreshed is not None:
                        effective_profiles[profile_index] = refreshed
                        profile = refreshed
                        probe_kwargs["cookies"] = profile.cookies or None
                        probe_kwargs["headers"] = profile.headers or None
                        probe_kwargs["identity_label"] = profile.name
                    _wait_after_throttle(url)
                    raw_probe = _probe_url(url, **probe_kwargs)
                    row = _coerce_probe_result(raw_probe, url=url, profile=profile)
                    row["observation_role"] = (
                        "baseline"
                        if profile.name == owner_identity
                        else "negative_control"
                        if profile.name == "anonymous"
                        else "candidate"
                    )
            rows.append(row)
            matrix_inputs.append(
                {
                    **row,
                    "owner_identity": owner_identity,
                    "object_id": object_id,
                    "candidate_sources": list(record.get("candidate_sources") or []),
                    "endpoint": url,
                    "method": requested_method,
                    "evidence_refs": [
                        "bac:"
                        f"{object_id or 'unknown'}:{profile.name}:"
                        f"{row.get('response_fingerprint', '')[:24]}"
                    ],
                }
            )

        assessment = assess_access_control(rows, owner_identity=owner_identity)
        edges = build_relational_evidence(rows, owner_identity=owner_identity, object_id=object_id)
        for edge in edges:
            edge["target_url"] = getattr(target, "url", None)
        relational_out.extend(edges)
        observations_out.append(
                            {
                    "resource_url": url,
                    "object_id": object_id,
                    "owner_identity": owner_identity,
                    "candidate_sources": list(record.get("candidate_sources") or []),
                    "enumerated_from": record.get("enumerated_from"),
                    "identities_tested": [row["identity"] for row in rows],
                    "observations": rows,
                    "assessment": assessment,
                }

        )

        if assessment["status"] == "confirmed":
            foreign = next(
                row for row in rows if row["identity"] != owner_identity and row["accessible"]
            )
            evidence = {
                "type": "relational_access_control",
                "owner_identity": owner_identity,
                "object_id": object_id,
                "identity_observations": rows,
                "relational_edges": edges,
                "redaction": "cookies, authorization headers, and raw bodies omitted",
            }
            negative_control = next(
                (
                    row
                    for row in rows
                    if row.get("identity") != owner_identity and not row.get("accessible")
                ),
                None,
            )
            evidence["causal_signal"] = True
            evidence["negative_control_complete"] = negative_control is not None
            if negative_control is None:
                evidence["promotion_guard"] = {
                    "status": "blocked",
                    "reason": "foreign_denied_negative_control_missing",
                }
                gaps_out.append(
                    {
                        "resource_url": url,
                        "object_id": object_id,
                        "owner_identity": owner_identity,
                        "status": "needs_review",
                        "confidence_level": "Needs Human Review",
                        "reason": "No denied foreign-identity negative control was observed.",
                        "identities_tested": [row["identity"] for row in rows],
                    }
                )
                continue
            owner_row = next(
                row for row in rows if row.get("identity") == owner_identity
            )
            finding = _create_idor_finding(
                url,
                int(foreign["status_code"]),
                int(foreign["content_length"]),
                f"with non-owner identity {foreign['identity']}",
                evidence=evidence,
                confidence_level="Needs Human Review",
                description_suffix=(
                    f"Identity {owner_identity} was recorded as the owner, while "
                    f"identity {foreign['identity']} reproduced successful access."
                ),
                owner_role=next(
                    (
                        str(row.get("role"))
                        for row in rows
                        if row.get("identity") == owner_identity
                    ),
                    None,
                ),
                foreign_role=str(foreign.get("role") or "unknown"),
            )
            target_url = getattr(target, "url", None)
            if isinstance(target, dict):
                target_url = target.get("url") or target_url
            parsed_target = urlparse(str(target_url or url))
            strict_target_backed = bool(
                state.get("require_target_backed_proof", True)
            )
            verification = verify_replay_evidence(
                finding,
                baseline=owner_row,
                candidate=foreign,
                negative_control=negative_control,
                causal_signal=True,
                negative_control_complete=True,
                validator_id="access_control.idor",
                validator_version="v96.1",
                causal_basis=(
                    "owner access and reproducible foreign access differed while "
                    "a denied foreign-identity control was observed"
                ),
                engagement_id=str(state.get("engagement_id") or ""),
                hypothesis_id=finding.hypothesis_id,
                scope_context={
                    "target_origin": f"{parsed_target.scheme}://{parsed_target.netloc}",
                    "declared_scope": list(scope_origins),
                    "scope_bound": bool(scope_origins),
                },
                identity_context={
                    "owner_identity": owner_identity,
                    "candidate_identity": str(foreign.get("identity") or ""),
                    "tested_identities": [str(row.get("identity") or "") for row in rows],
                },
                replay_metadata={
                    "method": str(
                        record.get("method") or record.get("http_method") or "GET"
                    ).upper(),
                    "owner_status_code": int(owner_row.get("status_code") or 0),
                    "candidate_status_code": int(foreign.get("status_code") or 0),
                    "negative_control_status_code": int(negative_control.get("status_code") or 0),
                },
                require_target_backed=strict_target_backed,
                **package_continuity_kwargs(state),
            )
            finding = finding.model_copy(
                update={
                    "confidence_level": (
                        "Tool-Confirmed" if verification.passed else "Needs Human Review"
                    ),
                    "evidence_bundle": (
                        verification.proof_bundle.model_dump(mode="json")
                        if verification.proof_bundle is not None
                        else None
                    ),
                    "evidence": {
                        **(finding.evidence or {}),
                        **verification.evidence,
                    },
                    "reasoning": (
                        finding.reasoning
                        if verification.passed
                        else f"IDOR replay verifier blocked promotion: {verification.reason}"
                    ),
                }
            )
            new_findings.append(finding)
            if (
                finding.confidence_level == "Tool-Confirmed"
                and verification.proof_bundle is not None
            ):
                confirmed_count += 1
                proof_bundles_out.append(
                    verification.proof_bundle.model_dump(mode="json")
                )
                audit_logger.warning("Tool-confirmed BAC differential for %s", url)
        elif assessment["status"] in {"coverage_gap", "needs_review", "inconclusive"}:
            gaps_out.append(
                {
                    "resource_url": url,
                    "object_id": object_id,
                    "owner_identity": owner_identity,
                    "status": assessment["status"],
                    "confidence_level": assessment["confidence_level"],
                    "reason": assessment["reason"],
                    "identities_tested": [row["identity"] for row in rows],
                }
            )

    matrix_update: dict[str, Any] = {}
    try:
        from webpent.config.settings import get_settings

        configured_enabled = bool(get_settings().enable_authorization_matrix)
        enabled = (
            bool(state.get("enable_authorization_matrix"))
            if "enable_authorization_matrix" in state
            else configured_enabled
        )
        if enabled:
            settings = get_settings()
            target_url = getattr(target, "url", None)
            if isinstance(target, dict):
                target_url = target.get("url") or target_url
            matrix_update = build_authorization_matrix(
                matrix_inputs,
                target_url=target_url,
                max_rows=int(
                    state.get("max_authorization_matrix_rows")
                    or settings.max_authorization_matrix_rows
                ),
                max_comparisons=int(
                    state.get("max_authorization_matrix_comparisons")
                    or settings.max_authorization_matrix_comparisons
                ),
            )
    except Exception as exc:
        logger.debug("Authorization Matrix projection failed: %s", exc)
        matrix_update = {
            "version": "1",
            "rows": [],
            "comparisons": [],
            "coverage_gaps": ["matrix_projection_failed"],
        }

    # Matrix-driven promotion is intentionally downstream of the existing
    # BAC assessment. It only consumes redacted rows with real fingerprints,
    # explicit ownership, and a differential comparison; the reporter never
    # creates findings from this projection.
    matrix_findings: list[Finding] = []
    if matrix_update.get("comparisons"):
        matrix_rows = list(matrix_update.get("rows") or [])
        row_index = {
            (
                str(row.get("identity_ref") or ""),
                str(row.get("object_ref") or ""),
                str(row.get("endpoint") or ""),
                str(row.get("method") or "GET").upper(),
            ): row
            for row in matrix_rows
            if isinstance(row, dict)
        }
        input_index = {
            (
                str(row.get("identity") or ""),
                str(row.get("object_id") or ""),
                str(row.get("endpoint") or row.get("resource_url") or ""),
                str(row.get("method") or "GET").upper(),
            ): row
            for row in matrix_inputs
        }
        existing_keys = {
            (
                str((getattr(finding, "evidence", None) or {}).get("object_id") or ""),
                str(getattr(finding, "url", "") or ""),
                str((getattr(finding, "evidence", None) or {}).get("method") or "GET").upper(),
            )
            for finding in findings + new_findings
        }
        for comparison in matrix_update.get("comparisons") or []:
            if not isinstance(comparison, dict):
                continue
            if not comparison.get("access_differential"):
                continue
            kind = str(comparison.get("comparison_kind") or "")
            if kind not in {"vertical", "ownership_differential"}:
                continue
            base_key = (
                str(comparison.get("object_ref") or ""),
                str(comparison.get("endpoint") or ""),
                str(comparison.get("method") or "GET").upper(),
            )
            left_key = (
                str(comparison.get("left_identity_ref") or ""),
                *base_key,
            )
            right_key = (
                str(comparison.get("right_identity_ref") or ""),
                *base_key,
            )
            left_row = row_index.get(left_key) or {}
            right_row = row_index.get(right_key) or {}
            left_input = input_index.get(left_key) or {}
            right_input = input_index.get(right_key) or {}
            left_fp = str(left_row.get("response_fingerprint") or "")
            right_fp = str(right_row.get("response_fingerprint") or "")
            if not left_fp or not right_fp or "unfingerprinted" in {left_fp, right_fp}:
                continue
            owner_identity = str(
                left_input.get("owner_identity") or right_input.get("owner_identity") or ""
            ).strip()
            if not owner_identity:
                continue
            owner_row = left_input if left_input.get("identity") == owner_identity else right_input
            foreign_row = right_input if owner_row is left_input else left_input
            owner_role = str(owner_row.get("role") or "unknown")
            foreign_role = str(foreign_row.get("role") or "unknown")
            if kind == "vertical" and {
                owner_role.lower(), foreign_role.lower()
            } <= {"", "unknown"}:
                continue
            if base_key in existing_keys:
                continue
            evidence = {
                "type": "authorization_matrix_comparison",
                "object_id": base_key[0],
                "method": base_key[2],
                "owner_identity": owner_identity,
                "comparison_kind": kind,
                "left_response_fingerprint": left_fp,
                "right_response_fingerprint": right_fp,
                "evidence_refs": list(comparison.get("evidence_refs") or [])[:16],
                "redaction": "cookies, authorization headers, and raw bodies omitted",
            }
            matrix_finding = _create_idor_finding(
                base_key[1],
                int(left_row.get("status_code") or right_row.get("status_code") or 0),
                0,
                f"matrix comparison {kind} between "
                f"{comparison.get('left_identity_ref')} and "
                f"{comparison.get('right_identity_ref')}",
                evidence=evidence,
                confidence_level="Needs Human Review",
                description_suffix=(
                    "Authorization matrix recorded reproducible response fingerprints "
                    "for a real access differential."
                ),
                owner_role=owner_role,
                foreign_role=foreign_role,
            )
            matrix_findings.append(
                matrix_finding.model_copy(
                    update={
                        "evidence": {
                            **(matrix_finding.evidence or {}),
                            "promotion_guard": {
                                "status": "blocked",
                                "reason": "matrix_requires_strict_replay_verifier",
                            },
                        }
                    }
                )
            )
            existing_keys.add(base_key)

    new_findings.extend(matrix_findings)
    confirmed_count += sum(
        1 for finding in matrix_findings if finding.confidence_level == "Tool-Confirmed"
    )

    mental_model_update: dict[str, Any] = {"nodes": {}, "edges": []}
    try:
        from webpent.models.mental_model import extract_mental_model_updates

        mental_model_update = extract_mental_model_updates(
            discovery_source="access_control_node",
            endpoints=[str(record["url"]) for record in records[:max_candidates]],
            target_url=getattr(target, "url", None),
        )
    except Exception as exc:
        logger.debug("Mental Model extraction (access_control) failed: %s", exc)

    # Do not return runtime cookie material.  The identity profile state is
    # supplied by the auth layer and is intentionally left untouched.
    _bac_result: dict[str, Any] = {
        "findings": findings + new_findings,
        "bac_observations": observations_out,
        "bac_coverage_gaps": gaps_out,
        "relational_evidence": relational_out,
        "proof_bundles": proof_bundles_out,
        "authorization_matrix": matrix_update,
        "mental_model": mental_model_update,
        "messages": [
            AIMessage(
                content=(
                    f"Access Control Mapper: probed {len(records[:max_candidates])} resources "
                    f"across {len(probe_profiles)} identities; "
                    f"confirmed {confirmed_count}, coverage gaps {len(gaps_out)}."
                )
            )
        ],
        "current_phase": "access_control_mapping",
    }
    for _gate_key in ("session_liveness", "session_cookies", "engagement_limitations"):
        if _liveness_gate and _gate_key in _liveness_gate:
            _bac_result[_gate_key] = _liveness_gate[_gate_key]
    return _bac_result


__all__ = [
    "_create_idor_finding",
    "_extract_idor_candidates",
    "_probe_url",
    "access_control_node",
]
