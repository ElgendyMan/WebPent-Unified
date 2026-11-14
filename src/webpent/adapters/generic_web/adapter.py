"""Target-neutral, bounded web-surface adapter.

This adapter is a read-only discovery implementation. It does not contain
product routes, challenge IDs, exploit payloads, or target-specific oracles.
Production use must be attached to an explicitly authorized registration; unit
tests should inject ``httpx.MockTransport`` and never use the network.
"""

from __future__ import annotations

import json
import re
import time
from collections import deque
from collections.abc import Mapping
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from webpent.shared.engagement_scope import normalize_scope_host
from webpent.shared.generic_web_contracts import (
    LIFECYCLE_CONTRACT_VERSION,
    CapabilityRecord,
    CaseDefinition,
    DiscoveryLimits,
    LifecycleAuthorization,
    LifecycleRunContext,
    LifecycleStageResult,
    SurfaceObservation,
)
from webpent.shared.http import (
    build_cookie_header,
    make_safe_httpx_client,
    sanitize_request_headers,
)
from webpent.shared.semantic_observations import SemanticProfileRegistry
from webpent.shared.target_adapters import (
    RegisteredTargetAdapter,
    TargetCaseBinding,
    TargetManifest,
)
from webpent.shared.workflow_contracts import (
    AUTHORIZED_API_READ,
    READ_ONLY_NAVIGATION,
    SAME_ORIGIN_RESOURCE_OBSERVATION,
)
from webpent.shared.workflow_contracts import (
    BROWSER_DOM_OBSERVATION as BROWSER_DOM_WORKFLOW,
)

GENERIC_WEB_TARGET_ID = "generic_web"
GENERIC_WEB_CASE_ID = "generic.web.surface_observation.v1"
GENERIC_WEB_PROFILE_ID = "generic.web.surface_observation.v1"
_GENERIC_API_DOCUMENT_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs/openapi.json",
    "/api-docs/swagger.json",
)

_SAFE_ROUTE_RE = re.compile(r"(?:^|[\"'`\s(=])((?:/|https?://)[^\"'`<>\s]{1,300})")


class _BoundedSurfaceParser(HTMLParser):
    """Extract only bounded structural metadata from one HTML document."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[str] = []
        self.title_present = False
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.lower()
        attributes = {str(key).lower(): value or "" for key, value in attrs}
        if lowered in {"a", "link"} and attributes.get("href"):
            self.links.append(attributes["href"])
        elif lowered == "script" and attributes.get("src"):
            self.scripts.append(attributes["src"])
        elif lowered == "form":
            self.forms.append(attributes.get("action", ""))
        elif lowered == "title":
            self._in_title = True
            self.title_present = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False


class GenericWebAdapter:
    """Bounded read-only adapter for an explicitly declared web origin."""

    target_id = GENERIC_WEB_TARGET_ID
    lifecycle_contract_version = LIFECYCLE_CONTRACT_VERSION
    semantic_profiles = SemanticProfileRegistry(
        {
            GENERIC_WEB_PROFILE_ID: {
                "target_family": GENERIC_WEB_TARGET_ID,
                "promotable": False,
                "rule": "surface_observation_only",
                "reason": "generic_discovery_never_confirms_a_vulnerability",
            }
        }
    )

    def __init__(
        self,
        target_origin: str,
        *,
        target_id: str = GENERIC_WEB_TARGET_ID,
        transport: httpx.BaseTransport | None = None,
        session_cookies: Mapping[str, str] | None = None,
        extra_headers: Mapping[str, str] | None = None,
        limits: DiscoveryLimits | None = None,
    ) -> None:
        normalized = _normalize_origin(target_origin)
        if not normalized:
            raise ValueError("generic_web_target_origin_invalid")
        normalized_target_id = _normalize_target_id(target_id)
        if not normalized_target_id:
            raise ValueError("generic_web_target_id_invalid")
        self.target_id = normalized_target_id
        self.target_origin = normalized
        self._transport = transport
        self._session_cookies = {
            str(key): str(value) for key, value in (session_cookies or {}).items()
        }
        self._extra_headers = sanitize_request_headers(dict(extra_headers or {}))
        self.limits = limits or DiscoveryLimits()
        self._last_observations: tuple[SurfaceObservation, ...] = ()
        self._last_classification = "unknown"

    def describe_target(self) -> dict[str, str]:
        return {
            "target_id": self.target_id,
            "target_origin": self.target_origin,
            "target_classification": self._last_classification,
            "workflow_mode": "read_only_same_origin_discovery",
            "raw_response_bodies_saved": "False",
            "credentials_or_cookies_saved": "False",
        }

    def capabilities(self) -> tuple[CapabilityRecord, ...]:
        return (
            CapabilityRecord("read_only_navigation", "available", "bounded_GET_declared"),
            CapabilityRecord(
                "same_origin_resource_observation",
                "available",
                "bounded_same_origin_GET_declared",
            ),
            CapabilityRecord(
                "authorized_api_read",
                "needs_profile",
                "explicit_authorized_API_profile_required",
            ),
            CapabilityRecord(
                "browser_dom_observation",
                "observation_only",
                "HTTP_transport_does_not_replace_browser_DOM",
            ),
            CapabilityRecord(
                "state_changing_execution",
                "unsupported",
                "generic_adapter_is_read_only",
            ),
        )

    def prepare(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        if case.case_id != GENERIC_WEB_CASE_ID:
            return LifecycleStageResult(
                "prepare", "unsupported", "case_not_owned_by_generic_adapter"
            )
        if case.mutates_state:
            return LifecycleStageResult("prepare", "unsupported", "state_changing_case_not_allowed")
        if run_context.target_id != self.target_id or run_context.case_id != case.case_id:
            return LifecycleStageResult("prepare", "blocked", "lifecycle_context_identity_mismatch")
        if not authorization.authorized:
            return LifecycleStageResult("prepare", "blocked", "explicit_authorization_required")
        if not self.accepts_origin(authorization.allowed_origin):
            return LifecycleStageResult("prepare", "blocked", "authorized_origin_outside_target")
        return LifecycleStageResult(
            "prepare",
            "ready",
            "read_only_same_origin_preconditions_ready",
            metadata={"target_backed": "True"},
        )

    def baseline(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del authorization
        if case.workflow_id != SAME_ORIGIN_RESOURCE_OBSERVATION:
            return LifecycleStageResult(
                "baseline", "unsupported", "workflow_not_supported_by_discovery"
            )
        result = self.discover()
        raw_observations = result.get("observations", ())
        observations = tuple(
            item for item in self._last_observations if isinstance(item, SurfaceObservation)
        )
        if not observations and isinstance(raw_observations, list):
            observations = tuple(
                item for item in raw_observations if isinstance(item, SurfaceObservation)
            )
        if not observations:
            return LifecycleStageResult(
                "baseline", "inconclusive", "baseline_observation_missing_or_unusable"
            )
        refs = tuple(
            f"baseline:{run_context.run_id}:surface:{index}"
            for index, _ in enumerate(observations)
        )
        return LifecycleStageResult(
            "baseline",
            "completed",
            "bounded_same_origin_baseline_observed",
            observation_refs=refs,
            metadata={"target_classification": str(result.get("target_classification", "unknown"))},
        )

    def execute_safe_action(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del authorization, run_context
        if case.mutates_state:
            return LifecycleStageResult(
                "execute_safe_action",
                "unsupported",
                "state_changing_execution_unsupported",
            )
        return LifecycleStageResult(
            "execute_safe_action",
            "observation_only",
            "generic_adapter_has_no_case_mutation_or_exploit_action",
        )

    def observe(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del authorization
        if not self._last_observations:
            return LifecycleStageResult(
                "observe", "inconclusive", "post_action_observation_unavailable"
            )
        return LifecycleStageResult(
            "observe",
            "completed",
            "bounded_same_origin_observation_reused_without_mutation",
            observation_refs=(f"observation:{run_context.run_id}:surface",),
            metadata={"target_classification": self._last_classification},
        )

    def execute_negative_control(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del case, authorization, run_context
        return LifecycleStageResult(
            "execute_negative_control",
            "needs_profile",
            "generic_surface_observation_has_no_independent_semantic_negative_control",
        )

    def cleanup(
        self,
        case: CaseDefinition,
        authorization: LifecycleAuthorization,
        run_context: LifecycleRunContext,
    ) -> LifecycleStageResult:
        del case, authorization, run_context
        return LifecycleStageResult("cleanup", "completed", "no_target_state_to_cleanup")

    def workflow_ids(self) -> tuple[str, ...]:
        return (
            READ_ONLY_NAVIGATION,
            SAME_ORIGIN_RESOURCE_OBSERVATION,
            AUTHORIZED_API_READ,
            BROWSER_DOM_WORKFLOW,
        )

    def workflow_executors(self) -> dict[str, object]:
        # Generic HTTP discovery does not impersonate a browser or submit API
        # calls. Browser/API execution needs an explicit reviewed profile.
        return {}

    def case_ids(self) -> tuple[str, ...]:
        return (GENERIC_WEB_CASE_ID,)

    def case(self, case_id: str) -> TargetCaseBinding | None:
        if str(case_id or "").strip() != GENERIC_WEB_CASE_ID:
            return None
        return TargetCaseBinding(
            case_id=GENERIC_WEB_CASE_ID,
            operation="navigate",
            path="/",
            oracle_id="generic.web.surface_observation",
            workflow_id=SAME_ORIGIN_RESOURCE_OBSERVATION,
            semantic_profile=GENERIC_WEB_PROFILE_ID,
            scoring_status="observation_only_not_benchmark_scored",
        )

    def semantic_profile_for_case(self, case_id: str) -> str | None:
        if str(case_id or "").strip() == GENERIC_WEB_CASE_ID:
            return GENERIC_WEB_PROFILE_ID
        return None

    def accepts_origin(self, origin: str) -> bool:
        return _normalize_origin(origin) == self.target_origin

    def case_definition(self) -> CaseDefinition:
        return CaseDefinition(
            case_id=GENERIC_WEB_CASE_ID,
            workflow_id=SAME_ORIGIN_RESOURCE_OBSERVATION,
            required_capabilities=("same_origin_resource_observation",),
            mutates_state=False,
            requires_auth=False,
            requires_negative_control=True,
            profile_id=GENERIC_WEB_PROFILE_ID,
        )

    def capability_map(
        self, observations: tuple[SurfaceObservation, ...]
    ) -> tuple[CapabilityRecord, ...]:
        has_observation = bool(observations)
        has_api_description = any(item.api_route_count > 0 for item in observations)
        return (
            CapabilityRecord(
                "read_only_navigation",
                "available" if has_observation else "inconclusive",
                "same_origin_GET_observation_completed"
                if has_observation
                else "no_observation_completed",
            ),
            CapabilityRecord(
                "same_origin_resource_observation",
                "available" if has_observation else "inconclusive",
                "bounded_same_origin_surface_observed"
                if has_observation
                else "surface_observation_unavailable",
            ),
            CapabilityRecord(
                "authorized_api_read",
                "needs_profile" if has_api_description else "unsupported",
                "api_description_observed_but_authorized_api_profile_required"
                if has_api_description
                else "generic_adapter_does_not_invent_api_routes",
            ),
            CapabilityRecord(
                "browser_dom_observation",
                "observation_only",
                "HTTP_parser_cannot_replace_reviewed_browser_DOM_transport",
            ),
            CapabilityRecord(
                "state_changing_execution",
                "unsupported",
                "generic_adapter_is_read_only_and_never_submits_forms",
            ),
        )

    def discover(self, start_url: str | None = None) -> dict[str, Any]:
        """Perform bounded GET-only discovery and return categorical observations."""
        start = _same_origin_url(start_url or self.target_origin, self.target_origin)
        if not start:
            return self._failure_result("invalid_target_url")

        queue: deque[tuple[str, int]] = deque([(start, 0)])
        queued = {start}
        origin = self.target_origin
        for path in _GENERIC_API_DOCUMENT_PATHS:
            candidate = f"{origin}{path}"
            if candidate not in queued:
                queue.append((candidate, 1))
                queued.add(candidate)
        seen: set[str] = set()
        observations: list[SurfaceObservation] = []
        gaps: list[str] = []
        redirects_blocked = 0
        errors = 0
        last_request_at = 0.0

        headers = {
            "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
            "Accept-Encoding": "identity",
        }
        cookie_header = build_cookie_header(self._session_cookies)
        if cookie_header:
            headers["Cookie"] = cookie_header
        headers.update(self._extra_headers)

        client_kwargs: dict[str, Any] = {
            "timeout": self.limits.timeout_seconds,
            "follow_redirects": False,
            "verify": True,
            "headers": headers,
        }
        if self._transport is not None:
            client_kwargs["transport"] = self._transport
        try:
            client_context = make_safe_httpx_client(**client_kwargs)
        except Exception:
            return self._failure_result("http_client_unavailable")

        with client_context as client:
            while queue and len(seen) < self.limits.max_pages:
                current, depth = queue.popleft()
                if current in seen:
                    continue
                seen.add(current)
                if not _safe_get_route(current, self.target_origin):
                    gaps.append("state_changing_get_filtered")
                    continue
                wait_for = (1.0 / self.limits.rate_limit_per_second) - (
                    time.monotonic() - last_request_at
                )
                if wait_for > 0:
                    time.sleep(min(wait_for, 1.0))
                try:
                    response = client.get(current)
                    last_request_at = time.monotonic()
                except Exception:
                    errors += 1
                    continue

                location = str(response.headers.get("location", "")).strip()
                if 300 <= response.status_code < 400 and location:
                    redirect = _same_origin_url(location, current)
                    if redirect and _safe_get_route(redirect, self.target_origin):
                        if redirect not in queued and depth < self.limits.max_depth:
                            queue.append((redirect, depth + 1))
                            queued.add(redirect)
                    else:
                        redirects_blocked += 1
                        gaps.append("cross_origin_redirect_filtered")
                    continue
                if response.status_code in {404, 410}:
                    continue

                text = _bounded_response_text(response, self.limits.max_body_bytes)
                record, discovered = _observe_response(current, response, text)
                observations.append(record)
                if depth >= self.limits.max_depth:
                    continue
                for candidate in discovered[: self.limits.max_links_per_page]:
                    normalized = _same_origin_url(candidate, current)
                    if not normalized or not _safe_get_route(normalized, self.target_origin):
                        if normalized:
                            gaps.append("state_changing_get_filtered")
                        else:
                            gaps.append("cross_origin_resource_filtered")
                        continue
                    if normalized not in queued:
                        queued.add(normalized)
                        queue.append((normalized, depth + 1))

        if not observations:
            gaps.append("no_observed_surface")
        if errors:
            gaps.append("request_or_parse_errors")
        gaps = list(dict.fromkeys(gaps))
        observation_tuple = tuple(observations)
        classification = _classify_surface(observation_tuple)
        self._last_observations = observation_tuple
        self._last_classification = classification
        return {
            "contract_version": "generic-web-discovery.v1",
            "target_id": self.target_id,
            "target_origin": self.target_origin,
            "target_classification": classification,
            "capabilities": [item.as_dict() for item in self.capability_map(observation_tuple)],
            "case_definition": self.case_definition().as_dict(),
            "observations": [item.as_dict() for item in observation_tuple],
            "pages_fetched": len(seen),
            "redirects_blocked": redirects_blocked,
            "errors": errors,
            "coverage_gaps": gaps,
            "limits": self.limits.as_dict(),
            "workflow_mode": "read_only_same_origin_discovery",
            "raw_response_bodies_saved": False,
            "credentials_or_cookies_saved": False,
        }

    def _failure_result(self, reason: str) -> dict[str, Any]:
        self._last_observations = ()
        self._last_classification = "unknown"
        capabilities = self.capability_map(())
        return {
            "contract_version": "generic-web-discovery.v1",
            "target_id": self.target_id,
            "target_origin": self.target_origin,
            "target_classification": "unknown",
            "capabilities": [item.as_dict() for item in capabilities],
            "case_definition": self.case_definition().as_dict(),
            "observations": [],
            "pages_fetched": 0,
            "redirects_blocked": 0,
            "errors": 1,
            "coverage_gaps": [reason],
            "limits": self.limits.as_dict(),
            "workflow_mode": "read_only_same_origin_discovery",
            "raw_response_bodies_saved": False,
            "credentials_or_cookies_saved": False,
        }


def build_generic_web_registration(
    adapter: GenericWebAdapter,
    *,
    authorization_requirements: tuple[str, ...] = ("operator_declared_authorization",),
) -> RegisteredTargetAdapter:
    """Build an explicit registration for one declared generic web origin."""
    if not isinstance(adapter, GenericWebAdapter):
        raise ValueError("generic_web_registration_adapter_required")
    return RegisteredTargetAdapter(
        adapter=adapter,
        source="webpent.adapters.generic_web.adapter",
        version="1",
        policy_ref="generic-web-read-only-same-origin-v1",
        proof_contract="central-causal-negative-sealed-replay-v1",
        manifest=TargetManifest(
            target_id=adapter.target_id,
            adapter_version="1",
            supported_capabilities=frozenset(
                {
                    "read_only_navigation",
                    "same_origin_resource_observation",
                    "browser_dom_observation",
                    "authorized_api_read",
                    "semantic_observation",
                }
            ),
            supported_case_types=frozenset({"navigate"}),
            authorization_requirements=authorization_requirements,
            allowed_scope=(adapter.target_origin,),
            redaction_policy="metadata_only_no_raw_bodies_or_credentials",
            cleanup_policy="no_state_change_forms_not_submitted_client_disposed",
        ),
        metadata={"target_family": GENERIC_WEB_TARGET_ID, "read_only": True},
    )


def _normalize_target_id(value: str) -> str:
    candidate = str(value or "").strip().lower()
    if not candidate or len(candidate) > 80 or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", candidate):
        return ""
    return candidate


def _normalize_origin(value: str) -> str:
    parsed = urlsplit(str(value or "").strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    if parsed.username or parsed.password:
        return ""
    try:
        host = normalize_scope_host(parsed.hostname)
    except Exception:
        host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        return ""
    port = parsed.port
    default = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
        parsed.scheme.lower() == "https" and port in {None, 443}
    )
    return f"{parsed.scheme.lower()}://{host}" + ("" if default else f":{port}")


def _same_origin_url(value: str, base: str) -> str | None:
    raw = str(value or "").strip()
    if not raw or raw.lower().startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
        return None
    absolute = urljoin(base, raw)
    if _normalize_origin(absolute) != _normalize_origin(base):
        return None
    parsed = urlsplit(absolute)
    if parsed.username or parsed.password:
        return None
    # Query values are not retained in observations or queue state. Keeping
    # parameter names is useful for route coverage without storing secrets.
    query_keys = []
    for item in parsed.query.split("&")[:20]:
        key = item.split("=", 1)[0].strip()
        if key:
            query_keys.append(key[:80])
    query = "&".join(f"{key}=" for key in query_keys)
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path or "/", query, ""))


def _safe_get_route(url: str, start: str) -> bool:
    parts = urlsplit(url)
    route = f"{parts.path or '/'}?{parts.query}" if parts.query else (parts.path or "/")
    lowered = route.lower()
    return not re.search(
        r"(?:^|[\\/_.?=&-])(logout|log-out|sign-out|delete|destroy|remove|reset|purge|wipe|shutdown|deactivate|unsubscribe|cancel|terminate|drop)(?:[\\/_.?=&-]|$)",
        lowered,
    )


def _bounded_response_text(response: httpx.Response, max_bytes: int) -> str:
    content = bytes(response.content[:max_bytes])
    encoding = response.encoding or "utf-8"
    try:
        return content.decode(encoding, errors="replace")
    except (LookupError, UnicodeError):
        return content.decode("utf-8", errors="replace")


def _observe_response(
    url: str, response: httpx.Response, text: str
) -> tuple[SurfaceObservation, list[str]]:
    content_type = str(response.headers.get("content-type", "")).lower()[:160]
    discovered: list[str] = []
    api_route_count = 0
    if "json" in content_type or "yaml" in content_type or "openapi" in url.lower():
        try:
            payload = json.loads(text)
        except (TypeError, ValueError):
            payload = {}
        if isinstance(payload, dict) and isinstance(payload.get("paths"), dict):
            api_route_count = min(len(payload["paths"]), 500)
            discovered.extend(str(item) for item in list(payload["paths"])[:100])
        classification = "api" if api_route_count or "json" in content_type else "unknown"
        record = SurfaceObservation(
            url=_safe_observation_url(url),
            classification=classification,
            status_code=response.status_code,
            content_type=content_type,
            api_route_count=api_route_count,
            observations=("api_description_observed",) if api_route_count else (),
        )
        return record, discovered

    parser = _BoundedSurfaceParser()
    try:
        parser.feed(text)
    except Exception:
        parser = _BoundedSurfaceParser()
    discovered.extend(parser.links[:100])
    discovered.extend(parser.scripts[:100])
    discovered.extend(match.group(1) for match in _SAFE_ROUTE_RE.finditer(text[:500_000]))
    route_candidates = []
    for item in discovered:
        if item not in route_candidates:
            route_candidates.append(item)
    script_count = len(parser.scripts)
    link_count = len(parser.links)
    form_count = len(parser.forms)
    script_routes = sum(
        1 for item in route_candidates if "/api/" in item.lower() or "graphql" in item.lower()
    )
    if script_count and not link_count and not form_count:
        classification = "spa"
    elif script_routes:
        classification = "hybrid"
    elif text.lstrip().startswith(("<", "<!doctype")):
        classification = "html"
    else:
        classification = "unknown"
    observations = []
    if parser.forms:
        observations.append("forms_described_not_submitted")
    if script_count:
        observations.append("scripts_present_static_only")
    record = SurfaceObservation(
        url=_safe_observation_url(url),
        classification=classification,
        status_code=response.status_code,
        content_type=content_type,
        title_present=parser.title_present,
        link_count=min(link_count, 500),
        form_count=min(form_count, 100),
        script_count=min(script_count, 500),
        api_route_count=min(script_routes, 500),
        observations=tuple(observations),
    )
    return record, route_candidates


def _safe_observation_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _classify_surface(observations: tuple[SurfaceObservation, ...]) -> str:
    if not observations:
        return "unknown"
    classes = {item.classification for item in observations}
    if "hybrid" in classes or {"html", "api"}.issubset(classes):
        return "hybrid"
    if "api" in classes:
        return "api"
    if "spa" in classes:
        return "spa"
    if "html" in classes:
        return "html"
    return "unknown"


__all__ = [
    "GENERIC_WEB_CASE_ID",
    "GENERIC_WEB_PROFILE_ID",
    "GENERIC_WEB_TARGET_ID",
    "GenericWebAdapter",
    "build_generic_web_registration",
]
