"""Typed, observation-first Playwright transport for the control plane.

The handler performs only explicitly requested, engagement-bound browser
observations. It never signs a proof, promotes a finding, stores cookies, or
performs signup/login/account actions. Proof generation remains in the strict
verifier after independent replay.
"""
from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable, Collection, Mapping
from pathlib import Path
from threading import RLock
from typing import Any
from urllib.parse import urlsplit

from webpent.shared.capability_manifest import resolve_browser_executable
from webpent.shared.control_plane import BrowserActionRequest
from webpent.shared.http import (
    build_host_resolver_rules_args,
    install_playwright_ssrf_guard,
)
from webpent.shared.semantic_observations import (
    SemanticProfileRegistry,
    derive_semantic_observation,
)

logger = logging.getLogger(__name__)

_ALLOWED_OPERATIONS = frozenset(
    {
        "navigate",
        "dom_capture",
        "screenshot",
        "observe_network",
        "validate_input",
        "typed_search",
    }
)
_DENIED_OPERATIONS = frozenset({"signup", "login", "create_account", "password_reset", "oauth"})


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8", "replace")).hexdigest()


def _origin(url: str) -> str:
    parsed = urlsplit(str(url))
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    host = parsed.hostname.lower().rstrip(".")
    port = parsed.port
    default = (parsed.scheme == "http" and port in {None, 80}) or (
        parsed.scheme == "https" and port in {None, 443}
    )
    return f"{parsed.scheme}://{host}" if default else f"{parsed.scheme}://{host}:{port}"


def _host(url: str) -> str:
    return (urlsplit(str(url)).hostname or "").lower().rstrip(".")


def _safe_text_digest(value: str, *, limit: int = 120_000) -> str:
    return _digest(str(value or "")[:limit])


class EphemeralProbeStore:
    """In-memory one-engagement probe resolver; values never enter evidence."""

    def __init__(self) -> None:
        self._values: dict[str, str] = {}
        self._lock = RLock()

    def put(self, probe_ref: str, value: str) -> None:
        if not str(probe_ref).startswith("probe://") or not isinstance(value, str):
            raise ValueError("ephemeral_probe_registration_invalid")
        with self._lock:
            self._values[str(probe_ref)] = value

    def resolve(self, probe_ref: str) -> str | None:
        with self._lock:
            return self._values.get(str(probe_ref))

    def clear(self, probe_ref: str) -> None:
        with self._lock:
            self._values.pop(str(probe_ref), None)


class PlaywrightBrowserHandler:
    """Real typed browser transport used behind BrowserActionAdapter."""

    handler_id = "webpent.playwright.observation"
    handler_version = "1.0"

    def __init__(
        self,
        *,
        target_origin: str,
        engagement_id: str,
        profile_root: str | Path | None = None,
        headless: bool = True,
        browser_timeout_ms: int = 15_000,
        probe_resolver: Callable[[str], str | None] | None = None,
        semantic_profile_registry: SemanticProfileRegistry | None = None,
        workflow_allowlist: Collection[str] | None = None,
        workflow_executors: Mapping[str, Callable[[Any, str, int], str | None]] | None = None,
    ) -> None:
        self.target_origin = _origin(target_origin)
        self.engagement_id = str(engagement_id or "").strip()
        self.profile_root = Path(profile_root).expanduser() if profile_root else None
        self.headless = bool(headless)
        self.browser_timeout_ms = max(100, min(120_000, int(browser_timeout_ms)))
        self._probe_resolver = probe_resolver
        self.semantic_profile_registry = (
            semantic_profile_registry
            if semantic_profile_registry is not None
            else SemanticProfileRegistry()
        )
        self.workflow_allowlist = frozenset(
            str(item).strip() for item in (workflow_allowlist or ()) if str(item).strip()
        )
        self.workflow_executors = {
            str(workflow_id).strip(): executor
            for workflow_id, executor in (workflow_executors or {}).items()
            if str(workflow_id).strip() and callable(executor)
        }
        if not self.target_origin or not self.engagement_id:
            raise ValueError("playwright_handler_target_and_engagement_required")

    def __call__(self, request: BrowserActionRequest) -> dict[str, Any]:
        return self.execute(request)

    def execute(self, request: BrowserActionRequest) -> dict[str, Any]:
        if request.engagement_id != self.engagement_id:
            return self._blocked("engagement_mismatch")
        if request.operation in _DENIED_OPERATIONS:
            return self._blocked("account_action_denied")
        if request.operation not in _ALLOWED_OPERATIONS:
            return self._blocked("browser_operation_not_implemented")
        if request.operation == "typed_search" and (
            not request.workflow_id or request.workflow_id not in self.workflow_allowlist
        ):
            return self._blocked("typed_search_workflow_not_allowlisted")
        if request.operation == "typed_search" and (
            str(request.workflow_id) not in self.workflow_executors
        ):
            return self._blocked("typed_search_workflow_executor_missing")
        if (
            request.semantic_profile is not None
            and self.semantic_profile_registry.contract(request.semantic_profile) is None
        ):
            return self._blocked("semantic_profile_not_registered")
        requested_origin = _origin(request.url)
        if requested_origin != self.target_origin:
            return self._blocked("target_origin_mismatch")
        host = _host(request.url)
        if not host:
            return self._blocked("target_host_missing")

        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:  # pragma: no cover - environment dependent
            return self._blocked(f"playwright_unavailable:{type(exc).__name__}")

        dialog_events: list[dict[str, Any]] = []
        network_events: list[dict[str, Any]] = []
        response_status: int | None = None
        semantic_response: Any | None = None
        semantic_content_type = ""
        semantic_body: bytes | None = None
        semantic_final_url = ""
        download_detected = False
        final_url = ""
        dom_digest = ""
        screenshot_digest = ""
        context = None
        browser = None
        page = None
        stage = "before_browser"
        try:
            with sync_playwright() as playwright:
                stage = "launch_browser"
                launch_args = build_host_resolver_rules_args(host)
                launch_kwargs: dict[str, Any] = {
                    "headless": self.headless,
                    "args": list(launch_args),
                }
                executable_path = resolve_browser_executable()
                if executable_path:
                    launch_kwargs["executable_path"] = executable_path
                browser = playwright.chromium.launch(**launch_kwargs)
                stage = "create_context"
                # Do not use a persistent context or load storage_state: every
                # observation is isolated and cannot retain real cookies.
                context = browser.new_context()
                install_playwright_ssrf_guard(context, target_hosts=(host,))
                timeout_ms = min(self.browser_timeout_ms, int(request.timeout_ms))
                context.set_default_timeout(timeout_ms)
                page = context.new_page()
                stage = "attach_observers"

                def on_dialog(dialog: Any) -> None:
                    dialog_events.append(
                        {
                            "type": str(getattr(dialog, "type", ""))[:40],
                            "message_digest": _safe_text_digest(
                                str(getattr(dialog, "message", ""))
                            ),
                        }
                    )
                    try:
                        dialog.dismiss()
                    except Exception:
                        logger.debug("playwright dialog dismissal failed", exc_info=True)

                def on_response(response: Any) -> None:
                    nonlocal response_status, semantic_response, semantic_content_type
                    try:
                        response_url = str(response.url)
                        if _origin(response_url) != self.target_origin:
                            return
                        if request.semantic_profile is not None and (
                            urlsplit(response_url).path == urlsplit(request.url).path
                            and urlsplit(response_url).query == urlsplit(request.url).query
                        ):
                            semantic_response = response
                            response_status = int(response.status)
                            semantic_content_type = str(
                                response.headers.get("content-type", "")
                            )
                        network_events.append(
                            {
                                "status": int(response.status),
                                "url_shape_digest": _digest(
                                    _origin(response_url) + urlsplit(response_url).path
                                ),
                                "resource_type": str(response.request.resource_type)[:40],
                            }
                        )
                    except Exception:
                        logger.debug("playwright response observation failed", exc_info=True)

                def on_download(_download: Any) -> None:
                    nonlocal download_detected
                    # The browser context is ephemeral and is disposed below;
                    # do not cancel the download, which can race page shutdown.
                    download_detected = True

                page.on("dialog", on_dialog)
                if (
                    request.operation in {"observe_network", "validate_input", "typed_search"}
                    or request.semantic_profile is not None
                ):
                    page.on("response", on_response)
                if request.semantic_profile is not None:
                    page.on("download", on_download)
                stage = "navigate"
                try:
                    response = page.goto(
                        request.url,
                        wait_until="domcontentloaded",
                        timeout=timeout_ms,
                    )
                except Exception:
                    if not request.semantic_profile:
                        raise
                    try:
                        fetched = page.evaluate(
                            """async (url) => {
                                const response = await fetch(url, {credentials: 'omit'});
                                return {
                                    status: response.status,
                                    contentType: response.headers.get('content-type') || '',
                                    finalUrl: response.url,
                                    body: await response.text(),
                                };
                            }""",
                            request.url,
                        )
                        response_status = int(fetched.get("status", 0))
                        semantic_content_type = str(fetched.get("contentType", ""))
                        semantic_final_url = str(fetched.get("finalUrl", request.url))
                        semantic_body = str(fetched.get("body", "")).encode(
                            "utf-8", "replace"
                        )
                        response = semantic_response
                    except Exception:
                        if not download_detected or semantic_response is None:
                            raise
                        response = semantic_response
                if (
                    response is not None
                    and int(response.status) >= 400
                    and request.semantic_profile is None
                ):
                    return self._blocked(
                        "blocked_http_status",
                        status_code=int(response.status),
                        operation=request.operation,
                    )
                if request.operation in {"validate_input", "typed_search"}:
                    stage = "resolve_probe"
                    probe_value = self._resolve_probe(request)
                    if probe_value is None:
                        return self._blocked("validator_probe_unavailable")
                    password_fields = page.locator("input[type='password']")
                    if password_fields.count() > 0:
                        return self._blocked("account_like_form_denied")
                    if request.operation == "typed_search":
                        executor = self.workflow_executors.get(str(request.workflow_id))
                        if executor is None:
                            return self._blocked("typed_search_workflow_executor_missing")
                        stage = "execute_typed_search"
                        executor_reason = executor(page, probe_value, timeout_ms)
                        if executor_reason:
                            return self._blocked(str(executor_reason)[:120])
                        fields = None
                    else:
                        fields = page.locator(
                            "input[type='text'], input[type='search'], "
                            "input[type='url'], input[type='email'], input:not([type])"
                        )
                    if request.operation != "typed_search":
                        stage = "fill_probe"
                        filled = False
                        filled_field: Any | None = None
                        for index in range(min(fields.count(), 20)):
                            field = fields.nth(index)
                            if field.is_visible():
                                field.fill(probe_value, timeout=timeout_ms)
                                filled = True
                                filled_field = field
                                break
                        if not filled or filled_field is None:
                            return self._blocked("validator_input_field_missing")
                        submit = page.locator(
                            "input[type='submit'], button[type='submit'], button:not([type])"
                        ).first
                        if submit.count() == 0 or not submit.is_visible():
                            # Some same-origin SPAs submit an explicitly typed
                            # search field on Enter and expose no button element.
                            # Keep this fallback narrowly typed to input[type=search].
                            if not self._is_search_field(filled_field):
                                return self._blocked("validator_submit_control_missing")
                            filled_field.press("Enter", timeout=timeout_ms)
                        else:
                            submit.click(timeout=timeout_ms)
                    stage = "settle_after_action"
                    page.wait_for_timeout(min(1000, timeout_ms))
                stage = "build_observation"
                semantic_observation: dict[str, Any] = {}
                if response is not None:
                    response_status = int(response.status)
                observed_url = semantic_final_url or page.url or request.url
                final_url = _origin(observed_url) + urlsplit(observed_url).path
                if request.semantic_profile is not None:
                    transient_body: bytes | None = None
                    transient_content_type = ""
                    try:
                        if semantic_body is not None:
                            transient_body = semantic_body
                            transient_content_type = semantic_content_type
                        elif response is not None:
                            transient_body = response.body()
                            transient_content_type = str(
                                response.headers.get("content-type", "")
                            ) or semantic_content_type
                        semantic_observation = derive_semantic_observation(
                            request.semantic_profile,
                            status_code=response_status,
                            content_type=transient_content_type,
                            body=transient_body,
                            final_path=urlsplit(page.url).path or "/",
                            registry=self.semantic_profile_registry,
                        )
                    finally:
                        # The raw response is never returned, logged, or retained
                        # beyond this transient derivation boundary.
                        del transient_body, transient_content_type
                if request.operation in {
                    "dom_capture",
                    "screenshot",
                    "observe_network",
                    "typed_search",
                }:
                    dom_digest = _safe_text_digest(page.content())
                if request.operation == "screenshot":
                    screenshot_digest = _digest(page.screenshot(type="png"))
                return {
                    "handler_status": "completed",
                    "handler_id": self.handler_id,
                    "handler_version": self.handler_version,
                    "target_backed": True,
                    "observation_role": request.observation_role,
                    "target_fingerprint": (
                        _origin_fingerprint(request.url)
                        if request.semantic_profile is not None
                        else _target_fingerprint(request.url)
                    ),
                    "request_digest": _digest(
                        {
                            "method": "GET",
                            "origin": self.target_origin,
                            "path": urlsplit(request.url).path or "/",
                            "query": urlsplit(request.url).query,
                            "operation": request.operation,
                            "semantic_profile": request.semantic_profile or "",
                            "probe_digest": request.probe_digest or "",
                        }
                    ),
                    "response_digest": _digest(
                        {
                            "status": response_status,
                            "final_url_shape": final_url,
                            "dom_digest": dom_digest,
                            "network_events": network_events,
                        }
                    ),
                    "status_code": response_status,
                    "final_url_shape_digest": _digest(final_url),
                    "dialog_count": len(dialog_events),
                    "dialog_events": dialog_events,
                    "network_event_count": len(network_events),
                    "network_event_shape_digests": [
                        str(event.get("url_shape_digest", ""))
                        for event in network_events
                    ],
                    "dom_digest": dom_digest,
                    "screenshot_digest": screenshot_digest,
                    "replayable": True,
                    **semantic_observation,
                }
        except Exception as exc:
            logger.warning("Playwright observation failed at %s: %s", stage, type(exc).__name__)
            return self._blocked(
                f"browser_execution_failed:{type(exc).__name__}",
                operation=request.operation,
                stage=stage,
            )
        finally:
            for resource in (page, context, browser):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        logger.debug("playwright resource close failed", exc_info=True)

    @staticmethod
    def _is_search_field(field: Any) -> bool:
        """Return true only for an explicitly typed search input."""
        try:
            return str(field.get_attribute("type") or "").lower() == "search"
        except Exception:
            return False

    def _resolve_probe(self, request: BrowserActionRequest) -> str | None:
        if self._probe_resolver is None or not request.probe_ref or not request.probe_digest:
            return None
        try:
            value = self._probe_resolver(request.probe_ref)
        except Exception:
            logger.debug("ephemeral probe resolver failed", exc_info=True)
            return None
        if not isinstance(value, str) or len(value) > 20_000:
            return None
        digest = "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
        return value if digest == request.probe_digest else None

    def _blocked(
        self,
        reason: str,
        *,
        status_code: int | None = None,
        operation: str | None = None,
        stage: str | None = None,
    ) -> dict[str, Any]:
        normalized_reason = str(reason)[:240]
        failure_code = normalized_reason.split(":", 1)[0]
        missing_fields_by_code = {
            "blocked_http_status": ["successful_http_observation"],
            "validator_probe_unavailable": ["validated_probe"],
            "validator_input_field_missing": ["input_field"],
            "typed_search_host_missing": ["typed_search_host"],
            "typed_search_opener_missing": ["typed_search_opener"],
            "typed_search_input_missing": ["typed_search_input"],
            "validator_submit_control_missing": ["submit_control"],
            "account_like_form_denied": ["non_account_form"],
            "browser_execution_failed": ["browser_observation"],
        }
        diagnostic = {
            "failure_code": failure_code,
            "missing_fields": missing_fields_by_code.get(failure_code, []),
            "status_code": status_code,
            "operation": str(operation or "")[:40],
        }
        if stage:
            diagnostic["stage"] = str(stage)[:40]
        return {
            "handler_status": "blocked",
            "target_backed": False,
            "replayable": False,
            "reason": normalized_reason,
            "failure_code": failure_code,
            "missing_fields": diagnostic["missing_fields"],
            "diagnostic": diagnostic,
        }


def _target_fingerprint(url: str) -> str:
    parsed = urlsplit(str(url))
    shape = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    return "sha256:" + hashlib.sha256(shape.encode("utf-8", "replace")).hexdigest()


def _origin_fingerprint(url: str) -> str:
    parsed = urlsplit(str(url))
    shape = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    return "sha256:" + hashlib.sha256(shape.encode("utf-8", "replace")).hexdigest()


__all__ = ["PlaywrightBrowserHandler"]
