# src/webpent/agents/execution_sandbox/agent.py
"""webpent.agents.execution_sandbox.agent

LangGraph node that performs bounded browser telemetry for queued XSS probes.

The legacy direct-Playwright path is compatibility telemetry only: a dialog
observation is never a confirmation, never creates a ProofBundle, and never
promotes a finding. Typed browser proof must use the control-plane replay path;
central promotion additionally requires target-backed causal evidence, an
independently executed negative control, and a sealed replayable ProofBundle.

For compatibility telemetry, the node may:

  1. Launch a headless Chromium browser via Playwright.
  2. Navigate to the finding's URL within the authorized scope.
  3. Submit bounded probes and observe browser behavior.
  4. Record redacted, bounded observations for human review.

Authentication injection and account operations are intentionally disabled in
this sandbox path.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import UUID, uuid4

from langchain_core.messages import AIMessage

from webpent.models.findings import Confidence, Finding, VulnClass
from webpent.shared.poc_policy import derive_execution_risk, evaluate_execution_gate
from webpent.shared.stealth import apply_jitter, enforce_min_interval, extract_host
from webpent.shared.target_package_context import package_continuity_kwargs
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

_TEXT_INPUT_SELECTOR = (
    "input[type='text'], input[type='search'], input[type='url'], "
    "input[type='email'], input:not([type])"
)
_SUBMIT_SELECTOR = "input[type='submit'], button[type='submit'], button:not([type])"
_NAV_TIMEOUT_MS = 15_000
# V3.5 Phase 3: Hard wall-clock limit for each payload test (60 seconds).
# Prevents adversarial pages from hanging the worker indefinitely via
# infinite loops, excessive redirects, or deliberate slowdowns.
_PAYLOAD_TEST_TIMEOUT_S = 60


def _has_payloads(state: PentestState) -> bool:
    payloads = state.get("payloads_to_test") or {}
    return any(len(pl) > 0 for pl in payloads.values())


def _execution_event(
    event: str,
    *,
    reason: str | None = None,
    finding: Finding | None = None,
    payload: str | None = None,
    result: str | None = None,
) -> dict[str, Any]:
    """Build a redaction-safe execution telemetry record.

    Raw URLs, payloads, cookies, response bodies, and browser handles are
    deliberately excluded. The digest lets operators correlate a replay
    attempt with a checkpoint without turning telemetry into an exploit
    artifact or a confirmation channel.
    """
    record: dict[str, Any] = {"event": event}
    if reason:
        record["reason"] = reason
    if finding is not None:
        record["finding_id"] = str(finding.id)
        record["vuln_class"] = str(getattr(finding.vuln_class, "value", finding.vuln_class))
    if payload is not None:
        record["payload_sha256"] = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    if result:
        record["result"] = result
    return record


def _try_launch_browser(target_hostnames: list[str] | None = None):
    """Launch a headless Chromium instance, pinning DNS for known targets.

    V6 Final-Seal-Revised: ``target_hostnames`` (typically the distinct
    hosts across the findings this sandbox run is about to test) are
    resolved and pinned via ``--host-resolver-rules`` BEFORE the browser
    exists, closing the DNS-rebinding TOCTOU race for those hosts
    without touching TLS SNI (see ``shared/http.py``'s
    ``build_host_resolver_rules_args`` docstring for why URL rewriting
    was the wrong mechanism). Hosts discovered only at request time
    (redirects, subresources) remain covered by the block-only route
    handler installed via ``install_playwright_ssrf_guard``.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        logger.error(
            "playwright is not installed. Install it with "
            "'pip install playwright' and run 'playwright install chromium'."
        )
        return None, None
    launch_args: list[str] = []
    if target_hostnames:
        try:
            from webpent.shared.http import build_host_resolver_rules_args
            launch_args = build_host_resolver_rules_args(*target_hostnames)
        except Exception as exc:
            logger.warning(
                "Failed to build --host-resolver-rules for %s (%s) — "
                "launching without DNS pinning; the route-handler block "
                "remains active as a backstop.",
                target_hostnames, exc,
            )
    try:
        pw = sync_playwright().start()
        from webpent.shared.capability_manifest import resolve_browser_executable

        executable_path = resolve_browser_executable()
        # Some Chromium builds (post ~M128) have dropped legacy "Old
        # Headless" mode entirely, but older installed Playwright driver
        # versions still request it by default via an internal
        # "--headless=old" arg. Chromium takes the last occurrence of a
        # repeated switch, so appending "--headless=new" here (after
        # Playwright's own default args) overrides that without requiring
        # the Playwright package version to exactly match whatever
        # Chromium revision happens to be installed locally.
        launch_args = [*launch_args, "--headless=new"]
        launch_kwargs: dict[str, Any] = {"headless": True, "args": launch_args}
        if executable_path:
            launch_kwargs["executable_path"] = executable_path
        try:
            browser = pw.chromium.launch(**launch_kwargs)
        except Exception as exc:
            if "Old Headless mode has been removed" not in str(exc):
                raise
            # Retry once against the standalone headless-shell binary next
            # to the main executable, if present, for Chromium builds that
            # need it explicitly.
            logger.warning(
                "Chromium rejected legacy headless mode; retrying with "
                "chrome-headless-shell if available (%s)", exc,
            )
            shell_path = None
            if executable_path:
                shell_candidate = Path(executable_path).parent.parent / "chrome-headless-shell"
                if shell_candidate.is_file():
                    shell_path = str(shell_candidate)
            if shell_path:
                launch_kwargs["executable_path"] = shell_path
                browser = pw.chromium.launch(**launch_kwargs)
            else:
                raise
        return pw, browser
    except Exception as exc:
        logger.error("Failed to launch Chromium: %s", exc)
        with contextlib.suppress(Exception):
            if "pw" in locals() and pw is not None:
                pw.stop()
        return None, None


def _normalise_auth_state_cookies(
    raw_cookies: Any,
    target_url: str,
) -> list[dict[str, Any]]:
    """Return target-scoped Playwright cookie records from canonical auth state.

    ``auth_state`` may be produced by a validator as a list containing only
    ``name``/``value``.  Playwright requires either a valid ``url`` or a
    ``domain`` plus ``path``; silently passing incomplete records makes the
    browser verification path fail while the rest of the scan continues.
    Records are therefore completed from the declared target origin and
    cross-origin or malformed records are rejected fail-closed.
    """
    if not isinstance(raw_cookies, list):
        return []
    target = urlparse(str(target_url))
    target_host = (target.hostname or "").strip().lower()
    if not target_host or target.scheme not in {"http", "https"}:
        return []

    result: list[dict[str, Any]] = []
    for raw in raw_cookies:
        if not isinstance(raw, dict):
            continue
        name = raw.get("name")
        value = raw.get("value")
        if not isinstance(name, str) or not name.strip():
            continue
        if not isinstance(value, str) or any(char in value for char in ("\r", "\n")):
            continue
        name = name.strip()
        record: dict[str, Any] = {"name": name, "value": value}

        raw_cookie_url = raw.get("url")
        if raw_cookie_url:
            cookie_url = urlparse(str(raw_cookie_url))
            if (
                cookie_url.scheme not in {"http", "https"}
                or (cookie_url.hostname or "").strip().lower() != target_host
            ):
                continue
            record["url"] = str(raw_cookie_url)
        else:
            raw_domain = str(raw.get("domain") or target_host).strip()
            cookie_domain = raw_domain.lstrip(".").lower()
            if cookie_domain != target_host:
                continue
            record["domain"] = raw_domain
            raw_path = raw.get("path")
            record["path"] = (
                raw_path
                if isinstance(raw_path, str) and raw_path.startswith("/")
                else "/"
            )

        for key in ("expires", "httpOnly", "secure", "sameSite"):
            if key in raw:
                record[key] = raw[key]
        result.append(record)
    return result


def _inject_cookies(context: Any, url: str, auth_state: dict[str, Any]) -> None:
    """Compatibility hook that never transports credentials or cookies.

    Browser proof uses the anonymous typed control-plane adapter.  The legacy
    fallback retains this call site only for compatibility and is explicitly
    prevented from consuming authentication state.
    """
    del context, url, auth_state
    logger.warning("Cookie injection blocked by account-action policy")


def _fill_form_and_submit(page, payload: str) -> bool:
    """Fill the first form on the page with ``payload`` and submit.

    V3.5: Now supports ``<input type="file">`` elements. Upon detecting
    a file input, a benign temporary file is generated and uploaded via
    Playwright's ``set_input_files()``. The temp file is deleted in a
    ``finally`` block.
    """
    import os
    import tempfile

    temp_file_path: str | None = None

    try:
        form = page.query_selector("form")
        if form is None:
            logger.debug("No <form> found on page — cannot inject payload")
            return False

        filled = 0

        # --- Handle text inputs ---
        inputs = form.query_selector_all(_TEXT_INPUT_SELECTOR)
        for inp in inputs:
            try:
                inp.fill(payload)
                filled += 1
            except Exception:
                continue

        # --- Handle file inputs (V3.5) ---
        file_inputs = form.query_selector_all("input[type='file']")
        if file_inputs:
            # Generate a benign temporary file with the payload text.
            # This allows testing file-upload endpoints for injection
            # vulnerabilities (e.g., web shell upload, XXE via SVG).
            try:
                fd, temp_file_path = tempfile.mkstemp(
                    suffix=".txt", prefix="webpent_test_"
                )
                with os.fdopen(fd, "w") as f:
                    f.write(payload)
                logger.debug("Created temp file for upload: %s", temp_file_path)
            except Exception as exc:
                logger.warning("Failed to create temp file for upload: %s", exc)
                temp_file_path = None

            if temp_file_path is not None:
                for finp in file_inputs:
                    try:
                        # Use locator's set_input_files for file upload
                        # ``page.locator(selector).set_input_files(path)``
                        # is the recommended Playwright API.
                        finp.set_input_files(temp_file_path)
                        filled += 1
                    except Exception as exc:
                        logger.debug("File input upload failed: %s", exc)
                        continue

        if filled == 0:
            logger.debug("Form found but no fillable inputs — skipping")
            return False

        submit = form.query_selector(_SUBMIT_SELECTOR) or page.query_selector(_SUBMIT_SELECTOR)
        if submit is None:
            logger.debug("No submit button found — trying form.submit()")
            try:
                page.evaluate("(el) => el.submit()", form)
            except Exception:
                logger.debug("form.submit() failed")
                return False
        else:
            try:
                submit.click()
            except Exception as exc:
                logger.debug("Submit click failed: %s", exc)
                return False
        return True
    except Exception as exc:
        logger.warning("Form fill/submit failed: %s", exc)
        return False
    finally:
        # V3.5: Explicitly delete the temporary file to prevent
        # accumulation of payload files on disk.
        if temp_file_path is not None:
            try:
                os.unlink(temp_file_path)
                logger.debug("Deleted temp file: %s", temp_file_path)
            except Exception as exc:
                logger.debug("Failed to delete temp file %s: %s", temp_file_path, exc)


def _test_payload_with_browser(
    browser, url: str, payload: str, auth_state: dict[str, Any],
    stealth_mode: bool = False,
) -> bool:
    """Test a single payload against ``url`` via Playwright with a hard deadline.

    V3.5 Phase 3: Enforces a strict wall-clock limit of
    :data:`_PAYLOAD_TEST_TIMEOUT_S` seconds per payload test. If the
    limit is exceeded, a ``TimeoutError`` is raised and caught, and the
    payload is marked as failed. This prevents adversarial pages from
    hanging the worker indefinitely.

    V5 Sprint 6: When ``stealth_mode`` is True, inserts randomized
    jitter before the initial navigation and before the form-submit
    action, and enforces the configured minimum inter-request interval
    for the target host. Both delays are accounted against the
    wall-clock deadline so stealth never causes the test to exceed its
    time budget silently.

    Returns ``True`` if a JavaScript dialog was triggered (XSS confirmed).
    """
    context = None
    page = None
    dialog_triggered = False
    start_time = time.time()

    # V5 Sprint 6: pre-navigation stealth delay. Skip if doing so would
    # blow the per-payload deadline — stealth must never cause a test
    # to time out without attempting the actual navigation.
    if stealth_mode:
        elapsed = time.time() - start_time
        if elapsed < _PAYLOAD_TEST_TIMEOUT_S - 1.0:
            apply_jitter(stealth_mode, label=f"playwright-navigate:{url}")
            enforce_min_interval(stealth_mode, extract_host(url))

    try:
        context = browser.new_context()
        # V6 Zero-Day Patched P0-1: Install SSRF route guard BEFORE
        # context.new_page() / page.goto(). Without this, Playwright
        # would navigate to internal IPs (169.254.169.254, redis:6379,
        # 127.0.0.1) — turning the browser into an SSRF proxy. The
        # guard aborts blocked-host requests with accessdenied.
        from webpent.shared.http import install_playwright_ssrf_guard
        install_playwright_ssrf_guard(context)
        _inject_cookies(context, url, auth_state)
        page = context.new_page()
        page.set_default_navigation_timeout(_NAV_TIMEOUT_MS)

        def _on_dialog(dialog) -> None:
            nonlocal dialog_triggered
            dialog_triggered = True
            logger.info(
                "Dialog observed (%s) at target shape %s; legacy promotion remains blocked "+
                "(payload_sha256=%s)",
                dialog.type,
                hashlib.sha256(url.encode("utf-8", "replace")).hexdigest()[:16],
                hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest(),
            )
            with contextlib.suppress(Exception):
                dialog.dismiss()

        page.on("dialog", _on_dialog)

        # --- Navigation (with deadline check) ---
        try:
            page.goto(url, wait_until="domcontentloaded")
        except Exception as exc:
            logger.warning("Navigation to %s failed: %s", url, exc)
            return False

        elapsed = time.time() - start_time
        if elapsed > _PAYLOAD_TEST_TIMEOUT_S:
            raise TimeoutError(
                f"Payload test exceeded {_PAYLOAD_TEST_TIMEOUT_S}s deadline "
                f"during navigation (elapsed: {elapsed:.1f}s)"
            )

        # --- Form fill and submit (with deadline check) ---
        # V5 Sprint 6: pre-submit stealth delay. Insert jitter before
        # the form-fill/submit action so the click does not follow the
        # navigation too quickly (a classic bot-detection signal).
        if stealth_mode:
            elapsed = time.time() - start_time
            if elapsed < _PAYLOAD_TEST_TIMEOUT_S - 1.0:
                apply_jitter(stealth_mode, label=f"playwright-submit:{url}")
                enforce_min_interval(stealth_mode, extract_host(url))

        submitted = _fill_form_and_submit(page, payload)
        if not submitted:
            return False

        elapsed = time.time() - start_time
        if elapsed > _PAYLOAD_TEST_TIMEOUT_S:
            raise TimeoutError(
                f"Payload test exceeded {_PAYLOAD_TEST_TIMEOUT_S}s deadline "
                f"during form submission (elapsed: {elapsed:.1f}s)"
            )

        # --- Post-submit wait (capped by remaining deadline) ---
        remaining_ms = max(
            0,
            int((_PAYLOAD_TEST_TIMEOUT_S - (time.time() - start_time)) * 1000),
        )
        wait_ms = min(2000, remaining_ms)
        if wait_ms > 0:
            with contextlib.suppress(Exception):
                page.wait_for_timeout(wait_ms)

        # V4.5 Sprint 3: Stored XSS detection — if no dialog triggered
        # immediately after form submission, revisit the target URL to
        # check if the payload was stored and fires on page load.
        if not dialog_triggered:
            remaining_ms = max(
                0,
                int((_PAYLOAD_TEST_TIMEOUT_S - (time.time() - start_time)) * 1000),
            )
            if remaining_ms > 1000:
                logger.debug(
                    "No immediate dialog — revisiting %s for Stored XSS check",
                    url,
                )
                with contextlib.suppress(Exception):
                    page.goto(url, wait_until="domcontentloaded")
                    revisit_wait = min(2000, remaining_ms)
                    page.wait_for_timeout(revisit_wait)

        return dialog_triggered

    except TimeoutError as exc:
        logger.warning(
            "Payload test for %s hit wall-clock deadline: %s", url, exc
        )
        return False
    except Exception as exc:
        logger.warning("Playwright payload test failed for %s: %s", url, exc)
        return False
    finally:
        if page is not None:
            with contextlib.suppress(Exception):
                page.close()
        if context is not None:
            with contextlib.suppress(Exception):
                context.close()


def _typed_browser_causal_predicate(
    baseline: dict[str, Any],
    candidate: dict[str, Any],
    negative_control: dict[str, Any],
) -> tuple[bool, str]:
    """Use only target response/network observations for the causal oracle."""
    candidate_delta = any(
        baseline.get(field) != candidate.get(field)
        for field in (
            "response_digest",
            "status_code",
            "final_url_shape_digest",
            "network_event_count",
            "dom_digest",
        )
    )
    negative_stable = (
        baseline.get("response_digest") == negative_control.get("response_digest")
        and baseline.get("status_code") == negative_control.get("status_code")
        and baseline.get("network_event_count")
        == negative_control.get("network_event_count")
    )
    return (
        candidate_delta and negative_stable,
        "target_response_or_network_delta_with_stable_negative_control",
    )


def _test_finding_payloads(
    browser,
    finding: Finding,
    payloads: list[str],
    auth_state: dict[str, Any],
    stealth_mode: bool = False,
    thread_id: str | None = None,
    verification_context: dict[str, Any] | None = None,
    proof_runner: Any | None = None,
) -> Finding:
    """Validate payloads without allowing a direct browser promotion bypass.

    When the typed control-plane runner is available, all proof-bound work goes
    through it and only its verifier attestation is returned to the caller. The
    legacy Playwright path remains as bounded telemetry for compatibility, but
    dialog detection alone can never confirm a finding or create a bundle.
    """
    attempted = 0
    context = verification_context or {}
    thread_update = {"thread_id": thread_id} if thread_id else {}
    for payload in payloads:
        attempted += 1
        if proof_runner is not None:
            try:
                from webpent.shared.browser_proof_runner import EphemeralProbe

                # Probe values are held only for this call and are represented
                # downstream by probe:// references and SHA-256 digests.
                result = proof_runner.run(
                    finding,
                    baseline=EphemeralProbe.from_value(
                        "baseline", "webpent-baseline-control"
                    ),
                    candidate=EphemeralProbe.from_value("candidate", payload),
                    negative_control=EphemeralProbe.from_value(
                        "negative_control", "webpent-neutral-control"
                    ),
                    causal_predicate=_typed_browser_causal_predicate,
                    scope_context=dict(context.get("scope_context") or {}),
                    identity_context=dict(context.get("identity_context") or {}),
                    target_url=finding.url,
                    replay_metadata={"browser": "typed_playwright"},
                    target_package=package_continuity_kwargs(
                        context.get("target_package")
                    ),
                    probe_values={
                        "baseline": "webpent-baseline-control",
                        "candidate": payload,
                        "negative_control": "webpent-neutral-control",
                    },
                )
            except Exception as exc:
                logger.warning(
                    "Typed browser proof runner failed closed for finding %s: %s",
                    finding.id,
                    type(exc).__name__,
                )
                result = None
            if result is not None and result.passed and result.attestation:
                attestation = dict(result.attestation)
                # A verifier attestation is an input to the central action
                # executor, not a promotion itself.  In particular, do not
                # mutate confidence here: CampaignExecutor must build, seal,
                # validate, and replay the bundle before Tool-Confirmed is
                # allowed anywhere downstream.
                return finding.model_copy(
                    update={
                        **thread_update,
                        "evidence": {
                            **(finding.evidence or {}),
                            "browser_validation_attempted": True,
                            "browser_validation_result": (
                                "typed_replay_attestation_pending_bundle"
                            ),
                            "verifier_attestation": attestation,
                            "proof_verified": True,
                            "proof_evidence": attestation.get("proof_evidence", ()),
                            "baseline": attestation.get("baseline"),
                            "candidate": attestation.get("candidate"),
                            "negative_control": attestation.get("negative_control"),
                            "evidence_refs": attestation.get("evidence_refs", ()),
                            "scope_context": attestation.get("scope_context", {}),
                            "identity_context": attestation.get("identity_context", {}),
                            "validator_id": attestation.get("validator_id", ""),
                            "validator_version": attestation.get("validator_version", ""),
                            "replay_metadata": attestation.get("replay_metadata", {}),
                            "promotion_guard": {
                                "status": "central_bundle_required",
                                "reason": "verifier_attestation_requires_central_sealed_bundle",
                            },
                        },
                    }
                )
            reason = (
                getattr(result, "reason", "typed_browser_proof_unavailable")
                if result is not None
                else "typed_browser_proof_runner_failed"
            )
            # A failed typed attempt is a reviewable observation, never a
            # confirmation. Continue only to gather bounded observations for
            # remaining candidate payloads.
            if result is not None and result.observations:
                observations = dict(result.observations)
            else:
                observations = {}
            return finding.model_copy(
                update={
                    **thread_update,
                    "confidence_level": "Needs Human Review",
                    "evidence": {
                        **(finding.evidence or {}),
                        "browser_validation_attempted": True,
                        "browser_payload_count": attempted,
                        "browser_validation_result": "typed_replay_failed",
                        "browser_validation_failure_reason": str(reason)[:240],
                        "browser_observations": observations,
                        "promotion_guard": {
                            "status": "blocked",
                            "reason": str(reason)[:240],
                        },
                    },
                }
            )

        # Compatibility fallback: direct Playwright is telemetry-only. It is
        # intentionally not passed to verify_replay_evidence and cannot change
        # confidence or attach a ProofBundle.
        dialog_observed = _test_payload_with_browser(
            browser,
            finding.url,
            payload,
            auth_state,
            stealth_mode=stealth_mode,
        )
        if dialog_observed:
            logger.warning(
                "Legacy browser dialog observed for finding %s; promotion blocked",
                finding.id,
            )
            return finding.model_copy(
                update={
                    **thread_update,
                    "confidence_level": "Needs Human Review",
                    "evidence": {
                        **(finding.evidence or {}),
                        "browser_validation_attempted": True,
                        "browser_payload_count": attempted,
                        "browser_validation_result": "dialog_observed_proof_blocked",
                        "browser_validation_failure_reason": "typed_replay_required",
                        "promotion_guard": {
                            "status": "blocked",
                            "reason": "dialog_only_signal_not_accepted",
                        },
                    },
                }
            )

    logger.info("Browser validation produced no promotion for finding %s", finding.id)
    return finding.model_copy(
        update={
            **thread_update,
            "evidence": {
                **(finding.evidence or {}),
                "browser_validation_attempted": True,
                "browser_payload_count": attempted,
                "browser_validation_result": "no_causal_signal",
                "browser_validation_failure_reason": "typed_replay_unavailable_or_not_demonstrated",
            }
        }
    )


def _perform_login(browser: Any, url: str, credentials: dict[str, str]) -> None:
    """Compatibility hook that rejects all authenticated browser actions."""
    del browser, url, credentials
    logger.warning("Authenticated browser login blocked by account-action policy")


# Retained as a compatibility sentinel; it is never populated or transported.
_LAST_LOGIN_COOKIES: dict[str, str] = {}


def _build_typed_browser_proof_runner(
    state: PentestState,
    *,
    thread_id: str | None,
) -> Any | None:
    """Build the runner only from live, registered typed control-plane objects."""
    runtime = state.get("runtime_context")
    if runtime is None or not getattr(runtime, "valid", False):
        return None
    adapter = getattr(runtime, "control_plane_browser_adapter", None)
    control_plane = getattr(runtime, "control_plane_runtime", None)
    replay_engine = getattr(runtime, "replay_engine", None)
    if adapter is None or control_plane is None or replay_engine is None:
        return None
    registry = getattr(runtime, "adapters", None)
    registered = (
        registry.get("control_plane_browser")
        if registry is not None and hasattr(registry, "get")
        else None
    )
    if registered is None or not callable(getattr(registered, "handler", None)):
        return None
    if registered.handler is not adapter:
        return None
    target_registration = getattr(runtime, "target_adapter_registration", None)
    if target_registration is None:
        return None
    try:
        target_errors = target_registration.validate()
        workflow_allowlist = tuple(target_registration.adapter.workflow_ids())
    except Exception:
        return None
    if target_errors or not workflow_allowlist:
        return None
    if hasattr(registry, "validate_for_execution"):
        valid_registration, _errors = registry.validate_for_execution(
            "control_plane_browser"
        )
        if not valid_registration:
            return None
    if getattr(registered, "proof_contract", "") != "observation_only_no_confirmation":
        return None
    engagement_id = str(state.get("engagement_id") or runtime.engagement_id or "").strip()
    if not engagement_id or engagement_id != str(runtime.engagement_id):
        return None
    scope = getattr(control_plane, "scope", None)
    session_manager = getattr(control_plane, "session_manager", None)
    if scope is None or session_manager is None:
        return None
    try:
        from webpent.shared.browser_proof_runner import BrowserProofRunner
        from webpent.shared.control_plane_runtime import BrowserActionAdapter

        if not isinstance(adapter, BrowserActionAdapter):
            return None
        session = session_manager.create_session(
            engagement_id=engagement_id,
            profile_ref=f"execution-{thread_id or 'run'}-{uuid4().hex}",
            browser_type="chromium",
            authenticated_origins=(),
            cookie_fingerprint="sha256:" + hashlib.sha256(
                f"{engagement_id}:{thread_id or ''}".encode()
            ).hexdigest(),
        )
        return BrowserProofRunner(
            replay_engine=replay_engine,
            adapter=adapter,
            session=session,
            scope=scope,
            engagement_id=engagement_id,
            workflow_allowlist=workflow_allowlist,
        )
    except (ImportError, OSError, TypeError, ValueError, RuntimeError) as exc:
        logger.warning(
            "Typed browser runner unavailable; execution remains fail-closed: %s",
            type(exc).__name__,
        )
        return None


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def execution_sandbox_node(state: PentestState) -> dict:
    """LangGraph node implementing active browser-based XSS exploitation.

    V4.5 Sprint 2: Adds Playwright pre-flight health check and
    authenticated login before payload execution.

    V5 Sprint 6: Reads ``stealth_mode`` from state and threads it
    through to per-payload tests so jitter is applied before each
    navigation and form-submit action.

    V7 P0: Dev Mode (and the pre-exploitation pause it used to force
    regardless of ``auto_approve``) has been removed. The graph's
    ``interrupt_before=[NODE_EXECUTION_SANDBOX]`` (see
    ``graph/builder.py``) pauses by default. P2 adds a second,
    defense-in-depth gate here: auto-approved high-risk work is surfaced
    for human approval and destructive work is rejected even if a caller
    bypasses the compile-time interrupt.
    """
    # V9 P0 [round-2 wiring audit]: _LAST_LOGIN_COOKIES is a
    # module-level dict (see bottom of file) shared by every call to
    # this node in this worker process, across ALL engagements. It is
    # only ever cleared+repopulated on a successful login later in
    # this function — nothing previously reset it on entry. A worker
    # process that has already handled one engagement (Celery prefork
    # workers persist across many tasks; so does a single asyncio
    # process) would silently inject a PRIOR engagement's still-cached
    # session cookies into THIS engagement's browser context whenever
    # this node runs without a fresh successful login overwriting them
    # first (e.g. this engagement has no `credentials` in state at
    # all, relying solely on operator-supplied session_cookies) — the
    # same cross-engagement leakage class the engagement-scope
    # ContextVar was deliberately built to prevent (see
    # shared/engagement_scope.py and pentest_worker.py's `finally:
    # clear_engagement_target_hosts(token)`), just not applied here.
    # Clear the compatibility sentinel at each invocation; it is never
    # populated because authenticated browser actions are forbidden.
    _LAST_LOGIN_COOKIES.clear()

    target = state["target"]
    findings: list[Finding] = list(state.get("findings") or [])
    payloads_to_test: dict[str, list[str]] = dict(state.get("payloads_to_test") or {})
    auth_state: dict[str, Any] = state.get("auth_state") or {}
    credentials: dict[str, str] = state.get("credentials") or {}
    playwright_enabled: bool = state.get("playwright_enabled", True)
    # V5 Sprint 6: read stealth flag from graph state (set by CLI --stealth).
    stealth_mode: bool = bool(state.get("stealth_mode", False))
    # V10 AUDIT FIX (C2): read thread_id from state so it can be passed
    # to _test_finding_payloads for mid-scan persistence stamping.
    thread_id: str | None = state.get("thread_id") or None
    execution_observations: list[dict[str, Any]] = [
        _execution_event(
            "start",
            reason="payload_queue_present",
        )
    ]

    logger.info(
        "Execution sandbox (Playwright) phase entered for target=%s "
        "(%d findings with payloads, stealth=%s)",
        target.url, len(payloads_to_test), stealth_mode,
    )

    # V7 P0 + P2: compile-time HITL remains the primary gate, while this
    # execution-side check protects resumed or directly-invoked nodes.
    gate = evaluate_execution_gate(state)
    gate_record = {
        "status": gate.status,
        "risk_level": derive_execution_risk(state),
        "reason": gate.reason,
        "human_approval_required": gate.status == "needs_approval",
    }
    if not gate.allowed:
        logger.warning(
            "Execution sandbox blocked by safety gate: status=%s risk=%s",
            gate.status,
            gate_record["risk_level"],
        )
        execution_observations.append(
            _execution_event("blocked", reason=gate.reason)
        )
        return {
            "execution_gate": gate_record,
            "execution_observations": execution_observations,
            "messages": [
                AIMessage(
                    content=(
                        "Execution sandbox blocked by safety policy: "
                        f"{gate.status} ({gate_record['risk_level']})."
                    )
                )
            ],
            "current_phase": "sandbox_execution",
        }

    # POST-P0 Phase 3: pre-phase session liveness probe. Runs once at
    # this choke point (every execution/validation round re-enters this
    # node, including optimizer replays). With a live session it stamps
    # healthy; with a dead session it performs the bounded re-login
    # (≤2/run, shared routine) and — if still dead — requests an honest
    # downgrade so validation stops producing false "not injectable"
    # results. The browser path stays cookie-free by account-action
    # policy; this probe governs the STATE, not the browser context.
    if state.get("session_cookies"):
        try:
            from webpent.shared.session_liveness import ensure_live_session

            liveness_update = ensure_live_session(state, thread_id=thread_id)
            liveness_record = liveness_update.get("session_liveness") or {}
            execution_observations.append(
                _execution_event(
                    "session_liveness",
                    reason=str(liveness_record.get("status") or "unknown"),
                )
            )
            if liveness_record.get("downgrade_requested"):
                logger.error(
                    "Execution sandbox: session dead after bounded re-auth — "
                    "downgrade requested; skipping browser execution (honest park)."
                )
                return {
                    "execution_gate": gate_record,
                    "session_liveness": liveness_record,
                    "session_cookies": liveness_update.get("session_cookies", {}),
                    "execution_observations": execution_observations,
                    "messages": [
                        AIMessage(
                            content=(
                                "Execution sandbox: authenticated session is dead and "
                                "re-auth budget is exhausted — findings remain parked "
                                "for human review (no execution with a dead session)."
                            )
                        )
                    ],
                    "current_phase": "sandbox_execution",
                }
            sandbox_state_update: dict[str, Any] = {"session_liveness": liveness_record}
            if liveness_update.get("session_cookies"):
                sandbox_state_update["session_cookies"] = liveness_update["session_cookies"]
        except Exception as exc:
            # Liveness is advisory for the browser path (which is
            # cookie-free anyway) — never block execution on a probe error.
            logger.warning("Session liveness probe error (continuing): %s", type(exc).__name__)
            sandbox_state_update = {}
    else:
        sandbox_state_update = {}

    # V4.5 Sprint 2: Pre-flight health check — skip if disabled.
    if not playwright_enabled:
        logger.info("Playwright disabled by pre-flight check — skipping sandbox")
        execution_observations.append(
            _execution_event("skipped", reason="playwright_disabled")
        )
        return {
            **sandbox_state_update,
            "execution_gate": gate_record,
            "execution_observations": execution_observations,
            "messages": [AIMessage(content="Execution sandbox: Playwright disabled (pre-flight).")],
            "current_phase": "sandbox_execution",
        }

    if not _has_payloads(state):
        logger.info("No payloads to test — skipping Playwright execution")
        execution_observations.append(
            _execution_event("skipped", reason="no_payloads_queued")
        )
        return {
            **sandbox_state_update,
            "execution_gate": gate_record,
            "execution_observations": execution_observations,
            "messages": [AIMessage(content="Execution sandbox: no payloads queued — skipping.")],
            "current_phase": "sandbox_execution",
        }

    findings_by_id: dict[UUID, Finding] = {f.id: f for f in findings}

    # Prefer the registered typed control-plane runner. It creates no direct
    # browser transport and keeps all proof-bound observations under the
    # ActionExecutor/replay/verifier chain.
    proof_runner = _build_typed_browser_proof_runner(
        state,
        thread_id=thread_id,
    )
    pw = None
    browser = None
    if proof_runner is None:
        # Compatibility fallback is telemetry-only and can never promote.
        _target_hosts = sorted({
            urlparse(f.url).hostname
            for f in findings
            if f.url and urlparse(f.url).hostname
        })
        pw, browser = _try_launch_browser(_target_hosts)
        if browser is None:
            logger.error("Could not launch Playwright browser — skipping sandbox execution")
            execution_observations.append(
                _execution_event("skipped", reason="browser_launch_failed")
            )
            return {
                **sandbox_state_update,
                "execution_gate": gate_record,
                "execution_observations": execution_observations,
                "messages": [
                    AIMessage(content="Execution sandbox: Playwright unavailable — skipped.")
                ],
                "current_phase": "sandbox_execution",
            }
        if credentials:
            # Account actions are intentionally forbidden. Do not invoke the
            # legacy login helper or consume real credentials.
            logger.warning("Credentialed browser login is disabled by policy")
            execution_observations.append(
                _execution_event("blocked", reason="account_actions_forbidden")
            )
    else:
        execution_observations.append(
            _execution_event("typed_runner_ready", reason="control_plane_replay_bound")
        )

    confirmed_count = 0
    tested_count = 0

    try:
        for finding_id_str, payloads in payloads_to_test.items():
            try:
                finding_id = UUID(finding_id_str)
            except ValueError:
                logger.warning("Malformed finding ID: %r", finding_id_str)
                execution_observations.append(
                    _execution_event("skipped", reason="malformed_finding_id")
                )
                continue

            finding = findings_by_id.get(finding_id)
            if finding is None:
                logger.warning("Finding %s not in state — skipping", finding_id)
                execution_observations.append(
                    _execution_event("skipped", reason="finding_not_in_state")
                )
                continue
            if not payloads:
                execution_observations.append(
                    _execution_event("skipped", reason="empty_payload_list", finding=finding)
                )
                continue
            # V9 P0 [round-2 wiring audit]: defense-in-depth — as of
            # this fix, payload_generator_node only ever seeds
            # payloads_to_test for XSS findings (see
            # _PAYLOAD_CONSUMING_CLASSES there), so this should always
            # be true. This check protects a RESUMED engagement whose
            # checkpointed state was written before that fix (a stale
            # sqli/csrf/ssrf/rce/deserialization entry). Without it, a
            # non-XSS finding would be form-submitted with an
            # LLM-generated "payload" string and, if any unrelated
            # on-page JS happens to fire a dialog, get wrongly marked
            # a confirmed result via a dialog-only marker
            # despite having no relationship to that finding's actual
            # vuln_class.
            if finding.vuln_class != VulnClass.XSS.value:
                logger.debug(
                    "Skipping browser payload test for finding %s: "
                    "vuln_class=%s is not browser-payload-driven "
                    "(stale payloads_to_test entry from before the "
                    "wiring fix, or a resumed pre-fix checkpoint).",
                    finding_id, finding.vuln_class,
                )
                execution_observations.append(
                    _execution_event(
                        "skipped",
                        reason="non_xss_payload_entry",
                        finding=finding,
                    )
                )
                continue

            tested_count += 1
            updated = _test_finding_payloads(
                browser, finding, payloads, auth_state,
                stealth_mode=stealth_mode,
                thread_id=thread_id,
                verification_context={
                    "engagement_id": state.get("engagement_id") or thread_id,
                    "hypothesis_id": finding.hypothesis_id,
                    "scope_context": {
                        "target_origin": f"{urlparse(finding.url).scheme}://{urlparse(finding.url).netloc}",
                        "declared_scope": list(state.get("target_scope") or ()),
                        "scope_bound": bool(state.get("target_scope") or target.url),
                    },
                    "identity_context": {
                        "mode": "anonymous",
                        "cookie_count": 0,
                        "identity_profile_count": 0,
                    },
                    "target_package": {
                        "target_package_id": state.get("target_package_id"),
                        "target_package_sha256": state.get("target_package_sha256"),
                        "target_package_scope_digest": state.get("target_package_scope_digest"),
                        "target_package_policy_digest": state.get("target_package_policy_digest"),
                    },
                },
                proof_runner=proof_runner,
            )
            # Always write back the browser outcome. Previously only a
            # confirmed dialog replaced the finding, so a real no-dialog
            # attempt disappeared before validator/reporting could explain
            # the coverage gap. The evidence remains fail-closed.
            findings_by_id[finding_id] = updated
            evidence = updated.evidence or {}
            browser_result = evidence.get("browser_validation_result")
            if not browser_result:
                browser_result = (
                    "dialog_observed_proof_blocked"
                    if evidence.get("positive_signal") is True
                    else "no_dialog"
                )
            promotion_guard = evidence.get("promotion_guard") or {}
            execution_observations.append(
                _execution_event(
                    "payload_test",
                    finding=updated,
                    payload=payloads[0],
                    result=str(browser_result),
                    reason=(
                        evidence.get("browser_validation_failure_reason")
                        or promotion_guard.get("reason")
                    ),
                )
            )
            if (
                updated.confidence == Confidence.CONFIRMED.value
                and (updated.evidence or {}).get("proof_bundle_sealed") is True
            ):
                confirmed_count += 1
    finally:
        with contextlib.suppress(Exception):
            if browser is not None:
                browser.close()
        with contextlib.suppress(Exception):
            if pw is not None:
                pw.stop()

    updated_findings: list[Finding] = [
        findings_by_id[f.id] for f in findings if f.id in findings_by_id
    ]

    summary = (
        f"Execution sandbox (Playwright) completed. Tested {tested_count} "
        f"finding(s); {confirmed_count} centrally bundle-confirmed."
    )
    execution_observations.append(
        _execution_event(
            "completed",
            reason="browser_run_finished",
            result=(
                f"tested={tested_count};confirmed={confirmed_count}"
            ),
        )
    )
    logger.info(summary)

    return {
        **sandbox_state_update,
        "findings": updated_findings,
        "execution_gate": gate_record,
        "execution_observations": execution_observations,
        "messages": [AIMessage(content=summary)],
        "current_phase": "sandbox_execution",
    }
