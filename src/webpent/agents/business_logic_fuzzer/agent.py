# src/webpent/agents/business_logic_fuzzer/agent.py
"""webpent.agents.business_logic_fuzzer.agent

V7 Sprint 2.7 — Business Logic Fuzzer (Race Conditions + State Abuse).

Detects business-logic vulnerabilities that traditional scanners miss:
race conditions (double-spend, TOCTOU in balance updates), workflow
bypass (skipping required steps), and state-machine abuse (applying a
discount code twice, using a coupon after expiry).

The agent identifies state-changing endpoints (POST/PUT/DELETE) from
crawled data, then sends concurrent request bursts to detect race
conditions. All bursts are gated by the
:class:`RequestRateGovernor <webpent.shared.rate_governor.RequestRateGovernor>`
to prevent accidental DoS.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from typing import Any
from urllib.parse import urljoin, urlparse
from uuid import NAMESPACE_URL, uuid5

from langchain_core.messages import AIMessage

from webpent.models.findings import Finding, Severity, VulnClass
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)

# Concurrent burst size for race-condition testing.
_BURST_SIZE = 10
# Maximum endpoints to fuzz per engagement (bounds engagement time).
_MAX_ENDPOINTS = 10

# POST-P0 Phase 8: bounded stateful-flow replay bounds. Total network
# cost is capped at _MAX_FLOW_REPLAYS flows x (baseline + skip + reorder)
# requests — no unbounded request storms are possible by construction.
_MAX_FLOW_REPLAYS = 3
_MAX_FLOW_STEPS = 3

# TEAM-1 (2026-10): bounded authorized-replay producer for race_condition.
# ``validate_race_condition`` (agents/validator/active_checks.py) refuses to
# confirm from a bare burst count — it requires ``evidence["race_replay"]``
# with baseline/candidate/negative-control observations, populated by "a
# separate authorized replay producer" (its own docstring). Nothing in this
# codebase ever populated that key (verified: `grep -rn "race_replay" src/`
# only matches the validator's own read of it) — every race_condition
# finding was structurally stuck at "Needs Human Review" forever, no matter
# how real the race was. The functions below are that producer. Gated
# behind the cheap concurrent burst already showing a differential
# (success_count > 1) and bounded to _MAX_RACE_REPLAYS endpoints per
# engagement, so the extra 2x-burst_size requests only run for endpoints
# that already look suspicious.
_MAX_RACE_REPLAYS = 5
# Negative control: same URL, same concurrent-burst mechanism, but a method
# the endpoint was never built to accept as a state-changing verb. A normal
# REST/form handler rejects TRACE (405/501/400, or simply never reaches the
# state-changing code path) regardless of auth or form fields, with no
# assumption about what would make a given body "invalid" for this
# endpoint. If TRACE also "succeeds" more than once, the burst/threading
# mechanism itself is suspect, not the target's locking.
_RACE_NEGATIVE_CONTROL_METHOD = "TRACE"


def _runtime_business_logic_limits() -> tuple[int, int]:
    """Return bounded, operator-tunable burst and endpoint limits."""
    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        burst_size = int(
            getattr(settings, "business_logic_burst_size", _BURST_SIZE)
        )
        max_endpoints = int(
            getattr(settings, "business_logic_max_endpoints", _MAX_ENDPOINTS)
        )
        return (
            max(1, min(burst_size, 20)),
            max(1, min(max_endpoints, 25)),
        )
    except Exception as exc:  # noqa: BLE001 - safe compatibility fallback
        logger.debug("Using default business-logic limits: %s", exc)
        return _BURST_SIZE, _MAX_ENDPOINTS


def _target_url(target: Any) -> str:
    if isinstance(target, dict):
        return str(target.get("url") or "")
    return str(getattr(target, "url", "") or "")


def _workflow_enrichment(
    state: PentestState,
    crawled_data: dict[str, Any],
    target: Any,
) -> dict[str, Any]:
    """Passively enrich state when the additive workflow flag is enabled."""
    try:
        from webpent.config.settings import get_settings

        if not get_settings().enable_workflow_understanding:
            return {}
        from webpent.models.hypothesis import Hypothesis, HypothesisOrigin
        from webpent.shared.workflow_understanding import (
            extract_workflow_observations,
            generate_business_logic_hypotheses,
            workflow_coverage_gaps,
        )

        target_url = _target_url(target)
        scope_checker = getattr(target, "is_in_scope", None)
        observations = extract_workflow_observations(
            crawled_data,
            target_url=target_url,
            scope_checker=scope_checker if callable(scope_checker) else None,
        )
        specs = generate_business_logic_hypotheses(observations, target_url=target_url)

        # UM-DR-30 (Workstream D §6 business-logic): the deterministic
        # invariant review. The checker was a zero-importer orphan while
        # its exact input (workflow observations) already flowed through
        # state — the classic dead-capability wiring gap. It is strictly
        # NON-PROMOTING: every result is a candidate signal whose
        # required_validation names the causal guard's evidence contract
        # (target-backed causal signal + independent negative control +
        # sealed replayable ProofBundle). Nothing here may confirm a
        # finding; a violated invariant only tells the campaign where a
        # guarded probe is worth spending budget.
        invariant_review: list[dict[str, Any]] = []
        try:
            from hashlib import sha256

            from webpent.business_logic.invariant_checker import InvariantChecker

            _engagement = str(state.get("engagement_id") or "").strip()
            _target_id = str(state.get("target_id") or "").strip() or (
                f"target-{sha256(target_url.encode('utf-8', 'ignore')).hexdigest()[:12]}"
                if target_url
                else ""
            )
            if _target_id and _engagement:
                invariant_review = [
                    result.model_dump(mode="json")
                    for result in InvariantChecker().check(
                        observations,
                        target_id=_target_id,
                        engagement_id=_engagement,
                    )
                ]
        except Exception as inv_exc:  # noqa: BLE001 — advisory layer, fail-soft
            logger.debug("Invariant review skipped safely: %s", inv_exc)
            invariant_review = []

        hypotheses = [
            Hypothesis(
                id=uuid5(NAMESPACE_URL, f"webpent:workflow:{spec.fingerprint}"),
                target_url=spec.target_url,
                statement=spec.statement,
                vuln_class=spec.vuln_class,
                confidence_score=spec.confidence_score,
                evidence_refs=spec.evidence_refs,
                origin=HypothesisOrigin.HEURISTIC,
                origin_detail=spec.origin_detail,
                evidence_contract=spec.evidence_contract,
                hint_provenance=spec.hint_provenance or ["business_logic"],
                estimated_cost=float(spec.request_budget),
            )
            for spec in specs
        ]
        logger.info(
            "Workflow understanding: %d observations, %d bounded hypotheses, "
            "%d gaps, %d invariant candidate signals",
            len(observations),
            len(hypotheses),
            len(workflow_coverage_gaps(crawled_data, observations)),
            len(invariant_review),
        )
        return {
            "workflow_observations": [item.model_dump(mode="json") for item in observations],
            "workflow_coverage_gaps": workflow_coverage_gaps(crawled_data, observations),
            "invariant_review": invariant_review,
            "hypotheses": hypotheses,
        }
    except Exception as exc:
        logger.warning("Workflow understanding skipped safely: %s", exc)
        return {
            "workflow_coverage_gaps": [
                {
                    "gap": "workflow_understanding_error",
                    "reason": "The passive workflow projection failed closed.",
                    "status": "error",
                }
            ],
        }


def _extract_state_changing_endpoints(
    crawled_data: dict[str, Any],
    max_endpoints: int = _MAX_ENDPOINTS,
) -> list[dict[str, Any]]:
    """Extract POST/PUT/DELETE endpoints from crawled data.

    Returns a list of dicts: ``{"url": str, "method": str, "form_data": dict}``.

    V9 P0 B5: previously this function fell back to treating every
    entry in ``crawled_data["endpoints"]`` (a list of URL strings) as
    a POST target — sending blind POST bursts to arbitrary URLs the
    crawler discovered. That's a broad attack surface with no signal
    that the endpoint actually accepts POST or has state-changing
    semantics. Now we ONLY act on structured form metadata in
    ``crawled_data["forms"]`` — each form dict must have an ``action``
    (or ``url``) and a ``method``. If no forms are populated, the
    fuzzer returns no endpoints (safe degradation — no findings, no
    broad POST noise). The crawler can be enhanced separately to
    populate ``crawled_data["forms"]`` with real form metadata.
    """
    endpoints: list[dict[str, Any]] = []

    if isinstance(crawled_data, dict):
        # V9 P0 B5: ONLY look at structured form metadata. Do NOT fall
        # back to bare endpoint URL strings — a blind POST to every
        # crawled URL is a broad attack with no exploitability signal.
        forms = crawled_data.get("forms") or []
        if isinstance(forms, list):
            for form in forms:
                if isinstance(form, dict):
                    method = str(form.get("method", "POST")).upper()
                    if method in ("POST", "PUT", "PATCH", "DELETE"):
                        url = form.get("action") or form.get("url")
                        if url:
                            endpoints.append(
                                {
                                    "url": url,
                                    "method": method,
                                    "form_data": form.get("data") or form.get("fields") or {},
                                }
                            )

    # Deduplicate by (url, method)
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for ep in endpoints:
        key = (ep["url"], ep["method"])
        if key not in seen:
            seen.add(key)
            unique.append(ep)

    return unique[:max(1, min(int(max_endpoints), 25))]


def _dispatch_request(
    client: Any, method: str, url: str, form_data: dict[str, Any], headers: dict[str, str]
) -> Any:
    """Issue one HTTP request with webpent's established method-to-call mapping.

    Shared by every request path in this module (single, sequential-detailed,
    concurrent-detailed) so the method dispatch is defined exactly once.
    ``GET``/``HEAD``/``OPTIONS``/``TRACE`` are routed through
    ``client.request`` with no body — needed for the race-condition
    negative control, which deliberately sends ``TRACE`` to a state-
    changing endpoint and expects a uniform rejection. Any other/unknown
    method falls back to POST, matching this module's long-standing
    default for malformed crawler-supplied methods.
    """
    if method == "POST":
        return client.post(url, data=form_data, headers=headers)
    if method == "PUT":
        return client.put(url, data=form_data, headers=headers)
    if method == "PATCH":
        return client.patch(url, data=form_data, headers=headers)
    if method == "DELETE":
        return client.delete(url, headers=headers)
    if method in ("GET", "HEAD", "OPTIONS", "TRACE"):
        return client.request(method, url, headers=headers)
    return client.post(url, data=form_data, headers=headers)


def _request_digest(method: str, url: str, form_data: dict[str, Any]) -> str:
    """Stable ``sha256:``-prefixed digest identifying what was actually sent.

    Same canonical-JSON-then-hash shape as the strict verifier's own
    ``_digest()`` (``shared/verifier.py``) — not imported directly since
    that one is private to its module, but deliberately mirrored so a
    candidate (POST, with body) and a TRACE negative control (no body)
    never collide, which is what lets ``verify_replay_evidence`` treat
    them as independently observed requests.
    """
    import json

    encoded = json.dumps(
        {"method": method, "url": url, "body": form_data or {}},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return f"sha256:{hashlib.sha256(encoded.encode('utf-8', 'replace')).hexdigest()}"


def _detailed_request(
    url: str,
    method: str,
    form_data: dict[str, Any],
    cookies: dict[str, str] | None = None,
    *,
    observation_role: str = "candidate",
) -> dict[str, Any]:
    """One bounded, SSRF-guarded, rate-governed request as redacted-ready evidence.

    Returns the observation shape BOTH ``validate_race_condition`` /
    ``_normalise_race_observation`` (``agents/validator/active_checks.py``,
    read from ``race_replay["baseline"/"candidate"/"negative_control"]``)
    AND the strict promotion verifier's ``_target_observation_ok``
    (``shared/verifier.py``) require: ``target_backed``, ``observation_role``,
    ``target_fingerprint``, ``request_digest``, ``response_digest`` — a
    status code alone (the old ``_send_concurrent_burst`` contract) cannot
    pass strict promotion at all. Never raises; returns a
    ``target_backed: False`` observation (status 0) on any transport
    failure, same fail-closed contract as ``_single_form_request``.
    """
    from webpent.shared.bac_identity_tester import target_fingerprint
    from webpent.shared.http import build_cookie_header, make_safe_httpx_client
    from webpent.shared.rate_governor import get_rate_governor

    governor = get_rate_governor()
    host = urlparse(url).hostname or "unknown"
    fingerprint = target_fingerprint(url)
    req_digest = _request_digest(method, url, form_data)
    empty: dict[str, Any] = {
        "url": url,
        "method": method,
        "status_code": 0,
        "target_backed": False,
        "observation_role": observation_role,
        "target_fingerprint": fingerprint,
        "request_digest": req_digest,
        "elapsed_ms": 0,
        "body_length": 0,
        "body_sha256": "",
        "headers": {},
    }
    try:
        with governor.acquire(host) as permit:
            if permit.aborted:
                logger.debug("Race-condition replay request aborted: %s", permit.reason)
                return empty
            headers: dict[str, str] = {}
            if cookies:
                headers["Cookie"] = build_cookie_header(cookies)
            started = time.monotonic()
            with make_safe_httpx_client(
                timeout=10.0, follow_redirects=False, verify=True
            ) as client:
                resp = _dispatch_request(client, method, url, form_data, headers)
            elapsed_ms = int((time.monotonic() - started) * 1000)
            governor.record_response(host, resp.status_code)
            body_bytes = resp.content or b""
            body_sha256 = hashlib.sha256(body_bytes).hexdigest()
            safe_headers = {str(k): str(v) for k, v in dict(resp.headers).items()}
            response_material = (
                f"{resp.status_code}|{len(body_bytes)}|{body_sha256}|"
                f"{sorted(safe_headers.items())!r}"
            )
            return {
                "url": url,
                "method": method,
                "status_code": int(resp.status_code),
                "target_backed": True,
                "observation_role": observation_role,
                "target_fingerprint": fingerprint,
                "request_digest": req_digest,
                "response_digest": (
                    f"sha256:{hashlib.sha256(response_material.encode()).hexdigest()}"
                ),
                "elapsed_ms": elapsed_ms,
                "body_length": len(body_bytes),
                "body_sha256": f"sha256:{body_sha256}",
                "headers": safe_headers,
            }
    except Exception as exc:
        logger.debug("Race-condition replay request failed for %s: %s", url, type(exc).__name__)
        return empty


def _send_concurrent_burst(
    url: str,
    method: str,
    form_data: dict[str, Any],
    cookies: dict[str, str] | None = None,
    burst_size: int = _BURST_SIZE,
    *,
    observation_role: str = "candidate",
) -> list[dict[str, Any]]:
    """Send ``burst_size`` concurrent identical requests to ``url``.

    Returns one detailed observation dict per response (see
    :func:`_detailed_request`) — not just a bare status code, so the result
    can double as race-replay evidence (``candidate`` or, with ``method``
    overridden to ``TRACE`` and ``observation_role="negative_control"``) with
    no second burst. Uses the :class:`RequestRateGovernor` to enforce the
    concurrent cap and error-rate abort. All requests use
    ``make_safe_httpx_client`` (SSRF guard + engagement-scope allowlist).

    V9 P0 B1: worker threads now inherit the parent thread's
    contextvars via ``contextvars.copy_context().run()``. Without this,
    the engagement-scope allowlist (a ContextVar) is empty inside the
    worker thread, so ``make_safe_httpx_client``'s SSRF guard blocks
    the operator-declared private-IP target — the module fails closed
    with zero requests reaching the target.
    """
    import contextvars

    results: list[dict[str, Any]] = []
    results_lock = threading.Lock()

    def _worker():
        observation = _detailed_request(
            url, method, form_data, cookies, observation_role=observation_role
        )
        with results_lock:
            results.append(observation)

    # V9 P0 B1: capture the parent thread's contextvars (including the
    # engagement-scope allowlist) and run each worker inside a copy.
    # ``contextvars.copy_context()`` returns a snapshot of the current
    # context; ``ctx.run(_worker)`` executes _worker with that context
    # active, so ContextVar lookups inside _worker see the parent's
    # values. This is the standard Python way to propagate contextvars
    # across thread boundaries.
    #
    # V9 P1 FIX: a ``contextvars.Context`` object is NOT reentrant
    # across concurrently-running threads — only one thread may be
    # "inside" ``ctx.run()`` at a time. The previous code called
    # ``contextvars.copy_context()`` ONCE and handed the SAME Context
    # object to every burst thread's ``target=``. As soon as two
    # threads were inside ``_worker`` at once (guaranteed here, since
    # ``_worker`` blocks on network I/O), every thread after the first
    # raised ``RuntimeError: cannot enter context: ... is already
    # entered`` — silently, since it propagates out of the Thread's
    # ``run()`` and is only ever printed to stderr by the default
    # excepthook, never caught by ``_worker``'s own try/except. Net
    # effect: a "burst_size-request concurrent burst" only ever ran
    # ONE request; the other burst_size-1 threads died before calling
    # the target at all. Since ``_detect_race_condition`` requires
    # more than one 2xx in the burst, race conditions were essentially
    # undetectable regardless of the cookie fix above.
    #
    # Fix: call ``contextvars.copy_context()`` separately for EACH
    # thread (still from this parent thread, so each copy still
    # carries the parent's ContextVar values — including the
    # engagement-scope allowlist) so every thread gets its own,
    # independently-enterable Context object.
    # RED-TEAM FIX (2026-10, finding #7): daemon=True as defense-in-depth.
    # t.join(timeout=30.0) below should always reap these, but if a thread
    # ever hangs past that timeout (a broken intermediary network layer,
    # say) a non-daemon thread would keep the process alive in the
    # background; daemon=True lets the process exit normally regardless.
    threads = [
        threading.Thread(target=contextvars.copy_context().run, args=(_worker,), daemon=True)
        for _ in range(burst_size)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30.0)

    return results


def _send_sequential_burst(
    url: str,
    method: str,
    form_data: dict[str, Any],
    cookies: dict[str, str] | None = None,
    count: int = _BURST_SIZE,
    *,
    observation_role: str = "baseline",
) -> list[dict[str, Any]]:
    """Send ``count`` requests ONE AT A TIME — the race-replay baseline arm.

    A single-use state-changing operation (redeem a coupon, cast a vote,
    withdraw a balance) should succeed once under normal, non-concurrent
    traffic and reject the rest — exactly what this measures. Comparing
    this against :func:`_send_concurrent_burst`'s candidate count is what
    separates a real TOCTOU gap from an endpoint that simply always
    returns 2xx regardless of how it's called (which a bare
    ``success_count > 1`` check, with no baseline, cannot tell apart from
    a genuine race — every call succeeding sequentially too means there
    was never a single-use invariant to race against).
    """
    return [
        _detailed_request(url, method, form_data, cookies, observation_role=observation_role)
        for _ in range(max(1, count))
    ]

def _single_form_request(
    url: str,
    method: str,
    form_data: dict[str, Any],
    cookies: dict[str, str] | None = None,
) -> int:
    """POST-P0 Phase 8: ONE bounded request; returns the status code (0 on failure).

    Uses the same SSRF-guarded client and rate governor as the race
    bursts. Session cookies are forwarded (the flow probes are only
    meaningful for authenticated surfaces — without a session this
    module's caller skips flow replay entirely).
    """
    from webpent.shared.http import build_cookie_header, make_safe_httpx_client
    from webpent.shared.rate_governor import get_rate_governor

    governor = get_rate_governor()
    host = urlparse(url).hostname or "unknown"
    try:
        with governor.acquire(host) as permit:
            if permit.aborted:
                return 0
            headers: dict[str, str] = {}
            if cookies:
                headers["Cookie"] = build_cookie_header(cookies)
            with make_safe_httpx_client(
                timeout=10.0, follow_redirects=False, verify=True
            ) as client:
                if method == "POST":
                    resp = client.post(url, data=form_data, headers=headers)
                elif method == "PUT":
                    resp = client.put(url, data=form_data, headers=headers)
                elif method == "PATCH":
                    resp = client.patch(url, data=form_data, headers=headers)
                elif method == "DELETE":
                    resp = client.delete(url, headers=headers)
                else:
                    resp = client.post(url, data=form_data, headers=headers)
            governor.record_response(host, resp.status_code)
            return int(resp.status_code)
    except Exception as exc:
        logger.debug("Flow replay request failed for %s: %s", url, type(exc).__name__)
        return 0


def _sequential_form_flows(forms: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Group state-changing forms into bounded multi-step flows (by source page).

    A flow is 2.._MAX_FLOW_STEPS state-changing forms sharing the same
    ``source_url`` (a crawler-recorded sequence, e.g. multi-page
    checkout). Purely deterministic grouping over already-discovered
    forms — nothing is enumerated or invented.
    """
    flows: list[list[dict[str, Any]]] = []
    groups: dict[str, list[dict[str, Any]]] = {}
    for form in forms or []:
        if not isinstance(form, dict):
            continue
        method = str(form.get("method") or "GET").upper()
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            continue
        source = str(form.get("source_url") or "")
        groups.setdefault(source, []).append(form)
    for _source, group in groups.items():
        if len(group) >= 2:
            flows.append(group[:_MAX_FLOW_STEPS])
        if len(flows) >= _MAX_FLOW_REPLAYS:
            break
    return flows


def _bounded_flow_replay(
    forms: list[dict[str, Any]],
    cookies: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Bounded stateful-flow probes: step-skip and step-reorder differentials.

    For at most _MAX_FLOW_REPLAYS flows (2..3 steps each):
      * baseline — execute steps in crawler-observed order,
      * skip     — execute the final step WITHOUT its predecessors,
      * reorder  — execute the final step BEFORE its predecessors.

    A hypothesis is emitted only when the final step succeeds (2xx) in a
    corrupted order while the honest baseline also succeeds — i.e. the
    server accepted the state transition out of sequence. The
    deterministic validation attempt IS the probe sequence itself; no
    confirmation authority is claimed (findings would still require the
    normal validator path).
    """
    observations: list[dict[str, Any]] = []
    hypotheses: list[dict[str, Any]] = []
    for flow in _sequential_form_flows(forms or []):
        steps = [
            {
                "url": str(f.get("action") or ""),
                "method": str(f.get("method") or "POST").upper(),
                "form_data": dict(f.get("data") or {}),
            }
            for f in flow
        ]
        if len(steps) < 2 or any(not s["url"] for s in steps):
            continue
        final = steps[-1]
        predecessors = steps[:-1]

        baseline_statuses = [
            _single_form_request(s["url"], s["method"], s["form_data"], cookies)
            for s in steps
        ]
        skip_status = _single_form_request(
            final["url"], final["method"], final["form_data"], cookies
        )
        reorder_statuses = [
            _single_form_request(final["url"], final["method"], final["form_data"], cookies)
        ] + [
            _single_form_request(s["url"], s["method"], s["form_data"], cookies)
            for s in predecessors
        ]

        def _ok(code: int) -> bool:
            return 200 <= code < 300

        baseline_ok = _ok(baseline_statuses[-1])
        skip_ok = _ok(skip_status)
        reorder_ok = _ok(reorder_statuses[0])
        observation = {
            "probe": "bounded_stateful_flow_replay",
            "steps": [
                {"url": s["url"], "method": s["method"]} for s in steps
            ],
            "baseline_statuses": baseline_statuses,
            "skip_step_status": skip_status,
            "reorder_statuses": reorder_statuses,
            "requests_used": len(steps) + 2,
        }
        observations.append(observation)
        if baseline_ok and (skip_ok or reorder_ok):
            hypotheses.append(
                {
                    "statement": (
                        "Stateful flow accepted a corrupted sequence: the final "
                        f"step ({final['method']} {final['url']}) succeeded "
                        + ("without its predecessors (skip)" if skip_ok else "")
                        + (" and " if skip_ok and reorder_ok else "")
                        + ("out of order (reorder)" if reorder_ok else "")
                        + ". Server-side state-transition enforcement is a candidate gap."
                    ),
                    "vuln_class": "unknown",
                    "evidence_ref": observation,
                    "advisory_only": True,
                    "requires_validation": True,
                }
            )
        # Hard bound: total requests across all flows stay small by
        # construction; break early if we somehow exceeded the budget.
        used = sum(int(o.get("requests_used") or 0) for o in observations)
        if used >= _MAX_FLOW_REPLAYS * (_MAX_FLOW_STEPS + 2):
            break
    return observations, hypotheses


def _detect_race_condition(status_codes: list[int]) -> bool:
    """Check if the status codes indicate a race condition.

    A race condition is detected when more than one request in the
    burst succeeded (returned 2xx) for an operation that should only
    succeed once (e.g., a withdrawal, a coupon application, a vote).
    """
    success_count = sum(1 for sc in status_codes if 200 <= sc < 300)
    return success_count > 1


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def business_logic_fuzzer_node(state: PentestState) -> dict:
    """LangGraph node: fuzz business-logic vulnerabilities via concurrent bursts.

    V7 Sprint 2.7: Identifies state-changing endpoints, sends
    concurrent request bursts (size 10) to each, and raises a finding
    if more than one request in the burst succeeds (indicating a race
    condition in the target's state update logic).
    """
    target = state.get("target")
    findings: list[Finding] = list(state.get("findings") or [])
    crawled_data: dict[str, Any] = state.get("crawled_data") or {}

    # SCENARIO CONTRACT (step 9): probe the session before this heavy
    # authenticated phase so flow replays carry live cookies only.
    _liveness_gate: dict[str, Any] = {}
    try:
        from webpent.shared.session_liveness import phase_liveness_update

        _liveness_gate = phase_liveness_update(state, phase="business_logic")
        if _liveness_gate.get("session_cookies"):
            state = {**state, "session_cookies": {
                **(state.get("session_cookies") or {}),
                **_liveness_gate["session_cookies"],
            }}
    except Exception as _gate_exc:  # noqa: BLE001 — gate must never stop the phase
        logger.warning("Business-logic session liveness gate skipped safely: %s", _gate_exc)
        _liveness_gate = {}

    workflow_update = _workflow_enrichment(state, crawled_data, target)

    logger.info(
        "Business Logic Fuzzer (V7 Sprint 2.7) entered for target=%s (%d findings)",
        getattr(target, "url", "<unknown>"),
        len(findings),
    )

    # Verify the RequestRateGovernor is available (wiring test per
    # Principle 4: no dead guardrails).
    try:
        from webpent.shared.rate_governor import get_rate_governor

        governor = get_rate_governor()
        logger.debug(
            "Business Logic Fuzzer: RequestRateGovernor available (max_concurrent=%d)",
            governor._max_concurrent,
        )
    except ImportError:
        logger.warning(
            "Business Logic Fuzzer: RequestRateGovernor not importable — skipping bursts."
        )
        _governor_skip_update: dict[str, Any] = {
            **workflow_update,
            "messages": [
                AIMessage(content="Business Logic Fuzzer: rate governor unavailable — skipped.")
            ],
            "current_phase": "business_logic_fuzzing",
        }
        for _gate_key in ("session_liveness", "session_cookies", "engagement_limitations"):
            if _liveness_gate and _gate_key in _liveness_gate:
                _governor_skip_update[_gate_key] = _liveness_gate[_gate_key]
        return _governor_skip_update

    # Extract state-changing endpoints using bounded operator settings.
    burst_size, max_endpoints = _runtime_business_logic_limits()
    endpoints = _extract_state_changing_endpoints(
        crawled_data,
        max_endpoints=max_endpoints,
    )
    if not endpoints:
        logger.info("Business Logic Fuzzer: no state-changing endpoints found")
        _no_endpoints_update: dict[str, Any] = {
            **workflow_update,
            "messages": [
                AIMessage(content="Business Logic Fuzzer: no state-changing endpoints found.")
            ],
            "current_phase": "business_logic_fuzzing",
        }
        for _gate_key in ("session_liveness", "session_cookies", "engagement_limitations"):
            if _liveness_gate and _gate_key in _liveness_gate:
                _no_endpoints_update[_gate_key] = _liveness_gate[_gate_key]
        return _no_endpoints_update

    # Extract session cookies.
    #
    # V9 P1 FIX: auth_node ALWAYS stores state["auth_state"]["cookies"]
    # as list[{"name": ..., "value": ..., "domain": ...}] — see
    # authentication/agent.py (both the operator-supplied-cookies path
    # and the Playwright-login path build this same list shape). The
    # previous `isinstance(auth_state.get("cookies"), dict)` check here
    # therefore always evaluated False, so auth_cookies was always None
    # and every fuzzer burst request went out unauthenticated.
    #
    # auth_node writes the SAME cookies to state["session_cookies"] as a
    # flat dict[str, str] — that field is the canonical, already-
    # flattened session-cookie jar every other cookie-consuming agent
    # reads from (crawler, recon/nuclei, validator/sqlmap+dalfox,
    # api_testing, request_smuggling). Match that established pattern
    # here instead of parsing the list form.
    auth_cookies: dict[str, str] | None = state.get("session_cookies") or None

    new_findings: list[Finding] = []
    # Bounds the baseline + negative-control replay to _MAX_RACE_REPLAYS
    # suspicious endpoints per engagement (see the constant's docstring).
    race_replays_used = 0

    for ep in endpoints:
        url = ep["url"]
        method = ep["method"]
        form_data = ep["form_data"]

        # Resolve relative URLs against the target.
        base_url = getattr(target, "url", "")
        if not url.startswith("http") and base_url:
            url = urljoin(base_url, url)

        logger.info(
            "Business Logic Fuzzer: bursting %s %s (%d requests)",
            method,
            url,
            burst_size,
        )

        candidate_observations = _send_concurrent_burst(
            url,
            method,
            form_data,
            cookies=auth_cookies,
            burst_size=burst_size,
        )
        status_codes = [int(o.get("status_code") or 0) for o in candidate_observations]

        if _detect_race_condition(status_codes):
            success_count = sum(1 for sc in status_codes if 200 <= sc < 300)
            status_histogram: dict[str, int] = {}
            for status_code in status_codes:
                key = str(status_code)
                status_histogram[key] = status_histogram.get(key, 0) + 1

            evidence: dict[str, Any] = {
                "race_probe": {
                    "observation_type": "candidate_burst_summary",
                    "target_backed": True,
                    "proof_ready": False,
                    "method": method,
                    "path": urlparse(url).path,
                    "burst_size": len(status_codes),
                    "candidate_successes": success_count,
                    "status_code_histogram": status_histogram,
                    "requires_baseline_negative_control_replay": True,
                }
            }
            reasoning = (
                f"Sent {burst_size} concurrent {method} requests to "
                f"{url}. {success_count} returned 2xx (status codes: "
                f"{status_codes}). More than one success in a burst "
                f"indicates the server does not atomically serialize "
                f"state-changing operations."
            )

            # Bounded authorized replay producer (see _MAX_RACE_REPLAYS'
            # docstring): populate evidence["race_replay"] so
            # validate_race_condition can actually confirm this finding
            # instead of parking at "Needs Human Review" forever for lack
            # of a baseline/negative-control replay. Best-effort — a
            # failure here still leaves the race_probe evidence above
            # intact, same as before this replay producer existed.
            if race_replays_used < _MAX_RACE_REPLAYS:
                race_replays_used += 1
                try:
                    baseline_observations = _send_sequential_burst(
                        url, method, form_data, cookies=auth_cookies, count=burst_size,
                    )
                    negative_observations = _send_concurrent_burst(
                        url,
                        _RACE_NEGATIVE_CONTROL_METHOD,
                        form_data,
                        cookies=auth_cookies,
                        burst_size=burst_size,
                        observation_role="negative_control",
                    )
                    def _success_count(observations: list[dict[str, Any]]) -> int:
                        return sum(
                            1 for o in observations if 200 <= int(o.get("status_code") or 0) < 300
                        )

                    baseline_successes = _success_count(baseline_observations)
                    negative_successes = _success_count(negative_observations)
                    first_candidate = candidate_observations[0] if candidate_observations else None
                    first_baseline = baseline_observations[0] if baseline_observations else None
                    first_negative = negative_observations[0] if negative_observations else None
                    evidence["race_replay"] = {
                        "baseline": first_baseline,
                        "candidate": first_candidate,
                        "negative_control": first_negative,
                        "baseline_successes": baseline_successes,
                        "candidate_successes": success_count,
                        "negative_control_successes": negative_successes,
                        "burst_size": len(status_codes),
                        "independent_control": True,
                    }
                    reasoning += (
                        f" Bounded replay: baseline (sequential) succeeded "
                        f"{baseline_successes}/{len(baseline_observations)}; "
                        f"negative control ({_RACE_NEGATIVE_CONTROL_METHOD}, "
                        f"concurrent) succeeded "
                        f"{negative_successes}/{len(negative_observations)}."
                    )
                except Exception as exc:
                    logger.warning(
                        "business_logic_fuzzer: race-condition replay producer "
                        "failed for %s %s (finding still raised without "
                        "race_replay evidence): %s",
                        method,
                        url,
                        exc,
                    )

            # V10 RESIDUAL FIX: wrap Finding construction in a narrow
            # try/except so a pydantic ValidationError (or any other
            # construction bug) is logged at ERROR and the for loop
            # continues to the next endpoint, instead of crashing the
            # business_logic_fuzzer_node entirely (which would lose all
            # subsequent race-condition findings and abort the graph
            # node). Mirrors access_control / request_smuggling pattern.
            try:
                finding = Finding(
                    title=f"Race condition: {method} {urlparse(url).path}",
                    description=(
                        f"The endpoint {url} accepted {success_count} concurrent "
                        f"{method} requests in a burst of {len(status_codes)}. "
                        f"This indicates a race condition in the server's state "
                        f"update logic — an attacker can exploit this to "
                        f"double-spend, apply a coupon multiple times, or "
                        f"bypass a use-count limit."
                    ),
                    severity=Severity.HIGH,
                    confidence_level="AI-Assessed",
                    # V10 P0-1: VulnClass.RACE_CONDITION is now a real enum
                    # member (added in V9 P1 FIX). Use the enum value for
                    # type-safety instead of the raw string.
                    vuln_class=VulnClass.RACE_CONDITION.value,
                    url=url,
                    tool_name="business_logic_fuzzer",
                    payload=str(form_data)[:200] if form_data else "",
                    reasoning=reasoning,
                    evidence=evidence,
                )
            except Exception as exc:
                logger.error(
                    "business_logic_fuzzer: failed to construct race-condition "
                    "finding for %s %s: %s",
                    method,
                    url,
                    exc,
                )
                finding = None
            if finding is not None:
                new_findings.append(finding)
                logger.warning(
                    "Race condition detected at %s %s (%d/%d succeeded)",
                    method,
                    url,
                    success_count,
                    len(status_codes),
                )

    logger.info("Business Logic Fuzzer: %d findings generated", len(new_findings))

    # V7 Cognitive Upgrade — Phase 2: extract Mental Model updates for
    # the state-changing endpoints this node fuzzed. Pure additive —
    # does not change any existing fuzzer logic. Deterministic
    # regex/heuristic, NO LLM.
    mental_model_update: dict[str, Any] = {"nodes": {}, "edges": []}
    try:
        from webpent.models.mental_model import extract_mental_model_updates

        # `endpoints` is a list[dict[str, Any]] with a "url" key —
        # extract just the URLs for the Mental Model extractor.
        fuzzer_endpoint_urls: list[str] = []
        for ep in endpoints:
            if isinstance(ep, dict):
                u = ep.get("url") or ep.get("endpoint") or ""
                if u:
                    fuzzer_endpoint_urls.append(u)
            elif isinstance(ep, str):
                fuzzer_endpoint_urls.append(ep)
        mental_model_update = extract_mental_model_updates(
            discovery_source="business_logic_fuzzer_node",
            endpoints=fuzzer_endpoint_urls,
            target_url=getattr(target, "url", None),
        )
    except Exception as exc:
        logger.debug("Mental Model extraction (business_logic_fuzzer) failed: %s", exc)

    # POST-P0 Phase 8: bounded stateful-flow replay (skip/reorder
    # differentials) over crawler-recorded multi-step form sequences.
    # Requires an authenticated session (Phase 3 contract) — without
    # session cookies the probes would test the anonymous surface and
    # the state-transition signal would be meaningless, so we skip
    # honestly. Results are advisory observations + hypothesis specs
    # that still route through the normal validation pipeline.
    flow_observations: list[dict[str, Any]] = []
    flow_hypotheses: list[dict[str, Any]] = []
    try:
        forms = crawled_data.get("forms") if isinstance(crawled_data, dict) else None
        if auth_cookies and isinstance(forms, list) and forms:
            flow_observations, flow_hypotheses = _bounded_flow_replay(
                forms, cookies=auth_cookies
            )
            if flow_observations:
                logger.info(
                    "Business Logic Fuzzer: stateful flow replay produced "
                    "%d observation(s) and %d hypothesis candidate(s) "
                    "(bounded, <=3 flows).",
                    len(flow_observations),
                    len(flow_hypotheses),
                )
    except Exception as exc:
        logger.debug("Bounded flow replay failed (non-fatal): %s", exc)

    message = (
        f"Business Logic Fuzzer: fuzzed {len(endpoints)} "
        f"endpoints with {_BURST_SIZE}-request bursts. Found "
        f"{len(new_findings)} race conditions."
    )
    if flow_observations:
        message += (
            f" Stateful flow replay added {len(flow_observations)} "
            f"bounded observation(s) with {len(flow_hypotheses)} "
            f"state-transition hypothesis candidate(s)."
        )
    if workflow_update:
        message += (
            f" Workflow understanding added "
            f"{len(workflow_update.get('workflow_observations', []))} observations "
            f"and {len(workflow_update.get('hypotheses', []))} bounded hypotheses."
        )
    workflow_update = dict(workflow_update or {})
    if flow_observations:
        merged_observations = list(workflow_update.get("workflow_observations") or [])
        merged_observations.extend(flow_observations)
        workflow_update["workflow_observations"] = merged_observations
    _blf_result: dict[str, Any] = {
        **workflow_update,
        # merge_findings reducer dedup by id — safe
        "findings": findings + new_findings,
        "mental_model": mental_model_update,
        "flow_hypotheses": flow_hypotheses,
        "messages": [AIMessage(content=message)],
        "current_phase": "business_logic_fuzzing",
    }
    for _gate_key in ("session_liveness", "session_cookies", "engagement_limitations"):
        if _liveness_gate and _gate_key in _liveness_gate:
            _blf_result[_gate_key] = _liveness_gate[_gate_key]
    return _blf_result
