"""Deterministic, bounded validators for injection and redirect candidates.

These checks are intentionally conservative.  A candidate is only promoted to
``Tool-Confirmed`` when a replay produces a class-specific, reproducible signal
that was absent from the baseline response.  Network failures and ambiguous
responses remain explicit ``Not Scanned``/``Needs Human Review`` outcomes;
``AI-Assessed`` is never used as a substitute for a missing validator here.

All requests go through WebPent's SSRF-pinned HTTP client and never follow
redirects.  Evidence contains response metadata and hashes/markers only; it
never stores Cookie, Authorization, Set-Cookie, or raw response bodies.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, unquote, urlencode, urlparse, urlunparse

from webpent.models.findings import Confidence, Finding
from webpent.shared.target_package_context import package_continuity_kwargs
from webpent.shared.verifier import verify_replay_evidence

logger = logging.getLogger(__name__)

_MAX_BODY_BYTES = 2_000_000
_SAFE_RESPONSE_HEADERS = frozenset(
    {"content-type", "content-length", "location", "server", "x-powered-by"}
)

# RED-TEAM FIX (2026-10): module-level constants for validate_race_condition's
# causal-signal and negative-control thresholds (moved up from local
# UPPER_CASE names inside the function, which ruff N806 correctly flags —
# UPPER_CASE is reserved for module-level constants, not locals). See the
# usage sites below for the full rationale of each threshold.
_MIN_CAUSAL_DIFFERENTIAL = 2
_MAX_NEGATIVE_CONTROL_SUCCESSES = 1


@dataclass(frozen=True)
class Replay:
    method: str
    url: str
    request_body: str | None
    status_code: int
    body: str
    headers: dict[str, str]
    elapsed_ms: int


def _body_digest(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()


def _target_fingerprint(url: str) -> str:
    parsed = urlparse(str(url))
    shape = urlunparse(parsed._replace(query="", fragment=""))
    return f"sha256:{hashlib.sha256(shape.encode('utf-8', 'replace')).hexdigest()}"


def _request_digest(replay: Replay) -> str:
    shape = {
        "method": replay.method,
        # The complete request shape is hashed only; raw query/body values are
        # never persisted. This keeps distinct payload replays independent.
        "url_shape": urlunparse(urlparse(replay.url)._replace(fragment="")),
        "body_sha256": _body_digest(replay.request_body or ""),
    }
    encoded = json.dumps(shape, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"


def _response_digest(replay: Replay) -> str:
    shape = {
        "status_code": replay.status_code,
        "body_sha256": _body_digest(replay.body),
        "headers": _safe_headers(replay.headers),
    }
    encoded = json.dumps(shape, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"


def _safe_headers(headers: dict[str, str]) -> dict[str, str]:
    """Keep harmless response metadata and drop all credential material."""
    return {
        key.lower(): str(value)[:300]
        for key, value in headers.items()
        if key.lower() in _SAFE_RESPONSE_HEADERS
    }


def _redact_query_url(url: str) -> str:
    """Return a stable URL shape without exposing query values."""
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if not params:
        return url
    return urlunparse(
        parsed._replace(query=urlencode([(name, "[REDACTED]") for name, _ in params]))
    )


def _candidate_parameter(finding: Finding) -> str | None:
    if finding.target_param:
        return finding.target_param
    parsed = urlparse(finding.url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if params:
        return params[0][0]
    for name in ("file", "path", "filename", "template", "url", "redirect", "next", "cmd", "query"):
        if name in finding.request_data:
            return name
    if finding.request_data:
        return next(iter(finding.request_data))
    return None


def _build_request(
    finding: Finding, parameter: str, value: str
) -> tuple[str, str, dict[str, str], str | None]:
    """Build a bounded GET/form replay from a Finding's structured context."""
    method = str(finding.request_method or "GET").upper()
    if method not in {"GET", "POST", "PUT", "PATCH"}:
        method = "GET"
    parsed = urlparse(finding.url)
    headers: dict[str, str] = {}
    if method == "GET":
        params = parse_qsl(parsed.query, keep_blank_values=True)
        replaced = False
        new_params: list[tuple[str, str]] = []
        for name, old_value in params:
            if not replaced and name == parameter:
                new_params.append((name, value))
                replaced = True
            else:
                new_params.append((name, old_value))
        if not replaced:
            new_params.append((parameter, value))
        return method, urlunparse(parsed._replace(query=urlencode(new_params))), headers, None

    form = dict(finding.request_data or {})
    content_type = str(form.pop("__webpent_content_type", "")).lower().strip()
    form[parameter] = value
    if content_type == "application/json":
        headers["Content-Type"] = "application/json"
        return method, finding.url, headers, json.dumps(form, separators=(",", ":"))
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    return method, finding.url, headers, urlencode(form, doseq=True)


def _csrf_header_from_cookies(cookies: dict[str, str] | None) -> str | None:
    """Return a decoded Laravel XSRF header value when the session provides it."""
    if not cookies:
        return None
    for name, value in cookies.items():
        if name.lower() == "xsrf-token" and value:
            return unquote(str(value))
    return None


def _replay(
    finding: Finding,
    parameter: str,
    value: str,
    cookies: dict[str, str] | None,
) -> Replay | None:
    method, url, headers, body = _build_request(finding, parameter, value)
    try:
        from webpent.shared.http import build_cookie_header, make_safe_httpx_client

        parsed = urlparse(url)
        headers.update(
            {
                "User-Agent": os.getenv(
                    "HTTP_USER_AGENT",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "Chrome/131.0.0.0 Safari/537.36",
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": os.getenv("HTTP_ACCEPT_LANGUAGE", "en-US,en;q=0.9"),
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Referer": f"{parsed.scheme}://{parsed.netloc}/",
            }
        )
        if cookies:
            headers["Cookie"] = build_cookie_header(cookies)
            csrf_token = _csrf_header_from_cookies(cookies)
            if csrf_token and method in {"POST", "PUT", "PATCH"}:
                # Laravel validates the token from the session cookie against
                # this header.  Never log or persist the token; it stays only
                # in the outbound request header.
                headers["X-XSRF-TOKEN"] = csrf_token
        started = time.monotonic()
        with make_safe_httpx_client(timeout=10.0, follow_redirects=False, verify=True) as client:
            if method == "GET":
                response = client.get(url, headers=headers)
            else:
                response = client.request(method, url, headers=headers, content=body)
        raw_body = response.content[:_MAX_BODY_BYTES]
        decoded = raw_body.decode(response.encoding or "utf-8", "replace")
        return Replay(
            method=method,
            url=url,
            request_body=body,
            status_code=response.status_code,
            body=decoded,
            headers=dict(response.headers),
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    except Exception as exc:
        logger.debug("active validator replay failed for %s: %s", finding.id, type(exc).__name__)
        return None


def _evidence(
    baseline: Replay | None,
    probe: Replay | None,
    *,
    control: Replay | None = None,
    validator: str,
    parameter: str | None,
    payload_label: str,
    matched_marker: str | None = None,
) -> dict[str, Any]:
    """Create evidence without raw bodies, cookies, auth headers, or OOB URLs."""
    result: dict[str, Any] = {
        "validator": validator,
        "parameter": parameter,
        "payload_label": payload_label,
        "matched_marker": matched_marker,
        "replay": "baseline_then_candidate_then_negative_control",
    }

    def _observation(replay: Replay, role: str) -> dict[str, Any]:
        return {
            "target_backed": True,
            "observation_role": role,
            "target_fingerprint": _target_fingerprint(replay.url),
            "request_digest": _request_digest(replay),
            "response_digest": _response_digest(replay),
            "method": replay.method,
            "url": _redact_query_url(replay.url),
            "status_code": replay.status_code,
            "body_length": len(replay.body),
            "body_sha256": _body_digest(replay.body),
            "headers": _safe_headers(replay.headers),
            "elapsed_ms": replay.elapsed_ms,
        }

    if baseline is not None:
        result["baseline"] = _observation(baseline, "baseline")
    if probe is not None:
        result["candidate"] = _observation(probe, "candidate")
    if control is not None:
        result["negative_control"] = _observation(control, "negative_control")
    return result


def _confirmed(
    finding: Finding,
    evidence: dict[str, Any],
    reasoning: str,
    payload_label: str,
    *,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    merged_evidence = {**(finding.evidence or {}), **evidence}
    if not (
        bool(merged_evidence.get("causal_signal"))
        and bool(merged_evidence.get("negative_control_complete"))
    ):
        merged_evidence["promotion_guard"] = {
            "status": "blocked",
            "reason": "causal_signal_and_negative_control_required",
        }
        return finding.model_copy(
            update={
                "confidence_level": "Needs Human Review",
                "evidence": merged_evidence,
                "reasoning": (
                    f"{reasoning} Automated promotion was blocked because the replay "
                    "did not provide both causal signal and a completed negative control."
                ),
            }
        )

    baseline = merged_evidence.get("baseline")
    candidate = merged_evidence.get("candidate")
    negative_control = merged_evidence.get("negative_control")
    # UM-DR-35 §1.3 condition 8 — the class-specific validator's technical
    # signal is a RECORDED FACT of this experiment: this boundary is
    # reached only by a class validator that matched its class marker in
    # the actual candidate replay body (evidence["causal_signal"] is that
    # recorded match — never a bare caller assertion), with its
    # independent negative control already verified to not reproduce the
    # marker (negative_control_complete gate above). The signal is
    # stamped on the candidate observation (its role ONLY) so the
    # CausalGuard authority adjudicates the full experiment evidence:
    # the guard still demands the recorded semantic differential vs the
    # baseline, an independent control, and complete observations; a
    # non-CONFIRMED verdict blocks (fail-closed). A marker without a real
    # differential cannot confirm; a differential without the class signal
    # stays INCONCLUSIVE.
    if (
        bool(merged_evidence.get("causal_signal"))
        and isinstance(candidate, dict)
        and "validator_technical_signal" not in candidate
    ):
        candidate = {
            **candidate,
            "validator_technical_signal": True,
            "class_validator_id": str(
                merged_evidence.get("validator") or "active_validator"
            ),
        }
        merged_evidence["candidate"] = candidate
    context = verification_context or {}
    verification = verify_replay_evidence(
        finding,
        baseline=baseline if isinstance(baseline, dict) else None,
        candidate=candidate if isinstance(candidate, dict) else None,
        negative_control=negative_control,
        causal_signal=bool(merged_evidence.get("causal_signal")),
        negative_control_complete=bool(merged_evidence.get("negative_control_complete")),
        validator_id=str(merged_evidence.get("validator") or "active_validator"),
        validator_version="active-replay.v1",
        causal_basis=str(
            merged_evidence.get("causal_basis")
            or merged_evidence.get("matched_marker")
            or "class_specific_baseline_candidate_differential"
        ),
        engagement_id=str(context.get("engagement_id") or ""),
        hypothesis_id=str(context["hypothesis_id"]) if context.get("hypothesis_id") else None,
        scope_context=context.get("scope_context"),
        identity_context=context.get("identity_context"),
        replay_metadata={
            "payload_label": payload_label,
            "target_backed": True,
            "negative_control": "independent_control_replay",
        },
        require_target_backed=True,
        **package_continuity_kwargs(context),
    )
    merged_evidence.update(verification.evidence)
    if not verification.passed or verification.proof_bundle is None:
        return finding.model_copy(
            update={
                "confidence_level": "Needs Human Review",
                "evidence": merged_evidence,
                "reasoning": (
                    f"{reasoning} Automated promotion was blocked by the strict verifier: "
                    f"{verification.reason}."
                ),
            }
        )

    return finding.model_copy(
        update={
            "confidence": Confidence.CONFIRMED.value,
            "confidence_level": "Tool-Confirmed",
            "payload": payload_label,
            "evidence": merged_evidence,
            "evidence_bundle": {
                "request": {
                    "method": evidence.get("candidate", {}).get("method"),
                    "url": evidence.get("candidate", {}).get("url"),
                    "headers": evidence.get("candidate", {}).get("headers", {}),
                    "body": "[REDACTED-FORM-BODY]"
                    if evidence.get("candidate", {}).get("method") != "GET"
                    else None,
                },
                "response": evidence.get("candidate", {}),
            },
            "reasoning": reasoning,
        }
    )


def _ambiguous(
    finding: Finding,
    evidence: dict[str, Any],
    reasoning: str,
    *,
    not_scanned: bool = False,
) -> Finding:
    merged_evidence = {**(finding.evidence or {}), **evidence}
    # A deterministic validator that cannot build the replay (missing
    # parameter context or failed transport) is an infrastructure/coverage
    # limitation, not an AI assessment. Preserve the v58 evidence contract
    # so reports and downstream retry logic can distinguish it from a clean
    # negative replay.
    if not_scanned or evidence.get("validation_unavailable"):
        merged_evidence.setdefault("tool_infra_failure", True)
    if evidence.get("validation_unavailable"):
        merged_evidence.setdefault("missing_validator_class", evidence.get("validator"))
    if (
        evidence.get("validation_unavailable") or not_scanned
    ) and "not confirmation" not in reasoning.lower():
        reasoning = (
            f"{reasoning} This is not confirmation; it is a validation "
            "coverage or infrastructure limitation."
        )
    return finding.model_copy(
        update={
            "confidence_level": "Not Scanned" if not_scanned else "Needs Human Review",
            "evidence": merged_evidence,
            "reasoning": reasoning,
        }
    )


def _inband_marker_check(
    finding: Finding,
    vuln_class: str,
    payload: str,
    markers: tuple[str, ...],
    cookies: dict[str, str] | None,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    parameter = _candidate_parameter(finding)
    if not parameter:
        return _ambiguous(
            finding,
            {
                "validator": vuln_class,
                "validation_unavailable": True,
                "reason": "no_parameter_context",
            },
            f"{vuln_class.upper()} validator could not run: no target parameter was available.",
        )
    baseline_value = str(finding.request_data.get(parameter, ""))
    baseline = _replay(finding, parameter, baseline_value, cookies)
    probe = _replay(finding, parameter, payload, cookies)
    control_value = f"{baseline_value}-webpent-negative-control"
    control = _replay(finding, parameter, control_value, cookies)
    if baseline is None or probe is None or control is None:
        return _ambiguous(
            finding,
            _evidence(
                baseline,
                probe,
                control=control,
                validator=vuln_class,
                parameter=parameter,
                payload_label=payload,
            ),
            f"{vuln_class.upper()} validator could not complete the three replays "
            "(baseline, candidate, negative control).",
            not_scanned=True,
        )
    lowered = probe.body.lower()
    baseline_lowered = baseline.body.lower()
    control_lowered = control.body.lower()
    marker = next(
        (
            item
            for item in markers
            if item.lower() in lowered and item.lower() not in baseline_lowered
        ),
        None,
    )
    evidence = _evidence(
        baseline,
        probe,
        control=control,
        validator=vuln_class,
        parameter=parameter,
        payload_label=payload,
        matched_marker=marker,
    )
    evidence["causal_signal"] = bool(marker)
    evidence["negative_control_complete"] = bool(
        marker and marker.lower() not in control_lowered
    )
    if marker:
        return _confirmed(
            finding,
            evidence,
            f"{vuln_class.upper()} replay produced marker {marker!r} only after the controlled "
            "payload was injected; the baseline did not contain that marker.",
            payload,
            verification_context=verification_context,
        )
    return _ambiguous(
        finding,
        evidence,
        f"{vuln_class.upper()} replay completed but did not produce a class-specific marker "
        "absent from both baseline and negative control. No automated confirmation is claimed.",
    )


def _normalise_race_observation(
    value: Any,
    *,
    role: str,
) -> dict[str, Any] | None:
    """Keep only redacted transport metadata for a race replay observation."""
    if not isinstance(value, dict):
        return None
    allowed = {
        "target_backed",
        "observation_role",
        "target_fingerprint",
        "request_digest",
        "response_digest",
        "method",
        "url",
        "status_code",
        "body_length",
        "body_sha256",
        "headers",
        "elapsed_ms",
    }
    observation = {key: value[key] for key in allowed if key in value}
    observation["observation_role"] = role
    if isinstance(observation.get("url"), str):
        observation["url"] = _redact_query_url(observation["url"])
    if isinstance(observation.get("headers"), dict):
        observation["headers"] = _safe_headers(observation["headers"])
    return observation


def validate_race_condition(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    """Validate a bounded race replay without issuing requests in this stage.

    The business-logic fuzzer may produce a candidate burst summary, but only a
    separate authorized replay producer can populate ``race_replay`` with
    baseline, candidate, and independent negative-control observations. This
    function therefore never treats a burst count alone as confirmation.
    """
    del cookies
    evidence = dict(finding.evidence or {})
    replay = evidence.get("race_replay")
    if not isinstance(replay, dict):
        return _ambiguous(
            finding,
            {
                "validator": "race_condition",
                "validation_unavailable": True,
                "validation_failure_reason": "race_replay_required",
            },
            "Race-condition candidate has no bounded baseline/candidate/negative-control "
            "replay. A burst count alone is not confirmation.",
        )

    baseline = _normalise_race_observation(replay.get("baseline"), role="baseline")
    candidate = _normalise_race_observation(replay.get("candidate"), role="candidate")
    negative_control = _normalise_race_observation(
        replay.get("negative_control"), role="negative_control"
    )
    try:
        baseline_successes = int(replay["baseline_successes"])
        candidate_successes = int(replay["candidate_successes"])
        negative_successes = int(replay["negative_control_successes"])
        burst_size = int(replay["burst_size"])
    except (KeyError, TypeError, ValueError):
        return _ambiguous(
            finding,
            {
                "validator": "race_condition",
                "validation_unavailable": True,
                "validation_failure_reason": "race_metrics_incomplete",
            },
            "Race-condition replay metrics are incomplete or non-numeric; "
            "no automated confirmation is claimed.",
        )

    metrics_valid = (
        0 <= baseline_successes <= burst_size
        and 0 <= candidate_successes <= burst_size
        and 0 <= negative_successes <= burst_size
        and burst_size > 1
    )
    independent_control = replay.get("independent_control") is True
    # RED-TEAM FIX (2026-10): a bare `candidate_successes > baseline_successes`
    # (any positive difference, even exactly 1) is too sensitive to ordinary
    # network noise — one stray timeout during the slower sequential baseline
    # is enough to manufacture a "causal signal" for a finding that gets
    # promoted straight to Tool-Confirmed. Require a differential of at
    # least 2 successes (see _MIN_CAUSAL_DIFFERENTIAL above): a genuine
    # TOCTOU gap under a full concurrent burst normally produces more than
    # one extra success, not exactly one.
    causal_signal = bool(
        metrics_valid
        and (candidate_successes - baseline_successes) >= _MIN_CAUSAL_DIFFERENTIAL
    )
    # RED-TEAM FIX (2026-10): the previous condition compared
    # `negative_successes` (TRACE, sent CONCURRENTLY) against
    # `baseline_successes` (the real method, sent SEQUENTIALLY) — two
    # quantities with no direct logical relationship. In the common real
    # case, TRACE is rejected outright by the transport/framework layer
    # regardless of any race (negative_successes == 0), which made this
    # condition trivially true almost always (0 <= baseline_successes holds
    # whenever metrics_valid does), so it added no real independent
    # protection beyond causal_signal. The negative control should answer
    # "does the burst mechanism itself produce multiple spurious successes
    # for a verb the target was never built to treat as state-changing?" —
    # that is a property of negative_successes ALONE, not a comparison to
    # an unrelated baseline. Require it to be small in absolute terms (see
    # _MAX_NEGATIVE_CONTROL_SUCCESSES above).
    negative_control_complete = bool(
        metrics_valid
        and independent_control
        and negative_successes <= _MAX_NEGATIVE_CONTROL_SUCCESSES
    )
    replay_evidence = {
        "validator": "race_condition",
        "baseline": baseline,
        "candidate": candidate,
        "negative_control": negative_control,
        "race_metrics": {
            "baseline_successes": baseline_successes,
            "candidate_successes": candidate_successes,
            "negative_control_successes": negative_successes,
            "burst_size": burst_size,
        },
        "causal_signal": causal_signal,
        "negative_control_complete": negative_control_complete,
        "negative_control_independent": independent_control,
    }
    if baseline is None or candidate is None or negative_control is None:
        replay_evidence.update(
            {
                "validation_unavailable": True,
                "validation_failure_reason": "race_observations_incomplete",
            }
        )
        return _ambiguous(
            finding,
            replay_evidence,
            "Race-condition replay is missing one or more redacted target observations; "
            "no automated confirmation is claimed.",
            not_scanned=True,
        )

    if causal_signal and negative_control_complete:
        return _confirmed(
            finding,
            replay_evidence,
            "Bounded race replay produced more successful candidate operations than the "
            "baseline while the independent negative control did not reproduce the signal.",
            "bounded_concurrent_replay",
            verification_context=verification_context,
        )
    replay_evidence["promotion_guard"] = {
        "status": "blocked",
        "reason": "causal_signal_and_negative_control_required",
    }
    return _ambiguous(
        finding,
        replay_evidence,
        "Race replay completed without both a causal success differential and an "
        "independent negative control. No automated confirmation is claimed.",
    )


def validate_lfi(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    return _inband_marker_check(
        finding,
        "lfi",
        "/etc/passwd",
        ("root:x:0:0", "root:x:"),
        cookies,
        verification_context,
    )


def validate_path_traversal(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    return _inband_marker_check(
        finding,
        "path_traversal",
        "../../../../../../etc/passwd",
        ("root:x:0:0", "root:x:"),
        cookies,
        verification_context,
    )


def validate_ssti(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    """Confirm server-side expression evaluation with a baseline differential."""
    parameter = _candidate_parameter(finding)
    if not parameter:
        return _ambiguous(
            finding,
            {"validator": "ssti", "validation_unavailable": True, "reason": "no_parameter_context"},
            "SSTI validator could not run: no template-like parameter was available.",
        )
    # The expression is deliberately harmless and does not execute a command.
    payload = "{{17*23}}"
    baseline_value = str(finding.request_data.get(parameter, ""))
    baseline = _replay(finding, parameter, baseline_value, cookies)
    probe = _replay(finding, parameter, payload, cookies)
    control = _replay(
        finding,
        parameter,
        f"{baseline_value}-webpent-negative-control",
        cookies,
    )
    evidence = _evidence(
        baseline,
        probe,
        control=control,
        validator="ssti",
        parameter=parameter,
        payload_label="arithmetic_expression",
        matched_marker="391",
    )
    if baseline is None or probe is None or control is None:
        return _ambiguous(
            finding,
            evidence,
            "SSTI validator could not complete baseline/candidate/negative-control replays.",
            not_scanned=True,
        )
    evidence["causal_signal"] = "391" in probe.body and "391" not in baseline.body
    evidence["negative_control_complete"] = "391" not in control.body
    if "391" in probe.body and "391" not in baseline.body and "391" not in control.body:
        return _confirmed(
            finding,
            evidence,
            "SSTI replay evaluated a harmless arithmetic expression to 391; the "
            "baseline did not contain 391.",
            payload,
            verification_context=verification_context,
        )
    return _ambiguous(
        finding,
        evidence,
        "SSTI replay completed without a new arithmetic-evaluation marker. "
        "No automated confirmation is claimed.",
    )


def validate_nosql_injection(
    finding: Finding,
    cookies: dict[str, str] | None = None,
    verification_context: dict[str, Any] | None = None,
) -> Finding:
    """Use a bounded type-confusion differential; never dump or enumerate data."""
    parameter = _candidate_parameter(finding)
    if not parameter:
        return _ambiguous(
            finding,
            {
                "validator": "nosql_injection",
                "validation_unavailable": True,
                "reason": "no_parameter_context",
            },
            "NoSQL injection validator could not run: no query-like parameter was available.",
        )
    baseline_value = str(finding.request_data.get(parameter, "invalid-webpent-value"))
    baseline = _replay(finding, parameter, baseline_value, cookies)
    candidate = json.dumps({"$ne": None}, separators=(",", ":"))
    probe = _replay(finding, parameter, candidate, cookies)
    control_value = "invalid-webpent-negative-control"
    control = _replay(finding, parameter, control_value, cookies)
    evidence = _evidence(
        baseline,
        probe,
        control=control,
        validator="nosql_injection",
        parameter=parameter,
        payload_label="json_operator_ne_null",
    )
    if baseline is None or probe is None or control is None:
        return _ambiguous(
            finding,
            evidence,
            "NoSQL validator could not complete baseline/candidate/negative-control replays.",
            not_scanned=True,
        )
    auth_boundary = baseline.status_code in {401, 403} and 200 <= probe.status_code < 300
    materially_changed = abs(len(probe.body) - len(baseline.body)) >= max(
        32, int(len(baseline.body) * 0.10)
    )
    evidence["causal_signal"] = bool(auth_boundary and materially_changed)
    evidence["negative_control_complete"] = bool(control.status_code in {401, 403})
    if auth_boundary and materially_changed and control.status_code in {401, 403}:
        evidence["differential"] = "unauthorized_baseline_to_success_candidate"
        return _confirmed(
            finding,
            evidence,
            "NoSQL type-confusion replay changed an unauthorized baseline (401/403) "
            "to a materially different 2xx response. This is a bounded authorization "
            "differential; no data enumeration was performed.",
            candidate,
            verification_context=verification_context,
        )
    evidence["differential"] = "no_confirming_authorization_boundary"
    return _ambiguous(
        finding,
        evidence,
        "NoSQL replay completed without a strong unauthorized-to-success differential. "
        "No automated confirmation is claimed.",
    )


__all__ = [
    "validate_lfi",
    "validate_nosql_injection",
    "validate_path_traversal",
    "validate_race_condition",
    "validate_ssti",
]
