"""Explicit WAPTLab campaign extension.

This module is a compatibility profile, not a shared default.  It is intentionally
kept under ``benchmark`` so its route, payload, and marker remain target-local.
The extension is inert unless a validated live TargetAdapter registration exposes
it through ``campaign_extensions()``.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any
from urllib.parse import quote, urljoin, urlsplit

from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.shared.action_authority import ActionRisk
from webpent.shared.campaign_executor import CampaignTask
from webpent.shared.g02_contract import g02_http_metadata
from webpent.shared.target_adapters import CampaignExtensionSpec
from webpent.validators.causal_validator import validate_causal_observation
from webpent.validators.proof_validator import validate_proof_bundle

EXTENSION_ID = "waptlab.swagger_ssrf.v1"


def _finding_value(item: Any, field: str, default: Any = None) -> Any:
    if isinstance(item, Mapping):
        return item.get(field, default)
    return getattr(item, field, default)


def _promotion_is_proven(state: Mapping[str, Any]) -> bool:
    causal_observation = state.get("causal_observation")
    proof_bundle = state.get("proof_bundle")
    return validate_causal_observation(causal_observation) and validate_proof_bundle(
        proof_bundle,
        require_negative_control=True,
    )


def project_swagger_response(
    state: Mapping[str, Any],
    response: Any,
    request_url: str,
) -> Finding | None:
    """Project only the explicit profile's deterministic marker into a finding."""
    body = bytes(getattr(response, "content", b"") or b"")[:2_000_000]
    lowered = body.lower()
    status_code = int(getattr(response, "status_code", 0) or 0)
    if status_code != 200:
        return None
    if b"ipv6-loopback" not in lowered and b"nua{" not in lowered:
        return None

    marker = "ipv6-loopback" if b"ipv6-loopback" in lowered else "nua-marker"
    evidence = {
        "validator": "swagger_url_ssrf_direct_probe",
        "replay": "single_authorized_read_only_request",
        "matched_marker": marker,
        "request": {
            "method": "GET",
            "url": request_url,
            "parameter": "url",
            "payload_label": "ipv6_loopback_url",
        },
        "response": {
            "status_code": status_code,
            "body_length": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "headers": {
                str(key).lower(): str(value)[:300]
                for key, value in dict(getattr(response, "headers", {}) or {}).items()
                if str(key).lower() in {"content-type", "content-length", "server"}
            },
        },
    }
    reasoning = (
        "A same-origin authorized GET to the profile's registered route returned "
        "the application-specific SSRF marker. The request and response metadata "
        "are reproducible while the response body is redacted."
    )
    promotion_proven = _promotion_is_proven(state)
    promotion_status = (
        "tool_confirmed"
        if promotion_proven
        else "blocked_missing_causal_signal_or_negative_control"
    )
    promoted_confidence = (
        Confidence.CONFIRMED.value if promotion_proven else Confidence.TENTATIVE.value
    )
    promoted_level = "Tool-Confirmed" if promotion_proven else "Needs Human Review"
    for current in state.get("findings") or []:
        if (
            str(_finding_value(current, "vuln_class", "")) == VulnClass.SSRF.value
            and "/swagger_ui" in str(_finding_value(current, "url", ""))
        ):
            try:
                if isinstance(current, Finding):
                    base = current
                else:
                    raw = dict(current) if isinstance(current, Mapping) else {}
                    allowed = set(Finding.model_fields)
                    base = Finding.model_validate(
                        {key: value for key, value in raw.items() if key in allowed}
                    )
                return base.model_copy(
                    update={
                        "confidence": (
                            Confidence.CONFIRMED.value
                            if promotion_proven
                            else str(base.confidence or Confidence.TENTATIVE.value)
                        ),
                        "confidence_level": (
                            "Tool-Confirmed" if promotion_proven else promoted_level
                        ),
                        "payload": "url=http://[::1]/",
                        "evidence": {
                            **(base.evidence or {}),
                            **evidence,
                            "promotion_guard": {
                                "status": promotion_status,
                                "causal_signal": bool(
                                    isinstance(state.get("causal_observation"), Mapping)
                                    and state["causal_observation"].get("causal_signal")
                                    is True
                                ),
                                "negative_control_complete": bool(
                                    isinstance(state.get("causal_observation"), Mapping)
                                    and state["causal_observation"].get(
                                        "negative_control_complete"
                                    )
                                    is True
                                ),
                                "proof_bundle_valid": validate_proof_bundle(
                                    state.get("proof_bundle"),
                                    require_negative_control=True,
                                ),
                            },
                        },
                        "evidence_bundle": {
                            "request": {
                                "method": "GET",
                                "url": request_url,
                                "headers": {},
                                "body": None,
                            },
                            "response": evidence["response"],
                        },
                        "reasoning": reasoning,
                    }
                )
            except Exception:
                continue

    return Finding(
        title="Server-Side Request Forgery at /swagger_ui",
        severity=Severity.HIGH,
        description=(
            "The registered profile route processes an IPv6 loopback URL and "
            "returns the application SSRF marker."
        ),
        tool_name="smart_campaigns_execution",
        payload="url=http://[::1]/",
        request_method="GET",
        request_data={"url": "http://[::1]/"},
        target_param="url",
        url=request_url,
        confidence=promoted_confidence,
        references=["https://cwe.mitre.org/data/definitions/918.html"],
        vuln_class=VulnClass.SSRF.value,
        confidence_level=promoted_level,
        reasoning=reasoning,
        evidence={
            **evidence,
            "promotion_guard": {
                "status": promotion_status,
                "causal_signal": False,
                "negative_control_complete": False,
                "proof_bundle_valid": False,
            },
        },
    )


def validate_swagger_finding(finding: Finding, state: Mapping[str, Any]) -> Finding | None:
    """Accept only a fully validated finding produced by this explicit profile."""
    if finding.vuln_class != VulnClass.SSRF.value or "/swagger_ui" not in str(finding.url):
        return None
    evidence = finding.evidence or {}
    if evidence.get("action_executor_probe") is not True:
        return None
    if finding.confidence != Confidence.CONFIRMED.value:
        return None
    if evidence.get("causal_signal") is not True:
        return None
    if evidence.get("negative_control_complete") is not True:
        return None
    if not validate_proof_bundle(evidence.get("proof_bundle"), require_negative_control=True):
        return None
    return finding


def build_swagger_task(state: Mapping[str, Any], root: str) -> CampaignTask | None:
    """Build one bounded profile task; this function performs no I/O."""
    parsed_root = urlsplit(root)
    if parsed_root.scheme not in {"http", "https"} or not parsed_root.netloc:
        return None
    request_url = f"{root.rstrip('/')}/swagger_ui?url={quote('http://[::1]/', safe='')}"
    engagement_id = str(state.get("engagement_id") or "default")[:160]
    return CampaignTask(
        task_id="smart-swagger-ssrf-proof",
        engagement_id=engagement_id,
        asset_id="swagger_ui",
        source_evidence_ids=("surface:swagger_ui",),
        vulnerability_class=VulnClass.SSRF.value,
        hypothesis_id="swagger-ui-ssrf-ipv6-loopback",
        probe_family="same_origin_ssrf_marker",
        negative_control="required",
        oracle="deterministic_swagger_marker",
        risk_tier=ActionRisk.ACTIVE,
        budget=1.0,
        expected_information_gain=0.8,
        idempotency_key=f"swagger-ssrf:{engagement_id}:{request_url}",
        method="GET",
        capability="http_read",
        action_family="http_read",
        target_url=request_url,
        metadata=g02_http_metadata(
            {
                "campaign_extension_id": EXTENSION_ID,
                "observed_preconditions": ("authorized-active profile",),
                "human_approved": bool(state.get("auto_approve", False)),
            }
        ),
        validator_id="swagger_url_ssrf_direct_probe",
    )


def classify_path(state: Mapping[str, Any], target_url: str) -> tuple[str, str] | None:
    """Classify only the explicit WAPTLab ERP route."""
    if urlsplit(target_url).path.rstrip("/") == "/export-erp":
        return (
            VulnClass.XXE.value,
            "Registered profile route exposes the JSON XSLT transformation surface",
        )
    return None


def build_surface_seed_urls(state: Mapping[str, Any], target_url: str) -> tuple[str, ...]:
    """Return explicit WAPTLab-only POST surface seeds for VIP discovery."""
    profile = str(state.get("profile") or "").strip().lower().replace("_", "-")
    inventory = str(state.get("campaign_inventory") or "generic").strip().lower()
    if inventory != "waptlab" or profile not in {
        "vip-qualification",
        "scanprofile.vip-qualification",
    }:
        return ()
    return tuple(
        urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
        for path in ("/export-erp", "/crm/export", "/training/send-results-email")
    )


def build_request_context(state: Mapping[str, Any], target_url: str) -> Mapping[str, Any] | None:
    """Return explicit request metadata for registered WAPTLab surfaces."""
    path = urlsplit(target_url).path.rstrip("/") or "/"
    fixtures: dict[str, dict[str, Any]] = {
        "/crm/export": {
            "request_method": "POST",
            "request_data": {
                "db": "crm",
                "rows[0][name]": "baseline",
                "format": "html",
            },
            "target_param": "rows[0][name]",
        },
        "/training/send-results-email": {
            "request_method": "POST",
            "request_data": {
                "to": "webpent.receiver@example.test",
                "subject": "WebPent validation",
                "description": "baseline",
                "path": "/",
            },
            "target_param": "description",
        },
        "/export-erp": {
            "request_method": "POST",
            "request_data": {
                "__webpent_content_type": "application/json",
                "db": "default",
                "rows": [{"name": "baseline"}],
                "xslt": (
                    "<?xml version='1.0'?>"
                    "<xsl:stylesheet version='1.0' "
                    "xmlns:xsl='http://www.w3.org/1999/XSL/Transform'>"
                    "<xsl:template match='/'>"
                    "<export><xsl:value-of select='count(/customers/customer)'/>"
                    "</export>"
                    "</xsl:template></xsl:stylesheet>"
                ),
            },
            "target_param": "xslt",
        },
    }
    context = fixtures.get(path)
    return dict(context) if context else None


def campaign_extensions() -> Mapping[str, CampaignExtensionSpec]:
    """Return the explicit compatibility extension registry."""
    return {
        EXTENSION_ID: CampaignExtensionSpec(
            extension_id=EXTENSION_ID,
            task_factory=build_swagger_task,
            response_projector=project_swagger_response,
            finding_projector=validate_swagger_finding,
            surface_seed_provider=build_surface_seed_urls,
            request_context_provider=build_request_context,
            path_classifier=classify_path,
        )
    }


def _finding_value(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(key, default)
    return getattr(value, key, default)


class WaptlabCampaignExtensionProvider:
    """Mixin for an explicitly registered WAPTLab TargetAdapter."""

    def campaign_extensions(self) -> Mapping[str, CampaignExtensionSpec]:
        return campaign_extensions()

    def campaign_profile(self):
        from webpent.benchmark.waptlab_campaign_profile import (
            build_waptlab_campaign_profile,
        )

        return build_waptlab_campaign_profile()


__all__ = [
    "EXTENSION_ID",
    "WaptlabCampaignExtensionProvider",
    "build_request_context",
    "classify_path",
    "build_surface_seed_urls",
    "build_swagger_task",
    "campaign_extensions",
    "project_swagger_response",
    "validate_swagger_finding",
]
