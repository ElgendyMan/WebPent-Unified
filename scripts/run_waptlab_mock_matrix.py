"""Run a loopback-only WAPTLab coverage matrix against the WebPent mock fixture.

The fixture is not WAPTLab and this report must never be presented as live WAPTLab
validation.  It measures detector and proof-loop coverage using the real Finding
model and validators while Docker networking is unavailable.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from webpent.agents.validator import active_checks, structural_checks
from webpent.agents.validator.agent import _validate_open_redirect
from webpent.models.findings import Confidence, Finding, Severity, VulnClass
from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.shared.http import make_safe_httpx_client

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "docs" / "waptlab_mock_matrix.json"


def _finding(
    url: str,
    vuln_class: str,
    *,
    method: str = "GET",
    data: dict[str, str] | None = None,
    target_param: str | None = None,
) -> Finding:
    return Finding(
        title=f"Mock coverage: {vuln_class} at {url}",
        severity=Severity.MEDIUM,
        description="Loopback-only detector coverage fixture; not live WAPTLab evidence.",
        tool_name="waptlab_mock_matrix",
        url=url,
        request_method=method,
        request_data=data or {},
        target_param=target_param,
        vuln_class=vuln_class,
    )


def _validated(label: str, finding: Finding, validator: Any) -> dict[str, Any]:
    result = validator(finding)
    return {
        "label": label,
        "status": "tool-confirmed"
        if result.confidence_level == "Tool-Confirmed"
        else "candidate-or-review",
        "confidence_level": result.confidence_level,
        "confidence": str(result.confidence),
        "reasoning": result.reasoning,
        "evidence_keys": sorted((result.evidence or {}).keys()),
        "url": result.url,
    }


def _raw_probe(
    label: str,
    url: str,
    *,
    method: str = "GET",
    data: str | None = None,
    headers: dict[str, str] | None = None,
    confirmed: bool = False,
    reasoning: str = "",
) -> dict[str, Any]:
    try:
        with make_safe_httpx_client(timeout=5.0, follow_redirects=False, verify=True) as client:
            if method == "POST":
                response = client.post(url, content=data or "", headers=headers or {})
            else:
                response = client.get(url, headers=headers or {})
        body = response.text[:2_000_000]
        return {
            "label": label,
            "status": "tool-confirmed" if confirmed else "candidate-or-review",
            "confidence_level": "Tool-Confirmed" if confirmed else "Needs Human Review",
            "confidence": Confidence.CONFIRMED.value if confirmed else Confidence.TENTATIVE.value,
            "http_status": response.status_code,
            "body_markers": [
                marker
                for marker in (
                    "MOCK_SQLI_HEADER_MARKER",
                    "MOCK_SQLI_CSV_MARKER",
                    "MOCK_SSRF_MARKER",
                    "MOCK_ES_TRAVERSAL_MARKER",
                    "MOCK_XML_SINK_MARKER",
                    "root:x:0:0",
                    "391",
                    "APP_DEBUG=true",
                    "markdown-editor 0.3.0",
                )
                if marker.lower() in body.lower()
            ],
            "response_headers": {
                key.lower(): str(value)[:200]
                for key, value in response.headers.items()
                if key.lower() in {"content-type", "location", "server"}
            },
            "reasoning": reasoning,
            "url": url,
        }
    except Exception as exc:
        return {
            "label": label,
            "status": "not-scanned",
            "confidence_level": "Not Scanned",
            "confidence": Confidence.TENTATIVE.value,
            "error_type": type(exc).__name__,
            "reasoning": f"Loopback probe failed: {type(exc).__name__}.",
            "url": url,
        }


def _run_matrix_unscoped(base_url: str) -> dict[str, Any]:
    base = base_url.rstrip("/")
    results: list[dict[str, Any]] = []
    results.append(
        _raw_probe(
            "header_sqli",
            f"{base}/sqli/header",
            headers={"X-Forwarded-For": "127.0.0.1' OR '1'='1"},
            reasoning=(
                "Controlled header differential produced the fixture marker; "
                "no SQL engine confirmation was claimed."
            ),
        )
    )
    results.append(
        _raw_probe(
            "csv_ingestion_sqli",
            f"{base}/csv",
            method="POST",
            data="name\n1' UNION SELECT NULL--\n",
            headers={"Content-Type": "text/csv"},
            reasoning=(
                "Controlled CSV payload produced the fixture marker; sqlmap was unavailable, "
                "so this remains review-only."
            ),
        )
    )
    results.append(
        _validated(
            "jwt_path_traversal",
            _finding(
                f"{base}/crm/view?path=safe",
                VulnClass.PATH_TRAVERSAL.value,
                target_param="path",
            ),
            active_checks.validate_path_traversal,
        )
    )
    redirect_url = f"{base}/oauth/authorize?redirect_uri=//evil.example/return"
    results.append(
        _validated(
            "double_slash_redirect",
            _finding(
                redirect_url,
                VulnClass.OPEN_REDIRECT.value,
                target_param="redirect_uri",
            ),
            _validate_open_redirect,
        )
    )
    results.append(
        _validated(
            "oauth_redirect_uri",
            _finding(
                redirect_url,
                VulnClass.OPEN_REDIRECT.value,
                target_param="redirect_uri",
            ),
            _validate_open_redirect,
        )
    )
    results.append(
        _validated(
            "download_idor",
            _finding(f"{base}/crm/download/1", VulnClass.IDOR.value),
            structural_checks.validate_idor,
        )
    )
    results.append(
        _validated(
            "tenant_context_switching",
            _finding(f"{base}/dashboard/view-crm/1", VulnClass.IDOR.value),
            structural_checks.validate_idor,
        )
    )
    results.append(
        _validated(
            "training_email_ssti",
            _finding(
                f"{base}/training/send-results-email",
                VulnClass.SSTI.value,
                method="POST",
                data={"template": "safe"},
                target_param="template",
            ),
            active_checks.validate_ssti,
        )
    )
    results.append(
        _validated(
            "export_blade_ssti",
            _finding(
                f"{base}/crm/export",
                VulnClass.SSTI.value,
                method="POST",
                data={"template": "safe"},
                target_param="template",
            ),
            active_checks.validate_ssti,
        )
    )
    results.append(
        _raw_probe(
            "swagger_url_ssrf",
            f"{base}/swagger_ui?url={base}/internal",
            reasoning=(
                "Fixture returned a fetched internal preview, but no OOB callback was available; "
                "review-only."
            ),
        )
    )
    results.append(
        _raw_probe(
            "image_fetch_ssrf",
            f"{base}/profile/fetch-image",
            method="POST",
            data="image_url=http%3A%2F%2F127.0.0.1%3A18083%2Finternal",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            reasoning=(
                "Fixture returned the supplied image URL and SSRF marker, but no OOB callback "
                "was available; review-only."
            ),
        )
    )
    results.append(
        _raw_probe(
            "stored_profile_xss",
            f"{base}/profile",
            method="POST",
            data="name=%3Cscript%3Ealert(1)%3C%2Fscript%3E&email=a%40b.test&description=x",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            reasoning=(
                "Controlled stored-XSS payload was accepted by the fixture; browser sink "
                "confirmation remains review-only."
            ),
        )
    )
    results.append(
        _raw_probe(
            "quoted_field_xss",
            f"{base}/profile",
            method="POST",
            data="name=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E&email=a%40b.test",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            reasoning=(
                "Malformed-quoting payload was submitted to the fixture; browser sink "
                "confirmation remains review-only."
            ),
        )
    )
    results.append(
        _raw_probe(
            "elasticsearch_snapshot_traversal",
            f"{base}/elasticsearch",
            method="POST",
            data=json.dumps({"url": "../../../../etc/passwd"}),
            headers={"Content-Type": "application/json"},
            reasoning=(
                "Controlled Elasticsearch traversal payload produced the fixture marker; "
                "campaign remains human-review."
            ),
        )
    )
    results.append(
        _validated(
            "public_backup_disclosure",
            _finding(
                f"{base}/composer.lock.bak",
                VulnClass.INFO_DISCLOSURE.value,
            ),
            structural_checks.validate_info_disclosure,
        )
    )
    results.append(
        _validated(
            "laravel_app_debug",
            _finding(f"{base}/debug?trigger=1", VulnClass.INFO_DISCLOSURE.value),
            structural_checks.validate_info_disclosure,
        )
    )
    results.append(
        _raw_probe(
            "frontend_dependency_exposure",
            f"{base}/js/markdown-editor-0.3.0.js",
            reasoning=(
                "Versioned vulnerable-component fingerprint was served; dependency exploitability "
                "requires package-specific review."
            ),
        )
    )
    results.append(
        _raw_probe(
            "public_elasticsearch_exposure",
            f"{base}/es/fetch/elasticsearch:9200/_search",
            reasoning=(
                "Public Elasticsearch-like service response was reachable; authorization and "
                "version impact require human review."
            ),
        )
    )
    results.append(
        _raw_probe(
            "oob_xxe",
            f"{base}/xml/upload",
            method="POST",
            data='<!DOCTYPE x [<!ENTITY webpent SYSTEM "file:///etc/passwd">]><x>&webpent;</x>',
            headers={"Content-Type": "application/xml"},
            reasoning=(
                "XML sink marker was produced, but OOB callback was unavailable; no XXE "
                "confirmation is claimed."
            ),
        )
    )
    results.append(
        _raw_probe(
            "xslt_injection",
            f"{base}/xml/upload",
            method="POST",
            data="<xsl:stylesheet><xsl:copy-of select=\"document('file:///etc/passwd')\"/></xsl:stylesheet>",
            headers={"Content-Type": "application/xml"},
            reasoning=(
                "XSLT document/copy-of marker was produced, but campaign remains "
                "human-review."
            ),
        )
    )

    summary: dict[str, int] = {}
    for result in results:
        status = str(result["status"])
        summary[status] = summary.get(status, 0) + 1
    return {
        "schema_version": "waptlab-mock-matrix-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": "WebPent v60",
        "mode": "loopback-mock-detector-coverage",
        "target_contacted": False,
        "waptlab_modified": False,
        "source_fixture": "scripts/waptlab_mock.py (not WAPTLab)",
        "campaign_count": len(results),
        "summary": summary,
        "campaigns": results,
        "safety_statement": (
            "This matrix exercises WebPent validators against a local synthetic fixture. "
            "It is not live WAPTLab evidence; only the Docker-blocked static ground truth "
            "and the local fixture behavior are measured."
        ),
    }


def run_matrix(base_url: str) -> dict[str, Any]:
    host = urlparse(base_url).hostname
    if not host:
        raise ValueError("base URL must include a hostname")
    token = set_engagement_target_hosts(base_url)
    try:
        return _run_matrix_unscoped(base_url)
    finally:
        clear_engagement_target_hosts(token)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run loopback-only WAPTLab mock coverage matrix")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = run_matrix(args.base_url)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(args.output)
    print(json.dumps(report["summary"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
