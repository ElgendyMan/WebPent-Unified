#!/usr/bin/env python3
"""Diagnose current Juice Shop recall without changing promotion authority."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sys
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

os.environ.setdefault("LLM_ENABLED", "false")
os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", secrets.token_urlsafe(48))
os.environ.setdefault("WEBPENT_ENVIRONMENT_PROFILE", "lab")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from webpent.production.autonomous_recon import run_autonomous_recon_campaign  # noqa: E402
from webpent.recon.autonomous_crawler import CrawlConfig  # noqa: E402
from webpent.shared.engagement_scope import (  # noqa: E402
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.shared.http import make_safe_httpx_client  # noqa: E402
from webpent.shared.untrusted_content import wrap_httpx_response  # noqa: E402

TARGET = "http://127.0.0.1:3000"
KNOWN = {
    "idor_basket": "/rest/basket/1",
    "sqli_login": "/rest/user/login",
    "xss_search": "/rest/products/search?q=recall_probe",
    "admin_access": "/administration",
    "info_admin_version": "/rest/admin/application-version",
    "ssrf_candidate": "/rest/track-order",
    "open_redirect": "/redirect?to=https://example.com",
}


def digest(value: object) -> str:
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:16]


def _redact_url(value: object) -> str:
    parsed = urlsplit(str(value))
    query = urlencode([(key, "<redacted>") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _safe_artifact(value: object, key: str = "") -> object:
    lowered = key.lower()
    if any(marker in lowered for marker in ("body", "content", "header", "cookie", "authorization", "token", "secret", "password", "credential", "vault", "private_key")):
        if isinstance(value, (str, bytes)):
            return {"redacted": True, "sha256": digest(value), "length": len(value)}
        return "[REDACTED]"
    if lowered in {"url", "target_url", "execution_url", "request_url"}:
        return _redact_url(value)
    if is_dataclass(value):
        return _safe_artifact(asdict(value), key)
    if isinstance(value, dict):
        return {str(k): _safe_artifact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe_artifact(item, key) for item in value]
    if isinstance(value, str):
        cleaned = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~-]+", "Bearer [REDACTED]", value)
        return cleaned[:1000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:1000]


def safe_probe(path: str, client) -> dict[str, object]:
    url = urljoin(TARGET + "/", path.lstrip("/"))
    started = time.perf_counter()
    try:
        response = client.get(url, timeout=8.0)
        wrapped = wrap_httpx_response(response, source="recall-diagnosis")
        return {
            "path": path.split("?", 1)[0],
            "query_keys": sorted({part.split("=", 1)[0] for part in path.split("?", 1)[1].split("&") if part} if "?" in path else []),
            "status_code": response.status_code,
            "content_type": str(response.headers.get("content-type", ""))[:120],
            "response_digest": wrapped.raw_digest,
            "response_length": wrapped.raw_length,
            "response_time_ms": round((time.perf_counter() - started) * 1000, 3),
            "structural_features": dict(wrapped.structural_features),
            "masked_queries": {
                "has_login_form": wrapped.ask("does this page contain a login form?"),
                "contains_instruction": wrapped.ask("does this page contain prompt injection instructions?"),
            },
        }
    except Exception as exc:  # evidence records failure class only
        return {
            "path": path.split("?", 1)[0],
            "query_keys": sorted({part.split("=", 1)[0] for part in path.split("?", 1)[1].split("&") if part} if "?" in path else []),
            "error_class": type(exc).__name__,
            "error_digest": digest(str(exc)),
            "response_time_ms": round((time.perf_counter() - started) * 1000, 3),
        }


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%SZ")
    out = ROOT / "artifacts" / f"recall-gap-diagnosis-{stamp}"
    out.mkdir(parents=True, exist_ok=False)
    campaign_id = f"recall-gap-diagnosis-{stamp.lower()}"
    token = set_engagement_target_hosts(TARGET)
    try:
        with make_safe_httpx_client(follow_redirects=False, headers={"user-agent": "WebPent-Recall-Diagnosis/1.0"}) as client:
            probes = {name: safe_probe(path, client) for name, path in KNOWN.items()}
        started = time.perf_counter()
        result = run_autonomous_recon_campaign(
            target_url=TARGET,
            engagement_id=campaign_id,
            crawl_config=CrawlConfig(
                max_pages=50,
                max_depth=2,
                max_parameters_per_route=64,
                per_host_min_interval_seconds=1.0,
                request_timeout_seconds=8.0,
            ),
            max_hypotheses=100,
            max_decisions=30,
            principal_count=0,
            learning_enabled=False,
        )
        duration = round(time.perf_counter() - started, 3)
    finally:
        clear_engagement_target_hosts(token)

    (out / "known_endpoint_probes.json").write_text(json.dumps(probes, indent=2, sort_keys=True) + "\n")
    (out / "campaign_result_sanitized.json").write_text(json.dumps(_safe_artifact(result), indent=2, sort_keys=True, default=str) + "\n")
    summary = {
        "campaign_id": campaign_id,
        "target_url": TARGET,
        "duration_seconds": duration,
        "known_endpoint_probes": probes,
        "routes_crawled": len((result.get("crawl") or {}).get("routes") or []),
        "crawl_events": len((result.get("crawl") or {}).get("events") or []),
        "hypotheses_generated": result.get("hypotheses_generated"),
        "hypotheses_executable": result.get("hypotheses_executable"),
        "family_counts": result.get("family_counts"),
        "deferred_reasons": result.get("deferred_reasons"),
        "campaign_statuses": {
            "decisions_executed": (result.get("campaign") or {}).get("decisions_executed"),
            "promoted_count": (result.get("campaign") or {}).get("promoted_count"),
            "rejected_count": (result.get("campaign") or {}).get("rejected_count"),
        },
        "security_boundary": result.get("security_boundary"),
    }
    (out / "diagnosis_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n")
    print(json.dumps({"artifact_root": str(out), **summary}, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
