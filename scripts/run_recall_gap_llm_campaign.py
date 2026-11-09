#!/usr/bin/env python3
"""Run the recall-gap campaign against the authorized local Juice Shop target."""
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
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

os.environ.setdefault("LLM_ENABLED", "true")
os.environ.setdefault("OPENAI_MODEL", "gpt-5-mini")
os.environ.setdefault("LLM_MAX_CALLS_PER_RUN", "100")
os.environ.setdefault("WEBPENT_LLM_MAX_CALLS_PER_RUN", "100")
os.environ.setdefault("WEBPENT_LLM_WARNING_TOKENS_PER_RUN", "100000")
os.environ["WEBPENT_AUDIT_SECRET_KEY"] = secrets.token_urlsafe(48)
os.environ["AUDIT_SECRET_KEY"] = os.environ["WEBPENT_AUDIT_SECRET_KEY"]
os.environ["CELERY_PAYLOAD_KEY"] = secrets.token_urlsafe(48)
os.environ["WEBPENT_CELERY_PAYLOAD_KEY"] = os.environ["CELERY_PAYLOAD_KEY"]
os.environ.setdefault("WEBPENT_ENVIRONMENT_PROFILE", "lab")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from langchain_core.messages import HumanMessage, SystemMessage  # noqa: E402

from webpent.config.settings import get_settings  # noqa: E402
from webpent.models.evidence import sha256_text  # noqa: E402
from webpent.production.autonomous_recon import run_autonomous_recon_campaign  # noqa: E402
from webpent.production.context_authority import ContextAuthority  # noqa: E402
from webpent.recon.autonomous_crawler import CrawlConfig  # noqa: E402
from webpent.recon.payload_advisor import advice_mapping, advise_payloads  # noqa: E402
from webpent.recon.payload_library import PayloadLibrary  # noqa: E402
from webpent.recon.wstg_catalog import WSTGCatalog  # noqa: E402
from webpent.shared.engagement_scope import (  # noqa: E402
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.shared.http import make_safe_httpx_client  # noqa: E402
from webpent.shared.llm import TaskType, get_llm, llm_usage_scope  # noqa: E402
from webpent.shared.untrusted_content import wrap_httpx_response  # noqa: E402

TARGET = "http://127.0.0.1:3000"
MODEL = "gpt-5-mini"
INPUT_RATE = 0.25 / 1_000_000
OUTPUT_RATE = 2.00 / 1_000_000


def digest(value: object) -> str:
    return hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:16]


def redact_url(value: object) -> str:
    parsed = urlsplit(str(value))
    query = urlencode([(key, "<redacted>") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)])
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def safe_artifact(value: object, key: str = "") -> object:
    lowered = key.lower()
    if lowered in {"input_tokens", "output_tokens", "total_tokens", "tokens_today", "token_count"} and (isinstance(value, (int, float)) or value is None):
        return value
    if any(marker in lowered for marker in ("body", "content", "header", "cookie", "authorization", "token", "secret", "password", "credential", "vault", "private_key")):
        if isinstance(value, (str, bytes)):
            return {"redacted": True, "sha256": digest(value), "length": len(value)}
        return "[REDACTED]"
    if lowered in {"url", "target_url", "execution_url", "request_url"}:
        return redact_url(value)
    if is_dataclass(value):
        return safe_artifact(asdict(value), key)
    if isinstance(value, dict):
        return {str(k): safe_artifact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [safe_artifact(item, key) for item in value]
    if isinstance(value, str):
        value = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~-]+", "Bearer [REDACTED]", value)
        value = re.sub(r"(?i)(password|secret|authorization|cookie|token)\s*[:=]\s*[^,;\s]+", r"\1=[REDACTED]", value)
        return value[:1200]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:1200]


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(safe_artifact(value), indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def cost(entry: dict[str, object]) -> float:
    if str(entry.get("model")) != MODEL:
        return 0.0
    return int(entry.get("input_tokens") or 0) * INPUT_RATE + int(entry.get("output_tokens") or 0) * OUTPUT_RATE


def _login(client, email: str, password: str) -> tuple[int, str]:
    response = client.post(
        f"{TARGET}/rest/user/login",
        json={"email": email, "password": password},
        timeout=15.0,
    )
    wrapped = wrap_httpx_response(response, source="principal-login")
    try:
        data = json.loads(wrapped.raw_for_deterministic_validation())
    except (TypeError, ValueError, json.JSONDecodeError):
        data = {}
    token = str(((data or {}).get("authentication") or {}).get("token") or "")
    return response.status_code, token


def provision_m4_principals(engagement_id: str) -> dict[str, object]:
    """Create disposable Juice Shop identities and seal only bearer tokens in M4."""
    stamp = str(int(time.time() * 1000))
    email = f"webpent-foreign-{stamp}@example.test"
    password = "Wp-" + secrets.token_urlsafe(18) + "-Aa1!"
    owner_email = os.environ.get("JUICE_OWNER_EMAIL", "").strip()
    owner_password = os.environ.get("JUICE_OWNER_PASSWORD", "")
    if not owner_email or not owner_password:
        raise RuntimeError("JUICE_OWNER_EMAIL and JUICE_OWNER_PASSWORD are required at runtime")
    target_token = set_engagement_target_hosts(TARGET)
    try:
        with make_safe_httpx_client(follow_redirects=False) as client:
            create = client.post(
                f"{TARGET}/api/Users",
                json={
                    "email": email,
                    "password": password,
                    "passwordRepeat": password,
                    "securityQuestion": {"key": "what is your favorite color?", "question": "What is your favorite color?"},
                    "securityAnswer": "blue",
                },
                timeout=15.0,
            )
            owner_status, owner_token = _login(client, owner_email, owner_password)
            foreign_status, foreign_token = _login(client, email, password)
    finally:
        clear_engagement_target_hosts(target_token)
    if create.status_code not in (200, 201, 409) or owner_status != 200 or foreign_status != 200 or not owner_token or not foreign_token:
        raise RuntimeError("principal_provisioning_failed")
    target_fp = sha256_text(TARGET)[:16]
    authority = ContextAuthority(engagement_id=engagement_id, target_fingerprint=target_fp)
    authority.seal_principal_credentials(principal_alias="owner", role="owner", password="bearer:" + owner_token)
    authority.seal_principal_credentials(principal_alias="foreign", role="foreign-user", password="bearer:" + foreign_token)
    return {
        "enabled": True,
        "owner_login_status": owner_status,
        "foreign_login_status": foreign_status,
        "user_creation_status": create.status_code,
        "aliases": ["owner", "foreign"],
        "credentials_persisted_in_artifact": False,
        "binding": "M4 vault-bound bearer attachment; tokens never enter LLM prompts",
    }


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dt%H%M%SZ")
    campaign_id = f"recall-gap-llm-{stamp.lower()}"
    out = ROOT / "artifacts" / campaign_id
    out.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter()
    payload_library = PayloadLibrary.from_json(ROOT / "docs/payload_library.json")
    wstg_catalog = WSTGCatalog.from_json(ROOT / "docs/wstg_catalog.json")
    settings = get_settings()
    if not settings.llm_enabled:
        write_json(out / "STOPPED.json", {"reason": "LLM_ENABLED resolved false", "at": datetime.now(timezone.utc).isoformat()})
        return 2
    llm = get_llm(TaskType.ANALYSIS)
    llm_calls: list[dict[str, object]] = []
    payload_call_records: list[dict[str, object]] = []
    payload_advice_records: list[dict[str, object]] = []
    principal_provisioning = provision_m4_principals(campaign_id)
    usage_index = 0
    with llm_usage_scope(settings) as usage:
        preflight_prompt = "Return only the single integer result for this connectivity check: 2+2."
        preflight_started = time.perf_counter()
        response = llm.invoke([
            SystemMessage(content="You are a connectivity probe. Do not request secrets."),
            HumanMessage(content=preflight_prompt),
        ])
        completion = str(getattr(response, "content", ""))
        new_usage = usage[usage_index:]
        usage_index = len(usage)
        entry = dict(new_usage[-1]) if new_usage else {"status": "usage_unavailable"}
        preflight = {
            "phase": "preflight",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "latency_ms": round((time.perf_counter() - preflight_started) * 1000.0, 3),
            "prompt_digest": digest(preflight_prompt),
            "completion_digest": digest(completion),
            "response_summary": completion[:80],
            "usage": entry,
            "cost_usd": round(cost(entry), 9),
        }
        llm_calls.append(preflight)
        if completion.strip() != "4":
            write_json(out / "STOPPED.json", {"reason": "live_llm_preflight_unexpected", "preflight": preflight})
            return 2

        def payload_callback(surface_map):
            nonlocal usage_index
            advice, records = advise_payloads(
                surface_map=surface_map, llm=llm, batch_size=8,
                payload_library_data=payload_library, wstg_catalog=wstg_catalog,
            )
            new_usage = usage[usage_index:]
            usage_index = len(usage)
            for index, record in enumerate(records):
                usage_entry = dict(new_usage[index]) if index < len(new_usage) else {"status": "usage_unavailable"}
                record["usage"] = usage_entry
                record["cost_usd"] = round(cost(usage_entry), 9)
                payload_call_records.append(record)
                llm_calls.append(record)
            payload_advice_records.extend(item.as_dict() for item in advice)
            return advice_mapping(advice), {"enabled": True, "accepted": len(advice), "calls": len(records), "source": "live_llm_advisory"}

        campaign_started = time.perf_counter()
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
            max_hypotheses=80,
            max_decisions=30,
            principal_count=2,
            learning_enabled=False,
            payload_advisor=payload_callback,
            payload_library=payload_library,
            wstg_catalog=wstg_catalog,
        )
        campaign_duration = time.perf_counter() - campaign_started
        total_usage = [dict(item) for item in usage]

    total_cost = round(sum(cost(item) for item in total_usage), 9)
    total_tokens = sum(int(item.get("total_tokens") or 0) for item in total_usage)
    campaign_block = result.get("campaign") or {}
    decisions = campaign_block.get("decisions") or result.get("decisions") or []
    statuses = {}
    for decision in decisions:
        status = str((decision.get("promotion") or {}).get("decision") or decision.get("validator_outcome") or "UNKNOWN").upper()
        statuses[status] = statuses.get(status, 0) + 1
    write_json(out / "run_config.json", {
        "campaign_id": campaign_id, "target_url": TARGET, "model": MODEL,
        "llm_enabled": True, "max_llm_calls": 100, "budget_usd": 5.0,
        "crawler": {"max_pages": 50, "max_depth": 2, "per_host_min_interval_seconds": 1.0},
        "adapter_used": False, "principal_count": 2,
        "knowledge_sources": {
            "payload_library_entries": len(payload_library),
            "wstg_tests": len(wstg_catalog),
            "payload_export": "docs/payload_library.json",
            "wstg_export": "docs/wstg_catalog.json",
        },
        "principal_provisioning": principal_provisioning,
        "raw_target_content_policy": "structural metadata only in LLM prompts and sanitized evidence",
        "started_at": datetime.now(timezone.utc).isoformat(),
    })
    write_json(out / "campaign_result_sanitized.json", result)
    write_json(out / "llm_calls.json", llm_calls)
    write_json(out / "payload_advice.json", payload_advice_records)
    write_json(out / "payload_selection_calls.json", payload_call_records)
    write_json(out / "usage_trace_numeric.json", total_usage)
    write_json(out / "cost_report.json", {
        "model": MODEL, "input_rate_usd_per_million": 0.25, "output_rate_usd_per_million": 2.0,
        "llm_calls": len(total_usage), "input_tokens": sum(int(x.get("input_tokens") or 0) for x in total_usage),
        "output_tokens": sum(int(x.get("output_tokens") or 0) for x in total_usage),
        "total_tokens": total_tokens, "actual_cost_usd": total_cost,
        "preflight_cost_included": True, "pricing_source": "live model catalog recorded in campaign run",
    })
    summary = {
        "campaign_id": campaign_id, "target_url": TARGET,
        "duration_seconds": round(campaign_duration, 3),
        "total_wall_seconds": round(time.perf_counter() - started, 3),
        "llm_calls": len(total_usage), "llm_cost_usd": total_cost,
        "payload_advice_accepted": len(payload_advice_records),
        "knowledge_sources": {
            "payload_library_entries": len(payload_library),
            "wstg_tests": len(wstg_catalog),
            "hypotheses_with_payload_id": sum(1 for item in result.get("hypotheses", []) if item.get("payload_id")),
            "hypotheses_with_wstg_reference": sum(1 for item in result.get("hypotheses", []) if item.get("wstg_reference")),
        },
        "principal_provisioning": principal_provisioning,
        "routes_crawled": len((result.get("crawl") or {}).get("routes") or []),
        "crawl_events": len((result.get("crawl") or {}).get("events") or []),
        "hypotheses_generated": result.get("hypotheses_generated"),
        "hypotheses_executable": result.get("hypotheses_executable"),
        "family_counts": result.get("family_counts"),
        "decision_status_counts": statuses,
        "promoted_count": int(campaign_block.get("promoted_count") or statuses.get("PROMOTED", 0)),
        "validator_refuted_count": sum(1 for decision in decisions if str(decision.get("validator_outcome", "")).upper() == "REFUTED"),
        "security_boundary": result.get("security_boundary"),
        "verdict": "PASS" if statuses.get("PROMOTED", 0) >= 3 else "PARTIAL",
    }
    write_json(out / "campaign_summary.json", summary)
    (out / "HONEST_REPORT.md").write_text(
        "# Recall-Gap LLM Campaign\n\n" + json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"artifact_root": str(out), **summary}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
