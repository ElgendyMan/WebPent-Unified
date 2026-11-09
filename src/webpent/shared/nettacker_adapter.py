"""Safe, observation-only adapter for Nettacker exported events.

This module deliberately does not import or execute Nettacker.  It accepts an
already captured JSON-compatible report/event payload and normalizes it into
WebPent's canonical evidence contract.  Imported records are recon/enrichment
observations only; confirmation remains the responsibility of WebPent's
validator and proof pipeline.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from webpent.models.evidence import AdapterResult, ScopeDecision
from webpent.shared.action_authority import ActionAuthority, ActionRequest, ActionResult
from webpent.shared.tool_adapters import ToolAdapter, adapt_result

NETTACKER_PROJECT = "Nettacker"
NETTACKER_COMMIT = "d274c40a276076c7d40260489d06943b756bd9d1"
NETTACKER_TOOL_VERSION = "0.4.1+source:" + NETTACKER_COMMIT
_MAX_INPUT_BYTES = 512 * 1024
_MAX_RECORDS = 256
_MAX_TEXT = 1000
_MAX_ID = 160

_SAFE_EVENT_KEYS = {
    "asset",
    "cpe",
    "cve",
    "cvss",
    "date",
    "description",
    "endpoint",
    "event",
    "event_name",
    "event_type",
    "host",
    "hostname",
    "id",
    "ip",
    "json_event",
    "method",
    "module_name",
    "name",
    "path",
    "port",
    "port_state",
    "product",
    "protocol",
    "reference",
    "retrieved_at",
    "scan_id",
    "scan_unique_id",
    "schema",
    "service",
    "severity",
    "source",
    "state",
    "status",
    "status_code",
    "target",
    "timestamp",
    "title",
    "transport",
    "url",
    "version",
}
_BLOCKED_KEYS = {
    "authorization",
    "body",
    "cmd",
    "command",
    "cookie",
    "credential",
    "execute",
    "exec",
    "exploit",
    "exploit_code",
    "headers",
    "password",
    "payload",
    "raw",
    "request",
    "response_body",
    "secret",
    "session",
    "shell",
    "token",
}
_PARTIAL_VALUES = {"partial", "incomplete", "timeout", "timed_out", "truncated"}


def _text(value: Any, limit: int = _MAX_TEXT) -> str:
    return str(value or "").strip()[:limit]


def _safe_target(target: str) -> str:
    value = _text(target, 2048)
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("target_http_origin_required")
    return value


def _payload_size(payload: Any) -> int:
    return len(repr(payload).encode("utf-8", errors="replace"))


def _decode_jsonish(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text or text[0] not in "[{\"":
        return value
    try:
        import json

        return json.loads(text)
    except (TypeError, ValueError):
        return value


def _record_list(payload: Any) -> list[Mapping[str, Any]]:
    if isinstance(payload, Mapping):
        candidates: Any = None
        for key in ("events", "results", "records", "logs", "findings", "vulnerabilities"):
            if key in payload:
                candidates = _decode_jsonish(payload[key])
                break
        if candidates is None:
            candidates = [payload]
    elif isinstance(payload, Sequence) and not isinstance(payload, (str, bytes, bytearray)):
        candidates = payload
    else:
        raise ValueError("nettacker_events_must_be_json_object_or_list")

    if not isinstance(candidates, Sequence) or isinstance(candidates, (str, bytes, bytearray)):
        raise ValueError("nettacker_events_collection_required")
    if len(candidates) > _MAX_RECORDS:
        raise ValueError("nettacker_event_limit_exceeded")
    records = [item for item in candidates if isinstance(item, Mapping)]
    if len(records) != len(candidates):
        raise ValueError("nettacker_event_object_required")
    return records


def _normalise_key(key: Any) -> str:
    return _text(key, 80).lower().replace("-", "_")


def _normalise_event(record: Mapping[str, Any], index: int) -> dict[str, Any]:
    clean: dict[str, Any] = {
        "record_index": index,
        "source_project": NETTACKER_PROJECT,
        "source_commit": NETTACKER_COMMIT,
    }
    omitted: list[str] = []
    for key, value in record.items():
        name = _normalise_key(key)
        if name in _BLOCKED_KEYS or any(token in name for token in _BLOCKED_KEYS):
            omitted.append(name[:_MAX_ID])
            continue
        if name not in _SAFE_EVENT_KEYS:
            continue
        if name == "scan_unique_id":
            name = "scan_id"
        if name == "timestamp" and "retrieved_at" not in clean:
            name = "retrieved_at"
        decoded = _decode_jsonish(value) if name in {"event", "json_event"} else value
        if isinstance(decoded, (str, int, float, bool)) or decoded is None:
            clean[name] = _text(decoded) if isinstance(decoded, str) else decoded
        elif isinstance(decoded, (list, tuple)):
            clean[name] = [_text(item, 300) for item in decoded[:16]]
        elif isinstance(decoded, Mapping):
            clean[name] = {"present": True, "field_count": min(len(decoded), 32)}
        else:
            clean[name] = _text(decoded)

    if omitted:
        clean["unsafe_fields_omitted"] = sorted(set(omitted))[:16]
    clean.setdefault("source", NETTACKER_PROJECT)
    if "cve" in clean or _text(clean.get("id")).upper().startswith("CVE-"):
        clean["evidence_role"] = "cve_enrichment_only"
    else:
        clean["evidence_role"] = "recon_observation_only"
    return clean


def _envelope_status(payload: Any) -> str | None:
    if not isinstance(payload, Mapping):
        return None
    for key in ("status", "scan_status", "result_status"):
        value = _text(payload.get(key), 40).lower()
        if value in _PARTIAL_VALUES:
            return "partial"
    complete = payload.get("complete")
    if complete is False:
        return "partial"
    return None


def _with_partial_status(result: AdapterResult) -> AdapterResult:
    execution = result.execution.model_copy(update={"status": "partial"})
    observations = [item.model_copy(update={"status": "partial"}) for item in result.observations]
    return result.model_copy(update={"execution": execution, "observations": observations})


def _invalid_result(target: str, error: str, scope_decision: ScopeDecision) -> AdapterResult:
    def fail_runner(_target: str) -> Any:
        raise ValueError(error)

    adapter = ToolAdapter(
        name="nettacker-observation",
        runner=fail_runner,
        category="imported_observation",
        version=NETTACKER_TOOL_VERSION,
    )
    return adapter.run(
        target,
        scope_decision=scope_decision,
        parameters={"source_project": NETTACKER_PROJECT, "source_commit": NETTACKER_COMMIT},
    )


def adapt_nettacker_records(
    target: str,
    payload: Any,
    *,
    scope_decision: ScopeDecision = "not_checked",
    asset: str | None = None,
    endpoint: str | None = None,
    method: str | None = None,
) -> AdapterResult:
    """Normalize captured Nettacker events without running Nettacker or doing I/O."""
    try:
        safe_target = _safe_target(target)
        if _payload_size(payload) > _MAX_INPUT_BYTES:
            raise ValueError("nettacker_input_limit_exceeded")
        records = _record_list(payload)
        normalized = [_normalise_event(record, index) for index, record in enumerate(records)]
        result = adapt_result(
            tool_name="nettacker-observation",
            target=safe_target,
            result=normalized,
            asset=asset,
            endpoint=endpoint,
            method=method,
            parameters={
                "source_project": NETTACKER_PROJECT,
                "source_commit": NETTACKER_COMMIT,
                "execution_plane": "import_only",
                "confirmation_authority": "webpent_validator",
            },
            scope_decision=scope_decision,
            tool_version=NETTACKER_TOOL_VERSION,
        )
        return _with_partial_status(result) if _envelope_status(payload) == "partial" else result
    except (TypeError, ValueError) as exc:
        return _invalid_result(str(target)[:2048] or "invalid-target", str(exc), scope_decision)


def ingest_nettacker_records(
    authority: ActionAuthority,
    request: ActionRequest,
    payload: Any,
    *,
    asset: str | None = None,
    endpoint: str | None = None,
    method: str | None = None,
) -> ActionResult:
    """Bind a captured Nettacker import to WebPent authority and idempotency ledger."""

    def handler(bound_request: ActionRequest) -> AdapterResult:
        if bound_request.capability != "nettacker_observation":
            raise ValueError("nettacker_capability_required")
        result = adapt_nettacker_records(
            bound_request.target_url,
            payload,
            scope_decision="allowed",
            asset=asset,
            endpoint=endpoint,
            method=method,
        )
        context = {
            "action_id": bound_request.idempotency_key[:160],
            "engagement_id": bound_request.engagement_id[:128],
            "task_id": bound_request.task_id[:128],
            "execution_plane": "import_only",
        }
        execution = result.execution.model_copy(
            update={"parameters": {**result.execution.parameters, **context}}
        )
        observations = [
            item.model_copy(update={"parameters": {**item.parameters, **context}})
            for item in result.observations
        ]
        return result.model_copy(update={"execution": execution, "observations": observations})

    return authority.execute(request, handler)


def surface_data_from_nettacker(
    crawled_data: Mapping[str, Any] | None,
    result: AdapterResult,
    *,
    target_url: str,
) -> dict[str, Any]:
    """Project same-origin URL observations into the surface graph as validator-gated data."""
    data = dict(crawled_data) if isinstance(crawled_data, Mapping) else {}
    target_origin = _safe_target(target_url)
    root = urlsplit(target_origin)
    endpoints = list(data.get("nettacker_surface_records") or [])
    services = list(data.get("nettacker_service_fingerprints") or [])
    for observation in result.observations:
        value = observation.value if isinstance(observation.value, Mapping) else {}
        record = dict(value)
        record.update(
            {
                "source": NETTACKER_PROJECT,
                "source_commit": NETTACKER_COMMIT,
                "observation_id": observation.id,
            }
        )
        candidate_url = _text(value.get("url"), 2048)
        if candidate_url:
            parsed = urlsplit(candidate_url)
            if (
                parsed.scheme.lower() in {"http", "https"}
                and parsed.hostname
                and parsed.scheme.lower() == root.scheme.lower()
                and parsed.netloc.lower() == root.netloc.lower()
            ):
                record["url"] = candidate_url
                record["method"] = _text(value.get("method") or "GET", 12).upper()
                endpoints.append(record)
                continue
        if value.get("service") or value.get("port") or value.get("product"):
            services.append(record)
    data["nettacker_surface_records"] = endpoints[:250]
    data["nettacker_service_fingerprints"] = services[:250]
    data["nettacker_observation_count"] = len(result.observations)
    return data


def nettacker_adapter_manifest() -> dict[str, Any]:
    """Return non-executable integration metadata for capability reporting."""
    return {
        "status": "adapter_only",
        "available": True,
        "execution_available": False,
        "source_project": NETTACKER_PROJECT,
        "source_commit": NETTACKER_COMMIT,
        "source_version": "0.4.1",
        "authority": "webpent_validator",
        "network_io": False,
        "subprocess_io": False,
        "destructive": False,
        "fail_closed": True,
        "timeout_seconds": 0,
        "retry_budget": 0,
        "concurrency_limit": 1,
        "max_input_bytes": _MAX_INPUT_BYTES,
        "max_records": _MAX_RECORDS,
        "partial_output_supported": True,
        "cleanup": "not_applicable_import_only",
    }
