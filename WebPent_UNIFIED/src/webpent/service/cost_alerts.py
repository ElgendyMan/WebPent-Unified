"""Read-only cost projections and redacted idempotent alert dispatch."""
from __future__ import annotations

import asyncio
import inspect
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Mapping

from webpent.models.proof_bundle import ProofBundle
from webpent.service.manager import CampaignManager
from webpent.service.models import AlertEvent, FindingEvent
from webpent.service.store import ServiceStore

Sender = Callable[[dict[str, Any]], bool | Awaitable[bool]]


def _safe_finding_payload(finding: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only report-safe scalar metadata in the product projection."""
    blocked = ("password", "secret", "token", "cookie", "authorization", "header", "body")
    drop = object()

    def clean(key: str, value: Any) -> Any:
        if any(marker in key.lower() for marker in blocked):
            return drop
        if isinstance(value, Mapping):
            return {str(child_key)[:80]: child_value for child_key, child_value in
                    ((child_key, clean(str(child_key), child_value)) for child_key, child_value in value.items())
                    if child_value is not drop}
        if isinstance(value, (list, tuple)):
            return [item for item in (clean(key, item) for item in value) if item is not drop][:100]
        if isinstance(value, str):
            return value[:1000]
        if isinstance(value, (int, float, bool)) or value is None:
            return value
        return None

    return {str(key)[:80]: cleaned for key, value in finding.items()
            if (cleaned := clean(str(key), value)) is not drop}


@dataclass(frozen=True)
class CostSnapshot:
    campaign_id: str
    budget_limit: float
    used_budget: float
    budget_ratio: float
    used_actions: int
    llm_calls: int
    reported_tokens: int
    cache_hits: int
    cheap_model_calls: int
    tokens_saved: int
    actual_cost: float
    cost_per_action: float
    cost_per_finding: float
    candidates: int
    experiments: int
    findings: int
    promoted: int
    refuted: int
    needs_human_review: int
    inconclusive: int

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class AlertDispatcher:
    """Idempotent event dispatcher; sender is injected for safe delivery/testing."""

    def __init__(self, store: ServiceStore, sender: Sender | None = None,
                 *, webhook_url: str = "", on_promoted: bool = True,
                 on_refuted: bool = False, on_campaign_complete: bool = True) -> None:
        self.store = store
        self.sender = sender
        self.webhook_url = webhook_url
        self.on_promoted = bool(on_promoted)
        self.on_refuted = bool(on_refuted)
        self.on_campaign_complete = bool(on_campaign_complete)

    @staticmethod
    def _run_webhook(coro: Awaitable[bool]) -> bool:
        """Run the async signed webhook from sync service code safely."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return bool(asyncio.run(coro))
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=1) as executor:
            return bool(executor.submit(asyncio.run, coro).result())

    def _push_finding_webhook(self, event: FindingEvent) -> bool:
        from webpent.integrations.webhook import push_to_webhook
        from webpent.service.lifecycle_findings import build_lifecycle_finding

        vuln_class = str(event.payload.get("vulnerability_type", event.payload.get("vuln_class", "unknown"))).lower()
        severity = str(event.severity or "unknown").lower()
        route = str(event.payload.get("route") or event.payload.get("url") or "/")
        finding_url = route if route.startswith(("http://", "https://")) else f"https://redacted.invalid{route if route.startswith('/') else '/' + route}"
        # r6c (UM-DR-26): the notification Finding is built by the REGISTERED
        # lifecycle writer (service/lifecycle_findings.py) — a PROMOTED event
        # carries the promotion gate's Tool-Confirmed stamp with provenance,
        # which makes the alert actionable for push_to_webhook (the old
        # always-"Pending" shape silently dead-ended every promoted webhook).
        # This module keeps NO Tool-Confirmed literal (the M1-B/E-1
        # source-level ban, tests/test_m1b_tool_confirmed_writers.py).
        finding = build_lifecycle_finding(
            campaign_id=event.campaign_id,
            finding_id=event.finding_id,
            status=str(event.status or ""),
            severity=severity,
            title=event.title or "",
            vuln_class=vuln_class,
            route=route,
            finding_url=finding_url,
            cvss_score=str(event.payload.get("cvss_score") or "") or None,
            payload=event.redacted_payload(),
        )
        return self._run_webhook(push_to_webhook(finding, self.webhook_url))

    def emit(self, event: AlertEvent) -> bool:
        if not self.store.claim_alert(event):
            return False
        delivered = False
        try:
            if self.sender is not None:
                result = self.sender(event.payload)
                delivered = bool(asyncio.run(result) if inspect.isawaitable(result) else result)
            elif self.webhook_url and event.kind.startswith("finding."):
                finding_event = FindingEvent(
                    campaign_id=event.campaign_id,
                    finding_id=str(event.payload.get("finding_id", "unknown")),
                    status=str(event.payload.get("status", "")),
                    severity=str(event.payload.get("severity", "unknown")),
                    title=str(event.payload.get("title", "")),
                    evidence_ref=str(event.payload.get("evidence_ref", "")),
                    cost=float(event.payload.get("cost", 0.0) or 0.0),
                    payload=event.payload,
                    created_at=event.created_at,
                )
                delivered = self._push_finding_webhook(finding_event)
            elif self.webhook_url and event.kind == "campaign.completed":
                from webpent.integrations.webhook import push_to_webhook
                from webpent.models.findings import Finding
                finding = Finding(
                    title=f"Campaign {event.campaign_id} completed",
                    severity="info",
                    description="WebPent campaign lifecycle completion notification.",
                    tool_name="webpent.lifecycle",
                    url=str(event.payload.get("target_url") or "https://redacted.invalid/"),
                    confidence_level="Pending",
                    vuln_class="unknown",
                    campaign_id=event.campaign_id,
                )
                delivered = self._run_webhook(push_to_webhook(finding, self.webhook_url))
        finally:
            self.store.finish_alert(event.idempotency_key, status="delivered" if delivered else "queued")
        return delivered

    def budget_threshold(self, campaign_id: str, *, used: float, limit: float) -> bool:
        if limit <= 0 or used / limit < 0.8:
            return False
        event = AlertEvent(
            campaign_id=campaign_id,
            kind="budget_80_percent",
            payload={"event": "webpent_budget_alert", "campaign_id": campaign_id,
                     "threshold": 0.8, "used_budget": round(used, 6), "budget_limit": round(limit, 6)},
            idempotency_key=f"budget:{campaign_id}:80",
        )
        return self.emit(event)

    def health_failure(self, *, gate_name: str, output_digest: str, source_digest: str = "") -> bool:
        event = AlertEvent(
            campaign_id="system",
            kind="health_gate_failed",
            payload={"event": "webpent_health_alert", "gate_name": gate_name,
                     "output_digest": output_digest[:32], "source_digest": source_digest[:32]},
            idempotency_key=f"health:{gate_name}:{output_digest[:32]}",
        )
        return self.emit(event)

    def finding(self, event: FindingEvent) -> bool:
        if event.status == "promoted" and not self.on_promoted:
            return False
        if event.status == "refuted" and not self.on_refuted:
            return False
        if event.status not in {"promoted", "refuted"}:
            return False
        payload = event.redacted_payload()
        payload["lifecycle_event"] = f"finding.{event.status}"
        return self.emit(AlertEvent(
            campaign_id=event.campaign_id,
            kind=f"finding.{event.status}",
            payload=payload,
            idempotency_key=event.idempotency_key,
            created_at=event.created_at,
        ))

    def campaign_complete(self, campaign_id: str, *, findings: int, cost: float,
                          duration_seconds: float, target_url: str = "") -> bool:
        if not self.on_campaign_complete:
            return False
        return self.emit(AlertEvent(
            campaign_id=campaign_id,
            kind="campaign.completed",
            payload={
                "event": "campaign.completed",
                "campaign_id": campaign_id,
                "findings_count": int(findings),
                "cost": round(float(cost), 6),
                "duration_seconds": round(float(duration_seconds), 6),
                "target_url": target_url,
            },
            idempotency_key=f"campaign:{campaign_id}:completed",
        ))


class CostTrackingService:
    def __init__(self, store: ServiceStore, alerts: AlertDispatcher,
                 manager: CampaignManager) -> None:
        self.store = store
        self.alerts = alerts
        self.manager = manager

    def record_usage(self, campaign_id: str, **kwargs: Any) -> CostSnapshot:
        self.store.record_usage(campaign_id, **kwargs)
        return self.snapshot(campaign_id)

    def record_finding(self, campaign_id: str, finding: Mapping[str, Any], *, status: str, cost: float = 0.0) -> bool:
        safe_finding = _safe_finding_payload(finding)
        raw_bundle = finding.get("proof_bundle")
        if isinstance(raw_bundle, Mapping):
            try:
                bundle = ProofBundle.model_validate(raw_bundle)
                if bundle.verify_seal():
                    # The sealed bundle is already redaction-governed and its
                    # exact bytes are required for downstream authenticity.
                    safe_finding["proof_bundle"] = dict(raw_bundle)
            except (AttributeError, KeyError, RuntimeError, TypeError, ValueError):
                # An unverified bundle never enters the product projection.
                pass
        self.store.upsert_finding(campaign_id, safe_finding, status=status, cost=cost,
                                  created_at=datetime.now(timezone.utc).isoformat())
        event = FindingEvent(
            campaign_id=campaign_id,
            finding_id=str(safe_finding.get("finding_id") or safe_finding.get("id") or "unknown"),
            status=status,
            severity=str(safe_finding.get("severity") or "unknown"),
            title=str(safe_finding.get("title") or ""),
            evidence_ref=str(safe_finding.get("evidence_ref") or ""),
            cost=cost,
            payload=safe_finding,
        )
        return self.alerts.finding(event)

    def snapshot(self, campaign_id: str) -> CostSnapshot:
        row = self.store.get_campaign(campaign_id)
        usage = self.store.get_usage(campaign_id)
        findings = self.store.list_findings(campaign_id)
        # Use the exact manager/ledger root configured for this service.
        snapshot = self.manager.snapshot(campaign_id)
        counts = {status: sum(1 for item in findings if item["status"] == status) for status in
                  ("promoted", "refuted", "needs-human-review", "inconclusive", "candidate")}
        used = snapshot.used_budget
        limit = snapshot.budget_limit
        self.alerts.budget_threshold(campaign_id, used=used, limit=limit)
        calls = int(usage.get("llm_calls", 0))
        actions = snapshot.used_actions
        return CostSnapshot(
            campaign_id=campaign_id,
            budget_limit=limit,
            used_budget=used,
            budget_ratio=min(1.0, used / limit) if limit else 1.0,
            used_actions=actions,
            llm_calls=calls,
            reported_tokens=int(usage.get("reported_tokens", 0)),
            cache_hits=int(usage.get("cache_hits", 0)),
            cheap_model_calls=int(usage.get("cheap_model_calls", 0)),
            tokens_saved=int(usage.get("tokens_saved", 0)),
            actual_cost=float(usage.get("actual_cost", 0.0)),
            cost_per_action=round(used / actions, 6) if actions else 0.0,
            cost_per_finding=round(used / len(findings), 6) if findings else 0.0,
            candidates=counts["candidate"], experiments=actions, findings=len(findings),
            promoted=counts["promoted"], refuted=counts["refuted"],
            needs_human_review=counts["needs-human-review"], inconclusive=counts["inconclusive"],
        )


__all__ = ["AlertDispatcher", "CostSnapshot", "CostTrackingService"]
