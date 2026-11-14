"""Adapter-free autonomous reconnaissance production entrypoint.

This facade composes existing authorities. It discovers structural facts with the
bounded crawler, creates advisory hypotheses, and delegates executable families
to the existing AVI/ModernOrchestrator path. It does not authorize, validate,
seal, replay, or promote findings itself.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit, urlunsplit

from webpent.memory.learning_lifecycle import persist_campaign_learning, record_consultation_audit
from webpent.memory.lesson_consultant import LessonConsultant
from webpent.memory.lesson_models import PriorityAdjustmentMap
from webpent.production.experiment_fabric import EXPERIMENT_REGISTRY
from webpent.production.production_spine import ProductionSpineConfig, resolve_production_spine
from webpent.recon.autonomous_crawler import AutonomousCrawler, CrawlConfig, CrawlResult
from webpent.recon.hypothesis_generator import HypothesisGenerator
from webpent.recon.payload_library import PayloadLibrary
from webpent.recon.wstg_catalog import WSTGCatalog
from webpent.shared.engagement_scope import (
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.shared.scope_file import ScopeFileSpec, parse_scope_entries


class AutonomousReconError(RuntimeError):
    """Raised when the adapter-free production path cannot proceed safely."""


def run_autonomous_recon_campaign(
    *,
    target_url: str,
    engagement_id: str,
    entrypoint: str = "direct_invoke",
    scope_entries: Iterable[str] | None = None,
    crawl_config: CrawlConfig | None = None,
    max_hypotheses: int = 50,
    max_decisions: int = 30,
    principal_count: int = 0,
    client_id: str | None = None,
    lesson_consultant: LessonConsultant | None = None,
    learning_enabled: bool = True,
    learning_manager: Any | None = None,
    learning_tracker: Any | None = None,
    learning_audit_chain: Any | None = None,
    payload_advisor: Callable[[Any], tuple[dict[str, dict[str, Any]], dict[str, Any]]] | None = None,
    payload_library: PayloadLibrary | None = None,
    wstg_catalog: WSTGCatalog | None = None,
    should_halt: Callable[[], bool] | None = None,
    budget_check: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Run bounded adapter-free recon and the existing governed execution path.

    ``scope_entries`` is optional. Without it, the production spine's exact
    target-host scope is used and the result is labelled ``inferred_from_url``.
    With it, the existing strict scope-file parser is used for path rules while
    ScopeLaw remains the final request authority.
    """
    if not str(target_url).startswith(("http://", "https://")):
        raise AutonomousReconError("target_url must be HTTP(S)")
    if not str(engagement_id).strip():
        raise AutonomousReconError("engagement_id required")
    if int(max_hypotheses) < 1 or int(max_decisions) < 1:
        raise AutonomousReconError("hypothesis and decision limits must be positive")
    if int(principal_count) < 0:
        raise AutonomousReconError("principal_count must be non-negative")

    parsed_target = urlsplit(str(target_url))
    execution_target = urlunsplit(
        (parsed_target.scheme, parsed_target.netloc, parsed_target.path.rstrip("/"), parsed_target.query, "")
    ) or str(target_url)

    scope_spec: ScopeFileSpec | None = None
    if scope_entries is not None:
        try:
            scope_spec = parse_scope_entries([str(item) for item in scope_entries])
        except Exception as exc:
            raise AutonomousReconError(f"scope_parse_failed:{type(exc).__name__}") from exc

    config = ProductionSpineConfig(
        engagement_id=str(engagement_id),
        target_url=execution_target,
        entrypoint=str(entrypoint),
    )
    orchestrator, production_trace = resolve_production_spine(config)
    halt = should_halt or (lambda: False)
    budget = budget_check or (lambda: True)
    if scope_spec is not None:
        scope_fingerprint = scope_spec.fingerprint
    else:
        scope_fingerprint = "inferred_from_url"

    target_token = set_engagement_target_hosts(execution_target)
    try:
        crawler = AutonomousCrawler(
            target_url=execution_target,
            scope_law=orchestrator.scope_law,
            engagement_id=str(engagement_id),
            config=crawl_config or CrawlConfig(),
            scope_spec=scope_spec,
            should_halt=halt,
            budget_check=budget,
        )
        crawl_result: CrawlResult = crawler.crawl()
        surface_map = crawl_result.surface_map
        surface_map.scope_fingerprint = scope_fingerprint
        priority_adjustments: PriorityAdjustmentMap | None = None
        lesson_consultation: dict[str, Any] = {
            "enabled": bool(learning_enabled and client_id),
            "target_type": "generic_web",
            "applied_lesson_ids": [],
            "lesson_hits": 0,
            "knowledge_hits": 0,
        }
        if learning_enabled and str(client_id or "").strip():
            priority_adjustments, lesson_consultation = (lesson_consultant or LessonConsultant()).consult(
                target_url=execution_target,
                surface_map=surface_map,
                client_id=client_id,
                engagement_id=engagement_id,
            )
        payload_advice: dict[str, dict[str, Any]] = {}
        payload_advisory: dict[str, Any] = {
            "enabled": bool(payload_advisor),
            "accepted": 0,
            "fallback": not bool(payload_advisor),
        }
        if payload_advisor is not None:
            try:
                payload_advice, payload_advisory = payload_advisor(surface_map)
                payload_advice = dict(payload_advice or {})
                payload_advisory = dict(payload_advisory or {})
                payload_advisory["accepted"] = len(payload_advice)
            except Exception as exc:
                payload_advice = {}
                payload_advisory = {
                    "enabled": True,
                    "accepted": 0,
                    "fallback": True,
                    "error_class": type(exc).__name__,
                }
        hypotheses = HypothesisGenerator(
            max_hypotheses=max_hypotheses, principal_count=principal_count,
            payload_library=payload_library, wstg_catalog=wstg_catalog,
        ).generate(
            surface_map,
            priority_adjustments=priority_adjustments,
            payload_advice=payload_advice,
        )
        executable = [
            item for item in hypotheses
            if bool(item.get("executable"))
            and str(item.get("vulnerability_class", "")).upper() in EXPERIMENT_REGISTRY
        ]
        deferred = [item for item in hypotheses if item not in executable]
        family_counts: dict[str, dict[str, int]] = {}
        deferred_reasons: dict[str, int] = {}
        for item in hypotheses:
            family = str(item.get("vulnerability_class", "UNKNOWN")).upper()
            bucket = family_counts.setdefault(family, {"generated": 0, "executable": 0, "deferred": 0})
            bucket["generated"] += 1
            if item in executable:
                bucket["executable"] += 1
            else:
                bucket["deferred"] += 1
                metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
                reason = str(metadata.get("deferred_reason") or item.get("generation_reason") or "not_registered_or_missing_authority")
                deferred_reasons[reason] = deferred_reasons.get(reason, 0) + 1
        production_result: dict[str, Any]
        if crawl_result.surface_map.halted or crawl_result.surface_map.budget_exhausted or halt():
            production_result = {
                "decisions": [],
                "decisions_executed": 0,
                "promoted_count": 0,
                "rejected_count": 0,
                "halted_before_execution": True,
                "manual_path_used": False,
            }
        elif executable and budget():
            production_result = orchestrator.run_autonomous_validation_campaign(
                target_url=execution_target,
                hypotheses=executable,
                max_decisions=min(int(max_decisions), len(executable)),
            )
        else:
            production_result = {
                "decisions": [],
                "decisions_executed": 0,
                "promoted_count": 0,
                "rejected_count": 0,
                "no_executable_hypotheses": True,
                "manual_path_used": False,
            }

        result = {
            "campaign_type": "adapter_free_autonomous_recon",
            "adapter_used": False,
            "target_url": execution_target,
            "engagement_id": str(engagement_id),
            "scope_source": "scope_file" if scope_spec is not None else "inferred_from_url",
            "scope_fingerprint": scope_fingerprint,
            "production_trace": production_trace.summary(),
            "crawl": surface_map.as_dict(),
            "hypotheses": hypotheses,
            "hypotheses_generated": len(hypotheses),
            "hypotheses_executable": len(executable),
            "hypotheses_deferred": deferred,
            "family_counts": family_counts,
            "deferred_reasons": deferred_reasons,
            "principal_count": int(principal_count),
            "client_id": str(client_id or "").strip()[:128] or None,
            "lesson_consultation": lesson_consultation,
            "payload_advisory": payload_advisory,
            "campaign": production_result,
            "security_boundary": {
                "authority": "ModernOrchestrator/ScopeLaw/AVI/PromotionPipeline",
                "raw_target_content_returned": False,
                "credentials_attached_by": "M4 only",
            },
        }
        if learning_enabled and str(client_id or "").strip():
            result["learning"] = persist_campaign_learning(
                result,
                campaign_id=str(engagement_id),
                client_id=str(client_id),
                target_type=str(lesson_consultation.get("target_type") or "generic_web"),
                lessons_manager=learning_manager,
                tracker=learning_tracker,
                audit_chain=learning_audit_chain,
            )
            if learning_audit_chain is not None:
                result["learning"]["consultation_audit"] = record_consultation_audit(
                    lesson_consultation, campaign_id=str(engagement_id), audit_chain=learning_audit_chain,
                )
        return result
    finally:
        clear_engagement_target_hosts(target_token)


__all__ = ["AutonomousReconError", "run_autonomous_recon_campaign"]
