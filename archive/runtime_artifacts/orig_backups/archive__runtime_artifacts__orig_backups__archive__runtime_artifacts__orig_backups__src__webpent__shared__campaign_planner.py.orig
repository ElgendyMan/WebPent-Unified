"""Deterministic, passive campaign planner for the VIP bug-hunter loop."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from webpent.models.campaigns import (
    CampaignExecutionContract,
    CampaignPlanEntry,
    CampaignPlannerResult,
    HypothesisDAGEdge,
    HypothesisDAGNode,
)
from webpent.models.evidence import redact_sensitive
from webpent.shared.campaigns import build_generic_campaign_ledger
from webpent.shared.target_adapters import CampaignProfileSpec
from webpent.shared.validator_plugins import build_validator_plugin_registry

_CONTRACTS: dict[str, dict[str, Any]] = {}
_GENERIC_CONTRACT: dict[str, Any] = {
    "preconditions": ["matching discovered surface is in scope", "baseline response captured"],
    "identities": ["anonymous", "owner"],
    "actions": ["replay a bounded non-destructive differential", "compare against baseline"],
    "payload_strategy": ["validator-specific safe canary only"],
    "oracle": ["causal response or browser differential", "no heuristic-only claim"],
    "negative_control": ["equivalent benign input"],
    "cleanup": ["read-only or restore test state"],
    "budget": 2,
}
for _generic_key in (
    "xss_reflected",
    "xss_stored",
    "sqli_param",
    "idor_object",
    "auth_bypass_jwt",
    "open_redirect",
    "info_disclosure",
    "ssrf_url_param",
    "api_issue",
    "path_traversal",
):
    _CONTRACTS.setdefault(_generic_key, dict(_GENERIC_CONTRACT))


def _as_mapping(item: Any) -> Mapping[str, Any]:
    if isinstance(item, Mapping):
        return item
    if hasattr(item, "model_dump"):
        return item.model_dump(mode="json")
    return {}


def _observation_ref(item: Mapping[str, Any], prefix: str) -> str:
    return str(item.get("fingerprint") or item.get("evidence_ref") or item.get("ref") or prefix)[
        :200
    ]


def _safe_gap(value: Any) -> str:
    clean, _ = redact_sensitive(str(value))
    return re.sub(
        r"(?i)\b(token|secret|password|api[-_]?key)\s*[:=]\s*[^,\s]+",
        r"\1=[REDACTED]",
        clean,
    )[:200]


def _observation_tokens(item: Mapping[str, Any]) -> set[str]:
    """Return conservative semantic tokens from one observed surface.

    Tokenization is used only to decide which bounded campaign task is worth
    attempting.  It never asserts a vulnerability.  URL path/query and
    explicitly observed transport metadata are included so crawlers that emit
    plain endpoint records do not silently lose vertical campaign coverage.
    """
    values: list[str] = []
    for key in (
        "category",
        "vuln_class",
        "title",
        "statement",
        "reason",
        "signal_refs",
        "signals",
        "intent_tags",
        "surfaces",
        "url",
        "endpoint",
        "path",
        "method",
        "target_param",
        "target_params",
        "hint_provenance",
        "source",
        "discovery_kind",
        "content_type",
        "request_headers",
        "response_headers",
        "header_names",
        "filename",
        "file_name",
        "service",
        "technology",
        "object_id",
    ):
        value = item.get(key)
        if isinstance(value, Mapping):
            values.extend(str(x).lower() for x in value)
            values.extend(str(x).lower() for x in value.values())
        elif isinstance(value, (list, tuple, set)):
            values.extend(str(x).lower() for x in value)
        elif value:
            values.append(str(value).lower())

    tokens = {
        token for value in values for token in re.findall(r"[a-z0-9]+", value.lower()) if token
    }
    aliases = {
        "swagger-ui": {"swagger", "openapi"},
        "swaggerui": {"swagger", "openapi"},
        "open-api": {"openapi"},
        "graphql": {"api", "query"},
        "avatar": {"image", "profile", "url"},
        "photo": {"image", "profile", "url"},
        "upload": {"multipart", "file"},
        "import": {"multipart", "csv", "worker"},
        "csv": {"multipart", "worker"},
        "backup": {"artifact", "download"},
        "snapshot": {"elasticsearch", "service"},
        "debug": {"error", "laravel"},
        "oauth2": {"oauth", "callback", "redirect"},
        "oidc": {"oauth", "callback", "redirect"},
        "xml": {"multipart"},
    }
    for token in tuple(tokens):
        tokens.update(aliases.get(token, ()))
    return tokens


def _contract(
    key: str,
    *,
    status: str,
    gaps: list[str],
    execution_contracts: Mapping[str, Mapping[str, Any]],
    observed_preconditions: list[str] | None = None,
) -> CampaignExecutionContract:
    declared = execution_contracts.get(key, {})
    if not isinstance(declared, Mapping):
        declared = {}
    raw = dict(_CONTRACTS.get(key, _GENERIC_CONTRACT))
    raw.update(declared)
    # A declared precondition becomes observed only when the planner has a
    # concrete same-target observation supporting this campaign.  This keeps
    # execution fail-closed for unobserved campaigns while materializing the
    # evidence channel expected by the central executor.
    raw["observed_preconditions"] = list(observed_preconditions or [])[:12]
    raw["confidence_state"] = (
        "blocked" if status.startswith("blocked") else "ready" if not gaps else "unplanned"
    )
    return CampaignExecutionContract(**raw)


def _resolve_campaign_profile(
    *,
    campaign_inventory: str,
    campaign_profile: CampaignProfileSpec | None,
    ledger_projection_supplied: bool = False,
) -> CampaignProfileSpec | None:
    """Resolve an explicit profile without target or URL heuristics."""
    inventory = str(campaign_inventory or "generic").strip().lower()
    if inventory == "auto":
        inventory = "generic"
    if not inventory:
        inventory = "generic"
    if campaign_profile is not None and not isinstance(campaign_profile, CampaignProfileSpec):
        raise ValueError("campaign_profile_invalid")
    if campaign_profile is None:
        if inventory != "generic":
            raise ValueError("campaign_inventory_requires_explicit_profile")
        return None
    if inventory not in {"generic", campaign_profile.profile_id.strip().lower()}:
        raise ValueError("campaign_inventory_profile_mismatch")
    return campaign_profile


def build_campaign_plan(
    *,
    target_url: str,
    campaign_inventory: str = "generic",
    campaign_profile: CampaignProfileSpec | None = None,
    campaign_ledger: Mapping[str, Any] | None = None,
    execution_contracts: Mapping[str, Mapping[str, Any]] | None = None,
    observed_campaigns: set[str] | None = None,
    blocked_by: dict[str, str] | None = None,
    surface_observations: Iterable[Any] = (),
    workflow_observations: Iterable[Any] = (),
    explicit_gaps: Iterable[str] = (),
) -> dict[str, Any]:
    """Create a passive plan and DAG; executor evidence remains authoritative."""
    resolved_profile = _resolve_campaign_profile(
        campaign_inventory=campaign_inventory,
        campaign_profile=campaign_profile,
        ledger_projection_supplied=campaign_ledger is not None,
    )
    ledger_builder = (
        resolved_profile.ledger_builder
        if resolved_profile is not None
        else build_generic_campaign_ledger
    )
    plugin_builder = (
        resolved_profile.plugin_builder
        if resolved_profile is not None
        else build_validator_plugin_registry
    )
    if campaign_ledger is not None:
        if not isinstance(campaign_ledger, Mapping):
            raise ValueError("campaign_ledger_projection_invalid")
        ledger = dict(campaign_ledger)
    else:
        try:
            ledger = ledger_builder(
                observed_campaigns=observed_campaigns,
                blocked_by=blocked_by,
            )
        except Exception as exc:
            raise ValueError("campaign_profile_ledger_builder_failed") from exc
    if not isinstance(ledger, Mapping) or not isinstance(ledger.get("entries"), list):
        raise ValueError("campaign_profile_ledger_invalid")
    resolved_contracts = (
        execution_contracts
        if execution_contracts is not None
        else (resolved_profile.execution_contracts if resolved_profile is not None else _CONTRACTS)
    )
    if not isinstance(resolved_contracts, Mapping):
        raise ValueError("campaign_execution_contracts_invalid")
    surfaces = [_as_mapping(item) for item in surface_observations]
    workflows = [_as_mapping(item) for item in workflow_observations]
    workflow_ref_set = {_observation_ref(item, "") for item in workflows}
    try:
        plugins = plugin_builder(ledger["entries"])
    except Exception as exc:
        raise ValueError("campaign_profile_plugin_builder_failed") from exc
    if isinstance(plugins, (str, bytes)):
        raise ValueError("campaign_profile_plugins_invalid")
    plugin_by_campaign = {
        plugin.campaign_key: plugin for plugin in plugins if hasattr(plugin, "campaign_key")
    }
    observations = surfaces + workflows
    explicit = [_safe_gap(item) for item in explicit_gaps if item]
    nodes: list[HypothesisDAGNode] = []
    edges: list[HypothesisDAGEdge] = []
    entries: list[CampaignPlanEntry] = []
    all_gaps: list[str] = list(explicit)

    for campaign in ledger["entries"]:
        key = str(campaign["key"])
        campaign_id = f"campaign:{key}"
        raw_surfaces = campaign.get("surfaces", ())
        if not isinstance(raw_surfaces, (list, tuple, set)):
            raise ValueError("campaign_profile_campaign_surfaces_invalid")
        tokens = {str(x).lower() for x in raw_surfaces}

        matches = [item for item in observations if tokens & _observation_tokens(item)]
        refs = [_observation_ref(item, f"surface:{index}") for index, item in enumerate(matches)][
            :20
        ]
        gaps: list[str] = []
        status = str(campaign.get("status", "not_observed"))
        if not campaign.get("validator_id"):
            gaps.append(f"missing-validator:{key}")
        if not refs and status == "not_observed":
            gaps.append(f"missing-surface:{key}")
        if status.startswith("blocked"):
            gaps.append(f"{status}:{key}")
        if any("identity" in str(item).lower() for item in raw_surfaces) and not any(
            _observation_tokens(item) & {"identity", "authenticated", "role"}
            for item in workflows + surfaces
        ):
            gaps.append(f"missing-identity-context:{key}")
        entry = CampaignPlanEntry(
            id=int(campaign["id"]),
            key=key,
            surfaces=list(raw_surfaces),
            validator=campaign.get("validator"),
            validator_id=campaign.get("validator_id"),
            plugin_id=(plugin_by_campaign[key].plugin_id if key in plugin_by_campaign else None),
            evidence_schema=(
                plugin_by_campaign[key].evidence_schema
                if key in plugin_by_campaign
                else "EvidenceLedgerEntry:v1"
            ),
            status=status,
            matched_observation_refs=refs,
            gaps=list(dict.fromkeys(gaps))[:12],
            contract=_contract(
                key,
                status=status,
                gaps=gaps,
                execution_contracts=resolved_contracts,
                observed_preconditions=(
                    list(
                        (
                            resolved_contracts.get(key)
                            if isinstance(resolved_contracts.get(key), Mapping)
                            else _CONTRACTS.get(key, _GENERIC_CONTRACT)
                        ).get(
                            "preconditions",
                            _CONTRACTS.get(key, _GENERIC_CONTRACT).get("preconditions", []),
                        )
                    )
                    if refs
                    else []
                ),
            ),
        )
        entries.append(entry)
        nodes.append(
            HypothesisDAGNode(
                node_id=campaign_id,
                node_type="campaign",
                ref=key,
                status=status,
                metadata={
                    "validator_id": campaign.get("validator_id"),
                    "surfaces": list(raw_surfaces),
                },
            )
        )
        for ref in refs:
            observation_id = f"observation:{ref}"
            if not any(node.node_id == observation_id for node in nodes):
                nodes.append(
                    HypothesisDAGNode(
                        node_id=observation_id,
                        node_type=(
                            "workflow_observation"
                            if ref in workflow_ref_set
                            else "surface_observation"
                        ),
                        ref=ref,
                        status="observed",
                    )
                )
            edges.append(
                HypothesisDAGEdge(
                    source=observation_id,
                    target=campaign_id,
                    relation="observation_supports_campaign",
                )
            )
        for gap in entry.gaps:
            gap_id = f"gap:{gap}"
            if not any(node.node_id == gap_id for node in nodes):
                nodes.append(
                    HypothesisDAGNode(
                        node_id=gap_id,
                        node_type="coverage_gap",
                        ref=gap,
                        status="open",
                    )
                )
            edges.append(
                HypothesisDAGEdge(
                    source=campaign_id,
                    target=gap_id,
                    relation="campaign_blocked_by_gap",
                )
            )
        all_gaps.extend(entry.gaps)

    summary: dict[str, int] = {}
    for entry in entries:
        summary[entry.status] = summary.get(entry.status, 0) + 1
    result = CampaignPlannerResult(
        target_url=target_url,
        entries=entries,
        nodes=nodes,
        edges=edges,
        coverage_gaps=list(dict.fromkeys(all_gaps))[:200],
        summary=summary,
    )
    return result.model_dump(mode="json")


__all__ = ["build_campaign_plan"]
