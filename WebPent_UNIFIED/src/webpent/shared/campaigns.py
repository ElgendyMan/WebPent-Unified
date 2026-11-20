"""Application-aware campaign inventory and coverage accounting.

The inventory is deliberately declarative.  It does not execute probes and it
never turns a campaign into a confirmed finding.  A campaign can only become
``tested`` when an executor records evidence through the existing state
channels; otherwise the ledger exposes why coverage is absent.
"""

from __future__ import annotations

from typing import Any, Final

from webpent.agents.validator.registry import validator_id_for

# Campaigns remain human-review-only only when no deterministic live
# validator contract exists.  Vertical campaigns that reuse a registered base
# validator (for example IDOR or information disclosure) must still enter the
# normal planner/executor path; strict evidence/proof gates decide confirmation.
# The two former members (elasticsearch_snapshot_traversal, xslt_injection)
# left this set when the validator coverage engine promoted them to live
# validators (postp0_checks.py section 6). Their candidate supply is still a
# producer gap — tracked in the traceability docs, not hidden here.
CAMPAIGN_HUMAN_REVIEW: Final[frozenset[str]] = frozenset()

# Target-specific campaign matrices and proof contracts belong in explicit
# benchmark/profile modules.  Shared code accepts them only as injected data.

# Target-neutral campaigns are intentionally surface-driven.  They describe
# only validator-backed classes and never assert that a target exposes them.
GENERIC_CAMPAIGNS: Final[tuple[dict[str, Any], ...]] = (
    {
        "id": 1,
        "key": "xss_reflected",
        "surfaces": ("form", "input", "query", "xss"),
        "validator": "xss",
    },
    {
        "id": 2,
        "key": "xss_stored",
        "surfaces": ("profile", "stored", "browser"),
        "validator": "xss",
    },
    {
        "id": 3,
        "key": "sqli_param",
        "surfaces": ("query", "form", "search", "sqli"),
        "validator": "sqli",
    },
    {
        "id": 4,
        "key": "idor_object",
        "surfaces": ("object", "id", "identity", "idor"),
        "validator": "idor",
    },
    {
        "id": 5,
        "key": "auth_bypass_jwt",
        "surfaces": ("jwt", "auth", "token", "auth_bypass"),
        "validator": "auth_bypass",
    },
    {
        "id": 6,
        "key": "open_redirect",
        "surfaces": ("redirect", "url", "callback", "open_redirect"),
        "validator": "open_redirect",
    },
    {
        "id": 7,
        "key": "info_disclosure",
        "surfaces": ("error", "debug", "api", "info_disclosure"),
        "validator": "info_disclosure",
    },
    {
        "id": 8,
        "key": "ssrf_url_param",
        "surfaces": ("url", "fetch", "import", "ssrf"),
        "validator": "ssrf",
    },
    {
        "id": 9,
        "key": "api_issue",
        "surfaces": ("api", "rest", "json", "api_issue"),
        "validator": "api_issue",
    },
    {
        "id": 10,
        "key": "path_traversal",
        "surfaces": ("path", "file", "download", "path_traversal"),
        "validator": "path_traversal",
    },
)


def _status_for_campaign(campaign: dict[str, Any], observed: set[str]) -> str:
    campaign_key = str(campaign["key"])
    validator = campaign.get("validator")
    if campaign_key in CAMPAIGN_HUMAN_REVIEW:
        return "missing-validator"
    if validator is None or validator_id_for(str(validator)) is None:
        return "missing-validator"
    if campaign["key"] in observed:
        return "tested"
    return "not_observed"


def build_campaign_ledger(
    campaigns: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    *,
    source: str,
    proof_contracts: dict[str, dict[str, Any]] | None = None,
    observed_campaigns: set[str] | None = None,
    blocked_by: dict[str, str] | None = None,
) -> dict[str, Any]:
    observed = set(observed_campaigns or ())
    blocked = blocked_by or {}
    entries: list[dict[str, Any]] = []
    for campaign in campaigns:
        key = str(campaign["key"])
        status = _status_for_campaign(campaign, observed)
        if key in blocked:
            status = str(blocked[key])
        entries.append(
            {
                "id": int(campaign["id"]),
                "key": key,
                "surfaces": list(campaign["surfaces"]),
                "validator": campaign.get("validator"),
                "validator_id": validator_id_for(str(campaign["validator"]))
                if campaign.get("validator")
                else None,
                "proof_contract": (proof_contracts or {}).get(key, {}).get("proof_contract"),
                "oracle_family": (proof_contracts or {}).get(key, {}).get("oracle_family"),
                "negative_control": (proof_contracts or {}).get(key, {}).get("negative_control"),
                "status": status,
                "disposition": "human_review_only" if status == "missing-validator" else status,
                "human_review_only": status == "missing-validator",
                "evidence_complete": status == "tested",
            }
        )

    summary: dict[str, int] = {}
    for entry in entries:
        status = str(entry["status"])
        summary[status] = summary.get(status, 0) + 1
    return {"version": 1, "source": source, "entries": entries, "summary": summary}


def build_generic_campaign_ledger(
    *,
    observed_campaigns: set[str] | None = None,
    blocked_by: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a validator-backed inventory for arbitrary discovered surfaces."""
    return build_campaign_ledger(
        GENERIC_CAMPAIGNS,
        source="generic_surface_campaign_inventory",
        observed_campaigns=observed_campaigns,
        blocked_by=blocked_by,
    )


__all__ = [
    "CAMPAIGN_HUMAN_REVIEW",
    "GENERIC_CAMPAIGNS",
    "build_campaign_ledger",
    "build_generic_campaign_ledger",
]
