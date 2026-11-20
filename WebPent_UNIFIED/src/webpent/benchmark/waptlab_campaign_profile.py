"""Explicit WAPTLab campaign profile.

This module is intentionally outside ``webpent.shared``.  Its identifiers,
surface hints, and proof contracts are compatibility data for the authorized
WAPTLab benchmark only; generic planning must receive a profile explicitly and
never infer this matrix from a target URL.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Final

from webpent.shared.campaigns import build_campaign_ledger
from webpent.shared.target_adapters import CampaignProfileSpec
from webpent.shared.validator_plugins import (
    ValidatorPluginSpec,
    build_validator_plugin_registry,
)

VERTICAL_PROOF_CONTRACTS: Final[dict[str, dict[str, Any]]] = {
    "download_idor": {
        "oracle_family": "idor",
        "proof_contract": "owner_foreign_access",
        "negative_control": "foreign_denied_control",
    },
    "tenant_context_switching": {
        "oracle_family": "idor",
        "proof_contract": "tenant_owner_foreign_access",
        "negative_control": "same_tenant_authorized_control",
    },
    "stored_profile_xss": {
        "oracle_family": "stored_xss",
        "proof_contract": "browser_execution_marker",
        "negative_control": "encoded_and_literal_safe_controls",
    },
    "image_fetch_ssrf": {
        "oracle_family": "ssrf",
        "proof_contract": "correlated_oob_callback",
        "negative_control": "absent_control_callback",
    },
    "csv_ingestion_sqli": {
        "oracle_family": "csv_sqli",
        "proof_contract": "controlled_parser_dataflow_differential",
        "negative_control": "inert_csv_control",
    },
}

WAPTLAB_EXECUTION_CONTRACTS: Final[dict[str, dict[str, Any]]] = {
    "header_sqli": {
        "preconditions": ["header injection point is in scope", "baseline response captured"],
        "identities": ["anonymous", "owner"],
        "actions": ["replay a harmless header differential", "compare downstream response"],
        "payload_strategy": ["non-destructive SQLi canary in X-Forwarded-For"],
        "oracle": ["controlled response differential", "no generic parser error alone"],
        "negative_control": ["equivalent benign header value"],
        "cleanup": ["no persistent state expected"],
        "budget": 2,
    },
    "csv_ingestion_sqli": {
        "preconditions": ["authorized CSV upload or import workflow", "worker result observable"],
        "identities": ["owner", "tenant_admin"],
        "actions": ["submit a bounded fixture", "compare worker outcome"],
        "payload_strategy": ["single-field non-destructive SQLi differential"],
        "oracle": ["causal worker evidence", "correlated result change"],
        "negative_control": ["same CSV with inert value"],
        "cleanup": ["remove fixture artifact", "record worker cleanup status"],
        "budget": 3,
    },
    "jwt_path_traversal": {
        "preconditions": ["token-bearing path or download route", "scope allows read-only replay"],
        "identities": ["owner", "foreign_user"],
        "actions": ["compare canonical and encoded object references"],
        "payload_strategy": ["bounded traversal encoding variants"],
        "oracle": ["authorization-preserving differential", "object ownership mismatch"],
        "negative_control": ["owner object with canonical token"],
        "cleanup": ["read-only; no mutation"],
        "budget": 3,
    },
    "double_slash_redirect": {
        "preconditions": ["redirect-capable route observed"],
        "identities": ["anonymous"],
        "actions": ["compare canonical and double-slash paths"],
        "payload_strategy": ["same-origin redirect canary only"],
        "oracle": ["location and final origin comparison"],
        "negative_control": ["canonical same-origin path"],
        "cleanup": ["no persistent state expected"],
        "budget": 2,
    },
    "oauth_redirect_uri": {
        "preconditions": ["OAuth/OIDC flow and callback observed", "controlled identity available"],
        "identities": ["anonymous", "owner"],
        "actions": ["replay state/PKCE variations", "verify callback origin"],
        "payload_strategy": ["approved same-origin callback canary"],
        "oracle": ["state binding", "PKCE binding", "callback origin"],
        "negative_control": ["invalid state and mismatched verifier"],
        "cleanup": ["revoke temporary session", "remove test authorization"],
        "budget": 4,
    },
    "download_idor": {
        "preconditions": ["download object reference observed", "two identities available"],
        "identities": ["owner", "foreign_user"],
        "actions": ["compare owner and foreign-object reads"],
        "payload_strategy": ["bounded opaque identifier substitution"],
        "oracle": ["foreign denial or equivalent safe response", "no object disclosure"],
        "negative_control": ["owner reads own object"],
        "cleanup": ["read-only; delete no user data"],
        "budget": 3,
    },
    "tenant_context_switching": {
        "preconditions": [
            "tenant marker or switch workflow observed",
            "tenant identities configured",
        ],
        "identities": ["tenant_admin", "global_admin", "foreign_user"],
        "actions": ["compare tenant A/B context", "verify post-switch authorization"],
        "payload_strategy": ["bounded tenant-context transition"],
        "oracle": ["tenant isolation invariant", "context and object ownership"],
        "negative_control": ["same-tenant authorized operation"],
        "cleanup": ["restore original tenant context", "revoke temporary sessions"],
        "budget": 4,
    },
    "training_email_ssti": {
        "preconditions": [
            "training/email template workflow observed",
            "approval for rendered fixture",
        ],
        "identities": ["owner", "tenant_admin"],
        "actions": ["submit inert template marker", "compare rendered output"],
        "payload_strategy": ["non-executing expression canary"],
        "oracle": ["server-side rendering differential", "no execution claim from reflection"],
        "negative_control": ["literal marker"],
        "cleanup": ["remove test template/message"],
        "budget": 3,
    },
    "export_blade_ssti": {
        "preconditions": ["export/template surface observed", "artifact cleanup available"],
        "identities": ["owner", "tenant_admin"],
        "actions": ["request bounded export", "inspect generated artifact"],
        "payload_strategy": ["inert template expression marker"],
        "oracle": ["rendered server-side marker with causal artifact"],
        "negative_control": ["literal export field"],
        "cleanup": ["delete generated artifact"],
        "budget": 3,
    },
    "swagger_url_ssrf": {
        "preconditions": ["Swagger/OpenAPI URL fetch observed", "approved OOB/local canary"],
        "identities": ["anonymous", "owner"],
        "actions": ["submit isolated fetch canary", "correlate OOB event"],
        "payload_strategy": ["scope-approved canary URL only"],
        "oracle": ["OOB correlation with request fingerprint"],
        "negative_control": ["same-origin documentation URL"],
        "cleanup": ["expire canary", "remove imported specification"],
        "budget": 3,
    },
    "image_fetch_ssrf": {
        "preconditions": ["image URL fetch workflow observed", "approved OOB/local canary"],
        "identities": ["owner"],
        "actions": ["submit isolated image fetch canary", "correlate fetch evidence"],
        "payload_strategy": ["approved canary URL, no internal targets"],
        "oracle": ["OOB/browser event correlation"],
        "negative_control": ["owned static image URL"],
        "cleanup": ["remove profile image and expire canary"],
        "budget": 3,
    },
    "stored_profile_xss": {
        "preconditions": ["profile update and view workflow observed", "test account available"],
        "identities": ["owner", "viewer"],
        "actions": ["store inert marker", "view through approved browser"],
        "payload_strategy": ["non-executing context marker first"],
        "oracle": ["sanitized vs unsanitized DOM evidence"],
        "negative_control": ["literal text marker"],
        "cleanup": ["restore profile field"],
        "budget": 3,
    },
    "quoted_field_xss": {
        "preconditions": ["quoted attribute field observed", "browser evidence available"],
        "identities": ["owner"],
        "actions": ["submit inert attribute marker", "compare rendered attribute"],
        "payload_strategy": ["context-specific non-executing marker"],
        "oracle": ["attribute encoding differential"],
        "negative_control": ["literal quoted value"],
        "cleanup": ["restore field value"],
        "budget": 2,
    },
    "elasticsearch_snapshot_traversal": {
        "preconditions": ["in-scope snapshot/service surface observed", "read-only approval"],
        "identities": ["anonymous", "service_account"],
        "actions": ["inspect bounded snapshot metadata", "compare canonical paths"],
        "payload_strategy": ["read-only path normalization variants"],
        "oracle": ["unexpected snapshot metadata access"],
        "negative_control": ["authorized snapshot metadata"],
        "cleanup": ["no mutation; close service session"],
        "budget": 2,
    },
    "public_backup_disclosure": {
        "preconditions": ["backup/artifact route observed", "artifact ownership established"],
        "identities": ["anonymous", "owner"],
        "actions": ["request metadata-only artifact probe"],
        "payload_strategy": ["known test artifact identifier"],
        "oracle": ["public access to owned test backup"],
        "negative_control": ["nonexistent artifact"],
        "cleanup": ["remove test artifact"],
        "budget": 2,
    },
    "laravel_app_debug": {
        "preconditions": ["error response or Laravel fingerprint observed"],
        "identities": ["anonymous", "owner"],
        "actions": ["trigger bounded harmless error", "compare redacted response"],
        "payload_strategy": ["invalid read-only parameter"],
        "oracle": ["framework debug disclosure beyond expected baseline"],
        "negative_control": ["normal endpoint response"],
        "cleanup": ["no persistent state expected"],
        "budget": 2,
    },
    "frontend_dependency_exposure": {
        "preconditions": ["JavaScript bundle or lockfile reference observed"],
        "identities": ["anonymous"],
        "actions": ["collect version metadata", "compare advisory intelligence"],
        "payload_strategy": ["none; passive artifact analysis"],
        "oracle": ["version/evidence mapping with source hash"],
        "negative_control": ["unrelated asset"],
        "cleanup": ["no target mutation"],
        "budget": 1,
    },
    "public_elasticsearch_exposure": {
        "preconditions": ["in-scope Elasticsearch service fingerprint observed"],
        "identities": ["anonymous", "service_account"],
        "actions": ["collect bounded cluster/index metadata"],
        "payload_strategy": ["read-only metadata request"],
        "oracle": ["unauthorized metadata exposure"],
        "negative_control": ["authorized metadata baseline"],
        "cleanup": ["close connection"],
        "budget": 2,
    },
    "oob_xxe": {
        "preconditions": ["XML parser route observed", "approved local/OOB canary"],
        "identities": ["owner", "tenant_admin"],
        "actions": ["submit bounded XML fixture", "correlate parser event"],
        "payload_strategy": ["safe external-entity canary without local targets"],
        "oracle": ["causal OOB correlation or parser-safe rejection"],
        "negative_control": ["equivalent XML without entity"],
        "cleanup": ["remove uploaded XML and expire canary"],
        "budget": 3,
    },
    "xslt_injection": {
        "preconditions": ["XSLT transform workflow observed", "approval for inert fixture"],
        "identities": ["owner", "tenant_admin"],
        "actions": ["submit bounded transform", "inspect output and parser telemetry"],
        "payload_strategy": ["non-destructive document() marker"],
        "oracle": ["causal transform-side access evidence"],
        "negative_control": ["baseline transform"],
        "cleanup": ["remove transform fixture and output"],
        "budget": 3,
    },
}

WAPTLAB_CAMPAIGNS: Final[tuple[dict[str, Any], ...]] = (
    {
        "id": 1,
        "key": "header_sqli",
        "surfaces": ("headers", "query", "logging"),
        "validator": "sqli",
    },
    {
        "id": 2,
        "key": "csv_ingestion_sqli",
        "surfaces": ("multipart", "csv", "worker"),
        "validator": "sqli",
    },
    {
        "id": 3,
        "key": "jwt_path_traversal",
        "surfaces": ("jwt", "path", "download"),
        "validator": "path_traversal",
    },
    {
        "id": 4,
        "key": "double_slash_redirect",
        "surfaces": ("redirect", "path"),
        "validator": "open_redirect",
    },
    {
        "id": 5,
        "key": "oauth_redirect_uri",
        "surfaces": ("oauth", "redirect", "callback"),
        "validator": "open_redirect",
    },
    {
        "id": 6,
        "key": "download_idor",
        "surfaces": ("download", "object", "identity"),
        "validator": "idor",
    },
    {
        "id": 7,
        "key": "tenant_context_switching",
        "surfaces": ("tenant", "identity", "object"),
        "validator": "idor",
    },
    {
        "id": 8,
        "key": "training_email_ssti",
        "surfaces": ("template", "email", "workflow"),
        "validator": "ssti",
    },
    {
        "id": 9,
        "key": "export_blade_ssti",
        "surfaces": ("export", "template", "download"),
        "validator": "ssti",
    },
    {
        "id": 10,
        "key": "swagger_url_ssrf",
        "surfaces": ("swagger", "openapi", "url"),
        "validator": "ssrf",
    },
    {
        "id": 11,
        "key": "image_fetch_ssrf",
        "surfaces": ("profile", "image", "url"),
        "validator": "ssrf",
    },
    {
        "id": 12,
        "key": "stored_profile_xss",
        "surfaces": ("profile", "stored", "browser"),
        "validator": "xss",
    },
    {
        "id": 13,
        "key": "quoted_field_xss",
        "surfaces": ("profile", "form", "attribute"),
        "validator": "xss",
    },
    {
        "id": 14,
        "key": "elasticsearch_snapshot_traversal",
        "surfaces": ("elasticsearch", "snapshot", "service"),
        "validator": None,
    },
    {
        "id": 15,
        "key": "public_backup_disclosure",
        "surfaces": ("backup", "artifact", "download"),
        "validator": "info_disclosure",
    },
    {
        "id": 16,
        "key": "laravel_app_debug",
        "surfaces": ("error", "debug", "laravel"),
        "validator": "info_disclosure",
    },
    {
        "id": 17,
        "key": "frontend_dependency_exposure",
        "surfaces": ("javascript", "sbom", "bundle"),
        "validator": "javascript",
    },
    {
        "id": 18,
        "key": "public_elasticsearch_exposure",
        "surfaces": ("elasticsearch", "service", "network"),
        "validator": "info_disclosure",
    },
    {"id": 19, "key": "oob_xxe", "surfaces": ("xml", "multipart", "oob"), "validator": "xxe"},
    {
        "id": 20,
        "key": "xslt_injection",
        "surfaces": ("xml", "xslt", "multipart"),
        "validator": None,
    },
)


def build_waptlab_campaign_ledger(
    *,
    observed_campaigns: set[str] | None = None,
    blocked_by: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build the explicit WAPTLab compatibility campaign ledger."""
    return build_campaign_ledger(
        WAPTLAB_CAMPAIGNS,
        source="waptlab_audit_campaign_matrix",
        proof_contracts=VERTICAL_PROOF_CONTRACTS,
        observed_campaigns=observed_campaigns,
        blocked_by=blocked_by,
    )


def build_waptlab_validator_plugin_registry(
    campaigns: Iterable[Mapping[str, Any]] | None = None,
) -> tuple[ValidatorPluginSpec, ...]:
    """Build validator contracts for the explicit WAPTLab profile."""
    selected = WAPTLAB_CAMPAIGNS if campaigns is None else campaigns
    return build_validator_plugin_registry(selected)


def build_waptlab_campaign_profile() -> CampaignProfileSpec:
    """Return the non-serialized profile provider used by explicit adapters."""
    return CampaignProfileSpec(
        profile_id="waptlab",
        source="webpent.benchmark.waptlab_campaign_profile",
        version="1",
        ledger_builder=build_waptlab_campaign_ledger,
        plugin_builder=build_waptlab_validator_plugin_registry,
        execution_contracts=WAPTLAB_EXECUTION_CONTRACTS,
    )


__all__ = [
    "VERTICAL_PROOF_CONTRACTS",
    "WAPTLAB_EXECUTION_CONTRACTS",
    "WAPTLAB_CAMPAIGNS",
    "build_waptlab_campaign_ledger",
    "build_waptlab_campaign_profile",
    "build_waptlab_validator_plugin_registry",
]
