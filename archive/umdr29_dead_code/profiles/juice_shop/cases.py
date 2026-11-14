"""Allowlisted, read-only Juice Shop benchmark case registry.

This registry is a source-backed execution inventory, not an approval record and
not a vulnerability verdict. Every case remains pending independent review until
an external reviewer freezes the mapping and oracle contract.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Final, Literal
from urllib.parse import urlsplit

JuiceOperation = Literal["navigate", "typed_search"]


@dataclass(frozen=True)
class JuiceShopSafeCase:
    """One bounded local observation plan with no credentials or raw data."""

    case_id: str
    challenge_key: str
    category: str
    path: str
    operation: JuiceOperation
    oracle_id: str
    source_ref: str
    safe_to_execute: bool = True
    mapping_status: str = "pending_independent_review"
    oracle_status: str = "pending_safe_oracle_review"

    def __post_init__(self) -> None:
        if not self.case_id.startswith("juice."):
            raise ValueError("juice_case_id_must_be_namespaced")
        if not self.challenge_key or not self.category:
            raise ValueError("juice_case_identity_required")
        parsed = urlsplit(self.path)
        if parsed.scheme or parsed.netloc or not parsed.path.startswith("/"):
            raise ValueError("juice_case_path_must_be_relative")
        if "#" in self.path and self.operation != "typed_search":
            raise ValueError("juice_case_fragment_not_allowed")
        if self.operation == "typed_search" and not self.oracle_id.startswith("dom."):
            raise ValueError("typed_search_requires_dom_oracle")
        if not self.oracle_id or not self.source_ref:
            raise ValueError("juice_case_oracle_and_source_required")


_SOURCE_CATALOG = (
    "https://github.com/juice-shop/juice-shop/blob/master/"
    "data/static/challenges.yml"
)
_SOURCE_ROUTES = (
    "https://github.com/juice-shop/juice-shop/tree/master/routes"
)
_SOURCE_SERVER = "https://github.com/juice-shop/juice-shop/blob/master/server.ts"
_SOURCE_SEARCH = (
    "https://github.com/juice-shop/juice-shop/blob/master/"
    "frontend/src/app/search-result/search-result.component.ts"
)


ACCESS_LOG_PATH_TEMPLATE = "/support/logs/access.log.<UTC-date>"


def _current_access_log_path() -> str:
    """Resolve the local Juice Shop's date-rotated access log without I/O."""
    date = datetime.now(timezone.utc).date().isoformat()
    return f"/support/logs/access.log.{date}"


def canonical_mapping_cases() -> list[dict[str, object]]:
    """Return stable mapping identities without changing runtime paths.

    The access log is date-rotated by Juice Shop. Its runtime case keeps the
    concrete UTC-date path for local execution, while governance hashes use the
    target-local template so the mapping identity does not change each day.
    """
    canonical_cases: list[dict[str, object]] = []
    for case in JUICE_SHOP_SAFE_CASES:
        item = asdict(case)
        if case.case_id == "juice.access_log_disclosure.v1":
            item["path"] = ACCESS_LOG_PATH_TEMPLATE
        canonical_cases.append(item)
    return canonical_cases


# These are deliberately read-only candidates. They do not contain payloads,
# credentials, external destinations, or state-changing requests.
JUICE_SHOP_SAFE_CASES: Final[tuple[JuiceShopSafeCase, ...]] = (
    JuiceShopSafeCase(
        case_id="juice.directory_listing.v1",
        challenge_key="directoryListingChallenge",
        category="Sensitive Data Exposure",
        path="/ftp",
        operation="navigate",
        oracle_id="http.read_only.resource_existence_and_metadata",
        source_ref=_SOURCE_ROUTES,
    ),
    JuiceShopSafeCase(
        case_id="juice.forgotten_backup.v1",
        challenge_key="forgottenBackupChallenge",
        category="Sensitive Data Exposure",
        path="/ftp/coupons_2013.md.bak",
        operation="navigate",
        oracle_id="http.read_only.resource_existence_and_metadata",
        source_ref=_SOURCE_ROUTES,
    ),
    JuiceShopSafeCase(
        case_id="juice.access_log_disclosure.v1",
        challenge_key="accessLogDisclosureChallenge",
        category="Observability Failures",
        path=_current_access_log_path(),
        operation="navigate",
        oracle_id="http.read_only.log_resource_metadata",
        source_ref=_SOURCE_SERVER,
    ),
    JuiceShopSafeCase(
        case_id="juice.misplaced_signature_file.v1",
        challenge_key="misplacedSignatureFileChallenge",
        category="Observability Failures",
        path="/ftp/suspicious_errors.yml",
        operation="navigate",
        oracle_id="http.read_only.signature_resource_metadata",
        source_ref=_SOURCE_ROUTES,
    ),
    JuiceShopSafeCase(
        case_id="juice.exposed_metrics.v1",
        challenge_key="exposedMetricsChallenge",
        category="Observability Failures",
        path="/metrics",
        operation="navigate",
        oracle_id="http.read_only.metrics_publication",
        source_ref=_SOURCE_SERVER,
    ),
    JuiceShopSafeCase(
        case_id="juice.security_policy.v1",
        challenge_key="securityPolicyChallenge",
        category="Miscellaneous",
        path="/security.txt",
        operation="navigate",
        oracle_id="http.read_only.policy_resource_metadata",
        source_ref=_SOURCE_SERVER,
    ),
    JuiceShopSafeCase(
        case_id="juice.error_handling.v1",
        challenge_key="errorHandlingChallenge",
        category="Security Misconfiguration",
        path="/rest/qwertz",
        operation="navigate",
        oracle_id="http.read_only.error_disclosure_metadata",
        source_ref=_SOURCE_ROUTES,
    ),
    JuiceShopSafeCase(
        case_id="juice.redirect_local.v1",
        challenge_key="redirectCryptoCurrencyChallenge",
        category="Unvalidated Redirects",
        path="/redirect?to=http://127.0.0.1:3000/",
        operation="navigate",
        oracle_id="out_of_scope.external_destination_control",
        source_ref=_SOURCE_ROUTES,
        safe_to_execute=False,
    ),
    JuiceShopSafeCase(
        case_id="juice.privacy_policy_proof.v1",
        challenge_key="privacyPolicyProofChallenge",
        category="Security through Obscurity",
        path="/we/may/also/instruct/you/to/refuse/all/reasonably/necessary/responsibility",
        operation="navigate",
        oracle_id="http.read_only.policy_resource_metadata",
        source_ref=_SOURCE_ROUTES,
    ),
    JuiceShopSafeCase(
        case_id="juice.local_xss.v1",
        challenge_key="localXssChallenge",
        category="XSS",
        path="/",
        operation="typed_search",
        oracle_id="dom.safe_search_sink_observation",
        source_ref=_SOURCE_SEARCH,
    ),
    # Buffer candidates: they are intentionally pending and do not increase
    # approved coverage until an independent reviewer accepts their semantics.
    JuiceShopSafeCase(
        case_id="juice.well_known_security_policy.v1",
        challenge_key="securityPolicyChallenge",
        category="Miscellaneous",
        path="/.well-known/security.txt",
        operation="navigate",
        oracle_id="http.read_only.policy_resource_metadata",
        source_ref=_SOURCE_SERVER,
    ),
    JuiceShopSafeCase(
        case_id="juice.public_scoreboard_route.v1",
        challenge_key="scoreBoardChallenge",
        category="Miscellaneous",
        path="/score-board",
        operation="navigate",
        oracle_id="http.read_only.public_route_metadata",
        source_ref=_SOURCE_SERVER,
    ),
    JuiceShopSafeCase(
        case_id="juice.application_version_surface.v1",
        challenge_key="adminSectionChallenge",
        category="Sensitive Data Exposure",
        path="/rest/admin/application-version",
        operation="navigate",
        oracle_id="http.read_only.version_disclosure_metadata",
        source_ref=_SOURCE_SERVER,
        safe_to_execute=False,
        mapping_status="out_of_scope",
        oracle_status="out_of_scope",
    ),
)


def get_juice_shop_safe_case(case_id: str) -> JuiceShopSafeCase:
    """Return one exact case or fail closed."""
    for case in JUICE_SHOP_SAFE_CASES:
        if case.case_id == case_id:
            return case
    raise KeyError(f"unknown_juice_shop_safe_case:{case_id}")


def safe_case_ids() -> tuple[str, ...]:
    """Return stable registry identifiers for manifest generation."""
    return tuple(case.case_id for case in JUICE_SHOP_SAFE_CASES)


def safe_case_categories() -> frozenset[str]:
    """Return categories represented by the candidate registry."""
    return frozenset(case.category for case in JUICE_SHOP_SAFE_CASES)


__all__ = [
    "JuiceShopSafeCase",
    "JUICE_SHOP_SAFE_CASES",
    "get_juice_shop_safe_case",
    "safe_case_ids",
    "safe_case_categories",
    "ACCESS_LOG_PATH_TEMPLATE",
    "canonical_mapping_cases",
]
