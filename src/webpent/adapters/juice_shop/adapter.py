"""Juice Shop target adapter.

This module owns Juice Shop routes, case bindings, and semantic contracts. The
shared proof machinery remains target agnostic and receives this adapter
explicitly at orchestration time.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from webpent.profiles.juice_shop.cases import (
    JUICE_SHOP_SAFE_CASES,
    get_juice_shop_safe_case,
)
from webpent.shared.semantic_observations import SemanticProfileRegistry
from webpent.shared.target_adapters import (
    RegisteredTargetAdapter,
    TargetCaseBinding,
    TargetManifest,
)
from webpent.shared.workflow_contracts import READ_ONLY_NAVIGATION, TYPED_SEARCH

JUICE_SHOP_ORIGIN = "http://127.0.0.1:3000"

# Frozen benchmark artifacts retain their historical target-local names. This
# compatibility map is intentionally owned by the Juice Shop adapter and is not
# imported by generic runners or proof code.
JUICE_SHOP_WORKFLOW_COMPATIBILITY = {
    "juice-shop-readonly-navigation": READ_ONLY_NAVIGATION,
    "juice-shop-read-only-navigation": READ_ONLY_NAVIGATION,
    "juice-shop-mat-search": TYPED_SEARCH,
}


def canonical_workflow_id(workflow_id: str) -> str | None:
    """Translate a frozen Juice Shop workflow name into a generic contract."""
    value = str(workflow_id or "").strip()
    if value in JUICE_SHOP_WORKFLOW_COMPATIBILITY:
        return JUICE_SHOP_WORKFLOW_COMPATIBILITY[value]
    if value in {READ_ONLY_NAVIGATION, TYPED_SEARCH}:
        return value
    return None

JUICE_SHOP_SEMANTIC_PROFILES = SemanticProfileRegistry(
    {
        "juice.exposed_metrics.v1": {
            "target_family": "juice_shop",
            "promotable": True,
            "rule": "prometheus_publication",
            "reason": "bounded_prometheus_publication_shape_with_negative_control",
        },
        "juice.error_disclosure.v1": {
            "target_family": "juice_shop",
            "promotable": True,
            "rule": "verbose_server_error",
            "reason": "bounded_verbose_error_shape_with_negative_control",
        },
        "juice.access_log.v1": {
            "target_family": "juice_shop",
            "promotable": True,
            "rule": "access_log_shape",
            "reason": "bounded_public_access_log_shape_with_independent_control",
        },
    }
)

_CASE_SEMANTIC_PROFILES = {
    "juice.access_log_disclosure.v1": "juice.access_log.v1",
    "juice.exposed_metrics.v1": "juice.exposed_metrics.v1",
    "juice.error_handling.v1": "juice.error_disclosure.v1",
}
_APPROVED_ORACLE_CASES = frozenset(_CASE_SEMANTIC_PROFILES)


class JuiceShopTargetAdapter:
    """Explicit case and semantic registry for the loopback Juice Shop target."""

    target_id = "owasp_juice_shop"
    target_origin = JUICE_SHOP_ORIGIN
    semantic_profiles = JUICE_SHOP_SEMANTIC_PROFILES

    def workflow_ids(self) -> tuple[str, ...]:
        return (READ_ONLY_NAVIGATION, TYPED_SEARCH)

    def workflow_executors(self) -> dict[str, Any]:
        return {TYPED_SEARCH: _execute_juice_shop_mat_search}

    def case_ids(self) -> tuple[str, ...]:
        return tuple(case.case_id for case in JUICE_SHOP_SAFE_CASES)

    def case(self, case_id: str) -> TargetCaseBinding | None:
        try:
            case = get_juice_shop_safe_case(case_id)
        except KeyError:
            return None
        return TargetCaseBinding(
            case_id=case.case_id,
            operation=case.operation,
            path=case.path,
            oracle_id=case.oracle_id,
            workflow_id=(
                TYPED_SEARCH if case.operation == "typed_search" else READ_ONLY_NAVIGATION
            ),
            semantic_profile=self.semantic_profile_for_case(case.case_id),
            scoring_status=(
                "oracle_approved_partial"
                if case.case_id in _APPROVED_ORACLE_CASES
                else "not_scored"
            ),
        )

    def semantic_profile_for_case(self, case_id: str) -> str | None:
        return _CASE_SEMANTIC_PROFILES.get(str(case_id or "").strip())

    def accepts_origin(self, origin: str) -> bool:
        return _normalize_origin(origin) == self.target_origin


def _execute_juice_shop_mat_search(
    page: Any,
    probe_value: str,
    timeout_ms: int,
) -> str | None:
    """Execute the reviewed, read-only Juice Shop MAT search workflow."""

    host = page.locator("app-mat-search-bar#searchQuery").first
    fields = host.locator("input") if host.count() > 0 else None
    field_visible = bool(
        fields is not None
        and fields.count() > 0
        and fields.first.is_visible()
    )
    if not field_visible:
        opener = page.locator("button[aria-label='Open search']").first
        if opener.count() == 0 or not opener.is_visible():
            return "typed_search_opener_missing"
        opener.click(timeout=timeout_ms)
        page.wait_for_timeout(100)
        host = page.locator("app-mat-search-bar#searchQuery").first
        fields = host.locator("input") if host.count() > 0 else None
    if host.count() == 0 or not host.is_visible():
        return "typed_search_host_missing"
    if fields is None:
        return "typed_search_input_missing"
    for index in range(min(fields.count(), 20)):
        field = fields.nth(index)
        if field.is_visible():
            field.fill(probe_value, timeout=timeout_ms)
            field.press("Enter", timeout=timeout_ms)
            return None
    return "validator_input_field_missing"


JUICE_SHOP_TARGET_ADAPTER = JuiceShopTargetAdapter()
JUICE_SHOP_TARGET_REGISTRATION = RegisteredTargetAdapter(
    adapter=JUICE_SHOP_TARGET_ADAPTER,
    source="webpent.adapters.juice_shop.adapter",
    version="1",
    policy_ref="local-loopback-read-only-juice-shop",
    proof_contract="central-causal-negative-sealed-replay-v1",
    manifest=TargetManifest(
        target_id="owasp_juice_shop",
        adapter_version="1",
        supported_capabilities=frozenset(
            {"read_only_navigation", "typed_search", "semantic_observation"}
        ),
        supported_case_types=frozenset({"navigate", "typed_search"}),
        authorization_requirements=("explicit_authorization", "loopback_origin"),
        allowed_scope=(JUICE_SHOP_ORIGIN,),
        redaction_policy="metadata_only_no_raw_bodies_or_credentials",
        cleanup_policy="browser_context_dispose_without_target_mutation",
    ),
    metadata={"target_family": "owasp_juice_shop"},
)


def _normalize_origin(value: str) -> str:
    parsed = urlsplit(str(value or ""))
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    port = parsed.port
    default = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
        parsed.scheme.lower() == "https" and port in {None, 443}
    )
    return f"{parsed.scheme.lower()}://{parsed.hostname.lower()}" + (
        "" if default else f":{port}"
    )


__all__ = [
    "JUICE_SHOP_ORIGIN",
    "JUICE_SHOP_SEMANTIC_PROFILES",
    "JUICE_SHOP_TARGET_ADAPTER",
    "JUICE_SHOP_TARGET_REGISTRATION",
    "JUICE_SHOP_WORKFLOW_COMPATIBILITY",
    "JuiceShopTargetAdapter",
    "canonical_workflow_id",
]
