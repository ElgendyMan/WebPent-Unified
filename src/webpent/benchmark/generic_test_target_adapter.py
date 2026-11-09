"""Small loopback adapter used to prove target swapping without Juice Shop.

The module is deliberately target-local. It supplies a bounded read-only case and
an observation profile to the generic proof machinery; it performs no network I/O
by itself and stores no raw responses.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from webpent.shared.semantic_observations import SemanticProfileRegistry
from webpent.shared.target_adapters import (
    RegisteredTargetAdapter,
    TargetCaseBinding,
    TargetManifest,
)
from webpent.shared.workflow_contracts import READ_ONLY_NAVIGATION

GENERIC_TEST_ORIGIN = "http://127.0.0.1:4100"
GENERIC_TEST_CASE_ID = "generic.public_observation.v1"
GENERIC_TEST_PROFILE_ID = "generic.public_observation.v1"

GENERIC_TEST_SEMANTIC_PROFILES = SemanticProfileRegistry(
    {
        GENERIC_TEST_PROFILE_ID: {
            "target_family": "generic_test_target",
            "promotable": True,
            "rule": "prometheus_publication",
            "reason": "fixture_only_profile_for_target_swap_and_proof_contract_tests",
        }
    }
)


class GenericTestTargetAdapter:
    """Explicit loopback adapter with no Juice Shop dependencies."""

    target_id = "generic_test_target"
    target_origin = GENERIC_TEST_ORIGIN
    semantic_profiles = GENERIC_TEST_SEMANTIC_PROFILES

    def workflow_ids(self) -> tuple[str, ...]:
        return (READ_ONLY_NAVIGATION,)

    def workflow_executors(self) -> dict[str, object]:
        return {}

    def case_ids(self) -> tuple[str, ...]:
        return (GENERIC_TEST_CASE_ID,)

    def case(self, case_id: str) -> TargetCaseBinding | None:
        if str(case_id or "").strip() != GENERIC_TEST_CASE_ID:
            return None
        return TargetCaseBinding(
            case_id=GENERIC_TEST_CASE_ID,
            operation="navigate",
            path="/public-info",
            oracle_id="generic.read_only.public_observation",
            workflow_id=READ_ONLY_NAVIGATION,
            semantic_profile=GENERIC_TEST_PROFILE_ID,
            scoring_status="fixture_only_not_benchmark_scored",
        )

    def semantic_profile_for_case(self, case_id: str) -> str | None:
        if str(case_id or "").strip() == GENERIC_TEST_CASE_ID:
            return GENERIC_TEST_PROFILE_ID
        return None

    def accepts_origin(self, origin: str) -> bool:
        return _normalize_origin(origin) == GENERIC_TEST_ORIGIN


GENERIC_TEST_TARGET_ADAPTER = GenericTestTargetAdapter()
GENERIC_TEST_TARGET_REGISTRATION = RegisteredTargetAdapter(
    adapter=GENERIC_TEST_TARGET_ADAPTER,
    source="webpent.benchmark.generic_test_target_adapter",
    version="1",
    policy_ref="loopback-fixture-read-only",
    proof_contract="central-causal-negative-sealed-replay-v1",
    manifest=TargetManifest(
        target_id="generic_test_target",
        adapter_version="1",
        supported_capabilities=frozenset({"read_only_navigation", "semantic_observation"}),
        supported_case_types=frozenset({"navigate"}),
        authorization_requirements=("explicit_fixture_authorization", "loopback_origin"),
        allowed_scope=(GENERIC_TEST_ORIGIN,),
        redaction_policy="metadata_only_no_raw_bodies_or_credentials",
        cleanup_policy="fixture_context_dispose_without_target_mutation",
    ),
    metadata={"target_family": "generic_test_target", "fixture_only": True},
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
    "GENERIC_TEST_CASE_ID",
    "GENERIC_TEST_ORIGIN",
    "GENERIC_TEST_PROFILE_ID",
    "GENERIC_TEST_SEMANTIC_PROFILES",
    "GENERIC_TEST_TARGET_ADAPTER",
    "GENERIC_TEST_TARGET_REGISTRATION",
    "GenericTestTargetAdapter",
]
