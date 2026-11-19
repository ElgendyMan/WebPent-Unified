# tests/lab/lcs2_sweep_support.py
"""Support primitives for the LCS-2 sweep instrument (TC-3).

The AUTHORIZED spine construction path (identical to cycle 1's runner —
resolve_production_spine, the single authoritative resolver) plus trace
stage-diffing helpers.  Nothing here touches the spine's authority
semantics; this is the caller side of the frozen contract.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from webpent.models.evidence import sha256_text  # noqa: E402


def make_orchestrator(engagement_id: str, target_url: str) -> Any:
    """Authorized spine construction — the ONLY production path (v2 SDD).

    The factory auto-detects loopback -> lab_fixture_mode and binds
    ToolBoundary.allowed_hosts to the target host.  strict-HITL default
    (DR-002 decision): auto_approve=False.
    """
    from webpent.production.production_spine import (
        ProductionSpineConfig,
        resolve_production_spine,
    )

    config = ProductionSpineConfig(
        engagement_id=engagement_id,
        target_url=target_url,
        entrypoint="direct_invoke",
        modern_spine_enabled=True,
        auto_approve=False,
    )
    orch, _trace = resolve_production_spine(config)
    return orch


def seal_principals(engagement_id: str, target_url: str) -> None:
    """Seal User_A/User_B under v2 vault keys (sprint I-2 2.3 lab pattern)."""
    from webpent.production.context_authority import ContextAuthority

    target_fp = sha256_text(target_url)[:16]
    authority = ContextAuthority(engagement_id=engagement_id,
                                 target_fingerprint=target_fp)
    authority.seal_principal_credentials(
        principal_alias="User_B", role="owner", password="password_b")
    authority.seal_principal_credentials(
        principal_alias="User_A", role="foreign-user", password="password_a")


def stages_delta(new_stages: list[Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Extract (validator_proof, promotion_proof) from a decision's new
    trace stages."""
    v_proof: dict[str, Any] = {}
    p_proof: dict[str, Any] = {}
    for stage in new_stages:
        name = getattr(stage, "stage", "")
        proof = getattr(stage, "proof", {}) or {}
        if name == "validator_adapter_executed" and not v_proof:
            v_proof = proof
        elif name == "promotion_decision" and not p_proof:
            p_proof = proof
    return v_proof, p_proof


def ensure_runtime_env() -> None:
    """Residue-aware runtime environment for out-of-pytest execution (C2b
    rule: the same env redirection pytest's conftest applies)."""
    import tempfile

    os.environ.setdefault(
        "WEBPENT_AUDIT_SECRET_KEY", "test_key_32_chars_minimum_required_1234567890")
    os.environ.setdefault(
        "CELERY_PAYLOAD_KEY", "test-only-celery-payload-key-not-for-production-use")
    os.environ.setdefault(
        "JWT_SECRET_KEY", "test-only-jwt-secret-key-not-for-production-use-000000")
    os.environ.setdefault(
        "WEBPENT_ALLOW_DIRECT_ORCHESTRATOR_CONSTRUCTION_TEST_ONLY", "1")
    os.environ.setdefault("WEBPENT_ENTRYPOINT", "cli")
    if "WEBPENT_AUDIT_ROOT" not in os.environ:
        os.environ["WEBPENT_AUDIT_ROOT"] = str(
            Path(tempfile.mkdtemp(prefix="lcs2-audit-")))
    os.environ.pop("DATABASE_URL", None)
    os.environ.pop("WEBPENT_DATABASE_URL", None)


def allow_loopback():
    """Engagement-scope allowance for the loopback lab lanes."""
    from webpent.shared.engagement_scope import set_engagement_target_hosts

    return set_engagement_target_hosts("127.0.0.1", "localhost")
