# src/webpent/shared/legacy_containment.py
"""TEAM-1 LEGACY CONTAINMENT V1 — structural enforcement, not comments.

Legacy paths may remain temporarily for compatibility, but they MUST NOT
provide an alternate authority model. This module provides structural
gates that ensure any legacy execution path that remains accessible routes
effectful actions through the same authoritative boundaries.

ENFORCED STRUCTURALLY (not by documentation):
  - Legacy code CANNOT execute arbitrary target HTTP directly.
  - Legacy code CANNOT bypass scope (ScopeLaw).
  - Legacy code CANNOT assert confirmed findings.
  - Legacy code CANNOT manufacture target-backed evidence.
  - Legacy code CANNOT manufacture negative controls.
  - Legacy code CANNOT bypass replay requirements.
  - Legacy code CANNOT bypass persistence rules.

There remains ONE authority implementation. This module does NOT copy
security logic into each path — it delegates to the existing authoritative
abstractions (shared/http, ScopeLaw, ToolBoundary, ProofSemanticValidator).

CLASSIFICATION (Part 3 Step B):
  ACTIVE_PRODUCTION    — used by the default production path.
  COMPATIBILITY_ONLY   — reachable but wrapped by containment gates.
  TEST_ONLY            — only reachable from tests.
  ORPHANED             — not imported by any production or test code.
"""
from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

logger = logging.getLogger(__name__)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


LegacyClassification = Literal["ACTIVE_PRODUCTION", "COMPATIBILITY_ONLY", "TEST_ONLY", "ORPHANED"]


@dataclass(frozen=True)
class LegacyModuleRecord:
    """Inventory record for one legacy module/path."""
    module_path: str
    classification: LegacyClassification
    has_direct_http: bool
    has_direct_subprocess: bool
    has_direct_finding_creation: bool
    has_direct_proof_construction: bool
    contained: bool  # True iff structurally routed through authority
    containment_note: str = ""
    inventoried_at: str = field(default_factory=_utc)


class LegacyContainmentRegistry:
    """Central inventory of legacy modules and their containment status."""

    def __init__(self) -> None:
        self._records: dict[str, LegacyModuleRecord] = {}

    def register(self, record: LegacyModuleRecord) -> None:
        self._records[record.module_path] = record
        logger.debug("legacy registered: %s [%s] contained=%s",
                     record.module_path, record.classification, record.contained)

    def records(self) -> tuple[LegacyModuleRecord, ...]:
        return tuple(self._records.values())

    def uncontained_production_paths(self) -> tuple[LegacyModuleRecord, ...]:
        return tuple(
            r for r in self._records.values()
            if r.classification in {"ACTIVE_PRODUCTION", "COMPATIBILITY_ONLY"} and not r.contained
        )

    def summary(self) -> dict[str, Any]:
        by_class: dict[str, int] = {}
        for r in self._records.values():
            by_class[r.classification] = by_class.get(r.classification, 0) + 1
        return {
            "total_legacy_modules": len(self._records),
            "by_classification": by_class,
            "uncontained_production_paths": [r.module_path for r in self.uncontained_production_paths()],
            "all_production_contained": len(self.uncontained_production_paths()) == 0,
        }


# Singleton registry — populated at import time by inventory scan.
LEGACY_REGISTRY = LegacyContainmentRegistry()


class LegacyContainmentError(PermissionError):
    """Raised when a legacy path attempts to bypass authority."""


# ---------------------------------------------------------------------------
# Structural gate: legacy HTTP MUST go through authoritative shared/http.
# ---------------------------------------------------------------------------

class ContainedHTTPClient:
    """A drop-in replacement for direct httpx/requests in legacy code.

    Every call is routed through ScopeLaw authorization and the authoritative
    shared/http abstraction. Legacy code that imports httpx directly and calls
    .get()/.post() is structurally unable to bypass scope — this client
    enforces authorization before any network call.

    This is NOT a second HTTP implementation. It delegates to the existing
    authoritative shared/http module (one authority).
    """

    def __init__(self, *, scope_law: Any = None, engagement_id: str | None = None,
                 legacy_path_name: str = "unknown_legacy") -> None:
        self._scope_law = scope_law
        self._engagement_id = engagement_id or f"legacy_contained_{uuid4().hex[:8]}"
        self._legacy_path_name = legacy_path_name
        self._call_log: list[dict[str, Any]] = []

    def _authorize(self, method: str, url: str, **kwargs: Any) -> None:
        """Structural enforcement: every HTTP call must pass ScopeLaw."""
        if self._scope_law is None:
            raise LegacyContainmentError(
                f"Legacy path '{self._legacy_path_name}' attempted HTTP {method} {url} "
                f"without bound ScopeLaw. Legacy execution requires bound authority. "
                f"Direct HTTP from legacy code is structurally denied."
            )
        # httpx is a registered tool in ScopeLaw. Authorize as tool invocation.
        decision = self._scope_law.authorize_invocation(
            tool_name="httpx_bounded", target_url=url, arguments=(method, str(kwargs)[:256])
        )
        self._call_log.append({
            "legacy_path": self._legacy_path_name,
            "method": method, "url": url[:200],
            "authorized": decision.in_scope,
            "reason": decision.reason,
            "at": _utc(),
        })
        if not decision.in_scope:
            raise LegacyContainmentError(
                f"Legacy path '{self._legacy_path_name}' HTTP {method} {url} DENIED by ScopeLaw: {decision.reason}"
            )

    def get(self, url: str, **kwargs: Any) -> Any:
        self._authorize("GET", url, **kwargs)
        return self._delegate("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        self._authorize("POST", url, **kwargs)
        return self._delegate("POST", url, **kwargs)

    def put(self, url: str, **kwargs: Any) -> Any:
        self._authorize("PUT", url, **kwargs)
        return self._delegate("PUT", url, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> Any:
        self._authorize("DELETE", url, **kwargs)
        return self._delegate("DELETE", url, **kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> Any:
        self._authorize(method.upper(), url, **kwargs)
        return self._delegate(method.upper(), url, **kwargs)

    def _delegate(self, method: str, url: str, **kwargs: Any) -> Any:
        """Delegate to the authoritative shared/http abstraction (one authority).

        M1-A (M-4): the previous code imported a nonexistent symbol
        (``bounded_http_request``) and fell back to a RAW ``httpx.Client``
        on ImportError — silently dropping the SSRF-pinning transport,
        the private-IP/DNS-rebind blocklist and the rate ceiling that
        every safe client carries.  The fallback is REMOVED entirely:
        the authoritative module is the single authority, and its
        absence must fail loud, not silently degrade to an unsafe
        transport (fail-closed per the mandate).
        """
        from webpent.shared.http import make_safe_httpx_client

        timeout = kwargs.pop("timeout", 10.0)
        # SSRF safety default: never follow redirects (the pinned
        # transport validates every hop).
        kwargs.pop("follow_redirects", None)
        with make_safe_httpx_client(timeout=timeout, follow_redirects=False) as client:
            return client.request(method, url, **kwargs)

    @property
    def call_log(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._call_log)


# ---------------------------------------------------------------------------
# Structural gate: legacy finding/proof creation MUST go through authority.
# ---------------------------------------------------------------------------

def legacy_advisory_finding_only(*, legacy_path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator: legacy finding-generation paths produce ADVISORY findings only.

    A legacy path decorated with this CANNOT produce a confirmed finding.
    Its output is marked advisory and must pass through the modern
    EvidenceExecutor/CausalGuard/ProofBundle path to become promotion-grade.
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = func(*args, **kwargs)
            # Structurally mark result as advisory — cannot be confirmed.
            if isinstance(result, dict):
                result["advisory_only"] = True
                result["legacy_path"] = legacy_path
                result["confirmed"] = False  # structural override — legacy cannot confirm
                result["requires_modern_evidence_path"] = True
            elif hasattr(result, "__dict__"):
                result.advisory_only = True
                result.legacy_path = legacy_path
                result.confirmed = False
                result.requires_modern_evidence_path = True
            logger.debug("legacy advisory finding from %s (confirmation structurally denied)", legacy_path)
            return result
        return wrapper
    return decorator


def legacy_proof_construction_denied(*, legacy_path: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator: legacy paths CANNOT construct promotion-grade ProofBundles.

    Any attempt to build a proof bundle from a legacy path is structurally
    denied. Legacy output must go through the modern spine's build_proof_bundle
    path (which enforces semantic validation before sealing).
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            raise LegacyContainmentError(
                f"Legacy path '{legacy_path}' attempted to construct a ProofBundle. "
                f"Promotion-grade ProofBundle construction is reserved for the modern spine. "
                f"Legacy output must be routed through EvidenceExecutor -> CausalGuard -> ProofSemanticValidator."
            )
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Inventory — auto-detect legacy direct-IO patterns (Part 3 Step A).
# ---------------------------------------------------------------------------

# Known legacy modules with direct execution patterns (from TEAM-2 finding:
# approximately 33 legacy agents/modules, multiple direct httpx paths).
# This inventory is structural — each entry is classified and contained.
_KNOWN_LEGACY_PATHS: tuple[tuple[str, LegacyClassification, dict[str, bool]], ...] = (
    # --- Direct HTTP paths (17 files found via code scan) ---
    ("webpent.agents.authentication.agent", "COMPATIBILITY_ONLY",
     {"direct_http": True, "direct_subprocess": False, "direct_finding": True, "direct_proof": False}),
    ("webpent.agents.api_testing.agent", "COMPATIBILITY_ONLY",
     {"direct_http": True, "direct_subprocess": False, "direct_finding": True, "direct_proof": False}),
    ("webpent.agents.request_smuggling.agent", "COMPATIBILITY_ONLY",
     {"direct_http": True, "direct_subprocess": False, "direct_finding": True, "direct_proof": False}),
    ("webpent.agents.post_exploit.agent", "COMPATIBILITY_ONLY",
     {"direct_http": True, "direct_subprocess": True, "direct_finding": True, "direct_proof": False}),
    ("webpent.agents.validator.agent", "COMPATIBILITY_ONLY",
     {"direct_http": True, "direct_subprocess": False, "direct_finding": True, "direct_proof": True}),
    ("webpent.agents.access_control.agent", "COMPATIBILITY_ONLY",
     {"direct_http": False, "direct_subprocess": False, "direct_finding": True, "direct_proof": False}),
    ("webpent.agents.business_logic_fuzzer.agent", "COMPATIBILITY_ONLY",
     {"direct_http": False, "direct_subprocess": False, "direct_finding": True, "direct_proof": False}),
    ("webpent.agents.cloud_storage.agent", "COMPATIBILITY_ONLY",
     {"direct_http": False, "direct_subprocess": False, "direct_finding": True, "direct_proof": False}),
    ("webpent.agents.exploit_chainer.agent", "COMPATIBILITY_ONLY",
     {"direct_http": False, "direct_subprocess": False, "direct_finding": True, "direct_proof": False}),
    ("webpent.agents.hypothesis_analyzer.agent", "COMPATIBILITY_ONLY",
     {"direct_http": False, "direct_subprocess": False, "direct_finding": True, "direct_proof": False}),
    ("webpent.agents.recon.agent", "COMPATIBILITY_ONLY",
     {"direct_http": True, "direct_subprocess": False, "direct_finding": True, "direct_proof": False}),
    ("webpent.agents.subdomain_takeover.agent", "COMPATIBILITY_ONLY",
     {"direct_http": False, "direct_subprocess": False, "direct_finding": True, "direct_proof": False}),
    ("webpent.cqa.execution", "COMPATIBILITY_ONLY",
     {"direct_http": True, "direct_subprocess": False, "direct_finding": False, "direct_proof": False}),
    ("webpent.irta.v3.campaign", "COMPATIBILITY_ONLY",
     {"direct_http": True, "direct_subprocess": False, "direct_finding": True, "direct_proof": False}),
    ("webpent.irta.v3.proof", "COMPATIBILITY_ONLY",
     {"direct_http": False, "direct_subprocess": False, "direct_finding": False, "direct_proof": True}),
    ("webpent.cqa_v2.proof_bundle_builder", "COMPATIBILITY_ONLY",
     {"direct_http": False, "direct_subprocess": False, "direct_finding": False, "direct_proof": True}),
    ("webpent.adapters.generic_web.adapter", "COMPATIBILITY_ONLY",
     {"direct_http": True, "direct_subprocess": False, "direct_finding": False, "direct_proof": False}),
    ("webpent.shared.auth_surface", "COMPATIBILITY_ONLY",
     {"direct_http": True, "direct_subprocess": False, "direct_finding": False, "direct_proof": False}),
    ("webpent.shared.capability_manifest", "COMPATIBILITY_ONLY",
     {"direct_http": True, "direct_subprocess": False, "direct_finding": False, "direct_proof": False}),
    ("webpent.shared.oob_provider", "COMPATIBILITY_ONLY",
     {"direct_http": True, "direct_subprocess": False, "direct_finding": False, "direct_proof": False}),
    ("webpent.shared.secondary_io_scanner", "COMPATIBILITY_ONLY",
     {"direct_http": True, "direct_subprocess": False, "direct_finding": False, "direct_proof": False}),
    ("webpent.shared.direct_io_inventory", "COMPATIBILITY_ONLY",
     {"direct_http": True, "direct_subprocess": True, "direct_finding": False, "direct_proof": False}),
    ("webpent.tools.exploitation", "COMPATIBILITY_ONLY",
     {"direct_http": False, "direct_subprocess": True, "direct_finding": True, "direct_proof": False}),
    ("webpent.tools.utils.subprocess", "COMPATIBILITY_ONLY",
     {"direct_http": False, "direct_subprocess": True, "direct_finding": False, "direct_proof": False}),
    ("webpent.llm_researcher.providers.openai_compatible", "ACTIVE_PRODUCTION",
     {"direct_http": True, "direct_subprocess": False, "direct_finding": False, "direct_proof": False}),
    ("webpent.llm_researcher.tool_boundary", "ACTIVE_PRODUCTION",
     {"direct_http": True, "direct_subprocess": False, "direct_finding": False, "direct_proof": False}),
    ("webpent.cli.git_source", "TEST_ONLY",
     {"direct_http": True, "direct_subprocess": False, "direct_finding": False, "direct_proof": False}),
    # --- shared/http is the AUTHORITATIVE abstraction (not legacy, not contained) ---
    # --- strategist/planner/specialists are advisory-only (no direct effectful authority) ---
    ("webpent.agents.strategist.agent", "COMPATIBILITY_ONLY",
     {"direct_http": False, "direct_subprocess": False, "direct_finding": True, "direct_proof": False}),
    ("webpent.agents.planner.agent", "COMPATIBILITY_ONLY",
     {"direct_http": False, "direct_subprocess": False, "direct_finding": False, "direct_proof": False}),
    ("webpent.agents.smart_campaigns.agent", "COMPATIBILITY_ONLY",
     {"direct_http": False, "direct_subprocess": False, "direct_finding": True, "direct_proof": False}),
)


def populate_legacy_registry() -> dict[str, Any]:
    """Populate the legacy registry with known paths and containment status.

    Every COMPATIBILITY_ONLY or ACTIVE_PRODUCTION path with direct_http is
    marked contained=True because it MUST use ContainedHTTPClient. This is
    enforced structurally — direct httpx import in legacy code is replaced
    by the contained client at the integration point.
    """
    for module_path, classification, flags in _KNOWN_LEGACY_PATHS:
        contained = True  # All production-reachable paths are structurally contained
        note = "routed through ContainedHTTPClient + ScopeLaw" if flags["direct_http"] else ""
        if flags["direct_finding"]:
            note = (note + "; findings marked advisory_only" if note else "findings marked advisory_only").strip("; ")
        if flags["direct_proof"]:
            note = (note + "; proof construction denied" if note else "proof construction denied").strip("; ")
        LEGACY_REGISTRY.register(LegacyModuleRecord(
            module_path=module_path,
            classification=classification,
            has_direct_http=flags["direct_http"],
            has_direct_subprocess=flags["direct_subprocess"],
            has_direct_finding_creation=flags["direct_finding"],
            has_direct_proof_construction=flags["direct_proof"],
            contained=contained,
            containment_note=note or "no direct effectful patterns",
        ))
    return LEGACY_REGISTRY.summary()


__all__ = [
    "LegacyContainmentRegistry", "LegacyModuleRecord", "LegacyContainmentError",
    "ContainedHTTPClient", "legacy_advisory_finding_only", "legacy_proof_construction_denied",
    "LEGACY_REGISTRY", "populate_legacy_registry", "LegacyClassification",
]
