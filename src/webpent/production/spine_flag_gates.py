"""M2-impl WP-F (R6 of Ruling M2-001) — fail-closed consumers for the five
SDD §8 spine feature flags.

The flags are DECLARED and RESOLVED exclusively inside the frozen
production_spine surface (``ProductionSpineConfig`` fields, strict-bool env
fallback, fail-closed defaults). Until this module, they had ZERO consumers
(NF-M2-02): the intake machinery ran ungated. This module is the consumer
layer — the ONLY way gating decisions are made — and it enforces:

  * FACTORY-BOUND: a snapshot is built from the factory-resolved
    ProductionSpineConfig object ONLY. It never reads ``state`` keys or
    environment variables at consumption time — an env flip mid-engagement
    cannot retroactively open a gate (re-derivation re-resolves honestly).
  * BINDING: every gate decision carries the snapshot's engagement binding
    (engagement_id + target digest) and refuses scheduling when the caller's
    binding is absent or a placeholder (``target_unknown`` — the NF-M2-04
    placeholder-binding class).
  * NOT SETTABLE BY FIXTURES/ARTIFACTS: fixtures and artifacts are DATA.
    No fixture field can influence any gate: the snapshot is derived from
    the config object alone, and gate inputs are identity strings only.
    (Test: a fixture carrying flag-like keys schedules nothing extra.)
  * DISABLED = NOTHING SCHEDULABLE: a disabled flag yields a DENY decision
    with a reason — the gated path schedules zero work.

Phase-1 semantics preserved: ``live_proxy_source_enabled`` is hardwired-off
at the factory (enabling it is a hard reject there); its consumer refuses
unconditionally. ``foreign_report_writer_access`` gates M3 report-writer
authority; its consumer exists here so the flag is consumed, and the M3
reporter adopts it at that milestone (documented boundary).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Final

DENY: Final[str] = "DENY"
ALLOW: Final[str] = "ALLOW"

_PLACEHOLDER_FINGERPRINT: Final[str] = "target_unknown"


@dataclass(frozen=True)
class SpineFlagSnapshot:
    """Immutable, factory-bound view of the five SDD §8 flags."""

    engagement_id: str
    target_binding_digest: str
    exploration_ingress_enabled: bool
    static_fixture_source_enabled: bool
    live_proxy_source_enabled: bool
    multi_principal_execution_enabled: bool
    foreign_report_writer_access: bool

    @classmethod
    def from_config(cls, config: Any) -> "SpineFlagSnapshot":
        """Build from the factory-resolved ProductionSpineConfig ONLY.

        Fail-closed: missing config fields read as False (the strict-bool
        resolution in production_spine guarantees real bools; a foreign
        config-like object cannot enable anything by omission).
        """
        engagement_id = str(getattr(config, "engagement_id", "") or "")
        target_url = str(getattr(config, "target_url", "") or "")
        digest = hashlib.sha256(target_url.encode("utf-8", "replace")).hexdigest()[:16]

        def _flag(name: str) -> bool:
            value = getattr(config, name, None)
            return value is True  # ONLY a resolved True opens a gate

        return cls(
            engagement_id=engagement_id,
            target_binding_digest=digest,
            exploration_ingress_enabled=_flag("exploration_ingress_enabled"),
            static_fixture_source_enabled=_flag("static_fixture_source_enabled"),
            live_proxy_source_enabled=_flag("live_proxy_source_enabled"),
            multi_principal_execution_enabled=_flag("multi_principal_execution_enabled"),
            foreign_report_writer_access=_flag("foreign_report_writer_access"),
        )


@dataclass(frozen=True)
class GateDecision:
    flag: str
    decision: str  # ALLOW / DENY
    reason: str
    engagement_id: str
    target_binding_digest: str


def _binding_problem(engagement_instance_id: Any, target_fingerprint: Any) -> str | None:
    """Binding check shared by scheduling gates (SDD §8: bound to engagement
    + target fingerprint). Placeholder/absent bindings never schedule
    (NF-M2-04 placeholder class)."""
    if not isinstance(engagement_instance_id, str) or not engagement_instance_id.strip():
        return "binding_missing_engagement_instance"
    if not isinstance(target_fingerprint, str) or not target_fingerprint.strip():
        return "binding_missing_target_fingerprint"
    if target_fingerprint.strip() == _PLACEHOLDER_FINGERPRINT:
        return "binding_placeholder_target_fingerprint"
    return None


def gate_exploration_ingress(
    snapshot: SpineFlagSnapshot, *, engagement_instance_id: Any, target_fingerprint: Any,
) -> GateDecision:
    """Scheduling gate for the exploration-ingress boundary (intake)."""
    problem = _binding_problem(engagement_instance_id, target_fingerprint)
    if problem:
        return GateDecision("exploration_ingress", DENY, problem,
                            snapshot.engagement_id, snapshot.target_binding_digest)
    if not snapshot.exploration_ingress_enabled:
        return GateDecision("exploration_ingress", DENY,
                            "flag_disabled_nothing_schedulable",
                            snapshot.engagement_id, snapshot.target_binding_digest)
    return GateDecision("exploration_ingress", ALLOW, "flag_enabled_and_bound",
                        snapshot.engagement_id, snapshot.target_binding_digest)


def gate_static_fixture_source(
    snapshot: SpineFlagSnapshot, *, engagement_instance_id: Any, target_fingerprint: Any,
) -> GateDecision:
    """Scheduling gate for the static-fixture SOURCE (fixture-derived
    candidates)."""
    problem = _binding_problem(engagement_instance_id, target_fingerprint)
    if problem:
        return GateDecision("static_fixture_source", DENY, problem,
                            snapshot.engagement_id, snapshot.target_binding_digest)
    if not snapshot.static_fixture_source_enabled:
        return GateDecision("static_fixture_source", DENY,
                            "flag_disabled_nothing_schedulable",
                            snapshot.engagement_id, snapshot.target_binding_digest)
    return GateDecision("static_fixture_source", ALLOW, "flag_enabled_and_bound",
                        snapshot.engagement_id, snapshot.target_binding_digest)


def gate_multi_principal_execution(
    snapshot: SpineFlagSnapshot, *, engagement_instance_id: Any, target_fingerprint: Any,
) -> GateDecision:
    """Scheduling gate for multi-principal experiment dispatch (distinct
    actor / independent negative control)."""
    problem = _binding_problem(engagement_instance_id, target_fingerprint)
    if problem:
        return GateDecision("multi_principal_execution", DENY, problem,
                            snapshot.engagement_id, snapshot.target_binding_digest)
    if not snapshot.multi_principal_execution_enabled:
        return GateDecision("multi_principal_execution", DENY,
                            "flag_disabled_nothing_schedulable",
                            snapshot.engagement_id, snapshot.target_binding_digest)
    return GateDecision("multi_principal_execution", ALLOW, "flag_enabled_and_bound",
                        snapshot.engagement_id, snapshot.target_binding_digest)


def gate_live_proxy_source(snapshot: SpineFlagSnapshot) -> GateDecision:
    """Unconditional Phase-1 refusal (the factory hardwires the flag off and
    hard-rejects enabling attempts; the consumer never allows)."""
    return GateDecision("live_proxy_source", DENY,
                        "phase1_hardwired_off",
                        snapshot.engagement_id, snapshot.target_binding_digest)


def gate_foreign_report_writer(
    snapshot: SpineFlagSnapshot, *, engagement_instance_id: Any, target_fingerprint: Any,
) -> GateDecision:
    """Consumer for the M3 report-writer authority flag. Fixtures/artifacts
    reach this gate as DATA only — a fixture can never mint report-writer
    authority; the flag resolves exclusively at the factory."""
    problem = _binding_problem(engagement_instance_id, target_fingerprint)
    if problem:
        return GateDecision("foreign_report_writer", DENY, problem,
                            snapshot.engagement_id, snapshot.target_binding_digest)
    if not snapshot.foreign_report_writer_access:
        return GateDecision("foreign_report_writer", DENY,
                            "flag_disabled_nothing_schedulable",
                            snapshot.engagement_id, snapshot.target_binding_digest)
    return GateDecision("foreign_report_writer", ALLOW, "flag_enabled_and_bound",
                        snapshot.engagement_id, snapshot.target_binding_digest)


def evaluate_all(snapshot: SpineFlagSnapshot, *, engagement_instance_id: Any,
                 target_fingerprint: Any) -> dict[str, GateDecision]:
    """Evaluate every scheduling gate (operator-visible snapshot of the
    flag posture for the engagement binding)."""
    return {
        "exploration_ingress": gate_exploration_ingress(
            snapshot, engagement_instance_id=engagement_instance_id,
            target_fingerprint=target_fingerprint),
        "static_fixture_source": gate_static_fixture_source(
            snapshot, engagement_instance_id=engagement_instance_id,
            target_fingerprint=target_fingerprint),
        "multi_principal_execution": gate_multi_principal_execution(
            snapshot, engagement_instance_id=engagement_instance_id,
            target_fingerprint=target_fingerprint),
        "live_proxy_source": gate_live_proxy_source(snapshot),
        "foreign_report_writer": gate_foreign_report_writer(
            snapshot, engagement_instance_id=engagement_instance_id,
            target_fingerprint=target_fingerprint),
    }


__all__ = [
    "SpineFlagSnapshot", "GateDecision", "ALLOW", "DENY",
    "gate_exploration_ingress", "gate_static_fixture_source",
    "gate_multi_principal_execution", "gate_live_proxy_source",
    "gate_foreign_report_writer", "evaluate_all",
]
