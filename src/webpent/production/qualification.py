"""Pure production-readiness qualification records.

The checker evaluates operator-supplied evidence only. It never starts Docker,
connects to Redis/Celery, reads secrets, or declares distributed qualification
from local unit tests.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_REQUIRED_CHECKS = (

    "docker_health",
    "redis_health",
    "celery_worker_health",
    "multi_worker_lease_contention",
    "crash_restart_recovery",
    "checkpoint_resume",
    "cross_process_idempotency",
    "secrets_externalized",
    "tls_enforced",
    "logs_redacted",
    "retention_policy_declared",
    "target_unchanged",
)


@dataclass(frozen=True)
class ProductionEvidence:
    """Boolean evidence supplied by an external qualification procedure."""

    docker_health: bool = False
    redis_health: bool = False
    celery_worker_health: bool = False
    multi_worker_lease_contention: bool = False
    crash_restart_recovery: bool = False
    checkpoint_resume: bool = False
    cross_process_idempotency: bool = False
    secrets_externalized: bool = False
    tls_enforced: bool = False
    logs_redacted: bool = False
    retention_policy_declared: bool = False
    target_unchanged: bool = False
    external_target_contacted: bool = False


@dataclass(frozen=True)
class ProductionQualificationReport:
    """Fail-closed production qualification projection."""

    checks: tuple[tuple[str, bool], ...]
    qualified: bool
    status: str
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "checks": dict(self.checks),
            "qualified": self.qualified,
            "status": self.status,
            "reasons": list(self.reasons),
        }


def qualify_production(evidence: ProductionEvidence) -> ProductionQualificationReport:
    """Evaluate production evidence without performing any environment action."""
    checks = tuple((name, bool(getattr(evidence, name))) for name in _REQUIRED_CHECKS)
    reasons = [f"missing:{name}" for name, passed in checks if not passed]
    if evidence.external_target_contacted:
        reasons.append("external_target_contacted_during_qualification")
    qualified = not reasons
    return ProductionQualificationReport(
        checks=checks,
        qualified=qualified,
        status="qualified" if qualified else "not_qualified",
        reasons=tuple(reasons),
    )


__all__ = ["ProductionEvidence", "ProductionQualificationReport", "qualify_production"]
