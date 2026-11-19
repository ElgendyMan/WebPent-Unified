# src/webpent/production/campaign_worker_claims.py
"""Campaign-lifetime worker claims — Track 12 item 3 wired into the
service layer (v0.25.0, "wire WorkerCoordinator into MultiCampaignService"
following the 0.18.0 engine-merge pattern: additive, default-off,
fail-safe).

What this adapter does
----------------------
A RUNNING campaign occupies a coordination claim for its whole lifetime:
two workers (different processes/machines sharing ``coord_dir``) can never
run the same campaign's work unit at the same time, even though each has
its own in-process concurrency governor.

Outcome mapping (fail-safe contract, mirrors the governor's):

* ``ACQUIRED`` / ``RENEWED`` / ``TAKEOVER`` — the claim is held; the
  campaign may start.
* ``BUSY`` — another LIVE worker holds the unit: the start is REFUSED
  (fail-closed) with a clear, actionable rejection.
* ``SCOPE_CONFLICT`` — the unit is held under a different scope hash
  (never taken over by design): the start is REFUSED (fail-closed).
  This indicates inconsistent operator input, not a transient condition.
* ``DENIED_ERROR`` — the coordination ledger itself failed. This is a
  resource-guard outage, NOT a scope/authorization decision, so the
  caller fails OPEN (proceeds) with the error recorded — scope and
  authorization were already enforced upstream by ``webpent.scope`` and
  are never replaced by this guard.

Scope hash: derived deterministically from the campaign's normalized
target (never from raw content) so a second claim for the same target
agrees, and a materially different target conflicts.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from webpent.production.worker_coordination import (
    ClaimDecision,
    ClaimOutcome,
    WorkerCoordinator,
)

logger = logging.getLogger(__name__)

__all__ = [
    "CampaignWorkerClaims",
    "make_campaign_claims_from_settings",
]


def _work_unit_id(campaign_id: str) -> str:
    """Deterministic coordination unit for one campaign."""
    return f"campaign:{campaign_id}"


def _scope_hash(client_id: str, target_url: str) -> str:
    """Stable, content-free scope fingerprint for a claim.

    Identical (client, target) pairs agree; anything else conflicts —
    which is exactly the fail-closed behavior we want for double-start
    protection across workers.
    """
    raw = f"{client_id}\x00{target_url}".encode("utf-8", "replace")
    return hashlib.sha256(raw).hexdigest()[:16]


class CampaignWorkerClaims:
    """Thin adapter: campaign lifecycle ⇄ ``WorkerCoordinator`` claims."""

    def __init__(self, coordinator: WorkerCoordinator) -> None:
        self._coordinator = coordinator

    @property
    def worker_id(self) -> str:
        return self._coordinator.worker_id

    @property
    def coord_dir(self) -> str:
        return str(self._coordinator.coord_dir)

    # ------------------------------------------------------------------
    # lifecycle hooks (called by the service facade)
    # ------------------------------------------------------------------
    def claim(
        self, campaign_id: str, *, client_id: str, target_url: str
    ) -> dict[str, Any]:
        """Claim the campaign's work unit for this worker.

        Returns the decision dict. ``held`` is True when the caller may
        proceed; False means the start must be refused (fail-closed
        outcomes only — BUSY / SCOPE_CONFLICT). Ledger failures fail
        open with ``held=True`` and ``fail_open`` set, after logging.
        """
        decision = self._coordinator.claim_work(
            client_id,
            _scope_hash(client_id, target_url),
            _work_unit_id(campaign_id),
            work_kind="campaign",
        )
        return self._project(decision)

    def release(
        self, campaign_id: str, *, client_id: str, target_url: str
    ) -> None:
        """Release the campaign claim (halt/complete/failure path).

        Never raises — a release failure must not break the lifecycle
        transition it accompanies.
        """
        try:
            self._coordinator.release_claim(
                client_id,
                _work_unit_id(campaign_id),
                note="campaign lifecycle end",
            )
        except Exception:  # noqa: BLE001 — fail-safe release
            logger.warning(
                "campaign_worker_claims: release failed for %s "
                "(stale claim expires via TTL)",
                campaign_id,
                exc_info=True,
            )

    # ------------------------------------------------------------------
    # projection
    # ------------------------------------------------------------------
    def _project(self, decision: ClaimDecision) -> dict[str, Any]:
        outcome = decision.outcome
        if not isinstance(outcome, ClaimOutcome):
            try:
                outcome = ClaimOutcome(str(outcome))
            except ValueError:
                outcome = ClaimOutcome.DENIED_ERROR
        if outcome in (ClaimOutcome.ACQUIRED, ClaimOutcome.RENEWED, ClaimOutcome.TAKEOVER):
            return {
                "held": True,
                "outcome": outcome.value,
                "worker_id": self._coordinator.worker_id,
                "work_unit_id": decision.work_unit_id,
                "note": decision.note,
            }
        if outcome in (ClaimOutcome.BUSY, ClaimOutcome.SCOPE_CONFLICT):
            return {
                "held": False,
                "outcome": outcome.value,
                "holder_worker_id": decision.holder_worker_id,
                "expires_at": decision.expires_at,
                "note": decision.note,
            }
        # DENIED_ERROR (or anything unknown): the ledger is unavailable —
        # a resource-guard outage, never a scope decision. Fail open,
        # loudly, with the error recorded for the audit trail.
        logger.warning(
            "campaign_worker_claims: ledger unavailable (%s) — failing "
            "open for campaign %s; scope/authorization unaffected",
            decision.note,
            decision.work_unit_id,
        )
        return {
            "held": True,
            "outcome": ClaimOutcome.DENIED_ERROR.value,
            "fail_open": True,
            "note": decision.note,
        }

    def snapshot(self, client_id: str = "") -> dict[str, Any]:
        """Read-only coordination snapshot for ``ops workers``."""
        return self._coordinator.snapshot(client_id=client_id)


def make_campaign_claims_from_settings() -> CampaignWorkerClaims | None:
    """Optional backend construction (the lease-backend seam pattern).

    Enabled only when ``worker_coordination_enabled`` is true AND a
    ``worker_coordination_dir`` is configured. Any construction failure
    logs and returns ``None`` so the service silently keeps its
    default-off behavior (fail-open resource guard, never a security
    boundary).
    """
    try:
        from webpent.config.settings import get_settings

        settings = get_settings()
        if not bool(getattr(settings, "worker_coordination_enabled", False)):
            return None
        coord_dir = str(getattr(settings, "worker_coordination_dir", "") or "").strip()
        if not coord_dir:
            logger.info(
                "campaign_worker_claims: enabled but worker_coordination_dir "
                "is empty — staying default-off"
            )
            return None
        coordinator = WorkerCoordinator(coord_dir)
        return CampaignWorkerClaims(coordinator)
    except Exception:  # noqa: BLE001 — optional backend must never break init
        logger.warning(
            "campaign_worker_claims: construction failed — falling back to "
            "no-coordination mode",
            exc_info=True,
        )
        return None
