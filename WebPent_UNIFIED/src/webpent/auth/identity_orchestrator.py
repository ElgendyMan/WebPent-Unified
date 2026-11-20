# src/webpent/auth/identity_orchestrator.py
"""webpent.auth.identity_orchestrator — ق7 virtual-identity path (FEATURE_PROPOSALS ق7).

Proposal contract (ق7، WebPent_FEATURE_PROPOSALS.md):

    عمق Auth/Session: ``multi_step_auth`` و``session_pool`` (legacy)
    و``jwt_analyzer`` موجودون — وحّدهم في مسار «هوية افتراضية» يبني/
    يحافظ جلسات متعددة الأدوار تلقائيًا ويغذي authorization matrix
    بجلسات حية بدل افتراضات.

    ("Auth/Session depth: multi_step_auth, session_pool (legacy) and
    jwt_analyzer exist — unify them into a 'virtual identity' path that
    builds/maintains multi-role sessions automatically and feeds the
    authorization matrix with LIVE sessions instead of assumptions.")

New module (the pieces it unifies are imported, never edited —
``auth/session_pool.py`` is free and ``auth/reauth_vault.py`` sits
behind the frozen gate). What the orchestrator adds over the bare pool:

1. **Role profiles** — one :class:`IdentityProfile` per virtual
   identity: a role name, a CREDENTIALS HANDLE (a vault reference;
   raw secrets never enter this layer) and the multi-step login flow
   step names (the ``multi_step_auth`` vocabulary).
2. **Automatic build/maintain** — ``ensure_sessions()`` runs the
   injected ``session_factory`` per role and seeds the
   ``SessionPool``; ``maintain()`` forces the pool's health-check +
   bounded re-auth pass and reports per-role outcomes.
3. **LIVE sessions into the authorization matrix** —
   ``build_live_matrix()`` fails CLOSED per row: an observation whose
   role has no live session at build time is excluded from the matrix
   and recorded as an explicit gap (``no_live_session:<role>``). The
   resulting matrix carries a ``session_provenance`` block so the
   report can distinguish observed-with-live-session from assumed.

Postures inherited unchanged:

* **Fail-closed at the session boundary** (``SessionPool.acquire``
  contract): the caller gets a healthy session or ``None`` — never a
  dead session.
* **Read-only snapshots** — health/provenance views never expose
  session material (cookies/headers are not logged here).
* **No network in this module** — the factory/probe callbacks own all
  traffic; the orchestrator is pure orchestration and injectable clocks.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from webpent.auth.session_pool import (
    MAX_SESSIONS_PER_POOL,
    SessionPool,
)

logger = logging.getLogger(__name__)

__all__ = [
    "IdentityProfile",
    "IdentityBuildOutcome",
    "IdentityOrchestrator",
]

SessionFactory = Callable[["IdentityProfile"], Any | None]
HealthProbe = Callable[[str, Any], bool]


@dataclass(frozen=True)
class IdentityProfile:
    """One virtual identity — a handle to credentials, never the secrets.

    ``credentials_handle`` is the operator-side reference (e.g. a
    ``reauth_vault`` key or a profile id) that the injected factory
    resolves; raw credentials are intentionally out of scope here.
    ``login_flow`` carries the multi-step flow's step NAMES (the
    ``multi_step_auth`` analyzer's vocabulary) for provenance only —
    the factory owns the actual steps.
    """

    role: str
    credentials_handle: str
    login_flow: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "credentials_handle": self.credentials_handle,
            "login_flow": list(self.login_flow),
            "raw_credentials_included": False,
        }


@dataclass
class IdentityBuildOutcome:
    """Result of one role's session build attempt (never raises)."""

    role: str
    status: str  # built | factory_none | factory_error | empty_role | capped
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"role": self.role, "status": self.status, "detail": self.detail}


@dataclass
class _ProvenanceAccumulator:
    live_roles: set[str] = field(default_factory=set)
    excluded_roles: set[str] = field(default_factory=set)
    excluded_rows: int = 0
    verified_rows: int = 0


class IdentityOrchestrator:
    """Build/maintain multi-role LIVE sessions and feed the authz matrix.

    The orchestrator owns ONE ``SessionPool`` (per engagement, by
    construction — instantiate one orchestrator per engagement). The
    ``session_factory`` performs the actual multi-step login with the
    profile's credentials handle; the ``health_probe`` answers "is this
    session still live" for the pool's lazy health layer.
    """

    def __init__(
        self,
        *,
        profiles: Iterable[IdentityProfile],
        session_factory: SessionFactory,
        health_probe: HealthProbe | None = None,
        health_interval: float = 300.0,
        max_roles: int = MAX_SESSIONS_PER_POOL,
        now: Callable[[], float] | None = None,
    ) -> None:
        self._profiles: dict[str, IdentityProfile] = {}
        for profile in profiles:
            if not isinstance(profile, IdentityProfile):
                continue
            role = str(profile.role or "").strip()
            if not role or role in self._profiles:
                continue
            self._profiles[role] = profile
        if session_factory is None:
            raise ValueError("session_factory is required (fail-closed: no silent anonymous fallback)")
        self._session_factory = session_factory

        def _reauth_from_factory(role: str) -> Any | None:
            # Automatic maintenance (ق7): a dead session re-authenticates
            # through the SAME factory that built it — the pool's
            # one-bounded-attempt rule still applies.
            profile = self._profiles.get(role)
            if profile is None or not profile.credentials_handle:
                return None
            return self._session_factory(profile)

        self._pool = SessionPool(
            health_probe=health_probe,
            reauth=_reauth_from_factory,
            health_interval=health_interval,
            max_sessions=max_roles,
            now=now,
        )
        self._now = now
        self._last_outcomes: list[IdentityBuildOutcome] = []

    # ------------------------------------------------------------------
    # build / maintain
    # ------------------------------------------------------------------

    @property
    def roles(self) -> list[str]:
        return sorted(self._profiles)

    def ensure_sessions(self) -> list[IdentityBuildOutcome]:
        """Build a session per profile via the factory; register successes.

        Bounded by the pool's capacity; every outcome is recorded (and
        retrievable via :attr:`last_outcomes`). Never raises — a factory
        error is that role's failure, others continue.
        """
        outcomes: list[IdentityBuildOutcome] = []
        for role in self.roles:
            profile = self._profiles[role]
            if not profile.credentials_handle:
                outcomes.append(
                    IdentityBuildOutcome(role=role, status="factory_none", detail="no credentials handle")
                )
                continue
            try:
                session = self._session_factory(profile)
            except Exception as exc:  # noqa: BLE001 — per-role fail-soft
                logger.debug("identity build failed for %s: %s", role, exc)
                outcomes.append(
                    IdentityBuildOutcome(role=role, status="factory_error", detail=type(exc).__name__)
                )
                continue
            if session is None:
                outcomes.append(IdentityBuildOutcome(role=role, status="factory_none"))
                continue
            if not self._pool.register(role, session):
                outcomes.append(IdentityBuildOutcome(role=role, status="capped"))
                continue
            outcomes.append(IdentityBuildOutcome(role=role, status="built"))
        self._last_outcomes = outcomes
        return outcomes

    @property
    def last_outcomes(self) -> list[IdentityBuildOutcome]:
        return list(self._last_outcomes)

    def acquire(self, role: str) -> Any | None:
        """Healthy session or None — the SessionPool fail-closed contract."""
        return self._pool.acquire(role)

    def maintain(self) -> dict[str, Any]:
        """Force a health pass over every role; re-auth bounded per role.

        Read-only reporting: role -> live/none plus re-auth counts.
        Never exposes session material.
        """
        for role in self.roles:
            # acquire() forces the pool's lazy health-check + bounded
            # re-auth per role; failures simply return None.
            self._pool.acquire(role)
        snapshot = {entry["role"]: entry for entry in self._pool.snapshot()}
        return {
            role: {
                "live": bool(snapshot.get(role, {}).get("healthy")),
                "reauth_count": int(snapshot.get(role, {}).get("reauth_count", 0)),
            }
            for role in self.roles
        }

    def session_provenance(self) -> dict[str, Any]:
        """Read-only live-roles snapshot for matrix/report attachment."""
        live = sorted(
            role
            for role in self.roles
            if self._pool.acquire(role) is not None
        )
        return {
            "live_roles": live,
            "configured_roles": self.roles,
            "raw_session_material_exposed": False,
        }

    # ------------------------------------------------------------------
    # LIVE sessions into the authorization matrix
    # ------------------------------------------------------------------

    def build_live_matrix(
        self,
        observations: Iterable[Mapping[str, Any]],
        *,
        target_url: str | None = None,
    ) -> dict[str, Any]:
        """Feed ``build_authorization_matrix`` with live-verified rows ONLY.

        Fail-closed per row: an observation whose ``role`` has no live
        session at build time is EXCLUDED from the matrix and recorded
        as an explicit ``no_live_session:<role>`` gap — the matrix never
        silently mixes assumed-identity rows with live ones. The return
        carries ``session_provenance`` on top of the standard matrix.
        """
        from webpent.shared.authorization_matrix import build_authorization_matrix

        accumulator = _ProvenanceAccumulator()
        for role in self.roles:
            if self._pool.acquire(role) is not None:
                accumulator.live_roles.add(role)

        verified: list[Mapping[str, Any]] = []
        for row in observations:
            if not isinstance(row, Mapping):
                accumulator.excluded_rows += 1
                continue
            role = str(row.get("role") or "").strip()
            if role not in accumulator.live_roles:
                accumulator.excluded_roles.add(role or "unknown")
                accumulator.excluded_rows += 1
                continue
            accumulator.verified_rows += 1
            verified.append(row)

        matrix = build_authorization_matrix(verified, target_url=target_url)
        gaps = list(matrix.get("coverage_gaps") or [])
        for role in sorted(accumulator.excluded_roles):
            gaps.append(f"no_live_session:{role}")
        if accumulator.excluded_rows:
            gaps.append("identity_rows_excluded_no_live_session")
        matrix["coverage_gaps"] = sorted(set(gaps))
        matrix["session_provenance"] = {
            "live_roles": sorted(accumulator.live_roles),
            "excluded_roles": sorted(accumulator.excluded_roles),
            "rows_verified_live": accumulator.verified_rows,
            "rows_excluded": accumulator.excluded_rows,
            "sessions_instead_of_assumptions": True,
        }
        return matrix
