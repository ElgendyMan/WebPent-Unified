"""webpent.auth.worker_session_factory — M3 UM-DR-17 (ق7): the runner-side
session_factory injection for the identity orchestrator.

M0 FEATURE_DELTA disposition for ق7 (identity_orchestrator):

    «غير موصول — يحتاج حقن session_factory من runner»
    ("not wired — needs session_factory injection from the runner")

The orchestrator (``auth/identity_orchestrator.py``) was fully built and
13/13 green but had NO production caller able to hand it a
``session_factory``: its constructor is deliberately fail-closed
(``session_factory is required — no silent anonymous fallback``), so
without a runner-side factory the whole live-identity column stays
unreachable. This module is that factory, backed by the worker-only
reauth vault:

* **Cookie restoration path** — the identity vault
  (``seal_identity_profiles`` / ``unseal_identity_profiles``) holds the
  operator-supplied per-role profiles (the SAME material
  ``run_pentest_task`` already seals); the factory restores a live
  session for a role whose profile carries validated cookies.
* **Login path** — an injected ``login_executor`` callable performs the
  actual multi-step login (the worker default is None: no executor, no
  session — fail-closed, exactly like the orchestrator's constructor).
* **Credentials are HANDLES, never values** — the factory receives
  ``IdentityProfile.credentials_handle`` (a vault key), resolves
  material INSIDE the vault boundary, and never returns raw secrets;
  the restored session object carries cookies only, and its repr is
  redacted.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from webpent.auth.identity_orchestrator import (
    IdentityBuildOutcome,
    IdentityOrchestrator,
    IdentityProfile,
)
from webpent.auth.reauth_vault import unseal_identity_profiles

logger = logging.getLogger(__name__)

SessionFactory = Callable[[IdentityProfile], Any | None]


@dataclass(frozen=True)
class RestoredSession:
    """A live session restored from the vault's sealed cookies.

    Carries cookie NAMES and the cookie jar only; the ``cookies`` mapping
    is the runtime material the pool hands to probes. The dataclass is
    deliberately repr-safe: ``redacted`` is the only string surfaced by
    default logging.
    """

    role: str
    source: str = "reauth_vault:identity_cookies"
    validated: bool = True
    _cookie_names: tuple[str, ...] = field(default=())

    @property
    def cookie_names(self) -> tuple[str, ...]:
        return self._cookie_names

    def __repr__(self) -> str:  # pragma: no cover - logging path
        return (
            f"RestoredSession(role={self.role!r}, source={self.source!r}, "
            f"cookies={len(self._cookie_names)}, validated={self.validated})"
        )


def profiles_from_state(
    identity_profiles: dict[str, Any] | None,
    *,
    credentials_handle: str,
) -> list[IdentityProfile]:
    """Convert the state channel's profile dicts to orchestrator profiles.

    The state ``identity_profiles`` channel carries
    ``{label: {name, role, cookies?, login_flow?, ...}}`` (the auth
    agent's report-safe runtime metadata). Only the ROLE and the
    login-flow step NAMES survive the conversion — cookies and every
    other runtime value stay in the vault, never in the profile.
    """
    out: list[IdentityProfile] = []
    if not isinstance(identity_profiles, dict):
        return out
    for label, profile in identity_profiles.items():
        if not isinstance(profile, dict):
            continue
        role = str(profile.get("role") or label or "").strip()
        if not role:
            continue
        steps = profile.get("login_flow") or profile.get("steps") or []
        step_names = tuple(
            str(step)[:120] for step in steps if str(step).strip()
        ) if isinstance(steps, (list, tuple)) else ()
        out.append(
            IdentityProfile(
                role=role,
                credentials_handle=credentials_handle,
                login_flow=step_names,
            )
        )
    return out


def vault_session_factory(
    *,
    thread_id: str,
    identity_key: str | None = None,
    login_executor: Callable[[IdentityProfile], Any | None] | None = None,
) -> SessionFactory:
    """Build the worker-side session factory backed by the reauth vault.

    Resolution order per profile (fail-closed — None means "no live
    session for this role", never an anonymous fallback):

    1. the identity vault's sealed profile for the role carries validated
       cookies → :class:`RestoredSession`;
    2. a ``login_executor`` is injected → its result (the executor owns
       the multi-step login; None/exception → no session);
    3. otherwise → None.
    """

    def _factory(profile: IdentityProfile) -> Any | None:
        vault_key = profile.credentials_handle or identity_key or thread_id
        sealed = unseal_identity_profiles(vault_key)
        if isinstance(sealed, dict):
            # STRICT role match on the sealed entry's OWN role field —
            # never a fallback scan over every sealed profile (that would
            # hand one role another role's session: a cross-role leak).
            for entry in sealed.values():
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("role") or "") != profile.role:
                    continue
                cookies = entry.get("cookies")
                if isinstance(cookies, dict) and cookies and entry.get("validated"):
                    return RestoredSession(
                        role=profile.role,
                        source="reauth_vault:identity_cookies",
                        validated=True,
                        _cookie_names=tuple(sorted(str(name) for name in cookies.keys())),
                    )
        if login_executor is not None:
            try:
                return login_executor(profile)
            except Exception as exc:  # noqa: BLE001 — per-role fail-soft
                logger.debug(
                    "ق7 login executor failed for role=%s: %s",
                    profile.role,
                    type(exc).__name__,
                )
                return None
        return None

    return _factory


@dataclass(frozen=True)
class WorkerIdentityOrchestrator:
    """The runner-side bundle: orchestrator + its provenance projection."""

    orchestrator: IdentityOrchestrator
    thread_id: str
    identity_key: str
    factory: SessionFactory
    profiles: tuple[IdentityProfile, ...]

    def ensure_sessions(self) -> list[IdentityBuildOutcome]:
        return self.orchestrator.ensure_sessions()

    def provenance(self) -> dict[str, Any]:
        """Report-safe projection for logs / the task result dict."""
        base = self.orchestrator.session_provenance()
        return {
            **base,
            "thread_id": self.thread_id,
            "identity_key": self.identity_key,
            "profiles": [profile.as_dict() for profile in self.profiles],
            "raw_session_material_exposed": False,
        }


def build_worker_identity_orchestrator(
    *,
    thread_id: str,
    client_id: str = "",
    engagement_id: str = "",
    identity_profiles: dict[str, Any] | None = None,
    login_executor: Callable[[IdentityProfile], Any | None] | None = None,
    health_probe: Callable[[str, Any], bool] | None = None,
) -> WorkerIdentityOrchestrator | None:
    """Construct the ق7 runner bundle, or None when there is nothing to run.

    None (not an empty orchestrator) when: no thread id, or no identity
    profiles — the honest "this engagement has no identity column" case.
    The vault key shape mirrors ``run_pentest_task``'s sealing exactly
    (``identity_vault_key(client_id, engagement_id)``), so the factory
    reads what the worker sealed.
    """
    from webpent.auth.reauth_vault import identity_vault_key

    if not str(thread_id).strip():
        return None
    identity_key = (
        identity_vault_key(str(client_id or ""), str(engagement_id or thread_id))
        or thread_id
    )
    profiles = profiles_from_state(identity_profiles, credentials_handle=identity_key)
    if not profiles:
        return None
    factory = vault_session_factory(
        thread_id=thread_id,
        identity_key=identity_key,
        login_executor=login_executor,
    )
    orchestrator = IdentityOrchestrator(
        profiles=profiles,
        session_factory=factory,
        health_probe=health_probe,
    )
    return WorkerIdentityOrchestrator(
        orchestrator=orchestrator,
        thread_id=thread_id,
        identity_key=identity_key,
        factory=factory,
        profiles=tuple(profiles),
    )


__all__ = [
    "RestoredSession",
    "WorkerIdentityOrchestrator",
    "build_worker_identity_orchestrator",
    "profiles_from_state",
    "vault_session_factory",
]
