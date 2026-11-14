"""webpent.oast.bridge — OAST verification bridge (ق1 revival).

The legacy v4 line ships a full OAST layer (``webpent.oast.server`` /
``webpent.oast.correlate``) and the newer engine ships
``webpent.shared.oob_provider`` (interactsh sessions, redacted
interactions). Neither is wired to the CURRENT evidence pipeline: the
engine cannot see out-of-band interactions, so whole vulnerability
classes (blind SSRF, XXE, blind SQLi via timing/OOB, cache poisoning
confirmation, webhook side effects) stay invisible to it.

This bridge closes exactly that gap WITHOUT breaking the project's
evidence-first philosophy:

  - every hypothesis gets a per-hypothesis NONCE (HMAC over the
    hypothesis id, engine-held secret): an interaction only correlates
    when its nonce matches, so cross-hypothesis or forged callbacks
    cannot manufacture evidence;
  - the bridge emits CANDIDATE findings ONLY — the output schema has
    no verdict field at all, and every candidate carries
    ``requires_validator=True``: a deterministic validator (the same
    cqa_v2 contract the rest of the pipeline uses) must confirm before
    anything is promoted. An OAST interaction is an observation, never
    a verdict;
  - interactions are deduplicated by their evidence digest, and the
    provider's own redaction (no raw headers/bodies — digests only)
    is preserved end to end.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Any, Protocol

__all__ = [
    "OastVerificationBridge",
    "CandidateFinding",
    "CandidateOnlyRule",
]

_BRIDGE_SECRET_CONTEXT = "webpent/oast-bridge/v1"


class CandidateOnlyRule(Exception):
    """Raised when a caller asks the bridge to hand out a verdict.

    The rule is enforced twice: the candidate schema has no verdict
    field, and this guard makes the intent impossible to bypass by
    accident. Promotion belongs to the deterministic validator layer.
    """


class _InteractionSource(Protocol):
    """The subset of ``webpent.shared.oob_provider.OobProvider`` used."""

    def open(self, finding_id: str) -> str | None: ...

    def poll(
        self, finding_id: str, timeout_seconds: float, max_attempts: int
    ) -> Any: ...

    def close(self, finding_id: str) -> None: ...


@dataclass(frozen=True)
class CandidateFinding:
    """An OAST-correlated CANDIDATE finding — never a verdict."""

    hypothesis_id: str
    nonce: str
    payload_host: str
    interaction_type: str
    evidence_digest: str
    observed_at: str | None = None
    requires_validator: bool = True
    status: str = "candidate"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": "candidate_finding",
            "hypothesis_id": self.hypothesis_id,
            "nonce": self.nonce,
            "payload_host": self.payload_host,
            "interaction_type": self.interaction_type,
            "evidence_digest": self.evidence_digest,
            "observed_at": self.observed_at,
            "requires_validator": self.requires_validator,
            "status": self.status,
        }


@dataclass
class _HypothesisSession:
    hypothesis_id: str
    nonce: str
    finding_id: str
    payload_host: str | None
    seen_digests: set[str] = field(default_factory=set)


def _nonce_for(hypothesis_id: str, secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"),
        f"{_BRIDGE_SECRET_CONTEXT}:{hypothesis_id}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    # interactsh-style subdomain label: lowercase alphanumeric, bounded
    return digest[:20]


class OastVerificationBridge:
    """Per-hypothesis OAST sessions correlated to candidate findings."""

    def __init__(
        self,
        provider: _InteractionSource,
        *,
        secret: str,
        poll_timeout_seconds: float = 5.0,
        max_attempts: int = 3,
    ) -> None:
        if not secret:
            raise ValueError("oast bridge requires an engine-held secret")
        self._provider = provider
        self._secret = secret
        self._poll_timeout = poll_timeout_seconds
        self._max_attempts = max_attempts
        self._sessions: dict[str, _HypothesisSession] = {}

    # -- session lifecycle -------------------------------------------

    def arm(self, hypothesis_id: str) -> str | None:
        """Open an OAST session for one hypothesis; returns the nonce.

        Fail-soft: a provider that cannot open a session (no network
        collab domain, offline mode) returns None — the investigation
        continues with in-band evidence only.
        """
        if hypothesis_id in self._sessions:
            return self._sessions[hypothesis_id].nonce
        nonce = _nonce_for(hypothesis_id, self._secret)
        finding_id = f"oast-{nonce}"
        payload_host = self._provider.open(finding_id)
        if not payload_host:
            return None
        self._sessions[hypothesis_id] = _HypothesisSession(
            hypothesis_id=hypothesis_id,
            nonce=nonce,
            finding_id=finding_id,
            payload_host=payload_host,
        )
        return nonce

    def payload_host(self, hypothesis_id: str) -> str | None:
        session = self._sessions.get(hypothesis_id)
        return session.payload_host if session else None

    def disarm(self, hypothesis_id: str) -> None:
        session = self._sessions.pop(hypothesis_id, None)
        if session is not None:
            self._provider.close(session.finding_id)

    # -- correlation ---------------------------------------------------

    def poll(self, hypothesis_id: str) -> list[CandidateFinding]:
        """Poll the session and return NEW correlated candidates.

        An interaction correlates ONLY when the provider redacted it
        under this session's own payload host (the nonce-signed
        subdomain). Digests are passed through from the provider — the
        bridge never re-derives evidence content, so it cannot invent
        what the collector did not see.
        """
        session = self._sessions.get(hypothesis_id)
        if session is None:
            return []
        interaction = self._provider.poll(
            session.finding_id,
            timeout_seconds=self._poll_timeout,
            max_attempts=self._max_attempts,
        )
        if interaction is None:
            return []
        host = str(getattr(interaction, "payload_host", "") or "")
        digest = str(getattr(interaction, "evidence_digest", "") or "")
        if not host or not digest:
            return []
        # nonce binding: the observed host must be the nonce-signed
        # subdomain of the session's own payload host — a callback on
        # another host (or another hypothesis's host) correlates to
        # nothing.
        if session.payload_host not in host or session.nonce not in host:
            return []
        if digest in session.seen_digests:
            return []
        session.seen_digests.add(digest)
        return [
            CandidateFinding(
                hypothesis_id=hypothesis_id,
                nonce=session.nonce,
                payload_host=host,
                interaction_type=str(
                    getattr(interaction, "interaction_type", "") or ""),
                evidence_digest=digest,
                observed_at=getattr(interaction, "observed_at", None),
            )
        ]

    # -- the hard rule ---------------------------------------------------

    @staticmethod
    def confirm(candidate: CandidateFinding, **_kwargs: Any) -> None:
        """Never callable: promotion is not the bridge's job."""
        raise CandidateOnlyRule(
            "the OAST bridge emits candidates only; promotion requires a "
            "deterministic validator (cqa_v2 contract)"
        )
