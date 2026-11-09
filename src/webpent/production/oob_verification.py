# src/webpent/production/oob_verification.py
"""webpent.production.oob_verification — Track 12, item 7.

Roadmap contract (المسار 12، البند 7 — التحقق خارج النطاق المحلي):

    أي خدمة callbacks لإثبات حالات عمياء لا تُتاح إلا في بيئة يسيطر
    عليها المستخدم، وبموافقة صريحة ونطاق محدود، مع منع استخدامها ضد
    أطراف غير مخولة.

    ("Any callback service for proving blind findings is available ONLY
    in an environment the USER controls, with explicit consent and a
    limited scope, and NEVER against unauthorized parties.")

Design
------
``OobVerifier`` is the policy gate + interaction ledger for using an
out-of-band callback service to prove blind findings (SSRF, blind
XSS...):

* **User-controlled only (hard gate):** the callback endpoint must be
  provided by the operator (``OobServiceConfig.base_url``), and the
  verifier refuses to enable itself unless ``user_controlled`` AND
  ``explicit_consent`` are both set. Third-party OOB services are NOT
  wired and NOT accepted — there is no default endpoint anywhere in
  the module, and nothing is enabled by default.
* **Scope-limited:** the config carries the authorized scope hash and
  (optionally) the allowed origins. A callback credit for an
  interaction whose finding target falls outside the scope is DENIED
  and logged — OOB confirmations can never be used to bless out-of-
  scope hits.
* **Per-finding interaction tokens:** deterministic, keyless,
  id-carrying markers (``campaign:finding:nonce`` digests) so an
  inbound callback can be attributed to exactly one finding attempt.
  Tokens leak nothing (identifier digests only).
* **Attribution ledger:** inbound interactions are appended to a
  client-scoped JSONL ledger (hash) with the decision (credited /
  denied_scope / denied_unknown_token). The platform's existing
  ``mark_oob_confirmed`` path remains the single place where a finding
  becomes CONFIRMED; this module only decides whether an inbound
  callback is trustworthy and in-scope.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

__all__ = [
    "OobDecision",
    "OobInteraction",
    "OobServiceConfig",
    "OobVerifier",
    "build_interaction_token",
]


@dataclass
class OobServiceConfig:
    """Operator-supplied callback service (user-controlled, consented)."""

    base_url: str = ""
    user_controlled: bool = False
    explicit_consent: bool = False
    scope_hash: str = ""
    allowed_origins: tuple[str, ...] = ()
    note: str = ""


@dataclass
class OobInteraction:
    """One inbound callback observation (identifier-level only)."""

    token: str
    source_ip_hash: str = ""   # hashed — raw IPs never stored
    received_at: float = field(default_factory=time.time)
    decision: str = ""         # credited | denied_scope | denied_unknown_token
    finding_ref: str = ""
    detail: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "source_ip_hash": self.source_ip_hash,
            "received_at": self.received_at,
            "decision": self.decision,
            "finding_ref": self.finding_ref,
            "detail": self.detail[:200],
        }


@dataclass
class OobDecision:
    """Policy verdict for an inbound callback."""

    credited: bool
    reason: str
    interaction: OobInteraction

    def as_dict(self) -> dict[str, Any]:
        return {"credited": self.credited, "reason": self.reason, **self.interaction.as_dict()}


def build_interaction_token(
    campaign_id: str,
    finding_ref: str,
    nonce: str,
    *,
    scope_hash: str = "",
) -> str:
    """Deterministic, information-free interaction marker.

    Only digests of identifiers — no target URLs, no payloads. The
    scope hash participates so tokens are not portable across scopes.
    """
    payload = "|".join(
        (campaign_id, finding_ref, nonce, scope_hash)
    )
    digest = hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:24]
    return f"oob-{digest}"


class OobVerifier:
    """Consent-gated, scope-limited OOB callback policy + ledger."""

    def __init__(
        self,
        config: OobServiceConfig,
        *,
        ledger_dir: str | os.PathLike[str] | None = None,
    ) -> None:
        self._config = config
        self._known_tokens: set[str] = set()
        self._token_index: dict[str, str] = {}  # token -> finding_ref
        self._ledger_dir = Path(ledger_dir).expanduser() if ledger_dir else None  # noqa: E501
        if self._ledger_dir is not None:
            self._ledger_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    # ------------------------------------------------------------------
    # enablement gate (the roadmap's hard conditions)
    # ------------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        """Available ONLY when the environment is user-controlled with
        explicit consent. There is no default endpoint and no bypass."""
        cfg = self._config
        return bool(
            cfg.user_controlled
            and cfg.explicit_consent
            and str(cfg.base_url or "").strip()
            and cfg.scope_hash.strip()
        )

    def disabled_reason(self) -> str:
        if self.enabled:
            return ""
        if not self._config.user_controlled:
            return "callback endpoint is not an environment the user controls"
        if not self._config.explicit_consent:
            return "explicit operator consent missing"
        if not str(self._config.base_url or "").strip():
            return "no user-controlled callback endpoint configured"
        return "no scope hash bound — OOB credit would be scope-less"

    # ------------------------------------------------------------------
    # outbound: markers embedded in probes
    # ------------------------------------------------------------------
    def issue_token(self, campaign_id: str, finding_ref: str, nonce: str) -> str | None:
        """Mint a marker for an in-scope probe. None when disabled."""
        if not self.enabled:
            return None
        token = build_interaction_token(
            campaign_id, finding_ref, nonce, scope_hash=self._config.scope_hash
        )
        self._known_tokens.add(token)
        self._token_index[token] = finding_ref
        return token

    def callback_url(self, token: str) -> str | None:
        """The user-controlled endpoint URL carrying this marker."""
        if not self.enabled or not token:
            return None
        base = self._config.base_url.rstrip("/")
        return f"{base}/{token}"

    # ------------------------------------------------------------------
    # inbound: attribution + scope check
    # ------------------------------------------------------------------
    def record_interaction(
        self,
        token: str,
        *,
        finding_target_origin: str = "",
        source_ip: str = "",
    ) -> OobDecision:
        """Attribute an inbound callback. Credits ONLY known tokens
        whose finding target is inside the authorized scope."""
        ip_hash = (
            hashlib.sha256(str(source_ip).encode("utf-8", "replace")).hexdigest()[:16]
            if source_ip
            else ""
        )
        interaction = OobInteraction(token=str(token or ""), source_ip_hash=ip_hash)

        if not self.enabled:
            interaction.decision = "denied_unknown_token"
            interaction.detail = "verifier disabled (consent/control gate)"
            self._append(interaction)
            return OobDecision(False, self.disabled_reason(), interaction)

        token_str = str(token or "")
        if token_str not in self._known_tokens:
            interaction.decision = "denied_unknown_token"
            interaction.detail = "token not issued by this verifier"
            self._append(interaction)
            return OobDecision(False, "unknown interaction token", interaction)

        finding_ref = self._token_index.get(token_str, "")
        interaction.finding_ref = finding_ref

        origin = ""
        try:
            parts = urlsplit(str(finding_target_origin or "").strip())
            origin = f"{(parts.scheme or 'https').lower()}://{(parts.hostname or '').lower()}"
        except ValueError:
            origin = ""
        allowed = {o.lower().rstrip("/") for o in self._config.allowed_origins}
        # Empty allowlist → the scope-bound token IS the scope control.
        in_scope = (not allowed and bool(origin)) or (origin in allowed)
        if not in_scope:
            interaction.decision = "denied_scope"
            interaction.detail = f"origin '{origin or 'unknown'}' outside authorized origins"
            self._append(interaction)
            return OobDecision(
                False, "interaction target outside the authorized scope", interaction
            )

        interaction.decision = "credited"
        interaction.detail = "in-scope interaction credited for confirmation path"
        self._append(interaction)
        return OobDecision(True, "in-scope callback credited", interaction)

    # ------------------------------------------------------------------
    # ledger (client-scoped via hashed subdir when dir provided)
    # ------------------------------------------------------------------
    def _append(self, interaction: OobInteraction) -> None:
        if self._ledger_dir is None:
            return
        try:
            sub = self._ledger_dir
            if self._config.scope_hash:
                digest = hashlib.sha256(
                    self._config.scope_hash.encode("utf-8", "replace")
                ).hexdigest()[:12]
                sub = self._ledger_dir / f"scope-{digest}"
                sub.mkdir(parents=True, exist_ok=True, mode=0o700)
            with open(sub / "oob_interactions.jsonl", "a", encoding="utf-8") as fh:
                fh.write(json.dumps(interaction.as_dict(), separators=(",", ":")) + "\n")
        except OSError:
            logger.warning("oob_verification: ledger append failed", exc_info=True)

    def read_ledger(self, *, limit: int = 200) -> list[dict[str, Any]]:
        if self._ledger_dir is None:
            return []
        path = self._ledger_dir
        if self._config.scope_hash:
            digest = hashlib.sha256(
                self._config.scope_hash.encode("utf-8", "replace")
            ).hexdigest()[:12]
            path = self._ledger_dir / f"scope-{digest}"
        try:
            with open(path / "oob_interactions.jsonl", encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError:
            return []
        records: list[dict[str, Any]] = []
        for line in lines[-max(1, limit) :]:
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    records.append(data)
            except ValueError:
                continue
        return records
