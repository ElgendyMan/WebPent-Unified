"""webpent.approvals.binding — M9 (Part 4 §11): approval binding,
voiding-on-material-change, and the audit trail.

Part 4 §11: "approval bound to (engagement, manifest, action, target,
identity, tier, preview, budget, approver, expiry); material change
voids approval" and "channels: CLI prompt first, authenticated
notification integrations optional (notification ≠ approval);
timeout/deny/cancel/emergency-stop". Acceptance: "approval audit
trail complete; no approval reuse after material change (tested)".

Design:

* :func:`fingerprint_action` — the canonical sha256 over the binding
  tuple's action side (method, path, family, capability, identity,
  tier, preview digest, budget). ANY change to any component changes
  the fingerprint — that IS the material-change detector.
* :class:`ApprovalBinding` — the immutable approval record bound to
  the full tuple, with expiry and status.
* :class:`ApprovalLedger` — the append-only audit trail (JSONL):
  every lifecycle event (requested / granted / denied / timeout /
  cancelled / voided / consumed / expired / emergency_stop) recorded
  with its timestamp and the binding id.
* :class:`ApprovalGate` — the channel-first gate: CLI prompt first
  (the channel handler is injectable; tests stub it), timeout / deny /
  cancel paths, one-time CONSUME (reuse refused), material-change
  VOIDING (any tuple component change), expiry, and the global
  emergency stop. The gate COMPLETES authorization, never replaces
  it: its output is an approval the authorization layer may consult —
  a policy denial still wins (test-pinned).
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from webpent.approvals.classification import ApprovalTier, TierClassification

__all__ = [
    "ApprovalBinding",
    "ApprovalGate",
    "ApprovalLedger",
    "ChannelOutcome",
    "fingerprint_action",
]

ChannelHandler = Callable[[Mapping[str, Any]], "ChannelOutcome"]


@dataclass(frozen=True)
class ChannelOutcome:
    """One approval channel's answer.

    ``granted`` may only be True for an APPROVAL channel (CLI prompt,
    authenticated interactive). Notification channels return
    ``notification_only=True`` — their outcomes can never grant.
    """

    granted: bool = False
    notification_only: bool = False
    approver: str = ""
    detail: str = ""


def cli_prompt_channel(request: Mapping[str, Any]) -> ChannelOutcome:
    """The CLI-prompt-first channel (Part 4 §11's default).

    Prompts on stdin; empty/refused input is a DENY. Tests inject
    their own handler; production callers wrap this for TTY checks.
    """
    try:
        answer = input(
            f"Approve {request.get('tier', '?')} action "
            f"{request.get('method', '')} {request.get('path', '')} "
            f"(budget {request.get('budget', 0)})? [y/N] "
        )
    except EOFError:
        return ChannelOutcome(granted=False, detail="eof")
    granted = answer.strip().lower() in {"y", "yes"}
    return ChannelOutcome(granted=granted, approver="cli-operator", detail=answer.strip()[:40])


def fingerprint_action(
    *,
    engagement_id: str,
    manifest_digest: str,
    method: str,
    path: str,
    action_family: str,
    capability: str,
    identity_ref: str,
    tier: str,
    preview: str,
    budget: float,
) -> str:
    """The canonical action fingerprint (any component change alters it)."""
    canonical = json.dumps(
        {
            "engagement_id": str(engagement_id),
            "manifest_digest": str(manifest_digest),
            "method": str(method).upper(),
            "path": str(path),
            "action_family": str(action_family),
            "capability": str(capability),
            "identity_ref": str(identity_ref),
            "tier": str(tier),
            "preview_digest": hashlib.sha256(str(preview).encode("utf-8", "replace")).hexdigest()[:16],
            "budget": round(float(budget), 6),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class ApprovalBinding:
    """The immutable approval record — the full Part 4 §11 tuple."""

    approval_id: str
    engagement_id: str
    manifest_digest: str
    action_fingerprint: str
    method: str
    path: str
    action_family: str
    capability: str
    identity_ref: str
    tier: ApprovalTier
    preview: str
    budget: float
    approver: str
    approved_at: float
    expires_at: float
    channel: str = "cli_prompt"
    status: str = "granted"  # granted | denied | timeout | cancelled | voided | consumed

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at

    def as_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "engagement_id": self.engagement_id,
            "manifest_digest": self.manifest_digest,
            "action_fingerprint": self.action_fingerprint,
            "method": self.method,
            "path": self.path,
            "action_family": self.action_family,
            "capability": self.capability,
            "identity_ref": self.identity_ref,
            "tier": self.tier.value,
            "preview": self.preview[:200],
            "budget": self.budget,
            "approver": self.approver,
            "approved_at": self.approved_at,
            "expires_at": self.expires_at,
            "channel": self.channel,
            "status": self.status,
        }


class ApprovalLedger:
    """Append-only JSONL audit trail — every event, ordered, durable."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._path = Path(path) if path else None
        self._events: list[dict[str, Any]] = []

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        entry = {
            "event": event,
            "recorded_at": time.time(),
            "uuid": uuid.uuid4().hex[:12],
            **fields,
        }
        self._events.append(entry)
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def events(self) -> list[dict[str, Any]]:
        return list(self._events)

    def events_for(self, approval_id: str) -> list[dict[str, Any]]:
        return [e for e in self._events if e.get("approval_id") == approval_id]


@dataclass
class ApprovalGate:
    """The channel-first approval gate with voiding and emergency stop."""

    engagement_id: str
    manifest_digest: str = ""
    ledger: ApprovalLedger = field(default_factory=ApprovalLedger)
    channel: ChannelHandler = cli_prompt_channel
    channel_name: str = "cli_prompt"
    default_ttl_seconds: float = 3600.0
    _bindings: dict[str, ApprovalBinding] = field(default_factory=dict)
    _emergency_stopped: bool = False

    def emergency_stop(self, reason: str = "") -> None:
        self._emergency_stopped = True
        self.ledger.record("emergency_stop", engagement_id=self.engagement_id, reason=reason[:200])

    def _fingerprint(
        self,
        *,
        method: str,
        path: str,
        action_family: str,
        capability: str,
        identity_ref: str,
        tier: str,
        preview: str,
        budget: float,
    ) -> str:
        return fingerprint_action(
            engagement_id=self.engagement_id,
            manifest_digest=self.manifest_digest,
            method=method,
            path=path,
            action_family=action_family,
            capability=capability,
            identity_ref=identity_ref,
            tier=tier,
            preview=preview,
            budget=budget,
        )

    def request_approval(
        self,
        classification: TierClassification,
        *,
        method: str,
        path: str,
        action_family: str,
        capability: str,
        identity_ref: str,
        preview: str,
        budget: float,
        ttl_seconds: float | None = None,
    ) -> ApprovalBinding:
        """Run the channel; return the binding (status carries the outcome).

        TIER_0 never prompts (no approval required — authorization
        alone governs). Emergency stop refuses everything. The channel
        outcome is recorded in the ledger either way.
        """
        if self._emergency_stopped:
            binding = ApprovalBinding(
                approval_id=uuid.uuid4().hex[:16],
                engagement_id=self.engagement_id,
                manifest_digest=self.manifest_digest,
                action_fingerprint="",
                method=method,
                path=path,
                action_family=action_family,
                capability=capability,
                identity_ref=identity_ref,
                tier=classification.tier,
                preview=preview,
                budget=budget,
                approver="",
                approved_at=time.time(),
                expires_at=time.time(),
                channel=self.channel_name,
                status="cancelled",
            )
            self.ledger.record(
                "cancelled",
                approval_id=binding.approval_id,
                reason="emergency_stop_active",
                tier=classification.tier.value,
            )
            self._bindings[binding.approval_id] = binding
            return binding

        if not classification.approval_required:
            binding = ApprovalBinding(
                approval_id=uuid.uuid4().hex[:16],
                engagement_id=self.engagement_id,
                manifest_digest=self.manifest_digest,
                action_fingerprint="",
                method=method,
                path=path,
                action_family=action_family,
                capability=capability,
                identity_ref=identity_ref,
                tier=classification.tier,
                preview=preview,
                budget=budget,
                approver="policy:tier_0",
                approved_at=time.time(),
                expires_at=time.time(),
                channel=self.channel_name,
                status="granted",
            )
            self.ledger.record(
                "granted",
                approval_id=binding.approval_id,
                tier=classification.tier.value,
                reason="tier_0_no_approval_required",
            )
            self._bindings[binding.approval_id] = binding
            return binding

        fingerprint = self._fingerprint(
            method=method,
            path=path,
            action_family=action_family,
            capability=capability,
            identity_ref=identity_ref,
            tier=classification.tier.value,
            preview=preview,
            budget=budget,
        )
        self.ledger.record(
            "requested",
            engagement_id=self.engagement_id,
            tier=classification.tier.value,
            method=method,
            path=path,
            action_fingerprint=fingerprint,
            budget=budget,
        )
        outcome = self.channel(
            {
                "engagement_id": self.engagement_id,
                "tier": classification.tier.value,
                "method": method,
                "path": path,
                "preview": preview[:200],
                "budget": budget,
                "reasons": list(classification.reasons),
            }
        )
        if outcome.notification_only:
            # A notification channel can never grant (Part 4 §11).
            status = "timeout"
            approver = ""
        elif outcome.granted:
            status = "granted"
            approver = outcome.approver or "unknown-approver"
        elif outcome.detail == "timeout":
            status = "timeout"
            approver = ""
        else:
            status = "denied"
            approver = outcome.approver or ""

        ttl = self.default_ttl_seconds if ttl_seconds is None else float(ttl_seconds)
        binding = ApprovalBinding(
            approval_id=uuid.uuid4().hex[:16],
            engagement_id=self.engagement_id,
            manifest_digest=self.manifest_digest,
            action_fingerprint=fingerprint if status == "granted" else "",
            method=method,
            path=path,
            action_family=action_family,
            capability=capability,
            identity_ref=identity_ref,
            tier=classification.tier,
            preview=preview,
            budget=budget,
            approver=approver,
            approved_at=time.time(),
            expires_at=time.time() + ttl,
            channel=self.channel_name,
            status=status,
        )
        self.ledger.record(
            status,
            approval_id=binding.approval_id,
            approver=approver,
            action_fingerprint=binding.action_fingerprint,
            tier=classification.tier.value,
            channel_detail=outcome.detail[:120],
        )
        self._bindings[binding.approval_id] = binding
        return binding

    def consume(
        self,
        binding: ApprovalBinding,
        *,
        method: str,
        path: str,
        action_family: str,
        capability: str,
        identity_ref: str,
        tier: str,
        preview: str,
        budget: float,
    ) -> tuple[bool, str]:
        """One-time consumption with material-change voiding.

        Refusal reasons: not granted / already consumed / expired /
        material change (fingerprint mismatch) / emergency stop.
        """
        if self._emergency_stopped:
            self.ledger.record("refused", approval_id=binding.approval_id, reason="emergency_stop_active")
            return False, "emergency_stop_active"
        # Resolve the CURRENT registry state — the caller may hold a
        # stale pre-consumption copy of the immutable binding.
        current_state = self._bindings.get(binding.approval_id, binding)
        if current_state.status != "granted":
            return False, f"binding_not_granted:{current_state.status}"
        if current_state.expired:
            self._void(current_state, "expired")
            return False, "expired"
        current = self._fingerprint(
            method=method,
            path=path,
            action_family=action_family,
            capability=capability,
            identity_ref=identity_ref,
            tier=tier,
            preview=preview,
            budget=budget,
        )
        if current != current_state.action_fingerprint:
            self._void(current_state, "material_change")
            return False, "material_change_voids_approval"
        consumed = current_state.__class__(
            **{**current_state.__dict__, "status": "consumed"}
        )
        self._bindings[current_state.approval_id] = consumed
        self.ledger.record(
            "consumed",
            approval_id=current_state.approval_id,
            action_fingerprint=current,
        )
        return True, "consumed"

    def cancel(self, binding: ApprovalBinding, reason: str = "") -> None:
        self._void(binding, f"cancelled:{reason[:80]}" if reason else "cancelled")

    def _void(self, binding: ApprovalBinding, reason: str) -> None:
        voided = binding.__class__(**{**binding.__dict__, "status": "voided"})
        self._bindings[binding.approval_id] = voided
        self.ledger.record("voided", approval_id=binding.approval_id, reason=reason[:200])
