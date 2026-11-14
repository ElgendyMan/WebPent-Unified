"""Central policy gate for autonomous actions.

This module intentionally separates authorization from transport. It never
constructs HTTP requests or shell commands; callers provide a handler only
after the request has passed the deterministic gates here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from urllib.parse import urlsplit

from webpent.config.settings import ScanMode, Settings, get_settings
from webpent.shared.action_ledger import SQLiteActionLedger
from webpent.shared.capability_manifest import capability_available
from webpent.shared.package_scope import ScopeCompiler
from webpent.shared.safety_gate import EngagementSafetyGate


class ActionRisk(str, Enum):
    """Risk tiers used by the authority gate."""

    READ_ONLY = "read_only"
    ACTIVE = "active"
    DESTRUCTIVE = "destructive"


class ActionStatus(str, Enum):
    """Typed authorization/execution outcomes."""

    AUTHORIZED = "authorized"
    POLICY_DENIED = "policy_denied"
    INFRASTRUCTURE_FAILURE = "infrastructure_failure"
    EXECUTED = "executed"


@dataclass(frozen=True)
class ActionRequest:
    """Bounded action intent; it is not a transport request."""

    task_id: str
    engagement_id: str
    target_url: str
    method: str = "GET"
    action_family: str = "http_read"
    capability: str = "http_read"
    risk: ActionRisk = ActionRisk.READ_ONLY
    identity_ref: str = "anonymous"
    idempotency_key: str = ""
    estimated_cost: float = 1.0
    human_approved: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ActionDecision:
    """Immutable policy decision with machine-readable reasons."""

    status: ActionStatus
    reasons: tuple[str, ...]
    audit_event: dict[str, Any]

    @property
    def allowed(self) -> bool:
        return self.status == ActionStatus.AUTHORIZED


@dataclass(frozen=True)
class ActionResult:
    """Execution result returned by the central executor."""

    status: ActionStatus
    decision: ActionDecision
    output: Any = None


class ActionAuthority:
    """Deterministic, fail-closed policy authority for one engagement."""

    _ALLOWED_FAMILIES = frozenset(
        {
            "http_read",
            "browser_read",
            "browser_action",
            "recon",
            "validation",
            "workflow",
            "form_submit",
            "file_upload",
            "oob",
        }
    )
    _READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

    # Sprint I-1, item 2.5 (M3 v1.1 §5.3): the flag spec's own fallback
    # pattern (D-02's exact symbol list is not available to this sprint —
    # see the sprint changelog) — a capability name containing any of
    # these substrings, case-insensitive, is treated as a foreign-writer
    # registration attempt.
    _FOREIGN_WRITER_PATTERNS = ("report", "writer", "persist", "ledger", "finding", "export")

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        allowed_origin: str,
        manifest: dict[str, Any] | None = None,
        used_actions: int = 0,
        used_budget: float = 0.0,
        ledger: SQLiteActionLedger | None = None,
        adapter_registry: Any | None = None,
        require_g02: bool = False,
        safety_gate: EngagementSafetyGate | None = None,
        target_package: Mapping[str, Any] | None = None,
        scope_compiler: ScopeCompiler | None = None,
        # Sprint I-1, item 2.5 (M3 v1.1 §5.3): defaults to the fail-closed
        # value. Callers that have resolved a ProductionSpineConfig pass
        # config.foreign_report_writer_access through explicitly.
        foreign_report_writer_access: bool = False,
    ) -> None:
        self.settings = settings or get_settings()
        self.allowed_origin = self._normalize_origin(allowed_origin)
        self.manifest = manifest or {}
        self.used_actions = used_actions
        self.used_budget = used_budget
        self.ledger = ledger
        self.adapter_registry = adapter_registry
        self.require_g02 = bool(require_g02)
        self.safety_gate = safety_gate
        self.target_package = dict(target_package or {})
        self.scope_compiler = scope_compiler
        self.foreign_report_writer_access = bool(foreign_report_writer_access)
        self.trace: list[dict[str, Any]] = []

    @staticmethod
    def _normalize_origin(value: str) -> str:
        parsed = urlsplit(str(value or "").strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return ""
        host = parsed.hostname.lower()
        port = parsed.port
        default_port = (parsed.scheme.lower() == "http" and port in {None, 80}) or (
            parsed.scheme.lower() == "https" and port in {None, 443}
        )
        return f"{parsed.scheme.lower()}://{host}{'' if default_port else f':{port}'}"

    def _decision(
        self, request: ActionRequest, reasons: list[str], status: ActionStatus
    ) -> ActionDecision:
        event = {
            "task_id": request.task_id[:128],
            "engagement_id": request.engagement_id[:128],
            "action_family": request.action_family[:64],
            "method": request.method.upper()[:16],
            "risk": request.risk.value,
            "identity_ref": request.identity_ref[:128],
            "status": status.value,
            "reasons": tuple(reasons),
        }
        self.trace.append(event)
        return ActionDecision(status=status, reasons=tuple(reasons), audit_event=event)

    def authorize(self, request: ActionRequest) -> ActionDecision:
        """Authorize an action without invoking any external handler."""
        # Sprint I-1, item 2.5 (M3 v1.1 §5.3): checked FIRST and raises
        # (not a soft policy_denied reason) — this is meant to be loud
        # and un-absorbable by ordinary decision-reason handling. Does
        # NOT apply to the OQ-1-ratified sanctioned writers (worker/CLI
        # persistence), which never construct an ActionRequest through
        # this authority at all.
        if not self.foreign_report_writer_access:
            capability_lower = request.capability.lower()
            for pattern in self._FOREIGN_WRITER_PATTERNS:
                if pattern in capability_lower:
                    from webpent.shared.exceptions import ForeignWriterAccessDenied

                    raise ForeignWriterAccessDenied(
                        gate="action_authority.capability_registration",
                        detail=(
                            f"capability={request.capability!r} matches foreign-writer "
                            f"pattern {pattern!r}"
                        ),
                    )
        reasons: list[str] = []
        method = request.method.upper().strip()
        mode = getattr(self.settings.scan_mode, "value", self.settings.scan_mode)
        target_origin = self._normalize_origin(request.target_url)

        if self.safety_gate is not None:
            safety_decision = self.safety_gate.authorize_request(request)
            if not safety_decision.allowed:
                reasons.extend(safety_decision.reasons)

        if not request.task_id or not request.engagement_id:
            reasons.append("identity:task_and_engagement_required")
        if self.target_package:
            if self.scope_compiler is None:
                reasons.append("package:scope_compiler_unavailable")
            else:
                scope_decision = self.scope_compiler.decide(
                    request.target_url,
                    method=method,
                    action_class=request.action_family,
                    redirect_chain=tuple(
                        str(item) for item in (request.metadata.get("redirect_chain") or [])
                    ),
                )
                if not scope_decision.allowed:
                    reasons.append(f"scope:{scope_decision.status.value}:{scope_decision.reason}")
            package_status = str(
                self.target_package.get("status")
                or self.target_package.get("target_package_status")
                or ""
            )
            if package_status != "ready":
                reasons.append("package:admission_not_ready")
            if str(self.target_package.get("revocation_state") or "active") == "revoked":
                reasons.append("package:revoked")
            expiry = self.target_package.get("expires_at") or self.target_package.get(
                "package_expires_at"
            )
            try:
                parsed_expiry = datetime.fromisoformat(
                    str(expiry).replace("Z", "+00:00")
                ).astimezone(UTC)
                if not expiry or parsed_expiry <= datetime.now(UTC):
                    reasons.append("package:expired_or_invalid_expiry")
            except (TypeError, ValueError):
                reasons.append("package:expired_or_invalid_expiry")
            request_package_id = str(request.metadata.get("target_package_id") or "")
            package_id = str(
                self.target_package.get("package_id")
                or self.target_package.get("target_package_id")
                or ""
            )
            if not package_id or request_package_id != package_id:
                reasons.append("package:package_id_mismatch")
            request_digest = str(request.metadata.get("target_package_sha256") or "")
            package_digest = str(
                self.target_package.get("package_sha256")
                or self.target_package.get("target_package_sha256")
                or ""
            )
            if not package_digest or request_digest != package_digest:
                reasons.append("package:digest_mismatch")
        if request.action_family not in self._ALLOWED_FAMILIES:
            reasons.append("policy:action_family_not_allowlisted")
        if not self.target_package and (
            not self.allowed_origin or target_origin != self.allowed_origin
        ):
            reasons.append("scope:target_origin_mismatch")
        if method not in self._READ_METHODS:
            if mode != ScanMode.AUTHORIZED_ACTIVE.value:
                reasons.append("policy:active_method_requires_authorized_active_profile")
            if not request.human_approved and not self.settings.smart_auto_approve:
                reasons.append("approval:active_action_not_approved")
        if request.risk == ActionRisk.DESTRUCTIVE:
            reasons.append("policy:destructive_actions_are_not_autonomous")
        if request.risk == ActionRisk.ACTIVE and mode != ScanMode.AUTHORIZED_ACTIVE.value:
            reasons.append("policy:active_risk_requires_authorized_active_profile")
        if not capability_available(self.manifest, request.capability):
            reasons.append(f"capability:{request.capability}:unavailable")
        if self.require_g02:
            adapter_name = str(request.metadata.get("adapter_name") or "").strip()
            if self.adapter_registry is None:
                reasons.append("g02:adapter_registry_unavailable")
            else:
                valid, adapter_errors = self.adapter_registry.validate_for_execution(
                    adapter_name
                )
                if not adapter_name:
                    reasons.append("g02:request:adapter_name:required")
                inventory_ref = str(
                    request.metadata.get("g02_inventory_ref") or ""
                ).strip()
                proof_contract = str(
                    request.metadata.get("g02_proof_contract") or ""
                ).strip()
                if not inventory_ref:
                    reasons.append("g02:request:g02_inventory_ref:required")
                if not proof_contract:
                    reasons.append("g02:request:g02_proof_contract:required")
                adapter = self.adapter_registry.get(adapter_name)
                if adapter is not None:
                    if inventory_ref and inventory_ref != adapter.static_inventory_ref:
                        reasons.append("g02:request:inventory_ref_mismatch")
                    if proof_contract and proof_contract != adapter.proof_contract:
                        reasons.append("g02:request:proof_contract_mismatch")
                if not valid:
                    reasons.extend(f"g02:{error}" for error in adapter_errors)
        if (
            request.estimated_cost <= 0
            or request.estimated_cost > self.settings.smart_action_budget
        ):
            reasons.append("budget:invalid_or_over_engagement_limit")
        if self.used_actions >= self.settings.smart_max_actions:
            reasons.append("budget:max_actions_exhausted")
        if self.used_budget + request.estimated_cost > self.settings.smart_action_budget:
            reasons.append("budget:action_budget_exhausted")
        if self.settings.smart_require_idempotency and not request.idempotency_key.strip():
            reasons.append("idempotency:key_required")

        status = ActionStatus.POLICY_DENIED if reasons else ActionStatus.AUTHORIZED
        return self._decision(request, reasons, status)

    def execute(
        self, request: ActionRequest, handler: Callable[[ActionRequest], Any]
    ) -> ActionResult:
        """Authorize, then invoke a caller-supplied handler exactly once."""
        decision = self.authorize(request)
        if not decision.allowed:
            return ActionResult(status=decision.status, decision=decision)
        method = request.method.upper().strip()
        reservation = None
        if self.ledger is not None:
            reservation = self.ledger.reserve(
                idempotency_key=request.idempotency_key,
                engagement_id=request.engagement_id,
                task_id=request.task_id,
                target_origin=self._normalize_origin(request.target_url),
                method=method,
                action_family=request.action_family,
                identity_ref=request.identity_ref,
                tenant_context=str(request.metadata.get("tenant_context", "unknown")),
                vulnerability_class=str(request.metadata.get("vulnerability_class", "unknown")),
                validator_id=str(request.metadata.get("validator_id", "")),
                estimated_cost=request.estimated_cost,
                max_actions=self.settings.smart_max_actions,
                max_budget=self.settings.smart_action_budget,
                action_signature=str(
                    request.metadata.get("hypothesis_signature")
                    or request.metadata.get("hypothesis_id")
                    or request.idempotency_key
                ),
            )
            if not reservation.allowed:
                denied = self._decision(
                    request,
                    [reservation.reason or "ledger:reservation_denied"],
                    ActionStatus.POLICY_DENIED,
                )
                return ActionResult(status=denied.status, decision=denied)
            self.used_actions = max(self.used_actions, reservation.used_actions)
            self.used_budget = max(self.used_budget, reservation.used_budget)

        try:
            output = handler(request)
        except (AttributeError, KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:  # pragma: no cover - exact exception belongs to transport
            if self.ledger is not None:
                self.ledger.complete(
                    request.engagement_id, request.idempotency_key, status="failed"
                )
            failure = self._decision(
                request,
                [f"handler:infrastructure_failure:{type(exc).__name__}"],
                ActionStatus.INFRASTRUCTURE_FAILURE,
            )
            return ActionResult(status=failure.status, decision=failure)
        self.used_actions += 1 if reservation is None else 0
        self.used_budget += request.estimated_cost if reservation is None else 0.0
        if self.ledger is not None:
            self.ledger.complete(
                request.engagement_id, request.idempotency_key, status="executed"
            )
        executed = self._decision(request, [], ActionStatus.EXECUTED)
        return ActionResult(status=executed.status, decision=executed, output=output)
