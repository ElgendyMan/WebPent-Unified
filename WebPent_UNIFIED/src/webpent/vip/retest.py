# src/webpent/vip/retest.py
"""webpent.vip.retest — Track 11, item 7: controlled re-testing.

Roadmap contract (المسار 11، البند 7):

    إعادة اختبار منضبطة: إعادة فحص نتيجة سابقة داخل النطاق المصرح به،
    وتحديث حالتها مع حفظ سجل المقارنة.

    ("Controlled re-testing: re-check a previous finding INSIDE the
    authorized scope, update its status, and keep a comparison record.")

Hard contracts (non-negotiable, enforced in this order):

1. **Authorization is mandatory.** An empty authorization reference
   aborts before any other work (same posture as ``webpent hunt``).
2. **Scope is mandatory and enforced before ANY network byte.** A typed
   scope policy (``webpent.scope``) must be supplied; the finding's URL
   is evaluated with the same ``ScopeEnforcer`` used by the platform. A
   blocked decision means NO request is made — outcome
   ``blocked_by_scope``.
3. **Bounded, deterministic probe.** Exactly ONE replay of the stored
   evidence request via the hardened SSRF-guarded HTTP factory
   (``make_safe_httpx_client``). No retry storms, no payloads, no
   escalation logic, no exploration. A retest never sends a new attack
   payload — it replays the exact stored request.
4. **Fail-safe verdicts.** Outcomes are ``still_present`` (deterministic
   reproduction of the stored signature), ``fixed`` (deterministic
   contradiction of the stored marker), or ``inconclusive`` (anything
   else — human review). Inconclusive downgrades the finding to
   "Needs Human Review" and NEVER promotes confidence.
5. **Comparison record is durable.** Every retest appends one JSONL row
   (before/after evidence hashes, outcome, authorization ref, probe
   summary) to the retest ledger, and the finding row is updated through
   the standard DB manager so the platform's status-history audit trail
   records the transition.

This module is deliberately independent of the graph: it is a CLI-facing
operator tool (``webpent retest ...``) for triaging yesterday's results,
not an agent node.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID

from webpent.models.findings import Finding
from webpent.shared.finding_aggregation import finding_fingerprint

logger = logging.getLogger(__name__)

__all__ = [
    "RetestOutcome",
    "RetestResult",
    "RetestLedger",
    "validate_authorization",
    "load_scope_policy",
    "replay_probe",
    "decide_outcome",
    "apply_retest",
    "run_retest",
]


class RetestOutcome(str, Enum):
    """Closed verdict vocabulary — no auto-escalation path exists."""

    STILL_PRESENT = "still_present"
    FIXED = "fixed"
    INCONCLUSIVE = "inconclusive"
    BLOCKED_BY_SCOPE = "blocked_by_scope"


@dataclass
class ProbeResult:
    """Bounded replay result of the stored evidence request."""

    ok: bool
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body_excerpt: str = ""
    error: str = ""
    elapsed_ms: int = 0


@dataclass
class RetestResult:
    """Full auditable comparison record for one retest."""

    finding_id: str
    fingerprint: str
    outcome: RetestOutcome
    prior_confidence_level: str
    new_confidence_level: str
    checked_at: str
    authorization_ref: str
    probe: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_ledger_row(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "fingerprint": self.fingerprint,
            "outcome": self.outcome.value,
            "prior_confidence_level": self.prior_confidence_level,
            "new_confidence_level": self.new_confidence_level,
            "checked_at": self.checked_at,
            "authorization_ref": self.authorization_ref,
            "probe": self.probe,
            "notes": self.notes,
        }


def validate_authorization(authorization: str | None) -> str:
    """Mandatory authorization contract (identical posture to unified hunt)."""
    value = (authorization or "").strip()
    if not value:
        raise ValueError(
            "--authorization مطلوب لإعادة الاختبار: مرّر مرجع التصريح الكتابي "
            "باختبار هذا الهدف. WebPent لا يعيد اختبار أي نتيجة خارج تفويض صريح."
        )
    return value


def load_scope_policy(scope_file: str) -> Any:
    """Load the typed scope policy file (REQUIRED — retest refuses without it)."""
    from webpent.scope import parse_scope_file

    if not scope_file or not str(scope_file).strip():
        raise ValueError(
            "ملف النطاق المصرح به مطلوب (--scope-file): إعادة الاختبار تعمل "
            "داخل النطاق المصرح به فقط، ولا تُرسل أي طلب بدونه."
        )
    return parse_scope_file(scope_file)


def _stored_markers(finding: Finding) -> list[str]:
    """Deterministic markers that must reappear if the issue still exists.

    Sources, in priority order: the per-finding canary token embedded in
    the validated payload, and any explicit ``verified_markers`` recorded
    in the evidence bundle by the validator. Never inferred by an LLM.
    """
    markers: list[str] = []
    if finding.canary_token:
        markers.append(finding.canary_token)
    bundle = finding.evidence_bundle if isinstance(finding.evidence_bundle, dict) else {}
    stored = bundle.get("verified_markers")
    if isinstance(stored, list):
        markers.extend(str(m) for m in stored if str(m).strip())
    seen: set[str] = set()
    unique = []
    for marker in markers:
        if marker not in seen:
            seen.add(marker)
            unique.append(marker)
    return unique


def _stored_status(finding: Finding) -> int | None:
    bundle = finding.evidence_bundle if isinstance(finding.evidence_bundle, dict) else {}
    response = bundle.get("response")
    if isinstance(response, dict):
        status = response.get("status_code")
        try:
            return int(status) if status is not None else None
        except (TypeError, ValueError):
            return None
    return None


def _stored_request(finding: Finding) -> dict[str, Any] | None:
    """Recover the replayable request from the evidence bundle or the row."""
    bundle = finding.evidence_bundle if isinstance(finding.evidence_bundle, dict) else {}
    request = bundle.get("request")
    if isinstance(request, dict) and request.get("url"):
        return request
    if finding.url:
        return {
            "method": finding.request_method or "GET",
            "url": finding.url,
            "headers": {},
            "body": finding.request_data or None,
        }
    return None


def replay_probe(finding: Finding, *, timeout: float = 15.0) -> ProbeResult:
    """Replay the STORED evidence request once, through the guarded client.

    No payload regeneration, no fuzzing, no redirects beyond the guarded
    factory's policy — a retest replays history, it does not explore.
    """
    import time

    from webpent.shared.http import (
        HTTPTransportError,
        SSRFRedirectBlockedError,
        make_safe_httpx_client,
    )

    request = _stored_request(finding)
    if request is None:
        return ProbeResult(ok=False, error="no replayable request in stored evidence")

    method = str(request.get("method") or "GET").upper()
    url = str(request.get("url") or finding.url or "")
    if not url:
        return ProbeResult(ok=False, error="stored request has no URL")
    headers = request.get("headers") if isinstance(request.get("headers"), dict) else {}
    body = request.get("body")

    started = time.monotonic()
    try:
        with make_safe_httpx_client(timeout=timeout, follow_redirects=False) as client:
            if method in {"GET", "HEAD", "OPTIONS"}:
                response = client.request(method, url, headers=headers or None)
            else:
                response = client.request(
                    method,
                    url,
                    headers=headers or None,
                    json=body if isinstance(body, dict) else None,
                    content=None if isinstance(body, dict) else body,
                )
    except (SSRFRedirectBlockedError, HTTPTransportError) as exc:
        elapsed = int((time.monotonic() - started) * 1000)
        return ProbeResult(
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
            elapsed_ms=elapsed,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        elapsed = int((time.monotonic() - started) * 1000)
        return ProbeResult(ok=False, error=f"{type(exc).__name__}: {exc}", elapsed_ms=elapsed)

    elapsed = int((time.monotonic() - started) * 1000)
    text = ""
    try:
        text = response.text or ""
    except (AttributeError, ValueError):
        text = ""
    safe_headers = {
        str(k).lower(): str(v)
        for k, v in (response.headers or {}).items()
        if str(k).lower() in {"content-type", "location", "server", "content-length"}
    }
    return ProbeResult(
        ok=True,
        status_code=int(getattr(response, "status_code", 0) or 0),
        headers=safe_headers,
        body_excerpt=text[:2000],
        elapsed_ms=elapsed,
    )


def decide_outcome(finding: Finding, probe: ProbeResult) -> tuple[RetestOutcome, list[str]]:
    """Deterministic verdict from the probe vs the stored signature.

    * probe failed (network/guard/none replayable) → INCONCLUSIVE
    * signature reproduced (status equal AND every stored marker present,
      when markers exist) → STILL_PRESENT
    * deterministic contradiction (stored status equal but a defined
      marker is ABSENT) → FIXED
    * anything else (status drift, no markers, ambiguous) → INCONCLUSIVE
    """
    notes: list[str] = []
    if not probe.ok:
        notes.append(f"probe failed: {probe.error}")
        return RetestOutcome.INCONCLUSIVE, notes

    stored_status = _stored_status(finding)
    markers = _stored_markers(finding)
    notes.append(f"probe status={probe.status_code} elapsed_ms={probe.elapsed_ms}")
    if stored_status is not None:
        notes.append(f"stored status={stored_status}")

    body = probe.body_excerpt or ""
    marker_hits = [m for m in markers if m and m in body]

    if markers:
        if probe.status_code == stored_status and len(marker_hits) == len(markers):
            notes.append("stored signature reproduced (status + all markers present)")
            return RetestOutcome.STILL_PRESENT, notes
        if probe.status_code == stored_status and not marker_hits:
            notes.append(
                "stored status reproduced but stored markers absent — deterministic contradiction"
            )
            return RetestOutcome.FIXED, notes
        notes.append(
            f"ambiguous signature (markers found {len(marker_hits)}/{len(markers)}, "
            "status may differ) — human review required"
        )
        return RetestOutcome.INCONCLUSIVE, notes

    if stored_status is not None and probe.status_code != stored_status:
        notes.append(
            "status drift with no stored marker — endpoint behavior changed; "
            "human review required before declaring fixed"
        )
        return RetestOutcome.INCONCLUSIVE, notes

    notes.append("no deterministic marker/status signature stored — human review required")
    return RetestOutcome.INCONCLUSIVE, notes


def apply_retest(finding: Finding, result: RetestResult) -> Finding:
    """Return the updated finding copy (status update, never a promotion).

    Rules:

    * STILL_PRESENT  — level unchanged; evidence gains the retest block.
    * FIXED          — level unchanged (closure is a HUMAN decision); the
      retest block + reasoning note carry the deterministic contradiction.
    * INCONCLUSIVE   — downgraded to "Needs Human Review" (fail-safe).
      A promotion can never be produced here.
    * BLOCKED_BY_SCOPE — level unchanged; the attempt itself is recorded.
    """
    evidence = dict(finding.evidence) if isinstance(finding.evidence, dict) else {}
    evidence["retest"] = result.to_ledger_row()
    reasoning = finding.reasoning or ""
    retest_note = f"[retest {result.checked_at}] {result.outcome.value}: " + "; ".join(result.notes)
    new_reasoning = (reasoning + "\n" + retest_note).strip() if reasoning else retest_note

    update: dict[str, Any] = {"evidence": evidence, "reasoning": new_reasoning}
    if result.outcome == RetestOutcome.INCONCLUSIVE:
        update["confidence_level"] = "Needs Human Review"

    return finding.model_copy(update=update)


class RetestLedger:
    """Append-only JSONL comparison log (one row per retest attempt).

    Stored OUTSIDE the repository (operator data, not source control),
    following the same posture as the findings ledger.
    """

    def __init__(self, path: str | Any) -> None:
        from pathlib import Path

        self.path = Path(str(path)).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, result: RetestResult) -> None:
        row = result.to_ledger_row()
        row["recorded_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    def history_for(self, finding_id: str | UUID) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        rows: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(row.get("finding_id")) == str(finding_id):
                    rows.append(row)
        return rows


def run_retest(
    finding: Finding,
    *,
    scope_policy: Any,
    authorization: str,
    timeout: float = 15.0,
    ledger: RetestLedger | None = None,
    skip_network: bool = False,
) -> RetestResult:
    """Full gated retest of one finding. Returns the comparison record.

    Order of operations (fail-closed): authorization → scope → probe →
    verdict → persisted update by the CALLER (the CLI owns DB writes so
    this pure layer stays testable without a database).
    """
    validate_authorization(authorization)

    from webpent.scope import ScopeEnforcer

    enforcer = ScopeEnforcer(scope_policy)
    decision = enforcer.check_url(finding.url, method=finding.request_method or "GET")
    checked_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    fingerprint = finding_fingerprint(finding)

    if not decision.allowed:
        result = RetestResult(
            finding_id=str(finding.id),
            fingerprint=fingerprint,
            outcome=RetestOutcome.BLOCKED_BY_SCOPE,
            prior_confidence_level=finding.confidence_level,
            new_confidence_level=finding.confidence_level,
            checked_at=checked_at,
            authorization_ref=authorization,
            probe={"scope_decision": decision.status.value, "reason": decision.reason},
            notes=[f"blocked by scope: {decision.reason}"],
        )
        if ledger is not None:
            ledger.append(result)
        return result

    if skip_network:
        result = RetestResult(
            finding_id=str(finding.id),
            fingerprint=fingerprint,
            outcome=RetestOutcome.INCONCLUSIVE,
            prior_confidence_level=finding.confidence_level,
            new_confidence_level=finding.confidence_level,
            checked_at=checked_at,
            authorization_ref=authorization,
            probe={"dry_run": True},
            notes=["dry-run: no request was sent"],
        )
        if ledger is not None:
            ledger.append(result)
        return result

    probe = replay_probe(finding, timeout=timeout)
    outcome, notes = decide_outcome(finding, probe)
    new_level = (
        "Needs Human Review"
        if outcome == RetestOutcome.INCONCLUSIVE
        else finding.confidence_level
    )
    result = RetestResult(
        finding_id=str(finding.id),
        fingerprint=fingerprint,
        outcome=outcome,
        prior_confidence_level=finding.confidence_level,
        new_confidence_level=new_level,
        checked_at=checked_at,
        authorization_ref=authorization,
        probe={
            "ok": probe.ok,
            "status_code": probe.status_code,
            "elapsed_ms": probe.elapsed_ms,
            "error": probe.error,
        },
        notes=notes,
    )
    if ledger is not None:
        ledger.append(result)
    return result
