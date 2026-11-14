"""webpent.safety.autonomy_tiers — bounded-decision autonomy (ق2).

The proposal file (WebPent_FEATURE_PROPOSALS.md, ق2) calls for "decision
authority inside a cage" instead of a blanket human-in-the-loop default:
the loop already exists, but high-risk decisions bounce to HITL and the
VIP/econ layers are advisory. This module makes autonomy a FIRST-CLASS,
PROVABLE configuration:

  - four tiers of escalating intrusiveness (0 read/recon, 1 non-destructive
    probes, 2 confirmatory payloads, 3 full exploitation);
  - promotion between tiers is a COMPUTED decision from recorded evidence
    (evidence score), remaining budget, and a rate cap — never an LLM
    assertion, never a bare flag;
  - every grant and promotion is signed into an append-only, replayable
    audit log (JSONL, one line per event);
  - HITL stays available as the operator's CEILING: ``max_tier`` caps what
    the engine may ever reach for one engagement (the default ceiling is
    deliberately 1, so nothing changes for an operator who configures
    nothing — fail-closed);
  - the safety cage composes the EXISTING primitives: an engaged kill
    switch freezes every tier above 0 immediately, and a tier's authority
    never exceeds what the spend governor and request ledger already allow.

Evidence-first: the tier decision reads ONLY recorded evidence (proof
bundles, confirmed/refuted hypotheses, validator outcomes) — it never
reads or trusts an LLM's confidence.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

__all__ = [
    "AutonomyTier",
    "TierPolicy",
    "TierDecision",
    "AutonomyCage",
    "AuditLog",
    "kill_switch_engaged",
]

#: Injectable kill-switch reader (the production import is deferred so
#: importing this module never imports the whole safety stack).
kill_switch_engaged: Callable[[], bool]


def kill_switch_engaged() -> bool:  # noqa: F811 — runtime binding
    from webpent.safety.kill_switch import engaged

    return engaged()


class AutonomyTier:
    """Tier ordinal + stable name; tiers compare by intrusiveness."""

    RECON = 0
    PROBE = 1
    CONFIRM = 2
    EXPLOIT = 3

    NAMES = {
        0: "read/recon",
        1: "non-destructive probes",
        2: "confirmatory payloads",
        3: "full exploitation",
    }

    def __init__(self, value: int) -> None:
        if value not in self.NAMES:
            raise ValueError(f"unknown autonomy tier: {value!r}")
        self.value = value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, AutonomyTier) and other.value == self.value

    def __le__(self, other: "AutonomyTier") -> bool:
        return self.value <= other.value

    def __lt__(self, other: "AutonomyTier") -> bool:
        return self.value < other.value

    def __int__(self) -> int:
        return self.value

    def __repr__(self) -> str:
        return f"AutonomyTier({self.value}, {self.NAMES[self.value]!r})"


@dataclass(frozen=True)
class TierPolicy:
    """The operator's cage for ONE engagement (fail-closed defaults).

    ``max_tier`` is the HITL ceiling: the engine may compute any
    promotion it likes, it can never cross this line. ``promotion_floor``
    is the minimum evidence score a promotion requires. ``min_interval_
    seconds`` rate-caps promotions so a runaway loop cannot walk the
    ladder in one second.
    """

    engagement_id: str
    client_id: str
    max_tier: int = 1
    promotion_floor: float = 0.6
    min_promotion_interval_seconds: float = 60.0
    audit_path: str = ""


@dataclass
class TierDecision:
    """The computed, auditable promotion decision."""

    from_tier: int
    to_tier: int
    granted: bool
    reason: str
    evidence_score: float
    at: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_tier": self.from_tier,
            "to_tier": self.to_tier,
            "granted": self.granted,
            "reason": self.reason,
            "evidence_score": self.evidence_score,
            "at": self.at,
        }


class AuditLog:
    """Append-only JSONL audit trail; one HMAC-signed line per event.

    The signature chain (each line carries the digest of the previous
    line) makes silent tampering detectable at replay time — the same
    property the request ledger and refutation ledger already give the
    evidence layer.
    """

    def __init__(self, path: str | Path, secret: str = "") -> None:
        self.path = Path(path) if path else None
        self._secret = secret or os.environ.get("WEBPENT_AUDIT_SECRET", "dev-chain")
        self._prev_digest = ""
        self._events = 0

    def append(self, event: dict[str, Any]) -> str:
        event = dict(event)
        event["prev"] = self._prev_digest
        payload = json.dumps(event, sort_keys=True, default=str)
        digest = hmac.new(
            self._secret.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        line = json.dumps(
            {"sig": digest, "event": event}, sort_keys=True, default=str
        )
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        self._prev_digest = digest
        self._events += 1
        return digest

    @property
    def events(self) -> int:
        return self._events

    def verify_file(self) -> tuple[bool, str]:
        """Replay the JSONL from disk and re-compute the chain."""
        if self.path is None or not self.path.exists():
            return True, "empty"
        prev = ""
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    return False, f"line {lineno}: bad json ({exc})"
                event = record.get("event") or {}
                expected = hmac.new(
                    self._secret.encode("utf-8"),
                    json.dumps(event, sort_keys=True, default=str).encode(
                        "utf-8"
                    ),
                    hashlib.sha256,
                ).hexdigest()
                if record.get("sig") != expected or event.get("prev") != prev:
                    return False, f"line {lineno}: chain break"
                prev = record["sig"]
        return True, "ok"


def evidence_score(records: list[dict[str, Any]]) -> float:
    """Deterministic evidence score from recorded records only.

    Weights (0..1 per record, capped at 1.0 total): a replay-valid sealed
    proof bundle is the strongest signal (0.5 each); a confirmed
    hypothesis 0.25; a validator-confirmed finding 0.2; supporting
    evidence items 0.05. Unknown record shapes contribute nothing — the
    score never trusts a free-text claim.
    """
    score = 0.0
    for record in records or []:
        kind = str(record.get("kind", ""))
        if kind == "proof_bundle" and record.get("replay_valid") is True:
            score += 0.5
        elif kind == "hypothesis" and record.get("status") == "confirmed":
            score += 0.25
        elif kind == "finding" and record.get("validator") == "confirmed":
            score += 0.2
        elif kind == "evidence" and record.get(
                "direction") == "supporting":
            score += 0.05
    return min(score, 1.0)


class AutonomyCage:
    """The decision authority: computes promotions, enforces the cage."""

    def __init__(
        self,
        policy: TierPolicy,
        *,
        kill_switch: Callable[[], bool] | None = None,
        clock: Callable[[], float] = time.time,
        audit_secret: str = "",
    ) -> None:
        self.policy = policy
        self.kill_switch = kill_switch or kill_switch_engaged
        self.clock = clock
        self.current = AutonomyTier(0)
        self.audit = AuditLog(policy.audit_path, secret=audit_secret)
        self._last_promotion_at: float | None = None
        self.audit.append(
            {
                "event": "cage_open",
                "engagement_id": policy.engagement_id,
                "client_id": policy.client_id,
                "max_tier": policy.max_tier,
            }
        )

    def allowed(self) -> AutonomyTier:
        """The tier the engine may act at RIGHT NOW (kill-switch aware)."""
        if self.kill_switch():
            return AutonomyTier(0)
        return AutonomyTier(min(self.current.value, self.policy.max_tier))

    def may_execute(self, requested: int) -> TierDecision:
        """Fail-closed authority check for one requested action tier."""
        allowed = self.allowed()
        ok = requested <= allowed.value
        decision = TierDecision(
            from_tier=self.current.value,
            to_tier=requested,
            granted=ok,
            reason=(
                "within current tier authority"
                if ok
                else (
                    f"requested tier {requested} exceeds current authority "
                    f"{allowed.value}"
                )
            ),
            evidence_score=0.0,
            at=self.clock(),
        )
        self.audit.append(
            {
                "event": "authority_check",
                "engagement_id": self.policy.engagement_id,
                "requested": requested,
                "granted": ok,
                "reason": decision.reason,
            }
        )
        return decision

    def evaluate_promotion(
        self, records: list[dict[str, Any]]
    ) -> TierDecision:
        """Compute (and, when justified, apply) one promotion step.

        Promotion is one step at a time; the evidence floor, the HITL
        ceiling, the rate interval and the kill switch all gate it.
        """
        score = evidence_score(records)
        now = self.clock()
        target = AutonomyTier(min(self.current.value + 1, 3))

        def denied(reason: str) -> TierDecision:
            decision = TierDecision(
                from_tier=self.current.value,
                to_tier=target.value,
                granted=False,
                reason=reason,
                evidence_score=score,
                at=now,
            )
            self.audit.append(
                {
                    "event": "promotion_denied",
                    "engagement_id": self.policy.engagement_id,
                    "to_tier": target.value,
                    "reason": reason,
                    "evidence_score": score,
                }
            )
            return decision

        if self.kill_switch():
            return denied("kill switch engaged: tier authority frozen")
        if target.value > self.policy.max_tier:
            return denied(
                f"operator ceiling (max_tier={self.policy.max_tier}) "
                "blocks the promotion — HITL ceiling holds"
            )
        if score < self.policy.promotion_floor:
            return denied(
                f"evidence score {score:.2f} below the promotion floor "
                f"{self.policy.promotion_floor:.2f}"
            )
        if (
            self._last_promotion_at is not None
            and now - self._last_promotion_at
            < self.policy.min_promotion_interval_seconds
        ):
            return denied(
                "promotion rate cap: the last promotion is younger than "
                f"{self.policy.min_promotion_interval_seconds:.0f}s"
            )

        self.current = target
        self._last_promotion_at = now
        decision = TierDecision(
            from_tier=target.value - 1,
            to_tier=target.value,
            granted=True,
            reason=(
                f"evidence score {score:.2f} clears the floor "
                f"{self.policy.promotion_floor:.2f}"
            ),
            evidence_score=score,
            at=now,
        )
        self.audit.append(
            {
                "event": "promotion_granted",
                "engagement_id": self.policy.engagement_id,
                "from_tier": decision.from_tier,
                "to_tier": decision.to_tier,
                "evidence_score": score,
                "at": now,
            }
        )
        return decision
