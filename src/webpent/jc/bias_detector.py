"""Judgment Council — U-JC-8: the Bias Detector.

Detects systemic bias patterns across recorded council sessions (JC-L-6):
each pattern needs a minimum number of recorded sessions before it may
fire (no false positives on clean data), and every finding carries a
recommendation (DoD).

Patterns (documented charter):

    systemic_confirmation  an advocate's claim matched the winner's action
                           in >= 90% of their sessions (blind support)
    recency_dominance      the LAST-argued advocate wins >= 70% of sessions
    anchor_stickiness      the FIRST-argued advocate wins >= 70% of sessions
    silent_veto            an advocate argued >= 5 sessions and never won
    majority_tyranny       dissenting views resolve "correct" >= 60% of the
                           time across >= 5 resolved outcomes, i.e. the
                           minority keeps being right and keeps losing
"""

from __future__ import annotations

import json
import logging
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_LOG = logging.getLogger(__name__)

MIN_SESSIONS = 5
MIN_RESOLVED_DISSENT = 5
CONFIRMATION_RATE = 0.90
DOMINANCE_RATE = 0.70
TYRANNY_RATE = 0.60

BIAS_TYPES = (
    "systemic_confirmation",
    "recency_dominance",
    "anchor_stickiness",
    "silent_veto",
    "majority_tyranny",
)

_RECOMMENDATIONS = {
    "systemic_confirmation":
        "require independent evidence before that advocate's support counts",
    "recency_dominance":
        "score arguments before hearing them, or randomize seating by rule",
    "anchor_stickiness":
        "collect all arguments before any scoring; first is not strongest",
    "silent_veto":
        "review that advocate's inputs; a never-winning voice is a broken sensor",
    "majority_tyranny":
        "raise the weight of dissent that keeps proving right (persistent minority)",
}


@dataclass
class BiasFinding:
    """One detected systemic pattern (L-4 envelope)."""

    bias_type: str
    severity: float
    evidence: list[str]
    recommendation: str
    confidence: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "bias_type": self.bias_type,
            "severity": round(self.severity, 4),
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "confidence": round(self.confidence, 4),
            "advisory": True,
        }


@dataclass
class SessionFacts:
    """What the detector needs from one recorded session."""

    session_id: str
    winner_id: str
    claims: dict[str, str]
    argue_orders: dict[str, int]
    ts: float


class BiasDetector:
    """Reads recorded verdicts and reports systemic bias patterns."""

    def __init__(self, sessions_path: Any, dissent_path: Any | None = None,
                 *, history_path: Any | None = None, min_sessions: int = MIN_SESSIONS):
        self.sessions_path = Path(str(sessions_path))
        self.dissent_path = None if dissent_path is None else Path(str(dissent_path))
        self.history_path = None if history_path is None else Path(str(history_path))
        self.min_sessions = int(min_sessions)

    # -------------------------------------------------------------- facts
    def _load_sessions(self, now_ts: float, window_days: int) -> list[SessionFacts]:
        try:
            lines = self.sessions_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        cutoff = now_ts - max(1, int(window_days)) * 86400.0
        facts = []
        for line in lines:
            row = None
            with suppress(ValueError):
                row = json.loads(line)
            if not isinstance(row, dict):
                continue
            # R2-jc-05: tolerate a valid-JSON row with a corrupt "ts".
            try:
                ts = float(row.get("ts", 0.0) or 0.0)
            except (TypeError, ValueError):
                continue
            if ts < cutoff:
                continue
            verdict = row.get("verdict") or {}
            summary = verdict.get("advocates_summary") or {}
            if not summary:
                continue
            top = max(
                sorted(summary),
                key=lambda a: summary[a].get("score", 0.0),
            )
            facts.append(SessionFacts(
                session_id=str(row.get("session_id") or ""),
                winner_id=top,
                claims={a: str(d.get("claim") or "") for a, d in summary.items()},
                argue_orders={a: int(d.get("argue_order", 0)) for a, d in summary.items()},
                ts=float(row.get("ts") or 0.0),
            ))
        return facts

    # ------------------------------------------------------------- detect
    def detect(self, window_days: int = 30, *,
               now_ts: float | None = None) -> list[BiasFinding]:
        """Run all five pattern checks over the session window."""
        now_ts = time.time() if now_ts is None else float(now_ts)
        sessions = self._load_sessions(now_ts, window_days)
        findings: list[BiasFinding] = []
        if len(sessions) < self.min_sessions:
            return findings

        # 1. silent veto: argued >= min_sessions, never won
        appearances: dict[str, int] = {}
        wins: dict[str, int] = {}
        for s in sessions:
            for aid in s.claims:
                appearances[aid] = appearances.get(aid, 0) + 1
                wins[aid] = wins.get(aid, 0) + (1 if aid == s.winner_id else 0)
        for aid in sorted(appearances):
            if appearances[aid] >= self.min_sessions and wins[aid] == 0:
                findings.append(BiasFinding(
                    bias_type="silent_veto",
                    severity=min(1.0, appearances[aid] / (2.0 * self.min_sessions)),
                    evidence=[f"{aid} argued in {appearances[aid]} sessions, won 0"],
                    recommendation=_RECOMMENDATIONS["silent_veto"],
                    confidence=min(1.0, appearances[aid] / (2.0 * self.min_sessions)),
                ))

        # 2. systemic confirmation: same claim as winner >= 90% of their sessions
        support: dict[str, list[int]] = {}
        for s in sessions:
            winner_claim = s.claims.get(s.winner_id, "")
            for aid, claim in s.claims.items():
                if aid == s.winner_id:
                    continue
                support.setdefault(aid, []).append(1 if claim == winner_claim else 0)
        for aid in sorted(support):
            marks = support[aid]
            if len(marks) >= self.min_sessions and sum(marks) / len(marks) >= CONFIRMATION_RATE:
                findings.append(BiasFinding(
                    bias_type="systemic_confirmation",
                    severity=min(1.0, sum(marks) / len(marks)),
                    evidence=[
                        f"{aid} echoed the winner's action in "
                        f"{sum(marks)}/{len(marks)} sessions"
                    ],
                    recommendation=_RECOMMENDATIONS["systemic_confirmation"],
                    confidence=min(1.0, sum(marks) / len(marks)),
                ))

        # 3./4. argue-order dominance
        first_wins = sum(1 for s in sessions if s.argue_orders.get(s.winner_id) == 0)
        last_wins = sum(
            1 for s in sessions
            if s.argue_orders.get(s.winner_id) == max(s.argue_orders.values())
        )
        n = len(sessions)
        if first_wins / n >= DOMINANCE_RATE:
            findings.append(BiasFinding(
                bias_type="anchor_stickiness",
                severity=first_wins / n,
                evidence=[f"first-argued advocate won {first_wins}/{n} sessions"],
                recommendation=_RECOMMENDATIONS["anchor_stickiness"],
                confidence=first_wins / n,
            ))
        if last_wins / n >= DOMINANCE_RATE:
            findings.append(BiasFinding(
                bias_type="recency_dominance",
                severity=last_wins / n,
                evidence=[f"last-argued advocate won {last_wins}/{n} sessions"],
                recommendation=_RECOMMENDATIONS["recency_dominance"],
                confidence=last_wins / n,
            ))

        # 5. majority tyranny from the dissent register
        tyranny = self._majority_tyranny()
        if tyranny is not None:
            findings.append(tyranny)

        findings.sort(key=lambda f: f.bias_type)
        self._record_history(findings, now_ts)
        return findings

    def _majority_tyranny(self) -> BiasFinding | None:
        if self.dissent_path is None:
            return None
        from webpent.jc.dissent import DissentRegister

        register = DissentRegister(self.dissent_path)
        resolved = [
            r for r in register._resolve().values()
            if r["outcome"] in ("correct", "incorrect")
        ]
        if len(resolved) < MIN_RESOLVED_DISSENT:
            return None
        rate = sum(1 for r in resolved if r["outcome"] == "correct") / len(resolved)
        if rate < TYRANNY_RATE:
            return None
        return BiasFinding(
            bias_type="majority_tyranny",
            severity=rate,
            evidence=[
                f"dissent proved correct in {sum(1 for r in resolved if r['outcome'] == 'correct')}"
                f"/{len(resolved)} resolved outcomes"
            ],
            recommendation=_RECOMMENDATIONS["majority_tyranny"],
            confidence=rate,
        )

    # ------------------------------------------------------------ history
    def _record_history(self, findings: list[BiasFinding], now_ts: float) -> None:
        if self.history_path is None or not findings:
            return
        try:
            self.history_path.parent.mkdir(parents=True, exist_ok=True)
            rows = []
            for f in findings:
                rows.append({"ts": now_ts, "bias_type": f.bias_type,
                             "severity": round(f.severity, 4)})
            with self.history_path.open("a", encoding="utf-8") as handle:
                for row in rows:
                    handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        except OSError as exc:
            _LOG.warning("bias history write failed: %s", exc)

    def get_bias_timeline(self, bias_type: str) -> list[tuple[float, float]]:
        """(ts, severity) history of one bias type from the recorded runs."""
        if self.history_path is None:
            return []
        try:
            lines = self.history_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        timeline = []
        for line in lines:
            row = None
            with suppress(ValueError):
                row = json.loads(line)
            if isinstance(row, dict) and row.get("bias_type") == str(bias_type):
                # R2-jc-05: corrupt numeric fields are skipped, not fatal.
                try:
                    ts = float(row.get("ts", 0.0))
                    severity = float(row.get("severity", 0.0))
                except (TypeError, ValueError):
                    continue
                timeline.append((ts, severity))
        return sorted(timeline)


__all__ = ["BIAS_TYPES", "BiasDetector", "BiasFinding"]
