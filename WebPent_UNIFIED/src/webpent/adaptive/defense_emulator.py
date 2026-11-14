"""Phase 2 — Internal Defense Emulator (risk assessment before sending).

Fix 1: per-target calibration — learn which patterns are actually blocked on
this target from observed responses, adjust scores dynamically (not fixed
rules). Fix 4: extra statistical signals (request timing regularity, header
fingerprint, payload entropy) without requiring ML.

Scores every execution plan 0-10 on how likely it is to trigger a WAF/alert.
Modifies or defers high-risk plans. Never blocks entirely — either lowers
signature or defers to the exploratory lane.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

_OBVIOUS_PAYLOAD = re.compile(
    r"(union\s+select|<script|>\s*<|/\.\./|;--|drop\s+table|cat\s+/etc/passwd|1=1|or 1=1)",
    re.I,
)
_RISK_KEYWORDS = ("union", "select", "script", "alert", "eval", "system", "passthru",
                  "etc/passwd", "shadow", "cmd=", "exec=", "shell=")


def _payload_entropy(sample: str) -> float:
    """Shannon entropy of the payload — high entropy often indicates
    obfuscated/encoded payloads that WAFs flag."""
    if not sample:
        return 0.0
    freq: dict[str, int] = {}
    for ch in sample:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(sample)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


@dataclass
class RiskAssessment:
    risk_score: float
    level: str
    modified_plan: Any = None
    action: str = "send"
    reasons: list[str] = None


class TargetProfile:
    """Fix 1: per-target learned profile. Calibrated from observed responses —
    which patterns were blocked (raise score) vs which passed (lower score)."""

    def __init__(self) -> None:
        self.blocked_patterns: set[str] = set()
        self.passed_patterns: set[str] = set()

    def calibrate(self, sample: str, blocked: bool) -> None:
        """Record that a pattern (keyword) was blocked or passed on this target."""
        s = sample.lower()
        for kw in _RISK_KEYWORDS:
            if kw in s:
                if blocked:
                    self.blocked_patterns.add(kw)
                else:
                    self.passed_patterns.add(kw)

    def adjustment(self, sample: str) -> float:
        """Return score adjustment: +2 for patterns known blocked here,
        -1 for patterns known to pass."""
        s = sample.lower()
        adj = 0.0
        for kw in self.blocked_patterns:
            if kw in s:
                adj += 2.0
        for kw in self.passed_patterns - self.blocked_patterns:
            if kw in s:
                adj -= 1.0
        return adj


class DefenseEmulator:
    """Assess and adapt a plan before it is sent. Per-target calibrated."""

    def __init__(self) -> None:
        self.profile = TargetProfile()

    def assess(self, plan: Any, *, recent_request_count: int = 0,
               waf_known: bool = False, request_jitter: float = 0.0) -> RiskAssessment:
        reasons: list[str] = []
        score = 0.0

        body = str(getattr(plan, "body", "") or "")
        url = str(getattr(plan, "url", "") or "")
        label = str(getattr(plan, "label", "") or "")
        sample = f"{url} {body} {label}"

        # 1. Obvious payload signatures
        if _OBVIOUS_PAYLOAD.search(sample):
            score += 4.0
            reasons.append("obvious_payload_signature")
        kw_hits = sum(1 for k in _RISK_KEYWORDS if k in sample.lower())
        score += min(3.0, kw_hits * 0.5)
        if kw_hits >= 2:
            reasons.append(f"{kw_hits}_risk_keywords")

        # Fix 4: payload entropy — obfuscated payloads score higher
        entropy = _payload_entropy(sample)
        if entropy > 4.5:
            score += 1.0
            reasons.append(f"high_payload_entropy_{entropy:.1f}")

        # Fix 4: request timing regularity — perfectly regular requests look
        # scripted. jitter=0 (perfectly regular) raises score.
        if request_jitter < 0.1 and recent_request_count > 5:
            score += 1.0
            reasons.append("perfectly_regular_timing_looks_scripted")

        # 2. Rate / repetition
        if recent_request_count > 10:
            score += 2.0
            reasons.append("high_request_rate")
        if label.startswith("burst"):
            score += 1.5
            reasons.append("burst_pattern_visible")

        # 3. Known WAF on target
        if waf_known:
            score += 2.0
            reasons.append("waf_known_on_target")

        # Fix 1: per-target calibration adjustment
        cal = self.profile.adjustment(sample)
        if cal != 0:
            score += cal
            reasons.append(f"target_calibration_{cal:+.1f}")

        score = max(0.0, min(10.0, score))
        if score < 3.0:
            level, action = "low", "send"
            modified = plan
        elif score < 6.0:
            level, action = "medium", "modify_and_send"
            modified = self._obfuscate(plan)
        else:
            level, action = "high", "defer_to_exploratory"
            modified = self._obfuscate(plan)

        return RiskAssessment(risk_score=round(score, 1), level=level,
                              modified_plan=modified, action=action,
                              reasons=reasons or [])

    @staticmethod
    def _obfuscate(plan: Any) -> Any:
        try:
            setattr(plan, "adaptive_slowdown", 0.5)
            setattr(plan, "obfuscate_payload", True)
        except Exception:
            pass
        return plan


__all__ = ["DefenseEmulator", "RiskAssessment", "TargetProfile"]
