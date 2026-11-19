"""Autonomous Bug Hunter Core v3.0 — five integrated components.

1. AttackPlanner — dynamic, risk-based attack plan (not a static checklist).
2. ContextualCorrelationEngine — links findings into compound vulnerabilities.
3. AdaptiveKnowledgeGraph — per-target memory; learns from success/failure.
4. StrategyEngine — offensive mode: escalating confirmation, variants, impact.
5. StealthResilienceLayer — detects blocks, adapts rate/timing/identity, safe
   stop + retry with different strategy, scope bounds.

All components are fail-closed: missing data → conservative default, never
fabricated.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlsplit


# ---------------------------------------------------------------------------
# 1. AttackPlanner — dynamic risk-based plan
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class EndpointRisk:
    path: str
    method: str
    risk_score: float          # 0.0-1.0
    requires_auth: bool = False
    handles_sensitive_data: bool = False
    accepts_user_input: bool = True


@dataclass
class AttackStep:
    step_id: str
    target_endpoint: str
    technique: str
    priority: float            # higher = first
    rationale: str = ""


class AttackPlanner:
    """Builds a dynamic attack plan. Endpoints with higher risk + sensitive
    data + user input get prioritized. On a new finding, generates
    complementary attack steps (not just continues the list)."""

    def score_endpoint(self, ep: EndpointRisk) -> float:
        # C1 fix: incorporate the caller-provided risk_score as a base,
        # never ignore it. 0.5 weight to input, 0.5 to heuristics.
        score = 0.5 * float(ep.risk_score or 0.0) + 0.15
        if ep.handles_sensitive_data:
            score += 0.15
        if ep.accepts_user_input:
            score += 0.125
        if not ep.requires_auth:
            score += 0.075
        return min(1.0, score)

    def build_plan(self, endpoints: list[EndpointRisk]) -> list[AttackStep]:
        scored = [(self.score_endpoint(ep), ep) for ep in endpoints]
        scored.sort(key=lambda x: x[0], reverse=True)
        steps: list[AttackStep] = []
        for i, (score, ep) in enumerate(scored):
            techniques = ["input_validation", "authz_check", "error_handling"]
            if ep.handles_sensitive_data:
                techniques.append("data_exposure")
            if not ep.requires_auth:
                techniques.append("unauth_access")
            for t in techniques:
                steps.append(AttackStep(
                    step_id=f"step_{i}_{t}", target_endpoint=ep.path,
                    technique=t, priority=score,
                    rationale=f"risk_score={score:.2f} technique={t}"))
        steps.sort(key=lambda s: s.priority, reverse=True)
        return steps

    def complementary_steps(self, finding: dict[str, Any]) -> list[AttackStep]:
        """When a finding is discovered, generate complementary attack steps."""
        vuln = str(finding.get("vuln_class", "unknown"))
        endpoint = str(finding.get("endpoint", finding.get("url", "")))
        complements: list[AttackStep] = []
        if vuln in ("idor", "auth_bypass", "broken_access_control"):
            complements.append(AttackStep("comp_authz", endpoint, "horizontal_privilege_escalation",
                                          priority=0.9, rationale="authz flaw → test other users/roles"))
            complements.append(AttackStep("comp_vertical", endpoint, "vertical_privilege_escalation",
                                          priority=0.85, rationale="authz flaw → test admin functions"))
        if vuln in ("xss", "sqli", "command_injection"):
            complements.append(AttackStep("comp_variants", endpoint, "payload_variants",
                                          priority=0.8, rationale="injection → test encodings/waf-bypass"))
        if vuln in ("info_disclosure", "error_handling"):
            complements.append(AttackStep("comp_leak", endpoint, "sensitive_data_extraction",
                                          priority=0.75, rationale="info leak → extract more data"))
        return complements


# ---------------------------------------------------------------------------
# 2. ContextualCorrelationEngine — compound vulnerabilities
# ---------------------------------------------------------------------------

@dataclass
class CompoundVulnerability:
    compound_id: str
    components: list[str]       # finding_ids
    compound_type: str
    confidence_boost: float
    description: str


class ContextualCorrelationEngine:
    """Links isolated findings into compound vulnerabilities. Two isolated
    low-severity findings together may be critical."""

    def correlate(self, findings: list[dict[str, Any]]) -> list[CompoundVulnerability]:
        compounds: list[CompoundVulnerability] = []
        by_endpoint: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            ep = str(f.get("endpoint", f.get("url", "")))
            by_endpoint.setdefault(ep, []).append(f)

        for ep, group in by_endpoint.items():
            classes = {str(f.get("vuln_class", "")) for f in group}
            fids = [str(f.get("finding_id", f.get("title", "?"))) for f in group]
            # info_disclosure + missing_authz = sensitive data exposure
            if "info_disclosure" in classes and any(c in classes for c in ("idor", "auth_bypass", "broken_access_control")):
                compounds.append(CompoundVulnerability(
                    f"comp_{ep}_data_exposure", fids, "sensitive_data_exposure", 0.3,
                    f"{ep}: info disclosure + missing authz = sensitive data exposure"))
            # error_handling + injection = detailed error leak aids exploitation
            if "error_handling" in classes and any(c in classes for c in ("xss", "sqli", "command_injection")):
                compounds.append(CompoundVulnerability(
                    f"comp_{ep}_aided_exploit", fids, "error_aided_exploitation", 0.25,
                    f"{ep}: detailed errors aid injection exploitation"))
            # weak_session + auth_bypass = full account takeover
            if "weak_session" in classes and "auth_bypass" in classes:
                compounds.append(CompoundVulnerability(
                    f"comp_{ep}_account_takeover", fids, "account_takeover", 0.4,
                    f"{ep}: weak session + auth bypass = account takeover"))
        return compounds


# ---------------------------------------------------------------------------
# 3. AdaptiveKnowledgeGraph — per-target memory
# ---------------------------------------------------------------------------

@dataclass
class TargetKnowledge:
    target_id: str
    strengths: list[str] = field(default_factory=list)
    weaknesses: list[str] = field(default_factory=list)
    defense_patterns: list[str] = field(default_factory=list)
    successful_attacks: dict[str, int] = field(default_factory=dict)
    failed_attacks: dict[str, int] = field(default_factory=dict)
    behavior_signature: dict[str, Any] = field(default_factory=dict)


class AdaptiveKnowledgeGraph:
    """Per-target memory. Learns from success/failure. Alerts when target
    behavior changes (defense changed)."""

    def __init__(self) -> None:
        self.targets: dict[str, TargetKnowledge] = {}

    def get(self, target_id: str) -> TargetKnowledge:
        return self.targets.setdefault(target_id, TargetKnowledge(target_id=target_id))

    def record_attack(self, target_id: str, technique: str, success: bool) -> None:
        tk = self.get(target_id)
        if success:
            tk.successful_attacks[technique] = tk.successful_attacks.get(technique, 0) + 1
        else:
            tk.failed_attacks[technique] = tk.failed_attacks.get(technique, 0) + 1

    def should_skip(self, target_id: str, technique: str) -> tuple[bool, str]:
        """Skip a technique proven to fail repeatedly (>=3 failures, 0 success)."""
        tk = self.get(target_id)
        fails = tk.failed_attacks.get(technique, 0)
        success = tk.successful_attacks.get(technique, 0)
        if fails >= 3 and success == 0:
            return True, f"technique_{technique}_failed_{fails}x_with_zero_success"
        return False, "ok"

    def detect_behavior_change(self, target_id: str, new_signature: dict[str, Any]) -> tuple[bool, str]:
        """Compare new behavior signature to stored one. If significantly
        different → alert (defense may have changed)."""
        tk = self.get(target_id)
        if not tk.behavior_signature:
            tk.behavior_signature = dict(new_signature)
            return False, "baseline_recorded"
        diffs = [k for k in new_signature if tk.behavior_signature.get(k) != new_signature[k]]
        if len(diffs) >= 2:
            tk.behavior_signature = dict(new_signature)
            return True, f"target_behavior_changed: {','.join(diffs)} — recheck_critical_points"
        return False, "behavior_stable"


# ---------------------------------------------------------------------------
# 4. StrategyEngine — offensive mode: escalating confirmation + impact
# ---------------------------------------------------------------------------

class ImpactLevel(str, Enum):
    NONE = "none"
    USER_DATA = "user_data"
    SYSTEM_DATA = "system_data"
    FULL_SYSTEM = "full_system"


@dataclass
class EscalationResult:
    finding_id: str
    confirmation_level: int     # 0-3, higher = more confirmed
    variants_tested: int
    impact: ImpactLevel
    priority: RiskLevel
    evidence: list[str] = field(default_factory=list)


class StrategyEngine:
    """Offensive mode: escalating confirmation (level 0-3), variant testing,
    impact estimation, priority classification based on real evidence."""

    ESCALATION_LEVELS = ["presence_detected", "reproducible", "state_change", "data_exfiltrated"]

    def escalate(self, finding: dict[str, Any], *, confirmation_level: int = 0,
                 variants_tested: int = 0, impact_evidence: str = "none") -> EscalationResult:
        conf = min(3, max(0, confirmation_level))
        # Impact from evidence
        if "system" in impact_evidence or "admin" in impact_evidence:
            impact = ImpactLevel.FULL_SYSTEM
        elif "user_data" in impact_evidence or "pii" in impact_evidence:
            impact = ImpactLevel.USER_DATA
        elif "data" in impact_evidence:
            impact = ImpactLevel.SYSTEM_DATA
        else:
            impact = ImpactLevel.NONE
        # Priority from confirmation + impact.
        # P1-10 (0.33.0): the old ladder tested `conf >= 1 or impact !=
        # NONE` BEFORE the bare `conf >= 1` branch, so MEDIUM was
        # unreachable and every marginally-confirmed finding reported HIGH.
        if conf >= 2 and impact in (ImpactLevel.FULL_SYSTEM, ImpactLevel.SYSTEM_DATA):
            priority = RiskLevel.CRITICAL
        elif impact != ImpactLevel.NONE:
            priority = RiskLevel.HIGH
        elif conf >= 1:
            priority = RiskLevel.MEDIUM
        else:
            priority = RiskLevel.LOW
        evidence = [self.ESCALATION_LEVELS[i] for i in range(conf + 1)]
        return EscalationResult(
            finding_id=str(finding.get("finding_id", finding.get("title", "?"))),
            confirmation_level=conf, variants_tested=variants_tested,
            impact=impact, priority=priority, evidence=evidence)

    def suggest_variants(self, vuln_class: str) -> list[str]:
        """Suggest payload/technique variants to test."""
        base = {"xss": ["<script>", "javascript:", "onerror=", "svg/onload", "data:text/html"],
                "sqli": ["'", "\"", " OR 1=1--", " UNION SELECT", "time-based blind"],
                "command_injection": [";", "&&", "|", "`", "$()"],
                "idor": ["other_user_id", "negative_id", "uuid_guess", "admin_id"]}
        return base.get(vuln_class, ["parameter_fuzzing", "encoding_variants", "header_injection"])


# ---------------------------------------------------------------------------
# 5. StealthResilienceLayer — block detection + adaptation + scope bounds
# ---------------------------------------------------------------------------

class DefenseSignal(str, Enum):
    NONE = "none"
    RATE_LIMIT = "rate_limit"          # 429s
    WAF_BLOCK = "waf_block"            # 403 + block markers
    CAPTCHA = "captcha"                # captcha challenge
    SLOW_DOWN = "slow_down"            # latency spike


@dataclass
class StealthState:
    request_interval: float = 1.0
    user_agent_rotation: int = 0
    consecutive_failures: int = 0
    detected_defense: DefenseSignal = DefenseSignal.NONE
    allowed_scope: list[str] = field(default_factory=list)


class StealthResilienceLayer:
    """Detects defense signals, adapts rate/timing/identity. Safe stop on
    persistent blocks. Enforces scope bounds (never leaves allowed scope)."""

    BLOCK_MARKERS = ("cloudflare", "sucuri", "akamai", "captcha", "blocked", "rate limit")

    def __init__(self, allowed_scope: list[str] | None = None) -> None:
        self.state = StealthState(allowed_scope=allowed_scope or [])

    def in_scope(self, url: str) -> bool:
        """Scope bound by registrable host comparison (P1-11, 0.33.0).

        The old containment check (`scope_entry in url`) was trivially
        bypassable: https://notexample.com/, https://evil.com/?u=example.com
        and https://example.com@evil.com/ all passed while the class
        contract says the layer NEVER leaves allowed scope. Scope entries
        may be bare domains or URLs (their hostname is extracted). Exact
        host or dot-boundary subdomain match only.
        """
        if not self.state.allowed_scope:
            return True  # no scope restriction configured
        try:
            host = (urlsplit(url).hostname or "").strip().lower()
        except ValueError:
            return False
        if not host:
            return False
        for entry in self.state.allowed_scope:
            scope = str(entry).strip().lower()
            if not scope:
                continue
            if "://" in scope:
                try:
                    scope = (urlsplit(scope).hostname or "").strip().lower()
                except ValueError:
                    continue
            if not scope:
                continue
            if host == scope or host.endswith("." + scope):
                return True
        return False

    def analyze_response(self, status_code: int, headers: dict[str, str],
                         body: str = "", latency_ms: float = 0) -> DefenseSignal:
        hstr = " ".join(f"{k}:{v}" for k, v in (headers or {}).items()).lower()
        bstr = (body or "").lower()
        if status_code == 429:
            self.state.detected_defense = DefenseSignal.RATE_LIMIT
        elif status_code == 403 and any(m in hstr or m in bstr for m in self.BLOCK_MARKERS):
            self.state.detected_defense = DefenseSignal.WAF_BLOCK
        elif "captcha" in bstr or "captcha" in hstr:
            self.state.detected_defense = DefenseSignal.CAPTCHA
        elif latency_ms > 5000:
            self.state.detected_defense = DefenseSignal.SLOW_DOWN
        else:
            self.state.detected_defense = DefenseSignal.NONE
            self.state.consecutive_failures = 0
        if self.state.detected_defense != DefenseSignal.NONE:
            self.state.consecutive_failures += 1
        return self.state.detected_defense

    def adapt(self) -> dict[str, Any]:
        """Adapt strategy based on detected defense. Returns the adaptation
        actions taken. Never returns 'fake success'."""
        actions: list[str] = []
        d = self.state.detected_defense
        if d == DefenseSignal.NONE:
            # C3 fix: when no defense detected, gradually return interval to normal
            if self.state.request_interval > 1.0:
                self.state.request_interval = max(1.0, self.state.request_interval / 2)
                actions.append(f"recover_normal_pace: interval={self.state.request_interval:.1f}s")
        elif d == DefenseSignal.RATE_LIMIT:
            self.state.request_interval = min(30.0, self.state.request_interval * 3)
            actions.append(f"slow_down: interval={self.state.request_interval:.1f}s")
        elif d == DefenseSignal.WAF_BLOCK:
            self.state.user_agent_rotation += 1
            self.state.request_interval = min(60.0, self.state.request_interval * 2)
            actions.append("rotate_user_agent")
            actions.append(f"slow_down: interval={self.state.request_interval:.1f}s")
            actions.append("switch_payload_signature")
        elif d == DefenseSignal.CAPTCHA:
            self.state.request_interval = 120.0
            actions.append("long_backoff_120s")
        elif d == DefenseSignal.SLOW_DOWN:
            self.state.request_interval = min(10.0, self.state.request_interval * 1.5)
            actions.append("moderate_slow_down")
        should_stop = self.state.consecutive_failures >= 5
        if should_stop:
            actions.append("safe_stop: 5 consecutive blocks — halt for manual review")
        return {"defense_detected": d.value, "actions": actions,
                "should_safely_stop": should_stop,
                "new_request_interval": self.state.request_interval}

    def safe_stop(self) -> dict[str, Any]:
        """Graceful stop: record state, return resume info."""
        return {"stopped_safely": True,
                "state": {"request_interval": self.state.request_interval,
                          "consecutive_failures": self.state.consecutive_failures,
                          "detected_defense": self.state.detected_defense.value},
                "resume_hint": "retry_after_cooldown_with_different_strategy"}


__all__ = [
    "AdaptiveKnowledgeGraph", "AttackPlanner", "AttackStep", "CompoundVulnerability",
    "ContextualCorrelationEngine", "DefenseSignal", "EndpointRisk", "EscalationResult",
    "ImpactLevel", "RiskLevel", "StealthResilienceLayer", "StealthState",
    "StrategyEngine", "TargetKnowledge",
]
