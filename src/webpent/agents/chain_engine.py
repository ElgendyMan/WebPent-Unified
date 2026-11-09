"""Bounded post-campaign chaining of already-confirmed findings.

The engine is deliberately advisory until a caller supplies a governed executor.
It never performs raw target I/O, never attaches credentials, and never changes an
individual finding.  A confirmed combined chain therefore requires the caller to
provide an executor that delegates to the existing M4/AVI/PromotionPipeline path.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from itertools import combinations, permutations
from typing import Any, Callable, Iterable, Mapping, Sequence

from webpent.models.proof_bundle import ProofBundle, proof_bundle_promotion_ready


MAX_CHAINS_PER_CAMPAIGN = 5


@dataclass(frozen=True)
class ChainPattern:
    name: str
    description: str
    requires: tuple[dict[str, str], ...]
    impact: str
    combined_severity: str
    narrative: str
    combined_cvss_floor: float


CHAIN_PATTERNS: tuple[ChainPattern, ...] = (
    ChainPattern(
        name="info_disclosure_to_idor",
        description="User IDs exposed -> use them for IDOR access",
        requires=(
            {"family": "INFO_DISCLOSURE", "gives": "user_ids"},
            {"family": "IDOR", "needs": "user_ids"},
        ),
        impact="HIGH",
        combined_severity="CRITICAL",
        narrative="The application exposes user identifiers ({disclosure_evidence}); combined with {idor_evidence}, an attacker can enumerate users and access their data.",
        combined_cvss_floor=9.0,
    ),
    ChainPattern(
        name="idor_to_account_takeover",
        description="Access to user data -> use their tokens/sessions -> full account control",
        requires=(
            {"family": "IDOR", "gives": "other_user_data"},
            {"family": "AUTH_BYPASS", "needs": "session_or_token"},
        ),
        impact="CRITICAL",
        combined_severity="CRITICAL",
        narrative="IDOR exposes another user's data and the authentication weakness supplies a session or token, creating a path to account takeover.",
        combined_cvss_floor=9.8,
    ),
    ChainPattern(
        name="ssrf_to_internal_access",
        description="SSRF vulnerability -> access internal services/metadata",
        requires=({"family": "SSRF", "gives": "internal_access"},),
        impact="CRITICAL",
        combined_severity="CRITICAL",
        narrative="The SSRF reaches an internal resource or metadata service, demonstrating an internal-access impact.",
        combined_cvss_floor=9.0,
    ),
    ChainPattern(
        name="xss_to_csrf_bypass",
        description="Stored XSS -> steal CSRF token -> perform actions as user",
        requires=({"family": "XSS", "gives": "script_execution"},),
        impact="HIGH",
        combined_severity="HIGH",
        narrative="Stored script execution is combined with the observed missing CSRF boundary to perform an authenticated action.",
        combined_cvss_floor=7.0,
    ),
    ChainPattern(
        name="idor_to_privilege_escalation",
        description="IDOR/BOLA -> role manipulation -> admin functions",
        requires=(
            {"family": "BOLA", "gives": "object_access"},
            {"family": "AUTH_BYPASS", "needs": "role_parameter"},
        ),
        impact="CRITICAL",
        combined_severity="CRITICAL",
        narrative="BOLA object access is combined with a role-manipulation authentication weakness to demonstrate privilege escalation.",
        combined_cvss_floor=9.0,
    ),
)


@dataclass(frozen=True)
class ChainCandidate:
    chain_id: str
    pattern: str
    description: str
    step_1_finding: dict[str, Any]
    step_2_finding: dict[str, Any] | None
    prerequisites_met: bool
    estimated_impact: str
    confidence: float
    narrative: str
    verification_needed: tuple[str, ...]
    target_url: str
    engagement_id: str
    chain_input: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "pattern": self.pattern,
            "description": self.description,
            "step_1_finding": dict(self.step_1_finding),
            "step_2_finding": dict(self.step_2_finding) if self.step_2_finding else None,
            "prerequisites_met": self.prerequisites_met,
            "estimated_impact": self.estimated_impact,
            "confidence": self.confidence,
            "narrative": self.narrative,
            "verification_needed": list(self.verification_needed),
            "target_url": self.target_url,
            "engagement_id": self.engagement_id,
            "chain_input": dict(self.chain_input),
        }


@dataclass(frozen=True)
class ChainExecutionResult:
    chain_id: str
    status: str
    confirmed: bool
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)
    proof_bundle_ref: str | None = None
    replay_verified: bool = False
    gates_passed: tuple[str, ...] = ()
    gates_failed: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "status": self.status,
            "confirmed": self.confirmed,
            "reason": self.reason,
            "evidence": dict(self.evidence),
            "proof_bundle_ref": self.proof_bundle_ref,
            "replay_verified": self.replay_verified,
            "gates_passed": list(self.gates_passed),
            "gates_failed": list(self.gates_failed),
        }


@dataclass(frozen=True)
class CombinedChainReport:
    chain_id: str
    title: str
    pattern: str
    steps: tuple[dict[str, Any], ...]
    combined_severity: str
    combined_cvss: float
    cvss_justification: str
    impact: str
    evidence: tuple[dict[str, Any], ...]
    proof_bundle_ref: str | None
    replay_verified: bool
    gates_passed: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "pattern": self.pattern,
            "steps": [dict(item) for item in self.steps],
            "combined_severity": self.combined_severity,
            "combined_cvss": self.combined_cvss,
            "cvss_justification": self.cvss_justification,
            "impact": self.impact,
            "evidence": [dict(item) for item in self.evidence],
            "proof_bundle_ref": self.proof_bundle_ref,
            "replay_verified": self.replay_verified,
            "gates_passed": list(self.gates_passed),
        }

    def to_markdown(self) -> str:
        lines = [
            f"# {self.title}",
            "",
            f"- Chain ID: `{self.chain_id}`",
            f"- Pattern: `{self.pattern}`",
            f"- Combined severity: **{self.combined_severity}**",
            f"- Combined CVSS: **{self.combined_cvss:.1f}**",
            "",
            "## Steps",
            "",
        ]
        lines.extend(
            f"{item.get('step')}. {item.get('finding') or item.get('chain')}: {item.get('result')}"
            for item in self.steps
        )
        lines.extend([
            "",
            "## CVSS justification",
            "",
            self.cvss_justification,
            "",
            "## Evidence",
            "",
            "Evidence is redacted and references sealed ProofBundles and governed chain execution.",
            "",
        ])
        return "\n".join(lines)


@dataclass(frozen=True)
class ChainRun:
    candidates: tuple[ChainCandidate, ...]
    executions: tuple[ChainExecutionResult, ...]
    reports: tuple[CombinedChainReport, ...]

    def to_dict(self) -> dict[str, Any]:
        confirmed = sum(1 for item in self.executions if item.confirmed)
        return {
            "chains_discovered": len(self.candidates),
            "chains_confirmed": confirmed,
            "chains_refuted": sum(1 for item in self.executions if item.status == "chain_refuted"),
            "chains_blocked": sum(1 for item in self.executions if item.status == "chain_blocked"),
            "combined_severity_upgrades": len(self.reports),
            "candidates": [item.to_dict() for item in self.candidates],
            "executions": [item.to_dict() for item in self.executions],
            "reports": [item.to_dict() for item in self.reports],
        }


ChainExecutor = Callable[[ChainCandidate], ChainExecutionResult | Mapping[str, Any]]
AuditEvent = Callable[[str, Mapping[str, Any]], None]


def _text(value: Any) -> str:
    return str(value or "").strip()


def normalize_family(value: Any) -> str:
    text = _text(value).upper().replace("-", " ").replace("/", " ")
    compact = " ".join(text.split())
    if "BOLA" in compact or "BROKEN OBJECT" in compact:
        return "BOLA"
    if "IDOR" in compact or "INSECURE DIRECT" in compact:
        return "IDOR"
    if "INFO" in compact and "DISCLOS" in compact:
        return "INFO_DISCLOSURE"
    if "AUTH" in compact and "BYPASS" in compact:
        return "AUTH_BYPASS"
    if "SSRF" in compact:
        return "SSRF"
    if "XSS" in compact:
        return "XSS"
    return compact.replace(" ", "_")


def _as_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(k): v for k, v in value.items()}
    if hasattr(value, "to_dict"):
        try:
            result = value.to_dict()
            return dict(result) if isinstance(result, Mapping) else {}
        except Exception:
            return {}
    if hasattr(value, "model_dump"):
        try:
            result = value.model_dump(mode="json")
            return dict(result) if isinstance(result, Mapping) else {}
        except Exception:
            return {}
    return {}


def _status(finding: Mapping[str, Any]) -> str:
    evidence = _as_mapping(finding.get("evidence"))
    promotion = _as_mapping(finding.get("promotion")) or _as_mapping(evidence.get("promotion"))
    return _text(finding.get("status") or promotion.get("decision") or finding.get("validator_outcome")).upper()


def _family(finding: Mapping[str, Any]) -> str:
    evidence = _as_mapping(finding.get("evidence"))
    return normalize_family(finding.get("family") or finding.get("vulnerability_class") or finding.get("vuln_class") or evidence.get("vulnerability_class"))


def _capabilities(finding: Mapping[str, Any]) -> set[str]:
    capabilities: set[str] = set()
    raw = finding.get("capabilities") or finding.get("gives") or finding.get("needs")
    if isinstance(raw, str):
        capabilities.add(raw)
    elif isinstance(raw, (list, tuple, set, frozenset)):
        capabilities.update(str(item) for item in raw)
    metadata = _as_mapping(finding.get("metadata"))
    for key in ("capabilities", "gives", "needs", "chain_capabilities"):
        value = metadata.get(key)
        if isinstance(value, str):
            capabilities.add(value)
        elif isinstance(value, (list, tuple, set, frozenset)):
            capabilities.update(str(item) for item in value)
    family = _family(finding)
    if family in {"IDOR", "BOLA"}:
        capabilities.update({"object_access", "other_user_data"})
        if metadata.get("identity_template_candidate") or metadata.get("resource_template"):
            capabilities.add("user_ids")
    return {item.strip().lower() for item in capabilities if item.strip()}


def _target(finding: Mapping[str, Any]) -> tuple[str, str]:
    return (
        _text(finding.get("target_url") or finding.get("target") or finding.get("url")),
        _text(finding.get("engagement_id") or finding.get("campaign_id")),
    )


def _mind_map_support(pattern: ChainPattern, findings: Sequence[Mapping[str, Any]], notes: Sequence[str]) -> bool:
    if not notes:
        return True
    haystack = " ".join(_text(item) for item in notes).lower()
    terms = [pattern.name.replace("_", " "), *(_family(item).lower() for item in findings)]
    return any(term and term in haystack for term in terms)


def _projection(finding: Mapping[str, Any]) -> dict[str, Any]:
    evidence = _as_mapping(finding.get("evidence"))
    promotion = _as_mapping(finding.get("promotion")) or _as_mapping(evidence.get("promotion"))
    return {
        "finding_id": _text(finding.get("id") or finding.get("finding_id")),
        "family": _family(finding),
        "status": _status(finding),
        "target_url": _target(finding)[0],
        "engagement_id": _target(finding)[1],
        "route": _text(finding.get("route") or finding.get("url") or evidence.get("route")),
        "severity": _text(finding.get("severity") or finding.get("cvss_score")),
        "proof_bundle_ref": _text(finding.get("proof_bundle_ref") or evidence.get("proof_bundle_ref")) or None,
        "capabilities": sorted(_capabilities(finding)),
        "promotion_gates": list(promotion.get("gates_passed") or [])[:8],
    }


def _verified_promoted_proof(finding: Mapping[str, Any]) -> ProofBundle | None:
    """Return a strictly verified bundle, never a ref-only claim.

    A status string and ``proof_bundle_ref`` are reporting metadata, not proof.
    Chain discovery therefore requires the actual sealed/authenticated bundle
    and an explicit replay verification result from the governed campaign.
    """
    evidence = _as_mapping(finding.get("evidence"))
    raw = finding.get("proof_bundle") or evidence.get("proof_bundle")
    if not raw:
        return None
    try:
        bundle = raw if isinstance(raw, ProofBundle) else ProofBundle.model_validate(raw)
    except Exception:
        return None
    replay_verified = bool(finding.get("replay_verified") or evidence.get("replay_verified"))
    if not replay_verified or not proof_bundle_promotion_ready(bundle):
        return None
    return bundle


def _safe_chain_source_identifier(finding: Mapping[str, Any]) -> str | None:
    """Extract a bounded identifier from sealed step-1 evidence only."""
    metadata = _as_mapping(finding.get("metadata"))
    candidate = metadata.get("resource_id") or metadata.get("disclosed_resource_id")
    bundle = _verified_promoted_proof(finding)
    if bundle is not None:
        causal = _as_mapping(getattr(bundle, "causal_oracle", {}))
        identity = _as_mapping(getattr(bundle, "identity_context", {}))
        candidate = candidate or causal.get("resource_id") or identity.get("resource_id")
    value = _text(candidate)
    # Resource identifiers are data, not routes. Reject anything that could
    # introduce a path/query separator into a governed request.
    if not value or len(value) > 128 or any(char in value for char in "/?#\\\r\n"):
        return None
    return value


def _supports(requirement: Mapping[str, str], finding: Mapping[str, Any]) -> bool:
    if normalize_family(finding.get("family")) != normalize_family(requirement.get("family")):
        return False
    needed = _text(requirement.get("needs") or requirement.get("gives")).lower()
    return not needed or needed in _capabilities(finding)


def _chain_id(pattern: ChainPattern, members: Sequence[Mapping[str, Any]]) -> str:
    raw = json.dumps({"pattern": pattern.name, "members": [_projection(item) for item in members]}, sort_keys=True)
    return "chain_" + hashlib.sha256(raw.encode()).hexdigest()[:16]


def discover_chains(
    findings: Iterable[Mapping[str, Any]],
    *,
    mind_map_notes: Sequence[str] = (),
    max_chains: int = MAX_CHAINS_PER_CAMPAIGN,
    patterns: Sequence[ChainPattern] = CHAIN_PATTERNS,
) -> tuple[ChainCandidate, ...]:
    """Discover only same-engagement combinations of already confirmed findings."""
    eligible = []
    for raw in findings:
        item = _as_mapping(raw)
        if (
            item
            and _status(item) in {"PROMOTED", "CONFIRMED", "TOOL-CONFIRMED", "TOOL_CONFIRMED"}
            and _verified_promoted_proof(item) is not None
        ):
            eligible.append(item)
    eligible = eligible[:256]
    result: list[ChainCandidate] = []
    seen: set[str] = set()
    for pattern in patterns:
        if len(pattern.requires) == 1:
            combinations_to_check = ((item,) for item in eligible)
        else:
            combinations_to_check = permutations(eligible, len(pattern.requires))
        for members in combinations_to_check:
            if len(members) > 1 and members[0] is members[1]:
                continue
            if not all(_supports(req, item) for req, item in zip(pattern.requires, members)):
                continue
            targets = {_target(item) for item in members}
            if len(targets) != 1:
                continue
            target_url, engagement_id = next(iter(targets))
            if not target_url or not engagement_id:
                continue
            if not _mind_map_support(pattern, members, mind_map_notes):
                continue
            chain_id = _chain_id(pattern, members)
            if chain_id in seen:
                continue
            seen.add(chain_id)
            first, second = members[0], members[1] if len(members) > 1 else None
            result.append(
                ChainCandidate(
                    chain_id=chain_id,
                    pattern=pattern.name,
                    description=pattern.description,
                    step_1_finding=_projection(first),
                    step_2_finding=_projection(second) if second else None,
                    prerequisites_met=True,
                    estimated_impact=pattern.impact,
                    confidence=0.8,
                    narrative=pattern.narrative.format(
                        disclosure_evidence=_projection(first).get("route") or "step 1 evidence",
                        idor_evidence=_projection(second).get("route") if second else "step 1 evidence",
                    ),
                    verification_needed=("execute the governed chain request", "verify combined causal impact"),
                    target_url=target_url,
                    engagement_id=engagement_id,
                    chain_input={
                        "source_finding_id": _projection(first).get("finding_id"),
                        "source_resource_id": _safe_chain_source_identifier(first),
                        "input_authority": "sealed_step_1_proof_bundle",
                    },
                )
            )
            if len(result) >= max(0, min(int(max_chains), MAX_CHAINS_PER_CAMPAIGN)):
                return tuple(result)
    return tuple(result)


def _normalize_execution(candidate: ChainCandidate, value: ChainExecutionResult | Mapping[str, Any]) -> ChainExecutionResult:
    if isinstance(value, ChainExecutionResult):
        return value
    data = _as_mapping(value)
    return ChainExecutionResult(
        chain_id=candidate.chain_id,
        status=_text(data.get("status") or ("chain_confirmed" if data.get("confirmed") else "chain_refuted")),
        confirmed=bool(data.get("confirmed")),
        reason=_text(data.get("reason") or "governed chain executor returned no reason"),
        evidence={str(k): v for k, v in _as_mapping(data.get("evidence")).items()},
        proof_bundle_ref=_text(data.get("proof_bundle_ref")) or None,
        replay_verified=bool(data.get("replay_verified")),
        gates_passed=tuple(str(item) for item in (data.get("gates_passed") or ())),
        gates_failed=tuple(str(item) for item in (data.get("gates_failed") or ())),
    )


def _combined_report(candidate: ChainCandidate, result: ChainExecutionResult, pattern: ChainPattern) -> CombinedChainReport:
    scores: list[float] = []
    for item in (candidate.step_1_finding, candidate.step_2_finding or {}):
        raw = _text(item.get("severity"))
        try:
            scores.append(float(raw))
        except ValueError:
            pass
    base = max(scores or [0.0])
    cvss = round(max(base, pattern.combined_cvss_floor), 1)
    title = f"[{pattern.combined_severity}] Combined impact via {pattern.name.replace('_', ' ')}"
    steps = (
        {"step": 1, "finding": candidate.step_1_finding.get("finding_id"), "result": "confirmed prerequisite"},
        *(({"step": 2, "finding": candidate.step_2_finding.get("finding_id"), "result": "confirmed prerequisite"},) if candidate.step_2_finding else ()),
        {"step": 3, "chain": candidate.chain_id, "result": "governed chain execution confirmed"},
    )
    justification = f"The {pattern.name} pattern is confirmed by the individual evidence and a successful governed chain execution; combined impact floor is {pattern.combined_cvss_floor:.1f}, base individual score was {base:.1f}."
    return CombinedChainReport(
        chain_id=candidate.chain_id,
        title=title,
        pattern=pattern.name,
        steps=tuple(steps),
        combined_severity=pattern.combined_severity,
        combined_cvss=cvss,
        cvss_justification=justification,
        impact=pattern.narrative,
        evidence=(*({"source": "step_1", "proof_bundle_ref": candidate.step_1_finding.get("proof_bundle_ref")},), *([{"source": "step_2", "proof_bundle_ref": candidate.step_2_finding.get("proof_bundle_ref")}] if candidate.step_2_finding else []), {"source": "chain_execution", "evidence": result.evidence}),
        proof_bundle_ref=result.proof_bundle_ref,
        replay_verified=result.replay_verified,
        gates_passed=result.gates_passed,
    )


class ChainEngine:
    """Post-campaign chain coordinator; execution is caller-owned and governed."""

    def __init__(self, *, audit_event: AuditEvent | None = None, max_chains: int = MAX_CHAINS_PER_CAMPAIGN) -> None:
        self.audit_event = audit_event
        self.max_chains = max(0, min(int(max_chains), MAX_CHAINS_PER_CAMPAIGN))

    def _event(self, name: str, candidate: ChainCandidate, **extra: Any) -> None:
        if self.audit_event:
            payload = {"chain_id": candidate.chain_id, "pattern": candidate.pattern, **extra}
            self.audit_event(name, payload)

    def discover(self, findings: Iterable[Mapping[str, Any]], *, mind_map_notes: Sequence[str] = ()) -> tuple[ChainCandidate, ...]:
        candidates = discover_chains(findings, mind_map_notes=mind_map_notes, max_chains=self.max_chains)
        for candidate in candidates:
            self._event("chain.discovered", candidate, prerequisites_met=True)
        return candidates

    def execute(self, candidates: Sequence[ChainCandidate], executor: ChainExecutor | None) -> ChainRun:
        executions: list[ChainExecutionResult] = []
        reports: list[CombinedChainReport] = []
        pattern_by_name = {item.name: item for item in CHAIN_PATTERNS}
        for candidate in list(candidates)[: self.max_chains]:
            if executor is None:
                result = ChainExecutionResult(candidate.chain_id, "chain_blocked", False, "governed_chain_executor_not_supplied")
            else:
                try:
                    result = _normalize_execution(candidate, executor(candidate))
                except Exception as exc:
                    result = ChainExecutionResult(candidate.chain_id, "chain_refuted", False, f"governed_chain_executor_error:{type(exc).__name__}")
            self._event("chain.executed", candidate, status=result.status, confirmed=result.confirmed)
            executions.append(result)
            if result.confirmed and result.replay_verified and not result.gates_failed:
                pattern = pattern_by_name.get(candidate.pattern)
                if pattern:
                    report = _combined_report(candidate, result, pattern)
                    reports.append(report)
                    self._event("chain.confirmed", candidate, combined_severity=report.combined_severity, combined_cvss=report.combined_cvss)
                    continue
            self._event("chain.rejected", candidate, reason=result.reason)
        return ChainRun(tuple(candidates), tuple(executions), tuple(reports))

    def run(self, findings: Iterable[Mapping[str, Any]], *, mind_map_notes: Sequence[str] = (), executor: ChainExecutor | None = None) -> ChainRun:
        candidates = self.discover(findings, mind_map_notes=mind_map_notes)
        return self.execute(candidates, executor)


__all__ = [
    "CHAIN_PATTERNS",
    "MAX_CHAINS_PER_CAMPAIGN",
    "ChainCandidate",
    "ChainEngine",
    "ChainExecutionResult",
    "ChainPattern",
    "ChainRun",
    "CombinedChainReport",
    "discover_chains",
    "normalize_family",
]
