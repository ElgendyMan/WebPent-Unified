"""The Apex Predator — U-APEX-8, the Result Fusion Engine (v87).

APEX-L-6 FUSE RESULTS: several tools see the same target and disagree.
This engine merges their findings into one picture: grouped by
(vuln_class, endpoint), consensus computed from how many of the reporting
tools agree, confidence weighted by each tool's historical accuracy
(APEX-L-7), conflicts resolved to the higher-confidence finding with the
disagreement recorded — never silently dropped. Output order is
deterministic. Every fused finding is advisory (APEX-L-9): it informs the
operator, it does not act.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

PREAMBLE_LINE = (
    "advisory: fused findings are weighted evidence, not verdicts — the "
    "operator decides what is real."
)

#: confidence weight when no accuracy entry exists for a tool
DEFAULT_ACCURACY = 0.5


@dataclass
class Evidence:
    """One tool's raw claim about one endpoint."""

    vuln_class: str
    endpoint: str
    severity: str
    confidence: float
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "vuln_class": self.vuln_class,
            "endpoint": self.endpoint,
            "severity": self.severity,
            "confidence": round(self.confidence, 4),
            "detail": self.detail,
        }


@dataclass
class ExecResult:
    """What one tool reported from its run."""

    tool_id: str
    findings: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool_id": self.tool_id,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class FusedFinding:
    """Several tools' claims about one (vuln_class, endpoint) merged."""

    finding_id: str
    vuln_class: str
    endpoint: str
    severity: str
    confidence: float
    evidence: list[Evidence] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    consensus: float = 0.0
    disagreements: list[str] = field(default_factory=list)
    advisory_note: str = PREAMBLE_LINE

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "vuln_class": self.vuln_class,
            "endpoint": self.endpoint,
            "severity": self.severity,
            "confidence": round(self.confidence, 4),
            "evidence": [e.to_dict() for e in self.evidence],
            "sources": list(self.sources),
            "consensus": round(self.consensus, 4),
            "disagreements": list(self.disagreements),
            "advisory_note": self.advisory_note,
        }


class ResultFusion:
    """Merge per-tool results into weighted, deduplicated findings."""

    def fuse(
        self,
        results: list[ExecResult],
        accuracy: dict[str, float] | None = None,
    ) -> list[FusedFinding]:
        if not results:
            return []
        accuracy = accuracy or {}
        reporting_tools = {r.tool_id for r in results if r.findings}

        groups: dict[tuple[str, str], list[Evidence]] = {}
        claim_tool: dict[int, str] = {}
        for result in results:
            for finding in result.findings:
                key = (finding.vuln_class, finding.endpoint)
                groups.setdefault(key, []).append(finding)
                claim_tool[id(finding)] = result.tool_id

        fused: list[FusedFinding] = []
        for (vuln_class, endpoint), claims in groups.items():
            claims = sorted(claims, key=lambda c: c.detail)
            source_tools = sorted(
                {claim_tool[id(c)] for c in claims}
            )
            # accuracy-weighted confidence: each tool's claim is discounted
            # by its historical accuracy before averaging
            weighted = [
                (claim, float(accuracy.get(claim_tool[id(claim)], DEFAULT_ACCURACY)))
                for claim in claims
            ]
            # accuracy-weighted confidence: each tool's claim is discounted
            # by its historical accuracy, then the discounted claims average
            confidence = (
                sum(c.confidence * w for c, w in weighted) / len(weighted)
                if weighted else 0.0
            )
            # severity: the most severe reported, deterministically
            severity = max((c.severity for c in claims), key=_severity_rank)
            consensus = len(source_tools) / len(reporting_tools)
            fused.append(
                FusedFinding(
                    finding_id=_finding_id(vuln_class, endpoint),
                    vuln_class=vuln_class,
                    endpoint=endpoint,
                    severity=severity,
                    confidence=confidence,
                    evidence=list(claims),
                    sources=source_tools,
                    consensus=consensus,
                )
            )
        # deterministic order: vuln_class, then endpoint
        fused.sort(key=lambda f: (f.vuln_class, f.endpoint))
        return fused

    def resolve_conflict(
        self, conflicting: list[FusedFinding]
    ) -> FusedFinding:
        """Pick the higher-confidence fused finding, recording what the
        others said so nothing is silently discarded."""
        if not conflicting:
            raise ValueError("resolve_conflict needs at least one finding")
        winner = max(
            conflicting, key=lambda f: (f.confidence, f.finding_id)
        )
        losers = [f for f in conflicting if f is not winner]
        disagreements = [
            f"{f.finding_id} ({f.vuln_class} at {f.endpoint}): "
            f"confidence {f.confidence:.2f}, sources "
            f"{','.join(f.sources) or 'none'}"
            for f in losers
        ]
        merged_sources = sorted({*winner.sources, *(s for f in losers for s in f.sources)})
        return FusedFinding(
            finding_id=winner.finding_id,
            vuln_class=winner.vuln_class,
            endpoint=winner.endpoint,
            severity=winner.severity,
            confidence=winner.confidence,
            evidence=list(winner.evidence),
            sources=merged_sources,
            consensus=winner.consensus,
            disagreements=disagreements,
        )


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_rank(label: str) -> int:
    """RT-12/RT-16: rank a severity label by its normalized form
    (case/whitespace tolerant). An unknown label ranks below every
    known one (-1) instead of returning None and crashing the max()
    comparison — and the fused finding keeps the original label as
    reported, so no classification is ever invented here."""
    return _SEVERITY_RANK.get(str(label).strip().lower(), -1)


def _finding_id(vuln_class: str, endpoint: str) -> str:
    seed = f"{vuln_class}|{endpoint}"
    return "find-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
