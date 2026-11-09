"""State for one autonomous hunt.

The state is additive: it wraps the existing controller/planner state rather
than replacing it, so the orchestrator can hand the same mapping to
``smart_campaigns_node`` and ``AutonomousController`` unchanged.

Everything stored here is redaction-safe. No cookies, tokens, credentials, or
raw request/response bodies are retained.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from webpent.autonomous.hunt_contracts import (
    HuntOutcome,
    HuntPhase,
    HuntStopReason,
    PhaseRecord,
    digest,
    redact,
)

_MAX_RECORDS = 256


@dataclass
class AutonomousHuntState:
    """Mutable working state for a single autonomous hunt."""

    engagement_id: str
    target_url: str
    phase: HuntPhase = HuntPhase.RECON
    stop_reason: HuntStopReason | None = None
    outcome: HuntOutcome | None = None

    # Iteration bookkeeping
    iteration: int = 0
    max_iterations: int = 5

    # Accumulated advisory data (passed through to existing components)
    target_knowledge: dict[str, Any] = field(default_factory=dict)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    selected_tasks: list[dict[str, Any]] = field(default_factory=list)
    outcomes: list[dict[str, Any]] = field(default_factory=list)
    proof_bundles: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)

    # Evidence ledgers (mirrors the controller's expected keys)
    positive_evidence_ledger: list[dict[str, Any]] = field(default_factory=list)
    negative_evidence_ledger: list[dict[str, Any]] = field(default_factory=list)
    knowledge_gaps: list[dict[str, Any]] = field(default_factory=list)

    # Convergence tracking
    seen_action_signatures: list[str] = field(default_factory=list)
    evidence_fingerprints: list[str] = field(default_factory=list)

    # Advisory discovery output (suggestion 3): the bounded candidate set
    # mined from this round's outcome records, plus the signatures of
    # every candidate discovery has already minted (cross-round dedup so
    # the loop never re-probes the same candidate).
    discovery: dict[str, Any] | None = None
    discovery_signatures: list[str] = field(default_factory=list)

    # Append-only phase trace
    phase_trace: list[PhaseRecord] = field(default_factory=list)

    # Scan profile for this hunt; projected into the controller state so the
    # smart planner engages under the same governance as explicit scans.
    scan_mode: str = "safe-smart"

    # Learning hints produced by the memory layer (advisory only)
    learning_hints: dict[str, float] = field(default_factory=dict)

    def record_phase(
        self,
        phase: HuntPhase,
        status: str,
        reason: str = "",
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        self.phase = phase
        if len(self.phase_trace) < _MAX_RECORDS:
            self.phase_trace.append(
                PhaseRecord(phase=phase, status=status, reason=reason, detail=dict(detail or {}))
            )

    def evidence_fingerprint(self) -> str:
        """Digest of current evidence ledgers, used for no-new-evidence stop."""
        return digest(
            {
                "positive": len(self.positive_evidence_ledger),
                "negative": len(self.negative_evidence_ledger),
                "knowledge_gaps": len(self.knowledge_gaps),
                "findings": len(self.findings),
            }
        )

    def has_new_evidence_since(self, fingerprint: str) -> bool:
        return self.evidence_fingerprint() != fingerprint

    def as_controller_state(self) -> dict[str, Any]:
        """Project into the mapping ``AutonomousController``/planner expect.

        This is the bridge that lets the orchestrator reuse the existing
        bounded controller without reimplementing it.
        """
        return {
            "engagement_id": self.engagement_id,
            "target_url": self.target_url,
            "scan_mode": self.scan_mode,
            # The smart planner reads the target origin from a ``target``
            # mapping (``_target_url``); without it the planner's
            # same-origin projection drops every hypothesis silently.
            "target": {"url": self.target_url},
            "target_knowledge": self.target_knowledge,
            "hypotheses": self.hypotheses,
            "positive_evidence_ledger": self.positive_evidence_ledger,
            "negative_evidence_ledger": self.negative_evidence_ledger,
            "knowledge_gaps": self.knowledge_gaps,
            "findings": self.findings,
            "completed_action_signatures": list(self.seen_action_signatures),
        }

    def to_report_json(self) -> dict[str, Any]:
        """Full redaction-safe report payload for the bounded hunter's JSON report.

        Exposed over the ``webpent.autonomous`` library API since the
        v0.32.0 removal of the retired ``hunt-auto`` CLI alias (whose
        ``--output`` flag used to serialize exactly this payload).
        """
        report = self.summary()
        report["findings"] = list(self.findings)
        report["hypotheses"] = [
            {
                # Discovery seeds carry hypothesis_id/gap_id rather than
                # pattern_id; a blank label in the report helps no one
                # (red-team R10).
                "pattern_id": str(
                    item.get("pattern_id")
                    or item.get("id")
                    or item.get("hypothesis_id")
                    or item.get("gap_id")
                    or ""
                ),
                "priority": (
                    item.get("priority")
                    if isinstance(item.get("priority"), (int, float))
                    else None
                ),
            }
            for item in self.hypotheses
        ]
        # Critique C7: an operator reading the report must be able to see
        # that re-hypothesis happened and from which origins, without
        # diffing phase records.
        origins: dict[str, int] = {}
        for item in self.hypotheses:
            origin_key = str(item.get("origin") or "hunt")
            origins[origin_key] = origins.get(origin_key, 0) + 1
        report["hypothesis_origins"] = origins
        # Critique C7/B7: the discovery section is machine-derived counts
        # over the same records that drive execution — planned work and
        # discovered candidates stay separated, no personified narrative.
        report["discovery_summary"] = self._discovery_summary()
        # v77 suggestion 2: advisory remediation guidance over the
        # findings this hunt already holds. Machine-derived, redaction-
        # safe, and absent when nothing is classified.
        remediation = self._remediation_summary()
        if remediation is not None:
            report["remediation"] = remediation
        return report

    def _remediation_summary(self) -> dict[str, Any] | None:
        from webpent.remediation import (
            build_executive_summary,
            build_priority_dashboard,
        )

        summary = build_executive_summary(self.findings)
        if sum(summary["counts_by_severity"].values()) == 0:
            return None
        dashboard = build_priority_dashboard(self.findings)
        return {
            "executive_summary": summary,
            "priority_dashboard": dashboard,
            "non_claim": (
                "advisory remediation guidance over existing findings; "
                "nothing re-ran and nothing was confirmed here"
            ),
        }

    def _discovery_summary(self) -> dict[str, Any]:
        """Redaction-safe counts derived from the discovery output."""
        discovery = self.discovery or {}
        if not discovery:
            return {"present": False}
        tiers: dict[str, int] = {}
        for anomaly in discovery.get("anomalies", []) or []:
            if not isinstance(anomaly, dict):
                continue
            key = str(anomaly.get("tier") or "unclassified")
            tiers[key] = tiers.get(key, 0) + 1
        return {
            "present": True,
            "anomalies": len(discovery.get("anomalies", []) or []),
            "anomaly_tiers": tiers,
            "hypotheses": len(discovery.get("hypotheses", []) or []),
            "routes": len(discovery.get("routes", []) or []),
            "endpoints": len(discovery.get("endpoints", []) or []),
            "parameters": len(discovery.get("params", []) or []),
            "hybrid_scenarios": len(discovery.get("hybrids", []) or []),
            "minted_candidate_signatures": len(self.discovery_signatures),
            "agenda": dict(discovery.get("agenda", {}) or {}),
        }

    def summary(self) -> dict[str, Any]:
        """Redaction-safe summary for CLI/report output."""
        return {
            "engagement_id": redact(self.engagement_id, 160),
            "target_url": redact(self.target_url, 240),
            "phase": self.phase.value,
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,
            "stop_reason": self.stop_reason.value if self.stop_reason else None,
            "outcome": self.outcome.value if self.outcome else None,
            "counts": {
                "hypotheses": len(self.hypotheses),
                "selected_tasks": len(self.selected_tasks),
                "outcomes": len(self.outcomes),
                "proof_bundles": len(self.proof_bundles),
                "findings": len(self.findings),
                "positive_evidence": len(self.positive_evidence_ledger),
                "negative_evidence": len(self.negative_evidence_ledger),
                "knowledge_gaps": len(self.knowledge_gaps),
            },
            "phase_trace": [record.as_dict() for record in self.phase_trace],
        }


__all__ = ["AutonomousHuntState"]
