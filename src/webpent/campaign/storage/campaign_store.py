"""CampaignStore — the campaign's paper trail (L-2 durability).

Every brief the operator sees and every ruling they record lives here
as one JSON file per campaign. Rulings are immutable on the brief, so
the store is append-per-campaign: the newest write for a campaign_id
is that campaign's current state, and nothing is ever merged silently.

Storage is deliberately boring: local JSON files under ``root_dir``.
No network I/O (direct-I/O scanner clean), no database, no lock file —
one writer per store, enforced by convention (the handoff layer).
"""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from webpent.campaign.schemas import (
    CampaignBrief,
    CampaignBudget,
    Decision,
    Family,
    Hypothesis,
    Phase,
    PhaseBudget,
    PivotAction,
    PivotTrigger,
    TargetThesis,
    ThesisEvidence,
)


class CampaignStore:
    """Persists campaign briefs as JSON files, one per campaign."""

    def __init__(self, root_dir: Path | str):
        self._root = Path(root_dir)
        self._root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save_brief(self, brief: CampaignBrief) -> None:
        path = self._path_for(brief.campaign_id)
        path.write_text(
            json.dumps(self._to_dict(brief), indent=2, sort_keys=True),
            encoding="utf-8")

    def get_brief(self, campaign_id: str) -> CampaignBrief | None:
        path = self._path_for(campaign_id)
        if not path.exists():
            return None
        return self._from_dict(json.loads(path.read_text(encoding="utf-8")))

    def list_briefs(self) -> list[CampaignBrief]:
        briefs: list[CampaignBrief] = []
        for path in sorted(self._root.glob("*.json")):
            briefs.append(self._from_dict(json.loads(path.read_text(
                encoding="utf-8"))))
        briefs.sort(key=lambda b: b.created_at)
        return briefs

    # ------------------------------------------------------------------
    # Serialization (explicit, not asdict — enums and datetimes must
    # round-trip losslessly, and silent str() coercion is how data dies)
    # ------------------------------------------------------------------

    def _path_for(self, campaign_id: str) -> Path:
        return self._root / f"{campaign_id}.json"

    def _to_dict(self, brief: CampaignBrief) -> dict[str, Any]:
        thesis = None
        if brief.thesis is not None:
            thesis = {
                "thesis_id": brief.thesis.thesis_id,
                "target_id": brief.thesis.target_id,
                "statement": brief.thesis.statement,
                "confidence": brief.thesis.confidence,
                "likely_vuln_families": [
                    [f.value, score]
                    for f, score in brief.thesis.likely_vuln_families
                ],
                "unlikely_vuln_families": [
                    [f.value, score]
                    for f, score in brief.thesis.unlikely_vuln_families
                ],
                "crown_jewels": list(brief.thesis.crown_jewels),
                "likely_entry_points": list(brief.thesis.likely_entry_points),
                "evidence": [asdict(e) for e in brief.thesis.evidence],
                "reasoning": brief.thesis.reasoning,
                "created_at": brief.thesis.created_at.isoformat(),
                "version": brief.thesis.version,
                "supersedes": brief.thesis.supersedes,
            }
        return {
            "campaign_id": brief.campaign_id,
            "created_at": brief.created_at.isoformat(),
            "thesis": thesis,
            "phases": [self._phase_to_dict(p) for p in brief.phases],
            "total_budget": asdict(brief.total_budget),
            "decision": brief.decision.value,
        }

    def _phase_to_dict(self, phase: Phase) -> dict[str, Any]:
        return {
            "phase_id": phase.phase_id,
            "order": phase.order,
            "goal": phase.goal,
            "thesis_alignment": phase.thesis_alignment,
            "hypotheses": [asdict(h) | {"family": h.family.value}
                           for h in phase.hypotheses],
            "budget": asdict(phase.budget),
            "exit_criteria": list(phase.exit_criteria),
            "success_indicators": list(phase.success_indicators),
            "failure_indicators": list(phase.failure_indicators),
            "pivot_triggers": [asdict(t) | {"action": t.action.value}
                               for t in phase.pivot_triggers],
            "entry_criteria": list(phase.entry_criteria),
            "target_id": phase.target_id,
        }

    def _from_dict(self, raw: dict[str, Any]) -> CampaignBrief:
        thesis_raw = raw.get("thesis")
        thesis = None
        if thesis_raw is not None:
            thesis = TargetThesis(
                thesis_id=thesis_raw["thesis_id"],
                target_id=thesis_raw["target_id"],
                statement=thesis_raw["statement"],
                confidence=thesis_raw["confidence"],
                likely_vuln_families=[
                    (Family(f), score)
                    for f, score in thesis_raw["likely_vuln_families"]
                ],
                unlikely_vuln_families=[
                    (Family(f), score)
                    for f, score in thesis_raw["unlikely_vuln_families"]
                ],
                crown_jewels=list(thesis_raw["crown_jewels"]),
                likely_entry_points=list(thesis_raw["likely_entry_points"]),
                evidence=[
                    ThesisEvidence(
                        evidence_id=e["evidence_id"],
                        source=e["source"],
                        source_ref=e["source_ref"],
                        claim=e["claim"],
                        weight=e["weight"],
                    )
                    for e in thesis_raw["evidence"]
                ],
                reasoning=thesis_raw["reasoning"],
                created_at=datetime.fromisoformat(thesis_raw["created_at"]),
                version=thesis_raw["version"],
                supersedes=thesis_raw["supersedes"],
            )
        return CampaignBrief(
            campaign_id=raw["campaign_id"],
            created_at=datetime.fromisoformat(raw["created_at"]),
            thesis=thesis,
            phases=[self._phase_from_dict(p) for p in raw["phases"]],
            total_budget=CampaignBudget(**raw["total_budget"]),
            decision=Decision(raw["decision"]),
        )

    def _phase_from_dict(self, raw: dict[str, Any]) -> Phase:
        return Phase(
            phase_id=raw["phase_id"],
            order=raw["order"],
            goal=raw["goal"],
            thesis_alignment=raw["thesis_alignment"],
            hypotheses=[
                Hypothesis(
                    hypothesis_id=h["hypothesis_id"],
                    family=Family(h["family"]),
                    statement=h["statement"],
                    success_indicator=h["success_indicator"],
                    failure_indicator=h["failure_indicator"],
                    probe_strategy=h["probe_strategy"],
                    estimated_requests=h["estimated_requests"],
                    estimated_llm_calls=h["estimated_llm_calls"],
                    estimated_duration_seconds=h["estimated_duration_seconds"],
                    order=h["order"],
                )
                for h in raw["hypotheses"]
            ],
            budget=PhaseBudget(**raw["budget"]),
            exit_criteria=list(raw["exit_criteria"]),
            success_indicators=list(raw["success_indicators"]),
            failure_indicators=list(raw["failure_indicators"]),
            pivot_triggers=[
                PivotTrigger(
                    trigger_id=t["trigger_id"],
                    condition=t["condition"],
                    condition_type=t["condition_type"],
                    threshold=t["threshold"],
                    action=PivotAction(t["action"]),
                    reason=t["reason"],
                )
                for t in raw["pivot_triggers"]
            ],
            entry_criteria=list(raw["entry_criteria"]),
            target_id=raw["target_id"],
        )
