"""CampaignMemory — U-CAMPAIGN-9.

The historian's memory: every completed campaign is recorded as JSON
under the memory's own directory (brief via the same serialization the
CampaignStore uses, plus a record file carrying the report's totals
and the thesis's family mix). Recall is read-only and deterministic:
an empty memory yields empty answers, never errors.

Storage is deliberately boring local JSON — zero network, zero
dynamic attribute resolution (direct protocol reads on the report's
recorded fields).
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from webpent.campaign.schemas import CampaignBrief, Family
from webpent.campaign.storage.campaign_store import CampaignStore

_RECORD_VERSION = "campaign_memory_v1"


@dataclass(frozen=True)
class RecordedReport:
    """The report fields the memory records, read off the report object."""

    campaign_id: str
    outcome: dict = field(default_factory=dict)
    findings_total: int = 0
    budget_requests_used: int = 0


@dataclass(frozen=True)
class MemoryRecord:
    """One recalled campaign: its id, its brief, its recorded report."""

    memory_id: str
    campaign_id: str
    brief: CampaignBrief
    report: RecordedReport

    @property
    def thesis(self):
        return self.brief.thesis


class CampaignMemory:
    """Persists completed campaigns as JSON and recalls them read-only."""

    def __init__(self, root_dir: Path | str):
        self._root = Path(root_dir)
        self._records_dir = self._root / "records"
        self._records_dir.mkdir(parents=True, exist_ok=True)
        self._briefs = CampaignStore(root_dir=self._root / "briefs")

    # -- recording ---------------------------------------------------------

    def record(self, brief: CampaignBrief, report: Any) -> str:
        """Record one completed campaign; re-recording updates in place."""
        memory_id = f"mem-{brief.campaign_id}"
        self._briefs.save_brief(brief)
        recorded = RecordedReport(
            campaign_id=report.campaign_id,
            outcome=dict(report.outcome),
            findings_total=report.findings_total,
            budget_requests_used=report.budget_requests_used,
        )
        families = [
            [fam.name, weight]
            for fam, weight in brief.thesis.likely_vuln_families
        ]
        payload = {
            "version": _RECORD_VERSION,
            "memory_id": memory_id,
            "campaign_id": brief.campaign_id,
            "target_id": brief.thesis.target_id,
            "families": families,
            "report": asdict(recorded),
        }
        self._path_for(memory_id).write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return memory_id

    # -- recall (read-only) ------------------------------------------------

    def get(self, memory_id: str) -> MemoryRecord | None:
        path = self._path_for(memory_id)
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        brief = self._briefs.get_brief(payload["campaign_id"])
        if brief is None:
            return None
        report_dict = payload["report"]
        return MemoryRecord(
            memory_id=payload["memory_id"],
            campaign_id=payload["campaign_id"],
            brief=brief,
            report=RecordedReport(
                campaign_id=report_dict["campaign_id"],
                outcome=dict(report_dict["outcome"]),
                findings_total=report_dict["findings_total"],
                budget_requests_used=report_dict["budget_requests_used"],
            ),
        )

    def recall_by_target(self, target_id: str) -> list[MemoryRecord]:
        return [
            record for record in self._all()
            if record.brief.thesis.target_id == target_id
        ]

    def recall_by_family(self, family: Family) -> list[MemoryRecord]:
        selected = []
        for record in self._all():
            families = [
                fam for fam, _w in record.brief.thesis.likely_vuln_families
            ]
            if family in families:
                selected.append(record)
        return selected

    def list_all(self) -> list[MemoryRecord]:
        return self._all()

    # -- internals ----------------------------------------------------------

    def _path_for(self, memory_id: str) -> Path:
        return self._records_dir / f"{memory_id}.json"

    def _all(self) -> list[MemoryRecord]:
        records: list[MemoryRecord] = []
        for path in sorted(self._records_dir.glob("*.json")):
            memory_id = path.stem
            record = self.get(memory_id)
            if record is not None:
                records.append(record)
        return records
