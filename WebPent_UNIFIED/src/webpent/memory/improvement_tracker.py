"""Actual-data metrics for measuring whether campaign learning helps."""
from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _decisions(result: dict[str, Any]) -> list[dict[str, Any]]:
    campaign = result.get("campaign") if isinstance(result.get("campaign"), dict) else result
    return [item for item in campaign.get("decisions", []) if isinstance(item, dict)]


def _status(item: dict[str, Any]) -> str:
    promotion = item.get("promotion") if isinstance(item.get("promotion"), dict) else {}
    if promotion.get("decision") == "PROMOTED":
        return "promoted"
    outcome = str(item.get("validator_outcome") or item.get("status") or "").lower()
    if outcome == "refuted":
        return "refuted"
    return "inconclusive"


@dataclass(frozen=True)
class CampaignLearningMetrics:
    campaign_id: str
    client_id: str
    target_type: str
    recorded_at: str
    hypotheses_generated: int
    hypotheses_tested: int
    findings_promoted: int
    findings_refuted: int
    hypotheses_inconclusive: int
    cost_total: float
    cost_per_finding: float | None
    time_total: float | None
    time_to_first_finding: float | None
    lesson_hits: int
    adjusted_hypotheses: int
    boosted_tested: int
    boosted_promoted: int
    lesson_effectiveness: float | None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ImprovementTracker:
    """Small additive SQLite metric store with idempotent campaign records."""

    def __init__(self, database_path: str | Path = "./memory/global/improvement_metrics.sqlite3") -> None:
        self.path = Path(database_path)
        self._lock = threading.RLock()
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS campaign_learning_metrics (
                campaign_id TEXT PRIMARY KEY, client_id TEXT NOT NULL, target_type TEXT NOT NULL,
                recorded_at TEXT NOT NULL, metrics_json TEXT NOT NULL
            )""")

    def record_campaign(
        self, *, campaign_id: str, client_id: str, target_type: str,
        result: dict[str, Any], cost_total: float = 0.0,
        time_total: float | None = None, time_to_first_finding: float | None = None,
        lesson_consultation: dict[str, Any] | None = None,
    ) -> CampaignLearningMetrics:
        decisions = _decisions(result)
        statuses = [_status(item) for item in decisions]
        hypotheses = result.get("hypotheses") or []
        consultation = lesson_consultation or result.get("lesson_consultation") or {}
        adjusted = [item for item in hypotheses if isinstance(item, dict) and item.get("lesson_adjusted_score") is not None]
        boosted = [item for item in adjusted if bool((item.get("metadata") or {}).get("lesson_applied"))]
        boosted_tested_ids = {str(item.get("hypothesis_id")) for item in boosted if str(item.get("hypothesis_id"))}
        boosted_promoted = sum(
            1 for item in decisions
            if str(item.get("hypothesis_id")) in boosted_tested_ids and _status(item) == "promoted"
        )
        promoted = statuses.count("promoted")
        metrics = CampaignLearningMetrics(
            campaign_id=str(campaign_id)[:160], client_id=str(client_id)[:128], target_type=str(target_type)[:80],
            recorded_at=_now(), hypotheses_generated=len(hypotheses), hypotheses_tested=len(decisions),
            findings_promoted=promoted, findings_refuted=statuses.count("refuted"),
            hypotheses_inconclusive=statuses.count("inconclusive"), cost_total=round(max(0.0, float(cost_total)), 9),
            cost_per_finding=round(float(cost_total) / promoted, 9) if promoted else None,
            time_total=round(float(time_total), 6) if time_total is not None else None,
            time_to_first_finding=round(float(time_to_first_finding), 6) if time_to_first_finding is not None else None,
            lesson_hits=int(consultation.get("route_hits", 0)) + int(consultation.get("family_hits", 0)),
            adjusted_hypotheses=len(adjusted), boosted_tested=len(boosted), boosted_promoted=boosted_promoted,
            lesson_effectiveness=round(boosted_promoted / len(boosted), 6) if boosted else None,
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO campaign_learning_metrics(campaign_id,client_id,target_type,recorded_at,metrics_json) VALUES(?,?,?,?,?)",
                (metrics.campaign_id, metrics.client_id, metrics.target_type, metrics.recorded_at, json.dumps(metrics.as_dict(), sort_keys=True)),
            )
        return metrics

    def list_metrics(self, *, client_id: str | None = None, target_type: str | None = None) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if client_id:
            clauses.append("client_id=?"); params.append(str(client_id)[:128])
        if target_type:
            clauses.append("target_type=?"); params.append(str(target_type)[:80])
        query = "SELECT metrics_json FROM campaign_learning_metrics"
        if clauses: query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY recorded_at ASC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [json.loads(row[0]) for row in rows]

    def trends(self, *, client_id: str | None = None, target_type: str | None = None) -> dict[str, Any]:
        rows = self.list_metrics(client_id=client_id, target_type=target_type)
        return {
            "sample_count": len(rows),
            "cost_per_finding": [{"campaign_id": x["campaign_id"], "value": x["cost_per_finding"]} for x in rows],
            "time_to_first_finding": [{"campaign_id": x["campaign_id"], "value": x["time_to_first_finding"]} for x in rows],
            "hypothesis_efficiency": [{"campaign_id": x["campaign_id"], "value": (x["findings_promoted"] / x["hypotheses_tested"] if x["hypotheses_tested"] else None)} for x in rows],
            "metrics": rows,
        }


__all__ = ["CampaignLearningMetrics", "ImprovementTracker"]
