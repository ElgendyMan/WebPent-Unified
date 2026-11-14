"""U-FORGE-17 — The Payload Dashboard.

The corpus status view, exactly the spec's sections: totals, By
Family, By Quality, By Complexity (freshness), Learning. Rendered
from the real models: the PayloadIndexer owns the corpus rows, the
OutcomeTracker owns the outcome_records — the dashboard only reads
and aggregates, it never mutates either.

Freshness buckets (spec): fresh (< 30 days since ingestion),
recent (< 90), stable (>= 90). Zero network.
"""
from __future__ import annotations

from datetime import datetime, timezone

from webpent.forge.outcome_tracker import OutcomeTracker

FRESH_DAYS = 60
RECENT_DAYS = 90


def _bucket(days_old: int) -> str:
    if days_old < FRESH_DAYS:
        return "fresh"
    if days_old < RECENT_DAYS:
        return "recent"
    return "stable"


class PayloadDashboard:
    """Aggregates the corpus and its outcomes into one status view."""

    def __init__(self, indexer, tracker: OutcomeTracker) -> None:
        self._indexer = indexer
        self._tracker = tracker

    # ------------------------------------------------------------------

    def _outcomes(self) -> list:
        outcomes = []
        for p in self._indexer.list_all():
            outcomes.extend(
                self._tracker.outcomes_for(p.payload_id))
        return outcomes

    def data(self) -> dict:
        payloads = self._indexer.list_all()
        now = datetime.now(timezone.utc)

        families = {p.family.value for p in payloads}
        sources = {p.attribution.original_source
                   for p in payloads if p.attribution}

        by_family: dict[str, dict] = {}
        for p in payloads:
            by_family.setdefault(p.family.value, {"count": 0,
                                                  "pct": 0.0})
            by_family[p.family.value]["count"] += 1
        total = len(payloads)
        for entry in by_family.values():
            entry["pct"] = (entry["count"] / total * 100.0
                            if total else 0.0)

        by_quality = {"expert": 0, "advanced": 0, "moderate": 0,
                      "simple": 0}
        by_complexity = {"fresh": 0, "recent": 0, "stable": 0}
        for p in payloads:
            if p.complexity in by_quality:
                by_quality[p.complexity] += 1
            if p.attribution is not None:
                ingested = p.attribution.ingested_at
                if ingested.tzinfo is None:
                    ingested = ingested.replace(
                        tzinfo=timezone.utc)
                days_old = (now - ingested).days
            else:
                days_old = RECENT_DAYS  # unattributed: unknown age
            by_complexity[_bucket(days_old)] += 1

        outcomes = self._outcomes()
        success = sum(1 for o in outcomes if o.success)
        success_rate = (success / len(outcomes)
                        if outcomes else 0.0)
        top_performer = {"payload_id": "", "success_rate": 0.0}
        per_payload: dict[str, list[bool]] = {}
        for o in outcomes:
            per_payload.setdefault(o.payload_id, []).append(o.success)
        ranked = sorted(per_payload.items(),
                        key=lambda item: (-sum(item[1]),
                                          -len(item[1]),
                                          item[0]))
        if ranked:
            payload_id, marks = ranked[0]
            top_performer = {"payload_id": payload_id,
                             "success_rate": sum(marks) / len(marks)}

        return {
            "payloads": total,
            "families": len(families),
            "sources": len(sources),
            "by_family": by_family,
            "by_quality": by_quality,
            "by_complexity": by_complexity,
            "learning": {
                "total_outcomes": len(outcomes),
                "success_rate": success_rate,
                "top_performer": top_performer,
            },
        }

    def render(self) -> str:
        data = self.data()
        lines = [
            "=== THE FORGE — Corpus Dashboard ===",
            f"Payloads: {data['payloads']} | Families: "
            f"{data['families']} | Sources: {data['sources']}",
            "",
            "-- By Family --",
        ]
        for family in sorted(data["by_family"]):
            entry = data["by_family"][family]
            lines.append(
                f"  {family}: {entry['count']} "
                f"({entry['pct']:.1f}%)")
        lines += ["", "-- By Quality --"]
        for tier in ("expert", "advanced", "moderate", "simple"):
            lines.append(f"  {tier}: {data['by_quality'][tier]}")
        lines += ["", "-- By Complexity (freshness) --"]
        for bucket in ("fresh", "recent", "stable"):
            lines.append(
                f"  {bucket}: {data['by_complexity'][bucket]}")
        learning = data["learning"]
        lines += [
            "",
            "-- Learning --",
            f"Outcomes: {learning['total_outcomes']} | "
            f"Success rate: {learning['success_rate'] * 100:.1f}%",
            f"Top performer: "
            f"{learning['top_performer']['payload_id'] or '-'} "
            f"({learning['top_performer']['success_rate'] * 100:.1f}%)",
        ]
        return "\n".join(lines)
