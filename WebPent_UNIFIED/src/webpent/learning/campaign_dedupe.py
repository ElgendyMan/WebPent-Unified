# src/webpent/learning/campaign_dedupe.py
"""Cross-campaign dedupe (PROPOSALS_ULTIMATE_V2 §11, 2026-10-31).

A shared inventory of findings across campaigns plus a weighted-Jaccard
similarity check: a new finding that looks like something already in the
inventory is flagged ``possible_duplicate`` in the report — NOT dropped,
NOT hidden. The duplicate stays fully visible with its match attached;
only the operator (and the report reader) learn that campaign 7 may be
re-reporting campaign 2. Dedupe NEVER deletes, merges or downgrades a
finding.

Pure text similarity — no external embeddings, no network: the tokens
are the vuln class (weighted 3, the strongest identity signal) and the
endpoint's path segments and parameter names (weighted 1 each).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "DEFAULT_THRESHOLD",
    "CLASS_TOKEN_WEIGHT",
    "InventoryError",
    "tokenize",
    "weighted_jaccard",
    "CrossCampaignRegistry",
    "load_inventory",
    "save_inventory",
    "annotate_finding",
]

DEFAULT_THRESHOLD = 0.8
CLASS_TOKEN_WEIGHT = 3


class InventoryError(ValueError):
    """Raised when inventory load/save cannot proceed fail-closed."""


def tokenize(vuln_class: str, endpoint: str) -> dict[str, int]:
    """Token -> weight map for one finding.

    The vuln-class token carries weight CLASS_TOKEN_WEIGHT; each path
    segment and each query-parameter NAME carries weight 1. Values and
    raw payload text are excluded on purpose: they change per payload,
    they are not what makes two findings the same bug.
    """
    tokens: dict[str, int] = {}
    cls = str(vuln_class or "").strip().lower()
    if cls:
        tokens[cls] = tokens.get(cls, 0) + CLASS_TOKEN_WEIGHT
    path = str(endpoint or "")
    if "?" in path:
        path, _, query = path.partition("?")
        for pair in query.split("&"):
            name = pair.split("=", 1)[0].strip().lower()
            if name:
                tokens[name] = tokens.get(name, 0) + 1
    for segment in path.lower().split("/"):
        segment = segment.strip()
        if segment:
            tokens[segment] = tokens.get(segment, 0) + 1
    return tokens


def weighted_jaccard(a: dict[str, int], b: dict[str, int]) -> float:
    """Weighted Jaccard in [0, 1] over two token->weight maps."""
    if not a and not b:
        return 0.0
    keys = set(a) | set(b)
    intersection = sum(min(a.get(k, 0), b.get(k, 0)) for k in keys)
    union = sum(max(a.get(k, 0), b.get(k, 0)) for k in keys)
    if union == 0:
        return 0.0
    return intersection / union


@dataclass
class CrossCampaignRegistry:
    """The shared inventory: every finding from every past campaign."""

    findings: list[dict[str, Any]] = field(default_factory=list)

    def register(
        self,
        vuln_class: str,
        endpoint: str,
        campaign_id: str = "",
        detail: str = "",
    ) -> dict[str, Any]:
        record = {
            "vuln_class": str(vuln_class),
            "endpoint": str(endpoint),
            "campaign_id": str(campaign_id),
            "detail": str(detail),
        }
        self.findings.append(record)
        return record

    def check(
        self,
        vuln_class: str,
        endpoint: str,
        threshold: float = DEFAULT_THRESHOLD,
    ) -> dict[str, Any]:
        """Similarity check against the inventory (the new finding is NOT
        auto-registered — the caller registers it when it accepts it)."""
        tokens = tokenize(vuln_class, endpoint)
        best: dict[str, Any] | None = None
        best_score = 0.0
        for record in self.findings:
            score = weighted_jaccard(
                tokens, tokenize(record.get("vuln_class", ""), record.get("endpoint", ""))
            )
            if score > best_score:
                best_score = score
                best = record
        possible = best is not None and best_score >= threshold
        return {
            "possible_duplicate": possible,
            "similarity": round(best_score, 4),
            "threshold": threshold,
            "best_match": (
                {"vuln_class": best["vuln_class"], "endpoint": best["endpoint"],
                 "campaign_id": best["campaign_id"]}
                if possible and best is not None
                else None
            ),
        }


def load_inventory(path: str | Path) -> CrossCampaignRegistry:
    """Load a saved inventory; fail-closed on any structural problem."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise InventoryError(f"inventory_unreadable: {exc}") from exc
    try:
        doc = json.loads(data.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise InventoryError(f"inventory_invalid_encoding: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InventoryError(f"inventory_invalid_json: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("findings"), list):
        raise InventoryError("inventory_schema: expected {'findings': [...]}")
    for record in doc["findings"]:
        if not isinstance(record, dict):
            raise InventoryError("inventory_schema: findings must be objects")
    return CrossCampaignRegistry(findings=doc["findings"])


def save_inventory(
    path: str | Path, registry: CrossCampaignRegistry, *, write_enabled: bool
) -> None:
    """Persist the inventory (JSON, indent=2); the flag gates the write."""
    if not write_enabled:
        raise InventoryError("inventory_write_disabled")
    doc = {"findings": registry.findings}
    Path(path).write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")


def annotate_finding(
    finding: dict[str, Any],
    registry: CrossCampaignRegistry,
    threshold: float = DEFAULT_THRESHOLD,
) -> dict[str, Any]:
    """Attach a ``possible_duplicate`` marker when one is warranted.

    The finding is returned UNCHANGED when it is clean: dedupe adds a
    flag, it never removes, merges or downgrades anything.
    """
    verdict = registry.check(
        finding.get("vuln_class", ""), finding.get("endpoint", ""), threshold
    )
    if verdict["possible_duplicate"]:
        finding["possible_duplicate"] = {
            "similarity": verdict["similarity"],
            "threshold": verdict["threshold"],
            "best_match": verdict["best_match"],
        }
    return finding
