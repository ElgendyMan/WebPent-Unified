"""Economist — the blind spot locator (NC-ECON-1, U-ECON-9) ⭐⭐.

Finds where the public hunters are NOT looking, cross-referencing two
local sources (L-2: no network, ever):

    1. all public findings on the target (from the CompetitiveRadar DB)
    2. all scope entries (paths/subdomains from CEM's snapshots, via a
       ScopeAnalysis produced by the scope negotiator)

The charter algorithm, verbatim (L-3: deterministic):

    1. take all public findings on the target
    2. extract endpoint signatures (path patterns, not full URLs):
       a signature collapses to its first two path segments, e.g.
       ``/api/v2/users/{id}`` -> region ``/api/v2/*``
    3. extract vuln classes
    4. take all scope entries
    5. cross-reference:
       * scope paths whose region has no public finding = candidate
         ``path_region`` blind spots (grouped, e.g. ``/api/v1/*``);
       * subdomains with no public finding = ``subdomain`` spots;
       * watched vuln classes with no public finding on the program =
         ``vuln_class`` spots
    6. rank by estimated_ev:
       * path regions: ``region_ev_base_usd`` x uncovered entries
       * vuln classes: ``class_ev_base_usd`` x severity weight of the
         class family (severity x non-coverage)
       * subdomains: ``region_ev_base_usd`` (one entry each)

Ranking ties break by kind (path_region < vuln_class < subdomain),
then identifier, so the output order is a pure function of the inputs.
Confidence grows with observed data volume: gaps inferred from ten
findings are worth more than gaps inferred from one
(``min_data_volume_for_high_confidence`` in competition_params.yaml).

Advisory only (L-1); output is structured and ranked (DoD).
"""

from __future__ import annotations

import contextlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webpent.econ.competitive import CompetitiveRadar
from webpent.econ.market_kb import Target
from webpent.econ.scope_negotiator import ScopeAnalysis

_LOG = logging.getLogger(__name__)

#: family severity weights for vuln_class ranking (severity x coverage gap)
CLASS_SEVERITY_WEIGHT: dict[str, float] = {
    "RCE": 1.5,
    "SQLI": 1.4,
    "AUTH_BYPASS": 1.3,
    "SSRF": 1.2,
    "IDOR": 1.2,
    "ACCESS_CONTROL": 1.1,
    "XSS": 0.8,
    "INFO_DISCLOSURE": 0.6,
}

KIND_ORDER = {"path_region": 0, "vuln_class": 1, "subdomain": 2}


def load_blind_spot_params(path: Any) -> dict[str, float]:
    """Load the blind_spots block of competition_params.yaml; fail-soft."""
    config: dict[str, float] = {
        "min_data_volume_for_high_confidence": 10.0,
        "region_ev_base_usd": 400.0,
        "class_ev_base_usd": 800.0,
    }
    if path is None:
        return config
    try:
        import yaml

        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return config
    except Exception as exc:
        _LOG.warning("blind spot params unreadable; using defaults: %s", exc)
        return config
    if not isinstance(raw, dict):
        return config
    bs = raw.get("blind_spots") if isinstance(raw.get("blind_spots"), dict) else raw
    for key in list(config):
        if bs.get(key) is None:
            continue
        with contextlib.suppress(TypeError, ValueError):
            config[key] = max(0.0, float(bs[key]))
    return config


def region_of(signature: str) -> str:
    """Collapse one endpoint signature to a two-segment region pattern."""
    path = str(signature or "").split("?")[0].split("#")[0]
    if not path.startswith("/"):
        return ""
    parts = [p for p in path.split("/") if p][:2]
    if not parts:
        return "/"
    return "/" + "/".join(parts) + "/*"


@dataclass
class BlindSpot:
    """One uncovered area, with its reason and rough value (L-4)."""

    kind: str  # "path_region" | "vuln_class" | "subdomain"
    identifier: str
    reasoning: str
    estimated_ev: float
    confidence: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "identifier": self.identifier,
            "reasoning": self.reasoning,
            "estimated_ev": round(self.estimated_ev, 2),
            "confidence": round(self.confidence, 3),
            "timestamp": self.timestamp.isoformat(),
            "advisory": True,
        }


class BlindSpotLocator:
    """Deterministic cross-reference of scope vs public coverage."""

    def __init__(self, *, params_path: Any = None) -> None:
        self.params = load_blind_spot_params(params_path)
        self._params_file = params_path

    def locate(
        self,
        target: Target,
        radar: CompetitiveRadar,
        scope: ScopeAnalysis,
        *,
        now: datetime | None = None,
    ) -> list[BlindSpot]:
        target = target.sanitized() if isinstance(target, Target) else Target(
            str(target or ""), ""
        ).sanitized()
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        # 1-3: public findings on the target -> covered regions and classes
        findings = radar.get_findings(
            target.program_id, datetime.fromtimestamp(0, tz=timezone.utc)
        )
        covered_regions = set()
        seen_classes = set()
        for f in findings:
            with contextlib.suppress(ValueError, TypeError):
                region = region_of(f.endpoint_signature)
                if region:
                    covered_regions.add(region)
                if f.vuln_class:
                    seen_classes.add(f.vuln_class)

        # data volume drives confidence (DoD: confidence reflects data)
        volume_ref = max(
            1.0, float(self.params["min_data_volume_for_high_confidence"])
        )
        confidence = min(1.0, len(findings) / volume_ref)

        # 4: scope entries, split into paths and subdomains
        # R2-econ-05: the negotiator diverts path entries ("/api/v2/users")
        # to gray_zones (they authorize no host by themselves), so consume
        # gray-zone paths too; deduped against in_scope and bounded by
        # the same 256-entry cap.
        entries: list[str] = []
        seen_entries: set[str] = set()
        for entry in list(getattr(scope, "in_scope", None) or []):
            text = str(entry).strip()
            if text and text not in seen_entries:
                entries.append(text)
                seen_entries.add(text)
        for entry in list(getattr(scope, "gray_zones", None) or []):
            text = str(entry).strip()
            if text.startswith("/") and text not in seen_entries:
                entries.append(text)
                seen_entries.add(text)
        paths: list[str] = []
        subdomains: list[str] = []
        for entry in entries[:256]:
            entry = str(entry).strip()
            if entry.startswith("/"):
                paths.append(entry)
            elif entry and "." in entry:
                subdomains.append(entry)

        spots: list[BlindSpot] = []
        region_base = float(self.params["region_ev_base_usd"])

        # 5a: path regions with no public finding
        uncovered_counts: dict[str, int] = {}
        for path in paths:
            region = region_of(path)
            if region and region not in covered_regions:
                uncovered_counts[region] = uncovered_counts.get(region, 0) + 1
        for region, count in sorted(uncovered_counts.items()):
            spots.append(
                BlindSpot(
                    kind="path_region",
                    identifier=region,
                    reasoning=(
                        f"{len(findings)} public finding(s) cover "
                        f"{sorted(covered_regions) or ['nothing']} — {region} "
                        f"has {count} scope path(s) and no public finding"
                    ),
                    estimated_ev=region_base * count,
                    confidence=confidence,
                    timestamp=now,
                )
            )

        # 5b: subdomains with no public finding (their host, not path regions)
        for sub in sorted(set(subdomains)):
            spots.append(
                BlindSpot(
                    kind="subdomain",
                    identifier=sub,
                    reasoning=(
                        f"subdomain {sub} is in scope with no public finding "
                        "recorded against it"
                    ),
                    estimated_ev=region_base,
                    confidence=confidence,
                    timestamp=now,
                )
            )

        # 5c: watched vuln classes with no public finding on the program
        class_base = float(self.params["class_ev_base_usd"])
        from webpent.econ.competitive import load_competition_params

        watched = load_competition_params(self._params_file).get(
            "watched_classes", []
        )
        for vuln_class in watched:
            if vuln_class in seen_classes:
                continue
            weight = CLASS_SEVERITY_WEIGHT.get(vuln_class, 1.0)
            spots.append(
                BlindSpot(
                    kind="vuln_class",
                    identifier=vuln_class,
                    reasoning=(
                        f"no public {vuln_class} finding on {target.program_id}; "
                        f"family severity weight {weight:.1f}"
                    ),
                    estimated_ev=class_base * weight,
                    confidence=confidence,
                    timestamp=now,
                )
            )

        # 6: rank by estimated_ev desc, then kind, then identifier (L-3)
        spots.sort(key=lambda s: (-s.estimated_ev, KIND_ORDER.get(s.kind, 9), s.identifier))
        return spots


__all__ = [
    "CLASS_SEVERITY_WEIGHT",
    "BlindSpot",
    "BlindSpotLocator",
    "load_blind_spot_params",
    "region_of",
]
