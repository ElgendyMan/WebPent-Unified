# src/webpent/shared/epss.py
"""webpent.shared.epss — EPSS prioritization (Track 10.6 / 11.4, 0.26.0).

Roadmap contract (المسار 11، البند 4 — بصمة تقنية وترتيب أولويات):

    ربط المكونات المعلنة بمصادر CVE/EPSS كمؤشرات إرشادية، مع تحقق قبل
    إنشاء finding.

    ("Link declared components to CVE/EPSS sources as ADVISORY
    indicators, with verification before any finding is created.")

Until 0.25.0 the CVE/KEV half of that contract existed
(``shared/tech_stack_cve.py`` + ``shared/kev.py``) but EPSS was absent
entirely (zero hits in src/ and tests/). This module closes the gap
with the EXACT injected-catalog posture the repo already uses for CVE
feeds and KEV ids:

* **No network, ever.** The EPSS catalog is operator-supplied (a local
  JSON file the operator refreshes on their own cadence, or state
  carried in the campaign). The module never fetches anything — it
  mirrors ``kev.py``'s "injected catalog" contract and
  ``tech_stack_cve.py``'s feed posture.
* **Aggregates only.** An EPSS record is (cve_id, score, percentile).
  No target data, no finding data.
* **Advisory only.** An EPSS score reorders correlated CVEs for the
  operator's triage queue; it never creates, upgrades, or confirms a
  finding (``tech_stack_cve.CveCorrelation`` is already
  ``advisory_only``/``does_not_confirm`` — enrichment preserves that).

File format (operator-supplied JSON list)::

    [
      {"cve_id": "CVE-2024-1234", "epss": 0.94, "percentile": 0.99},
      ...
    ]

Fail-soft everywhere: a malformed file decodes to an empty catalog and
enrichment degrades to the pre-EPSS behavior.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

__all__ = [
    "EpssRecord",
    "load_epss_catalog",
    "build_epss_index",
    "enrich_correlations_with_epss",
    "epss_aware_sort_key",
]


@dataclass(frozen=True)
class EpssRecord:
    """One aggregate EPSS score — no target or finding data by design."""

    cve_id: str
    epss: float
    percentile: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "epss": round(self.epss, 6),
            "percentile": (
                round(self.percentile, 6) if self.percentile is not None else None
            ),
            "source": "operator-injected",
            "advisory_only": True,
        }


def _normalize_cve_id(value: Any) -> str:
    return str(value or "").strip().upper()


def _clamp01(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return min(1.0, max(0.0, number))


def load_epss_catalog(
    state_value: Any, *, settings_attr: str = "epss_catalog_path"
) -> list[EpssRecord]:
    """Resolve the EPSS catalog: campaign state first, then operator file.

    Mirrors ``operator_catalogs.load_kev_catalog``: a non-empty list in
    ``state_value`` wins; otherwise the JSON file named by the settings
    attribute is loaded. Fail-soft to [] exactly like the pre-EPSS
    no-catalog behavior.
    """
    if isinstance(state_value, list) and state_value:
        return _records_from(state_value)
    path_value = ""
    try:
        from webpent.config.settings import get_settings

        path_value = str(getattr(get_settings(), settings_attr, "") or "")
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
        path_value = ""
    if not path_value:
        return []
    try:
        data = json.loads(Path(path_value).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.debug("epss catalog unreadable at %s — treating as empty", path_value)
        return []
    return _records_from(data if isinstance(data, list) else [])


def _records_from(entries: Iterable[Any]) -> list[EpssRecord]:
    records: list[EpssRecord] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        cve_id = _normalize_cve_id(entry.get("cve_id") or entry.get("id") or entry.get("cve"))
        if not cve_id or cve_id in seen:
            continue
        score = _clamp01(entry.get("epss") if "epss" in entry else entry.get("score"))
        if score is None:
            continue  # a record without a usable score is not a record
        percentile = _clamp01(entry.get("percentile"))
        seen.add(cve_id)
        records.append(EpssRecord(cve_id=cve_id, epss=score, percentile=percentile))
    return records


def build_epss_index(records: Iterable[Any]) -> dict[str, EpssRecord]:
    """cve_id -> record index (case-normalized, first wins).

    Accepts :class:`EpssRecord` instances OR plain mappings with the
    same keys (liberal like ``tech_stack_cve.correlate_cves``'s feed
    handling); unusable entries are skipped silently.
    """
    index: dict[str, EpssRecord] = {}
    for record in records:
        if isinstance(record, EpssRecord):
            index.setdefault(record.cve_id, record)
            continue
        if isinstance(record, Mapping):
            converted = _records_from([record])
            if converted:
                index.setdefault(converted[0].cve_id, converted[0])
    return index


def enrich_correlations_with_epss(
    correlations: list[Any],
    epss_index: Mapping[str, EpssRecord],
) -> list[Any]:
    """Attach EPSS scores to CVE correlations (pure; never mutates input).

    Works on ``tech_stack_cve.CveCorrelation`` objects: returns NEW
    correlation objects with the ``epss`` field set where the catalog
    knows the CVE. Unknown CVEs keep ``epss=None`` and unchanged order.
    Advisory posture is inherited from the correlation itself.
    """
    enriched: list[Any] = []
    for correlation in correlations:
        record = epss_index.get(_normalize_cve_id(getattr(correlation, "cve_id", "")))
        if record is None:
            enriched.append(correlation)
            continue
        try:
            updated = correlation.model_copy(update={"epss": record.epss})
        except AttributeError:
            # Non-pydantic duck-typed correlation: shallow-copy defensively.
            updated = correlation
            try:
                object.__setattr__(updated, "epss", record.epss)
            except (AttributeError, TypeError):
                updated = correlation
        enriched.append(updated)
    return enriched


def epss_aware_sort_key(correlation: Any) -> tuple:
    """Sort key: KEV first, then EPSS desc, then fingerprint confidence desc.

    With ``epss=None`` everywhere this is EXACTLY the pre-EPSS ordering
    (``not kev, -confidence``), so enabling the module cannot reshuffle
    an empty-catalog deployment.
    """
    epss = getattr(correlation, "epss", None) or 0.0
    return (
        not bool(getattr(correlation, "kev", False)),
        -float(epss),
        -float(getattr(correlation, "fingerprint_confidence", 0.0) or 0.0),
    )
