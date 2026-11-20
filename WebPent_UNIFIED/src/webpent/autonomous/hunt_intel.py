"""Cross-session per-target intelligence (v80, Task 1).

Advisory-only memory that survives sessions: what a target has *proven*
vulnerable before (proof-verified bundles only), plus redacted endpoint
hints. At the start of a new round the store turns that history into
hypothesis seeds, so the hunter stops starting from zero. The store never
creates findings, never claims coverage, and never stores secrets or
query values.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

MAX_ORIGINS = 64
MAX_ENDPOINTS_PER_ORIGIN = 32
MAX_CLASSES_PER_ORIGIN = 16
MAX_SEEDS = 8
SEED_PRIORITY_CAP = 0.75


def _normalize_url(value: object) -> str:
    """Origin + path only: no query, no fragment, no credentials."""
    text = redact(str(value or ""))
    parts = urlsplit(text)
    if not parts.scheme or not parts.netloc:
        return ""
    host = parts.netloc.rpartition("@")[2].lower()
    if not host:
        return ""
    path = parts.path.split("?", 1)[0].split("#", 1)[0]
    if len(path) > 256:
        path = path[:256]
    return f"{parts.scheme.lower()}://{host}{path}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class IntelStore:
    """Per-target-origin intelligence persisted to one JSON file.

    Only proof-verified facts enter the store. Corrupt or wrong-typed
    files are discarded (logged, never raised): a broken intel file must
    degrade to "no memory", never crash a hunt.
    """

    def __init__(self, persist_path: Path | str) -> None:
        self.path = Path(persist_path)
        self._origins: dict[str, dict[str, Any]] = {}
        self.load()

    # -- persistence -------------------------------------------------

    def load(self) -> None:
        self._origins = {}
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            _LOG.warning("intel file unreadable; starting with no memory: %s", self.path)
            return
        if not isinstance(raw, dict):
            _LOG.warning("intel file wrong type; starting with no memory: %s", self.path)
            return
        for origin, record in raw.items():
            if isinstance(origin, str) and isinstance(record, dict):
                self._origins[origin] = self._sanitize_record(record)
            if len(self._origins) >= MAX_ORIGINS:
                break

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._origins, indent=2, ensure_ascii=False)
        try:
            fd, tmp_name = tempfile.mkstemp(dir=str(self.path.parent))
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    handle.write(payload)
                os.replace(tmp_name, self.path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp_name)
                raise
        except OSError as exc:
            _LOG.warning("intel save failed (memory stays in-process): %s", exc)

    @staticmethod
    def _sanitize_record(record: dict[str, Any]) -> dict[str, Any]:
        classes = record.get("verified_classes")
        cleaned_classes: dict[str, int] = {}
        if isinstance(classes, dict):
            for key, value in list(classes.items())[:MAX_CLASSES_PER_ORIGIN]:
                if isinstance(key, str) and isinstance(value, int) and value > 0:
                    cleaned_classes[key] = value
        endpoints: list[str] = []
        raw_endpoints = record.get("endpoint_hints")
        if isinstance(raw_endpoints, list):
            for entry in raw_endpoints:
                normalized = _normalize_url(entry)
                if normalized and normalized not in endpoints:
                    endpoints.append(normalized)
                if len(endpoints) >= MAX_ENDPOINTS_PER_ORIGIN:
                    break
        updated = record.get("updated_at")
        return {
            "verified_classes": cleaned_classes,
            "endpoint_hints": endpoints,
            "updated_at": updated if isinstance(updated, str) else "",
        }

    # -- updating ----------------------------------------------------

    def update_from_state(self, state: Any) -> None:
        """Feed the store from proof-verified bundles only.

        Candidate findings, guidance and any other state content are
        ignored: only facts that survived re-run verification count as
        memory. A hunt with no bundles at all records nothing — an empty
        record would only pollute the bounded origin memory.
        """
        target = _normalize_url(getattr(state, "target_url", "") or "")
        if not target:
            return
        bundles = getattr(state, "proof_bundles", None)
        if not isinstance(bundles, list) or not bundles:
            return
        parts = urlsplit(target)
        origin = f"{parts.scheme}://{parts.netloc}"
        record = self._origins.setdefault(
            origin, {"verified_classes": {}, "endpoint_hints": [], "updated_at": ""}
        )
        for bundle in bundles:
            if not isinstance(bundle, dict):
                continue
            vuln_class = str(
                bundle.get("vuln_class") or bundle.get("class") or ""
            ).strip()
            if vuln_class:
                counts = record["verified_classes"]
                counts[vuln_class] = counts.get(vuln_class, 0) + 1
            endpoint = _normalize_url(bundle.get("url") or bundle.get("path") or "")
            # CR-4: hints are per-origin; a URL belonging to another
            # origin never enters this origin's record.
            if (
                endpoint
                and endpoint.startswith(f"{origin}/")
                and endpoint not in record["endpoint_hints"]
            ):
                record["endpoint_hints"].append(endpoint)
        record["verified_classes"] = dict(
            sorted(
                record["verified_classes"].items(), key=lambda item: -item[1]
            )[:MAX_CLASSES_PER_ORIGIN]
        )
        record["endpoint_hints"] = record["endpoint_hints"][:MAX_ENDPOINTS_PER_ORIGIN]
        record["updated_at"] = _now_iso()
        while len(self._origins) > MAX_ORIGINS:
            oldest = min(
                (o for o in self._origins if o != origin),
                key=lambda o: self._origins[o].get("updated_at", ""),
                default=None,
            )
            if oldest is None:
                break
            del self._origins[oldest]

    # -- reading -----------------------------------------------------

    def hypothesis_seeds(self, target_url: str, cap: int = MAX_SEEDS) -> list[dict[str, Any]]:
        """Advisory seeds for a target, strongest proven classes first."""
        target = _normalize_url(target_url or "")
        if not target:
            return []
        parts = urlsplit(target)
        origin = f"{parts.scheme}://{parts.netloc}"
        record = self._origins.get(origin)
        if not record:
            return []
        seeds: list[dict[str, Any]] = []
        classes = record.get("verified_classes") or {}
        for vuln_class, count in sorted(classes.items(), key=lambda item: -item[1]):
            if len(seeds) >= cap:
                break
            priority = min(SEED_PRIORITY_CAP, 0.5 + min(count, 5) * 0.05)
            seeds.append(
                {
                    "vuln_class": vuln_class,
                    "priority": priority,
                    "rationale": (
                        f"previously verified on this target ({count}x); "
                        "memory-driven re-check, advisory only"
                    ),
                    "source": "intel",
                    "advisory": True,
                }
            )
        return seeds

    def origins(self) -> list[str]:
        return sorted(self._origins)

    def record_for(self, target_url: str) -> dict[str, Any] | None:
        target = _normalize_url(target_url or "")
        parts = urlsplit(target)
        if not parts.scheme or not parts.netloc:
            return None
        return self._origins.get(f"{parts.scheme}://{parts.netloc}")
