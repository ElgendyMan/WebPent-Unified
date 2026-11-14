# src/webpent/integration/source_mapping.py
"""Source → runtime attack-path mapping (integration layer).

Part of the Shannon→GOED protected integration (docs/integration/).
Architectural reference: Shannon's code-location join
(apps/worker/src/services/code-location-join.ts and the
``analysisCodeLocationSchema`` in apps/worker/src/ai/queue-schemas.ts,
AGPL-3.0) — **pattern only, no code copied**. The implementation below
is original GOED Python designed around GOED's own evidence/hypothesis
contracts (protocol §7: small isolated adapter, stable interfaces).

Purpose (protocol §10 item 3, §13):

* Represent **where in the target's source** a sink/source/guard lives
  (``CodeLocation``) WITHOUT storing any source text (no target file
  content ever enters the runtime — locations only).
* Correlate source locations with runtime endpoints, hypotheses, and
  evidence refs (``SourceMappingRecord``) so candidate attack paths in
  the GOED attack graph can carry a source lane as *advisory
  annotation*.
* Provide a deterministic join for reports/attack-graph projections.

Security contract:

* Source information is *advisory* — it can create/annotate hypotheses
  and attack-path candidates; it can NEVER confirm anything.
  CausalGuard remains the sole verdict authority (protocol §8).
* No file contents, only paths + line ranges + symbol names.
* Paths must be repo-relative; absolute paths and traversal are
  rejected fail-closed.
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAPPING_SCHEMA_VERSION = "integration-source-mapping-1.0"


class SourceRole(str, Enum):
    """Role of a code location in a candidate attack path."""

    SINK = "sink"
    SOURCE = "source"
    GUARD = "guard"


class CodeLocation(BaseModel):
    """A bounded pointer into the target's source tree (no content)."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    file: str = Field(min_length=1, max_length=400)
    start_line: int = Field(ge=1, le=10_000_000)
    end_line: int = Field(ge=1, le=10_000_000)
    role: SourceRole
    symbol: str = Field(min_length=1, max_length=240)

    @model_validator(mode="after")
    def _sane_path_and_range(self) -> CodeLocation:
        path = self.file.replace("\\", "/")
        if path.startswith("/") or (len(path) > 1 and path[1] == ":"):
            raise ValueError("absolute_source_paths_forbidden")
        parts = [p for p in path.split("/") if p not in ("", ".")]
        if not parts or any(p == ".." for p in parts):
            raise ValueError("source_path_traversal_forbidden")
        if self.end_line < self.start_line:
            raise ValueError("end_line_must_be_gte_start_line")
        return self

    @property
    def normalized_file(self) -> str:
        return "/".join(p for p in self.file.replace("\\", "/").split("/") if p not in ("", "."))


class SourceMappingRecord(BaseModel):
    """One deterministic source↔runtime correlation (advisory).

    ``evidence_refs`` must reference GOED canonical evidence /
    observation artifacts. ``hypothesis_id`` references GOED's
    hypothesis namespace. A record with no hypothesis and no evidence
    is still allowed (pure source observation) but can never be
    promoted by downstream logic — it is annotation only.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    code_location: CodeLocation
    endpoint_path: str = Field(min_length=1, max_length=400)
    http_method: str = Field(default="", max_length=10)
    hypothesis_id: str = Field(default="", max_length=120)
    evidence_refs: tuple[str, ...] = Field(default=())
    note: str = Field(default="", max_length=240)

    @property
    def mapping_id(self) -> str:
        """Stable content-derived id (deterministic, reproducible)."""
        payload = "|".join(
            [
                MAPPING_SCHEMA_VERSION,
                self.code_location.normalized_file,
                str(self.code_location.start_line),
                str(self.code_location.end_line),
                self.code_location.role.value,
                self.code_location.symbol,
                self.endpoint_path,
                self.http_method.upper(),
                self.hypothesis_id,
            ]
        )
        return "smap-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


class JoinedMapping(BaseModel):
    """Deterministic join result for one endpoint (report/graph ready)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    endpoint_path: str
    http_method: str
    locations: tuple[CodeLocation, ...]
    hypothesis_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    mapping_ids: tuple[str, ...] = ()


def join_source_locations(
    records: list[SourceMappingRecord],
) -> list[JoinedMapping]:
    """Group mapping records by (endpoint, method) deterministically.

    Pure function: same input list → same output list. Output is
    ordered by (endpoint_path, http_method). Suitable for attaching a
    source lane onto GOED's attack-graph projections and reports as
    advisory annotations.
    """
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for rec in records:
        key = (rec.endpoint_path, rec.http_method.upper())
        bucket = grouped.setdefault(
            key,
            {"locations": [], "hypothesis_ids": [], "evidence_refs": [], "mapping_ids": []},
        )
        bucket["locations"].append(rec.code_location)
        if rec.mapping_id not in bucket["mapping_ids"]:
            bucket["mapping_ids"].append(rec.mapping_id)
        if rec.hypothesis_id and rec.hypothesis_id not in bucket["hypothesis_ids"]:
            bucket["hypothesis_ids"].append(rec.hypothesis_id)
        for ref in rec.evidence_refs:
            if ref and ref not in bucket["evidence_refs"]:
                bucket["evidence_refs"].append(ref)

    joined: list[JoinedMapping] = []
    for (endpoint, method) in sorted(grouped.keys()):
        bucket = grouped[(endpoint, method)]
        joined.append(
            JoinedMapping(
                endpoint_path=endpoint,
                http_method=method,
                locations=tuple(
                    sorted(
                        bucket["locations"],
                        key=lambda c: (
                            c.normalized_file,
                            c.start_line,
                            c.end_line,
                            c.role.value,
                        ),
                    )
                ),
                hypothesis_ids=tuple(bucket["hypothesis_ids"]),
                evidence_refs=tuple(bucket["evidence_refs"]),
                mapping_ids=tuple(bucket["mapping_ids"]),
            )
        )
    return joined


__all__ = [
    "MAPPING_SCHEMA_VERSION",
    "CodeLocation",
    "JoinedMapping",
    "SourceMappingRecord",
    "SourceRole",
    "join_source_locations",
]
