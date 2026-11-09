# src/webpent/integration/surface_dossier.py
"""Consolidated attack-surface dossier (integration layer).

Part of the Shannon→GOED protected integration (docs/integration/).
Architectural reference: Shannon's recon deliverable structure
(apps/worker/src/collectors/recon-collector.ts — typed
attack-surface artifacts: endpoints, authentication, authz candidates,
injection sources, role architecture; AGPL-3.0) — **pattern only, no
code copied**. The implementation is original GOED Python that
*consolidates GOED's own runtime surface signals* into one
evidence-referenced dossier the research agenda can consume.

Purpose (capability matrix A2, protocol §13):

* One deterministic artifact unifying GOED's existing surface
  observations: crawled endpoints, authentication posture,
  authorization candidates, injection-source signals.
* Every item carries an ``evidence_ref`` pointing at GOED canonical
  evidence / observations — the dossier NEVER fabricates surface
  facts and NEVER returns findings (surface data ≠ vulnerability; see
  GOED's own surface-security contract in v29).
* ``from_state`` reads GOED state dicts defensively: missing keys are
  fine, malformed entries are skipped (counted), and no exception ever
  leaks target data.

Security contract:

* The dossier is advisory input for research planning only.
* No verdict authority; no ground truth; no credentials or secrets are
  stored (values are not copied — only structural facts).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

DOSSIER_SCHEMA_VERSION = "integration-surface-dossier-1.0"


class EndpointRecord(BaseModel):
    """A discovered runtime endpoint (structural facts only)."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    path: str = Field(min_length=1, max_length=400)
    http_method: str = Field(min_length=1, max_length=10)
    auth_required: bool = False
    evidence_ref: str = Field(min_length=1, max_length=160)
    note: str = Field(default="", max_length=240)

    @model_validator(mode="after")
    def _sane(self) -> EndpointRecord:
        if not self.http_method.upper().isalpha():
            raise ValueError("http_method_must_be_alpha")
        return self

    @property
    def method(self) -> str:
        return self.http_method.upper()


class AuthzCandidate(BaseModel):
    """A candidate authorization boundary worth researching (advisory)."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    endpoint_path: str = Field(min_length=1, max_length=400)
    role_ref: str = Field(min_length=1, max_length=120)
    expected_behavior: str = Field(min_length=1, max_length=240)
    evidence_ref: str = Field(min_length=1, max_length=160)


class InjectionSource(BaseModel):
    """An input vector worth researching (advisory, not a finding)."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    endpoint_path: str = Field(min_length=1, max_length=400)
    parameter: str = Field(min_length=1, max_length=120)
    kind: str = Field(min_length=1, max_length=60)  # e.g. "query", "body", "header"
    evidence_ref: str = Field(min_length=1, max_length=160)


class SurfaceDossier(BaseModel):
    """Deterministic consolidation of GOED runtime surface signals."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default=DOSSIER_SCHEMA_VERSION, min_length=1)
    endpoints: tuple[EndpointRecord, ...] = ()
    authz_candidates: tuple[AuthzCandidate, ...] = ()
    injection_sources: tuple[InjectionSource, ...] = ()
    auth_posture: str = Field(default="unknown", max_length=40)
    skipped_malformed: int = Field(default=0, ge=0)
    source: str = Field(default="goed_runtime_state", max_length=60)

    @model_validator(mode="after")
    def _no_duplicate_endpoints(self) -> SurfaceDossier:
        seen: set[tuple[str, str]] = set()
        for ep in self.endpoints:
            key = (ep.method, ep.path)
            if key in seen:
                raise ValueError("duplicate_endpoint_record")
            seen.add(key)
        return self

    def to_audit_dict(self) -> dict[str, Any]:
        """JSON-safe audit view (counts + refs, no target payloads)."""
        return {
            "schema_version": self.schema_version,
            "endpoint_count": len(self.endpoints),
            "authz_candidate_count": len(self.authz_candidates),
            "injection_source_count": len(self.injection_sources),
            "auth_posture": self.auth_posture,
            "skipped_malformed": self.skipped_malformed,
            "evidence_refs": sorted(
                {ep.evidence_ref for ep in self.endpoints}
                | {c.evidence_ref for c in self.authz_candidates}
                | {s.evidence_ref for s in self.injection_sources}
            ),
        }


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else ""


def build_surface_dossier(state: dict[str, Any]) -> SurfaceDossier:
    """Build a dossier from a GOED ``PentestState``-shaped dict.

    Reads (all optional, all read-only):

    * ``crawled_data`` / ``endpoints``: endpoint-ish dicts with
      ``path``/``url`` + optional ``method`` keys.
    * ``authorization_matrix`` / ``authz_candidates``: candidate rows.
    * ``injection_sources`` / ``input_vectors``: parameter signals.
    * ``auth_state`` / ``authentication``: posture summary string.

    Malformed entries are skipped and counted (never raise on target
    data); the result is a pure consolidation with required evidence
    refs defaulted to ``observation:<n>`` when the source row carries
    no explicit ref.
    """
    endpoints: list[EndpointRecord] = []
    authz: list[AuthzCandidate] = []
    injections: list[InjectionSource] = []
    skipped = 0
    counter = {"n": 0}

    def _ref(row: dict[str, Any]) -> str:
        explicit = row.get("evidence_ref") or row.get("evidence") or row.get("observation_id")
        if isinstance(explicit, str) and explicit.strip():
            return explicit.strip()[:160]
        counter["n"] += 1
        return f"observation:{counter['n']}"

    raw_endpoints: list[Any] = []
    for key in ("endpoints", "crawled_data"):
        value = state.get(key)
        if isinstance(value, list):
            raw_endpoints.extend(value)
    for row in raw_endpoints:
        if not isinstance(row, dict):
            skipped += 1
            continue
        path = _as_str(row.get("path")) or _as_str(row.get("url"))
        method = _as_str(row.get("method")) or "GET"
        if not path:
            skipped += 1
            continue
        try:
            endpoints.append(
                EndpointRecord(
                    path=path[:400],
                    http_method=method[:10],
                    auth_required=bool(row.get("auth_required", False)),
                    evidence_ref=_ref(row),
                    note=_as_str(row.get("note"))[:240],
                )
            )
        except Exception:
            skipped += 1

    raw_authz: list[Any] = []
    for key in ("authz_candidates", "authorization_matrix"):
        value = state.get(key)
        if isinstance(value, list):
            raw_authz.extend(value)
    for row in raw_authz:
        if not isinstance(row, dict):
            skipped += 1
            continue
        path = _as_str(row.get("endpoint_path")) or _as_str(row.get("path"))
        role = _as_str(row.get("role_ref")) or _as_str(row.get("role"))
        expected = _as_str(row.get("expected_behavior")) or _as_str(row.get("expected"))
        if not path or not role or not expected:
            skipped += 1
            continue
        try:
            authz.append(
                AuthzCandidate(
                    endpoint_path=path[:400],
                    role_ref=role[:120],
                    expected_behavior=expected[:240],
                    evidence_ref=_ref(row),
                )
            )
        except Exception:
            skipped += 1

    raw_injections: list[Any] = []
    for key in ("injection_sources", "input_vectors"):
        value = state.get(key)
        if isinstance(value, list):
            raw_injections.extend(value)
    for row in raw_injections:
        if not isinstance(row, dict):
            skipped += 1
            continue
        path = _as_str(row.get("endpoint_path")) or _as_str(row.get("path"))
        param = (
            _as_str(row.get("parameter"))
            or _as_str(row.get("param"))
            or _as_str(row.get("name"))
        )
        kind = _as_str(row.get("kind")) or "unknown"
        if not path or not param:
            skipped += 1
            continue
        try:
            injections.append(
                InjectionSource(
                    endpoint_path=path[:400],
                    parameter=param[:120],
                    kind=kind[:60],
                    evidence_ref=_ref(row),
                )
            )
        except Exception:
            skipped += 1

    auth_posture = "unknown"
    for key in ("auth_state", "authentication"):
        value = state.get(key)
        if isinstance(value, dict):
            posture = value.get("posture") or value.get("status")
            if isinstance(posture, str) and posture.strip():
                auth_posture = posture.strip()[:40]
                break
        elif isinstance(value, str) and value.strip():
            auth_posture = value.strip()[:40]
            break

    return SurfaceDossier(
        endpoints=tuple(sorted(endpoints, key=lambda e: (e.method, e.path))),
        authz_candidates=tuple(sorted(authz, key=lambda c: (c.endpoint_path, c.role_ref))),
        injection_sources=tuple(sorted(injections, key=lambda s: (s.endpoint_path, s.parameter))),
        auth_posture=auth_posture,
        skipped_malformed=skipped,
    )


__all__ = [
    "DOSSIER_SCHEMA_VERSION",
    "AuthzCandidate",
    "EndpointRecord",
    "InjectionSource",
    "SurfaceDossier",
    "build_surface_dossier",
]
