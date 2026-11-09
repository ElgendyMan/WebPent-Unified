# src/webpent/integration/reconciliation.py
"""Deterministic multi-stage observation reconciliation (integration layer).

Part of the Shannon→GOED protected integration (docs/integration/).
Architectural reference: Shannon's staged reconciliation
(apps/worker/src/ai/reconciliation/{prepare,enrich,form,materialize}.ts
— per-field re-validation, internal-provenance scrubbing before
downstream agents see data, stable task references, idempotent
publication; AGPL-3.0) — **pattern only, no code copied**. The Python
implementation below is original GOED work.

Purpose (capability matrix A9):

* ``prepare``  — validate producer observations field-by-field and
  scrub internal-only keys (ground-truth labels, hidden oracles,
  internal bookkeeping) so downstream research never sees them
  (protocol §22: Evaluator ≠ Executor).
* ``form``     — group observations into research tasks by typed
  identity (kind + endpoint + parameter + role); duplicates collapse.
* ``materialize`` — mint stable, idempotent task references
  (``REC-###`` derived from content hashes) for the research agenda /
  exploitation queue.

The result is *tasks*, never findings and never verdicts — CausalGuard
remains the sole verdict authority (protocol §8).
"""

from __future__ import annotations

import hashlib
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

RECONCILIATION_SCHEMA_VERSION = "integration-reconciliation-1.0"

# Keys scrubbed before downstream research consumption (protocol §22).
FORBIDDEN_INTERNAL_KEYS: frozenset[str] = frozenset(
    {
        "ground_truth",
        "ground_truth_id",
        "hidden_oracle",
        "expected_finding",
        "benchmark_label",
        "truth_label",
        "is_true_positive",
        "is_false_positive",
        "_sastid",
        "_internal_id",
        "producer_internal_id",
        "verdict",
        "confirmed",
    }
)

OBSERVATION_ID_PREFIX = "obs-"
E_NO_PRODUCER = "producer_id_missing"
E_BAD_PRODUCER = "producer_id_namespace_violation"
E_NO_KIND = "observation_kind_missing"
E_NO_PAYLOAD = "observation_payload_empty"


class Observation(BaseModel):
    """One producer observation admitted into reconciliation.

    ``producer_id`` must be namespaced (``<producer>-<id>``) so distinct
    producers cannot collide. ``payload`` holds redacted structural
    facts only (endpoint, parameter, kind...); secrets must already
    have been redacted upstream — this layer additionally scrubs
    forbidden internal keys as defense in depth.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    producer_id: str = Field(min_length=3, max_length=80)
    kind: str = Field(min_length=1, max_length=60)
    endpoint_path: str = Field(default="", max_length=400)
    parameter: str = Field(default="", max_length=120)
    role: str = Field(default="", max_length=40)
    payload: dict[str, Any]
    source_refs: tuple[str, ...] = Field(default=())

    @model_validator(mode="after")
    def _sane(self) -> Observation:
        if "-" not in self.producer_id:
            raise ValueError(E_BAD_PRODUCER)
        if not self.payload:
            raise ValueError(E_NO_PAYLOAD)
        return self

    @property
    def observation_id(self) -> str:
        """Stable content id for dedup (deterministic)."""
        canonical = repr(
            (
                self.producer_id,
                self.kind,
                self.endpoint_path,
                self.parameter,
                self.role,
                sorted(
                    (k, repr(v))
                    for k, v in self.payload.items()
                    if k not in FORBIDDEN_INTERNAL_KEYS
                ),
            )
        )
        return OBSERVATION_ID_PREFIX + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    def identity_key(self) -> tuple[str, str, str, str]:
        """Typed identity for task formation (deterministic grouping)."""
        return (self.kind, self.endpoint_path, self.parameter, self.role)


class ResearchTask(BaseModel):
    """A materialized reconciliation task (stable, idempotent ref)."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)

    task_ref: str = Field(min_length=5, max_length=40)
    kind: str = Field(min_length=1, max_length=60)
    endpoint_path: str = Field(default="", max_length=400)
    parameter: str = Field(default="", max_length=120)
    role: str = Field(default="", max_length=40)
    observation_ids: tuple[str, ...] = Field(min_length=1)
    producer_ids: tuple[str, ...] = Field(min_length=1)
    evidence_candidate_refs: tuple[str, ...] = Field(default=())

    def suggested_hypothesis_id(self) -> str:
        """Deterministic hypothesis-id suggestion for the agenda layer."""
        return "hyp-" + self.task_ref.split("-")[-1]


class ReconciliationResult(BaseModel):
    """Full, auditable result of one reconciliation run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = Field(default=RECONCILIATION_SCHEMA_VERSION, min_length=1)
    prepared: tuple[Observation, ...]
    scrubbed_keys: tuple[str, ...] = ()
    rejected: tuple[str, ...] = ()
    tasks: tuple[ResearchTask, ...]
    duplicate_observations_collapsed: int = Field(default=0, ge=0)


def _scrub_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Remove forbidden internal keys (defense in depth, deterministic)."""
    scrubbed: list[str] = []
    clean: dict[str, Any] = {}
    for key in sorted(payload.keys()):
        if key in FORBIDDEN_INTERNAL_KEYS:
            scrubbed.append(key)
            continue
        clean[key] = payload[key]
    return clean, tuple(scrubbed)


def _validate_observation_row(row: dict[str, Any]) -> tuple[Observation, tuple[str, ...]]:
    """Field-by-field validation (fail-closed on structural gaps)."""
    producer = row.get("producer_id")
    if not isinstance(producer, str) or not producer.strip():
        raise ValueError(E_NO_PRODUCER)
    kind = row.get("kind")
    if not isinstance(kind, str) or not kind.strip():
        raise ValueError(E_NO_KIND)
    payload = row.get("payload")
    if not isinstance(payload, dict) or not payload:
        raise ValueError(E_NO_PAYLOAD)
    clean_payload, scrubbed = _scrub_payload(payload)
    refs = row.get("source_refs")
    ref_tuple = (
        tuple(r.strip() for r in refs if isinstance(r, str) and r.strip())
        if isinstance(refs, list)
        else ()
    )
    return Observation(
        producer_id=producer.strip()[:80],
        kind=kind.strip()[:60],
        endpoint_path=str(row.get("endpoint_path", ""))[:400].strip(),
        parameter=str(row.get("parameter", ""))[:120].strip(),
        role=str(row.get("role", ""))[:40].strip(),
        payload=clean_payload,
        source_refs=ref_tuple,
    ), scrubbed


def reconcile(rows: list[dict[str, Any]]) -> ReconciliationResult:
    """Run prepare → form → materialize deterministically.

    Pure function: the same input list always yields the same result,
    including stable task refs (content-derived) — idempotent by
    construction (same inputs re-run → identical refs, no drift).
    """
    prepared: list[Observation] = []
    rejected: list[str] = []
    scrubbed_keys: list[str] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            rejected.append(f"row[{index}]:not_a_dict")
            continue
        try:
            obs, scrubbed = _validate_observation_row(row)
        except ValueError as exc:
            rejected.append(f"row[{index}]:{exc}")
            continue
        scrubbed_keys.extend(scrubbed)
        prepared.append(obs)

    # ---- form: group by typed identity, collapse duplicate content ----
    groups: dict[tuple[str, str, str, str], list[Observation]] = {}
    seen_obs_ids: set[str] = set()
    duplicates = 0
    for obs in prepared:
        oid = obs.observation_id
        if oid in seen_obs_ids:
            duplicates += 1
            continue
        seen_obs_ids.add(oid)
        groups.setdefault(obs.identity_key(), []).append(obs)

    # ---- materialize: stable content-derived refs (REC-<hash>) ----
    tasks: list[ResearchTask] = []
    for key in sorted(groups.keys()):
        members = groups[key]
        ids = tuple(sorted({m.observation_id for m in members}))
        producers = tuple(sorted({m.producer_id for m in members}))
        refs = tuple(
            sorted({r for m in members for r in m.source_refs})
        )
        hash_payload = "|".join(
            [RECONCILIATION_SCHEMA_VERSION, *key, *ids]
        )
        task_ref = "REC-" + hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()[:10].upper()
        tasks.append(
            ResearchTask(
                task_ref=task_ref,
                kind=key[0],
                endpoint_path=key[1],
                parameter=key[2],
                role=key[3],
                observation_ids=ids,
                producer_ids=producers,
                evidence_candidate_refs=refs,
            )
        )

    return ReconciliationResult(
        prepared=tuple(prepared),
        scrubbed_keys=tuple(sorted(set(scrubbed_keys))),
        rejected=tuple(rejected),
        tasks=tuple(sorted(tasks, key=lambda t: t.task_ref)),
        duplicate_observations_collapsed=duplicates,
    )


__all__ = [
    "FORBIDDEN_INTERNAL_KEYS",
    "OBSERVATION_ID_PREFIX",
    "RECONCILIATION_SCHEMA_VERSION",
    "Observation",
    "ReconciliationResult",
    "ResearchTask",
    "reconcile",
]
