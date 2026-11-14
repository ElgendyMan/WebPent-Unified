"""TEAM-1 — CampaignState: durable, versioned research state for process-restart continuity.

Persists: ResearchAgenda, outcomes, decisions, memory references, WorldModel
digest, finding lifecycle states, campaign budget. Loads after process restart.
Explicit versioning — unknown/incompatible versions fail safely (no silent
reinterpretation of old state).

This is NOT a substitute for trusted execution evidence. It is advisory
research state only. ProofBundle authority remains canonical.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Final, MutableSet

CAMPAIGN_STATE_VERSION: Final[str] = "campaign_state_v2"
OPERATOR_HALTED: Final[str] = "OPERATOR_HALTED"


class CampaignStateError(RuntimeError):
    pass


@dataclass
class CampaignState:
    """Durable campaign state — persistable across process boundaries.

    All fields are JSON-serializable. No in-memory object references.
    """
    engagement_id: str
    target_url: str
    state_version: str = CAMPAIGN_STATE_VERSION
    cycle: int = 0
    decisions: list[dict[str, Any]] = field(default_factory=list)
    outcomes: list[dict[str, Any]] = field(default_factory=list)
    agenda: dict[str, Any] = field(default_factory=lambda: {
        "unresolved_questions": [], "confirmed_facts": [], "rejected_hypotheses": [],
        "promising_relationships": [], "blocked_experiments": [], "follow_up_actions": [],
        "mutation_log": [],
    })
    findings: dict[str, dict[str, Any]] = field(default_factory=dict)
    world_model_digest: str | None = None
    memory_refs: list[str] = field(default_factory=list)
    budget: dict[str, Any] = field(default_factory=lambda: {
        "max_cycles": 5, "max_experiments": 10, "started_at": None, "deadline": None,
    })
    terminal_state: str | None = None  # None = in-progress, else terminal reason
    halt_requested: bool = False
    halt_requested_by: str | None = None
    halt_requested_at: float | None = None
    # M2-impl WP-A/WP-C (R3/R5 of Ruling M2-001): durable rehydration substrate.
    #   dedupe_keys           — canonical intake dedupe keys already consumed
    #                           for this engagement (NF-R2-07: durable dedupe).
    #   registered_candidates — canonical candidate records written at
    #                           registration time so the campaign node's
    #                           factory re-derivation can re-register them
    #                           (the campaign worker's load->factory->
    #                           re-register reference pattern, in-process).
    # Schema note: v1 -> v2 bump is fail-safe by design (from_json rejects
    # other versions loudly). No v1 production file exists (the machinery
    # was transport-dead pre-M2); v1 test fixtures are regenerated.
    dedupe_keys: list[str] = field(default_factory=list)
    registered_candidates: list[dict[str, Any]] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def digest(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, default=str, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def is_terminal(self) -> bool:
        return self.terminal_state is not None

    def budget_exhausted(self) -> tuple[bool, str | None]:
        if self.halt_requested:
            return True, OPERATOR_HALTED
        if self.cycle >= self.budget.get("max_cycles", 5):
            return True, "max_cycles_reached"
        if len(self.outcomes) >= self.budget.get("max_experiments", 10):
            return True, "max_experiments_reached"
        deadline = self.budget.get("deadline")
        if deadline and time.time() > float(deadline):
            return True, "deadline_exceeded"
        return False, None

    def mark_terminal(self, reason: str) -> None:
        self.terminal_state = reason
        self.updated_at = time.time()

    def request_halt(self, requested_by: str = "operator") -> None:
        """Set a cooperative stop request; the active action may finish."""
        self.halt_requested = True
        self.halt_requested_by = str(requested_by or "operator")[:128]
        self.halt_requested_at = time.time()
        self.updated_at = time.time()

    def resume(self) -> None:
        """Clear an operator halt without rewriting completed evidence."""
        self.halt_requested = False
        self.halt_requested_by = None
        self.halt_requested_at = None
        if self.terminal_state == OPERATOR_HALTED:
            self.terminal_state = None
        self.updated_at = time.time()

    def record_dedupe_key(self, key: str) -> None:
        """NF-R2-07: durable per-engagement dedupe key (idempotent)."""
        key = str(key)
        if key and key not in self.dedupe_keys:
            self.dedupe_keys.append(key)
            self.updated_at = time.time()

    def record_registered_candidate(self, *, candidate_id: str, hypothesis_ids: tuple[str, ...],
                                    experiment_signature: str, dedupe_key: str = "") -> None:
        """WP-C: canonical candidate record for graph-path rehydration.

        Idempotent by candidate_id: re-registering the same candidate id
        refreshes the record rather than duplicating it.
        """
        entry = {
            "candidate_id": str(candidate_id),
            "hypothesis_ids": [str(h) for h in hypothesis_ids],
            "experiment_signature": str(experiment_signature),
            "dedupe_key": str(dedupe_key or ""),
            "registered_at": time.time(),
        }
        for i, existing in enumerate(self.registered_candidates):
            if existing.get("candidate_id") == entry["candidate_id"]:
                self.registered_candidates[i] = entry
                self.updated_at = time.time()
                return
        self.registered_candidates.append(entry)
        self.updated_at = time.time()

    def record_decision(self, *, cycle: int, selected_hypothesis: str, selected_experiment: str,
                        agenda_digest: str, memory_inputs: list[str]) -> None:
        self.decisions.append({
            "cycle": cycle, "selected_hypothesis": selected_hypothesis,
            "selected_experiment": selected_experiment, "agenda_digest": agenda_digest,
            "memory_inputs": list(memory_inputs), "timestamp": time.time(),
        })
        self.updated_at = time.time()

    def record_outcome(self, *, cycle: int, experiment_id: str, outcome_class: str,
                       information_value: float, observation_digest: str) -> None:
        self.outcomes.append({
            "cycle": cycle, "experiment_id": experiment_id, "outcome_class": outcome_class,
            "information_value": information_value, "observation_digest": observation_digest,
            "timestamp": time.time(),
        })
        self.updated_at = time.time()

    def update_agenda(self, agenda_summary: dict[str, Any]) -> None:
        for key in ("unresolved_questions", "confirmed_facts", "rejected_hypotheses",
                    "promising_relationships", "blocked_experiments", "follow_up_actions"):
            if key in agenda_summary:
                self.agenda[key] = list(agenda_summary[key])
        if "mutation_count" in agenda_summary:
            self.agenda["mutation_count"] = agenda_summary["mutation_count"]
        self.updated_at = time.time()

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, default=str, indent=2)

    @classmethod
    def from_json(cls, text: str) -> CampaignState:
        data = json.loads(text)
        version = data.get("state_version", "")
        if version != CAMPAIGN_STATE_VERSION:
            raise CampaignStateError(
                f"Incompatible campaign state version: {version!r}. "
                f"Expected {CAMPAIGN_STATE_VERSION!r}. Failing safe — no silent reinterpretation."
            )
        data.pop("state_version", None)
        return cls(**data)


def persist_campaign_state(state: CampaignState, path: str) -> None:
    """Persist campaign state to disk. Atomic write (tmp + rename)."""
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        f.write(state.to_json())
    os.replace(tmp, path)  # atomic


def load_campaign_state(path: str) -> CampaignState:
    """Load campaign state from disk. Fails safe on version mismatch/corruption."""
    if not os.path.exists(path):
        raise CampaignStateError(f"Campaign state file not found: {path}")
    with open(path) as f:
        text = f.read()
    try:
        return CampaignState.from_json(text)
    except (json.JSONDecodeError, TypeError, CampaignStateError) as exc:
        raise CampaignStateError(f"Corrupted/incompatible campaign state at {path}: {exc}") from exc


class CampaignStateDedupeRegistry(MutableSet):
    """M2-impl WP-A (NF-R2-07): a MutableSet view over CampaignState's durable
    dedupe keys. ``add`` records AND persists (every accepted key survives the
    invocation); ``__contains__`` reads the durable set — so duplicates are
    rejected across invocations, processes, and graph resumes.
    """

    def __init__(self, campaign_state: "CampaignState",
                 persist_path: str | None = None,
                 persist_fn: Any | None = None) -> None:
        self._cs = campaign_state
        self._path = persist_path
        self._persist_fn = persist_fn

    def _persist(self) -> None:
        from webpent.production.campaign_state import persist_campaign_state as _default_persist
        persist = self._persist_fn or _default_persist
        if self._path:
            persist(self._cs, self._path)

    def __contains__(self, key: object) -> bool:
        return str(key) in self._cs.dedupe_keys

    def __iter__(self):
        return iter(self._cs.dedupe_keys)

    def __len__(self) -> int:
        return len(self._cs.dedupe_keys)

    def add(self, key: str) -> None:
        self._cs.record_dedupe_key(key)
        if self._path:
            self._persist()

    def discard(self, key: str) -> None:
        # MutableSet contract completion. Dedupe keys are append-only in the
        # registration path; an explicit discard is an operator-level undo
        # (persisted like add so the durable view stays consistent).
        key = str(key)
        if key in self._cs.dedupe_keys:
            self._cs.dedupe_keys.remove(key)
            self._cs.updated_at = time.time()
            if self._path:
                self._persist()


__all__ = ["CampaignState", "CampaignStateError", "CampaignStateDedupeRegistry",
           "persist_campaign_state", "load_campaign_state",
           "CAMPAIGN_STATE_VERSION", "OPERATOR_HALTED"]
