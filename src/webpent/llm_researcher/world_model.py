"""World Model — bounded observation store with deterministic content hashes.
Part of the Causal Feedback Bridge (v1.8.3).

The LLM may ONLY add observations to the world model. It may NEVER:
- Write verdicts
- Modify causal rules
- Modify thresholds
- Modify ground truth
- Modify governance
- Modify ProofBundle validity rules

Every observation has a deterministic SHA-256 content hash for audit trails.
"""
import hashlib
import json
from dataclasses import dataclass
from typing import Any


def _content_hash(observation: dict[str, Any]) -> str:
    """Deterministic hash of observation content. Used for audit trails."""
    canonical = json.dumps(observation, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _observation_key(observation: dict[str, Any]) -> str:
    """Unique key for deduplication: method + path + semantic_digest."""
    req = observation.get("request", {})
    return f"{req.get('method','GET')}|{req.get('path','/')}|{observation.get('semantic_digest','')}"


@dataclass
class StoredObservation:
    key: str
    content_hash: str
    observation: dict[str, Any]
    source: str = "initial"  # "initial" or "llm_experiment"
    hypothesis_id: str | None = None
    tool_used: str | None = None


class ObservationStore:
    """Bounded observation store with hash-based deduplication. Max 100 observations."""

    MAX_OBSERVATIONS = 100

    def __init__(self):
        self._store: dict[str, StoredObservation] = {}
        self._order: list[str] = []

    def add(self, observation: dict[str, Any], source: str = "initial",
            hypothesis_id: str | None = None, tool_used: str | None = None) -> dict[str, Any]:
        """Add an observation. Returns {added: bool, content_hash: str, key: str}."""
        key = _observation_key(observation)
        content_hash = _content_hash(observation)

        if key in self._store:
            return {"added": False, "content_hash": content_hash, "key": key,
                    "reason": "duplicate_key", "store_size": len(self._store)}

        if len(self._store) >= self.MAX_OBSERVATIONS:
            return {"added": False, "content_hash": content_hash, "key": key,
                    "reason": "store_full", "store_size": len(self._store)}

        stored = StoredObservation(key=key, content_hash=content_hash,
                                   observation=observation, source=source,
                                   hypothesis_id=hypothesis_id, tool_used=tool_used)
        self._store[key] = stored
        self._order.append(key)
        return {"added": True, "content_hash": content_hash, "key": key,
                "store_size": len(self._store)}

    def get_all(self) -> list[dict[str, Any]]:
        """Return all observations in insertion order — for CausalGuard input."""
        return [self._store[k].observation for k in self._order]

    def get_stored(self) -> list[StoredObservation]:
        """Return all stored observation records with metadata."""
        return [self._store[k] for k in self._order]

    def get_hashes(self) -> list[str]:
        """Return all content hashes for audit trail."""
        return [self._store[k].content_hash for k in self._order]

    def get_by_source(self, source: str) -> list[StoredObservation]:
        return [s for s in self._store.values() if s.source == source]

    def __len__(self) -> int:
        return len(self._store)


class WorldModel:
    """Bounded world model. LLM may only ADD observations through this interface.

    The world model is the ONLY channel through which LLM-generated research
    feeds back into deterministic causal validation.

    CausalGuard reads from get_causal_inputs().
    LLM writes through add_observation().
    """

    def __init__(self):
        self.store = ObservationStore()

    def add_observation(self, observation: dict[str, Any], source: str = "initial",
                       hypothesis_id: str | None = None,
                       tool_used: str | None = None) -> dict[str, Any]:
        """LLM/Bridge: add an observation. Returns metadata including content hash."""
        return self.store.add(observation, source=source,
                             hypothesis_id=hypothesis_id, tool_used=tool_used)

    def get_causal_inputs(self) -> list[dict[str, Any]]:
        """CausalGuard: get all observations for deterministic evaluation."""
        return self.store.get_all()

    def get_content_hashes(self) -> list[str]:
        """Audit: get all deterministic content hashes."""
        return self.store.get_hashes()

    def get_llm_added_observations(self) -> list[StoredObservation]:
        """Audit: get only observations added by LLM experiments."""
        return self.store.get_by_source("llm_experiment")

    def size(self) -> int:
        return len(self.store)

    def snapshot(self) -> dict[str, Any]:
        """Return a snapshot for trace recording."""
        return {
            "size": self.size(),
            "content_hashes": self.get_content_hashes(),
            "llm_added_count": len(self.get_llm_added_observations()),
            "initial_count": len(self.store.get_by_source("initial")),
        }
