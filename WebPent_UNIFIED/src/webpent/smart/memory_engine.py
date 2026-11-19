"""
VIP Smart Autonomous Bug Hunter — Smart Memory Engine.

Stores, indexes, and verifies learned patterns.
- Deterministic SHA-256 signatures for tamper detection
- Feature-based similarity query
- NEVER overrides causal decisions — provides hints only
- All learning is transparent and auditable
"""
import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any


def _canonical_hash(obj: Any) -> str:
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


@dataclass
class MemoryEntry:
    pattern_id: str
    pattern_type: str
    features: dict[str, Any]
    outcome: str
    confidence: float
    source: str
    signature: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.signature:
            self.signature = self._compute_signature()

    def _compute_signature(self) -> str:
        payload = {
            "pattern_id": self.pattern_id,
            "pattern_type": self.pattern_type,
            "features": self.features,
            "outcome": self.outcome,
            "confidence": self.confidence,
            "source": self.source,
        }
        return _canonical_hash(payload)

    def verify_signature(self) -> bool:
        return self.signature == self._compute_signature()


class SmartMemory:
    """
    Auditable memory for learned patterns.

    Governance:
    - Memory is HINT-ONLY — never overrides causal decisions
    - Every entry has a deterministic signature for tamper detection
    - Queries return similarity-weighted hints, not commands
    """

    def __init__(self):
        self._entries: dict[str, MemoryEntry] = {}

    def store(self, entry: MemoryEntry) -> None:
        """Store a verified memory entry."""
        if not entry.verify_signature():
            raise ValueError("Memory entry signature invalid — possible tampering")
        self._entries[entry.pattern_id] = entry

    def get(self, pattern_id: str) -> MemoryEntry | None:
        return self._entries.get(pattern_id)

    def verify(self, entry: MemoryEntry) -> bool:
        """Verify an entry against stored signature."""
        stored = self._entries.get(entry.pattern_id)
        if stored is None:
            return False
        return stored.signature == entry.signature and entry.verify_signature()

    def _feature_similarity(self, a: dict[str, Any], b: dict[str, Any]) -> float:
        """Simple generic feature similarity (0.0 to 1.0)."""
        if not a or not b:
            return 0.0
        common_keys = set(a.keys()) & set(b.keys())
        if not common_keys:
            return 0.0
        matches = 0.0
        for k in common_keys:
            if a[k] == b[k]:
                matches += 1.0
            elif isinstance(a[k], (int, float)) and isinstance(b[k], (int, float)):
                try:
                    max_val = max(abs(a[k]), abs(b[k]), 1)
                    matches += 1.0 - min(abs(a[k] - b[k]) / max_val, 1.0)
                except Exception:
                    pass
                    # Intentionally suppressed — reviewed 2026-09-03
        return matches / len(common_keys)

    def query_similar(self, features: dict[str, Any], top_k: int = 5) -> list[tuple[MemoryEntry, float]]:
        """Query memory for entries with similar features. Returns [(entry, similarity)]."""
        scored = []
        for entry in self._entries.values():
            sim = self._feature_similarity(features, entry.features)
            if sim > 0:
                scored.append((entry, sim))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def get_hint(self, features: dict[str, Any]) -> dict[str, Any]:
        """
        Get a learning hint for the given features.
        GOVERNANCE: can_override is ALWAYS False — memory never overrides causal.
        """
        similar = self.query_similar(features, top_k=3)
        if not similar:
            return {"can_override": False, "strength": 0.0, "suggested_outcome": None, "entries": 0}

        total_weight = sum(sim for _, sim in similar)
        vuln_weight = sum(
            sim for entry, sim in similar if entry.outcome == "vulnerable"
        )
        clean_weight = sum(
            sim for entry, sim in similar if entry.outcome == "clean"
        )

        strength = total_weight / len(similar) if similar else 0.0
        suggested = "vulnerable" if vuln_weight > clean_weight else "clean" if clean_weight > vuln_weight else None

        return {
            "can_override": False,  # HARD GOVERNANCE: never overrides
            "strength": min(strength, 0.75),  # Capped — hint only
            "suggested_outcome": suggested,
            "entries": len(similar),
            "confidence": max(vuln_weight, clean_weight) / total_weight if total_weight > 0 else 0.0,
        }

    def to_dict(self) -> dict[str, Any]:
        return {pid: asdict(entry) for pid, entry in self._entries.items()}
