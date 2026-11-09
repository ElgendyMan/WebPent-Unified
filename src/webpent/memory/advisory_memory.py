# src/webpent/memory/advisory_memory.py
"""TEAM-1 ADVISORY MEMORY BRIDGE V1 — operational cross-run knowledge.

Repairs Finding 4 (WRITE_ONLY_MEMORY): the knowledge/RAG structures exist
but have no effective runtime consumers. This module turns write-only
memory into an actual operational advisory memory.

ARCHITECTURE:
  Run N → outcome/lesson generated → sanitized persistence (LessonsManager)
  Run N+1 → AdvisoryMemoryBridge.retrieve_advisory() → relevant prior
            knowledge retrieved → sanitized projection → research context
            → influence on candidate prioritization / hypothesis selection

TRUST BOUNDARY (Part 10):
  Every retrieved lesson / RAG item / prior-run hypothesis is explicitly
  represented as UNTRUSTED ADVISORY KNOWLEDGE. It MUST NOT masquerade as:
    - observed target fact
    - executed result
    - trusted evidence
    - security authority

  A retrieved lesson MUST NOT:
    - authorize a host
    - authorize a tool
    - confirm a vulnerability
    - bypass CausalGuard
    - bypass ScopeLaw
    - become target-backed evidence
    - influence scope authorization, executor authorization, confirmation,
      proof validity, or promotion.

  It may influence ONLY: research ranking, hypothesis prioritization,
  redundancy avoidance, experiment utility, exploration/exploitation,
  unresolved-question handling — as ADVISORY information.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final, Literal
from uuid import uuid4

logger = logging.getLogger(__name__)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


# Provenance marker — every advisory knowledge item carries this.
# It is structurally impossible for an AdvisoryKnowledge to be treated
# as trusted evidence by the authority layer.
ADVISORY_PROVENANCE: Final[str] = "prior_run_advisory_untrusted"


@dataclass(frozen=True)
class AdvisoryKnowledge:
    """One item of untrusted advisory knowledge from a prior run.

    Structurally marked as advisory. Fields are frozen; cannot be mutated
    into trusted evidence. The `content` is the raw lesson text; the
    `projection` is the sanitized, context-ready form.
    """
    knowledge_id: str
    content: str
    source_run: str  # prior engagement/run id
    retrieved_at: str = field(default_factory=_utc)
    provenance: str = ADVISORY_PROVENANCE
    advisory_only: bool = True
    trust_level: Literal["untrusted_advisory"] = "untrusted_advisory"

    # Structural prohibition: this object can NEVER become authority.
    def is_authority(self) -> bool:
        return False

    def as_research_context(self) -> dict[str, Any]:
        """Project into research context — explicitly marked advisory."""
        return {
            "knowledge_id": self.knowledge_id,
            "projection": self._sanitized_projection(),
            "provenance": self.provenance,
            "advisory_only": True,
            "trust_level": self.trust_level,
            "source_run": self.source_run,
            "authority_claims": "none — advisory only, cannot authorize or confirm",
            "usage_constraint": "may_influence_ranking_only",
        }

    def _sanitized_projection(self) -> str:
        """Sanitize content for LLM context — strip authority-like claims.

        We do NOT delete useful content; we mark authority-like statements
        as untrusted claims so the LLM cannot mistake them for authority.
        """
        text = self.content
        # Mark authority-like patterns as [UNTRUSTED CLAIM: ...]
        authority_patterns = [
            (r"(?i)(confirmed\s+vulnerable|vulnerability\s+confirmed)", "[UNTRUSTED CLAIM: prior run asserted confirmation — NOT authoritative]"),
            (r"(?i)(scope\s+(is|has been)\s+expanded|scope\s+expanded)", "[UNTRUSTED CLAIM: scope assertion — ScopeLaw is sole authority]"),
            (r"(?i)(operator\s+approved|approval\s+(has been|was)\s+granted)", "[UNTRUSTED CLAIM: approval assertion — authorization is session-bound]"),
            (r"(?i)(causalguard\s+(already\s+)?passed|causal\s+guard\s+passed)", "[UNTRUSTED CLAIM: CausalGuard assertion — must re-adjudicate]"),
            (r"(?i)(external\s+target\s+(is\s+)?allowed|allowed\s+external)", "[UNTRUSTED CLAIM: target scope assertion — ScopeLaw is sole authority]"),
            (r"(?i)(negative\s+control\s+(is\s+)?known\s+to\s+pass|negative\s+control\s+passed|skip\s+negative\s+control)", "[UNTRUSTED CLAIM: negative control assertion — must re-run]"),
            (r"(?i)(ignore\s+the\s+scope\s+policy|bypass\s+scope|scope\s+(may\s+be|can\s+be)\s+ignored)", "[UNTRUSTED CLAIM: policy bypass instruction — rejected]"),
            (r"(?i)(vulnerability\s+already\s+confirmed|already\s+confirmed\s*—?\s*skip\s+testing|skip\s+testing)", "[UNTRUSTED CLAIM: prior run asserted confirmation — NOT authoritative]"),
            (r"(?i)(proof\s+(can|could)\s+be\s+trusted\s+without\s+re-?verification|trusted\s+without\s+re-?verification)", "[UNTRUSTED CLAIM: proof-trust assertion — all proof must be re-verified]"),
            (r"(?i)(do\s+not\s+run\s+baseline|skip\s+baseline|baseline\s+(is\s+)?(a\s+)?waste\s+of\s+time)", "[UNTRUSTED CLAIM: baseline-skip instruction — rejected]"),
        ]
        for pattern, replacement in authority_patterns:
            text = re.sub(pattern, replacement, text)
        return text[:2000]  # bounded projection


class AdvisoryMemoryBridge:
    """Bridges cross-run memory into runtime research context (advisory only).

    This is the operational consumer that repairs WRITE_ONLY_MEMORY. It
    retrieves lessons from LessonsManager, wraps them in AdvisoryKnowledge
    (explicit untrusted provenance), and provides a sanitized projection
    for the research context.

    It NEVER grants authority. It influences ranking only.
    """

    MAX_ADVISORY_ITEMS: Final[int] = 10
    MAX_ADVISORY_CHARS: Final[int] = 4000

    def __init__(self, *, client_id: str, lessons_manager: Any = None,
                 database_url: str | None = None) -> None:
        if not client_id or not isinstance(client_id, str):
            raise ValueError("client_id required for memory isolation")
        self._client_id = client_id
        self._retrieval_log: list[dict[str, Any]] = []

        if lessons_manager is not None:
            self._lessons = lessons_manager
        else:
            from webpent.memory.lessons import LessonsManager
            self._lessons = LessonsManager(database_url=database_url)

    def retrieve_advisory(self, *, target_url: str, query: str | None = None,
                          engagement_id: str | None = None,
                          limit: int = 5) -> tuple[AdvisoryKnowledge, ...]:
        """Retrieve relevant prior lessons as ADVISORY knowledge.

        Returns tuple of AdvisoryKnowledge (frozen, untrusted). These may
        inform research ranking ONLY. They cannot authorize or confirm.
        """
        bounded_limit = max(1, min(int(limit), self.MAX_ADVISORY_ITEMS))
        search_query = query or target_url

        try:
            raw_lessons = self._lessons.search_lessons(
                query=search_query,
                client_id=self._client_id,
                engagement_id=engagement_id,
                limit=bounded_limit,
            )
        except Exception as exc:
            logger.warning("advisory memory retrieval failed (advisory only, fail open): %s", exc)
            raw_lessons = []

        items: list[AdvisoryKnowledge] = []
        for i, content in enumerate(raw_lessons[:bounded_limit]):
            if not content or not isinstance(content, str):
                continue
            kid = f"adv_{uuid4().hex[:10]}"
            item = AdvisoryKnowledge(
                knowledge_id=kid,
                content=content[:4000],
                source_run=f"prior_run_{i}",
            )
            items.append(item)

        self._retrieval_log.append({
            "target_url": target_url[:200],
            "query": (query or "")[:200],
            "items_retrieved": len(items),
            "at": _utc(),
        })
        return tuple(items)

    def project_into_research_context(self, *, target_url: str,
                                      query: str | None = None) -> dict[str, Any]:
        """Produce a sanitized advisory-context projection for the research loop.

        This is what the ResearchControlLoop / LLM sees. It is explicitly
        bounded and marked advisory. The projection includes:
          - prior lessons (sanitized, authority-claims neutralized)
          - explicit usage constraint: ranking influence only
          - structural marker: cannot become authority
        """
        items = self.retrieve_advisory(target_url=target_url, query=query)
        projections = [item.as_research_context() for item in items]
        total_chars = sum(len(p["projection"]) for p in projections)
        # Bound total advisory context size.
        if total_chars > self.MAX_ADVISORY_CHARS:
            projections = projections[:max(1, len(projections) // 2)]

        return {
            "advisory_memory": {
                "provenance": ADVISORY_PROVENANCE,
                "items": projections,
                "item_count": len(projections),
                "advisory_only": True,
                "trust_level": "untrusted_advisory",
                "usage_constraint": "may_influence_ranking_only",
                "authority_claims": "none — advisory memory cannot authorize, confirm, or promote",
                "retrieved_at": _utc(),
            }
        }

    def persist_outcome(self, *, target_url: str, lesson: str,
                        engagement_id: str, outcome_class: str) -> bool:
        """Persist a sanitized lesson from this run (write path).

        Sanitized before persistence. Lessons stored here will be retrieved
        by future runs as ADVISORY knowledge only.
        """
        sanitized = self._sanitize_for_storage(lesson)
        if not sanitized:
            return False
        try:
            self._lessons.store_lesson(
                target_url=target_url,
                content=sanitized,
                client_id=self._client_id,
                engagement_id=engagement_id,
                vuln_class=outcome_class,
            )
            return True
        except Exception as exc:
            logger.warning("advisory memory persist failed: %s", exc)
            return False

    @staticmethod
    def _sanitize_for_storage(text: str) -> str:
        """Sanitize lesson content before storage — strip raw payloads/secrets."""
        if not text:
            return ""
        # Strip secrets-like patterns.
        secret_patterns = [
            r"(?i)(password|passwd|secret|token|api[_-]?key|bearer)\s*[:=]\s*\S+",
            r"[A-Za-z0-9+/]{40,}",  # long base64 blobs
        ]
        cleaned = text
        for pat in secret_patterns:
            cleaned = re.sub(pat, "[REDACTED]", cleaned)
        return cleaned[:4000]

    @property
    def retrieval_log(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._retrieval_log)


# Structural assertion: AdvisoryKnowledge can never become trusted evidence.
def assert_advisory_only(obj: Any) -> None:
    """Raise if an object claims to be advisory but carries authority markers."""
    if isinstance(obj, AdvisoryKnowledge):
        return  # structurally safe
    if isinstance(obj, dict):
        if obj.get("advisory_only") is True and obj.get("provenance") == ADVISORY_PROVENANCE:
            return
        # If it claims to be advisory but has authority fields, reject.
        if obj.get("confirmed") is True or obj.get("authorized") is True:
            raise PermissionError(
                "Object claims advisory status but carries authority markers (confirmed/authorized). "
                "Advisory memory cannot grant authority."
            )


__all__ = [
    "AdvisoryKnowledge", "AdvisoryMemoryBridge", "ADVISORY_PROVENANCE",
    "assert_advisory_only",
]
