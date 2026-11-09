"""V7 Phase 3 — Deterministic Skill Selection (100% rule-based)."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
_MANIFEST_PATH = Path(__file__).resolve().parents[3] / "knowledge_sources.yaml"


def _load_skills() -> list[dict[str, Any]]:
    try:
        import yaml

        if not _MANIFEST_PATH.is_file():
            return []
        with open(_MANIFEST_PATH) as f:
            return yaml.safe_load(f).get("skills", [])
    except Exception:
        return []


def select_skills(
    current_phase: str, vuln_class: str | None = None
) -> list[dict[str, Any]]:
    matched = []
    for skill in _load_skills():
        if skill.get("applies_to_phase") != current_phase:
            continue
        if vuln_class and vuln_class not in skill.get("applies_to_vuln_class", []):
            continue
        matched.append(skill)
    if matched:
        logger.info(
            "Skill selector: %d matched (phase=%s, vc=%s)",
            len(matched),
            current_phase,
            vuln_class or "any",
        )
    return matched


def get_skill_reference(skill: dict[str, Any], finding_id: str) -> str:
    """Return a bounded advisory reference for one selected skill.

    ``payload_corpus`` is intentionally resolved through the local knowledge
    store.  It must not be treated as target evidence: the payload-generator
    caller places the returned text inside its untrusted-data wrapper before
    any model invocation.  The payload path is offline-safe and therefore
    cannot silently turn a skill selection into live network I/O.
    """
    source = str(skill.get("reference_source", "") or "").strip()
    # POST-P0 Phase 10: playbook documents are retrievable skill
    # references (same advisory, untrusted-wrapped, offline-safe contract
    # as the payload corpus — never evidence, never confirmation).
    if source == "playbook":
        from webpent.shared.knowledge_retrieval import retrieve_knowledge_context

        classes = skill.get("applies_to_vuln_class", [])
        if isinstance(classes, str):
            classes = [classes]
        class_query = " ".join(str(value).strip() for value in classes if str(value).strip())
        query = " ".join(
            value
            for value in (str(skill.get("name", "")).strip(), class_query, "playbook procedure")
            if value
        )
        return retrieve_knowledge_context(
            query=query,
            doc_types=("playbook",),
            stack=str(skill.get("stack", "") or "").strip() or None,
            max_chars=1200,
        )
    if source == "payload_corpus":
        from webpent.shared.knowledge_retrieval import retrieve_knowledge_context

        classes = skill.get("applies_to_vuln_class", [])
        if isinstance(classes, str):
            classes = [classes]
        class_query = " ".join(str(value).strip() for value in classes if str(value).strip())
        query = " ".join(
            value
            for value in (str(skill.get("name", "")).strip(), class_query, "payload reference")
            if value
        )
        return retrieve_knowledge_context(
            query=query,
            doc_types=("payload",),
            stack=str(skill.get("stack", "") or "").strip() or None,
            per_type_k=2,
            max_chars=2000,
        )
    if source == "hacktricks":
        from webpent.shared.reference_lookup import reference_lookup

        return reference_lookup(
            query=skill.get("name", ""), finding_id=finding_id, source="hacktricks"
        )
    return ""
