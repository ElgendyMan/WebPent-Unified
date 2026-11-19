"""UM-DR-40 RC-5 — generation-time semantic hypothesis dedup.

The 39 register's RC-5: hypothesis dedup was fragmented. Per-batch
generation compared ``(url, vuln_class)`` TEXTUALLY, while the state
reducer (``merge_hypotheses``) upserts by ``id`` — and every
generation site produced a fresh random ``uuid4``, so the same
content re-entered the pool as a NEW id on every pass. The semantic
fingerprint existed but lived behind the adaptive-research flag.

The fix (this module, wired in ``graph/builder.py`` at the node
registration boundary): wrap the production ``hypothesis_node`` so
that, at GENERATION time, every freshly emitted hypothesis has its
random id replaced by the deterministic uuid5 of its content
fingerprint (normalized target URL + vuln class — exactly the pair
the textual per-batch dedup compared). Identical content from any
producer, in any pass, then carries the SAME id, and the existing
upsert-by-id reducer absorbs the re-entry instead of appending a
duplicate.

Design notes:

* ``Hypothesis.id`` assignment happens here, on the node's OUTPUT —
  the frozen model module and the frozen generator agent are NOT
  touched (the frozen-modules byte gate stays green; builder.py is
  the ruling-authorized delta file for this window, exactly as in
  the UM-DR-31 research-loop wiring).
* The fingerprint deliberately covers only (normalized URL, vuln
  class): that is the semantic pair the generator itself considered
  "the same hypothesis" in its per-batch check. Anything
  security-relevant — a different class, a different target —
  produces a different id and stays a separate pool entry.
* Pass-through guarantee: the wrapper changes ONLY the ids of the
  hypotheses the node emits in this update; the rest of the update
  dict is returned untouched.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

# re-exported for tests and diagnostics
__all__ = [
    "hypothesis_content_fingerprint",
    "deterministic_hypothesis_id",
    "deduplicated_hypothesis_node",
]


def hypothesis_content_fingerprint(
        target_url: str, vuln_class: str) -> str:
    """Deterministic sha256[:40] over the canonical (normalized
    URL, lowercased vuln class) pair — the generation-time semantic
    fingerprint (RC-5)."""
    canonical = json.dumps(
        {"t": str(target_url or "").strip().rstrip("/").lower(),
         "v": str(vuln_class or "").strip().lower()},
        sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:40]


def deterministic_hypothesis_id(fingerprint: str) -> UUID:
    """The uuid5 id derived from the fingerprint (the
    workflow-understanding convention: UM-DR-31 §5.3's uuid5 ids,
    applied to generation)."""
    return uuid5(NAMESPACE_URL, f"webpent:umdr40:{fingerprint}")


def _retag(update: dict[str, Any]) -> dict[str, Any]:
    """Replace the emitted hypotheses' random ids with their
    deterministic content ids (in place on the list, never on the
    frozen model code)."""
    hypotheses = update.get("hypotheses")
    if not isinstance(hypotheses, list):
        return update
    for hypothesis in hypotheses:
        try:
            target_url = getattr(hypothesis, "target_url", None)
            vuln_class = getattr(hypothesis, "vuln_class", None)
        except (AttributeError, TypeError):  # pragma: no cover
            continue  # defensive only: non-object pool entries
        if not target_url or not vuln_class:
            continue
        fingerprint = hypothesis_content_fingerprint(
            str(target_url), str(vuln_class))
        hypothesis.id = deterministic_hypothesis_id(fingerprint)
    return update


def deduplicated_hypothesis_node(state: Any) -> dict[str, Any]:
    """The production hypothesis node with RC-5 generation-time
    dedup applied to its output."""
    from webpent.agents.hypothesis_analyzer.agent import hypothesis_node

    return _retag(hypothesis_node(state))
