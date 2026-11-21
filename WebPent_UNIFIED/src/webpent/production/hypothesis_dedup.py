"""UM-DR-40 RC-5 → UM-DR-43C — generation-time semantic hypothesis dedup.

The 39 register's RC-5: hypothesis dedup was fragmented. Per-batch
generation compared ``(url, vuln_class)`` TEXTUALLY, while the state
reducer (``merge_hypotheses``) upserts by ``id`` — and every
generation site produced a fresh random ``uuid4``, so the same
content re-entered the pool as a NEW id on every pass. The semantic
fingerprint existed but lived behind the adaptive-research flag.

The RC-5 fix (wired in ``graph/builder.py`` at the node registration
boundary): wrap the production ``hypothesis_node`` so that, at
GENERATION time, every freshly emitted hypothesis has its random id
replaced by a deterministic id of its content fingerprint, so the
existing upsert-by-id reducer absorbs the re-entry.

UM-DR-43C EVOLUTION (directive §5): the RC-5 fingerprint covered only
``(normalized URL, vuln class)`` with the whole URL lower-cased —
merging case-sensitive paths and blind to principal/tenant/object/
operation context. This module now derives ids from the versioned
identity contract (``hypothesis_identity``, contract ``umdr43c:v1``):

  * hypotheses WITH structured identity context (identity_workflow
    productions, request_data identity keys, observed identity
    profiles) get a v2 fingerprint over (canonical target key, class,
    objective key, identity scope) — security-distinct contexts stay
    separate, identical contexts merge across producers;
  * hypotheses WITHOUT any identity context keep the EXACT legacy
    RC-5 fingerprint and id (byte-compatible) — old checkpoints
    replay unchanged, and the legacy merge remains explainable as
    "no identity context on either side" rather than silently
    claiming identity equality.

Design notes:

* ``Hypothesis.id`` assignment happens here, on the node's OUTPUT —
  the frozen model module and the frozen generator agent are NOT
  touched. ``graph/builder.py`` wiring is unchanged: it still binds
  ``NODE_HYPOTHESIS`` to ``deduplicated_hypothesis_node``; the
  evolution is entirely inside this module.
* Pass-through guarantee: the wrapper changes ONLY the ids of the
  hypotheses the node emits in this update; the rest of the update
  dict is returned untouched.
* No I/O, no network, no LLM: identity context comes exclusively from
  structured fields already carried on the hypothesis (§5.2), and the
  fingerprint computation is pure.
"""
from __future__ import annotations

import json
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from webpent.production.hypothesis_identity import (
    IdentityTelemetry,
    canonical_target_key,
    identity_from_hypothesis,
    identity_fingerprint,
    legacy_fingerprint,
)

# re-exported for tests and diagnostics (legacy API preserved)
__all__ = [
    "hypothesis_content_fingerprint",
    "deterministic_hypothesis_id",
    "deduplicated_hypothesis_node",
    "hypothesis_identity_fingerprint",
    "last_identity_telemetry",
]

# §8: the most recent pass's bounded counters, exposed for campaign
# reporting surfaces. Written by deduplicated_hypothesis_node; never
# contains hypothesis text, URLs or principals.
last_identity_telemetry: IdentityTelemetry = IdentityTelemetry()


def hypothesis_content_fingerprint(
        target_url: str, vuln_class: str) -> str:
    """The LEGACY RC-5 fingerprint (kept byte-compatible, §13).

    Callers predating UM-DR-43C — and hypotheses without identity
    context — continue to receive this exact value so their ids (and
    therefore checkpoints, findings' ``hypothesis_id`` links and
    decision-ledger references) never churn.
    """
    return legacy_fingerprint(target_url, vuln_class)


def hypothesis_identity_fingerprint(
        hypothesis: Any) -> tuple[str, bool]:
    """The UM-DR-43C fingerprint of one emitted hypothesis.

    Returns ``(fingerprint, identity_involved)``:

    * ``identity_involved=False`` — no structured identity context was
      found; the fingerprint is the legacy RC-5 value (id compat);
    * ``identity_involved=True`` — a structured context exists; the
      fingerprint is the versioned v2 value over the canonical target
      key, class, objective key and identity scope.

    The objective key generalizes the UMDR-31 "what is this about"
    notion: productions that state one (``differential:<object>``,
    ``invariant:<id>``) get it from ``origin_detail``'s structured
    ``objective=<key>`` line; the generic producer leaves it empty,
    which is itself deterministic.
    """
    if isinstance(hypothesis, dict):
        target_url = str(hypothesis.get("target_url") or "")
        vuln_class = str(hypothesis.get("vuln_class") or "")
    else:
        target_url = str(hypothesis.target_url or "")
        vuln_class = str(hypothesis.vuln_class or "")
    identity = identity_from_hypothesis(hypothesis)
    if identity.is_empty():
        return legacy_fingerprint(target_url, vuln_class), False
    objective_key = _objective_key_from_detail(hypothesis)
    return identity_fingerprint(
        target_url=target_url,
        vuln_class=vuln_class,
        objective_key=objective_key,
        identity=identity,
    ), True


def _objective_key_from_detail(hypothesis: Any) -> str:
    if isinstance(hypothesis, dict):
        detail = str(hypothesis.get("origin_detail") or "")
    else:
        detail = str(hypothesis.origin_detail or "")
    for line in detail.split():
        key, sep, value = line.partition("=")
        if sep and key.strip().lower() == "objective":
            return value.strip()[:200]
    return ""


def deterministic_hypothesis_id(fingerprint: str) -> UUID:
    """The uuid5 id derived from a legacy RC-5 fingerprint."""
    return uuid5(NAMESPACE_URL, f"webpent:umdr40:{fingerprint}")


def _identity_hypothesis_id(fingerprint: str) -> UUID:
    """The uuid5 id derived from a v2 identity fingerprint."""
    return uuid5(NAMESPACE_URL, f"webpent:umdr43c:{fingerprint}")


def _retag(update: dict[str, Any]) -> dict[str, Any]:
    """Replace the emitted hypotheses' random ids with deterministic
    content ids (in place on the list, never on the frozen model
    code), recording the pass's bounded identity telemetry (§8)."""
    global last_identity_telemetry
    hypotheses = update.get("hypotheses")
    if not isinstance(hypotheses, list):
        return update
    telemetry = IdentityTelemetry()
    seen_fingerprints: dict[str, int] = {}
    for hypothesis in hypotheses:
        try:
            target_url = getattr(hypothesis, "target_url", None)
            vuln_class = getattr(hypothesis, "vuln_class", None)
        except (AttributeError, TypeError):  # pragma: no cover
            continue  # defensive only: non-object pool entries
        if not target_url or not vuln_class:
            continue
        telemetry.hypotheses_emitted += 1
        fingerprint, identity_involved = (
            hypothesis_identity_fingerprint(hypothesis))
        if identity_involved:
            hypothesis.id = _identity_hypothesis_id(fingerprint)
            telemetry.identity_distinct_retained += 1
        else:
            hypothesis.id = deterministic_hypothesis_id(fingerprint)
            telemetry.unknown_context_retained += 1
        if fingerprint in seen_fingerprints:
            telemetry.exact_duplicates_merged += 1
        seen_fingerprints[fingerprint] = (
            seen_fingerprints.get(fingerprint, 0) + 1)
    telemetry.unique_after_dedup = len(seen_fingerprints)
    last_identity_telemetry = telemetry
    return update


def deduplicated_hypothesis_node(state: Any) -> dict[str, Any]:
    """The production hypothesis node with generation-time dedup
    (RC-5 ids, UM-DR-43C identity-aware where context exists)."""
    from webpent.agents.hypothesis_analyzer.agent import hypothesis_node

    return _retag(hypothesis_node(state))
