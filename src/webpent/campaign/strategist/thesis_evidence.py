"""Thesis evidence extraction (supports U-CAMPAIGN-1).

Turns the upstream signals (Oracle report, Prism pattern matches,
Economist score — all duck-typed Protocols) into a flat, weighted
evidence list. Every piece of evidence carries its source and weight;
the thesis builder refuses to proceed when the list is too thin.

The weights are FIXED constants, documented here, not learned: a
deterministic strategist (L-9) must not hide its arithmetic inside a
model call.
"""
from __future__ import annotations

from typing import Any

from webpent.campaign.schemas import ThesisEvidence

# Evidence weights — the strategist's published arithmetic.
WEIGHT_TECH_STACK = 0.6
WEIGHT_LEGACY_STACK = 0.7      # legacy markers are strong prior evidence
WEIGHT_SUBDOMAINS = 0.5
WEIGHT_LEAKED_SIGNALS = 0.65   # leaked credentials/keys are near-direct evidence
WEIGHT_CROWN_JEWELS = 0.6
WEIGHT_ECONOMIST = 0.5

# Words whose presence in a subdomain marks legacy/edge infrastructure.
_LEGACY_MARKERS = ("legacy", "old", "dev", "staging", "internal",
                   "vpn", "mail", "test", "uat", "beta")


def evidence_from_oracle(oracle: Any) -> list[ThesisEvidence]:
    """Extract weighted evidence from an Oracle-shaped report.

    Duck-typed: reads ``tech_stack``, ``subdomains``,
    ``historical_endpoints``, ``leaked_signals``, ``crown_jewel_hints``
    when present; missing attributes count as empty.
    """
    pieces: list[ThesisEvidence] = []

    # The duck-typed OracleReport protocol defines every field below;
    # absent collections arrive as empty ones, not missing attributes.
    # Direct reads keep this module statically observable (no getattr
    # dynamic-resolution sites in the direct-I/O inventory).
    tech_stack = oracle.tech_stack or {}
    if tech_stack:
        backend = tech_stack.get("backend", "unknown")
        pieces.append(ThesisEvidence(
            evidence_id="ev-oracle-stack",
            source="oracle",
            source_ref="tech_stack",
            claim=f"Observed backend stack: {backend} "
                  f"({tech_stack.get('framework', 'no framework')})",
            weight=WEIGHT_TECH_STACK,
        ))
        # Legacy stack markers multiply the attack surface.
        if any(m in str(v).lower() for v in tech_stack.values()
               for m in ("legacy", "old", "1.", "2.", "3.")):
            pieces.append(ThesisEvidence(
                evidence_id="ev-oracle-legacy-stack",
                source="oracle",
                source_ref="tech_stack",
                claim="Legacy version markers observed in the tech stack",
                weight=WEIGHT_LEGACY_STACK,
            ))

    subdomains = oracle.subdomains or []
    if subdomains:
        legacy = [s for s in subdomains
                  if any(m in s.lower() for m in _LEGACY_MARKERS)]
        pieces.append(ThesisEvidence(
            evidence_id="ev-oracle-subdomains",
            source="oracle",
            source_ref="subdomains",
            claim=f"{len(subdomains)} subdomains enumerated"
                  + (f", {len(legacy)} legacy/edge markers" if legacy else ""),
            weight=WEIGHT_SUBDOMAINS,
        ))
        if legacy:
            pieces.append(ThesisEvidence(
                evidence_id="ev-oracle-legacy-subdomains",
                source="oracle",
                source_ref="subdomains",
                claim="Legacy/edge subdomains present — forgotten "
                      "infrastructure is a classic soft entry point",
                weight=WEIGHT_LEGACY_STACK,
            ))

    endpoints = oracle.historical_endpoints or []
    if endpoints:
        pieces.append(ThesisEvidence(
            evidence_id="ev-oracle-endpoints",
            source="oracle",
            source_ref="historical_endpoints",
            claim=f"{len(endpoints)} historical API endpoints with "
                  "identifiable resource shapes",
            weight=WEIGHT_SUBDOMAINS,
        ))

    leaks = oracle.leaked_signals or []
    if leaks:
        pieces.append(ThesisEvidence(
            evidence_id="ev-oracle-leaks",
            source="oracle",
            source_ref="leaked_signals",
            claim=f"{len(leaks)} leaked-signal hits (credentials/keys in "
                  "public artifacts)",
            weight=WEIGHT_LEAKED_SIGNALS,
        ))

    jewels = oracle.crown_jewel_hints or []
    if jewels:
        pieces.append(ThesisEvidence(
            evidence_id="ev-oracle-jewels",
            source="oracle",
            source_ref="crown_jewel_hints",
            claim=f"Crown-jewel hints: {', '.join(str(j) for j in jewels[:3])}",
            weight=WEIGHT_CROWN_JEWELS,
        ))

    return pieces


def _family_name(family: Any) -> str:
    """Family keys may be Family enums or plain strings — read statically."""
    try:
        return family.value
    except AttributeError:
        return str(family)


def evidence_from_prism(patterns: list[Any]) -> list[ThesisEvidence]:
    """Extract evidence from Prism-shaped pattern matches.

    Each pattern's confidence becomes its evidence weight; the
    archetype name and typical families ride along for the builder.
    """
    pieces: list[ThesisEvidence] = []
    for i, pattern in enumerate(patterns or []):
        confidence = float(pattern.confidence or 0.0)
        if confidence <= 0.0:
            continue
        archetype = pattern.archetype_name
        families = pattern.typical_families or {}
        family_names = ", ".join(sorted(
            _family_name(f) for f in families.keys())) or "none"
        pieces.append(ThesisEvidence(
            evidence_id=f"ev-prism-{i}",
            source="prism",
            source_ref=str(archetype),
            claim=f"Archetype match '{archetype}' (confidence "
                  f"{confidence:.2f}) — typical families: {family_names}",
            weight=confidence,
        ))
    return pieces


def evidence_from_economist(economist: Any) -> list[ThesisEvidence]:
    """Extract the Economist's value-side evidence (always present).

    Even a bare Economist score is one piece of evidence — the
    build's MIN_EVIDENCE floor exists so that a lone Economist score
    can NEVER carry a thesis alone.
    """
    tier = economist.tier
    payout = float(economist.payout_potential or 0.0)
    return [ThesisEvidence(
        evidence_id="ev-economist",
        source="economist",
        source_ref=str(tier),
        claim=f"Economist tier {tier}: payout potential {payout:.2f}",
        weight=WEIGHT_ECONOMIST,
    )]
