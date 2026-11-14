"""U-FORGE-18 — The Integration Layer.

The bridge that lets ORACLE, PRISM, APEX, DOJO and CAMPAIGN use
THE FORGE's corpus through one surface:

- get_payloads_for_phase(Phase, Target): the campaign's phase asks
  the QueryEngine for the phase's family, the Contextualizer adapts
  each payload to the target's context (from the target's tags),
  and a bundle comes back per payload.
- get_tool_chain_for_payloads(bundles, Target): one APEX ChainStep
  per bundle; the chain carries an explicit advisory note and is
  never executed here.
- enrich_oracle_with_payloads(report): adds a payload_suggestions
  section keyed by family to the ORACLE report document.
- feed_outcome_to_prism(outcome, sink): forwards one outcome record
  to PRISM's learning surface.
- get_payloads_for_scenario(Scenario): DOJO scenarios pull their
  family's payloads.
- explain_payload_choice(payload_id): attribution-aware explanation
  of why a payload is fit for use.

Advisory only (FORGE laws): this layer holds no transport and has
no send/execute — nothing here does anything but select, adapt and
hand over evidence. Zero network.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass

from webpent.apex.tool_chain_builder import ChainStep, ToolChain
from webpent.forge.contextualizer import Contextualizer
from webpent.forge.query_engine import PayloadQueryEngine
from webpent.forge.schemas import (
    Family,
    NormalizedPayload,
    TargetContext,
)

# Campaign families with no forge counterpart: forge Family is NOT a
# superset of the campaign layer's families (corrected 2026-10-20 --
# the previous docstring overclaimed). A phase hunting only these
# families gets no payloads; the set is pinned by test so the
# divergence can never drift silently again.
UNMAPPABLE_CAMPAIGN_FAMILIES = frozenset(
    {"BOLA", "IDOR", "AUTH_BYPASS", "INFO_DISCLOSURE"})


@dataclass(frozen=True)
class PayloadBundle:
    """One corpus payload, adapted for one target context."""
    payload: NormalizedPayload
    adapted_raw: str
    context: str


def _context_from_target(target) -> TargetContext:
    """Build the forge TargetContext from a live_hunter Target's
    dimension tags (tech:php, waf:cloudflare, ...)."""
    tech: list[str] = []
    waf: list[str] = []
    contexts: list[str] = []
    for tag in target.tags or ():
        if ":" not in tag:
            continue
        prefix, _, value = tag.partition(":")
        if prefix == "tech":
            tech.append(value)
        elif prefix == "waf":
            waf.append(value)
        elif prefix == "ctx":
            contexts.append(value)
    if not contexts:
        contexts = ["json"]
    return TargetContext(
        tech_stack=tuple(tech),
        waf_detected=tuple(waf),
        endpoints=[],
        parameters=[],
        response_content_type="",
        param_context=tuple(contexts),
    )


class ForgeIntegration:
    """One advisory surface between THE FORGE and the rest."""

    def __init__(self, indexer, query_engine=None,
                 contextualizer=None) -> None:
        self._indexer = indexer
        self._query = query_engine or PayloadQueryEngine(indexer)
        self._contextualizer = contextualizer or Contextualizer()

    # ------------------------------------------------------------------

    def get_payloads_for_phase(self, phase, target,
                               limit: int = 5) \
            -> list[PayloadBundle]:
        """The campaign's phase asks for its family's payloads,
        adapted to the target's context. Campaign families with no
        forge counterpart (UNMAPPABLE_CAMPAIGN_FAMILIES) yield no
        payloads — documented, never silent-by-accident."""
        context = _context_from_target(target)
        # Direct read, no dynamic attribute resolution: campaign
        # families are enum members (plain strings satisfy the same
        # duck-typed contract and are handled by the isinstance arm).
        families = {
            (h.family.value if isinstance(h.family, enum.Enum)
             else str(h.family)).lower()
            for h in phase.hypotheses}
        bundles: list[PayloadBundle] = []
        seen: set[str] = set()
        for family_name in sorted(families):
            if family_name.upper() in UNMAPPABLE_CAMPAIGN_FAMILIES:
                continue
            try:
                family = Family[family_name.upper()]
            except KeyError:
                continue
            for scored in self._query.find(
                    family=family,
                    target=context,
                    limit=limit):
                payload = scored.payload
                if payload.payload_id in seen:
                    continue
                seen.add(payload.payload_id)
                adapted = self._contextualizer.adapt(
                    payload.raw,
                    context.param_context[0])
                bundles.append(PayloadBundle(
                    payload=payload,
                    adapted_raw=adapted,
                    context=context.param_context[0]))
                if len(bundles) >= limit:
                    return bundles
        return bundles

    def get_tool_chain_for_payloads(self, bundles, target=None) \
            -> ToolChain:
        """One advisory ChainStep per bundle; nothing executes."""
        steps = [
            ChainStep(
                tool_id=f"forge-payload-{bundle.payload.payload_id}",
                capability=bundle.payload.family.value.lower(),
                after=(index - 1 if index else None),
            )
            for index, bundle in enumerate(bundles)
        ]
        return ToolChain(
            chain_id=f"forge-chain-{len(steps)}",
            hypothesis_type=bundles[0].payload.family.value.lower()
            if bundles else "none",
            target=target.url if target else "",
            steps=steps,
            advisory_note=(
                "advisory chain: payload selection only — no step "
                "executes from the integration layer; a human "
                "operator and the approved transport decide use"),
            registry=None,
        )

    def enrich_oracle_with_payloads(self, report):
        """Add a payload_suggestions section keyed by family to an
        ORACLE report document's findings."""
        by_family: dict[str, list[NormalizedPayload]] = {}
        for finding in report.sections.get("findings", []):
            family_name = str(finding.get("family", "")).upper()
            try:
                family = Family[family_name]
            except KeyError:
                continue
            context = TargetContext(tech_stack=(), waf_detected=(),
                                    endpoints=[], parameters=[],
                                    response_content_type="",
                                    param_context=("html_attribute",))
            suggestions = [
                scored.payload
                for scored in self._query.find(
                    family=family, target=context, limit=5)
            ]
            by_family[family.value] = suggestions
        report.sections["payload_suggestions"] = by_family
        return report

    def feed_outcome_to_prism(self, outcome: dict, prism_sink) \
            -> None:
        """Forward one outcome record to PRISM's learning surface."""
        prism_sink(dict(outcome))

    def get_payloads_for_scenario(self, scenario) \
            -> list[NormalizedPayload]:
        """DOJO scenarios pull their family's payloads from the
        corpus."""
        family_name = str(scenario.family).upper()
        try:
            family = Family[family_name]
        except KeyError:
            return []
        context = TargetContext(tech_stack=(), waf_detected=(),
                                endpoints=[], parameters=[],
                                response_content_type="",
                                param_context=("html_attribute",))
        return [scored.payload
                for scored in self._query.find(family=family,
                                               target=context,
                                               limit=20)]

    def explain_payload_choice(self, payload_id: str) -> str:
        """Attribution-aware explanation of a payload's fitness."""
        payload = self._indexer.get_payload(payload_id)
        if payload is None:
            return f"unknown payload: {payload_id}"
        attribution = payload.attribution
        license_name = (attribution.license
                        if attribution else "unknown")
        source = (attribution.original_source
                  if attribution else "unattributed")
        return (
            f"{payload_id}: chosen for family "
            f"{payload.family.value} with quality "
            f"{payload.quality_score:.2f} and license "
            f"{license_name} (source: {source}). Advisory "
            f"selection only; use stays gated by the tool's laws.")
