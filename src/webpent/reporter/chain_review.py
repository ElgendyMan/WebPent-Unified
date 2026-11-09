"""webpent.reporter.chain_review — optional chain-review report sections.

Proposal 2 Phase 3 (2026-10-24): a reporter seam for chain status that
keeps the anti-fake rule (FRP-1 for chains) structurally intact:

  * ``proven_chains`` — the ONLY chain surface that may look like an
    outcome, sourced exclusively from
    :meth:`webpent.production.chain_composer.ChainComposer.proven_chains`.
  * ``suggested_chains_under_review`` — emitted ONLY behind
    ``ENABLE_CHAIN_REVIEW_SECTION`` (default False), and ALWAYS labeled as
    unproven advisory material.  It reads the proposal register (and,
    optionally, ``state.causal_chain_candidates``) and can never merge
    into findings, proven chains, or any other outcome surface.

This module is deliberately NOT part of the frozen manifest: it is new,
additive, read-only over the composer and state.
"""
from __future__ import annotations

from typing import Any

_STATUS_PROVEN = "PROVEN"

_ADVISORY_WARNING = (
    "UNPROVEN \u2014 candidates under review only. None of these is a "
    "confirmed finding; none appears in findings or proven chains unless "
    "a registered chain type proves it through the normal pipeline "
    "(real execution + dependency digest + semantic gate).")


def chain_review_sections(
    composer: Any,
    *,
    include_suggested: bool,
    state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the two chain sections for a report.

    ``include_suggested`` is the caller's flag gate (typically
    ``get_settings().enable_chain_review_section``); when False the
    suggested section is STRUCTURALLY ABSENT from the returned dict, not
    merely empty — a report renderer cannot render what it is not given.
    ``state`` optionally contributes ``causal_chain_candidates`` (the
    advisory Phase-1 feed) to the under-review section, each labeled with
    its provenance.
    """
    sections: dict[str, Any] = {
        "proven_chains": list(composer.proven_chains()),
    }
    if not include_suggested:
        return sections
    under_review: list[dict[str, Any]] = []
    try:
        register = composer.proposal_register()
    except Exception:  # noqa: BLE001 — advisory surface, fail-soft
        register = []
    for proposal in register:
        if str(proposal.get("status")) == _STATUS_PROVEN:
            continue  # proven chains already live in their own section
        entry = dict(proposal)
        entry["review_status"] = "under_review_unproven"
        entry["provenance"] = "chain_composer_register"
        under_review.append(entry)
    if isinstance(state, dict):
        for candidate in state.get("causal_chain_candidates") or []:
            if not isinstance(candidate, dict):
                continue
            entry = dict(candidate)
            entry["review_status"] = "under_review_candidate"
            entry["provenance"] = "causal_reasoning_v2"
            under_review.append(entry)
    sections["suggested_chains_under_review"] = {
        "advisory": True,
        "warning": _ADVISORY_WARNING,
        "chains": under_review,
    }
    return sections


def render_chain_review_markdown(sections: dict[str, Any]) -> str:
    """Render the two sections as report-ready markdown.

    The suggested section renders with its advisory warning INLINE —
    a reader can never mistake under-review material for an outcome,
    even if a future renderer drops the surrounding headers.
    """
    lines: list[str] = []
    proven = sections.get("proven_chains") or []
    lines.append(f"## Proven Chains ({len(proven)})")
    if proven:
        for chain in proven:
            lines.append(
                f"- `{chain.get('chain_id', '?')}` "
                f"[{chain.get('chain_type', '?')}] PROVEN "
                f"(legs: {', '.join(chain.get('leg_finding_ids', []) or [])})")
    else:
        lines.append("- None proven in this engagement.")
    suggested = sections.get("suggested_chains_under_review")
    if suggested is not None:
        chains = suggested.get("chains") or []
        lines.append("")
        lines.append(
            f"## Suggested Chains Under Review ({len(chains)}) "
            "\u2014 UNPROVEN, advisory")
        lines.append(f"> {suggested.get('warning', '')}")
        if chains:
            for chain in chains:
                lines.append(
                    f"- `{chain.get('chain_id', '?')}` "
                    f"[{chain.get('chain_type', '?')}] "
                    f"{chain.get('status', chain.get('review_status', '?'))} "
                    f"(provenance: {chain.get('provenance', '?')})")
        else:
            lines.append("- No unproven chain proposals on the register.")
    return "\n".join(lines)


__all__ = ["chain_review_sections", "render_chain_review_markdown"]
