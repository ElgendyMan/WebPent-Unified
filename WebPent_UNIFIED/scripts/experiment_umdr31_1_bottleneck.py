#!/usr/bin/env python3
"""UM-DR-31.1 Phase C — the hypothesis-to-execution gap, measured.

Reproduces the audit's Experiment B/C observation on the REAL code and
extends it: what score does a research-origin hypothesis actually get
from the unchanged strategist formula, and what happens to it?
"""
from __future__ import annotations

import json
import sys

sys.path.insert(0, "src")

from webpent.config.settings import get_settings


def main() -> int:
    s = get_settings()
    s.enable_adaptive_research_loop = True

    from webpent.production.adaptive_research import (
        generate_research_hypotheses,
        research_signal_inventory,
    )

    state = {
        "target_id": "t",
        "engagement_id": "e",
        "base_url": "https://lab.example",
        "target_url": "https://lab.example",
        "allowed_endpoints": ["/api/"],
        "is_production": False,
        "campaign_ledger": {"entries": [
            {"key": "idor:vaults", "status": "not_scanned"},
        ]},
        "invariant_review": [{
            "target_id": "t", "engagement_id": "e",
            "observation_fingerprint": "ab12cd34ef56ab12",
            "invariant": "authorization_context_must_be_present",
            "status": "candidate_violation",
            "reason": "cross-identity transition lacks identity context",
            "evidence_refs": ["crawl:seal"],
        }],
        "workflow_observations": [{
            "fingerprint": "ab12cd34ef56ab12",
            "endpoint": "https://lab.example/api/vaults/vlt_1/seal",
            "method": "POST",
            "from_state": "open", "to_state": "sealed",
            "authorization_boundary": "cross_identity",
            "scope_decision": "allowed",
            "evidence_refs": ["crawl:seal"],
        }],
        "hypotheses": [],
    }

    new, detail = generate_research_hypotheses(state, max_new=12)
    print("=== generated ===")
    print(json.dumps(detail, indent=1, default=str)[:600])
    for h in new:
        print(f"- id={str(h.id)[:12]} origin={h.origin} class={h.vuln_class} "
              f"conf={h.confidence_score} info_gain={h.info_gain} cost={h.estimated_cost} "
              f"det={h.deterministic_match}")

    # the strategist's own ranking (unchanged formula)
    from webpent.shared.prioritization import (
        PrioritizationAction,
        rank_open_hypotheses,
        recommend_action,
    )
    pool = list(new)
    ranked = rank_open_hypotheses(pool, state)
    print("\n=== strategist ranking (unchanged formula) ===")
    for h, score in ranked:
        action, _s2, rule = recommend_action(h, state)
        print(f"- {str(h.id)[:12]} class={h.vuln_class} score={score:.4f} -> {action}")
        print(f"    rule: {rule[:200]}")

    # info-gain presence check: does the ranking consume info_gain?
    print("\n=== info_gain vs score correlation (same formula) ===")
    for h, score in ranked:
        print(f"- info_gain={h.info_gain} score={score:.4f}")

    from webpent.shared.prioritization import score_hypothesis
    # sensitivity probe: bump info_gain to its ceiling and re-score
    probe = ranked[0][0]
    base = score_hypothesis(probe, state)
    probe.info_gain = 1.0
    bumped = score_hypothesis(probe, state)
    print(f"\ninfo_gain 0.x->1.0 score delta on the same hypothesis: {base:.4f} -> {bumped:.4f} "
          f"(delta={bumped - base:+.4f}) — does the formula consume info_gain?")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
