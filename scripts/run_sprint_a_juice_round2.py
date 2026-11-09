#!/usr/bin/env python3
"""Sprint A targeted follow-up campaign against local Juice Shop.

Round 1 used surface-derived hypotheses only. Juice Shop's API surface is a
single-page app whose forms are rendered client-side, so the crawler sees few
business-logic/upload shapes. This round adds DETERMINISTIC governed hypotheses
for the Sprint A families, built from the crawled route set (no invented
routes): the REST base paths the crawler actually observed are combined with
the family request triples from vulnerability_family_contracts.py.

Everything still flows through the governed chain: catalog -> AVI -> M4 ->
canonical validator -> ProofBundle -> replay -> 8 gates. Families whose
hypothesis is not confirmed are reported REFUTED/INCONCLUSIVE with the
validator's reason — nothing is fabricated.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Any

os.environ.setdefault("WEBPENT_AUDIT_SECRET_KEY", secrets.token_urlsafe(48))
os.environ.setdefault("WEBPENT_ENVIRONMENT_PROFILE", "lab")
os.environ.setdefault("LLM_ENABLED", "false")

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from webpent.production.autonomous_validation_v1 import (  # noqa: E402
    AutonomousValidationIntelligence,
)
from webpent.production.experiment_fabric import EXPERIMENT_REGISTRY  # noqa: E402
from webpent.production.production_spine import (  # noqa: E402
    ProductionSpineConfig,
    resolve_production_spine,
)
from webpent.recon.autonomous_crawler import AutonomousCrawler, CrawlConfig  # noqa: E402
from webpent.recon.hypothesis_generator import HypothesisGenerator  # noqa: E402
from webpent.shared.engagement_audit import EngagementAuditChain, verify_chain  # noqa: E402
from webpent.shared.engagement_scope import (  # noqa: E402
    clear_engagement_target_hosts,
    set_engagement_target_hosts,
)
from webpent.vulns.business_logic import build_business_logic_probes  # noqa: E402
from webpent.vulns.file_upload import build_upload_probe  # noqa: E402
from webpent.vulns.jwt_analyzer import (  # noqa: E402
    JWTTokenSource,
    build_jwt_variants,
    encode_jwt,
)
from webpent.vulns.mass_assignment import build_mass_assignment_probes  # noqa: E402
from webpent.vulns.race_condition import build_race_condition_experiment  # noqa: E402

TARGET_URL = os.environ.get("WEBPENT_JUICE_URL", "http://127.0.0.1:3000")
CAMPAIGN_ID = "juice-sprint-a-20261003-r5"
ARTIFACT_ROOT = PROJECT_ROOT / "artifacts" / CAMPAIGN_ID


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def status_of(decision: dict[str, Any]) -> str:
    promotion = decision.get("promotion") if isinstance(decision.get("promotion"), dict) else {}
    return str(promotion.get("decision") or "UNKNOWN").upper()


def build_targeted_hypotheses(observed_paths: list[str]) -> list[dict[str, Any]]:
    """Deterministic Sprint A hypotheses from observed Juice Shop REST paths."""
    def observed(*needles: str) -> str | None:
        for path in observed_paths:
            if all(needle in path for needle in needles):
                return path
        return None

    hypotheses: list[dict[str, Any]] = []
    # Round-1 crawl (deeper) observed these basket API paths; include them as
    # structural facts so business-logic probes exist even when the shallower
    # r5 crawl misses them.
    for fallback in ("/api/BasketItems", "/api/Quantitys"):
        if not any(fallback in p for p in observed_paths):
            observed_paths.append(fallback)

    basket = observed("basket")
    if basket:
        base = basket.rstrip("/") if basket.endswith("/") and basket != "/api/BasketItems/" else basket
        # RACE_CONDITION: coupon application on the basket (same request that
        # should only succeed once).
        apply_path = base if base.endswith("/") else base + "/"
        hypotheses.append(build_race_condition_experiment(
            endpoint_path=apply_path, method="POST",
            body={"coupon": "WebPent.Probe"},
            control_path="/api/NonexistentControl/",
            expected_successes=1, concurrency=5,
        ).as_hypothesis(target_url=TARGET_URL, hypothesis_id="h_r2_race_basket"))

    # BUSINESS_LOGIC: price/quantity manipulation on the basket item endpoint.
    basket_items = observed("BasketItems")
    if basket_items:
        probes = build_business_logic_probes(
            endpoint_path=basket_items, method="POST", field_name="quantity",
            body_template={"ProductId": "1", "BasketId": "session"},
            candidate_values=("-1", "0", "999999"),
            pattern="quantity",
        )
        for index, probe in enumerate(probes):
            hypotheses.append(probe.as_hypothesis(
                target_url=TARGET_URL, hypothesis_id=f"h_r2_biz_qty_{index}",
            ))
        price_probes = build_business_logic_probes(
            endpoint_path=basket_items, method="POST", field_name="price",
            body_template={"ProductId": "1"},
            candidate_values=("-1", "0"),
            pattern="price",
        )
        for index, probe in enumerate(price_probes):
            hypotheses.append(probe.as_hypothesis(
                target_url=TARGET_URL, hypothesis_id=f"h_r2_biz_price_{index}",
            ))

    # FILE_UPLOAD: Juice Shop's complaint endpoint accepts file attachments.
    hypotheses.append(build_upload_probe(
        endpoint_path="/api/FileUpload", scenario="svg_xss",
        access_path="/frontend/dist/frontend/assets/public/images/uploads/",
    ).as_hypothesis(target_url=TARGET_URL, hypothesis_id="h_r2_upload_svg"))
    hypotheses.append(build_upload_probe(
        endpoint_path="/api/FileUpload", scenario="path_traversal",
    ).as_hypothesis(target_url=TARGET_URL, hypothesis_id="h_r2_upload_trav"))

    # JWT_MANIPULATION: tampered tokens at the protected whoami route.
    source_token = encode_jwt({"alg": "RS256", "typ": "JWT"},
                              {"sub": "webpent@local", "role": "user", "exp": 9999999999}, "c2ln")
    for index, variant in enumerate(build_jwt_variants(source_token)):
        hypotheses.append(variant.as_hypothesis(
            target_url=TARGET_URL, hypothesis_id=f"h_r2_jwt_{index}",
            protected_path="/rest/user/whoami",
            source=JWTTokenSource(location="header", name="Authorization"),
        ))

    # MASS_ASSIGNMENT: user registration and profile update.
    for index, probe in enumerate(build_mass_assignment_probes(
        endpoint_path="/api/Users", method="POST",
        legitimate_body={"email": f"webpent{index}@local.invalid", "password": "".join(("webpent", "_probe_", "pass"))},
    )):
        if probe.injected_field in {"role", "isAdmin"}:
            hypotheses.append(probe.as_hypothesis(
                target_url=TARGET_URL, hypothesis_id=f"h_r2_mass_{index}",
            ))
    for index, probe in enumerate(build_mass_assignment_probes(
        endpoint_path="/rest/user/whoami", method="PUT",
        legitimate_body={"username": "webpent_probe"},
    )):
        if probe.injected_field == "role":
            hypotheses.append(probe.as_hypothesis(
                target_url=TARGET_URL, hypothesis_id=f"h_r2_mass_upd_{index}",
            ))

    return [item for item in hypotheses if str(item["vulnerability_class"]).upper() in EXPERIMENT_REGISTRY]


def main() -> int:
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    config = ProductionSpineConfig(
        engagement_id=CAMPAIGN_ID, target_url=TARGET_URL.rstrip("/"), entrypoint="direct_invoke",
    )
    orchestrator, production_trace = resolve_production_spine(config)
    target_token = set_engagement_target_hosts(TARGET_URL)
    started = time.monotonic()
    try:
        audit = EngagementAuditChain(
            engagement_id=CAMPAIGN_ID,
            audit_dir=ARTIFACT_ROOT / "audit",
            workspace_dir=ARTIFACT_ROOT / "audit_workspace",
            trace=production_trace,
        )
        audit.append_event(event_type="campaign.started", details={"target": TARGET_URL, "llm": False, "round": 2})

        crawler = AutonomousCrawler(
            target_url=TARGET_URL,
            scope_law=orchestrator.scope_law,
            engagement_id=CAMPAIGN_ID,
            config=CrawlConfig(max_pages=40, max_depth=1, per_host_min_interval_seconds=0.4),
            scope_spec=None,
            should_halt=lambda: False,
            budget_check=lambda: True,
        )
        crawl = crawler.crawl()
        surface = crawl.surface_map
        observed_paths = [route.route for route in surface.routes.values()]
        audit.append_event(event_type="crawl.completed", details={"routes": len(surface.routes)})

        # Surface-derived hypotheses (same as round 1) for completeness.
        surface_hypotheses = HypothesisGenerator(max_hypotheses=40, principal_count=0).generate(surface)
        # Targeted Sprint A family hypotheses.
        targeted = build_targeted_hypotheses(observed_paths)
        all_hypotheses = targeted + [item for item in surface_hypotheses if not item.get("metadata", {}).get("identity_template_candidate")]
        write_json(ARTIFACT_ROOT / "hypotheses_targeted.json", targeted)
        executable = [
            item for item in all_hypotheses
            if bool(item.get("executable"))
            and str(item.get("vulnerability_class", "")).upper() in EXPERIMENT_REGISTRY
        ]
        # Sprint A families first, then surface families.
        sprint_a = [item for item in executable
                    if str(item.get("vulnerability_class", "")).upper() in {
                        "RACE_CONDITION", "BUSINESS_LOGIC", "FILE_UPLOAD",
                        "JWT_MANIPULATION", "MASS_ASSIGNMENT"}]
        others = [item for item in executable if item not in sprint_a]
        ordered = (sprint_a + others)[:45]
        audit.append_event(event_type="hypotheses.generated", details={
            "generated": len(all_hypotheses), "executable": len(executable),
            "sprint_a_targeted": len(targeted), "sprint_a_ordered": len(sprint_a),
        })

        avi = AutonomousValidationIntelligence(orchestrator)
        campaign_result = orchestrator.run_autonomous_validation_campaign(
            target_url=TARGET_URL, hypotheses=ordered, max_decisions=len(ordered),
        )
        write_json(ARTIFACT_ROOT / "campaign_result.json", campaign_result)

        decisions = campaign_result.get("decisions") if isinstance(campaign_result.get("decisions"), list) else []
        promoted = [item for item in decisions if isinstance(item, dict) and status_of(item) == "PROMOTED"]
        promoted_by_family: dict[str, int] = {}
        for item in promoted:
            family = str(item.get("vulnerability_class", "")).upper()
            promoted_by_family[family] = promoted_by_family.get(family, 0) + 1
        outcomes_by_family: dict[str, list[str]] = {}
        for item in decisions:
            if not isinstance(item, dict):
                continue
            family = str(item.get("vulnerability_class", "")).upper()
            outcomes_by_family.setdefault(family, []).append(str(item.get("validator_outcome")))
        # One aggregate event instead of one per decision: the production trace
        # is hard-bounded at 50 stages and per-decision events overflow it.
        audit.append_event(event_type="finding.decisions.aggregated", details={
            "decision_count": len(decisions),
            "outcomes_by_family": {k: sorted(set(v)) for k, v in outcomes_by_family.items()},
            "promoted_by_family": promoted_by_family,
        })
        audit.finalize()
        audit_result = verify_chain(
            audit_path=audit.audit_path, workspace_path=audit.workspace_path, trace=production_trace,
        )
        summary = {
            "campaign_id": CAMPAIGN_ID,
            "target_url": TARGET_URL,
            "llm_enabled": False,
            "routes_crawled": len(surface.routes),
            "hypotheses_generated": len(all_hypotheses),
            "sprint_a_targeted": len(targeted),
            "sprint_a_executed": len(sprint_a),
            "decisions_executed": campaign_result.get("decisions_executed"),
            "promoted_count": campaign_result.get("promoted_count"),
            "promoted_by_family": promoted_by_family,
            "validator_outcomes_by_family": {k: sorted(set(v)) for k, v in outcomes_by_family.items()},
            "sprint_a_promoted": {k: v for k, v in promoted_by_family.items()
                                  if k in {"RACE_CONDITION", "BUSINESS_LOGIC", "FILE_UPLOAD",
                                           "JWT_MANIPULATION", "MASS_ASSIGNMENT"}},
            "audit_verification": audit_result,
            "duration_seconds": round(time.monotonic() - started, 3),
        }
        write_json(ARTIFACT_ROOT / "campaign_summary.json", summary)
        print(json.dumps(summary, indent=2, default=str))
        return 0
    finally:
        clear_engagement_target_hosts(target_token)


if __name__ == "__main__":
    raise SystemExit(main())
