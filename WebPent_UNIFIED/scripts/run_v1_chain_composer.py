#!/usr/bin/env python3
"""V-1 — THE CHAIN COMPOSER (TC-3, Dispatch #041 §2). DoD runner.

DoD: one chain proposed AND executed to a promoted chained finding on a
lab target — or the honest deferral with the precise gap.

Sequence (all through the NORMAL spine — full chain, full gates):
  1. Standalone finding A: INFO_DISCLOSURE on the chain lane's debug
     registry (lcs2/v1 engagement `v1_disc`) -> CONFIRMED -> PROMOTED.
  2. Standalone finding B: IDOR on the document object endpoint
     (engagement `v1_idor`, M4 two-principal) -> CONFIRMED -> PROMOTED.
  3. The composer ingests BOTH promoted findings -> the deterministic
     proposer (llm_authority=false) emits the cross-account-exfiltration
     proposal with the dependency contract.
     ANTI-FAKE CHECK: proven_chains() is EMPTY at this point — a proposed
     chain never surfaces.
  4. build_chain_hypothesis: the step-2 candidate path is DERIVED from
     the step-1 response (the hidden document id) with a dependency
     digest; executed through the spine on a fresh engagement (`v1_chain`)
     -> the chained finding CONFIRMED -> PROMOTED.
  5. record_execution -> chain PROVEN (digest match) -> proven_chains()
     surfaces EXACTLY the proven chain with both leg refs.
  6. Anti-fake negatives (NATIVE — TC-4 C4): the refutation leg runs
     through its OWN composer — the vulnerable lane's proposal is PROVEN
     by step 5 and by design cannot be rebuilt (a proven chain is never
     re-executed; build_chain_hypothesis refuses non-PROPOSED
     proposals), so the neg lane ingests the same two promoted findings
     into a FRESH composer, builds its own still-PROPOSED proposal, and
     grounds the hypothesis in the PATCHED lane's own observation — the
     registry as the patched lane itself serves it (owner/admin surface;
     the acting principal is refused, which IS the patch).  The chain
     step on the PATCHED lane (engagement `v1_chain_neg`) -> REFUTED ->
     recorded REFUTED on the neg composer, absent from proven_chains();
     a guessed step-2 value fails the digest and can never reach PROVEN
     (pinned by unit tests).
  7. The impact-uplift receipt: the chain hypothesis scored by the REAL
     EVScheduler at chain_potential 1.0 vs 1.8.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from tests.lab.lcs2_sweep_support import ensure_runtime_env  # noqa: E402

ensure_runtime_env()

from webpent.production.chain_composer import (  # noqa: E402
    ChainComposer,
    ChainFinding,
    chain_ev_uplift_report,
)
from webpent.shared.engagement_scope import (  # noqa: E402
    clear_engagement_target_hosts,
)

OUT = ROOT.parent / "download" / "vision_v1"
OUT.mkdir(parents=True, exist_ok=True)
NOW = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
log_lines: list[str] = []


def log(msg: str) -> None:
    print(msg)
    log_lines.append(msg)


def _run_decision(engagement_id: str, url: str, hyp: dict) -> dict:
    """One AVI decision through the AUTHORIZED factory path."""
    from tests.lab.lcs2_sweep_support import (
        make_orchestrator, seal_principals, stages_delta,
    )
    from webpent.production.autonomous_validation_v1 import (
        AutonomousValidationIntelligence,
    )

    orch = make_orchestrator(engagement_id, url)
    seal_principals(engagement_id, url)
    orch.run_deep_recon(target_url=url, observed=[
        {"path": "/api/", "method": "GET", "status_code": 200,
         "body": "{}", "headers": {}}])
    avi = AutonomousValidationIntelligence(orch)
    cursor = len(avi.trace.stages)
    avi._run_one_decision(target_url=url, hypotheses=[hyp], decision_number=1)
    v_proof, p_proof = stages_delta(avi.trace.stages[cursor:])
    return {"orch": orch, "avi": avi,
            "validator_outcome": (v_proof or {}).get("outcome"),
            "promotion_decision": ((p_proof or {}).get("decision") or "").upper(),
            "gates_failed": (p_proof or {}).get("gates_failed") or []}


def _authorized_read(url: str, path: str, headers: dict,
                     engagement_id: str = "v1_materialize") -> dict:
    """Chain-materialization read through the AUTHORIZED spine path
    (ScopeLaw + ToolBoundary; in-scope loopback).  Each read gets its own
    engagement id — the spine fails closed on config drift for a reused
    engagement (different target ports = different configs)."""
    from tests.lab.lcs2_sweep_support import allow_loopback, make_orchestrator

    tok = allow_loopback()
    try:
        orch = make_orchestrator(engagement_id, url)
        resp = orch.execute_real_request(
            method="GET", target_url=f"{url}{path}", headers=headers)
        body = resp.get("response_body", resp.get("body", ""))
        try:
            return json.loads(body) if isinstance(body, str) else dict(body)
        except (TypeError, ValueError):
            return {"_raw": str(body)[:2000]}
    finally:
        clear_engagement_target_hosts(tok)


def standalone_disclosure_finding(url: str) -> tuple[dict, ChainFinding | None]:
    hyp = {"id": "v1_disc_info", "vulnerability_class": "INFO_DISCLOSURE",
           "api_type": "rest", "path": "/api/admin/debug",
           "information_value": 0.9, "engagement_id": "v1_disc",
           "requests": {
               "baseline": {"method": "GET", "path": "/api/health",
                            "headers": {}},
               "candidate": {"method": "GET", "path": "/api/admin/debug",
                             "headers": {"X-User": "User_A"}},
               "negative_control": {"method": "GET", "path": "/api/version",
                                    "headers": {}}}}
    result = _run_decision("v1_disc", url, hyp)
    log(f"  [A] INFO_DISCLOSURE: validator={result['validator_outcome']} "
        f"promotion={result['promotion_decision']} "
        f"gates_failed={result['gates_failed']}")
    finding = None
    if (result["validator_outcome"] == "CONFIRMED"
            and result["promotion_decision"] == "PROMOTED"):
        observed = _authorized_read(url, "/api/admin/debug",
                                    {"X-User": "User_A"},
                                    engagement_id="v1_materialize_s1")
        finding = ChainFinding(
            finding_id="v1_finding_disclosure", family="INFO_DISCLOSURE",
            path="/api/admin/debug", engagement_id="v1_disc",
            promoted_at=NOW,
            evidence_ref=f"proof:v1_disc:info_disclosure:{NOW}",
            observed=observed)
    return result, finding


def standalone_idor_finding(url: str) -> tuple[dict, ChainFinding | None]:
    def _spec(actor: str, doc: str, role: str) -> dict:
        return {"method": "GET", "path": f"/api/documents/{doc}",
                "headers": {"X-User": actor}, "principal_alias": actor,
                "principal_role": role}
    hyp = {"id": "v1_idor_pub", "vulnerability_class": "IDOR",
           "api_type": "rest", "path": "/api/documents/",
           "information_value": 0.9, "resource_owner": "User_B",
           "engagement_id": "v1_idor",
           "requests": {
               "baseline": _spec("User_B", "DOC-B-PUB", "owner"),
               "candidate": _spec("User_A", "DOC-B-PUB", "foreign-user"),
               "negative_control": _spec("User_A", "DOC-NO-SUCH-999",
                                         "foreign-user")}}
    result = _run_decision("v1_idor", url, hyp)
    log(f"  [B] IDOR: validator={result['validator_outcome']} "
        f"promotion={result['promotion_decision']} "
        f"gates_failed={result['gates_failed']}")
    finding = None
    if (result["validator_outcome"] == "CONFIRMED"
            and result["promotion_decision"] == "PROMOTED"):
        finding = ChainFinding(
            finding_id="v1_finding_idor", family="IDOR",
            path="/api/documents/{doc_id}", engagement_id="v1_idor",
            promoted_at=NOW,
            evidence_ref=f"proof:v1_idor:idor:{NOW}",
            observed={"covered_object": "DOC-B-PUB"},
            resource_owner="User_B",
            covered_object_ids=["DOC-B-PUB"])
    return result, finding


def main() -> int:
    from tests.lab.chain_lab_target import start_chain_lab_server
    from tests.lab.lcs2_sweep_support import allow_loopback

    log(f"=== V-1 CHAIN COMPOSER — {NOW} — mode: LAB-FIXTURE (chain lane) ===")
    tok = allow_loopback()
    try:
        server, url = start_chain_lab_server(vulnerable=True)
        try:
            res_disc, finding_disc = standalone_disclosure_finding(url)
            res_idor, finding_idor = standalone_idor_finding(url)
        finally:
            server.should_exit = True

        composer = ChainComposer()
        proposals: list = []
        if finding_disc:
            proposals += composer.ingest(finding_disc)
        if finding_idor:
            proposals += composer.ingest(finding_idor)
        anti_fake_before = composer.proven_chains()
        deterministic = all(not p.llm_authority for p in proposals)
        log(f"  [3] proposals={len(proposals)} "
            f"(deterministic={deterministic}) "
            f"— proven_chains() BEFORE execution: {len(anti_fake_before)} (must be 0)")

        chained_result = None
        proven = []
        if proposals:
            proposal = proposals[0]
            step1_observed = finding_disc.observed
            chain_hyp = composer.build_chain_hypothesis(
                proposal.chain_id, engagement_id="v1_chain",
                step1_observed=step1_observed)
            if chain_hyp is None:
                log("  [4] chain hypothesis UNBUILDABLE (extraction failed)")
            else:
                log(f"  [4] chain hypothesis built: candidate path="
                    f"{chain_hyp['requests']['candidate']['path']} "
                    f"selected={chain_hyp['chain_metadata']['selected_object_id']} "
                    f"excluded={chain_hyp['chain_metadata']['excluded_object_ids']} "
                    f"(digest {proposal.dep_digest[:12]}…)")
                server2, url2 = start_chain_lab_server(vulnerable=True)
                try:
                    chained_result = _run_decision("v1_chain", url2, chain_hyp)
                    # semantic materialization MUST happen while the lane is
                    # live — the owner/viewer gate needs the real response.
                    used = chain_hyp["requests"]["candidate"]["path"].rsplit("/", 1)[-1]
                    step2_body = _authorized_read(
                        url2, f"/api/documents/{used}", {"X-User": "User_A"},
                        engagement_id="v1_materialize_s2")
                finally:
                    server2.should_exit = True
                log(f"  [4] CHAIN STEP: validator={chained_result['validator_outcome']} "
                    f"promotion={chained_result['promotion_decision']} "
                    f"gates_failed={chained_result['gates_failed']}")
                log(f"  [5] semantic materialization: owner={step2_body.get('owner')} "
                    f"viewer={step2_body.get('viewer')} "
                    f"classification={step2_body.get('classification')}")
                record = composer.record_execution(
                    proposal.chain_id,
                    step1_promoted=finding_disc is not None,
                    step2_validator_outcome=chained_result["validator_outcome"],
                    step2_promotion_decision=chained_result["promotion_decision"],
                    step2_used_value=used,
                    step2_response_body=step2_body,
                    proof_ref=f"proof:v1_chain:chained_idor:{NOW}")
                log(f"  [5] chain status after execution: {record.status}")

        # [6] anti-fake negative — NATIVE refutation leg (TC-4 C4).
        # The vulnerable lane's proposal is PROVEN at this point; asking
        # ITS composer to rebuild would return None (a proven chain is
        # never re-executed) and the leg would silently skip — the exact
        # defect V15-V flagged.  Fix: the neg lane builds its OWN proposal
        # (fresh composer, same two promoted findings, still PROPOSED)
        # and grounds it in the PATCHED lane's OWN observation — the
        # registry as the patched lane itself serves it to the owner/admin
        # principal (the acting principal is refused on this lane, which
        # is the patch under test).  The refutation is therefore
        # attributable to the patch, not to a fabricated step-1 payload.
        neg_result = None
        neg_record = None
        if proposals and finding_disc is not None and finding_idor is not None:
            server3, url3 = start_chain_lab_server(vulnerable=False)
            try:
                neg_observed = _authorized_read(
                    url3, "/api/admin/debug", {"X-User": "User_B"},
                    engagement_id="v1_materialize_neg")
                neg_composer = ChainComposer()
                neg_composer.ingest(finding_disc)
                neg_proposals = neg_composer.ingest(finding_idor)
                if neg_proposals:
                    neg_hyp = neg_composer.build_chain_hypothesis(
                        neg_proposals[0].chain_id,
                        engagement_id="v1_chain_neg",
                        step1_observed=neg_observed)
                else:  # pragma: no cover — the pair always proposes
                    neg_hyp = None
                if neg_hyp is not None:
                    neg_result = _run_decision("v1_chain_neg", url3, neg_hyp)
                    used_neg = neg_hyp["requests"]["candidate"]["path"].rsplit("/", 1)[-1]
                    neg_record = neg_composer.record_execution(
                        neg_proposals[0].chain_id,
                        step1_promoted=finding_disc is not None,
                        step2_validator_outcome=neg_result["validator_outcome"],
                        step2_promotion_decision=neg_result["promotion_decision"],
                        step2_used_value=used_neg,
                        step2_response_body=None,
                        proof_ref=f"proof:v1_chain_neg:refuted:{NOW}")
                else:
                    log("  [6] NEG hypothesis UNBUILDABLE from the patched "
                        "lane's own observation (extraction failed)")
            finally:
                server3.should_exit = True
            if neg_result is not None:
                log(f"  [6] PATCHED-lane chain step: validator="
                    f"{neg_result['validator_outcome']} promotion="
                    f"{neg_result['promotion_decision']} "
                    f"neg_composer_status={neg_record.status if neg_record else 'N/A'} "
                    f"(honest refutation, recorded)")
            else:
                log("  [6] PATCHED-lane refutation leg DID NOT RUN — "
                    "this must never happen silently")

        proven = composer.proven_chains()
        uplift = chain_ev_uplift_report({
            "vulnerability_class": "IDOR", "recon_signal_matches": 2,
            "estimated_cost": 6, "estimated_llm_calls": 1})
        log(f"  [7] EV uplift receipt: {uplift}")
        log(f"  [5] proven_chains(): {len(proven)} "
            f"(anti-fake: unproven proposals structurally absent)")
        log(f"=== V-1 CHAIN COMPOSER: "
            f"{'CHAIN PROVEN' if proven else 'DEFERRED'} ===")

        verdict = {
            "item": "V-1 Chain Composer", "mode": "LAB-FIXTURE (chain lane)",
            "emitted_at": NOW,
            "engagement_ids": ["v1_disc", "v1_idor", "v1_materialize",
                               "v1_chain", "v1_chain_neg"],
            "standalone_findings": {
                "info_disclosure": {k: v for k, v in res_disc.items()
                                    if k not in ("orch", "avi")},
                "idor": {k: v for k, v in res_idor.items()
                         if k not in ("orch", "avi")}},
            "proposal_register": composer.proposal_register(),
            "anti_fake": {
                "proven_before_execution": len(anti_fake_before),
                "must_be_zero": len(anti_fake_before) == 0,
                "patched_lane_result": None if not neg_result else {
                    "validator_outcome": neg_result["validator_outcome"],
                    "promotion_decision": neg_result["promotion_decision"],
                    "neg_composer_status": (neg_record.status if neg_record
                                            else None),
                    "native": True},
                "refutation_ran_natively": neg_result is not None},
            "proven_chains": proven,
            "ev_uplift": uplift,
            "cycle_log": log_lines,
        }
        (OUT / "chain_composer_verdict.json").write_text(
            json.dumps(verdict, indent=2))
        # DoD: the chain PROVEN through the full spine AND the refutation
        # leg ran natively on the patched lane (TC-4 C4 — it must never
        # silently skip again) AND the anti-fake pre-execution check held.
        neg_ok = (neg_result is not None
                  and neg_result["promotion_decision"] != "PROMOTED")
        dod_ok = (bool(proven) and len(anti_fake_before) == 0 and neg_ok)
        log(f"=== V-1 DoD: {'SATISFIED' if dod_ok else 'NOT SATISFIED'} ===")
        return 0 if dod_ok else 1
    finally:
        clear_engagement_target_hosts(tok)


if __name__ == "__main__":
    raise SystemExit(main())
