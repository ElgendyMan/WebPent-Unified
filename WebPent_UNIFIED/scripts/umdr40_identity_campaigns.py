#!/usr/bin/env python3
"""UM-DR-40 RC-4 — the identity before/after campaign proof.

Runs the SAME production campaign entrypoint
(``umdr37_production_campaigns.run_campaign`` →
``webpent.cli.unified_hunt.run_unified_hunt``) twice per arm:

* **baseline**: every identity capability OFF (the fail-closed
  default — the shipped behavior);
* **enabled**: the same campaign run inside
  ``identity_campaign_activation`` (the RC-4 per-campaign
  mechanism, all four capabilities ON).

The proof RC-4 demands: with the capabilities enabled, the campaign
demonstrates identity output from the REGISTERED node —
``principals_observed > 0`` measured by the production discovery
funnel — while the baseline arm shows the identity channels empty,
and the request/time budget impact of the difference is recorded.

Honest notes: the identity layer is advisory — it must NOT change
the confirmed-finding verdicts (the guard remains the sole
authority); the after-arm is expected to match the baseline on
confirmed findings and to differ on the identity channels and the
measured cost.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(REPO / "src"))

from umdr37_production_campaigns import run_campaign  # noqa: E402

from webpent.production.identity_activation import (  # noqa: E402
    activation_snapshot,
    budget_impact_record,
    identity_campaign_activation,
)

BASELINE_RUNS = 2
ENABLED_RUNS = 2

OUT_DIR = REPO.parents[0] / "deliverables" / "umdr40"


def _metrics(run: dict) -> dict:
    """The per-run comparison row (the campaign record's own
    vocabulary — no re-derivation)."""
    discrepancies = run.get("measurement_discrepancies") or {}
    return {
        "campaign_id": run.get("campaign_id"),
        "elapsed_s": run.get("elapsed_s"),
        "lab_request_count": run.get("lab_request_count"),
        "findings_confirmed": run.get("findings_confirmed"),
        "findings_total": run.get("findings_total"),
        "funnel_principals_observed": discrepancies.get(
            "funnel_principals_observed"),
        "differential_questions": (
            run.get("authorization_relationships") or {}
        ).get("differential_questions"),
        "authorization_observations": (
            run.get("authorization_relationships") or {}
        ).get("authorization_observations"),
        "identities_observed": run.get("identities_observed"),
        "guard_verdicts": run.get("guard_verdicts"),
        "source_commit": run.get("source_commit"),
        "tree_sha": run.get("tree_sha"),
        "tree_clean": run.get("tree_clean"),
    }


def main() -> int:
    started = datetime.now(timezone.utc).isoformat()
    baseline_runs: list[dict] = []
    for index in range(1, BASELINE_RUNS + 1):
        print(f"[umdr40] baseline run {index}/{BASELINE_RUNS} …",
              flush=True)
        baseline_runs.append(run_campaign(index))

    enabled_runs: list[dict] = []
    for index in range(1, ENABLED_RUNS + 1):
        print(f"[umdr40] identity-enabled run {index}/{ENABLED_RUNS} …",
              flush=True)
        with identity_campaign_activation() as activation:
            enabled_runs.append(run_campaign(
                BASELINE_RUNS + index))
            enabled_runs[-1]["identity_activation"] = activation[
                "snapshot"]

    baseline_metrics = [_metrics(r) for r in baseline_runs]
    enabled_metrics = [_metrics(r) for r in enabled_runs]

    impacts = [
        budget_impact_record(b, e)
        for b, e in zip(baseline_runs, enabled_runs)
    ]

    # the RC-4 proof per the 39 register's acceptance verbatim: "a
    # campaign demonstrates principals_observed > 0 from the
    # registered node". differential_questions is REPORTED as a
    # measurement, not required: the advisory matrix asks questions
    # only when the observed authorization evidence actually differs
    # across principals (this lab's symmetric matrix honestly yields
    # zero). Missing measurements = not proven, never assumed.
    enabled_proves = all(
        isinstance(m["funnel_principals_observed"], int)
        and m["funnel_principals_observed"] > 0
        for m in enabled_metrics)
    baseline_empty = all(
        (m["funnel_principals_observed"] or 0) == 0
        and (m["differential_questions"] or 0) == 0
        for m in baseline_metrics)
    verdicts_stable = all(
        b.get("guard_verdicts") == e.get("guard_verdicts")
        for b, e in zip(baseline_metrics, enabled_metrics))

    combined = {
        "schema": "umdr40-identity-campaigns/v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "started_at_utc": started,
        "mission": "UM-DR-40 RC-4 (per-campaign identity activation)",
        "entrypoint": ("umdr37_production_campaigns.run_campaign -> "
                       "webpent.cli.unified_hunt.run_unified_hunt "
                       "(no_llm=True, auto_approve=True)"),
        "arms": {
            "baseline": {
                "runs": BASELINE_RUNS,
                "capabilities": "all four identity flags OFF "
                                "(fail-closed default)",
                "snapshot": activation_snapshot(),
            },
            "enabled": {
                "runs": ENABLED_RUNS,
                "capabilities": "all four identity flags ON via "
                                "identity_campaign_activation",
            },
        },
        "baseline_metrics": baseline_metrics,
        "enabled_metrics": enabled_metrics,
        "budget_impact": impacts,
        "rc4_proof": {
            "acceptance_text": "a campaign demonstrates "
                               "principals_observed > 0 from the "
                               "registered node (39 register RC-4)",
            "enabled_runs_have_principals_observed": enabled_proves,
            "baseline_runs_identity_channels_empty": baseline_empty,
            "guard_verdicts_unchanged_across_arms": verdicts_stable,
            "proven": bool(enabled_proves and baseline_empty),
            "differential_questions_note": (
                "reported, not required: the advisory matrix asks "
                "questions only when observed authorization evidence "
                "differs across principals"),
        },
        "notes": (
            "The identity layer is advisory: the causal guard stays "
            "the sole verdict authority, so the confirmed findings "
            "and guard verdicts are expected to match across arms; "
            "the difference must be the identity channels and the "
            "recorded budget impact."),
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "IDENTITY_CAMPAIGN_RESULTS.json"
    out.write_text(json.dumps(combined, indent=2, default=str) + "\n",
                   encoding="utf-8")
    print(f"[umdr40] {out}")
    print(f"[umdr40] RC-4 proof: {combined['rc4_proof']}")

    # the human before/after report
    lines = [
        "# UM-DR-40 — Identity Activation Before/After Campaign Report",
        "",
        f"Generated {combined['generated_at_utc']} — production "
        "entrypoint, identical lab, identical configuration, the "
        "only difference being the per-campaign identity activation.",
        "",
        "## The arms",
        "",
        f"* **Baseline** ({BASELINE_RUNS} runs): every identity "
        "capability OFF — the shipped fail-closed default.",
        f"* **Enabled** ({ENABLED_RUNS} runs): the same campaign "
        "inside `identity_campaign_activation` (all four "
        "capabilities ON; RC-4's per-campaign mechanism).",
        "",
        "## Results (per run)",
        "",
        "| arm | run | principals (funnel) | differential questions | "
        "auth observations | requests | elapsed s | confirmed |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for arm, metrics in (("baseline", baseline_metrics),
                         ("enabled", enabled_metrics)):
        for m in metrics:
            lines.append(
                f"| {arm} | {str(m['campaign_id'])[:24]} | "
                f"{m['funnel_principals_observed']} | "
                f"{m['differential_questions']} | "
                f"{m['authorization_observations']} | "
                f"{m['lab_request_count']} | "
                f"{round(m['elapsed_s'], 1) if m['elapsed_s'] else '?'} | "
                f"{m['findings_confirmed']} |")
    proof = combined["rc4_proof"]
    lines += [
        "",
        "## The RC-4 proof, stated honestly",
        "",
        f"* Enabled runs demonstrate principals_observed > 0 from "
        f"the registered node (the register's acceptance, verbatim): "
        f"**{proof['enabled_runs_have_principals_observed']}**",
        f"* Baseline runs show the identity channels empty: "
        f"**{proof['baseline_runs_identity_channels_empty']}**",
        f"* Guard verdicts unchanged across arms (advisory-only "
        f"contract): "
        f"**{proof['guard_verdicts_unchanged_across_arms']}**",
        f"* **RC-4 PROVEN: {proof['proven']}**",
        "",
        "## Budget impact (recorded per RC-4)",
        "",
    ]
    for impact in impacts:
        lines.append(
            f"* `{impact['baseline_campaign_id']}` → "
            f"`{impact['enabled_campaign_id']}`: "
            f"{impact['deltas']} — identity counts: "
            f"{impact['baseline_identity_counts']} → "
            f"{impact['enabled_identity_counts']}")
    lines += [
        "",
        "Machine record: `IDENTITY_CAMPAIGN_RESULTS.json` (full "
        "campaign records are retained inside it).",
        "",
    ]
    report = OUT_DIR / "IDENTIFICATION_BEFORE_AFTER_REPORT.md"
    report.write_text(chr(10).join(lines), encoding="utf-8")
    print(f"[umdr40] {report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
