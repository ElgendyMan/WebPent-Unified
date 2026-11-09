#!/usr/bin/env python3
"""Re-freeze frozen_modules.sha256 for the UM-DR-26 window (2026-11-06)
per the DR-009 protocol. DRIFT_REGISTER entry: UM-DR-26.

The window is the EXECUTED PHASE 2 of the UM-DR-25 red-team plan (the
operator's "نفذ جميع المقترحات" work order): the recorded 67-failure
behavioral-rework plan, executed to completion. Each frozen-tree change
below is verified by its recovered test family BEFORE this refreeze
(the UM-DR-25 phase-2 red baseline was 67 failures across the families
listed; every family is green post-fix):

  - src/webpent/config/settings.py
    (UM-DR-26: three more undeclared settings fields discovered —
    enable_coverage_scheduling (planner advisory), enable_benchmark_gate
    (vulnbox harness) and cache_key_max_endpoints (sweep window) — the
    UM-DR-09/25 settings-drift class again; declared with fail-closed
    defaults. Refutation + safety + planner + vulnbox families green.)
  - src/webpent/recon/identity_discovery.py
    (UM-DR-26: the r6c S1 TWO-BRANCH redesign — jwt_claims branch
    (attempted only when supplied, winner s1_jwt_claims, source_url
    jwt://claims) and login_body branch (always attempted, payload_type
    recorded, bid/cart_id keys are RESOURCE SEEDS never identity,
    email-matched user-identity keys resolve with ZERO probes via the
    winner s1_login_body_mining); per-branch attempt records
    {stage,branch,attempted,resolved,resolved_key,payload_type,
    resource_seed_count,resource_seed_names}; S2 one-record-per-probe
    with result values (http_status/spa_catch_all_html/
    anonymous_shape_observed/json_identity_resolved); S3 self-heal runs
    even without transport support (trailing-slash path variant),
    winner s3_transport_self_heal; probe window clamped to 16 with an
    8-slot hint cap; attempt records capped 48 / serialized 32;
    exhaustion carries mined resource seeds. 14 r6c tests + 14 R9 tests
    green, test_identity_discovery.py consumers green.)
  - src/webpent/recon/principal_provisioning.py
    (UM-DR-26: the r6c identity_resolution rollup (attempted as bool,
    winner_strategies alias->winner map with None for unresolved,
    s4_honest_exhaustion count, exhausted_principals retained) exposed
    as a property and consumed by as_dict; the r9 D3 record —
    requested/detected/executed auth-type triple, never silently
    relabelled; the DETECTED strategy stays reachable as a fallback
    after the requested one fails. 14 r6c + 14 R9 tests green.)
  - src/webpent/recon/login_executor.py
    (UM-DR-26: the r9 D1-D4 validation rework — the validation-surface
    walk (configured -> bounded identity window (/whoami first) -> root,
    login URL structurally excluded, literal "None" refused so
    <base>/None can never render); verdicts session_validated /
    validation_inconclusive (2xx non-JSON) / anonymous-shape continue /
    validation_surface_unavailable (all-exception walk) /
    session_validation_rejected; status_code stays None without a login
    response (the r8 conflation defect); the D2 rejected-operator-token
    fall-through to a real credential login with the honest reason
    chain; runtime-only response_payload + identity_claims (B1 hygiene,
    never serialized); per-surface validation_probes. 14 r6c tests
    green + consumer suites green.)
  - src/webpent/shared/rate_governor.py
    (UM-DR-26: the kill-switch gate wired BEFORE any host slot is
    consumed — an engaged switch (flag on) aborts the permit with
    reason kill_switch_engaged leaving the per-host accounting
    untouched; flag-off behaviour byte-identical. Safety-governor
    integration family green.)
  - src/webpent/llm_researcher/providers/base.py
    (UM-DR-26: the LLM funnel boundary enforces the spend cap — usage
    recorded against the active engagement and, at the cap, the
    completion is replaced by the LLM_SPEND_CAP_REACHED error response
    (fail closed, spend preserved for accounting); flag-off unchanged.
    Safety-governor family green.)
  - src/webpent/recon/autonomous_crawler.py
    (UM-DR-26: the robots double gate actually consulted — a
    respect_robots=False config lifts only when the settings flag is OFF
    (legacy posture) or the active engagement is allowlisted; otherwise
    the crawler stays robots-respecting (robots_unavailable). Agency
    family green.)
  - src/webpent/safety/agency.py
    (UM-DR-26 wiring fix: _active_engagement_id imported a name
    (active_engagement_id) that target_workspace_context never exported
    — every no-argument call crashed with ImportError and the fail-closed
    wrapper masked it as an unauthorized decision. The engagement now
    derives from the M1b active-workspace identity axis, fail-soft.)
  - src/webpent/safety/request_ledger.py
    (UM-DR-26 wiring fix: the same broken alias in request_ledger —
    every _active_engagement_id() caller crashed; fixed identically.)
  - src/webpent/agents/planner/agent.py
    (UM-DR-26: the deterministic Coverage advisory rides the planner
    prompt ONLY when enable_coverage_scheduling is on AND a crawled
    surface yields cells; flag-off/no-surface prompts byte-identical,
    the state key stays absent, an advisory failure never breaks
    planning. Refutation-learning planner family green.)
  - src/webpent/production/validators.py
    (UM-DR-26: SIX more validator families registered into the canonical
    dispatch — CACHE_POISONING + PROTOTYPE_POLLUTION
    (production/advanced_validators.py) and the four graphql families
    (production/graphql_validator.py) — validators implemented with
    remediation templates but no dispatch entry, the UM-DR-25 family-C
    defect class again; both the import-time seam and the lazy fallback
    route them. Plus: the refutation-learning capture hook
    (maybe_record_validator_outcome) rides run_validator — REFUTED
    recorded, CONFIRMED resets, strictly advisory. Vulnbox + capability
    e2e + refutation families green.)
  - src/webpent/agents/hunter_graph.py
    (UM-DR-26: the r6c replan contract — FIRST-attempt REFUTED routes to
    the replan node once with the REAL verdict/status_category in the
    prompt; same-item (or degenerate) advisories are a NO-OP
    retire-and-advance (the refuted hypothesis is never re-exploited);
    different-item advisories swap with attempt+1 and consume the ladder
    slot; post-swap REFUTED advances without a new replan event; the
    INCONCLUSIVE retry semantics and budget stay byte-unchanged; the
    replan conditional edge gains the complete mapping. 8 r6c tests
    green + hunter-runner consumers green.)
  - src/webpent/recon/browser_farm.py
    (UM-DR-26 wiring fix: the Playwright SSRF guard allowlisted every
    private host EXCEPT the campaign's own declared target — a loopback
    lab target was aborting with ERR_ACCESS_DENIED on every navigation
    (the farm was blind on the very target it was asked to crawl).
    new_page accepts target_hosts and forwards them to
    install_playwright_ssrf_guard; other private hosts stay blocked.)
  - src/webpent/recon/browser_crawler.py
    (UM-DR-26 wiring fix: the crawler passes its own target origin into
    the farm's guard allowlist — one line, the campaign-target half of
    the browser fix. Browser-hunter family green.)
  - src/webpent/service/cost_alerts.py
    (UM-DR-26: a PROMOTED lifecycle notification carries
    confidence_level="Tool-Confirmed" with evidence naming the
    promotion_guard — honoring the M1-B/E-1 provenance contract AND
    un-deadening the promoted-alert path (push_to_webhook only pushes
    the actionable confidence set, so the old always-"Pending" shape
    silently dropped every promoted webhook). Webhook lifecycle family
    green.)
  - src/webpent/shared/preflight.py
    (UM-DR-26: the non-local-bind refusal message carries the r6
    contract's "unsafe {host} bind" phrasing (one-file surgical fix;
    no other test pinned the prior wording). FFUF-preflight family
    green.)

  * NO manifest-path removals; NO scope completions;
  * the result is verified by re-hashing (self-check) before write.

Usage: python scripts/refreeze_manifest_umdr26_phase2.py
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

WINDOW_REMOVED_FILES: list[str] = []
WINDOW_SCOPE_COMPLETION: list[str] = []

WINDOW_CHANGED_FILES = [
    "src/webpent/config/settings.py",
    "src/webpent/recon/identity_discovery.py",
    "src/webpent/recon/principal_provisioning.py",
    "src/webpent/recon/login_executor.py",
    "src/webpent/shared/rate_governor.py",
    "src/webpent/llm_researcher/providers/base.py",
    "src/webpent/recon/autonomous_crawler.py",
    "src/webpent/safety/agency.py",
    "src/webpent/safety/request_ledger.py",
    "src/webpent/agents/planner/agent.py",
    "src/webpent/production/validators.py",
    "src/webpent/agents/hunter_graph.py",
    "src/webpent/recon/browser_farm.py",
    "src/webpent/recon/browser_crawler.py",
    "src/webpent/service/cost_alerts.py",
    "src/webpent/shared/preflight.py",
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    entries: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            print(f"ABORT: unparsable manifest line: {line!r}", file=sys.stderr)
            return 1
        digest, relpath = parts[0], parts[1].strip()
        entries.append((digest, relpath))
        seen.add(relpath)

    for relpath in WINDOW_REMOVED_FILES:
        if relpath not in seen:
            print(f"ABORT: removal target not in manifest: {relpath}", file=sys.stderr)
            return 1
    entries = [(digest, relpath) for digest, relpath in entries if relpath not in set(WINDOW_REMOVED_FILES)]
    seen -= set(WINDOW_REMOVED_FILES)

    for relpath in WINDOW_CHANGED_FILES:
        path = REPO / relpath
        if not path.is_file():
            print(f"ABORT: declared change target missing on disk: {relpath}", file=sys.stderr)
            return 1
        new_digest = sha256(path)
        if relpath in seen:
            entries = [
                (new_digest, item_relpath) if item_relpath == relpath else (digest, item_relpath)
                for digest, item_relpath in entries
            ]
        else:
            entries.append((new_digest, relpath))
            seen.add(relpath)

    for relpath in WINDOW_SCOPE_COMPLETION:
        path = REPO / relpath
        if not path.is_file():
            print(f"ABORT: scope-completion target missing on disk: {relpath}", file=sys.stderr)
            return 1
        if relpath in seen:
            entries = [
                (sha256(path), item_relpath) if item_relpath == relpath else (digest, item_relpath)
                for digest, item_relpath in entries
            ]
        else:
            entries.append((sha256(path), relpath))
            seen.add(relpath)

    rendered = "\n".join(f"{digest}  {relpath}" for digest, relpath in entries) + "\n"
    # Self-check: every declared change re-hashes to what we are about to write.
    for relpath in WINDOW_CHANGED_FILES + WINDOW_SCOPE_COMPLETION:
        expected = sha256(REPO / relpath)
        written = next(digest for digest, item_relpath in entries if item_relpath == relpath)
        if expected != written:
            print(f"ABORT: self-check mismatch for {relpath}", file=sys.stderr)
            return 1
    MANIFEST.write_text(rendered, encoding="utf-8")
    print(f"refroze {len(WINDOW_CHANGED_FILES)} changed + {len(WINDOW_SCOPE_COMPLETION)} scope-completions; manifest entries: {len(entries)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
