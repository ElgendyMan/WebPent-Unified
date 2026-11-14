# UM-DR-33 Final Acceptance Report

Window: UM-DR-33 — Researcher Brain & Autonomous Campaign Evolution
Release: WebPent UNIFIED **v0.39.0**
Branch: `umdr33-researcher-brain-autonomous-campaigns`
Date: 2026-11-10

---

## 1. Executive summary

UM-DR-33 closed the engineering, security, release-integrity and
research-quality gaps carried from UM-DR-32, and made one strategic
capability advancement operational: **information gain is now a real,
tested input to the strategist's ranking** (closing the UM-DR-31
"decorative metric" finding with mutation-proof evidence), and the
**discovery funnel** (§12) makes the research pipeline's losses and
costs measurable with honest unmaterialised-stage markers.

Confirmed defects fixed this window (each with regression coverage and,
where frozen files were touched, the documented DR-009 thaw/refreeze
procedure with old pins recorded): the `bundle_id=None` evidence-chain
defect, the corrupted-trace budget reset, placeholder-credential
loading, the suite-dirtied working tree, the ground-truth dual-hash
divergence, the kill-switch fanout TypeError, and the 152/154/159
accounting erratum.

**8,990 unique test IDs = 8,981 passed + 6 skipped + 3 xfailed + 0
failed** (+87 / −0 vs the frozen baseline), release archive built twice
byte-identical.

## 2. Acceptance gate matrix (§16 — every gate evidence-based)

| Gate | Requirement | Verdict | Evidence |
|---|---|---|---|
| A | Source integrity | **PASS** | baseline report: full 12-commit UM-DR-32 lineage verified locally, unbroken parents, clean tree, exact commit/tree recorded |
| B | Release integrity | **PASS** | two builds from the SAME revision byte-identical (SHA-256 `8542b8cf…` initially, final recorded in the manifest), CRC valid, 17 policy exclusions, zero source exclusions, no self-inclusion |
| C | Version & docs | **PASS** | 0.39.0 across pyproject/`__init__`/CHANGELOG/Dockerfile/BUILD_INFO/manifest; Python floor(3.11)/tested(3.12.16)/recommended stated explicitly in README |
| D | SAST | **PASS** | all 28 MEDIUM bandit findings traced source-to-sink (0 unfixed confirmed defects; classification table in the security report); mypy-driven audit found and FIXED 2 real defects |
| E | Agentic security | **PASS** (with documented next hardening) | corrupted-budget fail-closed, placeholder rejection, kill-switch hardening — all fixed+tested; RAG-passage UntrustedContent wrapping and MemoryPromotionPolicy wiring recorded as the follow-up queue |
| F | Supply chain | **PASS** (constrained) | project-set audit clean after pin normalization; chromadb CVE-2026-45829 reachability analysis: embedded-only (no server API), no fixed release exists yet, upgrade trigger documented — not a silent exemption |
| G | Unified research model | **PARTIAL** | the funnel measures the model; the §6.1 23-type canonical entity extension was NOT built this window (honest NOT_IMPLEMENTED for the extension; UM-DR-32's typed identity/alias/multi-identity/composite channels remain the operative model) |
| H | Research intelligence | **PASS** | W_INFO_GAIN operational: exact-delta mutation proof, controlled ranking flips, decision crossing (PROMOTE/DEFER), safety-independence (scope/budget/admission ignore scores) — 19 tests |
| I | Autonomous execution | **PARTIAL** | the real authorized lane (research_campaign → AVI fabric → run_bounded_experiment under ToolBoundary+ScopeLaw; stateful discovery; CausalGuard for composite sequences) is verified in the suite; the harness-only `_run_differentials` bypass in the evaluation lab is documented precisely; the full compiled-graph identity-campaign E2E of §9.5 is NOT_VERIFIED this window |
| J | Causal evidence | **PASS** | confirmation authorities untouched; ProofBundle identity defect FIXED (stronger chain); replay/negative-control contracts green in suite |
| K | Negative controls | **PARTIAL** | existing controls preserved and extended by the new fail-closed tests; the §11.3 control-diversity expansion is NOT_IMPLEMENTED this window |
| L | Discovery funnel | **PASS** | 16-stage pure deterministic funnel with drop explanations and honest `not_materialized_in_state` markers; 20 tests; production telemetry wiring recorded as follow-up |
| M | Controlled evaluation | **PASS** | six-arm benchmark regenerated under the canonical identity, results reproduce UM-DR-32 exactly (0/0/0, 3/4@65, 4/4@82, 4/4@82); the composite-vs-unified isolation question (both 4/4@82) documented as open |
| N | Regression | **PASS** | 8,990 collected = 8,981+6+3 exact; 13/13 chunks; +87/−0 node-ID delta; frozen gate 650 pass; release gates 10/10 |
| O | Operability | **PASS** (core) | fail-closed defaults preserved; config validation hardened (placeholder rejection); full flag-dependency documentation is PARTIAL (settings descriptions carry the dependencies) |
| P | Delivery | **PASS** local / **BLOCKED_EXTERNAL_DEPENDENCY** remote | archive+checksum+manifest+reports complete; no Git remote/credentials in this environment — exact publication commands provided in the release-integrity report |

## 3. Capability qualification (honest statuses — deliverable #16)

| Capability | Implemented | Unit tested | Integration tested | Connected to production | Executed via compiled graph | Campaign demonstrated | Independently validated |
|---|---|---|---|---|---|---|---|
| Object identity registry (UM-DR-32) | yes | yes | yes | yes (identity_workflow node) | yes (suite wiring tests) | yes (benchmark arms) | no (team fixture only) |
| Alias resolution (UM-DR-32) | yes | yes | yes | yes | yes | yes | no |
| Multi-identity reasoning (UM-DR-32) | yes | yes | yes | yes | yes | yes (3/4 @65 req) | no |
| Composite workflows (UM-DR-32) | yes | yes | yes | yes (CausalGuard-guarded engine) | partial (engine yes; lab differentials harness-level) | yes (4/4 @82) | no |
| Canonical JSON identity (UM-DR-33) | yes | yes (18) | yes (benchmark artifact regenerated) | yes | n/a (library) | n/a | no |
| ProofBundle identity fix (UM-DR-33) | yes | yes (7) | yes (cqa_v2 consumers green) | yes | yes (suite) | n/a | no |
| info_gain prioritization (UM-DR-33) | yes | yes (19 incl. mutations) | yes (strategist consumers green) | yes (score_hypothesis is the production ranker) | yes (strategist node path) | not re-measured this window (recorded follow-up: six-arm delta with/without) | no |
| Hard-budget fail-closed (UM-DR-33) | yes | yes (6) | yes | yes (budget_governor is the graph's governor) | yes | n/a | no |
| Placeholder-credential rejection (UM-DR-33) | yes | yes (14) | yes (CLI loader contract tests evolved) | yes | n/a (CLI layer) | n/a | no |
| Discovery funnel (UM-DR-33) | yes | yes (20) | partial (module-level; lab/benchmark wiring is follow-up) | partial | no | no | no |
| Unified 23-type research entity model (§6.1) | **no** | — | — | — | — | — | — |
| Compiled-graph identity-campaign E2E (§9.5) | **no** | — | — | — | — | — | — |

## 4. Quantitative outcomes

- Baseline → final tests: 8,903 → 8,990 (+87, node-ID exact)
- New-test breakdown: canonical-hashing 18, funnel 20, evidence-chain 7,
  hard-budget+creds 20, info-gain 19, tree-hygiene 2, frozen-gate +1
- Security regressions added: 47 tests across 6 modules
- Confirmed defects fixed: 6 (R1–R6 in the remediation matrix) + 3
  documentation/provenance corrections (R5/R9/R10 + version reconciliation)
- Frozen windows (DR-009, each with old pin recorded): 4
  (proof_bundle_builder, budget_governor+loaders, prioritization,
  `__init__` version) + 1 frozen-from-birth (discovery_funnel)
- Benchmark: exact reproduction of the six-arm results under the
  canonical identity
- Archive: 4,766 entries / 16,436,266 bytes / byte-identical double build

## 5. Limitations — exact and unhidden

1. **Not implemented this window** (scope-realism, recorded for the next
   window): the §6.1 canonical 23-type entity extension; the §9.5
   full compiled-graph identity-campaign E2E; §11.3 negative-control
   diversity expansion; RAG-passage UntrustedContent wrapping;
   MemoryPromotionPolicy wiring + lesson expiry; kill-switch
   multi-process heartbeat floor; funnel wiring into the evaluation lab
   and benchmark artifact.
2. **Blocked externally:** GitHub publication (no remote/credentials —
   commands provided).
3. **Constrained:** chromadb pinned at the last affected release until a
   fixed release exists (embedded-only reachability documented; upgrade
   trigger recorded).
4. **Measurement boundary:** the six-arm benchmark remains a
   team-authored single-fixture population — no generalization or
   independent-holdout claim is made (UM-DR-32 honesty boundary
   preserved).

## 6. How WebPent's research capability actually advanced

The strategist now weighs *expected information gain* when deciding what
to investigate next — with proof that the metric moves rankings and
decisions and proof that it cannot move safety gates. The evidence chain
that confirms findings now produces correctly-identified ProofBundles.
The research pipeline is measurable end-to-end (the funnel), the budget
authority survives agent-side corruption, and a copied-but-unfilled
credential template can no longer masquerade as production-ready.
Objects, identities, relationships, states and workflows — the
UM-DR-32 capability spine — remain the operative model, now measured
rather than merely claimed.
