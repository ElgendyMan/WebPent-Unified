# WebPent V3 Phase 11 — Qualification Loop

## Scope

This document records the final live qualification runs performed against the authorized local WAPTLab and Juice Shop targets. The targets were treated as read-only test systems; no target source code, database, or container configuration was modified.

The qualification standard is intentionally strict: a finding is counted as **Tool-Confirmed** only when the product behavior is reproduced by the validator with a causal signal, a completed negative control, and a sealed evidence/proof bundle where the validator requires one. Surface observations and scanner hypotheses remain separate from confirmed vulnerabilities.

## Quality gates

| Gate | Result |
|---|---:|
| Pytest | 1096 passed, 0 failed |
| Ruff | Passed with no errors |
| Compileall | Passed |
| `git diff --check` | Passed |

The test suite includes regressions for campaign precondition materialization, report campaign-plan projection, evidence-ledger reason truncation, JWT differential routing, JWT cookie isolation, validator idempotency, and bounded Swagger/OpenAPI discovery.

## Live qualification results

| Target | Findings | Tool-Confirmed | Evidence bundles | Campaign entries | Entries with matched refs | Blocked by precondition |
|---|---:|---:|---:|---:|---:|---:|
| WAPTLab v5 | 35 | 1 | 1 | 27 | 7 | 0 |
| Juice Shop v11 | 27 | 0 | 0 | 30 | 4 | 0 |

### WAPTLab

WAPTLab produced **35 findings**. One IDOR finding was promoted to **Tool-Confirmed** with a sealed evidence bundle and a completed negative control. The remaining findings are retained as pending or needs-human-review observations and are not presented as confirmed vulnerabilities.

### Juice Shop

Juice Shop produced **27 findings**, including API and information-disclosure observations and XSS-related hypotheses. It produced **zero strict confirmations** in the final run. This is an honest qualification outcome: the JWT differential path was prevented from claiming a vulnerability when the unsigned-token response did not differ from the control after authenticated cookies were correctly excluded.

## Implemented Phase 11 corrections

The campaign planner now materializes `observed_preconditions` only when the corresponding surface or workflow observation is present. This preserves fail-closed execution while preventing a valid matched campaign from being blocked merely because the observation was not copied into the execution contract. The report now retains a backward-compatible campaign-plan projection rather than returning `null` when the plan exists.

The validator path received bounded target-scope propagation for replay and corrected first-attempt handling for `Not Scanned` findings. JWT probing was made fail-closed with respect to authenticated cookies: session cookies are not reused to manufacture an unsigned-token differential. A marker and regression tests preserve reliable routing when the JWT token is redacted or base64 encoded.

OpenAPI/Swagger discovery was expanded conservatively with bounded common paths and safe parsing of an embedded `swaggerDoc`; no JavaScript is executed, paths remain same-origin and bounded, and documentation discovery alone never becomes a finding. Evidence-ledger merge now truncates oversized tool-error reasons to the model limit instead of aborting an otherwise valid qualification run.

## Remaining qualification gap

The remaining Juice Shop gap is not a reporting or precondition blocker. The final run had no campaign entries blocked by precondition, and the plan contained matched observations. The missing strict confirmations reflect the absence of a validator-approved causal differential for the observed Juice Shop behavior. Therefore no additional finding was promoted solely to satisfy a numeric target.

## Reproducibility

The source of truth for the code release is the Git commit produced after the final quality gates. The live reports remain external qualification artifacts and are not included in the source archive unless explicitly copied into a release artifact directory. Secrets, session cookies, authorization headers, and raw sensitive bodies must not be included in the archive.
