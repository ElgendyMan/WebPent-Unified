# Source-Backed Candidate Inventory Review v1

## Executive conclusion

تم تنفيذ مرحلة **Source-Backed Candidate Inventory** على Juice Shop وWebGoat وcrAPI اعتمادًا على source revisions مثبتة، بدون إعادة تشغيل root/health observations وبدون اعتبار route reachability أو HTTP 200 أو lesson completion أو source presence vulnerability. النتيجة تثبت أن **3 حالات Juice Shop فقط** لديها حاليًا causal oracle معتمد وevidence محلي sealed/replayable؛ لا توجد حالة scoring-admitted حاليًا في WebGoat أو crAPI.

هذا ليس P10 أو VIP qualification. `official_isolated_p10_runs_authorized=false`، والمجموعة الحالية أقل من شرط P10: **3 cases / 3 classes** مقابل **10 cases / 6 classes**.

## Source and governance matrix

| Target | Version / source revision | Ground truth | Accepted cases | Current status |
|---|---|---|---:|---|
| Juice Shop | 20.2.0 / `1618a611b173b4bf114028e6e02549950606e29d` | Frozen GT: `docs/juice_shop_p10_ground_truth_v1.json`; SHA-256 `84bf4111235b546b337fbd3e76207d43a8e7a05f39685dd9ed51f739468aea52` | 3 | Partial scoring readiness |
| WebGoat | Source build / `7517acca95d9851da706452454c223dd13545ef4` | Not admitted for scoring | 0 | Source candidates only; quality withheld |
| crAPI | Compose source / `73d309cc8f28bbdeed31dbb35f05dba8354de3c9` | Not admitted for scoring | 0 | Mutable `VERSION=latest`; quality withheld |

The machine-readable inventory is `SOURCE-BACKED-CANDIDATE-INVENTORY-v1.json`. Its validator reports PASS and enforces loopback/GET-only scope, source-revision parity, causal readiness fields, proof steps, and the invariant that non-accepted candidates are never counted as FN.

## Juice Shop decisions

The accepted set is `juice.error_handling.v1` (`Security Misconfiguration`), `juice.exposed_metrics.v1` (`Observability Failures`), and `juice.local_xss.v1` (`XSS`). Each has a target-local semantic predicate, safe precondition, independent benign control, central verifier mapping, completed baseline/candidate/control evidence, sealed ProofBundle, `verify_seal`, and replay. No generic implementation was required; the existing adapter/profile is the correct target-local boundary.

The remaining candidates are explicitly excluded from scoring. `juice.access_log_disclosure.v1` is blocked pending governance and source-to-frozen-mapping reconciliation. `juice.directory_listing.v1`, `juice.forgotten_backup.v1`, and `juice.misplaced_signature_file.v1` are observation-only because redacted resource metadata does not prove a semantic vulnerability. Policy and scoreboard surfaces are out of scope. Reflected XSS is blocked pending a safe admitted workflow and oracle; persisted XSS, login injection, basket manipulation, NoSQL injection, and redirect candidates are out of scope for the current anonymous GET-only/no-mutation/no-credentials boundary.

## WebGoat decisions

Source analysis identified IDOR profile access, stored XSS comments, advanced SQL injection, SSRF task, path traversal, and CSRF flag surfaces. None is accepted for scoring. IDOR requires authenticated identities and cross-user comparison; stored XSS and SQL injection require state-changing/payload workflows; SSRF requires external or callback evidence; path traversal has no admitted safe causal oracle; CSRF requires state-changing cross-site behavior. The source evidence and hashes are recorded in the inventory. These rows remain blocked or out_of_scope and are not FN.

## crAPI decisions

Source analysis identified profile-video object access, vehicle-location BOLA, community-post access, coupon validation, mechanic/report object access, login-with-token, and reset-test-users surfaces. None is accepted for scoring. The object-access cases require authenticated identities and ownership comparisons; coupon validation and reset flows require mutation; login-with-token requires credentials/tokens. In addition, the compose source uses mutable `VERSION=latest`, so strict runtime reproducibility is not admitted until an immutable image digest is recorded. These rows remain blocked or out_of_scope and are not FN.

## Contract and proof requirements

Any future accepted candidate must include a target-local causal predicate, safe precondition, independent negative control, central verifier mapping, regression test, same-condition local live evidence, and a sealed/replayable ProofBundle. The required order remains: source analysis, ground-truth decision, oracle proposal, generic-versus-target-local classification, bounded implementation only if justified, regression, local live test, proof/seal/replay, and before/after comparison. No candidate is promoted merely because its source code or endpoint exists.

## Gap to P10 and decision packet

The exact gap is **7 additional cases and 3 additional classes** for the current Juice Shop approved set, followed by three valid isolated official runs, metrics recomputation, and final independent review. The inventory found no additional candidate that passed all gates in this phase. `SOURCE-BACKED-CANDIDATE-INVENTORY-DECISION-PACKET-v1.md` therefore records the options and recommends keeping the current set fail-closed while separately proposing only target-local contract expansion. It does not authorize frozen-GT edits, thresholds, credentials, mutation, Official P10, Bug Bounty, or external targets.

## Validation results

| Check | Result |
|---|---|
| Source-backed inventory validator | PASS: 3 targets, 3 accepted, 11 blocked, 3 observation-only, 11 out_of_scope |
| Targeted regression | 22 passed |
| Full pytest | 1926 passed |
| Ruff (`src scripts tests`) | PASS |
| Compileall | PASS |
| Official final gates | PASS |
| New live target execution | None; no root/health observation was repeated |

The new validator recomputes SHA-256 for every source evidence file available under the pinned local source roots and fails closed on missing files, revision drift, missing causal fields, proof-step gaps, unadmitted target cases, or qualification-state drift.

## State preservation

Generic Core, ActionAuthority, CampaignExecutor, ProofBundle semantics, frozen Ground Truth, policy thresholds, and qualification gates were not modified to inflate coverage. No new live target execution was performed for the non-admitted candidates, and no root/health observation was repeated.

Current official state remains: `P10=NOT_QUALIFIED`, `P9=NOT_QUALIFIED`, `VIP=NOT_QUALIFIED`, `Bug Bounty=BLOCKED`, `official_isolated_p10_runs_authorized=false`.
