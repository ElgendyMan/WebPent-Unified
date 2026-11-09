# Source-Backed Candidate Inventory Decision Packet v1

## Decision requested

القرار المطلوب هو تحديد مسار **توسيع candidate contracts** بعد هذه المرحلة، وليس فتح Official P10 أو إعلان qualification. المجموعة التي اجتازت كل شروط admission الحالية تحتوي على **3 حالات و3 classes فقط**؛ لذلك لا يمكن الوصول إلى حد P10 الرسمي البالغ 10 حالات و6 classes بصدق من خلال inventory الحالي وحده.

## Evidence and current state

| Target | Source revision | Accepted causal cases | Non-accepted candidates | Quality status |
|---|---|---:|---:|---|
| Juice Shop | `1618a611b173b4bf114028e6e02549950606e29d` | 3 / 3 classes | 10 | Partial scoring readiness only |
| WebGoat | `7517acca95d9851da706452454c223dd13545ef4` | 0 | 6 source-backed surfaces | GT/oracle not admitted |
| crAPI | `73d309cc8f28bbdeed31dbb35f05dba8354de3c9` | 0 | 7 source-backed surfaces | GT/oracle not admitted; `VERSION=latest` |

The complete candidate list and source-file hashes are in `SOURCE-BACKED-CANDIDATE-INVENTORY-v1.json`. The three accepted Juice Shop cases are `juice.error_handling.v1`, `juice.exposed_metrics.v1`, and `juice.local_xss.v1`. Their existing baseline evidence is proof-backed and sealed/replayable, but it is not a full P10 run because the approved set and run-count gates are incomplete.

## Exact blockers

The remaining Juice Shop candidates do not all fail for the same reason. `juice.access_log_disclosure.v1` is **blocked pending governance and mapping confirmation** because the source path and frozen mapping require explicit reconciliation. Directory listing, forgotten backup, and misplaced signature-file candidates currently remain **observation_only** because redacted resource metadata does not establish an admitted semantic vulnerability predicate. Policy and scoreboard surfaces are **out_of_scope** because route or feature presence has no accepted security-impact predicate. Reflected XSS is blocked for lack of an approved bounded workflow and oracle; persisted XSS, login injection, basket manipulation, NoSQL injection, and external redirect candidates require state mutation, credentials, payload workflows, or external destination behavior outside the current safety scope.

WebGoat has source-defined IDOR, stored XSS, SQL injection, path traversal, SSRF, and CSRF surfaces, but none has an independent ground-truth snapshot, an admitted target-local causal oracle, a safe precondition under the current GET-only/anonymous boundary, an independent negative control, and a verified sealed/replayable proof. crAPI has source-defined object-access, vehicle-location, post-access, coupon, mechanic/report, authentication, and reset surfaces, but the same causal evidence is not admitted; several additionally require credentials or mutation, and the compose source uses mutable `VERSION=latest`, which prevents a strict reproducibility claim until an immutable image digest is fixed.

## Options

| Option | Action | Benefit | Risk / constraint |
|---|---|---|---|
| A — Maintain fail-closed set | Keep 3 Juice Shop cases admitted; leave all other candidates in their recorded dispositions; do not open P10 | Preserves truthfulness, safety, and frozen-GT integrity | P10 gap remains 7 cases / 3 classes |
| B — Contract expansion on Juice Shop | Propose each additional causal contract separately, beginning with access-log mapping and then only safe same-origin semantic cases; obtain required owner/governance approval before frozen-GT or threshold changes | May increase admitted coverage without changing Generic Core | Some candidates cannot be safely tested under GET-only; no guarantee that 7 cases / 3 classes can be reached |
| C — Cross-target causal lab admission | Build target-local adapters and independently approved GT/oracles for WebGoat/crAPI using immutable, controlled fixtures and explicit credentials/mutation approval where required | Could provide genuine multi-target quality evidence | Requires new governed lab conditions, credentials/state mutation approvals, and substantial independent review; not authorized by this packet |

## Recommendation

التوصية هي **Option A الآن**، مع فتح workstream محدود لـOption B يبدأ بتحليل access-log mapping فقط ولا يغير frozen ground truth. لا يتم اعتماد أي candidate إضافي إلا بعد causal predicate وsafe precondition وindependent negative control وcentral verifier وsealed/replayable ProofBundle وsame-condition evidence. إذا تطلب أي مسار credentials أو mutation أو تعديل frozen GT أو thresholds، يجب إصدار packet جديد والحصول على Owner Approval صريح.

## Safety and governance invariants

`official_isolated_p10_runs_authorized=false`، و`human_independent_signoff_obtained=false`، و`P10/P9/VIP=NOT_QUALIFIED`، وBug Bounty=`BLOCKED`. لا تُحسب blocked أو observation-only أو out_of_scope كـTP أو FP أو FN أو clean أو confirmed. لا يوجد في هذا القرار إذن لتشغيل Official P10 أو Bug Bounty أو أي Target خارجي.

## Affected files and rollback

الملفات الجديدة أو المتأثرة بهذا workstream هي inventory وvalidator والتقارير الموجودة تحت `reports/evaluation/source_inventory/`، ولا يوجد تعديل على Generic Core أو frozen ground truth أو thresholds. Rollback آمن عبر revert للـcommit الذي يضيف inventory artifacts والـvalidator فقط؛ لا يلزم reset أو force push أو تغيير runtime targets.

## Decision status

هذا **Decision Packet غير معتمد كـOwner Approval**، ولا يغيّر أي gate. هو سجل فني يوضح أن الوصول إلى P10 غير ممكن حاليًا دون أدلة وعقود إضافية صادقة.
