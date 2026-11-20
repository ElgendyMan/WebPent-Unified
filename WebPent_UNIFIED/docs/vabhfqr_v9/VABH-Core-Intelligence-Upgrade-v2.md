# VABH Core Intelligence Upgrade v2

> هذا التقرير يصف تحسينًا هندسيًا bounded داخل sandbox/offline/recorded evidence فقط. لا يمثل detection quality على أهداف حقيقية، ولا يمنح P10 أو P9 أو VIP qualification.

## النطاق والهدف

الهدف من هذه الدورة هو تقوية الـGeneric Core في WebPent ليحوّل facts مسجلة إلى فرضيات أمنية أوسع، ثم يرتبها ويقترح الخطوة التالية، ثم يقيّم confirmation السببي عندما توجد observations مكتملة. كل طبقات الدورة advisory-only؛ لا يوجد فيها transport أو credentials أو login أو mutation أو finding creation أو qualification effect.

## ما تغير

| المكوّن | قبل الدورة | بعد الدورة | الحد الأمني المحفوظ |
|---|---|---|---|
| Hypothesis discovery | نمطان generic فقط: IDOR وinformation disclosure | 10 patterns evidence-linked | لا payloads، لا requests، لا findings |
| Vulnerability classes في benchmark | تغطية محدودة | 7 classes: auth_bypass, idor, info_disclosure, path_traversal, sqli, ssrf, xss | class presence ليست confirmation |
| Graph reasoning | علاقات مباشرة محدودة | bounded two-hop neighborhood لكل endpoint، مع chain reasoning داخلي bounded | لا inference غير محدود ولا target semantics |
| Research planning | ترتيب بسيط | deterministic portfolio utility يعتمد على confidence وevidence coverage وplan coverage وinformation gain وnovelty وcost وrisk | كل task proposal-only و`operation=validate` |
| Decision loop | لا composition موحد فعلي | fail-closed order: policy ثم scope ثم missing evidence ثم negative control ثم replay ثم budget ثم step limit ثم next proposal | لا تنفيذ ولا mutation ولا gate opening |
| Confirmation intelligence | لا طبقة موحدة لهذا المسار | baseline/candidate/negative-control عبر OracleEngine ثم ProofBundle validation وseal/replay | offline confirmation engineering evidence فقط، و`scoring_eligible=false` |
| Composition | discovery/planning/decision غير مجمعة في snapshot واحد | `VABHFQRV9Core.build_unified_intelligence` | typed inputs وmalformed inputs تُغلق `blocked` |

## Synthetic benchmark result

تم تشغيل `benchmarks/vabh_core_intelligence_v2.py` على facts اصطناعية مسجلة فقط. الـgraph يتكون من 9 entities و20 relations، ولا يوجد target execution أو network I/O.

| القياس | النتيجة |
|---|---:|
| Expected patterns | 10 |
| Distinct patterns emitted | 10 |
| Pattern coverage داخل fixture | 100% (10/10) |
| Distinct vulnerability classes | 7 |
| Planner queue | 6 bounded tasks |
| Unified-core queue task count | 10 |
| Decision | `continue` / `validate` proposal |
| Offline engineering confirmations | 1 |
| Confirmation proof valid | true |
| Confirmation replay verified | true |
| Scoring-eligible confirmations | 0 |
| Official qualification granted | false |
| Requests sent | 0 |
| Findings created | 0 |
| Qualification effect | false |

> **تفسير مهم:** 10/10 هنا تقيس code-path/pattern coverage على synthetic recorded graph facts، وليس نسبة اكتشاف ثغرات في العالم الحقيقي. و`engineering_confirmed=1` يثبت اكتمال contract/proof/replay في fixture offline فقط؛ لا يتحول إلى Finding أو TP أو scoring evidence رسمي.

## Confirmation contract

لا تنتقل النتيجة إلى posture هندسي مكتمل إلا بعد تحقق roles المستقلة للـbaseline وcandidate وnegative control، ووجود semantic delta يمر عبر `OracleEngine`، ثم ProofBundle صالح، ثم replay ناجح. النقل أو source presence أو response reachability وحدها لا تكفي. الحالات الناقصة أو malformed تظل `BLOCKED` أو `NEEDS_PROOF` أو `INCONCLUSIVE`، ولا تُحسب clean أو FN أو confirmed.

بالنسبة للـbounded chains، كل step يحتاج confirmation مستقلًا ومراجع evidence صريحة، وتُفحص dependencies والترتيب قبل اعتبار chain كاملة. حتى chain مكتملة في offline fixture لا تمنح qualification أو authority.

## Safety and governance invariants

| Invariant | Current value |
|---|---|
| External targets contacted | `false` |
| Credentials/login/tokens used | `false` |
| Destructive/state-changing actions | `false` |
| Requests sent by new benchmark | `0` |
| Findings created by unified core | `false` |
| Execution allowed | `false` |
| Mutation allowed | `false` |
| Qualification effect | `false` |
| `official_isolated_p10_runs_authorized` | `false` |
| P10 / P9 / VIP | `NOT_QUALIFIED` |
| Bug Bounty | `BLOCKED` |

## Regression and gate status

| Gate | Current result |
|---|---|
| Core/confirmation/decision/v9 focused suite | `32 passed` |
| Full regression | `2224 passed / 7 failed` — `PASS_WITH_LEGACY_BLOCKERS` |
| Scoped Ruff | `PASS` |
| Scoped Ruff format | `PASS` |
| G-02 direct-I/O inventory | `PASS`, 392 records |
| Benchmark runner | `PASS` |
| Failure classification | 4 approval-source-hash blockers; 2 WebGoat/crAPI runtime/source-attestation blockers; 1 missing local Juice Shop source fixture |

The seven full-suite failures remain outside this upgrade’s safe generic scope. Four are caused by the pre-existing `approval_source_hash_mismatch` boundary, two require WebGoat/crAPI runtime or source attestation, and one requires the unavailable local fixture `/tmp/juice-shop-source/data/static/challenges.yml`. No validator, frozen ground truth, policy, or threshold was weakened to hide them.

## Remaining VIP gaps

The upgrade improves the reasoning substrate but does not close the formal qualification gates. The remaining requirements are independently approved target-backed ground truth for at least 10 cases across 6 classes, a complete causal oracle and safe precondition for each case, independent negative controls, sealed/replayable ProofBundles, three valid isolated official runs, recomputed quality metrics, attributable human governance signoff, and a final qualification decision. Until those gates are satisfied, the truthful status remains **engineering-improved, evidence-limited, qualification-blocked, and fail-closed**.

## Reproducibility

From the repository root, run:

```bash
PYTHONPATH=src:. python3 benchmarks/vabh_core_intelligence_v2.py
PYTHONPATH=src:. pytest -q tests/test_core_intelligence_upgrade.py tests/test_decision_loop.py tests/test_confirmation_intelligence.py tests/test_vabh_final_audit_v10.py tests/test_vabhfqr_v9.py
PYTHONPATH=src:integrations/bbscout/src pytest -q
PYTHONPATH=src make g02-check
```

The machine-readable benchmark result is [`reports/evaluation/vabh_core_intelligence_v2.json`](../../reports/evaluation/vabh_core_intelligence_v2.json). The implementation is distributed across [`hypothesis_generator.py`](../../src/webpent/research/hypothesis_generator.py), [`planner.py`](../../src/webpent/research/planner.py), [`decision_loop.py`](../../src/webpent/research/decision_loop.py), [`confirmation_intelligence.py`](../../src/webpent/shared/confirmation_intelligence.py), and [`core.py`](../../src/webpent/vabhfqr_v9/core.py).
