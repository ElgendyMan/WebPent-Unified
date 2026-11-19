# Case Registry Preparation v1

## Purpose and boundary

ده **هيكل تسجيل هندسي فقط** لتتبع الحالات المرشحة، نضج الدليل، والانتقال بين مراحل الإثبات. لا يمثل اعتمادًا لحالات P10، ولا يغير Ground Truth أو thresholds، ولا يفتح Official Runs أو Bug Bounty.

> **Engineering validation != Qualification evidence**

## Required case record

كل case مستقبلية لازم تحتوي على `case_id`، target version/source digest، vulnerability class، hypothesis، safe precondition/reset contract، baseline/candidate/independent-negative-control references، `evidence_origin`، typed causal decision، invariant analysis، validator result، sealed digest، replay result، وgovernance status.

الـscoring لا يقبل إلا `target_runtime` مع oracle decision=`CONFIRMED`، وسلسلة دليل مكتملة، وsealed/replayable ProofBundle. أما `offline_fixture` فهو مفيد لاختبار engine فقط ولا يُعتبر target evidence.

## Evidence maturity

| المستوى | المعنى | promotion |
|---|---|---|
| `L0_UNASSESSED` | لا يوجد تحليل bounded | ممنوع |
| `L1_SOURCE_CANDIDATE` | فرضية مدعومة بالمصدر فقط | ممنوع |
| `L2_PRECONDITION_READY` | preconditions وreset مثبتان بدون سلسلة ملاحظات كاملة | ممنوع |
| `L3_OBSERVED` | توجد baseline/candidate/control، لكن oracle غير CONFIRMED أو origin ليس target runtime | ممنوع |
| `L4_SEALED_REPLAYABLE` | target-runtime CONFIRMED مع ProofBundle مختوم وإعادة تشغيل ناجحة | مسموح هندسيًا فقط |

الحالات `BLOCKED` و`INCONCLUSIVE` لا تُرقّى ولا تُحسب TP أو FP أو FN أو clean.

## Current registry entry

| Case | Target | Status | Maturity | Target ProofBundle |
|---|---|---|---|---|
| `webgoat.idor.view_other_profile.causal-vnext` | WebGoat | `BLOCKED` | `L1_SOURCE_CANDIDATE` | لا |

سبب الحجب هو غياب owner/attacker `LessonSession` مستقلتين، وغياب disposable owner-owned resource مع reset/state hash، وعدم وجود bounded semantic authorization observation ضمن النطاق الآمن الحالي.

## Promotion workflow

المسار المطلوب هو: source/behavior candidate review، ثم safe precondition/reset verification، ثم owner baseline، ثم distinct requester candidate، ثم independent negative control، ثم typed causal oracle، ثم central verifier، ثم target-runtime origin check، ثم ProofBundle seal، ثم deterministic replay، ثم engineering registry update. أي qualification لاحقة تحتاج governance review منفصلة ولا تُستنتج من التسجيل الهندسي.

## Governance

تظل `official_isolated_p10_runs_authorized=false`، و`P10/P9/VIP=NOT_QUALIFIED`، وBug Bounty=`BLOCKED`، و`human_independent_signoff_obtained=false`.
