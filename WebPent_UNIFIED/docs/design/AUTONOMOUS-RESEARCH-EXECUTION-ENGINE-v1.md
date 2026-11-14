# Autonomous Research Execution Engine v1

## الحالة والنطاق

يوثّق هذا المستند ترقية WebPent إلى **Autonomous Research Execution Engine (AREX)** لإدارة حملة بحث أمنية bounded داخل نطاق local/controlled فقط. التنفيذ الحالي هو demonstration هندسي قابل للإعادة على `ControlledIDORTarget` purpose-built يعمل على `http://127.0.0.1:<ephemeral-port>`، وليس تشغيلًا رسميًا لـP10 أو P9 أو VIP، وليس اختبارًا لهدف خارجي أو Bug Bounty.

| الحاجز | الحالة الحالية |
|---|---|
| External target / third-party / Bug Bounty | محظور |
| Credentials, login, cookies, auth bypass | غير مستخدمة |
| POST/PUT/DELETE أو state mutation | غير مستخدم |
| Callback / OOB / shell execution | غير مستخدم |
| Persistent daemon / polling scheduler | غير موجود |
| Official isolated P10 runs | `false` |
| P10 / P9 / VIP | `NOT_QUALIFIED` |
| Human independent signoff | `false` |
| Qualification effect | `false` |

## المعمارية التنفيذية

AREX لا يضيف transport أو authority بديلًا. تدفق الحملة هو:

```text
CampaignState
    -> AutonomousScheduler
    -> CapabilityAwareRouter
    -> ActionAuthority
    -> CampaignExecutor
    -> GenericCaseRunner
    -> Controlled target adapter
    -> causal oracle + negative control + central proof verifier
    -> feedback / lifecycle projection / learning memory
    -> next bounded checkpoint
```

`AutonomousScheduler` يختار task واحدًا فقط في كل استدعاء، ويطبق حد الخطوات وحد الميزانية ويتحقق من المهام المكتملة أو الفاشلة أو المقفولة والاعتماديات وidempotency. `CapabilityAwareRouter` advisory وfail-closed؛ فهو لا ينفذ network transport، ولا يسمح إلا بمسارات observation/analysis/proof المعروفة، مع GET أو HEAD، دون body، وبـread-only risk وعلى loopback.

بعد قرار الاختيار، يمر task عبر `ActionAuthority` و`CampaignExecutor`. الـexecutor مسؤول عن authorization وidempotency وlifecycle trace، بينما يظل transport ومعنى الحالة داخل `GenericCaseRunner` وtarget adapter المسجل. هذا الفصل يمنع scheduler أو أي specialist role من تجاوز policy أو تنفيذ request مباشرة.

## Campaign State وlineage

`CampaignState` هو checkpoint engagement/target-scoped يحتوي على campaign identity، target identity، scope digest، knowledge-model version، objectives، research/time budget، task buckets، active hypotheses، discovered assets، evidence summary، وimmutable lineage metadata. كل تحديث ينتج state جديدًا عبر `evolve` مع parent snapshot digest وevent sequence. يتم رفض الحقول التي تشبه secrets أو credentials، كما تُرفض snapshots ذات schema أو task-status غير صالح.

الحالة لا تخزن raw HTTP bodies أو credentials. evidence summary يقتصر على مراجع ونتائج redacted قصيرة، بينما observation references وproof references تبقى identifiers قابلة للتتبع دون نقل payload خام إلى state.

## Capability-aware routing

يستخدم router capability IDs عامة بدل target-specific shortcuts. المسارات المسموحة حاليًا هي:

| Capability | Route | شرط السلامة |
|---|---|---|
| `http_read` | `observation` | GET/HEAD، no body، read-only، loopback، authority متاحة |
| `offline_analysis` | `analysis` | تحليل محلي دون transport |
| `proof_verify` | `proof` | تحقق مركزي من evidence موجودة فقط |

يتم رفض `external_network`, `credential_use`, `auth_bypass`, `state_mutation`, `destructive_action`, `callback`, و`shell_execution`. عدم توفر capability أو scope أو authority ينتج decision من نوع `blocked` بدل fallback صامت.

## Hypothesis lifecycle projection

الحالات canonical داخل `HypothesisEngine` لم تُعدّل. أضيفت facade campaign-local تعرض labels المطلوبة في AREX وتحوّلها إلى canonical transitions مع الحفاظ على promotion policy الحالية:

| AREX label | Canonical projection | شرط أو معنى |
|---|---|---|
| `CREATED` | `unexplored` | hypothesis مسجلة ولم يبدأ التحقيق |
| `SUPPORTED` | `investigating` | توجد إشارات أو evidence أولية، دون confirmation |
| `VALIDATED` | `resolved_true` | لا يتم الانتقال إلا مع causal signal وindependent negative control وcentral proof sealed/replayable ومراجع evidence |
| `REJECTED` | `resolved_false` | يتطلب negative control يرفض الفرضية؛ لا يعني clean خارج نطاق الحالة |
| `BLOCKED` | `investigating` مع task/campaign block | precondition أو capability أو scope غير متاح؛ لا يتحول إلى false negative |

الـfacade لا تنشئ `Finding` ولا تستدعي `PROMOTED`، ولا تجعل technical proof في controlled target يساوي scoring أو qualification.

## Feedback وlearning memory

`ObservationFeedbackLoop` يستقبل observation/result redacted ويحدث state فقط عندما تكون task status أو hypothesis/assets/evidence summary صريحة في input. لا يستنتج vulnerability من HTTP status أو route reachability وحدهما. تحديث hypothesis يمر عبر manager instance وقواعد canonical engine.

`SecurityReasoningMemory` معزولة على exact engagement وtarget scope. تسجل lessons مثل supported أو rejected أو blocked أو inconclusive، وتربطها بـfeedback advisory. الذاكرة لا تملك execution capability، ولا تستبدل causal oracle، ولا تمنح promotion أو policy authority.

## Bounded specialist roles

الأدوار التالية مسجلة داخل role registry الحالي:

| الدور | المخرجات المسموحة | غير المسموح |
|---|---|---|
| Recon researcher | surface/evidence proposals | تنفيذ request أو تجاوز scope |
| Authorization researcher | authorization hypotheses | credential use أو auth bypass |
| Business-logic researcher | invariant hypotheses | mutation أو finding creation |
| Evidence reviewer | evidence/replay review proposal | oracle override أو promotion |
| Planner | bounded task proposals | policy override أو transport |

كل role advisory-only؛ لا role يستطيع تغيير policy أو frozen ground truth أو إنشاء finding مباشرة.

## Controlled campaign simulation

الـrunner `scripts/run_arex_controlled_campaign.py` ينفذ حملة finite واحدة باستخدام target adapter السابق فقط. قبل أي request يتحقق من:

```text
preconditions_ready = true
fixture_ready = true
identity_model_ready = true
reset_verified = true
runtime_digest_verified = true
network_scope_verified = true
```

بعد ذلك يختار scheduler task واحدًا بمسار observation، ثم يسمح للـexecutor بتشغيل lifecycle المسجل للحالة controlled IDOR. الـadapter ينفذ بالضبط ثلاث ملاحظات GET redacted: baseline للمالك، candidate للمهاجم ضد مورد المالك، وindependent negative control للمهاجم ضد مورد غير متعلق. causal oracle وcentral verifier يقرران النتيجة، ثم يتم seal وreplay verification للـProofBundle الموجود فعليًا. لا يتم إنشاء ProofBundle عند غياب observations.

النتيجة machine-readable محفوظة في `reports/evaluation/arex/controlled_campaign_v1.json`. التقرير يتضمن state وscheduler وexecution/case result وevaluation metrics وgovernance flags وboundedness counters، ولا يتضمن raw response bodies أو credentials.

## دلالة القياس

الـevaluation يقيس كفاءة الحملة وجودة hypothesis واكتمال evidence داخل controlled experiment واحد فقط. في التشغيل الناجح الحالي كانت النتيجة:

| المقياس | القيمة |
|---|---:|
| Cases | 1 |
| Target requests | 3 |
| Scheduler steps | 1 |
| Hypothesis quality | 1.0 |
| Evidence quality | 1.0 |
| Proof completeness | 1.0 |
| Validation accuracy | 1.0 داخل ground truth controlled فقط |
| Research efficiency | 0.225 |

هذه القيم لا تمثل real-world detection rate، ولا تثبت portability عبر targets متعددة، ولا تحقق minimum P10 case/class set، ولا تمنح qualification.

## Reproducibility وrollback

التشغيل قابل للإعادة من working tree عبر:

```bash
PYTHONPATH=src:integrations/bbscout/src \
python3 scripts/run_arex_controlled_campaign.py
```

يقوم target بإنشاء ephemeral loopback server، ويعيد fixture إلى deterministic initial state، ويغلق server عند نهاية context manager. لا توجد خدمة دائمة أو ملفات runtime مطلوبة. أي فشل في readiness أو authority أو route يوقف الحملة fail-closed ويترك الحالة في bucket `blocked` دون scoring.

## قرار الحوكمة

هذا milestone يثبت **bounded local campaign management، lifecycle integration، safety gates، وtarget-backed proof path** في controlled case واحدة. لا يثبت P10/P9/VIP qualification. تظل الحالات والسياسات والـthresholds وfrozen ground truth دون تعديل، وتظل Official P10 وBug Bounty مغلقتين حتى قرار حوكمة مستقل واستيفاء الشروط الرسمية.
