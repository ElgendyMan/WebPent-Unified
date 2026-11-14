# WebPent VIP Smart Autonomous Bug Hunter — Implementation Gap Analysis

**التاريخ:** 2026-08-22
**النطاق:** مراجعة static/offline للكود الحالي في WebPent، بدون target/provider I/O وبدون credentials أو أسرار.
**قاعدة القرار:** وجود module أو test لا يعني أن capability مكتملة end-to-end؛ يتم التفريق بين implementation موجودة، partial orchestration، وmissing qualification.

## 1. Executive assessment

WebPent لا يحتاج rewrite. لديه بالفعل طبقات قوية ومترابطة جزئيًا: Target Package v2، engagement binding، ScopeCompiler، ActionAuthority، capability preflight، state/checkpoint continuity، redaction، memory isolation، deterministic validators، ProofBundle sealing/replay، knowledge-gap and hypothesis components، attack-graph projection، وbounded controller.

الفجوة الرئيسية ليست غياب كل المكونات، بل أن بعضها ما زال **projection أو proposal فقط** ولا يقود autonomous research spine كاملة. كما أن بعض المسارات تحتاج إثباتًا أقوى بأن كل autonomous action يمر من authorization وscope وbudget وActionAuthority، وأن outcomes لا تتحول إلى confirmation عند غياب causal evidence أو negative control أو deterministic replay.

**الحكم الحالي:** architecture foundation قوية، لكن **VIP qualification غير مثبتة**. لا يجوز إعلان VIP قبل multi-run benchmark يقيس precision وrecall وfalse positives وreproducibility وzero unauthorized/out-of-scope actions وbounded stopping.

## 2. Architecture coverage matrix

| المكوّن | الموجود حاليًا | الحالة | الفجوة الدقيقة / قرار التنفيذ |
|---|---|---|---|
| Target Intelligence Engine | `research_intelligence.py` وطبقات workflow/observation موجودة | جزئي | يحتاج façade موحّد ينسّق ingestion → model update → gaps، بدل بقاء intelligence موزعة بين state nodes وhelpers |
| Canonical Target Knowledge Model | `models/mental_model.py` يقدم typed nodes/edges واستخراجًا deterministic وengagement-scoped | موجود قوي | يلزم ربط update lifecycle بالـcontroller والـcheckpoint schema وإضافة stale/invalidation policy قابلة للقياس |
| Target Knowledge Graph | `shared/attack_graph.py` يبني projection redacted من mental model والعلاقات والـfindings | جزئي قوي | graph حاليًا projection أكثر من كونه مصدر قرار موحّد؛ يلزم adapter واضح للـplanner والـhypothesis engine مع stable versioning |
| Identity and Authorization Model | authorization matrix، relational evidence، identity/context fields، Target Package scope | جزئي قوي | يلزم canonical identity principal/tenant/session model وربط كل hypothesis/action/evidence بنفس identity lineage |
| Stateful Workflow Model | workflow fields، runtime/checkpoint، research session، browser/runtime feedback | جزئي | يلزم explicit state-machine transitions وinvalidation عند login/tenant/workflow changes، مع رفض implicit state assumptions |
| Attack Surface Model | crawled surface، endpoint/route extraction، surface records، capability catalog | جزئي | يلزم canonical surface inventory بمصدر وثقة وتاريخ وmethod/parameter/auth context، مع dedup/versioning وعدم إسقاط endpoints المتعارضة |
| Knowledge Gap Engine | `KnowledgeGapEngine` يستخرج gaps من feedback/surface ويقترح actions bounded | موجود جزئيًا | proposal-only؛ يلزم lifecycle يربط gap → experiment → observation → resolved/blocked/expired، ويمنع loop repetition |
| Hypothesis Engine | `research/hypothesis_engine.py` يفرض transitions وcausal/negative-control requirements | موجود جزئي | لا يولّد hypotheses ولا يربط كل hypothesis بنظرية target model/attack graph بشكل مركزي |
| Hypothesis Ranking Engine | `hypothesis_ranker.py` scorer deterministic بسيط | جزئي | scoring محدود ولا يدمج risk، novelty، exploitability، authorization state، cost، uncertainty، expected information gain بصورة موحّدة |
| Attack Graph | attack graph builder وcausal edges موجودان | جزئي قوي | يحتاج graph-driven planning/chain selection وcycle control؛ لا يكفي بناء graph في التقرير فقط |
| Research Planner | `campaign_planner.py` يبني plans/contracts وDAG وcoverage gaps من observations | موجود جزئيًا | passive planner؛ يلزم adaptive planner يقرأ outcomes ويعدّل hypothesis depth/priority بدون bypass للـpolicy |
| Adaptive Campaign Controller | `AutonomousController` bounded iterations، idempotency، preconditions، recovery، optional bounded parallelism | موجود جزئي قوي | يلزم تثبيت loop contract مع knowledge update، evidence reduction، replanning، stop reasons، budget ledger، وresume continuity |
| Rabbithole / Deep Investigation Engine | anti-loop/rabbithole concepts موجودة في research intelligence وcontroller | مفقود كطبقة مستقلة | يلزم bounded deep-investigation policy: depth/time/cost caps، escalation فقط مع information gain، safe stop عند repeated weak evidence |
| Capability Registry | `CapabilityRegistry` وpreflight/manifest موجودان | موجود قوي | يلزم coverage matrix لكل action class، explicit unavailable/degraded semantics، وintegration tests تثبت missing capability لا تصبح clean |
| Deterministic Validator Framework | validator registry/plugins، structural/active/replay validators، proof validators | موجود قوي جزئيًا | يلزم common validator result schema وversioned contracts وconsistent inconclusive/blocked mapping لكل validator |
| Causal Validation | strict verifier وactive replay updates وcausal signal fields موجودة | موجود جزئي | يلزم تعميم ثلاثي replay على كل validators التي تدّعي confirmation، لا marker-only assumptions، وربط causal result بالـhypothesis transition |
| Negative Controls | independent negative-control replay أضيف لمسارات marker/SSTI/NoSQL وProofBundle | موجود جزئي | يلزم تعريف متى يكون control mandatory، وكيف يختار benign control مستقلًا، وكيف يسجل control failure كـinconclusive لا clean |
| ProofBundle + Replay Engine | sealed/replayable bundle، digests، tamper checks، proof store | موجود قوي جزئيًا | يلزم replay executor contract موحّد يعيد observations من adapter مصرح به، مع schema/version migration وreport continuity |
| Research Memory | decision log، lessons، research session، negative evidence ledger وعزل engagement | موجود جزئي قوي | يلزم memory write policy موحّدة تمنع hypotheses الضعيفة/الأسرار، وتربط memory provenance بالـtarget/package/engagement |
| RAG 2.0 | knowledge/lessons/vectorstore وclient/engagement isolation موجودة من الإصدارات السابقة | جزئي | يلزم retrieval contract versioned مع source provenance، confidence، freshness، tenant filter، وقياس retrieval usefulness؛ لا يجوز أن يصبح RAG evidence أو authorization |
| LLM Reasoning Boundary | `llm_reliability.py` وprompt/reliability tests موجودة | جزئي قوي | يلزم boundary موحّد يمنع LLM من تنفيذ action أو تأكيد finding، schema-constrained suggestions، budget/fallback/timeout semantics وaudit لكل استعمال |
| Bounded Autonomy Controller | bounded loop وActionExecutor injection وparallel policy وrecovery موجودة | موجود جزئي قوي | يلزم global budget ledger، max request/time/depth/parallel caps، persistent stop state، operator approval gates، وadversarial retry tests |
| Attack Chain Reasoning | causal edges وattack graph وDAG/hypothesis links موجودة | جزئي | يلزم chain evaluator يثبت prerequisite evidence لكل edge، يمنع speculative chain promotion، ويُخرج chain gaps صراحة |
| Qualification Benchmark | `benchmark/qualification.py` وmetrics/harness موجودة | جزئي | schemas موجودة لكن لا توجد نتيجة multi-run حية/مكتملة تثبت precision/recall/FP/unauthorized-zero على ground truth مع reproducibility |
| Multi-run Reproducibility Framework | run IDs، evidence artifacts، qualification matrix، stable fingerprints موجودة | جزئي | يلزم harness يعيد نفس fixtures عدة مرات، يقارن canonical outcomes/evidence digests، ويثبت عدم تسريب state أو تكرار leases بين runs |

## 3. Architectural conflicts and security risks

| الخطر | الأثر | المعالجة المطلوبة |
|---|---|---|
| Proposal/projection قد يُعامل كتنفيذ أو evidence | LLM/research planner قد يرفع confidence بلا target proof | فصل صريح بين proposal، authorized task، observation، validator result، وconfirmed finding في schemas وreducers |
| Autonomous loop قد يعيد نفس الفرضية | إهدار budget أو rate-limit وتكرار findings | stable hypothesis/action fingerprints، experiment ledger، anti-loop penalty، وstop reason persisted في checkpoint |
| Missing capability أو timeout قد يُفسر كـclean | false negatives خطيرة | outcome taxonomy إلزامية: blocked/inconclusive/infrastructure_failure/knowledge_gap؛ tests لكل path |
| Package/scope context قد يفقد continuity عند resume | out-of-scope أو duplicate lease | binding/lease continuity check قبل أي graph execution، وعدم استهلاك lease ثانية |
| Negative control غير مستقل | false causal confirmation | replay ثلاثي، role-specific digests، uniqueness checks، وcontrol failure ⇒ inconclusive |
| RAG أو memory cross-tenant leakage | تسريب معلومات بين engagements/clients | mandatory client/engagement filters، provenance checks، adversarial isolation tests |
| LLM prompt injection أو fabricated evidence | confirmation أو action غير مصرح | LLM output treated as untrusted proposal فقط، schema validation، no direct tool authority، وredacted context |
| Parallel execution مع shared mutable state | nondeterminism أو duplicate action | اختيار read-only independent tasks فقط، bounded workers، deterministic merge، وidempotency keys |
| Browser/provider/transport path خارج ActionAuthority | direct-I/O violation وخرق G-02 | static inventory + runtime guard + regression test لكل transport، ولا transport جديد ضمن هذه roadmap |
| Report continuity تنفصل عن ProofBundle | التقرير قد يعرض finding بلا proof | report builder يرفض confirmed status بدون sealed bundle/provenance/validator result، ويعرض inconclusive صراحة |

## 4. Test gaps

الاختبارات الحالية قوية في contracts منفردة، لكنها تحتاج تغطية تكاملية إضافية:

1. اختبار end-to-end offline للـloop كاملًا: target model → gap → hypothesis → rank → plan → ActionAuthority → observation → validator → ProofBundle → state update → replanning.
2. اختبار adversarial يرسل LLM output فيه confirmation أو tool call أو scope expansion ويثبت الرفض.
3. اختبار budget exhaustion، repeated weak hypothesis، timeout، missing capability، rate-limit، وworker redelivery مع stop-state persistence.
4. اختبار graph/mental-model version conflict وstale workflow identity.
5. اختبار multi-tenant RAG/memory isolation مع نفس endpoint وأسماء متشابهة بين engagements.
6. اختبار deterministic replay عبر عدة runs ومقارنة canonical evidence digests والـfinding IDs.
7. اختبار report continuity: حذف/تلاعب ProofBundle يجب أن يخفض status إلى inconclusive أو يوقف التقرير، لا يعرض confirmed.
8. اختبار G-02 inventory/runtime/precommit بعد كل transport أو executor change.
9. اختبار API/CLI/Celery package-backed bootstrap وresume مع عدم وجود raw package/trust keys في checkpoint/log/report.
10. اختبار أنه لا يتم إنشاء target/provider I/O في كل الاختبارات الجديدة؛ all live qualification تبقى منفصلة ومعلّمة صراحة.

## 5. Benchmark and qualification gaps

`QualificationMatrix` يصف ground truth وruns، لكنه لا يثبت بمفرده أن WebPent VIP. المطلوب benchmark versioned يحتوي cases معروفة، expected class، authorized fixture، deterministic adapter، وnegative cases. لكل run يجب تسجيل:

- confirmed true positives، rejected/unknown cases، false positives، وfalse negatives.
- sealed evidence artifact وcanonical digest وreplay result.
- target modified flag وout-of-scope action count وunauthorized action count.
- action/request/time/depth budget consumption وstop reason.
- reproducibility عبر runs متعددة بنفس input/version.

معايير VIP المقترحة يجب أن تكون **مقاسة لا وصفية**: precision وrecall وfalse-positive rate وreplay agreement وzero unauthorized/out-of-scope actions وbounded-loop compliance. لا يتم وضع أرقام نجاح اعتباطية قبل تعريف ground truth وتشغيل harness.

## 6. Migration and operational risks

التعديلات يجب أن تكون additive وbackward-compatible. legacy no-package scans تظل تعمل، بينما package-backed execution تظل fail-closed. أي schema جديد في state أو ProofBundle يجب أن يملك default آمنًا ومسار migration واضحًا. يجب عدم إضافة dependency runtime غير ضرورية، وعدم إدخال private keys أو credentials أو raw bodies في source أو fixtures أو archives.

Docker/Redis/Celery distributed qualification لم تثبت بهذه المراجعة. لذلك يتم تنفيذ offline deterministic harness أولًا، ثم qualification موزعة منفصلة إذا توفرت بيئة مصرح بها وقابلة للإعادة. لا يتم استخدام WAPTLab أو Juice Shop في هذه المرحلة بدون طلب وتشغيل مصرح به.

## 7. Recommended implementation order

1. تثبيت schemas/versioned contracts: `TargetKnowledgeSnapshot`, `ResearchExperiment`, `ValidatorResult`, `AutonomyBudget`, `StopState`، مع redaction وengagement identity.
2. إنشاء façade لـTarget Intelligence يحدّث mental model، attack surface، knowledge graph، وknowledge gaps كعملية واحدة deterministic.
3. توحيد hypothesis generation/ranking مع source/provenance وinformation-gain utility وanti-loop state.
4. ربط campaign planner بالـAutonomousController في loop صريح bounded: plan → authorize → execute → observe → validate → reduce → update → replan.
5. إنشاء Rabbithole engine bounded ومتوافق مع policy، يختار depth based on information gain ولا يفتح transport جديدًا.
6. تعميم validator result وcausal/negative-control/ProofBundle contract على كل confirmation paths.
7. توحيد memory/RAG retrieval والكتابة مع provenance وtenant/engagement isolation وfreshness.
8. تثبيت LLM boundary وfallback/timeout/budget tests، مع منع LLM من authority أو evidence.
9. إضافة global budget/stop persistence وredelivery/resume tests.
10. بناء offline multi-run qualification harness، ثم تشغيله على deterministic fixtures واستخراج metrics.
11. تشغيل full quality gates وG-02، تحديث README/audit/manifest، ثم commit/archive فقط بعد نجاحها.

## 8. Acceptance criteria for the roadmap

لن يُعلن النظام VIP إلا إذا أثبت harness قابل للإعادة أن كل confirmed finding يملك causal evidence وprovenance وvalidator result وnegative control عند اللزوم وsealed replayable proof واستمرارية تقريرية، وأن unknown/missing capability/timeout/LLM failure لا تتحول إلى clean. كما يجب إثبات zero unauthorized/out-of-scope actions، budget-bounded autonomous behavior، tenant isolation، ونجاح multi-run reproducibility على ground truth معلنة.

حتى استيفاء هذه البنود، الصياغة الصحيحة هي: **VIP-oriented architecture with strong bounded/evidence-driven components; formal VIP qualification pending benchmark evidence.**


## 9. Phase 2–3 acceptance report — offline implementation

تم تنفيذ أصغر دمج coherent بدون rewrite: أضيفت عقود `ActionBudgetState` و`StopDecision` و`AutonomousCycle`، مع حفظها في `PentestState` وdefaults آمنة في `initial_state`. كل محاولة صادرة تحجز التكلفة قبل التنفيذ؛ المحاولة المحجوبة أو الفاشلة تستهلك reservation، ولا يتم استدعاء handler عند فشل الحجز. كما تم إصلاح resume للـlegacy checkpoints حتى تُقرأ aliases `used_cost` و`used_actions` ولا تُصفّر الميزانية المتراكمة.

تم ربط `smart_campaigns` projection بالحزم الموجودة فعليًا: `KnowledgeBuilder` يعيد بناء target knowledge من state observations، و`AttackGraphBuilder` يعيد graph projection، و`ResearchLoopContract` يسجل fingerprint/version وgaps/actions/outcome taxonomy وbudget/stop telemetry. هذه المخرجات **advisory/report-safe فقط**؛ لا تمنح ActionAuthority، ولا تؤكد finding، ولا تستبدل validator أو sealed ProofBundle. تم إضافة redaction دفاعية للـsecret-like inline identifiers.

بوابات التحقق offline الحالية: `12 passed` في اختبارات autonomy/research-loop المركزة، وRuff وcompileall نجحا للملفات المعدلة. التغطية تشمل نفاد الميزانية قبل handler، استهلاك تكلفة الفشل، استنفاد replan، negative-control contradiction كـevidence stop، resume budget، stable knowledge fingerprint، projection graph، وsecret redaction.

الحدود المتبقية: لم يُبنَ بعد end-to-end offline harness يمر كاملًا من target model إلى validator وProofBundle ثم replan، ولم تُنفذ بعد توحيدات Rabbithole وmemory/RAG وLLM boundary وmulti-run qualification. لذلك لا يوجد أي ادعاء VIP أو live qualification في هذه المرحلة.


## Phase 4 acceptance — memory/RAG/LLM boundary (offline)

تم توحيد telemetry داخل `ResearchLoopContract` بصورة additive. العقد يحتفظ فقط بمؤشرات bounded للـmemory retrieval وحالات LLM (`accepted`/`needs_review`/`rejected`) ولا يحتفظ بـsnippets أو claims أو raw credentials، ولا يمنح أي authority أو confirmation. تم تمرير trace الحالي من `smart_campaigns` إلى العقد، مع استمرار العمل من projections redacted وعدم إضافة transport أو target/provider I/O.

بوابة phase 4: **PASS offline**. الاختبارات المركزة للـresearch loop وLLM reliability وmemory isolation وRAG وautonomy نجحت، مع إبقاء تحذيرات dev-only الخاصة بالمفاتيح الضعيفة في الاختبار كما هي. لا تُعد هذه النتيجة qualification حيًا.

## Phase 5 acceptance — reproducible qualification harness (offline)

تم توسيع `benchmark/qualification.py` بعقد `QualificationFixture` و`OfflineQualificationResult` ودالة `run_offline_qualification`. الـharness يشغل injected deterministic runner بتكرارات bounded، ويقارن canonical digests، ويفصل discovery عن confirmation، ويحسب candidate false positives/false negatives، proof/replay agreement، unauthorized/out-of-scope attempts، budget/stop records، وسلامة عدم تعديل الهدف. أضيف recursive redaction للـfixture scenario وrun metadata.

بوابة phase 5: **PASS offline**، بعد نجاح 35 اختبارًا مركّزًا وRuff وcompileall. الـharness لا ينفذ شبكة أو browser أو provider I/O، ولا ينتج live precision/recall؛ أي qualification رسمي ما زال **NOT QUALIFIED** حتى تُجمع fixtures/evidence معتمدة وتشغّل البوابة وفق سياسة مستقلة.

## Remaining qualification boundary

النتائج السابقة تثبت contracts وtelemetry وreproducibility harness فقط. لم يتم تشغيل WAPTLab أو Juice Shop في هذه الجولة، ولم يتم ادعاء VIP أو live qualification أو precision/recall. يلزم في المرحلة الأخيرة تشغيل full WebPent tests، فحص G-02، secret scan، مراجعة docs/audit، ثم commit/push فقط إذا بقيت الشجرة نظيفة وكل البوابات خضراء.


## Final gates acceptance — Gate 1–7

تم إغلاق Gate 1 وGate 2 وGate 3 بصورة offline قابلة لإعادة التوليد، كما تم تشغيل تكامل bbscout المستقل offline. الـcausal edge لا يُنشأ إلا من ProofBundle مختوم target-backed يحمل baseline/candidate وnegative-control مستقلًا وprovenance؛ والـedge يدخل attack graph serialized ويؤثر في ترتيب next-best-action عبر causal relevance bounded. كما يستهلك controller coverage ledger أثناء loop ويعيده في state النهائي، فتظل أولوية المسارات منخفضة التغطية قابلة للحفظ والاستئناف والتدقيق.

تم إنشاء `scripts/build_gate3_proof_artifact.py` لتوليد أول ProofBundle اصطناعي مختوم وقابل لإعادة التشغيل، و`scripts/run_offline_three_run_qualification.py` لتشغيل ثلاث جولات deterministic من نفس fixture. هذه artifacts تثبت صحة العقد والـreplay agreement وقابلية التكرار offline فقط؛ لا تمثل نتائج WAPTLab أو Juice Shop ولا يجوز عرضها كـlive qualification.

تمت مراجعة تكامل bbscout وتشغيل اختباراته المستقلة بعد استعادة checkout منفصل، مع اختبارات WebPent المركزة الخاصة بالـcausal/coverage/proof/qualification. لم تُفتح أي قناة target/provider جديدة، وظلت ActionAuthority وActionExecutor وحدود scope/authorization وredaction وbounded budget هي الحدود الوحيدة للتنفيذ.

**الحكم النهائي:** تنفيذ الخطة البرمجية والاختبارية تم حتى آخر بوابات offline، لكن **formal VIP qualification = NO / NOT QUALIFIED**. السبب ليس فشلًا مخفيًا في الاختبارات، بل غياب benchmark حي معتمد وground truth مستقل وقياس live precision/recall وzero unauthorized/out-of-scope عبر بيئة قابلة للإعادة، إضافة إلى عدم إثبات distributed Docker/Celery qualification. الصياغة الدقيقة هي: **VIP-oriented, bounded, evidence-driven architecture with offline qualification harness; formal VIP qualification pending live benchmark evidence.**

## Gate 7 evidence boundary

أي أرقام في Gate 3 وoffline three-run simulation تخص fixtures اصطناعية redacted ومولدة من الكود. تم تحديث manifest وaudit ليمنعا الخلط بين هذه الأرقام وبين اكتشافات حقيقية على targets. لا توجد credentials أو cookies أو tokens أو raw target responses أو private keys داخل source أو state أو report أو archive.

## Remaining work after this loop

المتبقي ليس rewrite: تشغيل benchmark حي مصرح به بصورة مستقلة، توثيق ground truth، إثبات end-to-end على adapters حقيقية ضمن نفس ActionAuthority، ثم إعادة تشغيل multi-run qualification مع قياس precision/recall وfalse-positive/false-negative وreplay agreement وunauthorized/out-of-scope counts. إلى أن يتم ذلك يظل قرار VIP مرفوضًا بصورة fail-closed.
