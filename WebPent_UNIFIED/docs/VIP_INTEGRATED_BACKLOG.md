# WebPent VIP Smart Autonomous Bug Hunter — Integrated Backlog

## الغرض

هذا الملف يحوّل الرؤية المرفقة إلى backlog قابل للتنفيذ والقياس. لا يُعتبر وجود module أو test مساويًا لاكتمال القدرة التشغيلية، ولا يُعتبر candidate أو hypothesis أو offline fixture ثغرة مؤكدة. تظل **Action Authority** و**target scope** و**causal evidence + negative control + sealed/replayable ProofBundle** بوابات إلزامية.

## الحالة عند نقطة البداية

| capability | الحالة المثبتة | الدليل الحالي | الفجوة التشغيلية |
|---|---|---|---|
| Action Authority | موجود ومختبر | authority contracts وSecurity Invariant Suite | توسيع تغطية كل execution adapters وتوحيد failure taxonomy |
| Evidence/ProofBundle | موجود ومختبر جزئيًا | proof, provenance, replay, report-quality tests | إنتاج ProofBundle حي كامل في qualification ما زال غير متحقق |
| Execution isolation | موجود مع timeout وparent-death safeguard | subprocess lifecycle وrecovery tests | إثبات end-to-end متعدد الأدوات يحتاج benchmark/qualification مضبوط |
| Target understanding | موجود كـtarget/workflow/application-intent models | `test_v17`, `test_v62`, workflow tests | توحيد Application Model وstable graph persistence |
| Knowledge/endpoint graph | موجود جزئيًا | `surface_evidence_graph`, intent/attack-graph tests | دمج endpoints, parameters, roles, objects, workflows في projection موحد |
| Attack Graph | موجود جزئيًا | `test_v19`, `test_v20`, `test_v62` | edge provenance وgap derivation وimpact path ranking |
| Hypothesis engine | موجود ومختبر جزئيًا | `test_v63`, strategist/research tests | توحيد scoring/evidence requirements وspecialist routing |
| Bounded autonomy | موجود ومختبر | controller/autonomy contracts | توسيع rabbit-hole state وstop reasons دون unbounded loop |
| Specialized researchers | موجودة كمسارات/عقود جزئية | research contracts/nodes وcampaign registry | adapters موحدة authentication/authorization/API/injection/business logic |
| Memory/RAG | موجود مع isolation boundary | memory/RAG isolation tests | experience schema وfeedback/reuse مع engagement isolation قابل للقياس |
| LLM assistant | موجود كـassistant boundary | provider/fallback/budget/injection tests | ضمان أن القرار النهائي deterministic في كل planner path |
| Benchmark/qualification | موجود offline وlive harness | golden benchmark وqualification matrix | رفع live coverage لا يتم بادعاء؛ يلزم runs مكتملة وproof فعلي |
| VIP mode/reporting | reporting quality موجودة وVIP qualification موجودة | scorecard/report/release gates | تجميع orchestration كامل مع verdict صادق ومؤشرات reproducibility |

## ترتيب التنفيذ المعتمد

### Sprint 1 — Target Brain

توحيد نموذج التطبيق إلى projections typed ومحدودة: technologies، APIs/endpoints، parameters، authentication/roles، objects، workflows، وbusiness-logic signals. كل record يجب أن يحمل target/engagement identity، same-origin URL عند وجوده، source/evidence references، وconfidence لا يرقى إلى confirmation.

**معيار القبول:** round-trip state/checkpoint لا يفقد الحقول، target isolation يمنع cross-engagement visibility، ولا يُنشأ task من record بلا observed provenance أو URL مصرح.

### Sprint 2 — Knowledge Graph وAsset Inventory

إنشاء projection موحد للعلاقات بين application وsurface وworkflow وidentity وobject وtechnology، مع stable identifiers وdeduplication deterministic. inventory لا يُعد finding ولا يفتح execution وحده.

**معيار القبول:** نفس corpus يعطي نفس graph digest، العقد المكررة لا تتضاعف، والعقد خارج النطاق أو بلا provenance تُوسم gap/ignored ولا تُنفذ.

### Sprint 3 — Attack Graph وKnowledge Gaps

اشتقاق attack paths من edges المرصودة فقط، وتسجيل كل gap باعتباره unknown قابلًا للبحث لا نتيجة أمنية. ربط gap بأقل InformationAction آمن يملك capability وvalidator مناسبين.

**معيار القبول:** لا يوجد edge من guess فقط، وكل path قابل للتتبع إلى observations، والـplanner يتوقف عند غياب تقدم أو budget.

### Sprint 4 — Hypothesis Engine وResearch Planner

توحيد hypothesis schema وscoring من probability/impact/cost/evidence-needed، مع deduplication وbranch lineage وrouting إلى researcher مناسب. LLM يمكنه الشرح أو الاقتراح فقط؛ الاختيار والتنفيذ والpromotion deterministic.

**معيار القبول:** hypothesis بلا evidence requirement أو scope binding لا تصل إلى execution، وإعادة checkpoint لا تغيّر ترتيب المهام لنفس state.

### Sprint 5 — Specialized Researchers

تقديم contracts مشتركة للـauthentication، authorization، API، injection، وbusiness logic researchers. كل researcher ينتج observations/hypotheses/actions typed ولا ينفذ مباشرة، ويُرفض أي campaign بلا validator أو proof plan.

**معيار القبول:** كل researcher يعلن capabilities وrequired evidence وsafe action class، وأي mismatch ينتج `missing-validator` أو `capability-gap` لا confirmation.

### Sprint 6 — Rabbit Hole وAutonomous Campaign Loop

توسيع bounded controller من next-best-action إلى فروع مرتبطة بإشارة ذات قيمة، مع max depth/time/actions/requests/cost، stop reasons واضحة، state fingerprints، وrecovery idempotency.

**معيار القبول:** لا loop غير محدود، لا إعادة تنفيذ غير idempotent بعد restore، وكل انتقال يسجل decision وbudget وevidence delta.

### Sprint 7 — Memory وLLM Assistant

تخزين lessons والـfeedback بتقسيم client/engagement/target، ومنع استخدام الذاكرة كدليل مباشر. إدخال RAG untrusted-wrapped مع redaction، وفشل مغلق **fail-closed** عند provider ambiguity أو secret leakage أو malformed structured output.

**معيار القبول:** corpus adversarial لا يغيّر authority أو scope، وLLM output لا يرفع lifecycle stage ولا ينشئ finding بلا deterministic verifier.

### Sprint 8 — VIP Mode وQualification

تجميع deep recon، knowledge building، graph، research loop، validation، والتقرير في وضع bounded واحد. تشغيل golden benchmark offline أولًا، ثم qualification المحلي فقط عند اكتمال single smoke/report/proof prerequisites.

**معيار القبول:** تقرير مهني يفرق بين observed/candidate/needs-review/confirmed، وVIP لا يصبح مؤهلًا إلا بتحقيق thresholds متعددة الجولات مع causal signal وnegative control وProofBundle قابل لإعادة التشغيل.

## قواعد loop

يُسمح بالانتقال بين السبرنتات بعد مرور targeted tests وRuff وcompileall وdirect-I/O inventory/G-02 عند تغيير المصدر، ثم full regression قبل commit منطقي. لا تُعاد جولات WAPTLab عشوائيًا بعد timeout أو عدم وجود report؛ يُحل السبب أولًا. أي نتيجة live غير مكتملة تُسجل `inconclusive` أو `blocked_by_capability`.

## تعريف الإنجاز

الإنجاز الوظيفي يعني أن المسار موجود، bounded، معزول، ومغطى باختبارات قابلة لإعادة التشغيل. أما **VIP qualification** فهو حكم مستقل لا يتحقق بعد بمجرد اكتمال المعمارية أو زيادة عدد الملفات أو candidates. الرقم 75% أو أي score آخر يجب أن يأتي من scorecard منشور وأدلة مسجلة، وليس من تقدير يدوي.

## خارج النطاق

لا يسمح هذا backlog بأي اختبار على أهداف خارجية، أو live provider I/O، أو CAPTCHA bypass، أو credentials غير مصرح بها، أو تعديل WAPTLab. كل runtime artifacts تبقى خارج Git، وكل التقارير المرفوعة تنقّي secrets/cookies/headers/bodies/payloads.
