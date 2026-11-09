# WebPent VIP Phase 2–6 Delivery

## النطاق

يُوثّق هذا الملف تنفيذ وتحقق الأجزاء الحالية من خطة VIP دون تشغيل WAPTLab أو Juice Shop. كل تغييرات التنفيذ additive وbounded وfail-closed، ولا تمنح أي finding حالة confirmed من غير causal signal وnegative control وProofBundle صالح.

## ما تم تنفيذه

| المرحلة | التنفيذ | ضمانات القبول |
|---|---|---|
| Phase 2 | توصيل `active_research_node` بالـgraph عبر RuntimeContext/handler محقون، مع route bounded إلى causal projection | لا يوجد transport داخل node؛ غياب handler أو target scope ينتج block/inconclusive |
| Phase 3 | إضافة `causal_research` projection deterministic يبني nodes/edges ويربط findings وobservations وcandidate actions | الحواف تحمل references وcontrol metadata؛ لا توجد ترقية ثقة أو confirmation داخل projection |
| Phase 4 | دعم batch متوازٍ bounded داخل `AutonomousController` مع اختيار محافظ وتجميع deterministic | التنفيذ legacy أحادي افتراضيًا؛ duplicate/in-flight idempotency محمي؛ لا توجد مشاركة mutable working state بين المهام |
| Phase 5 | إضافة recovery state/events وعقدة `recovery` رسمية في graph | يعاد التخطيط فقط لفشل infrastructure صريح قابل للإعادة؛ policy denial وprecondition failure لا يُعادان؛ الميزانية محدودة بحد أقصى 3 |
| Phase 6 | استهلاك `NegativeEvidenceLedger` داخل causal decision projection مع client/engagement scope | reusable negative evidence لا يُستخدم خارج engagement/client؛ يُسجل القرار في `research_unified_decision_trace` و`next_best_actions` |

## التغييرات الرئيسية

أضيفت حقول state الخاصة بعداد autonomous controller وrecovery بصورة متوافقة مع checkpoints القديمة، مع defaults صريحة في `initial_state.py`. أضيفت وحدة `src/webpent/shared/causal_research.py`، وهي projection بلا I/O ولا authorization ولا confirmation.

تم تسجيل عقد `active_research` و`causal_research` و`recovery` في `src/webpent/graph/builder.py`. مسار recovery لا ينفذ transport؛ وظيفته التحقق من قابلية retry ثم إعادة الدخول إلى controller فقط عند وجود candidate وميزانية متبقية.

تم تقوية bookkeeping في `CampaignExecutor` بقفل داخلي يحمي سجلات lifecycle وcoverage وdecision trace، مع مجموعة in-flight تمنع duplicate execution عند التوازي وتسمح بإعادة المحاولة بعد exception موثق فقط.

أُعيد توليد `docs/direct_io_inventory.json` بعد تغييرات المصدر. الناتج الحالي يحتوي 64 سجلًا، ويمر عبر contract الاختبار الخاص بـG-02.

## الاختبارات والبوابات

| البوابة | النتيجة |
|---|---:|
| targeted VIP/graph/research/recovery contracts | 17 passed |
| suite المشروع بالكامل | 1164 passed |
| Ruff على `src/ scripts/ tests/` | All checks passed |
| `git diff --check` | ناجح |
| G-02 direct-I/O contract | ناجح |
| تشغيل WAPTLab أو Juice Shop | لم يُنفّذ، وفق القيد الحالي |

ظهرت تحذيرات بيئية معروفة من Pydantic حول مفاتيح dev غير الآمنة، إضافة إلى تحذيرات deprecation من LangChain/Chroma؛ لم تتحول أي منها إلى failure ولم تُستخدم لتخفيف verifier أو proof policy.

## حدود النتيجة

هذا التسليم يثبت wiring والعقود وسلامة الحلقة محليًا عبر handlers/executors محقونة. لا يثبت عدد findings أو confirmations على هدف حي، لأن تشغيل المختبرات ممنوع في هذه المرحلة. كما أن causal graph وnegative ledger لا يرفعان الثقة تلقائيًا؛ هما يضيفان سياقًا قابلًا للتدقيق فقط، بينما يظل القرار النهائي خاضعًا لـVerifier وProofBundle.

## الملفات الجديدة والمعدلة ذات الصلة

- `src/webpent/graph/builder.py`
- `src/webpent/shared/autonomous_controller.py`
- `src/webpent/shared/campaign_executor.py`
- `src/webpent/shared/causal_research.py`
- `src/webpent/state/state.py`
- `src/webpent/state/initial_state.py`
- `docs/direct_io_inventory.json`
- `tests/test_v3_autonomous_graph_loop.py`
- `tests/test_vip_active_research.py`
- `tests/test_vip_causal_research.py`
- `tests/test_vip_parallel_controller.py`
- `tests/test_vip_recovery_loop.py`

## قرار الجاهزية

النتيجة الحالية هي **VIP graph/research-loop hardening verified locally** وليست شهادة أداء حي أو شهادة أن WebPent اكتشف عددًا معينًا من الثغرات. لا يجوز وصف أي نتيجة غير مدعومة بـProofBundle على أنها confirmed.
