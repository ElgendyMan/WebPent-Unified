# WebPent v60 — Baseline وفهم المشروع

## حالة النسخة

تم فك الحزمة `webpent_v60_20260817.zip` داخل المسار:

```text
/home/ubuntu/webpent_v60
```

تم التحقق من SHA-256 للحزمة، وكانت القيمة المطابقة لملاحظات التسليم:

```text
9e62fedef35e8efbd9fb66c19b7f0aeb5ec31146b17dac25c03838614867e15b
```

الحزمة لا تحتوي على `credentials` أو `.env` أو قاعدة بيانات أو ملفات تغطية أو ملفات audit حساسة، طبقًا لملاحظات التسليم. تم إنشاء بيئة تطوير معزولة داخل `.venv`، وتم تثبيت الحزمة نفسها وأدوات الاختبار دون تعديل منطق التطبيق.

## الصورة المعمارية

WebPent هو إطار لاختبار أمان تطبيقات الويب، مبني حول Python وFastAPI وCelery وLangGraph وPydantic. الفكرة الأساسية في التصميم هي الفصل بين إشارات الاكتشاف، والفرضيات، والأدلة المعيارية، والنتائج القابلة للتقرير. استجابة أو جملة مولّدة بواسطة LLM لا تُعتبر Finding مؤكدة بمفردها؛ الترقية إلى Finding قابلة للتقرير تتطلب دليلًا مؤكدًا من أداة أو مراجعة بشرية.

التدفق الرئيسي في `src/webpent/graph/builder.py` هو:

```text
planner
  -> auth
  -> recon -> crawler -> [javascript_intelligence] -> subdomain_takeover
  -> cloud_storage -> [target_understanding] -> scope_enforcer -> waf_detector
  -> hypothesis
  -> access_control -> api_testing -> business_logic_fuzzer -> request_smuggling
  -> disclosed_report_intel -> [attack_graph] -> strategist
  -> payload_generator
  -> execution_sandbox [HITL افتراضيًا]
  -> validator
  -> [payload_optimizer عند الحاجة]
  -> devils_advocate
  -> exploit_chainer -> post_exploit -> rabbit_hole
  -> cvss_engine -> business_impact -> cross_reasoning
  -> executive_summary -> reporter -> reflection
```

العناصر بين الأقواس اختيارية ومتحكم فيها من خلال feature flags. جميع حلقات إعادة المحاولة والـrabbit-hole محدودة بسياسات وعدّادات، ولا توجد قفزة منطقية تسمح لـLLM بتجاوز scope أو approval أو evidence gates.

## عقد الحالة المشتركة

المرجع المركزي للحالة هو `src/webpent/state/initial_state.py`، عبر الدالة `build_initial_state`. كل من CLI وCelery worker يستخدمان نفس مصنع الحالة، وهو أمر مهم حتى لا تختلف بنية checkpoint حسب نقطة بدء الفحص.

الحالة تحتوي على كائنات تشغيلية رئيسية مثل `target`, `credentials`, `session_cookies`, `identity_profiles`, `crawled_data`, `hypotheses`, `findings`, `canonical_observations`, `canonical_executions`, `relational_evidence`, `surface_security`, `target_understanding`, `attack_graph`, `execution_gate`, وسجلات التشخيص والتوجيه. القوائم التي تستخدم reducers يجب التعامل معها كمساحات append/merge، وليس استبدالها بقائمة جديدة داخل node إلا إذا كان عقد الـreducer يطلب ذلك صراحة.

## نقاط الدخول والتكامل

| المكوّن | الملف | الدور |
|---|---|---|
| CLI | `main.py` و`src/webpent/cli/` | تشغيل الفحص، preflight، وإدخال الخيارات التشغيلية من الطرفية. |
| API | `src/webpent/api/app.py` | FastAPI، المصادقة، RBAC، rate limiting، إنشاء الفحص، status، approval، findings، وOOB callbacks. |
| Worker | `src/webpent/workers/pentest_worker.py` | تنفيذ الفحص واستئنافه عبر Celery، مع حفظ الحالة والـcheckpoints. |
| Graph | `src/webpent/graph/builder.py` | تسجيل nodes وبناء LangGraph والتوجيه الشرطي وHITL interrupt. |
| State | `src/webpent/state/` | تعريف `PentestState`، reducers، ومصنع البداية المشترك. |
| Models | `src/webpent/models/` | نماذج الأهداف والفرضيات والنتائج والأدلة والهوية والـgoals. |
| Agents | `src/webpent/agents/` | وحدات منفصلة لكل مرحلة: recon، crawler، auth، validators، reporting وغيرها. |
| Tools | `src/webpent/tools/` | registry واكتشاف lazy وwrappers للأدوات الخارجية مثل ffuf وSQLMap وNuclei وPlaywright. |
| Memory/DB | `src/webpent/memory/` | SQLite/Alembic، checkpointing، embeddings/RAG، وحفظ findings. |
| Scripts | `scripts/` | doctor، التحقق من عدد الاختبارات، ground truth، ingestion، وmock OOB server. |
| Containers | `Dockerfile*` و`docker-compose*.yml` | stack للتطوير والاختبار والإنتاج مع Redis وPostgreSQL وAPI وworker. |

## الحواجز الأمنية الموجودة

الإعداد الافتراضي يبقي `auto_approve=false`، لذلك يتوقف الـgraph قبل `execution_sandbox` إلى أن تحصل الموافقة البشرية. العمليات عالية الخطورة تمر عبر risk gate، والعمليات destructive مرفوضة fail-closed. `ffuf`/active discovery مغلق افتراضيًا، ويُشترط ربطه بالـscope والـtimeouts والـregistry.

يوجد preflight يغلق bind العام عندما تكون posture غير آمنة، ولا يسمح بالتجاوز إلا override صريح. التحقق من TLS إجباري افتراضيًا، وتعطيل التحقق مخصص لمعمل مصرح به. كما توجد حماية WebSocket SSRF عبر Playwright 1.48، وتوقيع HMAC-SHA256 للـwebhooks، وحواجز redaction للـcredentials والـcookies وبيانات OOB.

مساحة الذاكرة وRAG اختيارية؛ `DISABLE_RAG` و`EMBEDDINGS_OFFLINE` يسمحان بتشغيل HTTP-only أو offline بدون تحميل نموذج embeddings أو إجراء تنزيلات غير متوقعة. مزودو LLM خلف router مركزي، ويمكن تعطيلهم لتشغيل deterministic fallback.

## Feature flags الأهم

| Flag | الوضع الافتراضي | الأثر |
|---|---:|---|
| `skip_recon` | `false` | يتجاوز recon/crawler ويبدأ من target أو target-understanding. لا يتجاوز strategist أو validator عند وجود فرضيات مفتوحة. |
| `enable_js_intelligence` | `false` | يضيف مراجعة static محدودة ومُزالة الحساسية لمصادر JavaScript. |
| `enable_target_understanding` | `false` | يبني نموذجًا منظمًا للـroutes والـworkflows وحالة المصادقة. |
| `enable_attack_graph` | `false` | يضيف attack graph استشاريًا قبل strategist. |
| `enable_surface_security_analysis` | `false` | يكتب passive observations وcoverage gaps فقط، ولا يثبت Finding. |
| `enable_bug_bounty_reporter` | `false` | يختار reporter مخصصًا لتقارير bug bounty. |
| `llm_enabled` | `true` حسب الإعداد | يسمح بالاتصال بمزودات LLM؛ تعطيله يشغل fallback حتمي محدود. |
| `auto_approve` | `false` | تعطيله يبقي HITL؛ تفعيله قرار مشغل صريح ولا ينبغي استخدامه إلا في scope مصرح. |
| `ffuf_enabled` | `false` | يمنع active content discovery ما لم يُفعّل صراحة مع wordlist وscope مناسبين. |

## نتائج التحقق المحلي

| الفحص | النتيجة | الملاحظات |
|---|---:|---|
| SHA-256 للحزمة | ناجح | مطابق للقيمة الموجودة في Delivery Notes. |
| Pytest collection | ناجح | تم جمع 442 اختبارًا. |
| Pytest full suite | ناجح | `442 passed` خلال نحو 35 ثانية. |
| `compileall` | ناجح | لا توجد أخطاء syntax/bytecode. |
| `scripts/doctor.py --json` مع LLM معطل | ناجح | كل مزودي LLM تم تخطيهم، وdeterministic fallback فعال. |
| `ruff check src/webpent` | يحتاج مراجعة | البيئة الحالية تعرض 468 مخالفة، منها 128 قابلة للإصلاح تلقائيًا؛ هذا لا يكسر الاختبارات لكنه يتعارض مع عبارة `All checks passed` في Delivery Notes، لذلك يجب تحديد scope/version CI قبل اعتبارها regression مؤكدة. |

التحذيرات الحالية لا تفشل الاختبارات، لكنها مهمة قبل production: مفاتيح `audit_secret_key` و`celery_payload_key` الافتراضية غير آمنة، وهناك deprecations من Pydantic/Alembic وLangChain، كما أن `HuggingFaceEmbeddings` يستخدم مسارًا deprecated. يجب توليد أسرار قوية خارج المستودع وعدم استخدام قيم المثال.

## ملاحظة على اتساق الوثائق

`WebPentv60—DeliveryNotes.md` يصف النسخة الحالية بأنها v60 ويذكر `442 passed`. في المقابل، `README.md` يحتوي نصًا تاريخيًا ما زال يشير إلى v59 و`398 tests passing`، كما أن عنوان بعض الوحدات ما زال يحمل أرقام إصدارات قديمة. هذا لا يغيّر نتيجة الاختبارات الحالية، لكنه يخلق التباسًا عند التطوير؛ من الأفضل توحيد version metadata وREADME وDelivery Notes في أول milestone تعديل.

## طريقة التشغيل المحلية الآمنة

```bash
cd /home/ubuntu/webpent_v60
source .venv/bin/activate
export LLM_ENABLED=false
export WEBPENT_LLM_ENABLED=false
export DISABLE_RAG=true
cp .env.example .env  # عند الحاجة فقط، ولا تضع أسرارًا حقيقية داخل الملف المرفق
python main.py --help
python main.py preflight
pytest -q
```

للتشغيل الكامل باستخدام Docker، المرجع الرسمي هو `Makefile` مع التسلسل `make dev-init`, ثم `make build-base`, ثم `make build-app`, وبعدها `make dev-up`. لا ينبغي تشغيل أي target خارجي أو active discovery إلا بعد التأكد من وجود authorization وscope واضحين.

## أولويات التطوير المقترحة

الأولوية الأولى هي تثبيت baseline قبل أي تعديل: تحديد نسخة Python ونسخ LangGraph الفعلية في lockfile، تحديد نطاق Ruff الذي تستخدمه CI، وإزالة الالتباس بين v59/v60. بعد ذلك نقدر نضيف features على شكل vertical slices صغيرة: تعديل state/model، ثم node، ثم route، ثم contract tests، ثم اختبار كامل.

الأولوية الثانية هي معالجة التحذيرات الأمنية والتوافقية دون خلطها بميزات جديدة: secrets قوية، تحديث إعداد Alembic، وتقييم migration من `HuggingFaceEmbeddings` إلى الحزمة الحديثة. الأهم ألا نكسر عقود `evidence`, `approval`, `scope`, و`redaction` أثناء أي refactor.

الأولوية الثالثة هي تشغيل اختبارات مركزة حول الجزء المراد تعديله قبل وبعد التغيير، ثم تشغيل المجموعة الكاملة. ملفات الاختبار الحالية تغطي بعمق مسارات v9 إلى v30، وv57 إلى v59، وP0/P1/P2 الحديثة، لذلك هي خريطة مهمة لفهم السلوك المتوقع وليست مجرد smoke tests.

## قواعد العمل التي سأحافظ عليها في التعديلات القادمة

سأتعامل مع `build_initial_state` و`PentestState` كعقد عام بين كل نقاط الدخول، ومع `builder.py` باعتباره مصدر الحقيقة للتوجيه. لن أسمح بترقية surface observation أو hypothesis إلى Finding بدون evidence contract، ولن أفعّل active tools أو auto-approve افتراضيًا. أي تغيير في graph route أو state reducer سيأتي معه test contract واضح، وسأحافظ على redaction وscope enforcement وHITL وfail-closed behavior كحواجز غير قابلة للكسر عرضيًا.
