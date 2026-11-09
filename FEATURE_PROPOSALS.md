# WebPent — فهم عميق واقتراحات الترقية نحو «Autonomous VIP Ultimate Full Bug Hunter»

> **سؤالك:** هل المشروع محتاج إضافات أو مميزات أو تعديلات ليصبح صياد ثغرات مستقلًا
> كاملًا شاملًا؟ هذه قراءتي الهندسية بعد التشغيل الفعلي والفحص الاستاتيكي وقراءة
> البنية — مع قائمة مقترحات مرتبة بالأولوية والأثر والجهد، مبنية على إعادة استخدام
> ما هو موجود فعلًا (لا اختراع من الصفر).

---

## 1) قراءتي للوضع الحالي — أين نقف فعلًا

**ما يملكه المشروع اليوم (وهو كثير):** حلقة هجوم كاملة فوق LangGraph (80+ عقدة) تخطط
وتستكشف وتبني فرضيات وتتحقق بأدلة حقيقية وتتعلم؛ محرك EGAIE للتحقيق المُغلَّف
بمقاييس معلومات حقيقية (InformationGain/Repetition/Prerequisites)؛ طبقة VIP
للحملات المستقلة بأدوار (leader/strategist/economist/tactician/skeptic/judge)؛
59 حزمة وكلاء متخصصين (من access_control إلى waf_detector)؛ dojo للتدريب والتقييم؛
econ/jc/prism لطبقات القرار والاقتصاد والامتثال؛ بوابات جودة استثنائية (5 بوابات
حاجبة + canary + SBOM)؛ 7,958 اختبارًا.

**ثلاث فجوات جوهرية تمنع لقب «Autonomous VIP Ultimate»:**

1. **الاستقلالية الحقيقية مقيدة بالتزامن لا بالذكاء:** الحلقة تعمل لكن القرارات
   «عالية المخاطر» ترجع لـHITL بشري افتراضيًا، وطبقات VIP/econ موجودة لكنها
   استشارية (advisory) لا منفذة. الصياد المستقل الكامل يحتاج **سلطة قرار محددة
   بإطار أمان** لا استشارة تُعرض ثم تُهمل.
2. **ذكاء المعرفة نحيف:** knowledge_pack = 7 ملفات/52KB. RAG فوق corpus بهذا
   الصغر يعطي استرجاعًا شكليًا لا استشرافًا. الحلقة التعليمية (lessons) حُذفت
   عمدًا في 0.29.0 لقضايا جودة — فالمشروع **ينسى كل حملة عند انتهائها** إلا عبر
   ما بقي في channels أخرى.
3. **الاستطلاع النشط العميق نصف معطل:** خادم OAST الكامل (interactions خارج
   النطاق، correlations) موجود في طبقة الـlegacy من v4 لكنه غير موصول بالمحرك
   الحالي — مع ملفات ultimate الأحدث (shared/oob_provider) تغطي جزءًا فقط.

---

## 2) المقترحات (مرتبة: الأثر ÷ الجهد، مع نقطة البدء الموجودة أصلًا)

### P0 — ترفع المشروع من «قوي» إلى «مستقل فعلًا»

**ق1. إحياء OAST كطبقة verification من الطبقة الـlegacy (الأثر الأكبر/جهد متوسط)**
- الوحدة جاهزة تقريبًا: `legacy: src/webpent/oast/{server,correlate}.py` +
  `shared/oob_provider.py` الأحدث + قالب deployment في `docs/oast-deployment.md`.
- المطلوب: منفذ HTTP خارج النطاق مع توقيع nonce لكل hypothesis، وجسر correlation
  إلى `ProofBundle` الحالي (عقد cqa_v2 جاهز للبرهان)، وقاعدة صارمة: تفاعل OAST
  يُظهر finding مرشحًا فقط ولا يرقّه بدون validator حتمي (يحافظ على فلسفة
  evidence-first).
- الأثر: فئات كاملة تُفتح — SSRF أعمى، XXE، blind SQLi عبر timing/OOB،
  cache poisoning التأكيدي، webhook-side effects.

**ق2. «سلطة القرار داخل قفص» بدل HITL الشامل (قلب الاستقلالية)**
- البنية موجودة: `safety/kill_switch.py` و`spend_governor` و`request_ledger`
  (legacy) + `BOUNDED_AUTONOMY_CONTRACT.md` + policy engine في config.
- المقترح: نظام **Autonomy Tiers** لكل هدف: tier-0 (قراءة/استطلاع) → tier-1
  (probes غير مدمرة) → tier-2 (payloads تأكيدية) → tier-3 (exploitation كاملة)
  — الترقية بين الطبقات محسومة بـEvidence Score + ميزانية + سقف معدل، وكل ترقية
  تُوقَّع في سجل تدقيق قابل للإعادة. HITL يبقى كـ**حد أقصى** يضبطه المشغل لا
  كحاجز افتراضي.
- الأثر: تشغيل حملة كاملة بلا إنسان مع بقاء الأمان قابل للإثبات — وهذا حرفيًا
  معنى VIP Autonomous.

**ق3. ذاكرة تعلم آمنة بالأدلة (إعادة إحياء lessons بشكل صحيح)**
- الدرس من حذف 0.29.0: المشكلة كانت تضخم نقاط بلا سقف وتلوثًا بين الحملات
  (وقد صُحح نفس النمط في `R2-dojo-01`).
- المقترح: lessons ledger جديد مبني على `persistent_finding_ledger` +
  `refutation_ledger` (legacy قوي) بعقود صارمة: كل درس مربوط بـevidence digest،
  decay إلزامي، عزل client_id/engagement_id، وسقف تأثير رقمي على الترتيب فقط
  (لا على التحقق)، وبوابة anti-fabrication من `proof_bundle_builder`.
- الأثر: الحملة رقم 100 تبدأ بمعرفة الحملات التسع والتسعين — جوهر «الأذكى مع
  الوقت».

### P1 — ترفع التغطية والعمق

**ق4. توسيع knowledge_pack آليًا من إنتاج المشروع نفسه:** كل حملة تولّد
hunt_notes/graph_trace/campaign_summary (موجودة في archive/generalization_evidence
كأمثلة) — سيل استرجاع يفهرسها كـexperience corpus بعد redaction. جهد قليل، أثر
مباشر على جودة الفرضيات.

**ق5. ربط dojo بالإنتاج كـself-benchmark مستمر:** dojo موجود للتدريب؛ اجعل
nightly canary يشغل dojo scenarios كـregression للأداء الصيادي (قياس: عائلات
مكتشفة/وقت/تكلفة) مع منحنى اتجاه في dashboard الـworkers.

**ق6. محرك استشاري CVE/KEV:** البذور موجودة (`shared/epss.py` + أسماء متغيرات
CVE_FEED_CATALOG_PATH/KEV_CATALOG_PATH في .env.llm مثال v4). اجمع epss + feed
محلي + مطابقة تقنيات في مرحلة target_understanding لتوجيه الفرضيات.

**ق7. عمق Auth/Session:** `multi_step_auth` و`session_pool` (legacy) و
`jwt_analyzer` موجودون — وحّدهم في مسار «هوية افتراضية» يبني/maintains جلسات
متعددة الأدوار تلقائيًا ويغذي authorization matrix بجلسات حية بدل افتراضات.

**ق8. ذكاء JS أعمق:** `js_discovery` و`javascript_intelligence` و`sourcemap_analysis`
(legacy قوي: استخراج secrets/maps) + esprima مثبتة الآن — مسار واحد: من كل bundle
→ endpoints/keys/routes → فرضيات مباشرة (API surface shadow).

### P2 — تحسينات بنية وتشغيل

**ق9. توحيد طبقة الـlegacy الناجية:** بعد المرحلة 1 من خطة الإصلاح، جدولة
«ترحيل مختار»: كل وحدة legacy إما تُستوعب في البنية الحالية (كما فعلنا مع
ProposalOrderSelector) أو تُعلن مهجورة رسميًا وتُنقل للأرشيف — لا منطقة رمادية
دائمة (قاعدة: إن لم تُستورد من أي كود نشط خلال إصدارين → أرشفة).

**ق10. تقارير bounty آلية من طرف لنهاية:** reporter/platform_export (legacy) +
قوالب HackerOne/Bugcrowd الموجودة في 0.26.0 → خط إنتاج: finding مؤكد → تقرير
مصاغ بـevidence → معاينة → إرسال بموافقة المشغل (tier-3 اختياري).

**ق11. fleet حقيقي متعدد الأهداف:** production/worker_coordination +
cross_process_leases + campaign_scheduler (legacy) — جدولة أهداف متعددة
بأولويات وميزانيات منفصلة على workers Celery مع portfolio_manager كلوحة قيادة.

---

## 3) أولوية التنفيذ المقترحة (لو بدأنا غدًا)

| الترتيب | المقترح | الجهد التقديري | الأثر على الهدف |
|---|---|---|---|
| 1 | ق2 Autonomy Tiers | 3–5 أيام | تحول الاستقلالية من شعار إلى نظام مُثبت |
| 2 | ق1 OAST revival | 3–4 أيام | فتح فئات ثغرات كاملة (SSRF/XXE/blind) |
| 3 | ق3 lessons آمنة | 4–6 أيام | ذاكرة تراكمية = ذكاء مركّب |
| 4 | ق4 knowledge auto-expansion | 1–2 أيام | RAG يتنفس من إنتاج الحملات |
| 5 | ق7+ق8 auth/JS | 4 أيام لكل منهما | عمق في أكثر عائلات البجات ربحية |
| 6 | ق5/ق6/ق9–11 | تدريجيًا | نضج تشغيلي وتغطية |

**خلاصة رأيي:** المشروع أقرب للهدف بكثير مما يوحي اسمه المتواضع — البنية
العصبية (graph + evidence contract + quality gates) هي الأصعب في بناءها وهي
موجودة وممتازة. الناقص ليس «مميزات جديدة» بقدر ما هو **توصيل الطبقات الجاهزة
بعضها ببعض** (OAST بالبرهان، safety بالاستقلالية، التعلم بالعزل، الإرث بالمحرك)
— وهذا بالضبط ما تفصله المقترحات أعلاه بالترتيب.
