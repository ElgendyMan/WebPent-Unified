# خطة v82: طبقات التضخيم الأربع (Recon / Quality / Operational / Intuition)

التاريخ: 2026-10-15 · النسخة المستهدفة: 0.7.0 (v82)

## المشكلة

v81 أعطت الصياد مخًا (orchestration) وحنكة (intel + dead-ends)، لكنه لا يزال:
(1) يرى بما استخرجه الـrecon وحده، (2) يرقي أي bundle يمر من المدقق دون
شك منهجي، (3) يعمل كنسخة واحدة متتالية، (4) لا يتعلم عبر الأهداف ولا يقيس
جودة فرضياته قبل صرف الميزانية.

## الاقتراح المركزي المنفذ (الـ15 بندًا كما وردت)

كل بند يصير وحدة مستقلة في حزمة `src/webpent/autonomous/amplifiers/`،
advisory بالكامل، بلا أي سلطة تنفيذ جديدة، وبلا شبكة في الاختبارات
(كل جالب خارجي `fetcher` محقون قابل للاستبدال بـdouble). القيود الموروثة:
redact لكل نص محفوظ، بلا أسرار ولا قيم استعلام، حدود صارمة، ملف تالف →
فارغ، فشل الوحدة لا يكسر جولة أبدًا.

### الطبقة 1 — تقوية العين (Recon Amplifiers)
* Task 1 `takeover.py` — Subdomain Takeover Scanner: جدول بصمات خدمات
  (cname_pattern → service → vulnerable_dangling)، محلل نصي على سجلات CNAME
  من fetcher محقون؛ finding بصمة ناقصة = advisory فقط.
* Task 2 `cloud_storage.py` — Cloud Storage Misconfig Detective: مولّد
  permutations نقٍ لاسم الشركة (backup/prod/dev/staging...) + مصنف استجابات
  S3/GCS/Azure من نص الاستجابة المحقون (مفتوح/محمي/غير موجود).
* Task 3 `wayback.py` — Historical Endpoint Tracker: adapter لصيغة CDX
  (جالب محقون)، استخراج endpoints قديمة، دمجها كبذور discovery advisory.
* Task 4 `js_analyzer.py` — Deep JS Analyzer: تحليل نصي ساكن: مفاتيح API
  مرشحة hardcoded، auth معلّق بتعليقات، URLs تطوير/ستاجنغ، feature flags،
  إصدارات API داخلية (v0/v1/v2). المرشحات advisory لا تُرقّى أبدًا.
* Task 5 `ct_mining.py` — Certificate Transparency Mining: adapter لـcrt.sh
  JSON (جالب محقون)، استخراج subdomains، تصفية scope، حدود صارمة.

### الطبقة 2 — تقوية الجودة (Quality Amplifiers)
* Task 6 `skeptic.py` — Self-Adversarial Validation ⭐: بروتوكول شكّ قبل
  الترقية: إعادة بـcache-buster، تكرار إحصائي (N=3)، جلسة طازجة، تفاوت توقيت.
  كل فحص = double قابل للحقن؛ الحكم `upheld`/`self_refuted`/`inconclusive`
  مع أسباب. الربط بالمنسّق: فحص شكّ advisory في مرحلة PROVE لا يمنع
  الترقية أبدًا (المدقق الختمي يبقى المرجع) — يسجل الحكم في detail فقط،
  لأن أي منع هنا سيكون سلطة جديدة فوق البوابات القائمة.
* Task 7 `triager_sim.py` — Triager Simulation Mode: مقارنة finding بأنماط
  رفض عامة معرفة offline (duplicate-pattern، NA-pattern) بتشابه حقل، وتقرير
  "يشبه أنماطًا مرفوضة لأن..." — advisory.
* Task 8 `fp_autopsy.py` — False-Positive Autopsy: عند رفض/انتفاذ ذاتي،
  تحليل السبب إلى (pattern_id → lesson) في KB ملفية advisory تُخفِّض
  ترتيب بذور نفس النمط لاحقًا (نفس عقد dead-ends: إعادة ترتيب لا حذف).

### الطبقة 3 — تقوية الأداء (Operational Amplifiers)
* Task 9 `swarm.py` — Multi-Agent Swarm Mode: منسّق أدوار (Scout/Striker/
  Philosopher/Skeptic/Scribe) يجري تمريرات دورية محدودة بالترتيب نفسه كل
  جولة، العقل مركزي واحد (المنسّق القائم)، كل دور = دالة على الحالة.
  تنفيذ تسلسلي محتمد (لا خيوط، لا عمليات) ليبقى حتميًا وقابلًا للاختبار.
* Task 10 `temporal.py` — Temporal Intelligence: تجميع ملاحظات موقوتة
  (status/طول/متجر) وكشف نمط زمني (نافذة deploy، تكرار دوري بالساعة)
  إحصائيًا نقيًا.
* Task 11 `rate_limit_map.py` — Rate-Limit Cartography: خريطة لكل endpoint
  من ملاحظات 429/ترويسات limit (مع double محقون لاختبار تجاوز الترويسات
  advisory)، تصنيف unbounded مشتبه به.
* Task 12 `session_topology.py` — Session Topology Mapping: مقارنة كوكي
  قبل/بعد تسجيل الدخول/الخروج (مدخلات ملاحظة فقط): مؤشرات fixation
  (كوكي الجلسة نفسه قبل المصادقة يبقى بعدها) وriding (بلا تغيير عند
  تبديل مستخدم) — تحليل نقي، advisory.

### الطبقة 4 — بونص الحدس (Intuition)
* Task 13 `anomaly.py` — Anomaly Detector: baseline إحصائي نقي (وسيط/MAD
  على الطول والتوقيت، توزيع status) وعلامة انحراف advisory.
* Task 14 `cross_target.py` — Cross-Target Pattern Recognition ⭐: تجميع
  intel عبر الأصول (تقنية fingerprint → كلاسات مُثبتة) في ملف عبر الجلسات،
  يقترح كلاسات advisory لهدف جديد بنفس البصمة.
* Task 15 `hypothesis_quality.py` — Hypothesis Quality Scoring: نقاط
  specifity/evidence/testability لكل فرضية وإعادة ترتيب advisory قبل
  صرف الميزانية (لا يحذف ولا يضيف).

### الإغلاق
* Task 16: تصدير الحزمة من `autonomous/__init__.py`، دمج نقاط دخول advisory
  في `hunt_runtime` (دوال تجميع اختيارية لا تُغيّر السلوك الافتراضي)،
  الإصدار 0.7.0 في الملفات الثلاثة، CHANGELOG عربي، صف v82 في جدول التتبع،
  سطر README، إعادة توليد جرد direct-IO بمراجعة diff، المجموعة الكاملة
  خضراء + ruff نظيف على الملفات الجديدة، ZIP `webpent_v82_amplifier_layers.zip`.

## معيار الإنجاز

* 2362 اختبارًا قائمًا + اختبارات الطبقات الجديدة كلها خضراء.
* ruff نظيف على كل ملف جديد.
* جرد direct-IO 4/4 بعد إعادة التوليد بمراجعة diff.
* ZIP v82 مُسلَّم.

## سجل التنفيذ

| # | المهمة | الحالة | الأدلة |
|---|--------|--------|--------|
| 1 | `takeover.py` | منفذة | بصمات 10 خدمات، CNAME حقن عبر `fetch_dns`، scan فاشل يرجّع errors لا استثناءات — 5 اختبارات |
| 2 | `cloud_storage.py` | منفذة | permutations للـ20 كلمة على 3 مزودين، تصنيف 9 استجابات، `scan_buckets` محتمد بـ`max_checks=64` — 7 اختبارات (صُحّحت توقعات 3 اختبارات بعد التطبيع والحد 64) |
| 3 | `wayback.py` | منفذة | تحليل CDX (حدود 500/64)، إزالة query، بذور discovery داخل النطاق — 4 اختبارات |
| 4 | `js_analyzer.py` | منفذة | سرّان يُطابقان على النص الخام ويُخزنان كبصمة فقط (`f"{value[:4]}...len{len}"`) لأن redact يدمر القيم، وبقية الـleads على النص المُنقّح — 4 اختبارات |
| 5 | `ct_mining.py` | منفذة | تحليل crt.sh + قوائم أسماء، `_domain_of` بفحص بنيوي (نقطة، بلا مسافات)، تصفية نطاق — 4 اختبارات |
| 6 | `skeptic.py` (الشك الذاتي) | منفذة | 4 شكوك بترتيب ثابت عبر `reprobe` محقون، cache-buster واحد مشترك، حكم upheld/self_refuted/inconclusive — ضمن 15 اختبار quality |
| 7 | `triager_sim.py` | منفذة | 7 أنماط رفض معروفة، تصنيف likely_duplicate/likely_na/clean، تقرير دفعة — ضمن quality |
| 8 | `fp_autopsy.py` | منفذة | `FPAutopsyStore` بحد 48 درسًا وحفظ ذري وملف تالف → فارغ، `demotion_for` سقف 0.20، `summarize_autopsy` — ضمن quality (اختبار 0.15 بالتسامح 1e-9) |
| 9 | `swarm.py` (الفريق الخماسي) | منفذة | 5 أدوار بدوال ن pure، دفع عبر `globals()` لتمكين التجاوز، جولات بحد 4، دور فاشل يُسجل ولا يكسر — 3 اختبارات ضمن operational |
| 10-12 | `operational.py` | منفذة | `temporal_profile` (نافذة دورية/إزاحة حجم)، `rate_limit_map` (unbounded بشرط ≥3 طلبات وصفير Limit-Headers)، `session_topology` (fixation/riding/incomplete_logout) — 9 اختبارات |
| 13-15 | `intuition.py` | منفذة | كاشف شواذ وسيط/MAD بـz>4، `rare_status` بشرط عينات ≥5، `CrossTargetStore` (حدود 48/16، حفظ ذري، فساد → فارغ، أهداف كـorigin مجرد بلا credentials)، تقييم جودة 0.4/0.35/0.25 بإعادة ترتيب لا حذف — 20 اختبارًا |
| 16 | الختام | منفذة | تصدير 24 رمزًا من `autonomous/__init__.py`؛ دالتا تجميع advisory في `hunt_runtime` (`advisory_recon_summary`, `advisory_cross_target_suggestions`) بلا استدعاء افتراضي — 4 اختبارات؛ الإصدار 0.7.0 في pyproject/`__init__`/اختبار الحزم؛ CHANGELOG عربي؛ سطر حالة README؛ صف v82 في تقرير الارتباط؛ direct-IO: 641 → 641 (سجل شبحي واحد تجنبناه بإعادة تسمية باراميتر كان يحتوي "os" داخل "cross")؛ ZIP `webpent_v82_amplifier_layers.zip` |

### إصلاحات أثناء التنفيذ
- `intuition.py`: استيراد `Counter` سقط في الإنشاء (NameError كان سيحدث أول تشغيل) — أُعيد.
- `intuition.py`: `record_proven` كان يخزّن `origin.netloc` فيكشف credentials في هدف مصادَق؛ صُحح إلى `hostname(:port)`.
- `hunt_runtime.py`: الباراميتر `cross_target_store` ضمنيًا يطابق إشارة "os" في ماسح direct-IO (سلسلة "cro**ss**") — أُعيد التسمية إلى `store` بدل تلويث جرد الموافقات.
- تصحيح توقع اختبار: وسيط latency الصحيح 53.5 لا 55.

### بوابة الإقفال
- المجموعة الكاملة: **2437 passed, 0 failures** (123.18 ثانية، 2026-10-15) — أساس v81 2362 + 75 جديدة (5+7+4+4+4+15+12+20+4).
- Ruff: نظيف على كل ملفات الحزمة الجديدة وملفات الاختبار الـ75 و`hunt_runtime.py` و`autonomous/__init__.py` (33 ملاحظة أصلية: 9 آلية، والبقية لفّ أسطر ودمج شرطين متداخلين SIM102 — صفر متبقٍ).
- direct-IO: **4/4 اختبارات** ناجحة بعد التجديد (641 → 641 سجلًا).
- الإصدار: 0.7.0 موحد في `pyproject.toml` و`src/webpent/__init__.py` و`tests/test_release_packaging.py`.
- ZIP: `webpent_v82_amplifier_layers.zip` (بلا `__pycache__`/`.pyc`).
