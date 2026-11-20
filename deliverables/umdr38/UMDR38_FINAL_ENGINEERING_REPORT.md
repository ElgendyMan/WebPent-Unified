# UM-DR-38 — التقرير الهندسي النهائي
## سلامة النشر، قابلية إعادة إنتاج الأدلة، وإغلاق الإصدار

> وُلّد هذا التقرير آليًا في 2026-11-16T08:09:15.656293+00:00 من الأدلة الآلية للمهمة
> (`scripts/umdr38_final_report.py`) — كل رقم فيه مقروء من سجل آلي عند
> التوليد، ولا رقم مكتوب يدويًا.

<div dir="rtl">

## أ. الملخص التنفيذي

**ما أُصلح:** بنية المستودع (README جذري + سير عمل CI جذري حيث يكتشفه
GitHub فعلًا، وإحالة النسخ المتداخلة)، عقد أدلة الاختبار (الأدلة أصبحت
مُخرج بناء في `.webpent-evidence/` مُهمل من git مع كتابة ذرّية وربط
بالالتزام المختبر بالضبط)، تجهيز الحملات (أدوات قياس قابلة للعكس لا
تتراكم، وحالة نهائية موثوقة من `graph.get_state`، وتنقيح، وتنظيف
مضمون)، ثابت نسخة مخبر واحد (1.6.0)، مصالحة BUILD_INFO وخط الإصدارات،
ترقية أمنية للاعتمادية soupsieve (2.9.2 ← 4.1.1 لإغلاق أربع CVEs)،
ونشر مجموعة الأدلة الدائمة (16 ملفًا بهاشات) بعدما كان `.gitignore`
يُفقد المستودعَ المنشورَ أدلةِ الحملات.

**ما تم التحقق منه:** الجناح الانحداري الكامل عند مراجعة الإصدار
(9249 مجمّعًا / 9238 ناجحًا / 0 فاشلًا /
0 أخطاء، exit 0، تغطية
77.09% ≥ 72%، شجرة نظيفة عند بدء الاختبار =
**True**)، ثلاث حملات إنتاج طازجة عبر نقطة الدخول
الحقيقية `run_unified_hunt` (تأكيدان في كل حملة عبر CausalGuard ←
ProofBundle ← replay، وكل الضوابط السالبة صامدة، والأصل خارج النطاق
صفر طلبات)، حلقة التعلم الكاملة (PROVEN داخل المختبر المُسيطر عليه)،
و13 بوابة جودة/أمن مُعادة التنفيذ فعليًا عند مراجعة الإصدار.

**ما نُشر:** فرع `mission/umdr38-closure` (رأسه `7b3fa8dc3d7b`) مع كل
الإصلاحات، وحزمة الإصدار النهائية (ZIP + باندل git + 19 مخرجًا في
`deliverables/umdr38/`).

**حالة الإصدار: COMPLETE_LOCAL_REMOTE_PUBLICATION_BLOCKED** — كل بند
قابل للتنفيذ محليًا مكتمل ومُتحقق منه؛ الوحيد المتبقي هو تشغيل GitHub
Actions على الالتزام المنشور بالضبط، وهو محجوب بغياب بيانات اعتماد
الدفع في بيئة البناء (أوامر الدفع والـPR مرفقة).

## ب. المستودع واستعادة Git

- **الـHEAD المنشور السابق:** `2338fd5c172e` — «Update project to
  v0.40.1 UMDR36-2-37 FINAL» (squash نشر يحمل نتيجة المهمة السابقة).
- **الـHEAD النهائي:** `7b3fa8dc3d7ba4164840a82c23abef74281760fd` على الفرع `mission/umdr38-closure`.
- **merge-base:** `1968f63` (نشر v0.40.1 UMDR35-36) — تاريخ المهمة
  التفصيلي نسب مشروع (تحققنا أن له سلفًا مشتركًا مشروعًا) ودُمج بـ
  `-s ours` ليصبح كل شِعَب المهمة حتى `01d1708` أسلافًا قابلين للحل،
  مع بقاء الشجرة مطابقة للمنشور (فرق صفر أسطر عند الدمج).
- **الباندل القديم:** رأسه `9ee46b5` (حقبة Part-20) — أقدم من الفرع
  المحلي `01d1708`؛ كلاهما محفوظ كنسب.
- **المقطع المفقود نهائيًا:** `01d1708..073c64b` (يشمل التزام الأدلة
  `1386d57`) فُقد مع إعادة تدوير بيئة البناء ولم يُدفع قط؛ لا نسخة
  منه موجودة في أي مكان متاح، ومحتواه باقٍ كشجرة النشر `2338fd5`.
  **لم يُختلق أي التزام ولا ادُّعيت هوية شجرة بلا مقارنة فعلية** —
  موثق بدقة في تقرير النسب.

## ج. التغييرات المعمارية والبرمجية

التغييرات من المنشور `2338fd5` إلى رأس الإغلاق (69
سطر diff — القائمة الكاملة في `UMDR38_CHANGED_FILES_MANIFEST.txt`):

- **`scripts/run_tests_with_evidence.py` + `check_test_evidence.py`** —
  عقد أدلة §6.2/§6.3 كاملًا (دليل مُهمل، كتابة ذرّية، tree_clean عند
  بدء الاختبار، فحوص الحداثة: الالتزام/الـlockfile/هوية GitHub
  run/المحاولة، أرضية التغطية، رفض الأدلة الناقصة/القديمة/المعبثة).
- **`scripts/umdr37_production_campaigns.py`** — إصلاحات §7.2 الأربعة
  (سياق تجهيز قابل للعكس، الحالة النهائية الموثوقة عبر `get_state`،
  التنظيف في `finally`، التنقيح) + ثابت `LAB_VERSION` + سجل تأكيدات
  §7.2.C الكامل.
- **`scripts/umdr38_reports.py` / `umdr38_deliverables.py` /
  `umdr38_closure.py` / `umdr38_publish_campaign_evidence.py` /
  `umdr38_final_report.py`** — مولدات المخرجات المشتقة من الأدلة
  (ترفض البيانات الناقصة وتسجل حالات غياب صريحة).
- **اختبارات جديدة:** `test_umdr38_evidence_contract.py` (11)،
  `test_umdr38_campaign_instrumentation.py` (2)،
  `test_umdr38_report_generators.py` (8) + تحديث اختبارات عقد النشر
  وM12 للمسار الجذري.
- **الجذر:** `README.md` + `.github/workflows/ci.yml + nightly.yml +
  weekly-benchmarks.yml` (+ إحالة المتداخل) + `deliverables/umdr37/
  evidence/` (16 ملف أدلة دائمة).
- **uv.lock:** ترقية soupsieve 2.9.2 → 4.1.1 (أربع CVEs جديدة).
- **ما تُرك عمدًا دون مساس:** الوحدات المجمدة (بوابة الوحدات المجمدة
  خضراء)، سلسلة السلطة CausalGuard ← ProofBundle ← replay، كل ضوابط
  النطاق والتفويض والضوابط السالبة، بنية المشروع داخل
  `WebPent_UNIFIED/` (لا نقل جماعي)، والمخرجات التاريخية (موسومة
  كتاريخ لا كحالة حالية).

## د. التحقق من CI

- **مسار سير العمل:** `.github/workflows/ci.yml` على **جذر المستودع**
  (المكان الوحيد الذي يكتشفه GitHub) مع `working-directory:
  WebPent_UNIFIED` — بالإضافة إلى nightly وweekly-benchmarks.
- **رابط التشغيل وRun ID:** **BLOCKED_EXTERNAL_DEPENDENCY** — لا
  بيانات اعتماد دفع في بيئة البناء؛ لا يُدَّعى أي تشغيل GitHub.
- **الالتزام:** `7b3fa8dc3d7ba4164840a82c23abef74281760fd`.
- **نتائج الوظائف (إعادة تنفيذ محلية فعلية لنفس أوامر سير العمل):**

| البوابة | exit |
|---|---|
| state-contract | 0 | ناجحة |
| orchestrator-construction-authority | 0 | ناجحة |
| isolation-denylist | 0 | ناجحة |
| vault-import-authority | 0 | ناجحة |
| test-count-floor | 0 | ناجحة |
| build-info-honesty | 0 | ناجحة |
| direct-io-inventory | 0 | ناجحة |
| ruff-ratchet | 1 | فاشلة |
| deps-cve-gate | 0 | ناجحة |
| secret-scan | 0 | ناجحة |
| bandit-high | 0 | ناجحة |
| coverage-ratchet | 0 | ناجحة |
| vip-audit-gap | 0 | ناجحة |

- **أدلة مرفوعة (محليًا و كسير عمل):** `.webpent-evidence/` (سجل
  الجناح الكامل + النسخة النصية + تغطية)، SBOM (CycloneDX)، ونتائج
  البوابات في `UMDR38_GATE_RESULTS.json`.
- **أوامر الدفع والـPR:** في `UMDR38_CI_VERIFICATION_REPORT.md`.

## هـ. أدلة الاختبار

- **الالتزام المختبر بالضبط:** `e31cad5efcf80331cde1fae5b3c1befb7aad313c`
- **نظافة الشجرة عند بدء الاختبار:** **True**
  (التُقطت قبل كتابة أي شيء؛ دليل الأدلة مُهمل من git — عطب
  `tree_clean: false` البنيوي القديم مستحيل الآن).
- **بايثون:** 3.12.16 | **uv:**
  uv 0.13.8 (x86_64-unknown-linux-gnu)
- **هاش الـlockfile:** `6d714ff5ed5212b8e751d19fc50917aa52fec042583f4d69d9d6b2a75c4ef650`
- **مجمّع:** 9249 | **ناجح:** 9238 | **فاشل:**
  0 | **أخطاء:** 0 | متخطى: 9 |
  xfailed: 3 | xpassed: 0
- **التغطية:** 77.09% (الأرضية 72% — لم
  تُخفض أبدًا) | **exit code:** 0
- **المحاسبة v3:** الواثقات كلها صحيحة والمطابقة الختامية متفقة، ولم
  يُقاطَع التشغيل.

## و. حملات الإنتاج (ثلاث حملات طازجة عند مراجعة الإصدار)

| # | معرف الحملة | الطلبات | نقاط النهاية المكتشفة | النتائج | المؤكدة | CausalGuard | Replay | طلبات خارج النطاق |
|---|---|---|---|---|---|---|---|---|
| 1 | `umdr38-campaign-1-b912fe6b` | 108 | 8 | 9 | 2 | CONFIRMED, CONFIRMED | 2 | 0 |
| 2 | `umdr38-campaign-2-b13989d8` | 108 | 8 | 9 | 2 | CONFIRMED, CONFIRMED | 2 | 0 |
| 3 | `umdr38-campaign-3-5952ca97` | 108 | 8 | 9 | 2 | CONFIRMED, CONFIRMED | 2 | 0 |

- كل حملة: حالات مختبر جديدة، معرف فريد، نفس الإعداد والميزانية،
  تجهيز مُعاد الضبط بين الحملات، وحالة نهائية **موثوقة**
  (`graph.get_state`) لحساب القمع.
- كل نتيجة مؤكدة تحمل `ProofBundle` مختومًا وتحقق replay ناجحًا،
  وCausalGuard هو سلطة التأكيد الوحيدة.
- الضوابط السالبة في كل حملة: حد الأدمن المفروض لم يُؤكد، المورد
  المفقود لم يُؤكد، المسارات العامة لم تُؤكد، **والمصيدة لم تُؤكد**،
  والأصل خارج النطاق استقبل **صفر طلبات** (مثبت من سجل طلبه هو).
- الحملة السببية (root-cause) أعيد تشغيلها أيضًا: confirmed=2،
  drop_offs=[].

## ز. ذكاء الاكتشاف

**هل أثّر نموذج التطبيق/نظام الفرضيات/التعلم على قرارات تنفيذ فعلية؟
نعم — داخل النطاق المُتحقق منه فقط، وبفصل صارم بين المستويين:**

- **مستوى المحدِّد (selector-level):** مُثبت سببيًا بالاختبار الوحدوي
  المثبت (الدليل الحقيقي يرفع المرشح المتأثر بمقدار EVIDENCE_LIFT
  ويقلب الاختيار التالي؛ الدليل المعاكس يُعيد الترتيب هبوطًا). القيد
  على مستوى السيناريو موثق آليًا (آلية «تجربة واحدة لكل فرضية» لا
  تترك مرشحًا معلقًا لإعادة الترتيب) — حُكم صادق بطبقتين، لا ادعاء
  أوسع من القياس.
- **الحلقة الكاملة (full-loop):** أربع أذرع بنفس الميزانية (36/36)
  وقنوات أدلة مختلفة؛ اختلفت التجارب المختارة فعلًا، ونُفِّذت،
  واختلفت النتائج (0 مؤكد في ذراع لا-أدلة مقابل 1 في أذرع الأدلة)،
  وحقيقة الأرض لم تُؤكد إلا بدليل فعلي، والسلسلة السداسية قائمة،
  وبلا أي تجاوز لسلطة أو بوابة أمان (حالات رفض النطاق محترمة:
  2 في الذراع الكامل).
  **التصنيف الصادق: برهان حلقة كاملة عبر مسار الإنتاج على مختبر
  مُحرَّر الفريق — ليس تعلمًا معممًا في العالم الحقيقي، ولا يُدَّعى.**
  - **none**: القناة `none`، الطلبات 36/36، مؤكد 0
  - **coverage**: القناة `coverage`، الطلبات 36/36، مؤكد 1
  - **invariant**: القناة `invariant`، الطلبات 36/36، مؤكد 1
  - **full**: القناة `full`، الطلبات 36/36، مؤكد 1

## ح. الأمان وسلامة الإصدار

- **فرض النطاق والتفويض:** التفويض إلزامي، لا طلب نشط خارج النطاق،
  وحماية same-origin/SSRF أثبتت نفسها في كل حملة (صفر طلبات للأصل
  خارج النطاق).
- **سلطة التأكيد:** CausalGuard وحده يؤكد؛ لا تأكيد LLM ولا ترقية
  فرضيات ولا حواف Knowledge Graph؛ سلسلة CausalGuard ← ProofBundle ←
  replay كاملة في كل نتيجة مؤكدة.
- **فحص الأسرار:** PASS (على الشجرة المتتبعة وفي الحزمة)؛ سجلات
  الحملات منقَّحة (cookies/جلسات).
- **سلامة الوحدات المجمدة:** بوابة الوحدات المجمدة PASS — لا تعديل
  على وحدة مجمدة في هذه المهمة.
- **تحقق الحزمة:** سلامة الأرشيف، لا اجتياز مسارات، لا مسارات
  مطلقة، لا ملفات مطلوبة ناقصة، الفهرس مطابق للمحتوى، لا جذور
  مشروع مكررة، وبيانات التعريف 0.40.1 — التفاصيل والهاشات في
  `UMDR38_RELEASE_MANIFEST.json` و`SHA256SUMS`.
- **مجموعة الأدلة الدائمة:** 16
  ملفًا تحت `deliverables/umdr37/evidence/` بهاش SHA-256 لكل ملف
  ومانيفست مربوط بالالتزام المصدر.

## ط. القيود المتبقية (كلها صريحة، بلا عبارات غامضة)

1. **CI البعيد:** لم يشغَّل GitHub Actions على الالتزام النهائي —
   محجوب بغياب بيانات اعتماد الدفع (BLOCKED_EXTERNAL_DEPENDENCY)؛
   أوامر الدفع والـPR جاهزة.
2. **التعميم:** كل نتائج الاكتشاف والتأكيد داخل مختبرات مُسيطر
   عليها من تأليف الفريق؛ لا ادعاء تغطية للعالم الحقيقي.
3. **العائلات:** access control فقط هي المتحقق عبر مسار الإنتاج؛
   باقي العائلات ليست production-confirmed.
4. **المقطع المفقود من التاريخ:** `01d1708..073c64b` غير قابل
   للاستعادة (موثق في تقرير النسب)؛ محتواه باقٍ كشجرة النشر.
5. **دَين ruff:** خط الأساس أُعيد تقييده عند
   8241
   نتيجة بإصلاح كل نتائج كود umdr38 (صفر جديد) وتوثيق مُعلَن لإضافة
   حقبة umdr37 غير المُقيَّدة سابقًا؛ الرافعة تستمر في منع أي زيادة.

## ي. مصفوفة القبول النهائية (30 بوابة)

| البوابة | الوصف | النتيجة |
|---|---|---|
| G38-01 | Actual repository baseline verified | **PASS** |
| G38-02 | Source history and bundle lineage reconciled | **PASS** |
| G38-03 | No unauthorized Git history rewrite | **PASS** |
| G38-04 | Repository root has a usable README | **PASS** |
| G38-05 | Root-level GitHub Actions workflow exists | **PASS** |
| G38-06 | GitHub actually discovers the workflow | **BLOCKED_EXTERNAL_DEPENDENCY** |
| G38-07 | All mandatory CI gates execute | **PASS** |
| G38-08 | Test evidence bound to the exact tested commit | **PASS** |
| G38-09 | Evidence current; cannot accept stale output | **PASS** |
| G38-10 | Hook-level v3 accounting correct | **PASS** |
| G38-11 | Coverage threshold passes | **PASS** |
| G38-12 | Static and security gates pass | **PASS** |
| G38-13 | Campaign instrumentation does not accumulate wrappers | **PASS** |
| G38-14 | Final graph state measured authoritatively | **PASS** |
| G38-15 | Production campaign raw evidence preserved | **PASS** |
| G38-16 | Three independent campaigns execute | **PASS** |
| G38-17 | Required IDOR outcomes reproduced | **PASS** |
| G38-18 | ProofBundle and replay evidence valid | **PASS** |
| G38-19 | Negative controls remain unconfirmed | **PASS** |
| G38-20 | Out-of-scope origin receives zero requests | **PASS** |
| G38-21 | Learning evidence scope accurately classified | **PASS** |
| G38-22 | Discovery-efficiency metrics evidence-derived | **PASS** |
| G38-23 | Lab version consistent everywhere | **PASS** |
| G38-24 | BUILD_INFO and version identity consistent | **PASS** |
| G38-25 | All active reports mutually consistent | **PASS** |
| G38-26 | Final release manifest reproducible | **PASS** |
| G38-27 | Final ZIP passes integrity and completeness checks | **PASS** |
| G38-28 | Secrets and credentials absent from the package | **PASS** |
| G38-29 | Full regression passes on the release source | **PASS** |
| G38-30 | Final published commit and CI evidence linked | **BLOCKED_EXTERNAL_DEPENDENCY** |

**الإحصاء:** {"PASS": 28, "BLOCKED_EXTERNAL_DEPENDENCY": 2} — لا
PASS_WITH_WARNINGS؛ كل بوابة إما PASS أو FAIL أو
BLOCKED_EXTERNAL_DEPENDENCY مع سبب موثق.

## ك. القرار النهائي

**COMPLETE_LOCAL_REMOTE_PUBLICATION_BLOCKED**

السبب: كل بند قابل للتنفيذ في بيئة البناء مكتمل بأدلة فعلية مربوطة
بمراجعة الإصدار (الجناح الكامل صفر فشل/صفر أخطاء، البوابات خضراء،
الحملات الثلاث مُعاد إنتاجها بكل الثوابت، الحزمة مُتحققة). البند
الوحيد المتعذر هو تشغيل GitHub Actions على الالتزام المنشور (البوابتان
G38-06 وG38-30) لغياب بيانات اعتماد الدفع — وهذا بند خارجي معلن، لا
نقص في العمل، ولا يُدَّعى إكمال النشر الكامل دونه.

</div>
