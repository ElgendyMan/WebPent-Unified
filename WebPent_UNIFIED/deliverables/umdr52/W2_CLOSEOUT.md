# W2_CLOSEOUT — UM-DR-52 Week 2: Adaptive Experimentation

**الحكم: COMPLETE على البناء والقياس المختبري (24/24 اختبارًا + دلتا تكامل VERIFIED)؛ اقتصاد الميدان FIELD يبقى مفتوحًا إلى حملات W3 — معلنًا، لا مخفيًا.**

## 1) الأدلة المبنية

| المكوّن | الملف | الاختبار |
|---|---|---|
| دورة الحياة الثمانية (VIEW بعد الـreducer) | `src/webpent/researcher/adaptive_engine.py` (`LIFECYCLE_STATES`, `lifecycle_of`, `reduce_final_lifecycle`) | `tests/test_umdr52_w2_adaptive.py::TestLifecycleView` (7) |
| دفتر التجارب + تعلم الفشل + QC التكرار | نفس الوحدة (`ExperimentLedger`, `ExperimentRecord`) | `::TestExperimentLedger` (7) |
| الاختيار المحدود بالمعلومة + الحارس | نفس الوحدة (`select_adaptive`) | `::TestSelectionAndParallelism` (3) |
| التوازي الآمن (لا خلط جلسات/هويات) | نفس الوحدة (`partition_safe_parallel`, fail-closed على جلسة مجهولة) | `::TestSelectionAndParallelism` (3) |
| اقتصاد التجربة مقاسًا | نفس الوحدة (`experiment_economics`) → `deliverables/umdr52/EXPERIMENT_ECONOMICS.json` | `::TestEconomics` (2) |
| عزل السلطة (استشاري نقي) | الوحدة كاملة — بلا I/O/تنفيذ/Findings | `::TestAuthorityIsolation` (2) |

**النتيجة: 24/24 أخضر.**

ما لم يُبنى لأنه موجود مسبقًا (قانون لا-تكرار §0.11): mutation/decomposition/competing-hypotheses/negative-evidence في `evolution.py`؛ صيغة الأولوية `EIG×Impact×Conf/(Cost+Risk)` في `brain_engine.py`؛ خطط التجارب التفريقية في `experiment_planner.py`.

## 2) قياس التكامل W1→W2 (البند الإغلاقي الإلزامي §4)

- **الملف:** `deliverables/umdr52/W2_INTEGRATION_DELTA.json` (مولّد من `scripts/umdr52_w2_integration_delta.py` عبر الصيغة الحقيقية `estimate_priority_inputs`/`priority_formula` على البركة المعتمدة).
- **الترتيب الكامل انقلب:** OFF `[transfer, invoice-read, order-skip, fasttrack, profile-write, list-read]` (بـdeclared info_gain) مقابل ON `[order-skip, transfer, invoice-read, fasttrack, profile-write, list-read]` — تجربة workflow-skip صعدت للمركز الأول بمصدرها الدعم السلوكي المقاس (`backing_for` مسجل لكل هدف في الملف).
- **الاختيار k=3 انقلب** بالعضوية والترتيب: OFF `[transfer, invoice-read, order-skip]` → ON `[order-skip, transfer, invoice-read]`.
- **السطح المخطط:** `plan_experiments` على هذا الـfixture ينتج ختتين فقط — انقلاب العضوية top-k مستحيل رياضيًا على بركة من 2؛ سجل كما هو (الـnote في الملف)، والسطح المقاس للتكامل هو بركة الـfixture المعتمدة.

## 3) تعلم الفشل (إلزامي §4 B2) — بحكم البناء والاختبار
- تجربة فاشلة بلا سبب محلَّل ⇒ الledger يرفض تسجيلها (`ValueError`) — fail-closed.
- تكرار تصميم فاشل مطابق على نفس الخلية ⇒ ممنوع بلا دليل جديد (`repeat_allowed`)؛ مسموح على خلية أخرى أو بدليل جديد.
- الدروس قابلة للسحب (`lessons()`) وتغذي `LESSONS_LEDGER.json`.

## 4) مقياس المعلومة — معلن ومسمّى بدقة (§4 B3)
`info_gain` في هذا المشروع **ليس entropy معايرًا** — إنه درجة كثافة حتمية معلنة (كثافة خلايا التغطية غير المحققة + gain المعلن للفرضية) بمصادر محسومة في `estimate_priority_inputs`. الصيغة النهائية `Priority = EIG×Impact×Conf/(Cost+Risk)` حرفية وحاضرة القرار (W1: الخريطة `p/(p+k)` تقلب قرارات) — التعريف مقيس لا مستعار.

## 5) الحدود المعلنة
1. `EXPERIMENT_ECONOMICS.json` حاليًا **مُعلنة-محددة** (fixture: declared info_gain + كلفة الثلاثية المقدّرة 3 طلبات) — سطر `scope_note` يصرح بذلك؛ اقتصاد الميدان بالقياس الحي يُقفل في إغلاق W3 أو يعلن NOT_VERIFIED.
2. توازي آمن مقاسًا كعزل هويات/جلسات في `partition_safe_parallel` — التنفيذ المتوازي الفعلي في الحملات الميدانية يبقى يد الحملة.
3. W6-chain عبر الحملات أُعيد قياسه في W3 (أثر الـledger عبر الحملات على Juice Shop).
