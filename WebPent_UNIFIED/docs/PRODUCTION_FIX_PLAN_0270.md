# PRODUCTION_FIX_PLAN_0270 — خطة إصلاح الإصدار 0.27.0 (red teaming موثق)

**التاريخ:** 2026-10-29
**الأساس:** الشجرة 0.26.0 (RESIDUAL CLOSURE) — 6708 اختبار أخضر، canary 7x STABLE، ruff ratchet 6250.
**المنهجية:** red teaming مركّز على حلقة التعلم (المسار 6.5)، طبقة النشر، سطح الـCLI، وبوابة المجمدة — بقراءة مباشرة للكود (file:line أدناه)، لا افتراضات.

---

## نتيجة الـred teaming — الأدلة

| # | الملاحظة | الدليل (file:line) | الخطورة |
|---|----------|--------------------|---------|
| C-9 | المسار 6.5 (A/B ظلّي لأثر الدروس) ما زال "بنية جاهزة": يوجد العقد (`integration/learning_ab_contract.py` — dataclasses فقط بلا أي منطق قرار) + المقاييس الرصدية (`memory/improvement_tracker.py`)، **وليس** هناك runner حقيقي control-vs-treatment ولا مجدول أسبوعي — لا شيء يشغّل النافذتين فعليًا | `docs/learning_source_of_truth.md:50-54` ("a real control-vs-treatment lab runner remains future work")؛ `integration/learning_ab_contract.py:36-50` (حقل `verdict` بلا محلل ينتجه)؛ grep على `ab_test\|ab_window\|ab_experiment` في src = صفر | عالية — الحلقة التعليمية بلا إثبات تجريبي دوري |
| C-10 | لا توجد عتبات رقمية معلنة لأي قرار ترقية/تراجع على نتائج A/B: عقد `ABEvidence.verdict` يعرّف ثلاث قيم ("learning_proven"/"inconclusive"/"learning_not_observed") لكن لا توجد دالة في الشجرة كلها تحسبه، ولا أي أرقام دنيا (حجم عينة، نسبة تحسّن، سماح تراجع) | `integration/learning_ab_contract.py:41`؛ grep `PROMOTION_REDUCTION\|thresholds.*ab\|min_hypotheses` = صفر | عالية — بلا عتبات معلنة أي قرار A/B يبقى اجتهادًا غير قابل للتدقيق |
| D-1 | حاوية الإنتاج تبدأ **root** ثم تفوّض عبر gosu في entrypoint (نمط موثق عمدًا لإصلاح تصادم uid الـbind-mount) — لكن لا يوجد مسار بديل rootless موثق ولا تحقق وقت التشغيل من أن السقوط فعلاً حدث | `Dockerfile:75-92`؛ `entrypoint.sh:1-30` | متوسطة — النمط الحالي مقصود لكن مسار التحقق غائب |
| D-2 | `WEBPENT_USERS` مفروض في compose (جيد) وأسرار LLM عبر `.env` 0600 عبر install.sh (أصلح 0.26.0) — لكن `credentials_template.json` في الجذر قد يُظن أنه قالب يُملأ ويُنسى بمفتاح حقيقي | `docker-compose.yml:128-129`؛ `credentials_template.json` (الجذر) | منخفضة — توثيق فقط |
| G-1 | `docs/learning_source_of_truth.md` يقرر أن `brain/lessons.py` متقاعد "يُحذف في نافذة أمان لاحقة معلنة" — ما زال في الشجرة ويحتفظ به اختباراته فقط | `docs/learning_source_of_truth.md:21-25` | منخفضة — نافذة معلنة |

## قرار النافذة 0.27.0

تنفيذ C-9 + C-10 كاملين في هذه النافذة (هما اللذان يحولان 6.5 من "بنية جاهزة" إلى "حلقة تعلم تعمل كل أسبوع"). البنود D-1/D-2/G-1 توثيق معلن في هذا الملف (نافذة لاحقة لو طلبت التنفيذ العميق).

---

## C-9 — مجدول نافذتي A/B الفعليتين (أسبوعي)

**الهدف:** كل أسبوع ISO، لكل (client_id, target_url) مسجّل في المختبر، تُفتح زوج نافذتين حقيقيتين على نفس الهدف وبنفس الوضع، بالتتابع:

1. **نافذة control** — حملة حقيقية بعلم التعلم مطفأ (`ENABLE_LESSON_CONSULTATION=false`).
2. **نافذة treatment** — حملة حقيقية بعلم التعلم مفعّل (الافتراضي الحالي، `enable_lesson_consultation=true`).

**التصميم (جديد بالكامل، إضافي):**

- وحدة جديدة: `src/webpent/memory/ab_lab.py` (memory/ هو مصدر الحقيقة لحلقة التعلم — قرار 6.1/6.2).
- مخزن SQLite مستقل `ab_lab.sqlite3` بنفس نمط `ImprovementTracker` (فشل مفتوح في القياس، لا يمس نتائج الأمان).
- جدولان: `ab_weeks` (week_key = `AB-<isoyear>-W<isoweek>`، client_id، target_url، target_type، mode، status، verdict_json) و `ab_runs` (week_key، arm، campaign_id، status: planned/running/completed/failed/metrics_missing، metrics_json).
- `open_week(...)` idempotent بـ (week_key, client_id, target_url) — لا ازدواج أسبوعي.
- `tick(now, runner, collector)`: يشغّل النافذة المستحقة الواحدة فقط لكل tick (control أولًا ثم treatment — منع التداخل على نفس الهدف)، ويجمع مقاييس الحملة من `ImprovementTracker` (نفس المسار الذي يكتبه hunt فعليًا عبر `facade.complete` → `persist_campaign_learning`).
- الحالة: `planned → control_done → evaluated` (أو `metrics_missing → evaluated_inconclusive`).
- الـrunner قابل للحقن: الإنتاج = استدعاء `webpent hunt --url ... --mode ... --authorization ... --client-id ...` كعملية منفصلة بالبيئة المفرّطة (لضمان عزل العلم بين النافذتين على مستوى العملية)، الاختبارات = fakes. **بدون authorization يرفض فتح أسبوع (fail-closed).**
- سقف معلن: `max_inconclusive_weeks = 4` — بعد 4 أسابيع غير حاسمة متتالية يوسم المختبر الأسبوع القادم بـ `paused_advisory` (توصية إيقاف مؤقت، لا حظر آلي).

**الربط:** أوامر `webpent ops learning-ab open|tick|status` في `cli/ops.py` (open/tick خلف `run_campaign` من مصفوفة RBAC المجمدة — نفس صلاحية إطلاق الحملات، بلا لمس المصفوفة).

**القبول:** اختبارات جديدة تغطي: idempotency الأسبوع، التسلسل control→treatment، رفض غياب authorization، جمع المقاييس وفقدانها (metrics_missing)، تحوّل الحالات، وtick لا يشغّل أكثر من نافذة مستحقة واحدة.

## C-10 — العتبات الرقمية المعلنة

**الهدف:** قرار A/B قابل للتدقيق رقميًا — لا اجتهاد.

**العتبات المعلنة (constants مجمّدة في `ab_lab.py`، منسوخة حرفيًا في هذا الملف):**

| العتبة | القيمة المعلنة | المعنى |
|--------|----------------|--------|
| `min_hypotheses_tested_per_arm` | **10** | أقل من 10 فرضيات مختبرة في أي ذراع → `inconclusive` (عينة صغيرة جدًا) |
| `promotion_reduction_ratio` | **0.10** | treatment يجب أن يقلّل الفرضيات المختبرة لكل finding مؤكد بنسبة ≥10% مقابل control |
| `regression_tolerance_ratio` | **0.20** | treatment أسوأ بنسبة ≥20% → `learning_not_observed` |
| `require_no_confirmed_loss` | **True** | أي نقصان في الـfindings المؤكدة في treatment مقابل control → يُسقَط الحكم إلى `learning_not_observed` مهما كانت الكفاءة (الأمان أولًا) |
| `max_inconclusive_weeks` | **4** | توصية إيقاف مؤقت بعد 4 أسابيع غير حاسمة متتالية |

**قاعدة الحسم (ترتيب تقييم صارم):**
1. أي ذراع ناقصة المقاييس أو أقل من `min_hypotheses_tested_per_arm` → `inconclusive` (سبب معلن).
2. `require_no_confirmed_loss` ومنقوص المؤكدات → `learning_not_observed`.
3. `efficiency_gain = 1 - (treatment_tested/confirmed) / (control_tested/confirmed)`:
   - ≥ `promotion_reduction_ratio` → `learning_proven`
   - ≤ `-regression_tolerance_ratio` → `learning_not_observed`
   - ما بينهما → `inconclusive`
4. النتيجة تُحفظ في `ab_weeks.verdict_json` (verdict + reasons + الأرقام الخام) وتظهر في `ops learning-ab status`.

**القبول:** دالة تقييم نقية حتمية (نفس المدخلات → نفس الحكم) مغطاة بحدود كل عتبة (فوق/تحت/الحد نفسه)، والحكم الثلاثي مطابق لقيم عقد `ABEvidence` القائمة.

---

## بنود موثقة خارج نطاق هذه النافذة (معلنة، بلا كسر)

- **D-1:** إضافة وضع rootless اختياري موثق + تحقق entrypoint أن السقوط فعلاً حدث (`id -u` بعد gosu) — نافذة نشر لاحقة.
- **D-2:** تحذير صريح في README/دليل النشر على أن `credentials_template.json` قالب قراءة فقط — نافذة توثيق.
- **G-1:** حذف `brain/lessons.py` المتقاعد بنافذة إعلان خاصة (سياسة "الحذف تغيير معلن منفصل").

---

## بروتوكول النافذة المجمدة 0.27.0

- ملفات جديدة (scope completions بعد إعادة التثبيت): `src/webpent/memory/ab_lab.py`، `tests/test_ab_lab.py`، `scripts/refreeze_manifest_0270_ab_lab.py`.
- ملفات معدلة (thaw موثق في `tests/test_frozen_module_gate.py` بمجموعة `AB_LAB_20261029_*`): `src/webpent/cli/ops.py` (أوامر learning-ab)، `tests/test_frozen_module_gate.py` (النافذة نفسها).
- إعادة تثبيت manifest بـ `scripts/refreeze_manifest_0270_ab_lab.py` (نفس بروتوكول 0.25.0/0.26.0: نفس المسارات والترتيب + الملفات الجديدة).
- بوابة النشر: بوابة المجمدة خضراء + الاختبارات الجديدة خضراء + canary 7x STABLE + ruff نظيف على الملفات الجديدة.
- الإصدار: pyproject/`__init__`/CHANGELOG → **0.27.0**، BUILD_INFO وCURRENT_RELEASE مواءمان.

---

## حالة إغلاق الخطة (2026-10-31 — تحديث أخير)

كل بنود هذه الخطة **مغلقة بالكامل**. آخر بند أُغلق هو G-1:

| البند | الحالة | النافذة |
|---|---|---|
| C-9 (مجدول نافذتي A/B) | ✅ منفذ | 0.27.0 (2026-10-29) |
| C-10 (العتبات الرقمية المعلنة) | ✅ منفذ | 0.27.0 (2026-10-29) |
| D-1 (وضع rootless + تحقق السقوط) | ✅ منفذ | 0.28.0 (2026-10-30) |
| D-2 (تحذير credentials_template.json) | ✅ منفذ (مبكرًا) | 0.27.0 (2026-10-30) |
| G-1 (حذف `brain/lessons.py` المتقاعد) | ✅ منفذ | **0.29.0 (2026-10-31)** |

تفاصيل نافذة G-1 (سياسة "الحذف تغيير معلن منفصل" — هذه هي نافذة الإعلان والتنفيذ):
- حُذف `src/webpent/brain/lessons.py` المتقاعد (قرار التقاعد في `docs/learning_source_of_truth.md`) مع اختباره `tests/test_u15_lessons.py` (5 اختبارات).
- `tests/lab/lcs2_sweep_instrument.py` (المستهلك غير الاختباري الوحيد): يحمل الآن مكافئًا محليًا أدنى للمفكرة بنفس الدلالات حرفيًا، موثق في مكانه.
- `scripts/resurrect.py`: شطب `webpent.brain.lessons` من `BRAIN_MODULES` (لا شيء يُستعاد؛ الحي `webpent.memory.lessons` مثبت في `SPINE_MODULES`).
- إعادة تجميد الـmanifest: `scripts/refreeze_manifest_0290_g1_lessons_removal.py` (659 → 658 مدخلًا، حذف معلن + bump `__init__.py`).
- الإصدار: pyproject/`__init__`/BUILD_INFO/CURRENT_RELEASE/Dockerfile ARG → **0.29.0**.
