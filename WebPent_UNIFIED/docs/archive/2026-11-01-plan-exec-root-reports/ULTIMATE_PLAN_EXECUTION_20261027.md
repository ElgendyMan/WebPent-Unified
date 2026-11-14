# سجل تنفيذ الخطة الشاملة — Ultimate Autonomous Bug Hunter

**تاريخ التنفيذ:** 2026-10-27
**الخطة:** `WEBPENT_ULTIMATE_MASTER_PLAN.md` (13 اقتراحًا، المرفوعة من
تقريرين + تدقيق كود مباشر بتاريخ 2026-10-25/26)
**الشجرة:** خلفًا مباشرًا لـ`webpent_FINAL_MERGED_20261026.zip` (الإصدار
0.13.0) — كل قرارات الدمج محفوظة ولم تُمس.
**الإصدار الناتج:** 0.14.0

هذا الملف هو السجل الهندسي الكامل للنافذة: ما نُفذ، بأي ترتيب، أي ملفات
التي لمست، أي بوابات تحركت ولماذا، وأي انحرافات عن نص الخطة مع مبررها.

---

## 1) ملخص التحقق النهائي

| المقياس | قبل (0.13.0) | بعد (0.14.0) |
|---|---|---|
| الاختبارات الكاملة | 6,334 | **6,430** (+96) |
| ناجحة | 6,326 | **6,424** |
| فاشلة | 7 (كلها موروثة) | **3** (نفس الموروث المتبقي — أنجحنا 4) |
| skipped | 0 | 2 (goed_v1 الموثّق) |
| xfailed | 1 | 1 (B-06 الموثّق) |
| سطور الكود الميت في src | ~22,215 | **0** (مؤرشفة) |
| أوامر الدخول | 3 بفلسفات ميزانية مختلفة | **1** (`hunt --mode`) + aliases |
| أعضاء VulnClass | 34 | **47** (+13) |
| بوابات frozen manifest | 770 إدخالًا | 650 (632 بعد الأرشفة + 18 scope completion) |
| direct-I/O records | 796 | 773 (الأرشفة أزالت مواقع نقل ميتة) |
| الإصدار | 0.13.0 | 0.14.0 (متزامن: pyproject + `__init__` + CHANGELOG + الاختبار) |

الفشل الموروث الثلاثة المتبقي (يفشل بالفعل على أشجار أصله — موثق في
`MERGE_20261026.md` §6): `test_jwt_confusion_*` (2) و`test_r3_e1_advisory`
(1). الفشل الرباعي `test_five_families` **أُصلح** في هذه النافذة (انظر
§7 أدناه).

## 2) ما نُفذ بالترتيب (خارطة الطريق، الجزء الرابع من الخطة)

| # | الاقتراح | الحالة | أهم الملفات |
|---|---|---|---|
| 1 | 10 — README بفلسفة 30 ثانية | ✅ كامل | `README.md` (أعيدت كتابته) |
| 2 | 4 — أرشفة الكود الميت | ✅ كامل | `archive/pre_v10_prototypes/` (17 مجلدًا + README جرد)، `pyproject.toml`، `frozen_modules.sha256` (−138)، اختبار البوابة |
| 3 | 11 — تثبيت بأمر واحد | ✅ كامل | `install.sh`، `.env.minimal.example`، `docker-compose.yml` (profile quickstart)، doctor (موجود) |
| 4 | 13 — init تفاعلي | ✅ كامل | `cli/commands.py` (`_run_interactive_init`) |
| 5 | 1 — توحيد المحرك | ✅ كامل | `state/unified_state.py`، `adapters/legacy_state_bridge.py`، `cli/unified_hunt.py`، `cli/commands.py` (hunt/hunt-plan/deprecations)، `state/state.py` (حقول الميزانية) |
| 6 | 3 — حلقة التعلّم | ✅ كامل | `graph/lesson_nodes.py`، `graph/builder.py` (عقدتان + توجيه)، `state/state.py` (3 قنوات) |
| 7 | 2 — الميزانية الديناميكية | ✅ كامل | `graph/surface_sizing.py`، `graph/budget_governor.py` (rb-3)، `graph/builder.py` (عقدة + سقف rabbit-hole مشتق) |
| 8 | 12 — وضوح المخرجات | ✅ كامل | `graph/progress_display.py`، `shared/finding_announcer.py`، `cli/unified_hunt.py` (stream)، ملخص تنفيذي (موجود من EGAIE — مذكور في README) |
| 9 | 5 — عمق recon | ✅ كامل | `tools/recon/gau.py`، `tools/recon/nmap.py`، `shared/source_leak_discovery.py`، تسجيل الأدوات + manifest التنفيذيات |
| 10 | 7 — فئات ثغرات جديدة | ✅ كامل | 13 عضو VulnClass، `validators/graphql_validator.py`، `validators/oauth_misconfig_validator.py`، `shared/cache_poisoning_detector.py`، `shared/prototype_pollution_detector.py`، `graph/detector_nodes.py` (4 عقد)، تغطية remediation كاملة في 7 ملفات |
| 11 | 8 — توافق LLM | ✅ كامل | `shared/llm_consistency.py` (خلف flag افتراضي معطل) |
| 12 | 6 — تشغيل متوازٍ | ✅ كامل | `shared/global_rate_governor.py`، `service/portfolio.py` |
| 13 | 9 — مراقبة workers | ✅ كامل | `api/workers_status.py` (router مضمّن في app.py)، `workers/monitor_alerts.py`، `dashboard/workers_page.html` |

## 3) البوابات التي تحركت (كل واحدة بتوثيق في مكانها)

1. **frozen_modules.sha256:** إزالة 138 مدخلًا مؤرشفًا (بوابة الاختبار:
   مجموعة `ULTIMATE_PLAN_20261027_ARCHIVED_PATHS` + الحاجز 690→630 +
   طرح الأرشيف من expected_drift)؛ إعادة تثبيت 10 ملفات مجمّدة معدّلة
   (`ULTIMATE_PLAN_20261027_THAW_PATHS`)؛ تثبيت 18 ملفًا جديدًا كـscope
   completion (`ULTIMATE_PLAN_20261027_SCOPE_COMPLETION_PATHS`). الإجمالي
   650.
2. **direct_io_inventory:** إعادة توليد (796→773): الأرشفة أزالت سجلات
   مواقع نقل ميتة (cqa/execution.py)، و+2 سجلات approved للحدود الآمنة
   في gau/nmap. دبابيس المواقع غير المعتمدة 33/27→31/25 (set-diff موثّق
   في تعليق الدبوس: الباقي = القديم ناقص الأرشيف، صفر مواقع جديدة).
3. **isolation_denylist:** عقد 1.2→1.3 — إعادة ترقيم مدخلي
   manual_review_ok في tools/registry.py (237/239→243/245) بعد إضافة
   gau/nmap لقائمة auto_discover (نفس الموقعين، نفس الأصل compile-time
   literal).
4. **broad-exceptions register:** تقاعد مدخل goed_v1/family_strategies.py
   (الملف غادر src/ مع الأرشيف) في الاختبار و
   `docs/ACCEPTED_EXCEPTIONS_REGISTER.md`.
5. **hygiene gate (r3_residue_classification.json):** إضافة
   `.env.minimal.example` لقائمة C4 (نفس فئة الإعفاء لـ.env.example) مع
   addendum موثّق.
6. **بوابة الإصدار:** 0.14.0 متزامن (pyproject + `__init__` + CHANGELOG +
   tests/test_release_packaging.py).
7. **اختبارات السلوك المحدثة بتوثيق (نفس النمط المتبع في كل نافذة
   سابقة):** `test_v23_cli_commands` (hunt→hunt-plan)،
   `team1_acceptance/test_m2a_exit_code_honesty` (نفس الشيء)،
   `test_vip_parallel_recon` (عدّادات الطوبولوجيا 48/50→55/57 — الـ7
   عقد الإضافية)، `test_five_families` (استيراد goed_v1 محمي + skipif
   موثّق لاختباري الجرد).

## 4) الإضافات المعمارية الجوهرية (قرارات التصميم)

### المحرك الموحّد (اقتراح 1)
قرار التصميم المركزي: **التوحيد عند نقطة الدخول وطبقة الميزانية، لا عند
الجراف**. الجراف الإنتاجي (80+ عقدة) هو المحرك الوحيد؛ أوضاع
quick/standard/deep هي presets موثقة (`state/unified_state.py`) تُمرر
كسقوف ميزانية عبر قنوات معلنة في الـschema، والميزانية الديناميكية تكيفها
حسب السطح المقاس. `--authorization` إلزامية للحظر الجديد (نفس وضعية
عائلة hunter). الحد الصلب (recursion_limit) دائمًا فوق الميزانية
الناعمة (حاكم الميزانية) بمقدار رأس مُوثّق (60 خطوة) — التقارب يتم
دائمًا عبر completion cutoff لا GraphRecursionError.

### حلقة التعلّم (اقتراح 3)
العقدتان fail-open للحملة وfail-closed للذاكرة: أي مشكلة في
الاستشارة/التخزين تعني "الحملة تكمل كما لو لا دروس موجودة" (سلوك ما قبل
الخطة بالظبط). مخرجات الاستشارة أرقام modifiers وملخصات مجردة — الدروس
بيانات أولًا وأخيرًا (حد الثقة الموثق في README).

### الميزانية الديناميكية (اقتراح 2)
`budget = 50 + surface_size × 1.0` مقيدة بـ`min(الناتج, 400)` وبسقف
التكلفة (40 خطوة/دولار)، وأرضية `max_graph_steps` (الرقم الديناميكي لا
يصغّر أبدًا هدفًا صغيرًا). الاحتياطيات النسبية 12%/15% بأرضية 19/24
الرياضيات الموثقة — عند الميزانية المسطحة 50 السلوك حرفيًا كما كان.
GOVERNOR_VERSION ارتفع rb-2→rb-3 لتكون الأدلة self-describing.

## 5) الالتزام بالأنماط المعمارية القائمة

كل وحدة جديدة بنيت فوق الأنماط الموجودة، لا بديلًا عنها:
- الكواشف الحتمية فوق نمط `tech_stack_cve.py` (دوال نقية فوق evidence
  محقون — صفر شبكة، صفر LLM).
- الـvalidators فوق نمط `production/validators.py` (ValidationResult مع
  CONFIRMED/REFUTED/INCONCLUSIVE).
- أدوات recon فوق نمط `arjun.py` (run_command boundary + scope check +
  settings gate).
- عقد الجراف مسجلة بنمط V7 deep-probe (تسجيل غير شرطي + تمرير داخلي عند
  التعطيل — صفر أثر جانبي).
- الـfeature flags بنمط `enable_parallel_recon` (كلها في settings.py مع
  توصيف دقيق، defaults حسب نص الخطة: GraphQL/الكواشف/dروس/الميزانية
  on، وgau/nmap/LLM-consistency/source-leak off).

## 6) الانحرافات عن نص الخطة (موثّقة بمبررها)

1. **نجاح 4 اختبارات موروثة** (خارج نص الخطة): الخطة لم تطلب إغلاق فجوة
   VulnClass لسلالة donorC، لكن اقتراح 7 أضاف أعضاء enum — وإضافة فئات
   العائلات الخمس كانت التعديل الصحيح المترابط (الإطار كله موجود
   وفاعل، والفجوة موثقة أصلًا في سجل الدمج). النتيجة: الفشل الموروث
   7→3.
2. **`validators/` كانت موجودة** (حزم causal القديمة) — الوحدات الجديدة
   أضيفت داخلها بدون مس `__init__.py` المجمد (الوحدة الفرعية تستورد
   مباشرة).
3. **عقد الكواشف الأربعة مسجلة دائمًا** بدل التسجيل الشرطي خلف flag
   (نمط `_attack_graph_enabled`): التمرير الداخلي أرخص تعقيدًا في التوصيل
   ويحقق نفس عقد "صفر أثر جانبي" (REST-only target يدفع 4 supersteps
   شبه-صفرية). موثّق في builder.py.
4. **اختباران لجرد استراتيجيات goed_v1 أصبحا skipif** بدل استمرار الفشل
   أو نقل الاستراتيجيات: الأرشفة هي نص الخطة، والاختباران كانا الاستخدام
   الحي الوحيد. موثّق في الاختبار نفسه وقسم الاستثناء بأرشيف README.

## 7) خطوات ما بعد هذه النافذة (خارطة الخطة للمراحل الطويلة)

الخطة نفسها تقدر بنافذات أطول للأثر الكامل — ما نُفذ هنا هو الهيكل
الكامل الموصول والمختبَر، والقابل للتوسيع:
- **اقتراح 1 المرحلة 1 (audit دالة-بدالة):** توثيق تداخل hunt-auto
  مقابل الجراف الكامل — الوحدة الموحدة تُغلفت فوق الجراف؛ الـaudit
  التفصيلي يبقى عمل متابعة قبل حذف aliases نهائيًا بعد دورتي إصدار.
- **اقتراح 3 المرحلة 3 (shadow/canary):** `shared/shadow_detector.py`
  جاهز؛ قياس "هل الاستشارة بالدروس حسّنت فعلًا" يحتاج حملات تراكمية على
  benchmark — البنية موصولة والقياس عمل تشغيلي.
- **اقتراح 2 المرحلة 4 (A/B على benchmark):** نفس المنطق — الأداة
  (`benchmark/metrics.py evaluate()`) جاهزة والمقارنة عمل قياس.
- **اقتراح 5 المرحلة 1 (قياس فجوة بأهداف حقيقية):** يتطلب targets
  مصرَّحًا بها — خارج نطاق نافذة كود.
- **اقتراح 7 المرحلة 5 (OAuth العميق):** النسخة الحتمية الأساسية نُفذت؛
  فهم تدفقات OAuth الكاملة (families كاملة) عمل متابعة.
- **حذف الأرشيف نهائيًا:** بعد دورة إصدار واحدة خالية من تقارير تعتمد
  عليه (المرحلة 3 من اقتراح 4).

## 8) كيف تتحقق بنفسك

```bash
.venv/bin/python -m pytest tests -q          # 6,424 passed / 3 inherited
python scripts/doctor.py                     # فحص صحة التثبيت
webpent hunt --help                          # الأمر الموحد
sha256sum -c frozen_modules.sha256           # البوابة: كل الإدخالات OK
uv run python scripts/regenerate_direct_io_inventory.py --help   # أداة الجرد (لا تشغلها إلا بعد تغيير نقل متعمد)
```
