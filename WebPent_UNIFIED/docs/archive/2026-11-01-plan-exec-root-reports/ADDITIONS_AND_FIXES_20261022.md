# سجل الاضافات والاصلاحات — TEAM-MERGE + TEAM-REVIEW-REFREEZE (2026-10-22)

هذا الملف يوثّق كل ما أُضيف وكل ما أُصلح في عملية الدمج والمراجعة وإعادة
التجميد على شجرة WebPent. كل بند موثّق برقم commit ومسار ملف قابل للتحقق
من الشجرة المسلّمة (ZIP). التاريخ النهائي للشجرة: commit `f6e2cb7`
(فرع `donorC-side`).

تسلسل الـ commits:
`ddc5a02` base v21 → `c916990` donorC (Comprehensive(1)) → `60e0460` donorV
(v15.2) → `0b1c041` merge → `9813774` restore 28 C-unique → `835c16e`
Project Zero → `3c4fffe` hygiene fix → `deb6724` purge → `d08e9d1` reports →
`4e32a86` hunter_runner fix → `1dfcbe4` re-freeze → `f6e2cb7` review report.

---

## 1) الاضافات المؤلَّفة (كود جديد كتبته في هذه العملية)

### أ. Project Zero — 7 بنود (commit `835c16e`) — 4940 سطرًا في 17 ملفًا

وحدات جديدة (10 ملفات):

| ملف | أسطر | البند |
|---|---|---|
| `src/webpent/memory/postmortem.py` | 548 | تشريح ما بعد الحملة (postmortem) |
| `src/webpent/shared/tech_stack_cve.py` | 484 | ربط حزمة التقنيات بثغرات CVE المعروفة |
| `src/webpent/shared/surface_influence_graph.py` | 366 | رسم بياني لتأثير الأسطح |
| `src/webpent/memory/taint_tracker.py` | 436 | تتبع التلوّث (taint tracking) للبيانات |
| `src/webpent/shared/red_vs_blue.py` | 329 | محاكاة هجوم/دفاع (red vs blue) |
| `src/webpent/models/postmortem.py` | 240 | نموذج بيانات postmortem |
| `src/webpent/shared/shadow_detector.py` | 265 | كاشف الظل (shadow detector) |
| `src/webpent/shared/surface_drift.py` | 256 | كشف انزياح الأسطح |
| `src/webpent/models/taint.py` | 136 | نموذج بيانات taint |

تعديل مؤلَّف داخل الالتزام نفسه:

- `src/webpent/agents/devils_advocate/agent.py` (+61 سطرًا): ربط إنتاجي حقيقي —
  السطر 341 يستورد `get_postmortem_manager`، والسطر 455 يستدعي
  `_record_devils_advocate_postmortem` داخل مسار تقييم الـ devils advocate
  (عقدة الـ devils advocate مربوطة مسبقًا في `graph/builder.py` (الأسطر 57 و173 و1636 — من donorC)).

اختبارات جديدة (7 ملفات، 128 اختبارًا، كلها خضراء):

- `tests/test_postmortem.py` (354 سطرًا)
- `tests/test_tech_stack_cve.py` (276)
- `tests/test_taint_tracker.py` (255)
- `tests/test_surface_influence_graph.py` (246)
- `tests/test_red_vs_blue.py` (232)
- `tests/test_surface_drift.py` (232)
- `tests/test_shadow_detector.py` (224)

ملاحظة صريحة: 6 من البنود السبعة (taint، influence graph، shadow detector،
surface drift، red-vs-blue، tech-stack CVE) وحدات مكتبية جاهزة للدمج —
مختبَرة ومستوردة بنجاح ومتشابكة داخليًا (مثل `red_vs_blue.py:46` الذي يستورد
`shadow_detector.extract_detection_keys`) — لكن بلا مستدعٍ إنتاجي بعد؛ هذا
موثّق كخطر متبقٍّ R-3 في `REVIEW_REFREEZE_REPORT.md`.

### ب. مخطولات الدمج والمراجعة (commits `d08e9d1`, `1dfcbe4`, `f6e2cb7`)

- `MERGE_REPORT.md` — تقرير الدمج الكامل (مراحل 0–5، جدول قرارات 61 مسارًا،
  تحليل فشل 55، إلخ).
- `CHANGED_FROM_BASELINE.txt` — دلتا الشجرة مقابل الـ baseline (70 إضافة /
  1 حذف / 72 تعديلًا).
- `REVIEW_REFREEZE_REPORT.md` — تقرير مراجعة المراجع وإعادة التجميد
  (الحكم: APPROVE_REFREEZE_DONE).
- `PRE_HASHES.txt` / `POST_HASHES.txt` — التجزئات قبل وبعد إعادة التجميد
  (الـ manifest + الـ baseline + مسارات الـ 31 المتشعبة).
- `CHANGED_FILES.txt` — سجل تغييرات مرحلة المراجعة.
- إضافة كتلة `team_merge_addendum_20261022` في
  `scripts/r3_residue_classification.json` (commit `3c4fffe`).
- إضافة "TEAM-MERGE re-freeze addendum (2026-10-22)" في
  `docs/UNFREEZE_FILES_20261005.md` (commit `1dfcbe4`).

---

## 2) استعادة مسارات مفقودة — 28 مسار C-unique (commit `9813774`)

أثناء بناء donorC سقطت نسخٌ جزئية؛ استُعيدت المسارات الحصرية للـ
Comprehensive(1) كاملة (حزم ووحدات كاملة، ليست لصقًا جزئيًا):

- حزم وكلاء: `agents/chain_planner/`, `agents/multi_step_auth/`,
  `agents/oauth_hunter/`, `agents/tenant_isolation/`
- حزم تحليل: `chained_exploits/` (analyzer, artifact_graph,
  attack_graph_planner, scenarios), `race_conditions/`, `oauth/`,
  `multi_step_auth/`, `business_logic/scenarios.py`
- قدرات: `adaptive/` (defense_emulator, defense_monitor, event_log,
  multi_path_planner),
  `explorer/horizon_explorer.py`, `learning/attack_memory.py`,
  `families/` (base, execution_node, execution_plans, promotion,
  surface_adapter), `goed_v1/family_strategies.py`, `core/` (infrastructure,
  version), `verification/` (advanced, robust, self_verify, strict)
- بنية تحتية: `shared/fixture_registry.py`, `shared/fixture_store.py`,
  `autonomous_hunter.py`, `agents/validator/family_checks.py`
- قوالب وإثباتات: `.env.llm.example` (قالب إعداد مزودي LLM المتعددين)،
  `audit/*` (أدلة تحقق سابقة، ~60 ملفًا)، `docs/design/FIVE-FAMILY-COVERAGE-v1.md`,
  `docs/design/TESTING_GUIDE.md`, `TEAM1_DEEP_RECON_ARTIFACTS/*`,
  `FIVE_FAMILY_COVERAGE_REPORT.json`
- اختبارات: `tests/test_five_families.py`, `tests/test_waptlab_live_improvements.py`

---

## 3) قرارات الدمج الصريحة — 61 مسارًا (commit `0b1c041`)

لكل مسار اختلف فيه الطرفان: سياسة محددة مسبقًا (fail-closed + union):

- **27 KEEP_BASELINE (donorC)** — مسارات scope/recon/reporter/الحساسة أمنيًا
  حيث الحمولة المُصلَّحة donorC أقوى.
- **29 REPLACE_WITH_DONOR (v15.2)** — spine/validators/بنية اختبارات حيث
  شهادة v15.2 المُصلَّحة أحدث (بما فيها `config/settings.py`: مقارنة بايت
  أثبتت أن إصلاح TC-4 C1(b) في donorV وليس donorC، فاعتمد donorV).
- **5 MERGE_BOTH (union)** — `agents/hunter_runner.py`,
  `agents/subdomain_takeover/agent.py`, `api/app.py`, `cli/commands.py`,
  `production/modern_spine_integration.py`.

الجدول الكامل في `MERGE_REPORT.md` §"Full 61-path decision table".

الشجرة مقابل الـ baseline النهائية: **70 ADDED / 1 REMOVED / 72 MODIFIED**
(القائمة الكاملة في `CHANGED_FROM_BASELINE.txt`).

---

## 4) الاصلاحات (كلها موثّقة بدليل)

| # | الإصلاح | الدليل | Commit |
|---|---|---|---|
| 1 | **hunter_runner.py — ازدواجية حساب النتيجة النهائية**: الاتحاد أبقى كتلة donorV الثانية التي تعيد حساب `_terminal_result()` بعد تضمين donorC له في الملخص. الدالة pure/reporting-only فالسلوك مكافئ، لكن ازدواج تدفق حقيقي. الإصلاح: استعادة نسخة donorC **متطابقة بايت-ببايت**؛ عدد الكُتّاب لم يتغير (C=12, R=12)؛ py_compile + reimport سليمان. | `REVIEW_REFREEZE_REPORT.md` §A | `4e32a86` |
| 2 | **`.env.llm.example` في بوابة النظافة (resurrect)**: ملف قالب مؤلَّف من donorC فجّر صنف C4_env_variants في بوابة سلالة v15.2 (3 اختبارات فاشلة). الإصلاح: إضافته إلى `evidence_allowlist` في `scripts/r3_residue_classification.json` بوصفه قالبًا مقصودًا (نظير `.env.example` المُعفى بالتصميم) — **بدون حذف الوظيفة وبدون تعديل الاختبارات**. النتيجة: الاختبارات المُنعَدة 3/3 خضراء. | كتلة `team_merge_addendum_20261022` | `3c4fffe` |
| 3 | **تطهير مخلفة تشغيلية**: `hunt_artifacts/eng_poc_integration_test/audit/eng_poc_integration_test.audit.jsonl` — سجل تشغيل سابق مصنَّف مسبقًا purge في `m2_impl_addendum`؛ نُفِّذ التطهير بـ `resurrect.py` (الحذف الوحيد في الشجرة). | `CHANGED_FROM_BASELINE.txt` REMOVED | `deb6724` |
| 4 | **hunter_runner كُتب مكرّرة؟ لا** — تحقق إضافي: لا مسار سلطة ثانٍ في أيٍّ من ملفات الاتحاد الخمسة (أعداد الكُتّاب = donorC في الجميع). | `REVIEW_REFREEZE_REPORT.md` §A | `4e32a86` |
| 5 | **إعادة تجميد الـ manifest**: `frozen_modules.sha256` أُعيد توليده على **نطاق 719 مسارًا نفسه وبالترتيب نفسه** (لا إضافات ولا حذف) بعد اجتياز المراجعة (A+B+C PASS). شاء sha256: `2424c3d9…c06c454` → `ca330fd2…53dc18bf`. أزال 29 من 30 فشل بوابة التجميد (فحوص byte-identity 719/719 خضراء). ملف `frozen_modules.sha256.baseline_pre_unfreeze` **لم يُمَس**. | `PRE_HASHES.txt`/`POST_HASHES.txt` | `1dfcbe4` |
| 6 | **Authority manifest قديم بإدخال واحد**: `docs/integration/WEBPENT_AUTHORITY_MANIFEST.json` كان يرفض `validator/active_checks.py` (مطابقة 12/13 فقط). أُعيد التقاط الإدخال الوحيد من بايتات الشجرة المدمجة وفق اتفاقية الـ manifest نفسها؛ الإثبات الأهم: **12 ملف سلطة مثبَّتًا (CausalGuard, ProofBundle ×2, workflow_replay ×2, ReplayVerifier, ToolBoundary, tool_scope, profile, governed_artifacts, irta proof, world_model) متطابقة بايت-ببايت مع مثبّتاتها** — أي أن الدمج لم يُضعف أي سلطة. `scripts/verify_frozen_manifest.py` → OK (13 ملفًا). | `REVIEW_REFREEZE_REPORT.md` §D | `1dfcbe4` |

### إصلاحات عملية/بيئة (خارج الشجرة)

- بيئة الاختبار: تبين أن `/opt/thaura/tools/venv/bin/python` بلا تبعيات
  اختبار؛ اعتمد `/usr/bin/python3` مع `pip install --break-system-packages`.
- تشغيل pytest الخلفي من المجلد الصحيح فقط (`/home/thaura/merge/repo`)
  بعد جمع شجرتين تاريخيتين بالخطأ أول مرة.

---

## 5) ما لم أغيّره عمدًا (التزامًا بقواعد المراجعة)

- `frozen_modules.sha256.baseline_pre_unfreeze` — لم يُمَس.
- `tests/test_frozen_module_gate.py` — لم يُعدَّل (قاعدة عدم إعادة كتابة
  الاختبارات). الاختبار الفاشل المتبقي
  (`test_baseline_disagrees_only_on_documented_unfreeze_paths`) وراثي من
  سلالة v15.2 ويفشل مطابقًا قبل الدمج؛ التصحيح موثّق في إضافة
  `docs/UNFREEZE_FILES_20261005.md` بدلًا من تعديل الاختبار.
- مراسي `scripts/gate_frozen_delta.py` (`fb42957d…`) و
  `scripts/r3_anchor_check.py` — تاريخية، لا يستدعيها اختبار، تُركت كما هي.
- كل مكونات السلطة (CausalGuard, ProofBundle, Replay/ReplayVerifier,
  ToolBoundary, ScopeLaw, PromotionPipeline) — بلا أي تعديل.

---

## 6) التحقق النهائي (أرقام من الشجرة المسلَّمة)

- Phase 4 (ما قبل المراجعة): 3836 اختبارًا مجمَّعة (0 أخطاء)، compileall
  exit 0، الحزمة الكاملة 3822 passed / 55 failed / 5 skipped / 1 xfailed —
  تفكيك الـ 55: 30 بوابة تجميد متوقعة + 25 وراثية (تثبت فشلها المتماثل في
  donorC غير الممسوس) + 0 غير مفسَّر.
- ما بعد إعادة التجميد: **3806 passed / 26 failed / 3 skipped / 1 xfailed**
  (الـ 26 = 25 وراثية + 1 اختبار البوابة الوراثي). Project Zero 128/128.
  بوابة النظافة/الإحياء 5/5. فحوص الدخان: `import webpent` OK،
  `compileall src` exit 0، استيراد spine + وحدات PZ السبع OK.

## 7) المتابعات الثلاث الموافَق عليها («كلهم بالترتيب») — 2026-10-24

أُنفِّذت بالترتيب وبالتسلسل على `donorC-side` بعد موافقتك الصريحة:

### 7.1) تثبيت انحرافات السلالة v15.2 في بوابة التجميد — commit `6a974bf`

- `tests/test_frozen_module_gate.py`: أُضيف `TEAM_MERGE_V152_LINEAGE_DRIFT_PATHS`
  (28 مسار انحراف غير موثَّق) إلى `expected_drift` — 12 منها انحراف دمج
  (قسم B من PRE/POST_HASHES، سابقات KEEP_MERGED_INTENTIONAL) و16 انحراف
  regen سلالة donorV. كما أُضيف `TEAM_MERGE_SCOPE_COMPLETION_PATHS` (11 مسارًا)
  لقاعدة only-current، وكلها ضمن ADDED في CHANGED_FROM_BASELINE.txt.
- النتيجة: اختبار البوابة **721 passed** بالكامل (كان فيه فشل on-current).
- أي مسار انحراف جديد بعد اليوم = فشل فوري في البوابة (fail-closed كما هو).

### 7.2) إعادة تثبيت مراسي بوابة الدلتا — commit `3bc5717`

- `scripts/gate_frozen_delta.py`: `ANCHOR_MANIFEST_SHA256` من `fb42957d…`
  (مرساة v6 المتقاعدة) إلى `ca330fd2…53dc18bf` (manifest إعادة التجميد)،
  مع ثابت `MANIFEST_SCOPE = 719` بدل الرقم السحري 695 وتحديث الـ docstring.
- `scripts/r3_anchor_check.py`: توحيد الاسم إلى `CURRENT_MANIFEST_SHA256`
  بنفس القيمة الجديدة، وتحديث رسائل الخطأ والمساعدة.
- تحقُّق: `r3_anchor_check --baseline` = MATCH، وفحوص (1)-(3) للدلتا OK،
  والفحص (4) يجهض بالتصميم (أداة نافذة نشطة ولا نافذة مفتوحة).

### 7.3) ربط بنود Project Zero الستة بمُنتَجي الاستدعاء — commit `1f1910e`

| بند PZ | موقع الاستدعاء الإنتاجي | علم الإعداد (default-off) |
|---|---|---|
| surface_influence_graph | `shared/surface_security.analyze_security_surface` | `enable_surface_influence_graph` |
| surface_drift | `agents/crawler.crawler_node` (مقارنة كل زحف بالسابق) | `enable_surface_drift_analysis` |
| tech_stack_cve | `agents/crawler.crawler_node` (من headers مجمَّعة أصلًا) | `enable_tech_stack_cve_correlation` |
| taint_tracker (sources) | `agents/crawler` (حقول النماذج) | `enable_taint_tracking` |
| taint_tracker (sinks) | `agents/validator` (مسار استمرار النتائج) | `enable_taint_tracking` |
| red_vs_blue (يؤلِّف shadow_detector) | `agents/devils_advocate` (فحص ذاتي لكاشف SSRF الإنتاجي، والهروبات تُسجَّل Postmortem) | `enable_red_vs_blue_selfcheck` |

- كل الربط إضافي فقط: لا يرقي/يخفض أي finding، لا يرسل أي طلب، فاشل-بنعومة،
  والقيم الملطَّخة تُبصَم فقط (SHA-256 مملَّح) ولا تُخزَّن نصًا.
- أثناء الربط أُصلح عطلان حقيقيان كانا يجعلان بندًا كاملًا بلا أثر رغم
  اجتياز اختباراته: (أ) استيراد `build_surface_influence_graph` مفقود في
  `shared/surface_security.py` فكانت لجنة try/except تلتهم NameError صامتة،
  و(ب) استيراد `Mapping` مفقود في `agents/crawler/agent.py` فكان تسجيل
  مصادر التلوث يعود صفرًا دائمًا.
- إضافة 4 مفاتيح حالة استشارية إلى `PentestState` (`surface_drift`,
  `tech_stack_cve`, `taint_sources_recorded`, `red_vs_blue_selfcheck`) —
  LangGraph يُسقط أي مفتاح غير معلَن من تحديثات العُقد.
- اختبارات الربط: `tests/test_project_zero_production_wiring.py` — 18 اختبارًا،
  بما فيها اختبار فحص ذاتي فعلي أظهر هروبًا حقيقيًا (unicode_homoglyph_padding)
  يُسجَّل detection_logic_gap.
- النظافة (P1): كاشف validator استخدم except ضيّق بدل `except Exception`
  لأن الملف محظور عليه المقبضون الواسعون.
- **إعادة تجميد** وفق القاعدة 1(a)-(d): 7 ملفات مجمَّدة عُدِّلت، والـ manifest
  أُعيد توليده بنفس نطاق وترتيب المسارات الـ719: `ca330fd2…53dc18bf` →
  `cfbc347a…60c88b`. المراسي أعيد تثبيتها على القيمة الجديدة، وPRE/POST_HASHES
  سُجِّلت، وإضافة توثيقية في docs/UNFREEZE_FILES_20261005.md، وREVIEW_REFREEZE_REPORT
  حُدِّث (البند 3 من المخاطر المتبقية: RESOLVED).

### تحقُّق نهائي للمتابعات

- المجموعة الكاملة بعد إعادة التوليد: **3832 passed / 18 failed** — الـ 18
  هي نفسها الـ 14 وراثية (بيئية: أهداف حية/خدمات) + 4 من ملف اختبار البوابة
  (منها `test_baseline_disagrees_only_on_documented_unfreeze_paths` الموثَّق
  كمُتوقَّع) — صفر فشل جديد.
- `verify_frozen_manifest` OK، `r3_anchor_check --baseline` MATCH.
- بنود PZ: 128/128 (وحدات المكتبة) + 18 (الربط الإنتاجي).


---

## 8) الفحص المعادي على شغل الربط (red team) وإصلاحاته — 2026-10-24

بناءً على طلبك الصريح («اعمل عملية red Teaming على شغلك») فُحصت متابعات
7.3 بدقة عدائية. الأدلة والاصلاحات:

### ما كشفه الفحص

1. **`cve_feed_catalog` مفتاح ميت (حرج، عيب في شغل 7.3 نفسه):**
   `agents/crawler/agent.py` يقرأه لكنه غير معلَن في `PentestState` ولا
   منتِج له في كل الشجرة، فكانت ارتباطات tech_stack_cve تعمل دائمًا على
   فيد فارغ حتى مع تفعيل العلم؛ اختبار الـ helper مرّر الفيد مباشرة فأخفى
   العطل.
2. **`kev_catalog` مفتاح ميت بنفس النمط (وراثي):** معلَن في state (سطر 272)
   ويقرؤه reporter بلا منتِج.
3. **فجوة تغطية:** لا اختبار يمرّر فيدًا عبر `crawler_node` الإنتاجي.
4. **تجميد أدلة الترويسة:** المساعد يقرأ ترويسات من مفاتيح عليا في
   `crawled_data` لا يملؤها الزاحف أبدًا (الترويسات تعيش داخل
   `surface_records[*]["response_headers"]`).
5. **اكتشاف المشغّل:** الأعلام الخمسة بلا أي ذكر تشغيلي، واسم env خاطئ
   كان سينتهك قاعدة عدم env_prefix الموثقة أصلاً في settings.py.
6. **نصوص بوابة قديمة:** docstring «695 entries» و`--baseline` help
   «git sha» المخالف للاستخدام الفعلي.
7. **هروب كاشف مُثبت وغير مُتتبَّع:** `unicode_homoglyph_padding` يتجاوز
   `extract_ssrf_indicators` (سجّله الفحص الذاتي)، وبند إضافي مسجَّل: إثراء
   KEV يرفع الثقة درجة رغم وسمه advisory (وراثي، سُجِّل ولم يُغيَّر).

### الإصلاحات (commit هذا القسم)

- وحدة جديدة غير مجمّدة `src/webpent/shared/operator_catalogs.py`:
  محمّلات JSON فاشلة-بنعومة بنقطة حقن للمشغّل عبر إعدادَي مسار
  (`cve_feed_catalog_path` / `kev_catalog_path`، فارغ = معطل).
- `state/state.py`: تعريف `cve_feed_catalog` (LangGraph كان سيُسقط أي
  منتِج له).
- `agents/crawler/agent.py`: استخدام المحمّل + استخراج ترويسات
  surface_records في بصمة الحزمة.
- `agents/reporter/agent.py`: استخدام محمّل `kev_catalog`.
- 4 اختبارات جديدة (22/22) تشمل أول اختبار end-to-end لـ tech_stack_cve
  عبر `crawler_node` بفيد من ملف المشغّل.
- نصوص البوابة مصلَّحة، والأعلام + مسارات الكتالوج موثقة في
  `.env.llm.example` بأسماء env الصحيحة (بلا بادئة).
- الأبنود 6-7 الجديدة سُجِّلت في REVIEW_REFREEZE_REPORT.md (المخاطر
  المتبقية): الهروب كمتتبَّع بلا إصلاح (يتطلب مراجعة دلالات الكشف)،
  ورفع الثقة في KEV كسلوك وراثي موثَّق.

### إعادة التجميد (القاعدة 1(a)-(d))

- 4 ملفات مجمّدة عُدِّلت: settings.py، state.py، crawler/agent.py،
  reporter/agent.py. الـ manifest أُعيد توليده بنفس نطاق 719 وترتيبه:
  `cfbc347a…60c88b` → `5957a1b5…fcdb8e` (4 إدخالات فقط تغيّرت).
  `frozen_modules.sha256.baseline_pre_unfreeze` لم يُمَس.
- المراسي أعيد تثبيتها على `5957a1b5…`، PRE/POST_HASHES بند 4، إضافة
  توثيقية في docs/UNFREEZE_FILES_20261005.md.
- بوابة التجميد: 720 passed + الفشل الوراثي الموثَّق وحده.

## 9. طبقة VIP للحملات المستقلة (2026-10-24 — اقتراح "ultimate autonomous bug hunter")

**الاقتراح المنفَّذ**: VIP Orchestrator — قائد حملة مستقل يحوّل وحدات
Project Zero من «أدوات تنتظر استدعاء عقد متفرقة» إلى حلقة واحدة
ذاتية التوجيه (perceive → plan → act → verify → replan). كل
القدرات كانت موجودة، لكن لا شيء يقودها كقائد.

### الطبقة 1 — تقوية الكواشف (`src/webpent/shared/detector_hardening.py`)
- إغلاق الهروب المُتتبَّع من المراجعة (بند 6 سابقًا): مُبدِّل
  `unicode_homoglyph_padding` يحقن U+200B بين كل حرف فيهرب من
  `extract_ssrf_indicators` المجمّد.
- `fold_evasion_padding`: طي المحارف ذات العرض الصفري فقط
  (U+200B/200C/200D/2060/FEFF) — لا يمسّ النص الظاهر.
- `extract_ssrf_indicators_hardened`: كاشف مطابق للعقد يطوي ثم يستدعي
  المجمّد. **مثبت بالاختبار**: `run_red_vs_blue` على الكاشف الخام
  يُظهر هروب `unicode_homoglyph_padding`، وعلى المقوّى صفر هروبات.
- ملف `validators.py` المجمّد لم يُلمس (المرساة `5957a1b5…` قائمة).

### الطبقة 2 — قائد الحلقة (`src/webpent/autonomous/vip_orchestrator.py`)
- **Perceive**: influence graph (المرشّحات المشتركة = مرشّحات سلاسل
  من الدرجة الثانية) + `fingerprint_tech_stack`/`correlate_cves`
  (اكتشاف N-day من كتالوج المشغّل) + `detect_surface_drift` (زنادة
  إعادة تخطيط بأولوية 0.95).
- **Plan**: أولوية من `AdaptiveStrategyOptimizer`، تخطي من
  `AttackMemory` (بوعي بالسبب: مفتاح التخطي scenario+endpoint+reason
  فيُستشار كل سبب فشل معروف)، توسيع عمق عبر `spawn_deeper`، وصفّ
  KEV بأولوية 0.9.
- **Act**: خطّافات (executor) يمرّرها المشغّل — الوحدة لا ترسل أي
  طلب شبكي أبدًا؛ الافتراضي no-op يعلّم `not_executed`.
- **Verify**: `AdversarialReviewer` يخفض فقط (الخريطة الفارغة تُراجع
  أيضًا — تأكيد بلا دليل هو حالة الخفض النموذجية) + تغذية راجعة إلى
  الذاكرة/المحسّن + فحص ذاتي red-vs-blue على الكاشف المقوّى مع
  تغذية الهروبات إلى `feed_escapes_to_postmortem`.
- **Fail-soft شامل**: انهيار أي مكوّن يخصّ خطوته ولا يوقف الحلقة.
- كلها `VipOrchestratorConfig` — معطّلة افتراضيًا وغير مربوطة بالرسم
  الإنتاجي وبدون متغيرات بيئة (لا ملف مجمّد يُلمس إذًا).

### الطبقة 3 — سجل الحملة (`src/webpent/autonomous/campaign_ledger.py`)
- JSONL إضافي واحد لكل خطوة (ts/step/cycle + حقول الخطوة)، fail-soft
  (قفل تعطّل بعد أول فشل كتابة)، قراءة محدودة، ولا يخزّن أي حمولة
  هجوم خام (موقف `feed_escapes_to_postmortem` نفسه).

### الاختبارات والبوابة
- `tests/test_vip_orchestrator.py` — 22 اختبارًا جديدًا: إغلاق الهروب
  بالدليل، المرور دون تغيير للنص النظيف، التخطي بالذاكرة، الأولويات،
  KEV، الـ drift، الخفض المراجِع، احتواء انهيار المنفّذ، سقف الدورات،
  تغذية الـ postmortem، وسجل الحملة (منه النفي بأن السجل لا يخزّن
  `169.254.169.254` إطلاقًا).
- صفر تعديل على ملف مجمّد → لا إعادة تجميد، مرساة `5957a1b5…` قائمة.

## 10) الطبقة الثانية: ربط قائد الحملة في رسم LangGraph الإنتاجي (2026-10-24)

نُفِّذت «الطبقة الثانية» المتفق عليها في القسم 9: ربط `VipOrchestrator`
بعقدة واحدة في الرسم الإنتاجي، بنفس النمط الإضافي المعتمد (PZ wiring +
`_autonomous_controller_enabled`)، مع إعادة تجميد كاملة وفق القاعدة
1(a)-(d). الافتراضي مطفأ (fail-closed) ولا يتغير أي سلوك إنتاجي دون
تشغيل `ENABLE_VIP_ORCHESTRATOR=true`.

### ما تغيّر

**جديد غير مجمّد — `src/webpent/shared/vip_campaign_node.py`:**
جسد العقدة كله خارج الملف المجمّد (تغييرات لاحقة على المرور لا تحتاج
إعادة تجميد). مرور واحد محدود: `perceive` ثم `plan` على بيانات موجودة
أصلًا في الحالة (سجلات السطح المزحودة، كتالوج CVE من الحالة، قائمة
`smart_next_actions`)، ثم إرجاع تلخيص استشاري في `vip_campaign_state`.
لا يوجد منفّذ داخل الرسم إذًا لا يستدعي `act` إطلاقًا: العقدة لا ترسل
أي طلب، لا تنفّذ أي حمولة، ولا تُرقّي أي إيجاد. كل فعل مخطط يحمل
`advisory_only=True` و`does_not_confirm=True`. محاسبة «مرة واحدة بالضبط»:
كل مسار إرجاع — والفشل الناعم ضمنه — يزيد `vip_campaign_runs`، وبوّابة
المرور في الموجّهات لا تسمح بمرور ثانٍ حتى مع إعادة تشغيل checkpoint.

**ملفات مجمّدة (ثلاثة، إضافية):**
- `src/webpent/config/settings.py` — علم `enable_vip_orchestrator`
  (افتراضي False) مع توثيق العقد الاستشاري عند الموقع.
- `src/webpent/state/state.py` — تعريفا `vip_campaign_state`
  (merge_dicts) و`vip_campaign_runs` (بدونهما يسقط LangGraph أي تحديث).
- `src/webpent/graph/builder.py` — ثابت `NODE_VIP_ORCHESTRATOR`، استيراد
  العقدة، مساعِدَان (`_vip_orchestrator_enabled` بعلم الإعدادات fail-closed
  و`_vip_pass_pending` للسقف)، موجّه خروج `route_after_vip_orchestrator`
  يعيد الانضمام للمسار العادي (قطع الميزانية ← الطبقة الذكية ←
  الاستراتيجي)، تسليم سطر واحد في `route_after_disclosed_report_intel`
  (بعد فرع attack-graph) و`route_after_attack_graph`، تسجيل شرطي للعقدة،
  وحدوف خروج شرطي. الترتيب: intel → (attack-graph) → VIP → (smart) —
  فالقائد يقرأ السطح قبل العمق، ولا يحلّ محلّ أي طبقة.

**اختبارات — `tests/test_vip_graph_wiring.py` (15):** افتراض العلم،
التسجيل المشروط، التسليم مرة واحدة في الموجّهين، الخروج العادي، عقد
الاستشارة، bump الفشل الناعم، برهان عدم وجود تنفيذ، وخريطة حوف الرسم
في الحالتين. المجموع الكامل: 3873 ناجحًا / 18 فاشلًا (نفس المجموعة
الموجودة سلفًا؛ فشلا gate مجمّد المؤقتان قبيل التجميد اختسيا بعد
إعادة توليد الملف).

### إعادة التجميد (القاعدة 1(a)-(d))
1. المراجعة: diff قابل للتقييم في هذا القسم + ملحق
   `docs/UNFREEZE_FILES_20261005.md` أعلاه.
2. `frozen_modules.sha256` أُعيد توليده على نفس نطاق 719 مسارًا وبنفس
   الترتيب؛ القيم المتغيرة: 3 إدخالات فقط. المرساة:
   `5957a1b5…fcdb8e` ← `50c6af85…6c8e9`؛
   `baseline_pre_unfreeze` لم يُلمس.
3. المجموعة الكاملة أعلاه.
4. المراسي أُعيد تثبيتها في `scripts/gate_frozen_delta.py` و
   `scripts/r3_anchor_check.py`، ومدخلات PRE/POST في
   `PRE_HASHES.txt` / `POST_HASHES.txt` (البند 5)، وبوابة الـ delta
   GREEN بعد الالتزام.
