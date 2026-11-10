# Changelog

## 0.39.0 — 2026-11-10 (UM-DR-33: researcher brain & autonomous campaign evolution)

> نافذة UM-DR-33: **إغلاق عيوب هندسة الإصدار المكتشفة + ترقية بحثية
> حقيقية**، مع الحفاظ الدستري الكامل على سلسلة التأكيد (CausalGuard
> هو سلطة التأكيد الوحيدة، ProofBundle + replay إلزاميان). (1)
> **عقد الهوية الموحد للـ JSON** (`webpent.shared.canonical_json`):
> تسلسل واحد معياري لكل هاشات الهوية — أُغلق تضارب الهاشين
> التاريخيين (b78ad5c6… المتقاعد / 58684262… المعتمد) مع اختبارات
> طفرة تثبت أن أي تغيير في الثغرات/الضوابط يغيّر البصمة. (2)
> **إصلاح سلسلة الأدلة**: عيب مؤكد تجريبيًا — كل ProofBundles كانت
> تحمل `bundle_id=None` (تجاوز صريح للـ default_factory)؛ أُصلح
> بنافذة ذوبان مجمّدة موثقة (DR-009) مع 7 اختبارات انحدار. (3)
> **تشغيل info_gain في ترتيب الـ strategist** (إغلاق عيب مراجعة
> UM-DR-31): W_INFO_GAIN=0.10 في المجموع المرجّح (متوازن لمجموع 1.0)،
> افتراضي محايد 0.5 لغير المقيَّم، مع اختبارات طفرة/انعكاس ترتيب/
> استقلالية الأمان (النطاق/الميزانية/الإذن لا يتأثروا بالنتيجة أبدًا).
> (4) **أمان الترشيح الوكيل**: ميزانية الخطوات تفشل مغلقًا عند فساد
> الأثر (لا إعادة تعيين أبدًا)، رفض placeholder credentials في المُحمِّل
> (fail-closed مع إعفاء أسماء الحقول)، تحصين kill_switch fanout.
> (5) **قمع الاكتشاف** (§12): 16 مرحلة قياس حتمية نقية من قنوات
> الحالة الحقيقية مع شرح أنماط الهدر — المسرود بصدق عبر
> `not_materialized_in_state`. (6) **تسوية المحاسبة**: خطأ 152→154/159
> صُحح بالـ node IDs الفعلية (erratum موثق). (7) **README**: الأرضية
> 3.11 مقابل المُختبر 3.12.16 معلنة صراحة. (8) **نظافة الشجرة**:
> econ CLI runtime state يحترم WEBPENT_ECON_DIR — السلسلة لا توسّخ
> الشجرة بعد الآن.


## 0.38.0 — 2026-11-09 (UM-DR-32: identity & business-logic evolution)

> نافذة UM-DR-32: **تحويل فهم WebPent للتطبيقات من اختبار النقاط النهائية
> إلى استدلال قائم على الأدلة حول الكائنات والهويات والحالات وسير العمل**،
> مع إغلاق عيوب هندسة الإصدار المكتشفة في المراجعة السابقة. (1) **ذكاء
> هوية الكائنات**: سجل هوية نموذجي مثبَّت على (المستأجر، نوع المورد،
> المعرّف الثابت) — لا المسار أبداً؛ دمج يحتاج أدلة مؤكِّدة؛ الامتناع
> عند ضعف الأدلة؛ تعارضات محفوظة لا تُداس. (2) **حل التمثيلات البديلة**:
> تصنيف قابل للعكس بست حالات صريحة، واعٍ أمنياً (حدود المستأجر/النوع/
> قيم الاستعلام محفوظة — لا تراجع عن F10/F11). (3) **الاستدلال متعدد
> الهويات**: نموذج أساسيات مستعار بلا بيانات اعتماد خام، مصفوفة
> الأساس×المستأجر×الكائن×العملية×الحالة، وإغلاق فجوة missing-validator:
> مسار privilege_differential كامل من الفرضية إلى المُصادق المسجل.
> (4) **سير العمل المركّب**: اكتشاف من الملاحظات الفعلية فقط، حدود
> محافظة، عقد سلامة للأدوات التدميرية (resettable+isolated+operator)，
> وتقييم بمعمارية التحقق القائمة (الحرس السببي للتفاضلات أحادية
> الفاعل؛ مسار مُصادق التفاضل للعابرة للفاعلين). (5) **التوحيد**: عقدة
> identity_workflow موصولة بسلسلة الاستشارة الإنتاجية قبل الـ strategist،
> قنوات حالة معلنة، فرضيات حتمية، وتلميحات جدولة ترتيبية فقط. القياس
> المضبوط: خط الأساس 0/4 مقابل الموحّد 4/4 بدقة 1.0 وصفر إيجابيات كاذبة
> تحت ميزانيات متكافئة. (6) **سلامة الإصدار**: منشئ أرشيف محمول (تخطيط
> الجذر والمستودع المتداخل)، مشغّل جناح محمول، عقد أصل التجارب (رفض
> الشجرة القذرة)، مصالحة هوية الإصدار (0.34.0 تاريخي / 0.38.0 حالي /
> v15.2 وسيم)، إصلاح فحص مخطط الأصل في قبول الفرضيات، وإعادة تثبيت
> موثقة لـ 6 ملفات مجمّدة + تجميد 5 وحدات جديدة من الولادة. سلطة
> التأكيد غير مسة: CausalGuard وProofBundle وعتبات الـ strategist. +150+
> اختباراً جديداً (8744 -> 8903 معرفاً فريداً، صفر محذوف؛ 8903
> مجمّعة -> 8894 ناجح / 0 فاشل / 6 متخطى / 3 xfailed — تسوية تامة).

## 0.37.1 — 2026-11-08 (UM-DR-31.1: intelligence & engineering uplift)

> نافذة UM-DR-31.1: **تنفيذ إصلاحات تدقيق UM-DR-31 كاملة (R1–R11) + تصحيح
> جدولة البحث الأصغري المُقاس**. (1) **الأمن**: فلتر قبول الفرضيات (R3/F05 —
> مضيف أجنبي/مخطط غير HTTP/URL مشوه لا يصل إلى الـ pool أبدًا، المرفوض
> يُسجل لا يُسقط)؛ حالة الحلقة الفاسدة fail-closed (R7/F18 — الفساد يستهلك
> الميزانية ولا يعيد تسليحها). (2) **الصحة**: عقد تصنيف نقي مُختبَر (R6 —
> 7 فئات + مجهول fail-closed؛ candidate غير قابل للفعل؛ غير المعروف لا
> يتحول صامتًا إلى فرصة)؛ بصمات تحفظ هوية query وحالة الأحرف (R4/F10/F11)؛
> دلالة research_hints_applied صادقة (R5/F06 — تطابق فعلي لا علم فارغ).
> (3) **الذكاء**: تلميحات surface من خلايا التغطية (ترتيب فقط داخل نفس
> الميزانية) — ذراع coverage-only في القياس الرباعي يصل الحقيقة الأرضية
> (0→1) تحت نفس سقف 36 طلبًا حيث كان يصفر، بصفر إيجابيات كاذبة في كل
> الأذرع. (4) **السلطة غير المساسة**: causal guard وProofBundle وعتبات
> الـ strategist وحارس IDOR — صفر تغيير. (5) **السلسلة**: أرضية Python
> 3.11 عمدًا (سطر dnspython المُرقّع 2.9.2 لا يدعم 3.10 — F07)؛ uv.lock
> مُعاد الحل (webpent 0.37.1، بلا فورك dnspython)؛ أثر ablation يُولَّد
> بأمر صريح وقت الإصدار فقط (R2/F02)؛ tag ‏v0.37.1-umdr31.1. +30 اختبارًا
> جديدًا.


## 0.37.0 — 2026-11-07 (UM-DR-31: evidence-driven adaptive research loop)

> نافذة UM-DR-31: **تحويل الإشارات الاستشارية إلى حلقة بحث تكيفية فعلية داخل
> الـ graph الإنتاجي** — لأول مرة، مخرجات خريطة فجوات التغطية والمراجعة
> الثابتة وملاحظات حدود التصريح تتدفق عبر عقدة `research_loop` مرتبطة
> بالـ strategist، فتغيّر قرارات البحث التالية (وليس مجرد تقرير لا يقرؤه
> أحد). (1) **المحرك**: `production/adaptive_research.py` — جرد إشارات
> مصنّف بتمييز سداسي (غير مُختبر/غير حاسم/محجوب تشغيليًا/محجوب بالسياسة/
> مرفوض بأمان/مؤكد)، توليد فرضيات ببصمات ثابتة (uuid5 حتمية + dedup دلالي:
> المرفوض الحاسم لا يُكرر أبدًا، والفرضيات المتشابهة المتفاوتة في هوية
> أمنية لا تُدمج)، حدود صارمة (3 تكرارات × 12 فرضية، قابلة للضبط،
> fail-closed عند غياب أي حد إلزامي). (2) **الربط الإنتاجي**: العقدة
> موصولة أمام الـ strategist على مسارات خط الاكتشاف وخط البحث ومسار
> إعادة التخطيط بعد التحقق (تجاوز خرائط شرطية مُعلن + حافة
> research_loop→strategist؛ العلم مغلقًا = شكل الـ graph مطابق بايت-بايت).
> (3) **وصلة المنفذ→التنفيذ**: تلميحات أولوية الدلائل المستمدة من ملاحظات
> حدود التصريح ترتّب حالات الـ stateful discovery داخل نفس الميزانية (لا
> تغيير نطاق/ميزانية/صلاحية)، مع ميزانية discovery قابلة لضبط الـ operator
> (افتراضي 360). (4) **القياس الصادق**: 50 اختبارًا جديدًا (وحدة + تكامل +
> E2E + قياس تجريبي رباعي الأذرع على هدف مضبوط) — تحت ميزانية 36 طلبًا
> يصل الذراع الموجَّه إلى الحقيقة الأرضية بينما لا يصل الأساسي؛ المجموعة
> 8,711 اختبارًا. الـ causal guard يبقى سلطة التأكيد الوحيدة؛ لا ترقيم،
> لا منح صلاحية، لا تجاوز بوابات.

## 0.36.0 — 2026-11-07 (UM-DR-30: production readiness & capability integration)

> نافذة UM-DR-30: **إغلاق فئة كاملة من إسقاط القنوات + توصيل قدرات الـ recall
> الميتة + إصلاح الوصلات الضعيفة** مع الحفاظ الكامل على الـ precision
> (الـ causal guard يبقى سلطة التأكيد الوحيدة، وكل جديد استشاري غير ترقيمي).
> (1) **عقد قنوات عمود العائلات**: مفاتيح الإخراج العشرون لعقدة family_execution
> كانت تُسقط صامتة بترشيح قنوات LangGraph (فئة R2-graph-03) — أُعلنت كلها
> في `PentestState` (9 مفاتيح family_* + 11 مفتاحًا موسعًا) مع اختبار بقاء
> على مستوى LangGraph عبر مسار البيانات الإنتاجي الحقيقي (28 اختبارًا).
> (2) **خريطة فجوات التغطية في الـ runtime**: `coverage_map`/`gap_detector`
> كانا يتيمين بصفر مستوردين — عقدة `coverage_gap_report` جديدة موصولة بين
> الـ reporter والـ reflection خلف علم fail-closed، تُسقط تقرير فجوات صريحًا
> محدودًا على قناة معلنة (رافعة recall: الحملة صارت ترى أين لم تنظر) (15
> اختبارًا). (3) **المراجعة الثابتة للأعمال**: `InvariantChecker` كان يتيمًا
> بينما مدخلاته تتدفق في الحالة — وُصّل داخل إثراء workflow لعقدة
> business_logic_fuzzer، استشاري غير ترقيمي بحت (required_validation يسمي
> عقد أدلة الـ causal guard) (15 اختبارًا). (4) **run_campaign.sh** أُعيد
> بناؤه على واجهة الـ CLI الحقيقية (--url/--authorization/--scope-file) مع
> اختبار اتساق أعلام آلي (8 اختبارات). (5) **تراكم CVE الـ langgraph يُغلق**:
> تدقيق pip-audit على الإغلاق الفعلي = صفر تحذيرات للعائلة المثبتة بالضبط
> (1.2.10/1.6.7)؛ dnspython 2.8.0→2.9.2 في `uv.lock` (CVE-2026-114605) مع
> 128 اختبار DNS/SSRF أخضر؛ وصُحح انجراف إصدار الـ lockfile (0.34.0→فعلي).
> **البوابات**: refreeze معلن لخمسة مسارات مجمّدة
> (`scripts/refreeze_manifest_umdr30.py`)، جرد direct-I/O مُجدَّد (1149 سجلًا،
> صفر هويات جديدة)، السويت الكاملة **8,661 مجمّعة → 8,652 passed / 6
> skipped / 3 xfailed / 0 failed** (chunked ×13). المصفوفة:
> `docs/engineering/UMDR30_FEATURE_QUALIFICATION_MATRIX.json`. **الصدق**:
> M10 تبقى مغلقة (holdout مستقل = BLOCKED_EXTERNAL_DEPENDENCY؛ شروط إعادة
> الفتح recall ≥ 0.5 ∧ precision ≥ 0.7 على مجموعة مستقلة)؛ LAB_QUALIFIED
> أحادي المستأجر في بيئات مُتحكّم بها فقط.

## 0.35.0 — 2026-11-07 (UM-DR-29: dead-code disposition + qualification truth)

> نافذة UM-DR-29: **إصلاح كامل للشيفرة الميتة والقدرات غير الموصولة والوصلات
> الضعيفة** مع تقرير تأهيل صادق. أكملت النافذة أرشيف ULTIMATE PLAN 2026-10-27
> اقتراح 4 physically (17 حزمة مكرّرة حُذفت من `src/` — النسخ القانونية في
> `archive/pre_v10_prototypes/`)، وأرشفت 7 حزم مجمّدة-ميتة إلى
> `archive/umdr29_dead_code/` مع refreeze موثّق (`frozen_modules.sha256`
> 661→639 إدخالًا، بروتوكول DR-009)، وصحّحت 6 docstrings مجمّدة كانت تدّعي
> كذبًا أن `goed_v1` هو المحرك الأساسي، وأصلحت `BUILD_INFO.git_head` (كان
> يشير لـ commit غير موجود)، وحدّثت جرد الـ direct-I/O (1197→1149 سجلًا،
> -31 هوية كلها داخل الحزم المؤرشفة). المصفوفة الآلية للقدرات:
> `docs/engineering/UMDR29_FEATURE_QUALIFICATION_MATRIX.json` — لا ادّعاء
> إنتاجيًا بلا دليل. M10 تبقى مغلقة (holdout مستقل = BLOCKED_EXTERNAL_DEPENDENCY).

## 0.34.0 — 2026-11-06 (unified tree; engineering windows M0–M12 + UM-DR-13..25 recorded below without a version bump)

> رأس النسخة الحالية لشجرة 0.34.0 الموحدة. نوافذ التنفيذ الهندسي الذاتي
> (M0–M12، ثم UM-DR-24 لبوابات الإصدار و UM-DR-25 لنافذة الفريق الأحمر)
> موثقة كاملة أدناه وفي `DRIFT_REGISTER.md` — بلا ترقية إصدار حتى ينفّذ
> المشغّل جانبه من عملية الإصدار (RELEASE_PROCESS.md).

## M1 RECOVERY WINDOWS — 2026-11-05 (M1-A / M1-B / M1-C / M1-D — بلا ترقية إصدار)

> نوافذ المرحلة الأولى من ولاية التنفيذ الهندسي الذاتي (Autonomous Engineering
> Execution Mandate) على شجرة 0.34.0 الموحدة، بترتيبها المعتمد: **M1-B سلامة
> الأدلة أولًا** (ترسّخ اختبار حراسة الميثاق)، ثم **M1-A الأمن والإعدادات**، ثم
> **M1-C توصيل القدرات**، ثم **M1-D التصرف في الإرث**. كل نافذة موثقة في
> `DRIFT_REGISTER.md` (UM-DR-10 / UM-DR-11 / UM-DR-12) مع اختبارات انحدار جديدة
> تسبق كل refreeze، ومراجعة الجاهزية الكاملة في `M1_READINESS_REVIEW.md`.
> التقرير الختامي للمرحلة: `M1_PHASE_REPORT.md`.

- **M1-B سلامة الأدلة (UM-DR-10):** الـLLM صار استشاريًا بحتًا في كل قرار ترقية
  (المسار العام `confirmed = det_confirmed` — كان يمنع تأكيد XSS دون اتصال بنًهائيًا؛
  شرط `llm_confirmed` الميت حذف من بوابة reauth؛ `causal_signal` حتمي فقط)؛ شرط
  إثباتي معماري على `confidence_level="Tool-Confirmed"` في `models/findings.py`
  (بلا `evidence_bundle` أو تسمية البوابة المؤكدة ⇒ ValueError)؛ `memory/db.py`
  يحمّل صفوف Tool-Confirmed غير المثبتة سابقًا **فاشلًا مُغلقًا**؛ `cost_alerts.py`
  توقف ختم الإشعارات بـTool-Confirmed؛ حذف مدخل IDOR الميت من
  `_DETERMINISTIC_STRUCTURAL_CLASSES`؛ إثبات مصدر صريح على بوابة تأكيد فرق الهوية؛
  شروط مسبقة مُركَّبة غير مُختلقة في محلل السلاسل (مرشحة فرضيات موسومة فقط)؛
  `validate_exploit_chain` يتطلب replay تحكم (رفض chains الثنائية-2xx)؛
  `validate_oauth` يتطلب أثر الكود المسلَّم فعليًا؛ بوابة تصدير صارمة للمنصات (E-3).
- **M1-A الأمن والإعدادات (UM-DR-11):** middleware يرفض الطلبات الممولة عبر
  tunnel/proxy عندما يكون auth OFF (إغلاق مسار H-1 cloudflared)؛ رفض أسرار
  CHANGE-ME عبر JWT/AUDIT/CELERY + بذور WEBPENT_USERS (H-2)؛ تثبيت نطاق katana
  `-fs fqdn` (M-2)؛ ربط GlobalRateGovernor عند نقطة الاختناق (M-3)؛ إصلاح
  ContainedHTTPClient إلى النقل الآمن الوحيد بلا fallback (M-4)؛ حذف urlopen الخام
  من oob/dispatch لصالح النقل الآمن (M-5)؛ حراس SSRF على سياقات Playwright (L-1)؛
  إعلان مضيفي الارتباط في مسار الصيد CLI (L-3)؛ ربط OAST الافتراضي loopback (L-4)؛
  إلزام redact_sensitive على metadata لسجل القرارات (L-5).
- **M1-C توصيل القدرات (UM-DR-12):** إعلان الأعلام المُشار إليها وغير المُعلنة
  فاشلة مغلقة (`enable_oast` + عقد إعدادات OAST الخمسة، `enable_causal_chain_candidates`،
  `enable_campaign_resume`)؛ استثناء loopback الموثوق بالنطاق في نقل SSRF (إصلاح
  انحدار M-5 الذي أبطل قاعدة loopback الموثقة وأفشل جولات جامع OAST)؛ توصيل مرشحات
  السلاسل السببية خلف العلم (استشاري حصرًا، غياب بنيوي عند الإيقاف)؛ سطحا CLI:
  `webpent bounty` (معاينات ProofBundle المُروَّجة فقط — لا إرسال أبدًا) و
  `webpent portfolio` (ترتيب موجات فقط — لا إطلاق)؛ توصيل E-4 (ملاحظات recon
  الفعلية للـOAuth تُثبت الشرط المسبق)؛ سقف التغطية ratchet في CI/Makefile؛ ق5
  self-benchmark في nightly.
- **M1-D التصرف في الإرث (UM-DR-12):** حذف ملفات `.orig` الخمسة بعد التحقق
  البايتي من تطابق النسخ المؤرشفة؛ أرشفة `api/live_stream.py` المتجاوز؛ تشغيل
  محرك ق9 الموثق على العناقيد الميتة — كشف وأصلح **خلل over-match** في المحرك
  نفسه (كان يصنف كل شيء absorbed على أدلة مفبركة: ~190 مستوردًا زائفًا)؛ إعادة
  التشغيل الأمين: 5 مراجعة (سقف رمادي مؤدب بفايتة 0.34.2) و4 absorbed بمستوردين
  حقيقيين؛ إصلاح tabs لملف Makefile الشجرة العاملة؛ مزامنة `docs/CURRENT_RELEASE.md`.
- **بوابات النافذة:** manifest مجمّد 659/659 بعد refreeze موثق (4 ملفات معلنة في
  نافذة M1-C/D)؛ بوابة التجميد + كل أطقم حراسة M1: **776 نجاحًا**؛ التجميع بلا
  أخطاء (8,223 اختبارًا قابلًا للتجميع بعد استكمال بيئة pip المعلنة)؛ بوابة العد
  8,223 ≥ أرضية 8,115؛ ratchet التغطية أخضر (4.27% ≥ 4.07%).

## UNIFIED-MERGE — 2026-11-02 (دمج النسخ الأربع في شجرة واحدة — بلا ترقية إصدار)

> دمج موثق لأربع نسخ من المشروع (ULTIMATE 0.34.0 r2 كأساس + v15.2 MERGED R4 + l10 WIP
> 0.12.0 + v4 start 0.3.0) في شجرة واحدة: اتحاد كامل، 666 تعارضًا حُسمت لصالح خط 0.34.0،
> خمسة ملفات دمجت يدويًا على مستوى المحتوى، والتفاصيل الكاملة في `MERGE_REPORT.md` في
> جذر الشجرة. هذا الإدخال يوثق **إصلاحات التكامل** التي أثبتها التشغيل الفعلي بعد الدمج
> (بيئة Python 3.12 + uv، 248 حزمة):

- **إصلاح:** `uv.lock` المُسلَّم كان غير متطابق مع `pyproject.toml` — أُعيد توليده
  (وإلا `uv sync --locked` يفشل من أول تشغيل).
- **إصلاح (5 بوابات collection):** استعادة `FAMILY_GRANT_REPLAY` في
  `egaie/differential.py` و`ProposalOrderSelector` في `egaie/selection.py` من سلالة
  l10 (بتعليق توثيقي في الملفين)؛ استعادة الاسم العام `decode_jwt_claims` في
  `recon/identity_discovery.py` وفق عقد R6 من v15.2 مع **refreeze موثق** لإدخاله في
  `frozen_modules.sha256`؛ إضافة `esprima` و`jsbeautifier` و`dnspython` إلى dev extras
  (تبعيات وكلاء مُسلَّمة كانت مفقودة).
- **قرار:** `tests/test_lessons_learning_loop.py` يُتخطى على مستوى الوحدة — نظام
  lessons حُذف عمدًا في نافذة G-1 (0.29.0) والاختبار من خط v4 يُحتفظ به للمرجعية.
- **معايرة:** بوابة عدد الاختبارات أُعيد تجميدها من القياس الفعلي: **7,958** (الشجرة
  الكاملة، كانت مجمدة خطأً على 1,940) و**7,116** (نسخة SLIM الإنتاجية).
- **نتيجة التشغيل:** `make test-count` أخضر في البناءين؛ صفر أخطاء collection؛
  frozen manifest 659/659 مطابق؛ 222/289 ناجحًا في مجموعات egaie/appsuite/labsuite مع
  **67 فشل انجراف API** (l10→0.34.0) موثقة بخطة إصلاح في `REDTEAM_AND_FIX_PLAN.md`.
- **إعادة تنظيم إنتاجية:** ملفات التشغيل المؤقتة (webpent.db، chroma.sqlite3،
  vulnbox_metrics، .orig، debug) نُقلت إلى `archive/runtime_artifacts/`، وبُنيت نسخة
  `WebPent_SLIM` (3,680 ملفًا) بعد فحص أمان عكسي للاستيراد (src→src وtests→src) بصفر
  مخالفات، مع floor معاير مستقل.
- **توثيق جديد:** `MERGE_REPORT.md`، `REDTEAM_AND_FIX_PLAN.md`،
  `FEATURE_PROPOSALS.md`، `CAPABILITIES_AND_ARCHITECTURE.md`، README محدث بقسم
  «نسخة الدمج الموحد».

## 0.34.0 — 2026-11-02 (نافذة جولة الred-team الثانية — إصلاح `RED_TEAM_ROUND2_20261102.md`)

> **حرفية النافذة:** جولة red-team ثانية غطت الوحدات غير المفحوصة سطرًا بسطر في الجولة الأولى
> (dojo/econ/jc/prism/graph — 68 ملفًا و16,669 سطرًا مقروءة بالكامل بخمسة وكلاء متوازيين)،
> وأنتجت 45 نتيجة مُتحقق منها (1 حرجة / 9 عالية / 18 متوسطة / 17 منخفضة)؛ كل النتائج
> الحرجة والعالية العشر أعيد التحقق منها يدويًا بقراءة الكود. هذه النافذة تغلق الدفعة C1
> (10/10) وC2 (18/18) وC3 (16/17 — الفعل الوحيد المؤجل: ربط
> `lesson_priority_adjustments` بعقد hypothesis/payload داخل الرسم، جزء بند
> R2-graph-07 المعماري، إلى 0.35.0 بتوثيق صريح)،
> بنفس بروتوكول 0.33.0: اختبار جديد يفشل قبل الإصلاح ويجوز بعده + الأبواب كاملة.

### الحرجة والعالية (C1 — 10/10)
- **R2-graph-01 (حرجة)**: عقدة recon في `graph/builder.py` كانت تعيد الحالة الكاملة كـupdate
  فتتكرر قناة `node_step_trace` append-only في كل تشغيل إنتاجي ويتضخم عدّاد استهلاك
  الميزانية عند الحاكم ~5 خطوات وهمية. الإصلاح: مصنع `_make_combined_recon_node` يعيد
  الدلتا فقط عبر `_strip_append_only_channels` (اشتقاق القنوات append-only من
  `PentestState.__mro__`).
- **R2-graph-02**: راوتر hypothesis يعيد `strategist` تحت ضغط الميزانية لكن خريطة الحافة
  بلا مفتاح → `KeyError` يقتل التشغيل. الإصلاح: `HYPOTHESIS_PATH_MAP` تشمل
  NODE_STRATEGIST.
- **R2-graph-03**: `scope_drift_approved` غير معلنة في `PentestState` → langgraph يُسقطها
  → طريق موت في استئناف HITL. الإصلاح: إعلان القناة (+ `smart_mode`/
  `enable_smart_campaigns` لـR2-graph-07).
- **R2-graph-04**: استيراد `webpent.shared.checkpoints` غير الموجودة → checkpointer
  دائمًا None → توقف صامت بعد payload_generator في وضع HITL. الإصلاح: الاستيراد من
  `graph.checkpoints` + فشل صاخب `_resolve_checkpointer_for_run` عند غيابه مع
  auto_approve=False.
- **R2-jc-01..03**: sentinel `_UNSET` ينهار بـAttributeError عند تعطيل skeptic/judge من
  الإعدادات؛ `clamp01` على نطاق USD يحول ترتيب Economist/Tactician/Adapter لأبجدي
  فيختارون التوصية الخطأ؛ `canonical_json(default=str)` يجعل `context_hash` معتمدًا على
  PYTHONHASHSEED مع sets. الإصلاحات: إنزال None للأدوار المعطلة، مفتاح ترتيب
  `_rank_number` خام، تحويل sets إلى قوائم مرتبة في الهاش.
- **R2-dojo-01**: الإجابات الخاطئة تضخم نقاط التدريب بلا سقف (600.0) — الحساب على
  المحاولات الصحيحة فقط.
- **R2-econ-01**: `last_transition` naive من portfolio.yaml يفجر `auto_transition` بـ
  TypeError — تطبيع UTC عند الحدود + حزام أمان في auto_transition.
- **R2-prism-01**: `record_outcome` يقبل دليلًا من حملة أخرى → سجل تدقيق متناقض — فحص
  مقيّد بالحملة + `PRAGMA foreign_keys=ON`.

### المتوسطة (C2 — 18/18)
- dojo: مفاضلة على الميزانية المفروضة من نمط الدفاع (02)، اشتقاق العائلات من
  skill_families (03)، اشتراط تطبيق النمط فعليًا قبل إعلان فعاليته (04)، تعداد
  skill_families في CLI (05). econ: تطبيع since غير UTC (02)، فهرس فريد + INSERT OR
  IGNORE ضد الازدواج مع rows_ignored (03)، ذيل الـ4096 لا رأسه (04)، مسارات
  gray_zones تصل path_region (05)، الإشارة التالفة = partial لا ثقة 1.0 (06)، حقل
  رقمي تالف لا يحذف الهدف (07). jc: حواف buckets IEEE-754 (04)، تسامح صفوف ts
  تالفة في calibrator/bias/memory (05)، رفض تكرار advocate_id (06). prism: مفتاح
  الأبعاد في evidence_id ضد تصادم الدرجات (02)، كتابة ذرية لسجل الامتثال (03)،
  قراءة request_cost_step في الطبقتين (04)، إلزام مفاتيح noise_penalties الثلاثة
  (05)، تحقق مفاتيح value_weighter/anomaly_filter المستهلكة + رتابة العتبات (08).
  graph: redaction لا يمس channel_versions/versions_seen (05).

### المنخفضة (C3 — 16/17 مغلقة هذه النافذة)
- dojo-06..10 (فلتر غير حساس لحالة الأحرف، أسبقية strict_types، سقف cap=1،
  *.yml، حفظ ذري) — econ-08..11 (tier=NO_DATA، ترتيب sets، P_dup معدلة
  بالتشبع، تحذير KB أقدم من 90 يومًا) — jc-07/08/09 (سياق non-dict، عدّ الأسطر
  المكتوبة فعلًا، flock للقراءة-الكتابة) — prism-06/07 (PrismLawError عند حدود
  القانون) — graph-06 (عدّاد المؤكد عبر _finding_strength بدل validation_status
  غير الموجودة، في progress_display وunified_hunt معًا) — graph-07 إعلان القنوات.

### الأبواب
- **collect-only**: 6844 اختبارًا مجمعة، **0 أخطاء تجميع**.
- **Suite كاملة بخمس دفعات**: تم التسوية بالضبط (ر. أدلة التنفيذ) — 0 failed.
- **ruff ratchet**: 6209 == 6209 (F821/F402/E722/B025 نظيفة).
- **canary 7x**: STABLE مع بوابة التجميع.
- **التجميد**: manifest 659 أعيد تثبيته (13 مثبتة تغيّرت + 25 غير مثبتة موثقة في
  سكربت النافذة)؛ مجموعة `REDTEAM_R2_20261102_THAW_PATHS` (عنصر واحد:
  graph/checkpoints.py — البقية مغطاة بمجموعات سابقة)؛ direct-I/O أُعيد توليده
  عمدًا 814→816 (+2 dynamic_resolution getattr: blind_spots gray_zones وبuilder
  اشتقاق القنوات؛ −2 إزالة probes الـvalidation_status) — صفر مواقع نقل خام جديدة.
- اختبارات النافذة: 61 اختبار R2 جديد (c1=19، c2=15، c3=8، dojo=9، econ=10) كلها
  فشلت قبل إصلاحها؛ تحديث تثبيت سلسلة مصدر واحد في test_r3_e2_builder_rejection
  (استدعاء modern spine انتقل من `dict(state)` إلى `dict(working)` بعد إعادة
  الهيكلة — النية modern-first محفوظة ومثبتة).

## 0.33.0 — 2026-11-01 (نافذة التصلّب الإنتاجي الشاملة — تنفيذ `PRODUCTION_HARDENING_PLAN_0330.md`)

> **حرفية النافذة:** خطة 0.33.0 أُنشئت من مراجعة نقدية شاملة بالأدلة (6740 اختبارًا،
> bandit 198 نتيجة مُفرزة يدويًا، ruff، و3 مراجعات عميقة متوازية بتحقق تنفيذي)،
> وكل بند فيها يحمل ملفًا وسطرًا وسيناريو فشل. هذه النافذة تنفّذ كل بنود B1/B2/B3
> (100%) + الحد الأدنى الملزم لـB4 (F-07 + 3أ-1 + 3أ-2) + إصلاحات P2 السريعة،
> مع بروتوكول التحقق الموحّد: اختبار جديد يفشل قبل الإصلاح ويجوز بعده + الأبواب كاملة.

### البوابات الجديدة (تصعد مستوى الصدق عن 0.32.0)
- **بوابة تجميع الاختبارات (3أ-2)**: أُثبت حيًّا أن بيئة ناقصة الoptional deps
  تُنتج 77 خطأ تجميع **صامتًا** — المنظومة "تخضر" والوحدات الخطأ لا تُجمع أصلًا.
  الcanary الآن يشغّل `pytest --collect-only tests` ويجمد: **0 أخطاء تجميع** شرط
  لصحة أي نتيجة (يظهر في التدخينة كـ`collection_clean`).
- **ملف القيود الموحّد (3أ-1)**: `requirements.constraints.txt` — أُثبت أن تثبيت
  أي جزء من الdeps وحده يسمح لـpip **بإنزال** pins مثبّتة (rich/uvicorn نزلوا فعليًا).
  التثبيت الوحيد المدعوم الآن: `pip install -e . -c requirements.constraints.txt`.
- **صحة صورة الإنتاج (F-07)**: `.dockerignore` — قبلها `COPY . .` كان يخبز في
  الطبقات: قاعدة بيانات الاشتباك الحية `webpent.db` + 36MB docs + reports/اختبارات.

### B1 — الوظائف الحاجبة (كلها بإصلاح + اختبار يعزلها)
- **F-01** `memory/ab_lab.py`: تصادم `run_id` — لم يكن يضم الهدف، فأي هدف ثانٍ
  لنفس العميل في نفس الأسبوع يُسقط `open_week` بـUNIQUE violation نهائيًا.
  المعرف الآن `week-arm-client16-targetdigest`.
- **F-02** `llm_researcher/providers/pool.py`: بئر المزوّدين كان **ميتًا وظيفيًا** —
  `OpenAICompatibleProvider(api_key=…, base_url=…)` بوسائط غير موجودة في التوقيع
  ⇒ `TypeError` في كل استدعاء ⇒ كل الslots تفشل ⇒ `REAL_API_UNAVAILABLE` حتى
  بمفاتيح صحيحة. أُصلح البناء (`api_key_env/base_url_env` من الslot + قيم محسومة)
  مع **صدق فشل جديد**: `LLMResponse.error` لم يعد يُسجَّل نجاحًا للslot.
- **F-03** `openai_compatible.py`: تسريب `httpx.Client` لكل نداء (بلا close) —
  أُضيف `close()` + context-manager، والpool يغلق في `finally`.
- **P1-09** `campaign/executor/pivot_engine.py`: `Any` في 3 تشرحات بلا استيراد
  (NameError كامن مع أول `get_type_hints`) — استُورد.

### B2 — الحدود الأمنية
- **F-04** `production/modern_spine.py`: مسار التراجع عن `make_safe_httpx_client`
  كان يعيد نفس الهدف على عميل httpx خام **بلا تثبيت DNS ولا blocklist** عند أي
  استثناء غير-SSRF — الحماية تُسقط بالضبط للهدف الوحيد المرخّص. أُغلق (fail-closed).
  - **إصلاح انحدار داخل-النافذة (مُتحقَّق بفشل 15 اختبار team1 ثم نجاحها):**
    إغلاق الfallback كشف أن `execute_real_request` لم يكن يسجل هدف الاشتراك
    أصلًا (حماية 0.32.0 كانت تعتمد على المحاولة الخام). الآن يسجّل الهدف عبر
    آلية الengagement-allowlist المصممة (نمط `_execute_local_loopback`)، ويُمرر
    `guard_redirects=False` ليرصد الـ30x كدليل open-redirect دون أي اتصال
    بوجهة الredirect — لا عميل خام في المسار إطلاقًا.
- **F-05** `api/workers_status.py`: `/api/v1/workers/status` و`/workers/health`
  كانتا بلا مصادقة على نفس تطبيق JWT — الحصاد: أسماء workers وعدد الاشتباكات
  النشطة وأزمنة التشغيل لمتخفٍّ. الآن `Depends(require_viewer)`.
- **F-06** `api/app.py` + `shared/engagement_scope.py`: باب قبول الفحص لا يمنع
  الأهداف الخاصة/link-local من جهة الخادم — المسار كان يفتح تحوّل الهدف المرخّص
  إلى مفتاح blocklist الـSSRF (`169.254.169.254` metadata قابل للزحف بمستخدم
  admin). الآن `admission_target_check` قبل التسجيل، ورفض metadata غير مشروط.
- **P2-02** `service/api.py`: `_check_owner` كان يفحص `is_admin` (غير موجودة على
  `User` — الصحيح `is_global_admin`) ⇒ authz معطّل وظيفيًا (fail-closed).
- **P2-04** `api/auth.py`: تعداد أسماء المستخدمين عبر توقيت bcrypt — مسار
  "مستخدم مجهول" لا يعدو يعمل dummy-hash بتوقيت مكافئ.
- **P2-05** `api/scan_registry.py`: `claim_resume_capability` كان SELECT-then-UPDATE
  بقفل داخل-العملية فقط ⇒ عاملان API يطأَن نفس الclaim — صار UPDATE شرطي واحد
  يفحص `rowcount`.

### B3 — صلابة الصيد الطويل (17 بندًا — كلها مغلقة)
- **P1-01** `hunt_orchestrator.py`: عدّاد الجولات الهادئة لا يُصفَّر على الجولات
  المُنتِجة ⇒ إنهاء مبكر `NO_NEW_EVIDENCE` — يُصفَّر الآن عند أول دليل جديد.
- **P1-02** `ab_lab.py`: فجوة check-then-act بين اختيار النافذة ووضع `running`
  (نداءا `tick()` متوازيان ينفذان نفس النافذة) — حجز شرطي `WHERE status='planned'`.
- **P1-03** `ab_lab.py`: إعادة `open_week` بتفويض/نمط مختلف كانت تُقبل بصمت وتنفّذ
  تحت التفويض القديم — الآن تُرفض بتعارض صريح.
- **P1-04** `memory/db.py`: حماية OOB-clobber في `save_finding` داخل-العملية فقط
  (انتكاس V10 P1-10 عبر العمليات) — `BEGIN IMMEDIATE` + الإشعار خارج القفل.
- **P1-05** `brain/ev_scheduler.py`: أرضية منع-الجوع كانت تتجاوز سقف الميزانية
  (3 على 10 فرضيات ⇒ منح 10) — مقيدة بالسقف.
- **P1-06** `hunt_memory.py`: `_load` كان يثق بتوقيع الصف المخزّن دون تحقق ⇒
  ذاكرة مزوَّرة تُصدَّق — تحقق إجباري عند القراءة.
- **P1-07** `hunt_memory.py`: عند سقف 512 كانت التحديثات للأنماط القائمة تُهمل
  بصمت (نتيجة مصححة لا تكتب أبدًا) — الupsert يتجاوز السقف للمفاتيح القائمة.
- **P1-08** `ab_lab.py`: تشغيل `running` منهار كان يحجب رأس الصف للأبد (لا أسبوع
  أحدث يُجدول) — الأسبوع يُتخطى لحساب الجدولة ويرفع علم stale للمشغّل.
- **P1-10** `autonomous_hunter.py`: درجة `MEDIUM` في سلّم التصعيد كانت ميتة
  (`conf>=1` يلتقطها فرع HIGH السابق) — أُعيد الترتيب.
- **P1-11** `autonomous_hunter.py`: فرض النطاق بـsubstring كان قابلًا للتجاوز
  (`notexample.com`/`evil.com?u=example.com`/`example.com@evil.com`) — الآن
  تحليل hostname ونطاق مسجّل.
- **P1-12** `core/infrastructure.py`: كتابة checkpoint غير-ذرّية كانت تُفسد
  `resume()` للأبد عند مقاطعة — كتابة `.tmp` + `os.replace()` + backup.
- **P1-13** `production/modern_spine.py`: حدود live_hunter كانت تنفجر `RuntimeError`
  في عمق المحرك — مسار `research_step_bounded` يتحول إلى `bounded_stop` مؤدب
  (عقد `RuntimeError` للواجهة المباشرة بقى كما هو مُثبّت باختبار team1).
- **P1-14** `adapters/controlled_target/adapter.py`: تسابق بلا قفل على ميزانية
  الطلبات و`start()` لsingleton عالمي — `threading.Lock`.
- **P1-15** `llm_researcher/interface.py`: `ResearchMemory.observations` تنمو للأبد
  رغم docstring "Bounded" — اقتطاع عند الكتابة.
- **P1-16** `recon/browser_crawler.py`: عمل قابل للفشل داخل `finally:` قبل إغلاق
  المتصفح كان يتخطى `close_campaign` ويحجب الاستثناء الأصلي — إعادة ترتيب.
- **P1-17** `shared/persistent_finding_ledger.py`: كتابة sqlite عبر-العمليات بلا
  WAL/busy_timeout ⇒ `database is locked` تحت دمج متزامن — `WAL + busy_timeout`.

### P2 — نظافة مُنفذة في هذه النافذة
- **P2-01**: رسالة عامل الاختراق كانت ترشد لـ`WEBPENT_TASK_CRYPTO_KEY` — متغير
  لا يقرؤه أي سطر في الكود (الصحيح `CELERY_PAYLOAD_KEY`) — صُححت الرسالتان.
- **P2-09**: `except:` عريان في `recon/auth_handler.py` (E722) — ضُيّق.
- **P2-10**: تظليل استيراد `field` بمتغير حلقة في `causal_adapter_v2.py` و
  `advisory_registration.py` (F402 ×2) — أُعيدت التسمية.
- **P2-11**: `ImportError` ميتة في tuple استثناءات CSRF بعد `except ImportError:`
  السابق لها في نفس الtry (B025) — أُزيلت.
- **P2-18**: `poc_recorder.py` يكتب metadata بلا `encoding="utf-8"` (انهيار cp1252
  على Windows لمحتوى الهدف غير-ASCII) — أُضيف الترميز.

### الأرقام (بروتوكول §6 في الخطة)
- التجميع: **6783** = 6740 (خط 0.32.0) + 43 (اختبارات التصلّب الجديدة b1=10/b2=12/b3=21) — 0 أخطاء تجميع.
- ruff ratchet: 6209 = baseline 6209 (الست مواقع F821/F402/E722/B025 خرجت من
  الكود كليًا: `ruff --select F821,F402,E722,B025` ⇒ All checks passed).
- الملفات المعدلة: 21 مصدرًا + 4 اختبار + 3 ملفات اختبار جديدة + 3 بوابات/بنية
  (`.dockerignore`, `requirements.constraints.txt`, بوابة تجميع في canary).

## 0.32.0 — 2026-11-01 (نافذة إزالة الأوامر المتقادمة المعلنة: scan / hunt-auto / hunt-plan خرجت من الشجر — الوعد المعلن في بند ج.2 من نافذة 0.30.0 نُفذ حرفيًا)

> **حرفية النافذة المعلنة:** لافتات `scan`/`hunt-auto`/`hunt-plan` في
> 0.30.0 أعلنت كل منها "scheduled removal: v0.32.0" (نافذتان معلنتان بعد
> تلك). هذه هي تلك النافذة وتحمل الاسم المعلن حرفيًا: **v0.32.0** —
> رقم الإصدار 0.31.0 لم يُفتح عمدًا (لا بند معلن لها)؛ القفز من 0.30.0
> إلى 0.32.0 هو التزام بالنافذة الموعودة لا خطأ ترقيم، وموثق هنا.
> ما أُزيل هو **مداخل CLI المتقادمة فقط** — كل المحركات الحية بقيت
> ببايت سلوكي واحد: محرك الـgraph الإنتاجي (مستمر عبر `hunt` الموحد)،
> والصياد المحدود (`webpent.autonomous` — صار **مكتبة API** موثقة)،
> وعدّاء الصياد `run_hunter_campaign` (مستمر عبر `agent-hunt`).

- **المحذوف من `src/webpent/cli/commands.py`** (2245 → 1226 سطرًا):
  - أمر `scan` (نحو 660 سطرًا) — الأمر القديم الكامل؛ بوابة الصدق
    الخاصة به (`_chain_honesty_verdict` عند الاستدعاء) ماتت معه. مساعداه
    الوحيدان في الإنتاج ماتا معه: `_parse_report_formats` (مُطبِّع
    الفورمات المفصولة بفواصل — `hunt` الموحد يأخذ قيمة واحدة) و
    `_load_json_list` (مُحمِّل قوائم JSON — كان أصلًا re-export فقط).
    المساعدات المستخدمة بأوامر حية بقيت: `_chain_honesty_verdict`
    (مُختبرة مباشرة)، `_enforce_chain_honesty` (`agent-hunt`)،
    `_parse_credentials`/`_parse_cookies` (`unified_hunt`)،
    `_load_hunter_principals`، `_perform_preflight_check`.
  - أمر `hunt-plan` (الـplanner المتقاعد — مسار `--target` منه مطابق
    حرفيًا لـ`agent-hunt` الحي).
  - أمر `hunt-auto` (الصياد المحدود عبر CLI) — **مع نقل بوابة أمنية
    حقيقية قبل الحذف**: إغلاق إعادة التحقق من التفويض منتصف الحملة
    (v80 Task 3 / CR-5) كان يُعرَّف داخل أمر CLI فقط؛ نُقل **حرفيًا**
    إلى وحدة جديدة `src/webpent/autonomous/authorization_recheck.py`
    (`make_authorization_recheck(path, target)` → callable يُعاد تمريره
    إلى `run_wired_hunt(auth_recheck=...)`). البوابة: قراءة الملف من
    جديد كل استدعاء بلا كاش، وأي فشل قراءة/تحليل = سبب منمّق (فشل
    مغلق) لا مرور صامت. سلوك الـruntime (التوقف BLOCKED بسبب
    `authorization_revoked_mid_hunt`) يبقى مثبتًا في
    `tests/test_hunt_intel.py` كما هو.
  - 14 استيرادًا ميتًا نظّفها ruff (F401) بعد الحذف.
- **وحدات صياغة موثقة** (تعليقات/docstrings فقط): `cli/unified_hunt.py`
  (فقرة "legacy commands untouched" صارت "REMOVED in v0.32.0")،
  `state/unified_state.py`، `adapters/legacy_state_bridge.py`،
  `autonomous/hunt_state.py` (دلالة `to_report_json` صارت API مكتبة)،
  و`autonomous/__init__.py` (تصدير `make_authorization_recheck`).
- **مخازن intel/deadends بقيت مغطاة**: تغطية API موجودة أصلًا وعميقة
  (`test_hunt_intel.py`/`test_hunt_deadends.py`: round-trip، تلف ملف
  يتدهور لذاكرة فارغة، حفظ ذري، ولا record لحملة بلا proof bundles)؛
  واختبار تعادل wiring واحد جديد يجري نفس عقد الـCLI القديم عبر
  `run_wired_hunt` مباشرة.
- **الاختبارات (6752 → 6740، تسوية تامّة بند-ببند):** −26 محذوفة
  (12 لـ`test_autonomous_hunt_cli.py` كاملًا — ماتت مع سطحها؛ 1
  plan-only في `test_v23_cli_commands.py`؛ 8 في m2a: صنفا
  `TestHuntCliExitCodeHonesty`/`TestScanCliExitCodeHonesty` + دبوسا
  مصدر scan في الـsweep؛ 5 محمِّل JSON في `test_v14_entrypoint_wiring.py`)
  +14 مضافة (`tests/test_retired_alias_removal_v0320.py`: بوابات إزالة
  fail-closed — الأسماء الثلاثة غائبة من سجل الأوامر واستدعاؤها يفشل
  و`--help` لا يعلنها، و«الأوامر الحية» `hunt`/`agent-hunt` مسجلة؛ +
  5 اختبارات recheck المنقولة + 1 wiring تعادل) +1 (بند الـmanifest
  الجديد 658 → 659 في بوابة التجميد المتغيرة على عدد المدخلات) −1
  (سطح `webpent.cli.commands` خرج من قائمة أسطح بوابة R3 E-2 — لم يعد
  يربط `build_graph` على مستوى الوحدة بعد حذف scan؛ نقطة التركيب نفسها
  وworker وapi بقيا مثبتين). دبابس الصقلا المصدرية لسطح scan
  (`test_half1_behavioral` / `test_i_official_entrypoint`) أُعيد توجيهها
  لمسار `unified_hunt` الحقيقي — نفس العقد (استيراد `build_graph` من
  نفس نقطة التركيب)، لا إضعاف.
- **بوابة التجميد:** `frozen_modules.sha256` أعيد تجميدها
  (`scripts/refreeze_manifest_0320_alias_removal.py`): 658 → **659**
  مدخلًا (+1 scope completion) و6 ملفات معلنة أعيد تثبيتها؛ نافذة
  `ALIAS_REMOVAL_20261101_*` موثقة في `tests/test_frozen_module_gate.py`
  (thaw واحد: `cli/__init__.py` — تنظيف re-exports ماتت مستدعياتها).
  جرد I/O المباشر أُعيد توليده (`scripts/regen_direct_io_inventory_0320_alias_removal.py`):
  817 → 815 سجلًا — حذف معلن وحيد identity (`dynamic_resolution getattr`
  ×2 موقعًا داخل جسد scan)؛ صفر إضافات؛ دبوس unapproved-transport لم
  يتحرك؛ اختبار G-02 أخضر.
- **السقّاطة:** 6221 → **6209** (الحذف أنقص 11 مخالفة؛ الملفات الجديدة
  صفر مخالفات).
- **مرشح نافذة معلن (بلا وعد):** مسار `hunt` الموحد لا يحمل بعد بوابة
  صدق سلسلة البحث التي حملها `scan` (خروج غير-صفر عند قصور السلسلة) —
  كان انحرافًا قائمًا قبل هذه النافذة (unified hunt خرج هكذا منذ
  0.23.0) وليس رجوعًا سببها الحذف؛ يُعلن هنا كمرشح نافذة مستقبلية كي
  لا يُقرأ الصمت موافقة.
- **الهوية والبوابات:** الإصدار → **0.32.0** في
  pyproject/`__init__`/BUILD_INFO/CURRENT_RELEASE/Dockerfile ARG.
- **الأدلة:** `docs/FULL_SUITE_EVIDENCE_0320_ALIAS_REMOVAL_CHUNKED.txt`
  (6740 مطابقة تامّة)، canary 7x
  (`reports/canary/CANARY_7X_20261101_0.32.0.json`)، ruff ratchet 6209.

## 0.30.0 — 2026-11-01 (نافذة تنفيذ `WEBPENT_FIX_PLAN_20261029.md`: تحقق بند-ببند بالتشغيل الفعلي + مسح CVE للقفل المقفول + إغلاق متبقّي المرحلتين ب وج)

> **المنهجية:** الخطة أُعدّت يوم 2026-10-29 على حزمة 0.23.0، ووصّت نفسها
> صراحةً: "أعد التحقق من كل رقم هنا عند التنفيذ لأن الكود يتغير". لذلك
> نُفِّذت كبند-ببند على الشجرة الحالية (0.29.0): كل بند ثبت أو أُغلق
> بالتشغيل الفعلي لا بالقراءة، والأدلة الحرفية في
> `docs/FULL_SUITE_EVIDENCE_0300_PLANEXEC_CHUNKED.txt`.

- **المرحلة أ (أ.1 → أ.7) — كلها خضراء بالتشغيل** (كانت أُغلقت في نوافذ
  سابقة، وأعيد إثباتها اليوم): بوابة G-08 للجرد المباشر، اتفاق مصادر
  الإصدار، `reportlab` مُسجّلة رسميًا (4.4.9 مثبّتة ومُختبرة عبر
  `tests/oracle/test_u_oracle_11/12.py`)، عزل الحملات المتوازية (الملف
  كاملًا)، عدد عقد الـgraph، بوابة الاستثناءات الواسعة، والاختبارات
  المتبقية كلها خضراء (71 passed + 2 xfailان موثّقان بقرار DR-015).
- **ب.1 — ruff ratchet** (موجود كحاجز REQUIRED في `ci.yml` منذ نافذة
  2026-10-29): أُعيد تشغيله → 6221 ≤ baseline، والمكسب (6224 → 6221)
  **جمّد بسبب مسجّل** عبر `--update-baseline --reason` وفق بروتوكول
  السقّاطة.
- **ب.2 — CVEs / pip-audit (أكبر إصلاح في النافذة):**
  - **انحراف القفل المكشوف:** `uv.lock` كان منحرفًا عن `pyproject.toml`
    (لم يُعاد قفله بعد رفع 0.29.0): كان يحمل `langgraph 1.2.12`
    مخالفًا للتثبيت الحرفي `==1.2.10`، و`playwright 1.48.0` و
    `torch 2.13.0` و`typer 0.27.1` مخالفةً لتثبيتاتها، وحزمتين معلنتين
    في `[project.dependencies]` وغائبتين عن القفل (`arjun`, `dicttoxml`).
    `uv lock` أعاد المزامنة على التثبيتات الحرفية بالضبط.
  - **المسح الفعلي على المجموعة المقفولة** (`uv export --locked` ثم
    `pip-audit -r --no-deps` على 248 حزمة): **55 ثغرة في 11 حزمة**
    أُغلقت جميعها بترقيات القفل: `aiohttp 3.14.5`, `certifi 2026.10.23`,
    `filelock 4.2.6`, `langgraph-sdk 0.4.11`, `multidict 7.2.1`,
    `oauthlib 4.0.1`, `opentelemetry-* 1.45.2`, `pyasn1 0.6.5`,
    `pypdf 6.21.4` (تثبيت pyproject رُفع من 6.19.0), `setuptools 84.2.1`,
    `urllib3 2.8.0`.
  - **المتبقي الوحيد:** 4 PYSECs على `chromadb 1.5.9` — وهي أحدث إصدار
    على PyPI إطلاقًا (تحقّق بـ`pip index versions`) وبلا إصدار مُصلِح
    upstream؛ سُجّلت في `scripts/quality/cve_allowlist.json` بسببه
    الموثق وتاريخه، والبوابة صار تمرّ: **0 ثغرة غير مسموحة**.
    `docs/pip_audit_release.json` أُعيد تسجيله بتاريخ اليوم (191 حزمة
    مُدقَّقة على المجموعة المقفولة).
- **ب.3 — secrets/SAST/SBOM:** موجودة كخطوات REQUIRED في `ci.yml` منذ
  نافذة 2026-10-29 (فحص أسرار fingerprint-precise، bandit عالي الخطورة،
  SBOM CycloneDX artifact لكل تشغيل). أُعيد التحقق الفعلي: فحص الأسرار
  اليوم = **0 كشف**.
- **ب.4 — تاريخ Git:** المستودع الفعلي يحتفظ بتاريخ commits، ونافذة
  التسليم هذه تُسجَّل بـcommit موثق رقمه في ملف الإثبات (والـzip يستثني
  `.git` وفق اصطلاح التسليم الموثق للساندبوكس — كل تسليم مستقبلي يرفق
  برقم commit مرجعي، وتاريخ Git الكامل متاح في المستودع الفعلي).
- **ب.5 — نظافة الجذر:** آخر 10 تقارير تاريخية (MERGE/UNFREEZE/REMEDIATION/
  REVIEW_REFREEZE/ULTIMATE_PLAN_EXECUTION/ADDITIONS_AND_FIXES/CHANGED_FROM_BASELINE)
  خرجت من الجذر إلى `docs/archive/2026-11-01-plan-exec-root-reports/`
  (سكربت `scripts/root_reports_archive_20261101.py` يفشل مغلقًا)، وكل
  المؤشرات حدثت (README + تعليقات provenance في `src/` و`tests/`).
  الجذر الآن **37 ملفًا فعّالًا** (كان 152 يوم إعداد الخطة، 46 قبل
  النافذة). `frozen_modules.sha256.baseline_pre_unfreeze` بقي بالجذر
  عمدًا — البوابة المجمّدة تقرأه فعليًا (`tests/test_frozen_module_gate.py`).
- **ج.1 — تسمية SSO:** الكود صادق داخليًا ("documented SEAM, not an SSO
  client")، وخارطة الطريق الموحدة (بند التشغيل المؤسسي) أُهيّأت لتقول
  حرفيًا: SSO = **mapping seam غير موصول بمزوّد OIDC/SAML بعد ولا يُسوَّق
  كتكامل فعلي** — لا غموض تسويقي.
- **ج.2 — الأوامر المتقادمة:** لافتات `scan`/`hunt-auto`/`hunt-plan` أصبح
  كل منها يعلن **نافذة إزالة مجدولة: v0.32.0** (نافذتان معلنتان بعد
  هذه)، ورسالة `hunt-plan` صُححت اتجاهها (كانت تقول إن `hunt` انتقل
  إليها بدل إعلان إهمالها هي). إعلان الإزالة هنا في CHANGELOG.
- **ج.3 — فئات الثغرات المعلنة أُثبتت بالتشغيل:** 54 اختبارًا خضراء عبر
  `tests/test_prototype_pollution_detector.py` (سلبيتان صريحتان)،
  `tests/deep/test_cache_deception.py` (إيجابي + سلبيان)،
  `tests/test_v29_surface_security.py` و`tests/test_v58_http_discovery.py`
  (كشف GraphQL/introspection/batching/depth في `shared/surface_security.py`
  و`shared/http_discovery.py`)، و`tests/test_source_leak_discovery.py` —
  التغطية المعلنة في README (سطر فئات 2026-10-27) ليست ادعاءً.
- **الهوية والبوابات:** الإصدار → **0.30.0** في
  pyproject/`__init__`/BUILD_INFO/CURRENT_RELEASE/Dockerfile ARG؛
  `BUILD_INFO.brain_modules` حُدّث بحذف `lessons` (بقية G-1 قديمة)؛
  جرد I/O المباشر أُعيد توليده عمدًا لانزياح أسطر `cli/commands.py`
  (لا مواقع نقل جديدة)، و`frozen_modules.sha256` أُعيد تجميده
  (`refreeze_manifest_0300_plan_exec.py` بملفات التغيير المعلنة).
- **الأدلة:** `docs/FULL_SUITE_EVIDENCE_0300_PLANEXEC_CHUNKED.txt`
  (6752 مطابقة تامّة: 6746 passed / 0 failed / 3 skipped / 3 xfail،
  مع تصنيف flake زمني واحد 5× أخضر منفردًا)، canary 7x
  (`reports/canary/CANARY_7X_20261101_0.30.0.json`)، ruff ratchet 6221.



> سياسة "الحذف تغيير معلن منفصل": هذه هي نافذة الإعلان والتنفيذ التي
> وعدت بها قرارات 0.26.0 (`docs/learning_source_of_truth.md`) و0.27.0
> (الخطة). النطاق الحرفي للبند G-1: حذف المفكرة المتقاعدة الوحيدة
> (`src/webpent/brain/lessons.py` — سجل in-memory ميت من خط v14.1
> "restored-rewritten (minified)"، لا مسار إنتاجي يلمسه إطلاقًا) وما
> يلزم حرفيًا ليبقى الشجر أخضر. نظام التعلم الحي (`memory/` — مصدر
> الحقيقة المعلن) لم يُلمس ببايت واحد.

- **الحذف المعلن**: `src/webpent/brain/lessons.py` (U-15 S-5 Lessons Ledger، 44 سطرًا مصغّرة) + اختباره الوحيد `tests/test_u15_lessons.py` (5 اختبارات على المفكرة نفسها) — خارج الشجر. `brain/` يكمل بستة وحدات حية (ev_scheduler/blocked_path/curiosity/adaptation/payload_selector/scorecard) بلا أي تغيير.
- **المستهلك غير الاختباري الوحيد** (`tests/lab/lcs2_sweep_instrument.py` — أداة مختبر LCS2): استيرادها الوحيد للمفكرة استُبدل بمكافئ محلي أدنى داخل الأداة (`_RetiredLedgerLesson` + `_RetiredLessonsLedger`) بنفس الدلالات حرفيًا (auto-approval لنطاق run، DECAY_RATE=0.1، أرضية influence صفر) — عقد إعادة التشغيل واختباره (`test_lcs2_sweep_instrument.py`) بلا أي تغيير سلوكي، والسبب موثق في مكانه.
- **`scripts/resurrect.py`**: شطب `webpent.brain.lessons` من `BRAIN_MODULES` (لا شيء يُستعاد — الوحدة محذوفة عمدًا)؛ الحي `webpent.memory.lessons` يبقى مثبتًا في `SPINE_MODULES` كما هو.
- **إعادة تجميد الـmanifest** (`scripts/refreeze_manifest_0290_g1_lessons_removal.py` جديد): بروتوكول حذف معلن — يتحقق fail-closed أن الملف المعلن محذوف فعلًا ومثبت في الـmanifest قبل شطب مدخله، ثم يعيد تثبيت كل مدخلات الباقي من الشجر مع self-check قبل الكتابة. النتيجة: **659 → 658 مدخلًا** (حذف واحد + bump `__init__.py` للإصدار).
- **التحقق السلبي المعلن**: صفر استيراد لـ`webpent.brain.lessons` في الشجر كلها بعد الحذف (فحص grep موثق أدناه في بوابات النافذة).
- الإصدار: pyproject/`__init__`/BUILD_INFO/CURRENT_RELEASE/Dockerfile ARG → **0.29.0**؛ `docs/learning_source_of_truth.md` و`DRIFT_REGISTER.md` وملف الخطة حدثت جميعها بحالة الإغلاق النهائي.
- **أبواب النافذة**: السويت الكامل أخضر (6752 collected = 6746 passed + 3 skipped + 3 xfail، مطابقة تمامًا: 6758 collected في 0.28.0 − 1 اختبار بوابة المجمدة المعاملترized على مدخلات الmanifest (659 → 658) − 5 اختبارات u15 المحذوفة) — الدليل `docs/FULL_SUITE_EVIDENCE_0290_CHUNKED.txt`؛ canary 7x STABLE؛ ruff ratchet (6224 ≤ 6250، والدين انخفض فعليًا بحذف الملف المتقاعد وأُجمّد البصمة)؛ بوابة المجمدة 658 مدخلًا؛ أرضية عدد الاختبارات 6752 ≥ 1940.
- **الخطة مكتملة**: C-9 ✅ C-10 ✅ D-1 ✅ D-2 ✅ G-1 ✅ — لا بنود متبقية في `docs/PRODUCTION_FIX_PLAN_0270.md`.

## 0.28.0 — 2026-10-30 (نافذة ROOTLESS DEPLOYMENT: إغلاق البند D-1 من docs/PRODUCTION_FIX_PLAN_0270.md — وضع rootless موثق + تحقق وقت التشغيل أن السقوط فعلاً حدث)

> البند D-1 كان موثقًا في خطة 0.27.0 كـ"نافذة نشر لاحقة" — هذه هي تلك
> النافذة. النمط القائم (بدء root ثم تفويض gosu لإصلاح تصادم uid الـ
> bind-mount) يبقى الافتراضي كما هو بلا أي تغيير سلوكي؛ المضاف:
> مسار rootless اختياري كامل + بوابة تحقق fail-closed على مسار root.
> لا src/ في هذه النافذة — لا إعادة تثبيت manifest (الملفات المعدلة كلها
> خارج الـmanifest المجمد: entrypoint.sh، compose، Dockerfile، docs، اختبارات).

- **تحقق السقوط fail-closed (جوهر D-1)** (`entrypoint.sh`): قبل تسليم الـexec على مسار root، يطلب الـentrypoint من gosu تشغيل `id -u` باسم الهدف ويقارن الجواب بالـuid المطلوب — فشل الprobe أو أي mismatch بين المطلوب والمُسلَّم = **رفض بدء التطبيق بـexit 1** برسالة صريحة. الحاوية لا تشغّل التطبيق بهوية غير موثقة أبدًا، حتى لو كسرت صورة أساس مستقبلية gosu بصمت. كل إقلاع يطبع سطر الدليل: `privilege drop VERIFIED (uid=..., gid=...)`.
- **وضع rootless اختياري موثق**: لو بدأت الحاوية بـuid غير صفر (توجيه `user:`)، الـentrypoint الآن يتفرع من البداية: **بدون chown وبدون gosu** — تنفيذ مباشر للأمر بهوية البدء، مع إعلان `ROOTLESS MODE` في سجل الحاوية. قبل هذه النافذة كان أي بدء غير-root **يفشل بحتم** (gosu لا يعمل إلا root) — الوضع أصبح موجودًا فعلًا لأول مرة.
  - `docker-compose.rootless.yml` جديد (override اختياري فوق ملف الإنتاج): يفرض `WEBPENT_UID`/`WEBPENT_GID` بصيغة `:?` fail-fast — لا سقوط صامت على 1000 (فخ `${UID:-1000}` المدوّن أعلى entrypoint.sh نفسه)؛ الترويسة تعلن المقايضات: لا معالجة ملكية آلية، ومسارات الـbind-mount يجب أن تكون مملوكة مسبقًا للـuid الهدف.
  - تشغيل: `export WEBPENT_UID="$(id -u)" && export WEBPENT_GID="$(id -g)"` ثم `docker compose -f docker-compose.yml -f docker-compose.rootless.yml up -d`.
- **نظافة هوية الصورة**: `Dockerfile` كان يحمل `ARG WEBPENT_VERSION=0.3.0` أحفوريًا (فئة نفس علة `__version__` التي أصلحتها 0.26.0) — أصبح متفقًا **ديناميكيًا** مع SSOT الـpyproject عبر بوابة الاختبار بدل pin حرفي.
- اختبارات (+7 في `tests/test_production_deployment_contract.py`): فرع rootless fail-closed بمصدره، تحقق السقوط بمصده وترتيبه قبل الـexec، `bash -n`، **اختبار وظيفي حقيقي لفرع rootless** (على مشغّل غير-root: الـexec مباشر بلا gosu)، اختبار وظيفي لمسار root بـgosu استُبديل (صدق = تنفيذ بعد VERIFIED؛ كذب mismatch = رفض fail-closed — يتخطى على المشغلات غير-root)، فرض الـoverride الصريح (الخدمتان + لا `:-1000`)، واتفاق نسخة الصورة مع pyproject ديناميكيًا.
- بوابات النافذة: السويت الكامل أخضر + canary 7x STABLE + ruff ratchet + بوابة المجمدة بلا لمس (لا src/). النسخة: pyproject/`__init__`/BUILD_INFO/CURRENT_RELEASE/Dockerfile ARG → **0.28.0**.
- خطة الإصلاح بعد هذه النافذة: **C-9 ✅ C-10 ✅ D-1 ✅ D-2 ✅**؛ المتبقي المعلن فقط: G-1 (حذف `brain/lessons.py` المتقاعد — نافذة إعلان منفصلة بسياسة "الحذف تغيير معلن منفصل").

## 0.27.0 — 2026-10-29 (نافذة LEARNING A/B LAB: المسار 6.5 من "بنية جاهزة" إلى حلقة تعلم أسبوعية فعلية — C-9/C-10 وفق docs/PRODUCTION_FIX_PLAN_0270.md)

> نافذة "PRODUCTION FIX 0270": red teaming موثق على 0.26.0 أخرج
> `docs/PRODUCTION_FIX_PLAN_0270.md` بأدلة file:line؛ بنوداه العلويان
> (C-9 مجدول نافذتي A/B الفعليتين + C-10 العتبات الرقمية المعلنة)
> منفذان كاملين في هذه النافذة. كل المواد إضافية/معطلة افتراضيًا —
> لا تغيير على أي نتيجة أمان أو مسار حملة قائم.

- **C-9 — مجدول نافذتي A/B الأسبوعيتين الحقيقيتين** (`src/webpent/memory/ab_lab.py` جديد — مصدر الحقيقة memory/ وفق قرار 6.1/6.2):
  - كل أسبوع ISO لكل (client_id, target_url): زوج نافذتين **حقيقيتين متتاليتين** على نفس الهدف ونفس الوضع — control بعلم التعلم مطفأ (`ENABLE_LESSON_CONSULTATION=false` على مستوى العملية) ثم treatment بالافتراضي المحكوم (مفعّل).
  - مخزن SQLite إضافي (`ab_lab.sqlite3`) بحالة أسبوع موثقة: `planned → control_done → evaluated` (أو `failed`/`metrics_missing`)؛ فتح الأسبوع idempotent بـ(week_key, client, target) و**fail-closed** بلا authorization/client/target.
  - `tick` ينفّذ **نافذة مستحقة واحدة كحد أقصى لكل نداء** (سياسة التتابع المعلنة — لا تزامن على هدف واحد)، وبدون runner يعمل **خطة جافة** صادقة (`planned_run` بلا تنفيذ). الأسبوع العالق عند حد الأسبوع ISO يكمل عبر اختيار أقدم أسبوع غير منتهٍ.
  - عقد المقاييس الصادق: runner قابل للحقن (`runner(spec) → {ok, error, metrics}`) + `metrics_lookup` لمعمارية الخدمة (`make_tracker_metrics_lookup` يقرأ من ImprovementTracker الذي تكتبه `MultiCampaignService.complete` → `persist_campaign_learning`) + `record_run_metrics` للنشر الصريح — وعند غياب الأرقام: `metrics_missing` والحكم `inconclusive` بسببه المعلن. **المختبر لا يخترع أرقامًا أبدًا.**
  - runner الإنتاج المرجعي: `make_hunt_subprocess_runner` — `webpent hunt` حقيقي كعملية منفصلة بالعلم المفرّط لكل ذراع.
- **C-10 — العتبات الرقمية المعلنة** (`AB_THRESHOLDS` مجمّدة في نفس الوحدة، منسوخة حرفيًا في ملف الخطة):
  - `min_hypotheses_tested_per_arm=10`، `promotion_reduction_ratio=0.10`، `regression_tolerance_ratio=0.20`، `require_no_confirmed_loss=True`، `max_inconclusive_weeks=4` (بعد 4 أسابيع غير حاسمة متتالية: `paused_advisory` توصية للمشغل، لا حظر آلي).
  - `evaluate_ab_pair` هي **المكان الوحيد** لحساب الحكم: دالة نقية حتمية بمفاضلة كسرية دقيقة (`Fraction`) فلا تنقلب الحدود المعلنة بسبب فواصل العائمة، ومفردات الحكم مطابقة لعقد `ABEvidence` المجمد حرفيًا (`learning_proven | inconclusive | learning_not_observed`). فقدان أي finding مؤكد في treatment يُسقط الحكم إلى `learning_not_observed` مهما كانت الكفاءة — التعلم الذي يكلف نتائج ليس تعلمًا.
- **الربط التشغيلي**: `webpent ops learning-ab open|tick|status|record-metrics` في `cli/ops.py` — open/tick/record-metrics خلف صلاحية `run_campaign` المجمدة (بلا لمس مصفوفة RBAC)، وstatus قراءة فقط؛ status يعرض العتبات المعلنة نفسها (C-10 ظاهر للمشغل).
- **بروتوكول النافذة المجمدة**: إعادة تثبيت manifest بـ`scripts/refreeze_manifest_0270_ab_lab.py` (659 مدخلًا = 658 + `memory/ab_lab.py` scope completion)؛ `cli/ops.py` إعادة تثبيت ضمن عضويته الscope-completion القائمة (نافذة `AB_LAB_20261029_*` موثقة في بوابة المجمدة).
- اختبارات: **+38** جديدة (tests/test_ab_lab.py): idempotency الأسبوع، التسلسل control→treatment، الخطة الجافة، فشل الrunner واحتواء استثناءاته، صدق المقاييس بمصادره الأربعة، إعادة التشغيل العالق، كل حد من حدود العتبات الخمسة (فوق/تحت/عند الحد)، حتمية الحكم، توافق مفردات العقد المجمد، وربط CLI بكل مساراته.
- ruff نظيف على الملفات المنشأة بالكامل. الإصدار: pyproject/`__init__`/BUILD_INFO/CURRENT_RELEASE → 0.27.0.
- **إغلاق النافذة (تشغيل بوابات 2026-10-30)** — كل بوابات بروتوكول النافذة خضراء على شجرة 0.27.0 النهائية:
  - السويت الكامل أخضر: **6747 passed / 0 failed** (+2 skipped اختياريتان +3 xfail معتمدة = 6752 مطابقة تمامًا للعد المجمّع) — الدليل `docs/FULL_SUITE_EVIDENCE_0270_CHUNKED.txt`.
  - canary 7x **STABLE** بـ`ruff_clean=true` وخروج 0: `reports/canary/CANARY_7X_20261030_0.27.0.json`.
  - بوابة المجمدة خضراء (659 مدخلًا يطابق الشجرة) + عتبة عد الاختبارات 6752 ≥ 1940 + ruff ratchet 6248 ≤ 6250.
- **إصلاحان صغيران خارج src/ (بوابة canary نفسها — ملفات غير مجمّدة)**:
  - `scripts/canary_7x_20261028.py`: خطوة ruff داخل الcanary كانت فحصًا خامًا بلا baseline يعيد إظهار ديون ruff المعتمدة أصلاً في الratchet، فسجّلت كل أدلة النوافذ السابقة `ruff_clean=false` رغم أن البوابة القانونية (ratchet 0.26.0) خضراء — صار الcanary يستدعي `scripts/check_ruff_ratchet.py` نفسها (بوابة CI المعلنة) بدل فحص مكرر غير معاير. وكذلك اسم ملف الدليل صار ديناميكيًا بالتاريخ والإصدار (`CANARY_7X_<date>_<version>.*`) بعد أن كان الاسم الثابت القديم يكتب فوق دليل 0.24.0 التاريخي في كل نافذة لاحقة.
  - README: تحذير D-2 معلن (`credentials_template.json` قالب قراءة فقط — لا يُملأ ولا يُنسخ؛ الأسرار الحقيقية عبر `.env` 0600 و`WEBPENT_USERS`) — أول بنود التوثيق المؤجلة التي تُغلق مبكرًا.
- بنود النافذة المعلنة كما هي: D-1 (وضع rootless + تحقق entrypoint) في نافذة نشر لاحقة، G-1 (حذف `brain/lessons.py` المتقاعد) في نافذة إعلان منفصلة وفق سياسة الحذف المعلن.

## 0.26.0 — 2026-10-29 (إغلاق الفجوات المتبقية من الخارطة الموحدة: بوابات CI حاجبة، doctor موحد، مخرجات أوضح، تعلم موصول، تغطية إضافية، وإغلاق الجذر)

> نافذة "RESIDUAL CLOSURE 2026-10-29": تدقيق مستقل لكل مسارات
> `docs/WEBPENT_UNIFIED_MASTER_ROADMAP.md` ضد الشجرة (0.25.0) حدد
> الفجوات المتبقية؛ هذه النافذة أغلقتها. المواد الجديدة كلها
> إضافية/معطلة افتراضيًا ما لم تُذكر عكس ذلك.

- **بوابات CI صارت حاجبة (المسار 1 + 2.4)** — خطتا "report only" (`ruff check . || true` و`pip-audit || true`) رُقّيتا وفق ما خطط له ترويسة ci.yml نفسه:
  - **ruff ratchet** (`scripts/check_ruff_ratchet.py` + `scripts/quality/ruff_baseline.json`): يمنع زيادة الملاحظات (baseline مجمّد = 6289 بعد إغلاق الجذر، كان 7278 قبلها — التحسّن مُجمّد)؛ الخفض يُجمَّد بـ `--update-baseline --reason`.
  - **بوابة اعتماديات CVE** (`scripts/check_deps_gate.py` + `scripts/quality/cve_allowlist.json`): pip-audit حاجب مع allowlist مدقّق فارغة البذرة — عائلة langgraph 1.x الحالية نظيفة (0 ثغرات في `docs/pip_audit_release.json`)، وأي CVE جديد يفشل البناء.
  - **فحص أسرار** (`scripts/check_secrets.py`): مسح حتمي بلا اعتماديات (أنماط AWS/GitHub/Slack/Discord/مفاتيح خاصة/إسنادات عامة)؛ **لا يطبع القيم أبدًا** (بصمة sha256 فقط)؛ allowlist بمستوى (ملف، قاعدة، بصمة القيمة) — أي قيمة جديدة في نفس الملف تُكتشف؛ القيم المزيفة الموثقة (fixtures) تُتخطى بمنطق sentinel.
  - **SAST**: بوابة bandit عالية الخطورة (نفس أمر Makefile) أصبحت خطوة CI إلزامية.
  - **SBOM**: توليد CycloneDX من القفل في كل تشغيل CI + رفع artifact.
  - **تغطية**: أرضية مجمّدة `scripts/quality/coverage_baseline.json` (72%؛ المقاس الفعلي 72.7% على 6698 اختبار) مفروضة داخل `scripts/run_tests_with_evidence.py` (--cov-fail-under) — تشغيل واحد ينتج evidence + coverage.
  - **canary ليلي**: `.github/workflows/nightly.yml` بجدول cron يومي 02:00 UTC + تشغيل يدوي، يشغّل `scripts/canary_7x_20261028.py` ويرفع الأدلة.
- **`webpent doctor` أمر واحد حقيقي (المساران 8.4 و3.6)** (`src/webpent/cli/doctor.py` جديد): قاعدة البيانات (فتح عبر المدير القياسي + عدّ) + مزود النموذج (فحص التهيئة عبر `shared.preflight._check_llm_providers` نفسها، وprobe اختياري عبر مسار builders الحقيقي) + الأدوات الخارجية (nuclei/subfinder/httpx-pd/katana/dalfox/sqlmap) + حزمة المعرفة + Playwright — يعرض النواقص بوضوح ويخرج 0/1/2. أصلحت 4 مراجع معلقة لأمرٍ لم يكن موجودًا (README ×2، `install.sh`، banner الـquickstart في docker-compose).
- **إصلاح `install.sh`**: استدعاء `webpent llm-keys add` كان بتوقيع خاطئ لا يمكن أن ينجح (`add "$PROVIDER" <<< "$KEY"`) — صار يكتب المفتاح في `.env` غير المتتبَّع (0600) ويسجّل مرجع متغير البيئة بالتوقيع الصحيح `add PROVIDER MODEL --env-var ENV` (الموديل = نفس slug سلسلة FAST في `shared/llm.py` — لا اختراع slug).
- **هوية الإصدار (المسار 0.4)**: `src/webpent/__init__.py.__version__` كان عالقًا على "0.14.0" عبر أحد عشر ترقية pyproject — صار "0.26.0" مع قاعدة SSOT موثقة؛ `BUILD_INFO.json` و`docs/CURRENT_RELEASE.md` تمت مواءمتهما (0.3.0 وv15.2 كانا هويتين متضاربتين)؛ بوابة `test_release_packaging` صارت تتحقق من الاتفاق ديناميكيًا بدل pin أحفوري.
- **مخرجات أوضح (المسار 9)**:
  - سطر التقدم الحي + ملخص نهاية hunt أضافا **الوقت المنقضي المقاس** والسقوف المعلنة (زمن/تكلفة LLM)؛ العدّادات (llm calls/tokens) حقيقية من `get_llm_usage_trace` — **لا أرقام دولار مخترعة** (التسعير `unpriced` بحكم التصميم).
  - ملخص تنفيذي HTML: بلوك metadata تشغيل (calls/tokens/pricing) + **human_review_decision** صار يُعرض في التقرير والقوالب (`_finding_to_dict` + `report.html.j2`).
  - **قوالب منصات تقارير المكافآت (9.4/11.6)**: `BountyReport.to_hackerone_markdown()` و`to_bugcrowd_markdown()` (P1..P5 بتحويل CVSS موثق) عبر `webpent reports --platform hackerone|bugcrowd|neutral` — نفس المحتوى المروج بالبوابات، تخطيط حقلول مختلف.
- **حلقة التعلم (المسار 6)**:
  - قرار مصدر الحقيقة موثق (`docs/learning_source_of_truth.md`): `memory/` هو مصدر الحقيقة، `brain/lessons.py` نظام متوازٍ ميت يُستهلك باختباره فقط (تقاعد من العقد، إزالته نافذة لاحقة)؛ **إعفاء `hunt-auto` الموثق** (alias متقادم، لا يُمدّد).
  - **المعاير موصول بالكتابة والقراءة (12.8)**: `ops review decide --calibration-store` يسجل قرار المحلل في مخزن المعايرة (تجميعات فقط، fail-open — كتابة التعلم لا تكسر مراجعة قط)؛ `ops calibration --candidates JSON` أصبح مستهلكًا فعليًا لـ`calibrated_order` (إعادة ترتيب فقط، الثقة الخام لا تُعدَّل).
- **تغطية إضافية (المسارات 10.6/10.7/11.4)**:
  - **EPSS** (`src/webpent/shared/epss.py`): كتالوج مُحقن (بلا شبكة، نفس عقد KEV) + إثراء `CveCorrelation.epss` + مفتاح فرز KEV→EPSS→confidence (بلا EPSS = الترتيب القديم حرفيًا) + `epss_catalog_path` في الإعدادات.
  - **مؤشرات تطبيقات الجوال (10.7)** (`src/webpent/shared/mobile_app_indicators.py`): فحص APK/IPA كـZIP فقط (لا dex/AXML parsing، لا تنفيذ، لا شبكة)؛ تصنيف كل مؤشر in_scope/out_of_scope ضد الأصول المصرح بها (خارج النطاق يُعدّ ولا يُحمل)؛ الأسرار بصِم أحمر فقط.
- **VIP (المسار 11)**:
  - **الفرز البصري (11.2 — كان غائبًا كليًا)** (`src/webpent/vip/asset_triage.py`): مخزن معاينات لكل عميل (hashed dir، ملفات 0600، فهرس بصِمات فقط)؛ **بوابة ScopeEnforcer قبل أي بايت** (محجوب = صفر التقاط)؛ التقاط محقون (capturer callable — الوحدة لا تشغّل متصفحًا بذاتها)؛ **الاحتياز dry-run افتراضيًا** (retention_plan) والحذف `purge` صريح — عقد 0.23.0.
  - **جسر إشعارات مراقبة الأصول (11.1)**: `ConfirmationNotifier.notify_operational_alert` (نفس القنوات/الطابور/العتبة/التعطيل الافتراضي) + `autonomous/cem/notification_bridge.py` — تغيّرات CEM critical/signal-high تصل قناة المشغل (بإعادة تنبيه منعًا بالبصمة، كل نص عبر `redact`)؛ noise يبقى في الdigest.
- **تحصين تشغيلي (المسار 3)**:
  - **`WEBPENT_LOG_FORMAT=json` صار حقيقيًا** (3.5): `JsonLogFormatter` في `shared/console.py` (سطر JSON لكل حدث: ts/level/logger/message) — كان إعدادًا ميتًا في docker-compose منذ التحصين.
  - **تنبيه العمال العالقين مجدول (9.5 residual)**: حلقة خلفية اختيارية في `api/app.py` (`WEBPENT_WORKER_ALERT_INTERVAL_S`، افتراضي 0 = معطل) تستدعي `check_stalled_and_alert` دوريًا — كانت دالة بلا مجدول.
  - **دليل تشغيل العمال (3.4)**: `docs/workers_ops_runbook.md` — التشغيل، الصفوف، التزامن، تقسيم الميزانية، التعامل مع تعطل العامل، وحدود NOT-QUALIFIED المتبقية بنصها.
- **إغلاق الجذر (المساران 0.1 و7.2/7.4)**: **78 ملفًا تاريخيًا** (تقارير/أدلة/نتائج FABRIC_* وTEAM1_* وEVIDENCE_* وغيرها) نُقلت إلى `docs/archive/2026-10-28-root-artifacts/` بفهرس provenance، ومجلدات `goed_v1_8*` التسعة (9,515 سطرًا) إلى `docs/archive/2026-10-28-goed-v1.8-root-dirs/` — كل نقل بعد فحص مراجع (الملفات المحجوزة بمرجع نشط بقيت: 11 ملفًا موثقة في الفهرس)؛ `CHANGELOG.md` هو سجل الإصدار الوحيد النشط. **الخارطة الموحدة أُدرجت داخل المستودع**: `docs/WEBPENT_UNIFIED_MASTER_ROADMAP.md` + رابط README.
- **بوابة المجمدة (نافذة RESIDUAL CLOSURE 2026-10-29)**: إعادة تثبيت manifest بـ`scripts/refreeze_manifest_0260_residual_closure.py` (658 مدخلًا = 653 + **5 ملفات جديدة** scope-completion: `cli/doctor.py`، `shared/epss.py`، `shared/mobile_app_indicators.py`، `vip/asset_triage.py`، `autonomous/cem/notification_bridge.py`)؛ مجموعتا النافذة موثقتان في بوابة الاختبار (`RESIDUAL_CLOSURE_20261029_THAW_PATHS` = settings.py/commands.py/console.py/export.py/bounty_report.py/app.py/__init__.py + `RESIDUAL_CLOSURE_20261029_SCOPE_COMPLETION_PATHS`)؛ cli/unified_hunt.py وgraph/progress_display.py وcli/ops.py ضمن pins موثقة سلفًا.
- **إصلاحات أحفورة في الاختبارات (كلها كانت فاشلة سلفًا في 0.25.0 وليست من هذه النافذة)**: `test_release_packaging` (pins 0.14.0/التاريخ الأحفوري → عقد ديناميكي)، `test_vip_parallel_recon` (55/57 → 56/58 — عقدة dedup_gate من مسار 11.5 هبطت بعد كتابة الpin، موثقة)، `test_r3_e1_advisory` (اسم الحقل في vocabulary الadapter ليس مستهلكًا دلاليًا — مُدرج في allowed_files مع بقاء الفحص الدلالي).
- **الاختبارات:** +63 جديدة (doctor CLI ×8، ربط المعايرة ×7، الوحدات الجديدة ×20، وكلاء النافذة عبر مجموعات قائمة). **الجودة (نهائي):** السوت الكامل بالأدلة 6708 أخضر / 0 فاشل (6710 مع skip/xfail) مع تغطية 72.72% فوق الأرضية 72%؛ بوابة المجمدة 660 أخضر؛ canary 7x **STABLE** (854×8، `reports/canary/CANARY_7X_20261029_0.26.0.json`)؛ ruff ratchet مجمّد عند 6250؛ عدد الاختبارات فوق الأرضية (6713 >= 1940).


## 0.25.0 — 2026-10-28 (الخطوة التالية من 0.24.0: توصيل WorkerCoordinator بـ MultiCampaignService + أوامر كتابة محدودة خلف RBAC)

- **البند 12.3 تشغيليًا — ادعاءات العمال على مستوى الحملة (`src/webpent/production/campaign_worker_claims.py` جديد + ربط في `service/facade.py`):**
  إغلاق فجوة "الوحدة منفذة لكن غير موصولة بخدمة الحملات" (نمط دمج 0.18.0: إضافي، معطل افتراضيًا):
  - `CampaignWorkerClaims`: محوّل دورة حياة — الحملة RUNNING تحتفظ بادعاء تنسيق طوال عمرها؛ عاملان يتشاركان `coord_dir` لا يستطيعان تشغيل نفس الحملة معًا حتى مع محددات تزامن منفصلة لكل عملية.
  - إسقاط النتائج: ACQUIRED/RENEWED/TAKEOVER = محتفظ؛ BUSY = رفض fail-closed بعلة واضحة (عامل حي آخر يحتفظ)؛ SCOPE_CONFLICT = رفض fail-closed (لا يُستولى أبدًا)؛ DENIED_ERROR = فشل مفتوح مع تسجيل (الحارس مورد وليس حدودًا أمنية — النطاق/التفويض مستقلان سلفًا).
  - الربط في الواجهة: ادعاء بعد تذكرة الـ governor في `start()` (رفض الادعاء يحرر التذكرة ويكرّر السبب)؛ تحرير مضمون في `halt()`/`complete()`/مسار فشل `start()`؛ الافتراضي المعطل = سلوك مطابق حرفيًا لما قبل 0.25.0 (اختبار يؤكد عدم إنشاء مجلد التنسيق).
  - الإعدادات: `worker_coordination_enabled` (false افتراضيًا) + `worker_coordination_dir` — نمط backend الاختياري نفسه (`governor_cross_process`)؛ فشل البناء → None → تشغيل بلا تنسيق.
- **أوامر كتابة محدودة خلف RBAC (`ops.py` + `production/ops_state.py` جديد):** متابعة "أوامر الكتابة خلف RBAC عند طلب المشغل" من عمل 0.24.0:
  - `ops users bootstrap-admin|grant` — سجل هويات محلي (دور + عضويات عملاء)؛ admin فقط؛ التمهيد متاح فقط والسجل فارغ؛ الدور يُقرأ من الحالة أبدًا لا من وسيط المستخدم.
  - `ops review enqueue|claim|decide|pending` — طابور المراجعة عبر محرك 0.23.0 حرفيًا: TRIAGE_FINDINGS + عضوية مساحة العمل يفرضهما المحرك نفسه؛ توليد item id تلقائي عند الإغفال؛ قاعدة "موافقات N محللين مختلفين" و"صوت واحد لكل محلل" تعملان عبر إعادة التشغيل.
  - `ops portfolio register|admit|spend|status` — اقتصاديات المحفظة والصرف تحت الموازنة الموحدة (lead/admin؛ الكابس fail-closed؛ كل قرار يُسجل تدقيقيًا).
  - حالة دائمة: ملف JSON واحد (`--state`، أذونات 0600، كتابة ذرية) + سجل تدقيق JSONL إلحاقي بجانبه؛ إعادة البناء عبر واجهات عامة فقط (grant/enqueue/claim/submit_decision/register_program/record_spend) — قواعد المحرك يُعاد فرضها أثناء الاسترجاع فلا يمكن لحالة مزورة تصنيع موافقات؛ حالة تتجاوز الكابس المسجلة تُرفض fail-closed.
  - المصفوفة المجمدة في `enterprise_operations.py` لم تُمَس: اقتصاديات المحفظة قدرة lead/admin مفروضة في طبقة المحوّل (`PORTFOLIO_WRITE_ROLES`) موثقة كامتداد للطبقة، لا تعديلًا في مفردات المؤسسة.
- **بوابة المجمدة (نافذة OPS WRITE + WORKER CLAIMS 2026-10-28):** إعادة تثبيت manifest (653 مدخلًا = 651 + الملفان الجديدان scope-completion) وفق DR-009 (نفس المسارات والترتيب؛ `scripts/refreeze_manifest_0250_ops_write.py`)؛ وأُدرج الـ manifest في git صراحةً لأول مرة (استثناء `!frozen_modules.sha256` في .gitignore — القاعدة `*.sha256` كانت تبتلعه فضاع بين الجلسات مرتين واستُرجع من حزمة 0.24.0)؛ التوثيق في اختبار البوابة (`OPS_WRITE_20261028_SCOPE_COMPLETION_PATHS`)؛ settings.py/facade.py ضمن مجموعات thaw الموثقة سلفًا؛ ops.py يبقى تثبيت CLI_OPS scope-completion (غائب عن الـbaseline بالبناء).
- **إصلاح كامن (نظافة اختبارات من نافذة 0.18.0):** محدد التزامن عملية-عالمية كان يتسرب بين الاختبارات — حملة RUNNING من اختبار كانت تلتهم slots اختبار تالٍ (`test_multi_campaign_service` كان يفشل منفردًا منذ 0.18.0 ولم تلتقطه مجموعة الـcanary لعدم تضمينه). إصلاح بـ autouse fixture (`_reset_concurrency_governor_singleton` في conftest) عبر `reset_concurrency_governor()` — لا إضعاف للفحص داخل الاختبار الواحد.
- **نظافة ruff على نطاق النافذة:** كل الملفات الجديدة والمعدلة نظيفة تمامًا (شمل ذلك ديونًا سابقة داخل الملفات نفسها: E501/B008/I001/UP035 في ops.py وfacade.py كانت مررت سلفًا)؛ `B008` مستثنى لـ cli/ops.py فقط عبر `per-file-ignores` موثق (نمط Typer التصريحي مقصود — commands.py يتجنبه بأسلوب Annotated).
- **الاختبارات:** +53 (محوّل الادعاءات والمصنع الافتراضي + ربط الواجهة عبر-العمال + أذونات RBAC وحالات fail-closed + تدفق CLI الكامل بكل مساراته). **الجودة:** بوابة المجمدة 655 أخضر؛ مجموعة الانحدار مع الجديد 900 أخضر؛ **canary 7x: STABLE (849 × 8، توقيع الدخان متطابق)**.

## 0.24.0 — 2026-10-28 (DoD: canary مختبري 7x مستقر + ربط Track 12 بواجهة CLI عبر نافذة الأوامر المجمدة وبروتوكولها)

- **Canary مختبري 7x وفق Definition of Done (`scripts/canary_7x_20261028.py`):**
  "canary مختبري مستقر لسبعة تشغيلات متتالية على الأقل، مع مقارنة
  baseline" — منفذ حرفيًا بأدلة:
  - كل تشغيل = مجموعة الانحدار الكاملة (14 ملف اختبار، 847 اختبارًا:
    بوابة المجمدة + كل وحدات المسارين 11/12 + VIP) + **دخان مختبري
    وظيفي** في-العملية بلا شبكة: المحرك → تنسيق العمال (claim/dedup/
    عزل عميل) → الخطة والموافقة بdigest → المحفظة (ترتيب/قبول/رفض) →
    OOB (بوابة/رمز/ائتمان/رفض نطاق) → المعايرة (إعادة ترتيب/حياد
    بارد).
  - **معيار الاستقرار:** كل تشغيل أخضر بنفس عدد الاختبارات وتوقيع
    البايتات نفسه للدخان مقارنة بالـbaseline — **النتيجة: STABLE 7/7
    متطابقة** + ruff نظيف. عللتان أصلحتا أثناء بناء الدخان (ترتيب خطوة
    سقف المحفظة، مقارنات enum).
  - الأدلة: `reports/canary/CANARY_7X_20261028_0.24.0.{json,md}`.
- **ربط Track 12 بـCLI عبر نافذة الأوامر المجمدة وبروتوكولها
  (`src/webpent/cli/ops.py` جديد + دلتا سطرين في `commands.py`):**
  - النمط المعتمد (نافذة retest): ملف Typer sub-app **جديد** + سطرا
    ربط فقط في الملف المجمد — `webpent ops` **قراءة فقط** بلا أي تغيير
    في سلوك الحملات:
    - `ops governor`: لقطة محدد التزامن (+ عرض العقود عبر-العمليات عند
      تفعيلها) — جدول أو `--json`.
    - `ops workers --coord-dir`: لقطة التنسيق + ذيل سجل التغييرات.
    - `ops graph --out FILE --format html|json|dot`: تصدير جراف
      العلاقات (redaction-first) من قاعدة البيانات المحلية.
    - `ops calibration --client --store-dir`: مضاعفات الفئات وعدادات
      القرارات البشرية (تجميعات فقط).
    - `ops protection`: وضعية ضوابط الحماية + قائمة الرفض كاملة.
  - البروتوكول: إعادة تثبيت `frozen_modules.sha256` (651 مدخلًا) +
    تثبيت الملف الجديد `cli/ops.py` وفق نمط scope-completion الموثق
    (`CLI_OPS_20261028_SCOPE_COMPLETION_PATHS` في بوابة المجمدة) —
    دلتا commands.py داخل مجموعة thaw الموثقة سلفًا.
- **الاختبارات:** +15 (كل أمر CLI: جدول/json/أخطاء موقعة exit=2،
  تصدير الجراف بصيغه الثلاثة، تسجيل التسجيل في الاختبارات، تسجيل
  ops مرة واحدة بالضبط). **الجودة:** ruff نظيف على الجديد كله؛
  بوابة المجمدة 653 أخضر.

## 0.23.0 — 2026-10-28 (المسار 12 مكتمل: بند 9 التشغيل المؤسسي — RBAC، طابور مراجعة، SSO seam، عزل مساحات، احتفاظ وتصدير)

- **البند 9 — تشغيل مؤسسي (`src/webpent/production/enterprise_operations.py`):**
  إغلاق آخر بند في خارطة الطريق الموحدة، من بدائليات fail-closed صغيرة:
  - **RBAC مصفوفة مجمّدة:** أدوار (viewer/analyst/lead/admin) × صلاحيات
    بأقل امتياز؛ `authorize` يرفض أي دور أو صلاحية مجهولة (fail-closed)،
    ولا تعديل للمنح في زمن التشغيل.
  - **SSO seam موثق لا عميل SSO:** `SsoIdentity` يربط subject مُتحقق منه
    (من مُحوّل IdP الخاص بالمشغّل) إلى دور محلي عبر قواعد مراجَعة؛
    الهوية غير المربوطة تسقط إلى viewer — لا طريق صامت إلى admin، ولا
    اتصال شبكي من هذه الوحدة.
  - **عزل مساحات العمل:** كل عملية تتطلب عضوية صريحة (مُنحت) في مساحة
    العميل — الغريب يُرفض fail-closed.
  - **طابور مراجعة متعدد المحللين:** enqueue → claim → قرار مُنسب؛
    قاعدة "موافقات N محللين مختلفين" قبل أهلية الترشيح للتقرير
    (`nominatable`)، تصويت واحد لكل محلل، رفض خارج-مساحة الادعاء
    والقرار، ترتيب انتظار حتمي.
  - **سياسات احتفاظ:** فئات بيانات (أدلة خام/نتائج/سجلات تدقيق) بأيام
    لكل فئة؛ `apply_retention` **dry-run افتراضيًا** ويُرجع المستحق
    للحذف — الحذف الفعلي بيد المستدعي (خطأ سياسة لا يمسح شيئًا بنفسه)،
    والفئة المجهولة تفشل مغلقة.
  - **تصدير تدقيق:** حزمة JSONL لعميل واحد فقط (حاجز العزل مرة أخرى)،
    معرفات فقط، وحدث التصدير نفسه يُسجل في الدفتر.
- **الاختبارات:** +17 (المصفوفة المجمدة، fail-closed للقيم المجهولة،
  SSO المحايد الآمن، العزل المتبادل، قاعدة محللَين، منع التصويت
  المزدوج، dry-run افتراضي، عزل التصدير). **الجودة:** ruff نظيف.

## 0.22.0 — 2026-10-28 (المسار 12: بند 5 منطق الأعمال + بند 7 تحقق OOB مضبوط)

- **البند 5 — نمذجة منطق الأعمال (`src/webpent/production/business_logic_workflows.py`):**
  "نمذجة تدفقات عمل متعددة الخطوات في بيئات اختبار أو ضمن تفويض صريح،
  بحدود تشغيل محافظة ومراجعة بشرية" — حرفيًا:
  - نموذج تصريحي (خطوات معرفية بلا حمولات) مرتبط بعميل واحد + scope
    hash واحد، وبيئة `lab` (افتراضي) أو `authorized` بمرجع تفويض إلزامي.
  - **حدود محافظة مفروضة لا نصيحة:** سقف 12 خطوة، تنفيذ متسلسل (لا توازي
    لتدفق الأعمال)، قائمة أنواع أفعال ممنوعة ثابتة (دفع، حذف، تعديل
    دائم، بريد/SMS صادر، إعادة تعيين كلمات مرور، منح صلاحيات...)، وكل
    الخطوات داخل ربط النطاق نفسه — لا خلط.
  - **المراجعة البشرية بالبناء:** `plan_execution` يُنتج حزمة مراجعة
    (خطة + مخالفات + قائمة تحقق) ولا ينفذ شيئًا؛ الموافقة مرتبطة
    بـ**digest الخطة** — أي تعديل لاحق يبطلها ويستلزم موافقة جديدة؛
    بوابة `execution_allowed_for` هي المرجع الوحيد قبل أي تسليم تنفيذ.
- **البند 7 — تحقق OOB (`src/webpent/production/oob_verification.py`):**
  "أي خدمة callbacks لإثبات حالات عمياء لا تُتاح إلا في بيئة يسيطر عليها
  المستخدم، وبموافقة صريحة ونطاق محدود، مع منع استخدامها ضد أطراف غير
  مخولة" — حرفيًا:
  - **بوابة تفعيل صلبة:** `enabled` يتطلب endpoint يسيطر عليه المستخدم +
    موافقة صريحة + ربط نطاق — لا endpoint افتراضي في الوحدة إطلاقًا ولا
    خدمات OOB طرف ثالث؛ كل شيء معطل افتراضيًا.
  - رموز تفاعل حتمية بلا مفاتيح (هضم معرفات فقط، مرتبطة بـscope hash —
    لا تُنقل بين النطاقات) لربط callback وارد بمحاولة finding واحدة.
  - **ائتمان محدود بالنطاق:** callback وارد يُقيَّد فقط لرمز معروف وهدف
    داخل الأصول المصرح بها؛ خارج النطاق أو رمز مجهول → رفض + تسجيل
    (لا يمكن أن يبارك OOB إصابة خارج النطاق أبدًا). دفتر تفاعلات JSONL
    بمعرفات فقط (IP مجهّل) في نطاق hash خاص بالعميل.
- **الاختبارات:** +19 (الحدود المحافظة وأمثلة الأفعال الممنوعة، إبطال
  الموافقة عند تغيير الخطة، بوابة التفعيل بكل أسبابها، النطاق والرموز
  المزورة، الدفتر). **الجودة:** ruff نظيف.

## 0.21.0 — 2026-10-28 (المسار 12: بند 1 إدارة محفظة البرامج + بند 8 التعلم المعاير)

- **البند 1 — إدارة محفظة البرامج (`src/webpent/production/portfolio_manager.py`):**
  "ترتيب الأعمال وفق قيمة متوقعة وموازنة موحدة، مع حدود لكل حملة ولكل
  عميل" — حرفيًا:
  - ترتيب بـ**القيمة المتوقعة** EV = المكافأة × احتمال النجاح − التكلفة
    (تقديرات المشغّل)، حتمي ومستقر التعادل (EV نازل ثم الاسم صاعدًا).
  - **موازنة موحدة** بثلاث حدود: إجمالي، لكل عميل، لكل حملة — القبول
    fail-closed عند أي تجاوز برسالة صريحة، و`record_spend` يرفض هو الآخر
    أي مبلغ يكسر حداً (لا يُسجّل شيئًا) — المال مورد صلب.
  - سجل مصاريف وتقارير معرفات فقط (لا بيانات نتائج)، + سجل تدقيق JSONL
    اختياري لا يرفع أبدًا. طبقة اقتصادية فوق النطاق/التفويض — ليست بديلًا.
- **البند 8 — تعلم معاير (`src/webpent/production/confidence_calibration.py`):**
  "استخدام قرارات القبول والرفض البشرية في تحسين ترتيب الثقة، مع فصل
  بيانات العملاء ومنع الاعتماد على بيانات خام" — حرفيًا:
  - **تجميعات فقط — لا بيانات خام:** سجل التغذية الراجعة يحمل (عميل،
    فئة، قرار، فئة خطورة، نطاق ثقة) — لا عنوان ولا URL ولا payload
    (الحقول غير موجودة في النوع نفسه)، وسعة محدودة 500 سجل/فئة.
  - **فصل العملاء بالبناء:** مساحة تخزين لكل عميل (hash)؛ المضاعِف
    لا يقرأ بيانات عميل آخر أبدًا — المشترك الوحيد ثابت محايد.
  - **تعديل محدود مُنعّم:** تسوية Laplace + مزج 50/50 مع أولوية محايدة،
    مضاعِف مقيد [0.5, 2.0]، الفئة الباردة = 1.0 تمامًا؛ الثقة الخام لا
    تُعدَّل — **الترتيب فقط** هو الناتج، حتمي بتعادل مستقر بالمعرف.
- **الاختبارات:** +24 (ترتيب EV، الحدود الثلاثة والرفض fail-closed
  في القبول والتسجيل، عزل العملاء متبادلًا وثالث محايد، التنعيم يمنع
  تقلبات التاريخ الصغير، الحد الأقصى للمخزن، التلف يتحلل لبارد، سجل
  التدقيق). **الجودة:** ruff نظيف.

## 0.20.0 — 2026-10-28 (المسار 12: بند 4 رسم علاقات النتائج + بند 6 سياسة ضوابط الحماية)

- **البند 4 — رسم علاقات النتائج (`src/webpent/production/finding_relation_graph.py`):**
  "عرض روابط الأدلة والأصول والأثر التجاري في graph تفاعلي، دون تحويله
  إلى تعليمات استغلال آلية" — حرفيًا:
  - `build_finding_graph`: مُركّب حتمي (نفس المدخلات = نفس البايتات) يبني
    عقد `asset` (origin مُطبَّع) / `finding` (فئة+خطورة+معرف) /
    `evidence` (**الـhash فقط — الـpayload لا يدخل الجراف أبدًا**) /
    `impact` (وسم الأثر التجاري عند وجوده)، وحواف `targets`/`evidences`/
    `impacts`/`related_to` (علاقات يعلّنها المراجع فقط — لا استنتاج).
  - حاجز الاستغلال بالبناء: لا حقل في النموذج يمكنه حمل حمولة هجومية،
    والمُصدّرات تُسلسل النموذج نفسه فقط.
  - `render_html`: ملف HTML واحد مكتفٍ ذاتيًا (SVG + JS فانيلا، سحب/pan،
    نقر يُبرز جوار العقدة، ألوان حسب الخطورة) **بلا أي اعتماد شبكي** —
    آمن offline. إصلاح أمني أثناء التطوير: الـJSON المضمن في `<script>`
    كان يحمل النص الخام (خطر كسر `</script>`) — أُمّن التضمين بـ
    `\u003c/\u003e/\u0026` + escaping لعناوين SVG.
  - مُصدّرات: `graph_to_json` (مستقر ومفروض المفاتيح) و`graph_to_dot`
    (Graphviz) للوحات المؤسساتية.
- **البند 6 — سياسة ضوابط الحماية (`src/webpent/production/protection_controls.py`):**
  "عند رصد حظر أو تحديد معدل، يوقف النظام المحاولة أو يطلب مراجعة؛ لا
  تُبنى ميزة للتهرب أو تجاوز الضوابط" — حرفيًا:
  - كشف حتمي بلا أثر جانبي: `waf_block` (403/406/418 + مؤشرات WAF أو
    `cf-mitigated: block`)، `rate_limit` (429/Retry-After أو لغة حصة)،
    `challenge` (صفحات تداخل)، `backend_throttle` (502/503).
  - السياسة: حظر/تحدٍّ → **توقف + طلب مراجعة بشرية**؛ 429 → تراجع مؤدب
    يحترم Retry-After (بحد أقصى 900s، وتجاوزه يصعد للمراجعة)؛ تكرار
    الحدود → تصعيد للمراجعة لا تسريع؛ **لا مفتاح تهرب في الواجهة إطلاقًا** —
    قائمة الرفض (`FORBIDDEN_EVASIONS`: تدوير IP/بصمة، حل كابتشا، تمويه
    رؤوس، إعادة توزيع لتجاوز الحد...) مثبتة في مكان واحد.
  - تدقيق: `append_protection_log` JSONL ملحق-فقط لكل قرار (لقطات مُحجبة).
- **الاختبارات:** +29 (حتمية الجراف، إثبات عدم دخول الـpayload، escaping
  شامل للـHTML والـscript-context، دمج الأصول المشتركة، تصنيف الإشارات،
  قرارات السياسة والتصعيد، قائمة الرفض، سجل التدقيق). **الجودة:** ruff
  نظيف؛ اختبارات الوحدات المجمدة خضراء.

## 0.19.0 — 2026-10-28 (المسار 12: بند 2 طور 2 العقود عبر-العمليات + بند 3 تنسيق عدة عمال)

- **البند 2 طور 2 — عقود ملكية عبر-العمليات (`src/webpent/production/cross_process_leases.py`):**
  الوعد الموثق في 0.18.0 تحقق: محدد التزامن يصبح مشتركًا فعليًا بين عدة
  عمليات عمال (CLI + خادم API + عمال Celery) **خلف نفس الواجهة**.
  - `FileLeaseBackend`: مُقرض سلوتس ذري على مجلد تشغيل محلي، كل سلوت ملف
    صغير محروس بـ`fcntl.flock`: الحجز = فتح + flock حصري غير حاجب + كتابة
    metadata (الحملة/الهدف/PID/الوقت)؛ التحرير = تصفير وإغلاق (النواة
    تُسقط القفل).
  - **أمان الانهيار موروث من النواة:** موت العملية يُحرر flocks فورًا — لا
    لا توجد حالة "عقد يتيم" تحتاج تنظيفًا إطلاقًا؛ أول حاجز تالٍ يفوز بالملف.
  - **All-or-nothing:** سلوت هدف ثم سلوت عام بترتيب ثابت (لا deadlock
    عابر للحملات)؛ فشل أيٌّ يُرجع كل ما أُخذ.
  - الدمج: `ConcurrencyGovernor(lease_backend=...)` — القبول يتطلب السقوف
    المحلية **و**سلوتًا مشتركًا؛ `release` يحرر العقود أولًا؛
    `_promote_waiters` يحترم العقود قبل الترقية؛ النادل المحجوب **بالعقود
    فقط** يعيد الاقتراع كل 0.25s (موقعه في رأس طابور FIFO محفوظ — لا
    تجويع)؛ أخطاء الـbackend تفشل مفتوحة (عقد مورد لا حدود أمنية).
  - تفعيل اختياري: `WEBPENT_GOVERNOR_CROSS_PROCESS=true` +
    `WEBPENT_GOVERNOR_LEASE_DIR` (افتراضي آمن تحت temp) — معطل افتراضيًا.
- **البند 3 — تنسيق عدة عمال (`src/webpent/production/worker_coordination.py`):**
  "مشاركة حالة ونتائج منقحة ومنع التكرار ضمن حدود العميل والنطاق مع سجل
  واضح للتغييرات" — حرفيًا:
  - سجل مطالبات عمل ذري (flock): أول عامل يفوز بوحدة العمل؛ تجديد لنفس
    العامل؛ **TAKEOVER** بعد انتهاء TTL (عامل ميت لا يحجب العمل للأبد)؛
    **SCOPE_CONFLICT**: وحدة محجوزة تحت hash نطاق مختلف لا تُستولى أبدًا —
    التنسيق لا يصبح قناة لتوسيع الاستهداف.
  - سجل بصمات نتائج عبر-العمال بـ`O_CREAT|O_EXCL` (أول من يسجل يُبلّغ،
    البقية DUPLICATE) — الوجه متعدد العمليات لبوابة منع التكرار (بند 11.5).
  - **سجل تغييرات JSONL ملحق-فقط** لكل حدث (claim/renew/takeover/release/
    dedup) + `read_change_log` للوحات المراقبة.
  - عزل العميل بالبناء: مساحة أسماء لكل عميل (hash) — قراءة عابرة
    للعملاء مستحيلة؛ فشل السجل لا يمنع الإبلاغ أبدًا (INDETERMINATE/
    DENIED_ERROR مع تسجيل — قاعدة fail-safe نفس بوابة 11.5).
- **بوابة الوحدات المجمدة:** إعادة تثبيت `frozen_modules.sha256` (650
  مدخلاً) بعد مراجعة موثقة للفروق التراكمية من نوافذ 0.15–0.19 (كلها
  additive default-off) + مجموعة thaw موثقة لـ`service/facade.py`
  (TRACK11_12_20261028) في `tests/test_frozen_module_gate.py`.
- **الاختبارات:** +48 (عقود 15 منها عبر-عمليات حقيقية بعملية ابن تم
  قتلها SIGKILL لإثبات أمان الانهيار، تنسيق 16، اندماج المحرك 9،
  انحدار المحرك طور 1). **الجودة:** ruff نظيف على كل الملفات؛ بوابات
  الوحدات المجمدة 652 اختبارًا أخضر؛ صفر ملاحظات جديدة في db.py.

## 0.18.0 — 2026-10-28 (المسار 11 مكتمل: بند 8 الإشعارات + أول حزمة من المسار 12: محدد التزامن المشترك)

- **البند 8 — إشعارات التأكيد (`src/webpent/vip/notifications.py`):** أكمل
  عقد المسار 11. النقل (webhook موقّع HMAC عبر العميل المحصّن ضد SSRF من
  `integrations/webhook.py`) كان موجودًا منذ V5 لكنه **غير موصول بمسار
  التأكيد إطلاقًا**. أُضيف الآن:
  - **خطاف عند لحظة التأكيد:** `save_finding` (انتقال حالة إلى CONFIRMED
    فقط — ليس أول حفظ ولا تكرار CONFIRMED) و`mark_oob_confirmed` (تأكيد
    OOB يمر بمسار SQL مباشر) يستدعيان إشعارًا fire-and-forget بعد الcommit —
    لا يمكن أبدًا أن يحجب أو يكسر مسار الاستمرارية.
  - **حجب حساس افتراضيًا:** جسم الإشعار الحتمي = معرفات فقط (id/title/
    severity/vuln_class/url/campaign/evidence_hash). الـpayload الهجومي
    والreasoning لا يُرسلان إلا بتفعيل صريح
    (`NOTIFICATION_INCLUDE_DETAILS=true`) — الـevidence bundle لا يُرسل
    أبدًا عبر الإشعارات (التقرير هو سطح الأدلة).
  - **قنوات يختارها المستخدم، كلها معطلة افتراضيًا:** webhook
    (WEBHOOK_ENABLED+WEBHOOK_URL الموجودان) و/أو ملف JSONL محلي
    (`WEBPENT_NOTIFICATION_FILE_PATH`). حد أدنى للخطورة
    (`NOTIFICATION_MIN_SEVERITY`) وطابور إرسال محدود يُسقط بأمان عند
    الامتلاء (عدّاد صريح) — أولوية الاستمرارية على اكتمال الإشعار.
  - **Idempotency:** نفس الـfinding لا يُشعر أكثر من مرة في عمر العملية
    (سجل محدود 10 آلاف معرف).
- **المسار 12 بند 2 (طور 1) — محدد التزامن المشترك
  (`src/webpent/production/concurrency_governor.py`):** حراسة مورد
  process-wide بعدالة FIFO صارمة (لا تجويع حملة — الوصف الحرفي للخطة):
  سقف عام `WEBPENT_MAX_CONCURRENT_CAMPAIGNS` (افتراضي 2) وسقف لكل هدف
  مُطبَّع `WEBPENT_MAX_CONCURRENT_PER_TARGET` (افتراضي 1، تمييز منفذ
  صريح)، صفر = بلا حد. تذكرة القبول تعيش طوال عمر الحملة: تُقبَل في
  `MultiCampaignService.start` وتُفرج في `complete()`/`halt()`. رفض
  القبول fail-closed برسالة واضحة + لقطة مراقبة حية (active/waiting/
  admitted/rejected لكل هدف). عند أي خطأ داخلي القبول يفتح بالأمان
  (availability) مع تسجيل — الحارس مورد وليس بديلًا عن صلاحيات النطاق.
  التزامن العابر للعمليات (عدة workers) مؤجل لطور يلي وفق نفس الواجهة.
- **الاختبارات:** +33 اختبارًا (حجب الإشعارات، القنوات، Idempotency،
  سقوط الطابور، عتلة الانتقال في DB، عدالة FIFO تحت خيوط حقيقية،
  صلاحيات الأهداف والمنافذ، انتهاء المهلة، لقطة المراقبة، وتدخين e2e
  لسلوك القبول/الرفض/التحرير عبر الخدمة). الإجمالي على هذين الإصدارين:
  105 اختبارات جديدة.
- **جودة:** ruff نظيف على كل الملفات الجديدة، وصفر ملاحظات جديدة في
  db.py (2→2) وfacade.py (13→13).

## 0.17.0 — 2026-10-28 (المسار 11 VIP: إكمال البندين 5 و7 — منع التكرار قبل الترشيح + إعادة الاختبار المنضبطة)

**تنفيذ البندين المتبقيين من المسار 11 (مزايا VIP)** وفق خارطة الطريق الموحدة
`WEBPENT_UNIFIED_MASTER_ROADMAP.md`. كل جديد مضاف (additive) ولا يغيّر سلوكًا
قائمًا: علم `WEBPENT_ENABLE_DEDUP_GATE` يبقي شكل الجراف السابق حرفيًا عند إطفائه.

- **البند 5 — منع التكرار قبل الترشيح (`src/webpent/vip/dedup_gate.py`):**
  مراجعة قاعدة النتائج السابقة أصبحت **شرطًا قبل ترشيح أي finding للتقرير
  النهائي**. عقدة `dedup_gate` جديدة بين `executive_summary` و`reporter`
  (بالعلم `enable_dedup_gate`، مفعّلة افتراضيًا) تحمّل قاعدة النتائج السابقة
  من DB **لنفس الـengagement فقط** (عزل عملاء صارم — لا بيانات بين عملاء)،
  وتقارن ببصمة الهوية المنطقية المستقرة `finding_fingerprint` (IDOR مُفهرس
  على الـendpoint لا العنوان). القرارات الثلاثة: `new` / `duplicate`
  (بمرجع صريح للنتيجة السابقة) / `indeterminate`. **fail-safe حرفيًا:** أي
  فشل في قراءة القاعدة لا يمنع الحملة ولا يكتم شيئًا — كل النتائج تُوسم
  `indeterminate` للمراجعة البشرية. المكررات **لا تُحذف أبدًا**: تُوسم في
  `evidence["dedup_review"]` وتُنقل من جدول الترشيح الرئيسي إلى ملحق صريح
  في التقرير (`Appendix — Duplicates of Previously Reported Findings`)
  قابل للعكس بقرار بشري، ويبقى تقرير البوابة كاملًا في الحالة
  (`dedup_report`).
- **البند 7 — إعادة الاختبار المنضبطة (`src/webpent/vip/retest.py` +
  `webpent retest`):** أمران: `retest list` (عرض المرشحين من DB) و
  `retest finding <ID>` ببوابات إلزامية متسلسلة fail-closed:
  تصريح كتابي (`--authorization`) ← ملف نطاق مكتوب (`--scope-file`، رفض
  بلا أي طلب شبكي) ← قرار `ScopeEnforcer` قبل أي بايت على الشبكة
  (`blocked_by_scope` = صفر طلبات) ← **إعادة تشغيل واحدة محدودة** للطلب
  المخزَّن حرفيًا عبر `make_safe_httpx_client` المحصّن ضد SSRF (لا
  توليد payloads، لا استكشاف، لا عواصف إعادة محاولة). الحكم حتمي من
  مفردات مغلقة: `still_present` (التوقيع المخرن استُنسخ: الحالة + كل
  الماركات) / `fixed` (تناقض حتمي: الحالة قائمة والماركات غائبة —
  الإغلاق النهائي قرار بشري) / `inconclusive` (أي غموض → تخفيض لـ
  "Needs Human Review"، **لا ترقية إطلاقًا**). التحديث يمر عبر
  `save_finding` القياسي فتسجّله `finding_status_history` تلقائيًا،
  ويُلحق **سجل مقارنة JSONL** (`retest_ledger_path`) بكل محاولة: القبل
  والبعد والمخارج ومرجع التصريح وملخص الطلب.
- **CLI:** مجموعة `webpent retest` مسجلة في `cli/commands.py` (استيراد
  من أعلى الملف — صفر ملاحظات ruff جديدة، والملف تحسّن 66→62).
- **الاختبارات:** `tests/vip/` — 39 اختبارًا (تصنيف البصمات، عزل
  العملاء، fail-safe، بوابات الرفض الثلاث، الأحكام الحتمية، سجل
  المقارنة، ودخان تكامل مع DB حقيقي: مكرر مكتشف بمرجع سابق + جديد
  يمرّ). ruff نظيف على كل الملفات الجديدة.
- **الإعدادات الجديدة:** `enable_dedup_gate` (افتراضي true)،
  `retest_request_timeout` (15 ثانية)، `retest_ledger_path`
  (`~/.webpent/retest_ledger.jsonl` — خارج المستودع بوصفها بيانات
  تشغيلية).

## 0.14.0 — 2026-10-27 (ULTIMATE PLAN: تنفيذ الخطة الشاملة لصياد الثغرات المستقل)

**تنفيذ كامل الخطة الشاملة `WEBPENT_ULTIMATE_MASTER_PLAN.md`** (13 اقتراحًا،
بالترتيب المحدد في الجزء الرابع من الخطة نفسها). التفاصيل الكاملة لكل قرار:
`ULTIMATE_PLAN_EXECUTION_20261027.md`، وسجل الانحرافات في `DRIFT_REGISTER.md`.

- **اقتراح 10 — README جديد بفلسفة "30 ثانية ثم اعمق":** Hero من 3 جمل +
  تنبيه قانوني بارز + Quickstart في أول ثلث الصفحة + شجرة قرار بالأوضاع +
  التفاصيل التاريخية (v88/v89/EGAIE) منقولة لقسم `<details>` في آخر الصفحة.
- **اقتراح 4 — أرشفة 22,215 سطر كود ميت:** 17 مجلد نموذج أولي نقلت إلى
  `archive/pre_v10_prototypes/` مع README يوثق "لماذا مات" كل واحد. تم
  بتحقق grep أن لا مستورد حيًا (الاستثناء الموثّق الوحيد: اختبارا جرد
  استراتيجيات goed_v1 أصبحا skipif موثّقًا). pyproject يستبعدها من التعبئة
  وruff من الفحص. manifest البوابة نقص 138 إدخالًا (770→632) والحاجز
  الأدنى 690→630 بتوثيق.
- **اقتراح 11 — تثبيت بأمر واحد:** `install.sh` تفاعلي (سؤال أو اتنين بس)،
  `.env.minimal.example` (10 أسطر للبداية)، و`docker compose --profile
  quickstart up` لأول حملة في دقائق.
- **اقتراح 13 — `webpent init` تفاعلي:** بدون وسائط يبدأ الموجه (URL بفحص
  وصول فوري عبر الـHTTP boundary المحصّن، تأكيد تفويض كتابي إلزامي، اختيار
  الوضع، مؤشر LLM) ويطبع أمر الحملة الجاهز للنسخ — لا يشغّلها بنفسه.
- **اقتراح 1 — توحيد المحرك:** `webpent hunt --url ... --mode
  quick|standard|deep --authorization <ref>` هو نقطة الدخول الموحدة فوق
  الجراف الإنتاجي (80+ عقدة). `UnifiedState` (superset من PentestState +
  HunterGraphState) و`adapters/legacy_state_bridge.py` (عبور بلا فقدان).
  الأوامر القديمة (`scan`, `hunt-auto`, وشكل hunt التخطيطي القديم الذي
  انتقل إلى `hunt-plan`) تعمل كـdeprecated aliases بتوجيه واضح.
- **اقتراح 3 — حلقة التعلّم المغلقة موصولة بالجراف:** عقدة
  `lesson_consultation` بعد التخطيط مباشرة (سياق استشاري فقط — أرقام
  modifiers في [-0.5, 0.5]، أبدًا ليست تعليمات) وعقدة `lesson_extraction`
  بعد التأمل (كل false-positive يتحول لدرس قابل للاستشارة). كل حملة جديدة
  تبدأ بذاكرة الحملات السابقة.
- **اقتراح 2 — ميزانية خطوات ديناميكية:** عقدة `surface_sizing` بعد WAF
  تقيس السطح (endpoints/forms/params) وتحسب الميزانية: `50 + surface×1.0`
  بسقف 400 وبسقف تكلفة (40 خطوة/دولار). الاحتياطيات النسبية (12%/15%)
  بأرضية الحدود الموثقة (19/24). سقف rabbit-hole loop-back مشتق من
  الميزانية المتبقية. سلوك 50-خطوة الثابت محفوظ حرفيًا للمسار القديم.
- **اقتراح 7 — فئات ثغرات جديدة (13 عضو VulnClass):** 5 فئات عائلات donorC
  (business_logic/tenant_isolation/multi_step_auth_bypass/exploit_chain/
  oauth — أغلقت فجوة VulnClass الموروثة وأصلحت 4 اختبارات فاشلة موثقة) +
  8 فئات كواشف (GraphQL×4، cache poisoning، web cache deception، prototype
  pollution، OAuth misconfiguration) بـvalidators حتمية + تغطية remediation
  كاملة (patterns/root-causes/context/scenarios/impact/fix/checklist).
- **اقتراح 5 — عمق recon:** أداتا `gau` (اكتشاف أرشيفي) و`nmap` (محدود:
  top-N فقط، -sT فقط، خلف بوابة مزدوجة flag+تأكيد scope) بنمط arjun،
  و`source_leak_discovery` استشاري بحت (لا ينزّل كودًا أبدًا).
- **اقتراح 12 — وضوح المخرجات:** شريط تقدم حي بثماني مراحل مبني على
  node_step_trace + سطر فوري لكل finding مؤكد CRITICAL/HIGH لحظة ترقيته +
  ملخص تنفيذي أول التقرير.
- **اقتراح 8 — توافق قرارات LLM:** `verify_llm_consistency()` (agreement
  score استشاري، fail-closed "inconclusive") خلف `enable_llm_consistency_check`
  (افتراضيًا معطل — قرار تكلفة واعٍ).
- **اقتراح 6 — تشغيل متوازٍ:** `GlobalRateGovernor` (Redis أو in-memory،
  degradation أمين) + `service/portfolio.py` (portfolio dashboard + أولوية
  جدولة مبنية على الدروس).
- **اقتراح 9 — مراقبة تشغيلية:** `GET /api/v1/workers/status` (صادق عندما
  الـbroker غائب: available=false مع HTTP 200) + صفحة مراقبة HTML حية
  + تنبيهات stall.

**التحقق:** المجموعة الكاملة **6,424 ناجحًا / 3 فاشلة (كلها موروثة
موثّقة — نفس الثلاثة التي تفشل على أشجار أصلها) / 2 skip موثّق / 1
xfailed** — من 6,430 اختبارًا (+96 عن 0.13.0). الفشل الموروث انخفض من 7
إلى 3 (إغلاق فجوة VulnClass لسلالة donorC أصلح 4). كل البوابات خضرا:
frozen manifest (650 إدخالًا مع re-freeze موثّق)، direct-I/O (773 سجلًا،
دبابيس 31/25 بعد الأرشفة)، denylist (عقد 1.3)، broad-exceptions، hygiene
(مع allowlist للبيئة المبدئية)، الإصدار 0.14.0 متزامن.

## 0.13.0 — 2026-10-26 (MERGE: الدمج الرباعي + سلّم الهوية R5)

**هذا الإصدار هو الدمج الكامل لأربعة أسلاف** (تحليل ملف-بملف، لا نسخ أعمى؛
القرارات كاملة في `MERGE_20261026.md`):

- `webpent_l6.zip` (0.12.0/EGAIE + كل طبقات Oracle/Apex/JC/Dojo/Econ/CEM/
  Forge/EGAIE/Verdict/Emulator/Rehearsal) — أساس الملفات المشتركة.
- `WebPent_TEAM_MERGED_UNIFIED_20261024_v4.zip` (سلالة donorC): طبقة Project
  Zero كاملة + قائد VIP Orchestrator + detector hardening + كتالوجات المشغل +
  نظام api_key/identity_discovery + وحدات donorC×donorV (chain_planner/
  tenant_isolation/multi_step_auth/oauth_hunter/...).
- `webpent_MERGED_track123_x_projectzero_20261024.zip`: Track 1/2/3 كاملة
  (arjun، السبر المتوازي، rabbit-hole drafting المتوازي) + waf_evasion.
- `webpent_team_refreeze_20261022.zip`: ممتص بالكامل تقريبًا في unified_v4.
- `webpent_r5_identity_resolution_ladder.patch`: مطبّق بالكامل فوق الشجرة
  المدموجة (سلّم حل الهوية S1-S4، identity_vocab، متغيرات النقل، وإعادة
  توليد frozen_modules/direct_io_inventory على الشجرة المدموجة).

## 0.12.0 — 2026-10-17 (v88: THE ORACLE — العرّاف)

بناء طبقة العرّاف بالكامل (الخطة: `docs/plans/2026-10-17-v88-oracle.md`):
12 وحدة عبر 4 موجات، من الاستطلاع السلبي إلى التقرير ذي السعة فاتورة،
مع 12 قانون مُنفَّذ برمجيًا (ORACLE-L-1..L-12). 264 اختبارًا جديدًا في
`tests/oracle/` (13 ملفًا: وحدات U-ORACLE-1..12 + ملف التكامل وقائمة
القوانين الـ12 القابلة للتنفيذ)، فوق بوابة الـ250 الجديدة.

- **U-ORACLE-1..4 (الموجة 1: الحواس)** — مجمّع OSINT بسجل مصادر له
  أساس قانوني وحدود معدل لكل مصدر، وحارس Zero-Touch يمنع أي طلب نشط
  للمستهدف مع إثبات، وتعقيم الأسرار (hash فقط) وتصفية PII، ومستنتج
  التقنيات مع ربط CVEs، ومجمّع إشارات.
- **U-ORACLE-5..9 (الموجة 2: العقل)** — مُنبّئ مسارات الدخول→الهدف
  بدرجة قابلة للشرح، ومُركّب سلاسل من 12 نمطًا معززًا بالتنبؤات،
  ومحاكي kill-chain من 7 أطوار (`executed=False` دائمًا)، ومحلل 6
  منظورات، ومُرتّب تأثير أعمال بحد أقصى 1.0.
- **U-ORACLE-10..12 (الموجة 3: الحلقة والتقرير)** — مُتحقّق تنبؤات
  بدفتر JSONL يرفض أي ادعاء دقة تحت 10 عينات (L-8)، ومُعدّ تقارير
  7 أقسام (Markdown/JSON/PDF) يعيد تطبيق التعقيم دفاعيًا، وCLI
  `webpent oracle` بـ12 أمرًا ولوحة مشغّل بستة أقسام، preamble أولاً
  وaudit مقيد (1000 سطر) في كل أمر.
- **التكامل** — خط الأنابيب السلبي كاملًا يعمل تحت حظر sockets صارم؛
  حارس AST يثبت أن لا وحدة في `oracle/` تستورد أي أداة شبكة؛
  قائمة القوانين الـ12 كلٌّ بفحص تنفيذي؛ `webpent oracle` مسجَّل في
  الـCLI الرئيسي، والجمع بلا بيانات مشغّل مرفوض (fail-closed).

البوابة: 3588 اختبارًا ناجحًا (3324 أساس + 264 جديدًا)، Ruff نظيف
على `src/webpent/oracle/` و`src/webpent/cli/oracle.py` و`tests/oracle/`.
الإصدار 0.12.0 متزامن عبر pyproject و__init__ وCHANGELOG وREADME
و pin التغليف.

# CHANGELOG

كل التواريخ بتوقيت Africa/Cairo. المشاريع الموثقة: `docs/plans/` و
`docs/vip_autonomous_bug_hunter_traceability.md`.

## 0.11.2 — 2026-10-17 (v87.2: Red Team — إصلاحات RT-12..RT-20)

عملية red team ثانية على طبقة Apex Predator بعد v87.1 (الخطة:
`docs/plans/2026-10-17-v871-red-team.md`). 9 عيوب مؤكدة بالإثبات، كلٌّ
باختبار انحدار أحمر أولًا في `tests/apex/test_u_apex_14.py` ثم الإصلاح:

- **RT-12/RT-16** — دمج النتائج لم يعد ينهار على تسميات شدة غير قياسية
  (`HIGH`, `weird`): تطبيع الحالة والمسافة، والتسمية غير المعروفة ترجع
  أدنى ترتيب بدل `None`، والعنصر المدمج يحتفظ بالتسمية الأصلية.
- **RT-13** — `orchestrate` بلا runner يعيد تقرير خطة صادقًا: كل الخطوات
  مخطَّطة (`no runner injected`)، بلا حدث تعلم، بلا عدّاد إتمام، والـfeedback
  يعلن `planned_only` — لا نجاح مزيّف من مسار MCP `apex_recon`.
- **RT-14** — عقد خطأ structured في `dispatch`: التوكن الخاطئ والأداة
  المجهولة والوسيط الناقص يعيدون قاموسًا مع الـpreamble، لا استثناءات خام.
- **RT-15** — `chain run --execute` صادق واعٍ بالاعتماديات: تنفيذ عبر
  `ParallelRunner` (تخيٌّ انتقالي حقيقي)، أوامر تحمل الهدف لا ثنائيات عارية،
  مدة مقاسة وskipped محسوب من النتائج، وتغذية التعلم
  (`record_chain_outcome` + `record_tool_result`).
- **RT-17** — الخطوة الغائبة عن نتيجة التشغيل تُسجَّل `-1` (غير منفذة)
  لا `0` (نجاح مزيّف).
- **RT-18** — `get_best_chain_for` يتطلب `MIN_SAMPLES` أدلة قبل أي
  اقتراح، كبروس `get_tool_accuracy` (APEX-L-7).
- **RT-19** — ربط IPv6 loopback مقبول (`::1` و`[::1]:8080`)، والأشكال
  الفاسدة (`::1:99`) والمنتحلة تبقى مرفوضة.
- **RT-20** — بلا حقل `state: idle` مزيّف في `apex status`؛ يُعلن صراحة
  عدم وجود daemon واستشارية الطبقة، والعدادات من السجلات المسجَّلة فقط.

البوابة: **3324 اختبارًا ناجحًا** (3308 + 16 اختبار انحدار جديد)، Ruff
نظيف على الملفات الملموسة، جرد direct-IO بلا انحراف.

## 0.11.1 — 2026-10-17 (v87.1: Red Team — إصلاحات RT-01..RT-11)

عملية red team صارمة على طبقة Apex Predator (الخطة:
`docs/plans/2026-10-17-v87-red-team.md`): 11 عيبًا مؤكدًا بالأدلة،
كلٌّ منها باختبار انحدار أحمر أولًا ثم أخضر (15 اختبارًا في
`tests/apex/test_u_apex_13.py`).

- **RT-01 (حرج):** `apex_app` لم يكن مسجَّلًا في الـCLI الرئيسي أصلًا
  و`cli/apex.py` بلا نقطة دخول `main()` — أوامر `webpent apex` كانت
  غير موجودة. سُجِّل الـtyper في `commands.py` وأُضيف `main()`.
- **RT-02 (حرج):** مهلة تنفيذ الصندوق كانت تُهمل — `Sandbox.execute`
  و`LocalSandbox` و`SandboxBackend` أصبحت تنقل `timeout_seconds`
  من الاستدعاء أو الإعدادات، والمنفذ يمررها فعليًا.
- **RT-03 (حرج):** الـdry-run كان يزوّر مقاييس (سرعة مقاسة، خطوات
  منفذة). صار يسجل بصدق: `dry_run=True`، بلا نتائج خطوات، بلا سرعة.
- **RT-04 (عالٍ):** `chain_id` كان يتجاهل تغيّر الإعدادات — البصمة
  الآن تشمل خطوات القالب وأدوات السجل ومحتوى ملف chains.yaml بالبايت.
- **RT-05 (عالٍ):** فشل خطوة أوسط كان يترك الأحفاد بلا جدولة —
  التخطي ينتقل انتقالياً عبر كل الاعتماديات.
- **RT-06 (عالٍ):** فحص الربط المحلي كان `startswith("127.")`
  قابلًا للانتحال (`127.0.0.1.evil.com`) — صار تحليل host بـipaddress.
- **RT-07 (عالٍ):** سقف سجل التعلم كان على النتائج فقط — الآن السقف
  على كل أسطر الملف (أي نوع) فلا ينمو بلا حدود.
- **RT-08 (متوسط):** إعادة كتابة السجل كانت تطفو أسطر tool_result
  فوق outcome مشوِّهة ترتيب التسجيل — السجل الآن إلحاقي بترتيب الإدراج.
- **RT-09 (متوسط):** لوحة المشغّل كانت تتجاهل `max_recent_chains`
  وتعرض كل السجلات — تُحترم الآن في قسم Chains.
- **RT-10 (متوسط):** استثناء الأداة غير المسجلة كان dead code —
  `_require_registered` يحرس مسار التنفيذ فعلياً (وكخطأ نظيف في
  `tools install` لمُعرّف غير مُدقَّق، RT-11).
- **RT-11 (منخفض):** `tools install` لمعرّف غير مُدقَّق كان يخرج 0
  بصمت — يخرج 2 برسالة موجّهة.
- إعادة توليد `docs/direct_io_inventory.json` عمداً (نفس 647 هوية،
  6 إزاحات أسطر فقط من الإصلاحات).

## 0.11.0 — 2026-10-16 (v87: The Apex Predator — طبقة التنسيق الأعلى)

الطبقة الثامنة: **المفترس الأعلى** — دماغ تنسيق من 4 طبقات فوق كل
الطبقات السابقة، مغلف في `src/webpent/apex/` على 12 وحدة (U-APEX-1..12)
عبر أربع موجات (الخطة: `docs/plans/2026-10-16-v87-apex-predator.md`).
ميثاقه عشرة قوانين (APEX-L-1..L-10): الأدوات لا الكود، المُدقَّق فقط،
النطاق قبل الأداة، الصندوق دائماً، التوازي افتراضياً، دمج النتائج،
التعلم من كل شيء، السرعة هي الأفضلية، استشاري فقط، والـpreamble أولًا.

- **U-APEX-1/2/3/4** سجل الأدوات المُدقَّقة (31 أداة في 9 فئات في
  `config/apex/tools.yaml`، `verify_installed` بـwhich فقط)، صندوق
  التنفيذ (`DockerSandbox` يبني argv المعزول بلا تنفيذ docker — daemon
  محجوب في هذه البيئة ومُسجَّل، و`LocalSandbox` احتياطي محدود الموارد
  بمهلة صارمة)، حارس النطاق يفشل مغلقًا (نطاق فارغ = لا شيء)، والمنفذ
  يبني أوامر الأدوات بلا تنفيذ شبكي.
- **U-APEX-5/6/7/8** العدّاء المتوازي واعي الاعتماديات يقيس التسريع من
  الزمن الحقيقي (لا تقديرات ملبّسة بالقياسات)، المنسّق التكيّفي
  (decision → chain → run → fusion → learning) يفحص النطاق قبل جدولة
  أي شيء، منتقي الأدوات بدرجات سرعة/تخفٍ وملفات تعريف stealth ولا
  رقم دقة قبل الأدلة، ودمج النتائج يجمع الادعاءات بـ(الفئة، نقطة
  النهاية) ويخصم بدقة الأداة ويحسم التعارضات بالثقة.
- **U-APEX-9/10/11/12** محسّن السرعة (cache بـTTL، مهلات تكيّفية
  مُقيَّدة، prefetch، دفعات)، خادم MCP برمز SHA256 ومقارنة زمن-ثابت
  وإعلان ربط محلي فقط، واجهة `cli/apex.py` بنمط الدوجو (preamble أولًا،
  audit JSONL مُقنن بـ1000، `tools install` استشاري يطبع الأمر وينفّذ
  لا شيء، `chain run` تجربة جافة افتراضيًا)، ولوحة المشغّل بخمسة
  أقسام، وحلقة التعلم المستمر (سجل JSONL مُقنن بمسارات redacted
  بهاش الهدف لا نصه، ولا رقم دقة قبل MIN_SAMPLES=5 مشاهدات، أفضل
  سلسلة بالنجاح المسجَّل، اقتراحات تحسين من الإخفاقات المتكررة).
- **بوابة التحقق:** 3164 أساس + 129 اختبار apex جديد (منها 4 اختبارات
  تكامل بـsocket+subprocess patch: صفر شبكة وصفر عملية من مسارات apex،
  وبرهان L-9 بعدم استيراد أي وحدة apex لمكوّنات شبكة) = **3293 اختبارًا
  ناجحًا** من الزيب المفكوك، Ruff نظيف على نطاق apex.
- **جرد direct-IO:** سجلان جديدان في `apex/sandbox.py` (import subprocess
  وsubprocess.run) مُعاد تثبيتهما بقاعدة R4 — LocalSandbox هو الاحتياطي
  الموثّق المنفّذ للأوامر المسموحة بمهلة، بينما حدود عائلة subprocess
  المعتمدة تبقى `webpent.tools.utils.subprocess.run_command`.

## 0.10.1 — 2026-10-16 (v86.1: Red Team على The Dojo)

جولة red team صارمة على الطبقة السابعة (الخطة:
`docs/plans/2026-10-16-v86-red-team.md`): 10 عيوب مؤكدة، كل عيب
مُستنسخ باختبار فاشل أولاً (19 اختبار جديد في `tests/dojo/test_u_dojo_25.py`)
ثم إصلاح جذري واحد لكل عيب. البوابة: **3164 اختبار ناجح** (3144 أساس + 20
جديد، صفر فشل)، Ruff نظيف على نطاق الدوجو، وصفر شذوذ شبكة.

- **RT-01 (high)** المحرك تجاهل `RouteSpec.method`: `respond()` يطابق
  المسار فقط، فطريق POST يجيب GET بـ200. الإصلاح: مطابقة (مسار، method
  بحالة غير حساسة)، رفض 405 بعلامة `method_not_allowed` (أُضيفت لـ
  `RESPONSE_FLAGS`)، وكل الوكلاء المدمجون الأربعة يخططون بطريقة الطريق
  الفعلية بدل `GET` مثبتة.
- **RT-02 (high)** أنماط الدفاع تمحو الميزانية: `runner.run()` كان
  يُعيد كتابة `lab.request_budget` بميزانية السيناريو دائماً، وsparring/
  counter_adapter كانا يعيدان الكتابة **بعد** `pattern.apply()` —
  فنمطان من 12 (shrink_request_budget، rate_limit_lockout) كانا كوداً
  ميتاً. الإصلاح: العدّاء يضبط الميزانية للمختبر الجديد فقط، والمختبر
  المُمرر يحتفظ بميزانيته؛ الأساس يُضبط **قبل** تطبيق النمط.
- **RT-03 (medium)** الاحتفاظ كان يُتقاعد `sorted(instance_ids)`
  معجمياً لا بترتيب البدء؛ الإصلاح: ترتيب الإدراج في القاموس هو FIFO
  الحقيقي.
- **RT-04 (medium)** `save()`/`load()` في المدرب كانا يُسقطان
  `hints_used` — إعادة تحميل تُرجع التلميحة المدفوعة مجاناً (تجاوز
  اقتصاد HINT_COST=10). الإصلاح: حفظ واستعادة الحالة مع clamp.
- **RT-05 (medium)** `_skill_gap` كان يشترط `total_fp > 0`: عائلة
  تفشل 100% بصفر ادعاءات خاطئة لا تُعلن مهارة ناقصة أبداً — أوضح فجوة
  كانت تضيع (مخالف لـL-7). الإصلاح: إسقاط الشرط مع تفصيل مخصص للفشل
  الصادق.
- **RT-06 (high)** سجل الممارسة في CLI كان يسجل `scenario_id/score/
  success` فقط، وإعادة التميين بـ`requests_used=0, false_positives=0,
  time_steps=0, budget=0` — مهارة القياس من السجل تآخذ مكافأة كفاءة
  كاملة ولا ترى false positive أبداً. الإصلاح: `PracticeResult.as_dict()`
  (بما فيه `budget`) يُسجل كاملاً، وموقع إعادة تميين واحد `_rehydrate()`
  يقرأ بالمفاتيح مع `.get()` افتراضية فصيغ السجل القديمة تعمل.
- **RT-07 (low)** `burn(lab, -5)` كان **يزيد** الميزانية؛ الإصلاح:
  clamp للعدد السالب على صفر.
- **RT-08 (low)** `VulnPoint.requires_auth` كان حقل ميت لا يُقرأ
  أبداً؛ الإصلاح: نقطة الضعف التي تشترط auth غير مرئية للطالب بلا
  token صالح (L-3 ground truth).
- **RT-09 (medium)** سجل `history.jsonl` كان بلا سقف بينما audit
  مقيّد بـ1000؛ الإصلاح: `MAX_HISTORY_LINES = 5000` مع قص في `record()`.
- **RT-10 (medium)** `trend()` يجري حسابات على أي قيمة `score` — قيمة
  غير رقمية في السجل كانت تُسقط كل أوامر CLI التي تقرأ التاريخ؛
  الإصلاح: فلترة `int/float` فقط (bool مستبعد) قبل الحساب.

اختبارات مثبتة حُدّثت للدلالة المصححة، كل تحديث بسببه الموثق في الخطة:
`test_budget_exhaustion_rate_limits` (probe بطريقة الطريق الحقيقية)،
`test_budget_exhaustion_stops_the_waves` (ميزانية المختبر المُمرر تُضبط
في الاختبار لا من العدّاء)، `test_run_overrides_lab_budget` (مقسوم
لاحترام الميزانية المُمررة + سقف المختبر الجديد)، `test_skill_gap_
without_false_positives` (الفشل الصادق يُعلن). أداة الجرد المباشر
أُعيد توليدها عمداً بعد انزياح سطر واحد في `tournament.py` (645 سجلاً،
الغطاء والpin كما هما).


## 0.10.0 — 2026-10-16 (v86: The Dojo — ميدان التدريب الذاتي)

الطبقة السابعة: بيئة تدريب ذاتي مغلفة في `src/webpent/dojo/` على 12 وحدة
(U-DOJO-1..12) عبر أربع موجات، ميثاقها عشرة قوانين (DOJO-L-1..DOJO-L-10)
وعقدها: صفر شبكة (L-1)، حالة معزولة قابلة للتوجيه بـ`WEBPENT_DOJO_DIR`
(L-2)، ground truth موثق لكل سيناريو (L-3)، حتمية بالكامل بالبذور
(L-4)، تحسّن مقاس لا معلن (L-5)، صدق عدواني يشمل انتصار الأحمر (L-6)،
تغذية راجعة كدروس (L-7)، سطر تمهيد advisory قبل كل مخرج (L-8)، رتيبية
الاختبارات (L-9)، وصفر أثر على الحملات الحقيقية (L-10). الخطة الموثقة:
`docs/plans/2026-10-16-v85-dojo.md`.

- **U-DOJO-1** المحرك `engine.py`: `SimulatedTarget` + `RouteSpec` +
  `VulnPoint`/decoys — هدف محاكى حتمي بميزانية طلبات، تحقق auth، rate
  limit، burn للطلبات الفاشلة، وnormalize/strict_types لكل نقطة.
- **U-DOJO-2** مولد المختبرات `lab_generator.py`: 9 قوالب مختبرات
  (`config/dojo/scenarios/*.yaml`) ببذور، احتفاظ RETENTION_PER_TEMPLATE=5
  (الأقدم يُتقاعد)، stop/reset يردّان الحالة والstate_hash، و
  `get_vuln_map()` يفصل الحقيقة عن الطُعم للمدافع فقط.
- **U-DOJO-3/4** مكتبة السيناريوهات `scenario_library.py`: سيناريوهات
  مجمّدة بـground truth وتلميحات وعائلات مهارة، تحقق كامل، فرز، وتصفية
  بالعائلة والصعوبة.
- **U-DOJO-5** عدّاء التدريب `practice_runner.py`: صيغة الدرجة
  `score = 100 × (0.5×success + 0.2×time_eff + 0.1×req_eff +
  0.2×(1−fp))` بتكسير floor للزمن والطلبات، وكشف false_positives
  من الأحمر — والفشل الصادق درجة أعلى من النجاح بالخداع.
- **U-DOJO-6** المقيّم `skill_assessor.py`: مهارة لكل عائلة
  `skill = 100 × (0.4×success + 0.3×avg/100 + 0.2×(1−fp_rate) +
  0.1×(1−time_ratio))` مع MIN_SAMPLES=10 قبل أي ادعاء، واتجاه
  improving/declining/flat بنافذة.
- **U-DOJO-7** كاشف الضعف `weakness_identifier.py`: 5 أنواع (skill_gap
  عند success<0.5، speed_gap عند time_ratio>0.8، consistency_gap عند
  stddev>25.0، context_gap عند صعوبة وسطية، adaptation_gap) بعتبات
  ثابتة مسماة وMIN_SAMPLES_FOR_WEAKNESS=5، مرتبة بالشدة.
- **U-DOJO-8** مولّد الخطة `practice_generator.py`: أربع مراحل
  (warmup/focus/sparring/reassessment) بحيازات قصوى (MAX_WARMUP_ITEMS/
  MAX_FOCUS_ITEMS_PER_FAMILY/MAX_SPARRING_ITEMS)، warmup سهل فقط،
  focus على الأضعف أولًا، وخطة مجمّدة seed-based.
- **U-DOJO-9** التدريب المقيد `trainer.py`: جلسة خطوة-بخطوة مع
  HINT_COST=10 من الدرجة، تلميحات تُصفّر عند كل إجابة صحيحة، وحفظ/
  استئناف حالة الجلسة في دير الـdojo.
- **U-DOJO-10** كاتب الحالات `case_study.py`: تصدير Markdown لكل
  مباراة مع سطر advisory وعلم sanitization، وredaction بترتيب
  (bearer ثم authorization ثم cookie ثم أسرار عامة) بحد _MAX_TEXT=800.
- **U-DOJO-11** المباراة `sparring.py` + المدافع `defender.py`: 12 نمط
  دفاع (DEFENSE_PATTERNS — input filter/elevate auth/decoy hardening/
  shrink surface/rate limit=1/signature rotation وغيرها) يُطبَّق كلٌّ
  على نسخة جديدة من المختبر بلا mutation، و`counter_adapter.py`
  يكيّف الأحمر بين الجولات.
- **U-DOJO-11ب** البطولة `tournament.py`: 4 وكلاء مدمجين (naive/
  methodical/signature_matcher/adaptive) round-robin على بذور متطابقة،
  وترتيب بـtotal_score.
- **U-DOJO-12** الدفتر والسجل `progress.py`: ledger JSONL + audit
  JSONL مُقنن بـMAX_AUDIT_LINES=1000، trend محسوب من النصف الأقدم،
  وواجهة CLI `webpent dojo` بـ12 أمرًا (labs/scenarios/practice/spar/
  tournament/skill/weaknesses/plan/case-study/train/progress/status)
  كلٌّ بطباعة PREAMBLE_LINE أولًا (L-8) وسطر audit مُنقّح.
- **تكامل**: `tests/dojo/test_dojo_integration.py` يشمل صفر شبكة
  (socket patch)، عزل الكتابة لـL-2، عدم تأثير الحالة بين الجلسات،
  حتمية byte-identical لنفس البذرة، واستيراد الـdojo وحده لا يمس
  حالة أي حملة (L-10).
- **الأرقام المقاسة عند الإغلاق**: **3144 اختبارًا ناجحًا، 0 فشل**
  (خط الأساس 2882 + **262 اختبارًا جديدًا** في `tests/dojo/` — 26 ملفًا
  بما فيها التكامل)، متجاوزًا بوابة الـDoD (+200، الهدف ≥3082). Ruff
  نظيف (صفر أخطاء) على `src/webpent/dojo/` كاملًا و`cli/dojo.py`
  و`tests/dojo/`. جرد direct-IO: 645 سجلًا، المواقع غير المعتمدة
  مثبتة عند 20 بلا تغيير.

## 0.9.0 — 2026-10-16 (v85: مجلس الحكم Judgment Council)

طبقة meta-cognition فوق الدماغ السباعي: 12 وحدة في `src/webpent/jc/` على
أربع موجات، ميثاقها عشرة قوانين (JC-L-1..JC-L-10). الخطة الموثقة:
`docs/plans/2026-10-16-v85-judgment-council.md`.

- **U-JC-1** غرفة المجلس: استدعاء جلسة حتمية (session id = sha256 للسؤال +
  hash السياق بترتيب مفاتيح مجمد)، سقف جولات، seat تلقائي للشكّاك والقاضي،
  وتصعيد دائم عند غياب القاضي أو تجاوز الوقت.
- **U-JC-2** سبعة مدافعين (Tactician/Observer/Adapter/Historian/
  Strategist/Resilient/Economist): كل طبقة دماغ صوت واحد، يقرأ مفتاح
  سياقه الموثق، يبني evidence حتمية، إما يجادل أو ينسحب (والانسحاب مسجل).
- **U-JC-3** الشكّاك: 7 أعلام انحياز موثقة (confirmation/recency/anchoring/
  availability/overconfidence/sampling/cherry_picking)، شدة مقيدة ≤ 0.9،
  وفرضية بديلة إلزامية لكل تحدٍ.
- **U-JC-4** القاضي + قواعد الحكم: حتمي بالكامل، confidence في [0,1]
  بثلاث طبقات، والمعارضة (dissent) محفوظة كاملة لا تُسكت (JC-L-5).
- **U-JC-5** ميزان الأصوات + **U-JC-6** المسجل: توليف الأدلة، مغلف
  الشفافية L-4 على كل عقد، وتسجيل JSONL للجلسات والأحكام.
- **U-JC-7** معايرة الثقة: Brier score، drift عند فرق متوسطات > 0.1 بعد
  20 عينة على الأقل، وadjust() لا يفعل شيئًا قبل الحد الأدنى.
- **U-JC-8** كاشف الانحيازات عبر الجلسات و**U-JC-9** ذاكرة المجلس:
  أنماط انحياز من 3 جلسات على الأقل، تشابه الجلسات بـJaccard على مفاتيح
  السياق، ودروس (lessons) جاهزة للتصدير.
- **U-JC-10** الشارح بثلاث مستويات (one-liner/summary/full) و**U-JC-11**
  بروتوكول الoverride: المشغل سيادي (JC-L-7) — full/partial/advisory
  مع سبب إلزامي، دقة المشغل تُقاس وتُعرض.
- **U-JC-12** لوحة القيادة + CLI `webpent jc` (sessions/verdicts/
  calibration/dashboard/digest/override) بكل أمر مسجل في audit JSONL
  مُقنن بـ1000 سطر ومُنقّح.
- **تكامل**: 14 اختبار تكامل تشمل حتمية byte-identical، مصادر بلا LLM
  وبلا random، صفر شبكة (socket patch)، كل الأصوات مسموعة، pipeline كامل
  من dissent إلى lessons ومن calibration إلى drift إلى dashboard.
- إصلاحات أثناء التنفيذ: نمط الصف الفاسد (`row = None`) في 7 مواقع قراءة
  JSONL، apply() في override كان يكتب مفاتيح dict كسطور منفصلة، auto-seat
  بالـsentinel يفرق "لم يُقل" عن "لا أحد"، وفحص zero-network محكم.
- جرد direct-IO مُجدد عمدًا (فرق مراجَع من 10 أسطر: 5 أرقام أسطر فقط في
  `cli/commands.py`، صفر مواقع نقل جديدة).
- **موجة red team على مجلس الحكم** (الخطة الموثقة:
  `docs/plans/2026-10-16-v85-red-team.md`)، بمنهجية failing-test-first:
  10 عيوب مؤكدة، 9 منها حقيقية أُصلحت وواحد أُعيد تصنيفه أثناء التنفيذ
  (اختبار RT-07 الأول كان خاطئًا وليس الكود: mkstemp لا يستخدم لاحقة
  .tmp، فأُعيدت كتابة الفحص بمقارنة محتويات المجلد). أبرزها:
  `ZeroDivisionError` في `judge.py` حين تكون كل الدرجات صفرًا (حجة
  جوفاء = تصعيد بدل انهيار)؛ `sessions.jsonl` كان لا كاتب له في الإنتاج
  فيُستنزف كاشف التحيز (U-JC-8) — الآن `CouncilMemory.record()` يكتب
  سطر جلسة مضغوطًا متوافقًا مع الـconsumers القائمة؛ `jc verdicts --limit`
  كان يقصّ قبل التصفية فيخسر أحكامًا خلف صفوف بدون verdict؛ و`VerdictRules`
  كان يقبل high<medium وقيمًا خارج [0,1] بلا تدقيق (الآن: clamp، تبديل
  عند الانقلاب، revert للـepsilon والنسبة الخاطئة). في النقاد: علم
  confirmation لم يعد يُطلق على غرض واحد (يحتاج ≥2)، وعلم `general_doubt`
  صار موثقًا عبر `SKEPTIC_FLAGS`، وحذف وسيط ميت من `_counter_evidence`؛
  تسريب ملفات tmp عند فشل الإدخال/الإخراج أُغلق بـtry/finally في
  `record()` و`_rewrite()`؛ أرقام سحرية (عتبة 50$، نسبة انهيار 0.5،
  نافذة recency 30 يومًا) صارت ثوابت مسماة؛ وإسناد مكرر في `explainer._full`
  حُذف. 9 اختبارات regression جديدة في `tests/jc/test_v85_rt.py`،
  اختباران قديمان في `test_u_jc_3.py` حُدّثا (كانا يعتمدان على إطلاق
  confirmation بغرض واحد)؛ الشدة القصوى الفعالة الآن 5 أعلام = 0.75
  (الحد 0.9 ما زال حاجزًا نظريًا). Gate: 2882 اختبار ناجح من شجرة
  العمل، ruff نظيف على الوحدات الملموسة.

## 0.8.3 — 2026-10-16 (v84.1: red team على الدماغ الاقتصادي)

موجة red team صارمة على حزمة v84 بالكامل (12 وحدة econ + واجهة
`cli/econ.py`)، بمنهجية repro-first: كل عيب أُثبت بتنفيذ فعلي فاشل
(13 اختبار regression حمراء) قبل أي إصلاح، ثم إصلاح جذري واحد لكل عيب.
الخطة الموثقة: `docs/plans/2026-10-16-v84-red-team.md`.

- **RT-01**: أول سطر تالف في الـjournal كان يُسقط `findings value`
  بـ`UnboundLocalError` (نفس عائلة خلل أُصلح في learning_loop ولم تُصلح
  نسخة الـCLI) — تهيئة `row = None` قبل الحلقة.
- **RT-02**: `portfolio transition` كان يُطبَّق في الذاكرة فقط ويضيع
  عند انتهاء الأمر — أُضيف `PortfolioManager.save()` بكتابة YAML ذرية
  (tempfile + os.replace) بسبعة حقول round-trip، والـCLI يستدعيه بعد
  كل انتقال ناجح. وأثناء التنفيذ اكتُشف عيب round-trip مرافق: `load()`
  كان يتجاهل `last_transition` حين يفكّه PyYAML كـdatetime أصلاً.
- **RT-03 + RT-12**: التواريخ بإزاحات UTC مختلطة كانت تُخزَّن خامًا في
  `competitive.db` فتفسد مقارنات SQLite المعجمية (`13:00+03` تتفوق
  على `12:00+00`) — تسوية `astimezone(UTC)` في `_parse_finding` و
  `sanitized()`، واستبدال fallback `datetime.now` المخالف لـL-3 بـepoch
  حتمي (1970).
- **RT-04**: `payout_usd` غير رقمي كان يُسقط `analyze()` بالكامل —
  fail-soft: الصف الفاسد يُهمل والصفوف السليمة تُعلّم.
- **RT-05**: سبب الانتقال WATCHING→DORMANT كان يحسب الركود بعد كتابة
  `last_transition = now` فيسجل دائمًا "60 days" مهما كان الركود
  الفعلي — التقاط `stale_days` قبل الطفح (صدق L-4).
- **RT-06**: `target_id` مكرر في `budget_mapper.allocate` كان يُنتج
  تخصيصين بصمت فيشوه تقسيم 60/30/10 — `ValueError` صريح يذكر المعرّف.
- **RT-07**: خيار `--days` في `digest` كان يُقبل ويُدوَّن بلا أي أثر،
  وقسم "Top opportunities" كان فارغًا دائمًا — الـdigest الآن يوصل
  الرادار فعليًا: استعلام بفرص `--days` لبرامج ACTIVE/WATCHING (حد 8
  برامج) وتمريرها إلى `build_digest`.
- **RT-08**: `opportunities` لهدف غير معروف كان يسأل الرادار بصمت
  بمعرّف مصطنع — يرد الآن `found: false`.
- **RT-09**: `str(value or "")` كان يحوّل `0` و`False` إلى سلسلة فارغة
  في سجل التدقيق — `""` فقط لـNone.
- **RT-10**: قيم رقمية فاسدة في الـjournal كانت تُسقط الأمر بـtraceback
  — الصف الفاسد يُعامل كغير موجود (`found: false`، exit 0).
- **RT-11**: حقن بنية Markdown من معرفات محلية في اللوحة — `_md_cell()`
  يطوي `
`/`
` إلى مسافة ويحيّد `|` في كل الخلايا، وقسم "Bottom
  targets" أصبح جدولًا منضبطًا بأربعة أعمدة.

**عائلة أُصلحت ولاحقًا**: فحص ما بقي دون عيب موثق في
`docs/plans/2026-10-16-v84-red-team.md` (market_kb، scope_negotiator،
roi_optimizer، timing_advisor، saturation، blind_spots، حدود الملفات
وredact).

**البوابة**: 2649 اختبارًا ناجحًا (2636 أساس + 13 regression جديد،
L-6 رتيب)، ruff نظيف على كل الملفات الملموسة.

## 0.8.2 — 2026-10-16 (v84: الدماغ الاقتصادي Economic Brain v1)

تطبيق ميثاق THE ECONOMIST CHARTER (NC-ECON-1) بالكامل: 12 وحدة في
`src/webpent/econ/` على 4 موجات، كلها advisory بالكامل وصفر network
من جوهر الأداة (L-1، L-2)، وكل قرار deterministic بإدخال `now`
صريح (L-3) وبمظروف الشفافية الكامل (L-4).

- **Wave 1 (الأساس)**: `market_kb.py` قاعدة معرفة السوق (≥10 برامج،
  مصادر موثقة، حقن لقطات فقط)، `target_scorer.py` سكورر الأهداف،
  `scope_negotiator.py` مفاوض الـscope المحافظ، `roi_optimizer.py`
  مُقيّم الـEV مع recommendation وjustification لكل finding، و
  `timing_advisor.py` مستشار التوقيت بـ6 سيناريوهات بقواعد موثقة.
- **Wave 2 (المنافسة)**: `budget_mapper.py` توزيع 60/30/10 على
  INTENSIVE/ROUTINE/DORMANT، `competitive.py` رادار الاكتشافات العامة
  بـSQLite محلي بمخطط zero-PII من ستة أعمدة بالضبط، `saturation.py`
  مؤشر الإشباع بالصيغة 0.5/0.3/0.2 مع سياسة بيانات ناقصة واضحة.
- **Wave 3 (الفرص)**: `blind_spots.py` كاشف النقاط العمياء عبر
  تقاطع الـscope مع الاكتشافات العامة (مناطق مسارات/سابدومينات/أصناف)
  و`docs/econ/competitive_zero_pii.md` ضمان الـzero-PII بالمخطط لا
  بالنوايا الحسنة.
- **Wave 4 (المحفظة)**: `portfolio.py` آلة حالات بأربعة أحوال وخمسة
  انتقالات قانونية فقط، `learning_loop.py` حلقة تعلّم بعتبة أهمية
  إحصائية (10 نقاط بيانات قبل أي توصية، `docs/econ/learning_loop.md`)،
  و`dashboard.py` + `webpent econ` CLI: digest يومي بصيغتين
  (markdown/JSON) وعشرة أوامر، كلها مسجّلة في
  `download/econ/audit.jsonl` المحدود والمُنقّح.

الملفات المحاسبية: `config/econ/competition_params.yaml` و
`config/econ/portfolio.yaml` (22 هدفًا) و`download/econ/RUNNING_LOG.md`
و`docs/econ/decision_matrix.md`.

البوابة: **2636 اختبارًا ناجحًا** (+69 في `tests/econ/`)، Ruff نظيف
على كل الملفات الجديدة، جرد direct-IO مُجدد عمدًا من الماسح
المرجعي (643 سجلًا، لا مواقع unapproved جديدة)، وإصدار 0.8.2
متزامن عبر pyproject و`__init__.py` وCHANGELOG.

## 0.8.1 — 2026-10-16 (v83.1: red team على CEM)

موجة red team صارمة على وحدات CEM الاثنتي عشرة وواجهة CLI: 13 نتيجة
مؤكدة، كلها مثبتة بـrepro نُفِّذ قبل الإصلاح (الخطة والنقد في
`docs/plans/2026-10-15-v83-red-team.md`).

- **الإنفاق الصادق (عالية)**: `run_cem_cycle` يطلب من المجدول العدد
  المطلوب فعليًا، يصرف لكل هدف ملاحظة كاملة فقط عند سُدّادها، يعلّم
  ما لم يُسدّد في `skipped_budget`، و`report["spend"]` يجمع
  المُصروف لا المطلوب.
- **الscope مقدّس (عالية)**: عنصر scope بلا نقطة (TLD وحيد مثل
  `com`) يُرفض — لا يُصوّح لأي مضيف.
- **حدود الميزانية**: `register_launch` يقصّ مقترحًا متضخمًا إلى
  سقف الحملة المصغّرة (10%)، وwake_up وحده يصل إلى الميزانية
  اليومية؛ ثابت تاريخ الحملات مُسمّى ومُوثق.
- **الفرملة اللاتنسية**: تبريد فرملة الكمون يقبل `brake_hours`
  بدل الثابت الصلب.
- **دروس موسمية محصّنة**: `reap` لا يقاعد درسًا ضعيفًا في شهره
  الموسمي (وTTL يبقى مطلقًا)، `seasonal_watchlist` يستخدم القوة
  الفعّالة، و`lessons_for` يحجب المنقضي زمنيًا.
- **مفاتيح القتل**: `webpent cem resume` لا يفكّ المفتاح بصمت
  بعد الآن؛ الفك يحتاج `--clear-kill-switch` صريحًا ويُدوَّن.
- **اعتمادية ونظافة**: `write_digest` fail-soft أمام قيم غير
  قابلة للتسلسل، أعلام الرفض في wake_up تحمل `advisory`، سقف
  إعادة اختبار صادق (32/دورة)، حذف dead code من snapshot و
  diff_engine وتوحيد مطابقة الضجيج على `noise_matcher`، رفع
  الاستيرادات المؤجلة في cycle.

البوابة: **2567 اختبارًا ناجحًا** (+16)، Ruff نظيف، جرد direct-IO
بلا انحراف (643 سجلًا).

## 0.8.0 — 2026-10-15 (v83: وضع الاشتباك المستمر CEM)

طبقة رابعة فوق حلقة الصيد: `webpent.autonomous.cem` بـ12 بندًا على 4
طبقات، كلها advisory بالكامل ولا daemon إطلاقًا — "الاستمرارية" دالة
نقية واحدة `run_cem_cycle` يستدعيها مجدول خارجي (cron) بوقت محقون.

- **الطبقة 1 — البرج**: `snapshot.py` (محرك لقطات محدود وredacted
  ببصمة sha256)، `diff_engine.py` (تصنيف رباعي NOISE / SIGNAL_LOW /
  SIGNAL_HIGH / CRITICAL بإعدادات YAML محكومة بالقوائم البيضاء)،
  `scope_drift.py` (انجراف نطاق ودخول hosts خارج النطاق تُلاحَظ ولا
  تُلمَس إطلاقًا)، `scheduler.py` (مجدول مهذب: ساعات نشاط، سقف يومي،
  فرملة زمن استجابة، kill switch فوري دائم)، `cycle.py` (دورة الاشتباك
  النقية مع محاكاة 72 ساعة).
- **الطبقة 2 — المفاعل**: `reactor.py` (حملات مصغّرة بـ10% من الميزانية
  مع cooldown)، `regression_watch.py` (مراقبة انحدار findings بدورة
  إعادة اختبار محكومة)، `wake_up.py` (بروتوكول الاستيقاظ للأحداث
  الحرجة فقط بميزانية محدودة).
- **الطبقة 3 — الذاكرة الطولية**: `temporal_lessons.py` (سجل دروس
  بـTTL 90 يومًا وتعزيز موسمي)، `deployment_rhythm.py` (إيقاع نشر
  الهدف: ساعات وأيام الذروة ومعدل الانحدار بعدها)، `dormant_pool.py`
  (بركة فرضيات خاملة بشرط `blocked_on` تستيقظ عند تحقق التغيير).
- **الطبقة 4 — واجهة المشغّل**: `digest.py` (تقرير يومي Markdown+JSON
  محتمد وredacted) و`cli/cem.py` (أوامر `webpent cem`
  start/pause/resume/status/digest/findings/kill — عمليات ملفات حالة
  محلية فقط، كل أمر يُسجَّل في audit log محتمد بآخر 1000 سطر).

الحواجز السبعة الموروثة تُطبَّق على كل بند: advisory فقط، لا سلطة تنفيذ
جديدة ولا شبكة ذاتية (كل الجوالب محقونة)، وقت محقون `now`، redact لكل
نص محفوظ، حدود صارمة، ملف تالف → فارغ لا استثناء، والنطاق مقدّس.

## 0.7.0 — 2026-10-15 (v82: طبقات التضخيم الأربع)

حزمة جديدة `webpent.autonomous.amplifiers` بـ15 بندًا على 4 طبقات، كلها
advisory بالكامل: لا سلطة تنفيذ جديدة، لا شبكة من داخلها (كل جالب خارجي
محقون قابل للاستبدال بـdouble في الاختبارات)، redact لكل نص محفوظ، حدود
صارمة، ملف تالف → فارغ، وفشل أي وحدة لا يكسر جولة أبدًا.

- **الطبقة 1 — تقوية العين**: `takeover.py` (ماسح Subdomain Takeover
  ببصمات 10 خدمات على سجلات CNAME)، `cloud_storage.py` (مولّد permutations
  لدلاء S3/GCS/Azure + مصنف استجابات مفتوح/محمي)، `wayback.py` (استخراج
  endpoints تاريخية من صيغة CDX كبذور discovery)، `js_analyzer.py` (تحليل
  JS ساكن: بصمات مفاتيح مرشحة، auth معلّق، URLs تطوير، feature flags،
  إصدارات API)، `ct_mining.py` (تعدين crt.sh لتصفية subdomains داخل
  النطاق).
- **الطبقة 2 — تقوية الجودة**: `skeptic.py` (بروتوكول شكّ ذاتي رباعي
  قبل الثقة: cache-buster، تكرار إحصائي 2/3، جلسة طازجة، إعادة توقيت؛
  الحكم advisory لا يمنع الترقية أبدًا)، `triager_sim.py` (محاكاة
  triager بـ7 أنماط رفض معروفة: duplicate/NA)، `fp_autopsy.py` (تشريح
  الرفض إلى دروس ملفية تخفّض ترتيب بذور النمط نفسه لاحقًا — إعادة ترتيب
  لا حذف، بعقد dead-ends).
- **الطبقة 3 — تقوية الأداء**: `swarm.py` (تمرير حتمي محتمد بين خمسة
  أدوار: Scout/Striker/Philosopher/Skeptic/Scribe، بلا خيوط بلا عمليات)،
  `operational.py` (ذكاء زمني لنوافذ deploy والتكرار الدوري، خريطة
  rate-limit لكل endpoint مع مشتبهات unbounded، طوبولوجيا جلسات لمؤشرات
  fixation وriding وlogout ناقص).
- **الطبقة 4 — الحدس**: `intuition.py` (كاشف شواذ إحصائي نقي بوسيط/MAD
  وz-score قوي، ذاكرة عبر الأهداف: بصمة تقنية → كلاسات مُثبتة تُقترح
  advisory لأهداف جديدة بنفس البصمة، وتقييم جودة الفرضيات
  specificity/evidence/testability بإعادة ترتيب لا تحذف).
- **الربط**: تصدير كامل من `webpent.autonomous`، ودالتا تجميع advisory
  في `hunt_runtime` (`advisory_recon_summary`,
  `advisory_cross_target_suggestions`) لا يستدعيهما السلوك الافتراضي
  أبدًا.

## 0.6.0 — 2026-10-15 (v81: الذاكرة السلبية + وازن ميزانية الجولات)

- **ذاكرة المآزيق (`webpent.autonomous.hunt_deadends`)**: نظير سلبي
  لمتجر الاستخبارات — `DeadEndStore` يحفظ لكل origin أزواج
  (vuln_class, endpoint) التي حُسمت نظيفة بنتيجة منفذة حقيقية فقط
  (`clean`، أو `executed` مع `vulnerable` falsy). المحظور وغير المحسوم
  والمؤكد الثغرة لا يدخلان أبدًا؛ حفظ ذري، ملف تالف → ذاكرة فارغة، حدود
  64 origin/48 pair، redact وبلا استعلامات ولا أسرار. عبر
  `hunt-auto --deadends`.
- **وازن الميزانية (`webpent.autonomous.hunt_budget`)**: دالتان نقيتان
  تحوّلان نسبة المآزيق إلى توصيات: سقف جولات rehypothesize الهادئة
  (3 → 1 على هدف مُمسوح بالكامل) وتوصية ميزانية الجولة في التقرير.
  تخفيض فقط، أرضية 1، لا يرفع أي حد أبدًا؛ بلا متجر يبقى سلوك v80
  كما هو.
- **التخفيض الإشاري فقط**: seeds حزم التغطية المطابقة لمآزيق مسجلة
  تُخفَّض أولويتها (زوجي 0.25 / كلاس-مستوى 0.10 بعد زوجين) لكنها تبقى في
  القائمة؛ seeds الـintel ذات الدليل المُثبت وفرضيات الاكتشاف والفجوات
  ذات الدليل الطازج لا تُخفَّض أبدًا: الذاكرة السلبية لا تكبح دليلًا
  جديدًا. كل تخفيض ظاهر في سجل المراحل.
- الربط: `wire_orchestrator(..., deadends=...)` و`run_wired_hunt`،
  تحديث وحفظ في كل دورة تعلم، وفشل المتجر لا يكسر جولة أبدًا.

## 0.5.0 — 2026-10-15 (v80: ذاكرة تعبر الجلسات + تغطية المدققات الناقصة)

- **ذاكرة استخبارات لكل هدف (`webpent.autonomous.hunt_intel`)**:
  `IntelStore` يخزّن لكل origin الكلاسات المُثبتة بـ proof bundles فقط
  + مسارات endpoint بلا استعلام وبلا أسرار (حدود 64 origin/32
  endpoint/16 class)، حفظ ذري، ملف تالف → ذاكرة فارغة بلا انهيار،
  وseeds فرضيات advisory بأولوية ≤ 0.75. عبر `hunt-auto --intel`.
- **حزم تغطية (`webpent.autonomous.coverage_packs`)**: أربع حزم
  advisory للكلاسات بلا مدققات (SSTI، XXE، SSRF/OOB، BACKUP_FILES)
  بأوصاف probe ومتطلبات oracle بلا أي payload قابل للتنفيذ، وصفوفها
  ظاهرة في أجندة الاكتشاف بحالة صادقة `missing-validator`.
- **إعادة فحص التفويض داخل الحلقة**: `hunt-auto` يعيد التحقق من ملف
  التفويض أول كل دورة؛ استبدال الملف أو انتهاء صلاحيته في منتصف الجولة
  يوقفها BLOCKED بـ stop_reason جديد `authorization_revoked_mid_hunt`
  (صارم ومقصود).
- الربط: `wire_orchestrator(..., intel=..., auth_recheck=...)`، دمج
  seeds بلا تجاوز السقف 8/دورة مع dedup عبر الجولات، وفشل الذكاء لا
  يكسر جولة أبدًا.

## 0.4.0 — 2026-10-15 (v73 → v78، الإصدار القابل للنشر)

- **حزمة النشر (v78)**: بوابة تفويض إلزامية `--authorization` لـ
  `hunt-auto` (بلا تفويض صالح لا يُرسل طلب واحد؛ `--dry-run` معفي)،
  مولّد تقرير ارتباط Markdown/HTML self-contained عبر `--report`،
  رقم نسخة موحد 0.4.0، ودليل نشر وعمليات.
- **محرر الإصلاح الذكي (v77)**: باكج `webpent.remediation` (12 وحدة):
  أنماط CWE لكل الكلاسات الحقيقية، أسباب جذرية، سياقات، locators آمنة،
  سيناريوهات، أثر، قوالب إصلاح، قوائم تحقق بشرية، خطة عمل ثلاثية، لوحة
  أولويات، تقرير مطور، ملخص تنفيذي. Advisory-only بالكامل.
- **Red team على v77 (v77.1)**: 5 باغات مثبتة أُصلحت (KeyError على
  UNKNOWN في لوحة الأولويات، تسريب بيانات اعتماد في origin، اختراع
  class "None"، إهمال findings حاملة enum، إعادة عرض findings مُخطاة)،
  وتوحيد فك الحقول في `remediation/_fields.py`.
- **محرك الاكتشاف التكيفي (v75-v76)**: بناء checklist ذاتي من سجلات
  الجولات (مراقبة شواذ بعتبات مزدوجة، تصنيف عبر الجولات، seeds
  فرضيات، candidates routes/params/endpoints، هجينة مبنية على دليل)
  مع red-team remediation موثق.
- **حلقة الصيد الذاتية (v73-v74)**: orchestration، ربط runtime حقيقي
  بعقود G-02، تحقق proof bundles، ذاكرة تعلم مقيّدة، أمر
  `webpent hunt-auto`، توثيق تأهيل وتتبع.

## 0.3.0 — 2026-10-14 (v60 → v72)

- Smart Hunter: حملات ذكية، محرك فرضيات، طبقة remediation أولى،
  Knowledge Pack للـRAG، بوابة تحقق 865 اختبارًا.

## 0.2.x — قبل 2026-10-14

- بناء الإطار الأساسي: بروكسي، مصادر، validators، إسناد، CLI.
