# WebPent — Project Zero-tier: التسليم النهائي (7/7 بنود)

**الحالة: 128/128 اختبار ناجح، صفر فشل، lint نظيف بالكامل.**

هذا الملف يوثّق بصراحة كل حاجة اتعملت في الجلستين: البناء الأساسي للبنود السبعة،
وبعدها مرحلة نقد ذاتي صارمة لقيت فيها باگ حقيقي واحد وفجوات تغطية كانت لازم تتصلح.

---

## 1. ملخص الحالة النهائية

| # | البند | الملفات | عدد الاختبارات |
|---|------|---------|----------------|
| 1 | Taint tracking عبر الجلسات | `models/taint.py`, `memory/taint_tracker.py` | 16 |
| 2 | Attack surface dependency graph | `shared/surface_influence_graph.py` | 18 |
| 3 | Shadow/canary detection testing | `shared/shadow_detector.py` | 13 |
| 4 | Attack surface drift detection | `shared/surface_drift.py` | 16 |
| 5 | Red-vs-blue internal loop | `shared/red_vs_blue.py` | 13 |
| 6 | Postmortem structure | `models/postmortem.py`, `memory/postmortem.py` | 23 |
| 7 | CVE/version correlation | `shared/tech_stack_cve.py` | 29 |
| | **الإجمالي** | | **128** |

---

## 2. خلفية مهمة: إيه اللي كان موجود فعلًا قبل ما أبدأ

لما بدأت الثريد ده، عملت audit كامل للكود قبل ما أكتب أي سطر، والتزامًا بتعليمات
ملف الـ handoff ("متفترضش إن حاجة ناقصة من غير ما تتأكد بالكود الأول")، اكتشفت إن
**البنود 1، 3، 5 كانت خلصت فعلًا** من جزء سابق من نفس الجلسة مكنش ظاهر في الـ
context بتاعي وقتها. أكدت كده بتشغيل الاختبارات الحقيقية بتاعتهم مش بس بالنظر
للملفات. البنود **2، 4، 6، 7** كانت فعلًا ناقصة وبنيتها من الصفر.

كمان لقيت إني بنيت نسخة تانية مكررة من بند 3 (`shadow_canary.py`) قبل ما
أكتشف إن `shadow_detector.py` موجود بالفعل بتصميم أحسن (detector-agnostic بدل
ما يحتاج finding-key sets جاهزة) — مسحت نسختي عشان منسيبش تنفيذين متنافسين
لنفس البند.

---

## 3. 🐛 الباگ الحقيقي اللي اتلقى في مرحلة النقد الذاتي (بند 7)

### المشكلة
دالة مقارنة الإصدارات `_version_lte()` في `shared/tech_stack_cve.py` كانت
بتستخرج **كل** الأرقام من سترينج الإصدار بـ regex بسيط `\d+` بالطريقة دي:

```python
_VERSION_TOKEN_RE = re.compile(r"\d+")
tokens = _VERSION_TOKEN_RE.findall(version)
```

المشكلة: لو الإصدار فيه suffix شائع جدًا في الواقع زي `rc1` أو `beta2` أو `p1`
(موجود كتير في headers حقيقية زي `Server: Apache/2.4.49rc1`)، الرقم اللي في
آخر الـ suffix ده كان بيتفسر غلط كجزء إضافي من رقم الإصدار:

```
"2.4.49rc1"  →  (2, 4, 49, 1)   # غلط! ده أعلى من 2.4.49 نفسها
"2.4.49"     →  (2, 4, 49)
```

النتيجة العملية: لو السيرفر شغال نسخة **فيها ثغرة معروفة** بس مكتوبة بصيغة
`rc`/`beta`/`p`، الأداة كانت **مش هتكتشف التطابق** مع الـ CVE feed — يعني
false negative فعلي في بالظبط الحالة اللي بند 7 اتعمل عشانها (اكتشاف ثغرات
N-day بناءً على نسخة السيرفر).

### الإصلاح
غيّرت الـ regex عشان ياخد بس الجزء الرقمي المتصل من الأول (`^\d+(\.\d+)*`)
ويتجاهل أي suffix تمامًا (مش يحاول يفهمه، مش يدور على أرقام جواه):

```python
_VERSION_CORE_RE = re.compile(r"^\s*v?(\d+(?:\.\d+)*)")
```

دلوقتي `"2.4.49rc1"` و`"2.4.49-beta2"` و`"2.4.49"` الثلاثة بيتقارنوا كـ
`(2, 4, 49)` بالظبط — مفيش افتراض إن الـ pre-release أقدم أو أحدث، بس
تجاهل كامل للجزء اللي مش رقم أساسي (موثّق صراحة في الكود إن ده تحفظ متعمد).

### التأكد
- ضفت اختبار regression صريح (`test_version_lte_rc_suffix_does_not_corrupt_comparison`)
  بيمنع رجوع المشكلة دي تاني.
- جربت الـ pipeline كامل من الأول للآخر: `fingerprint_tech_stack()` على
  `Server: Apache/2.4.49rc1` → `correlate_cves()` مع CVE-2021-41773 (ثغرة
  Apache path traversal حقيقية ومعروفة) → اتأكد إن التطابق بيحصل صح دلوقتي.

---

## 4. فجوات تغطية اتصلحت (مش باگات منطقية، لكن اختبارات ناقصة خطيرة)

### بند 4 و2 — الاختبارات الأصلية كانت بس ضد fixtures يدوية
الاختبارات الأولانية بتاعة `surface_drift.py` و`surface_influence_graph.py`
كانت بتستخدم `SurfaceNode`/`SurfaceEvidenceGraph` مبنيين يدوي، مش الناتج
الحقيقي من `build_surface_evidence_graph()` اللي الكود الفعلي بيستخدمه.
ضفت integration tests حقيقية بتنده على الدالة الحقيقية عشان أتأكد إن
افتراضاتي عن شكل الـ `node_id` (hash من `node_type|label|method`) صحيحة
فعلًا مش بس في خيالي.

### بند 2 — توضيح حدود النطاق
اكتشفت إن فيه أجزاء تانية من الكودبيز (`agents/target_understanding/agent.py`)
بتقبل مفاتيح بديلة زي `urls`/`links`/`pages`/`resources` لقايمة الـ endpoints،
مش بس `endpoints`. فحصت وأكدت إن `build_surface_evidence_graph` (اللي بند 2
مبني فوقه) **برضه** بيقبل بس `endpoints` + الـ 3 مفاتيح التانية (مش المفاتيح
البديلة دي) — يبقى الكود بتاعي متوافق صح مع الموديول اللي قلت إني بنيت
عليه. وضحت الحدود دي صراحة في الـ docstring وضفت اختبار يوثقها، عشان حد
تاني ميفترضش نطاق أوسع مما هو فعلًا مدعوم.

### بند 6 — الـ workspace-scoping متكنش اتختبر خالص
الدالة `get_postmortem_manager()` بتاعة عزل قاعدة البيانات حسب كل engagement
(باستخدام `TargetWorkspace` و`activate_target_workspace`) كانت مكتوبة بس
الاختبارات الأصلية متكنش بتشغلها فعليًا — كانت بس بتختبر fallback للـ
singleton العادي. جربتها بـ `TargetWorkspace.for_target()` حقيقي، واتأكد
إن العزل شغال صح (كل engagement بياخد قاعدة بيانات منفصلة، والبيانات ما
بتسربش بين الاثنين). ضفت 2 اختبارات جديدة بتثبت السلوك ده.

### الربط بين `devils_advocate` و`postmortem` — اتأكد عليه فعليًا
كنت بس بتأكد إن الموديول بيتعمله `import` بنجاح، من غير ما أجرب الدالة
فعليًا بـ `Finding` حقيقي. جربتها دلوقتي end-to-end: بنيت `Finding` كامل
بكل الحقول المطلوبة، ونديت `_record_devils_advocate_postmortem()` عليه،
واتأكدت إن الـ postmortem record بيتسجل صح بكل الحقول (category, finding_id,
vuln_class, thread_id, campaign_id). كمان جربت الحالة الدفاعية: لو كتابة
الـ postmortem فشلت (مثلاً قاعدة البيانات واقعة)، الكود بيمسك الخطأ ويسجله
بـ `logger.warning` وما بيكسرش تنفيذ الـ graph — اتأكد من ده فعليًا مش بس
افتراض.

---

## 5. حاجات فحصتها في مرحلة النقد وطلعت سليمة (مش باگات)

- **حساسية حالة الأحرف في أسماء الـ parameters** (بند 2): لو نفس الـ
  parameter ظهر بـ `Account_Token` في endpoint و`account_token` في تاني،
  الكود بيعتبرهم مختلفين. ده سلوك متعمد صحيح (أسماء الـ HTTP parameters
  فعلًا case-sensitive)، مش باگ — قررت ميتغيرش عشان مطابقة case-insensitive
  ممكن تنتج ارتباطات وهمية (false correlations).

- **فحصت وشككت** إن `decision_log_database_path` مش موجودة فعليًا على
  `TargetWorkspace` (ظنيت إني فبركتها زي الحالة اللي حصلت قبل كده مع
  exception classes) — ده كان غلط مني، كنت بفتش في ملف غلط
  (`target_workspace_context.py` بدل `target_workspace.py`). اتأكد إنها
  موجودة وشغالة صح 100%.

---

## 6. طريقة التأكد

```bash
cd project
PYTHONPATH=src python3 -m pytest \
  tests/test_postmortem.py \
  tests/test_tech_stack_cve.py \
  tests/test_surface_drift.py \
  tests/test_surface_influence_graph.py \
  tests/test_taint_tracker.py \
  tests/test_shadow_detector.py \
  tests/test_red_vs_blue.py \
  -v
# => 128 passed
```

كل ملف من السبعة اتعمله `ruff check --select=E,F,I,UP` نظيف، و`ast.parse`
نظيف، وكل اختبار اتشغل فعليًا (مش افتراض) ضد قواعد بيانات SQLite حقيقية
(in-memory وfile-backed)، وضد `Finding`/`SurfaceEvidenceGraph` حقيقية مش
mocks، وضد الـ conftest الفعلي بتاع المشروع (مش tests منعزلة).

---

## 7. حاجات لسه مفتوحة / حدود معروفة

- لا تم بناء live CVE feed fetcher فعلي (بند 7 بياخد catalog محقون من
  برّه، بنفس فلسفة `kev.py` الموجودة أصلًا في الكودبيز — قرار معماري متعمد،
  مش نقص).
- مفيش تعديل على `shared/prioritization.py`'s الـ `_W_SUM` scoring system —
  بند 2 و4 بيطلعوا إشارات أولوية/ثقة منفصلة كـ output منظم، بدل ما يتعاملوا
  مباشرة مع النظام ده، بالظبط زي ما ملف الـ handoff حذّر من كسر الـ
  invariants بتاعته.
- `_version_lte()` دلوقتي بتتجاهل أي pre-release suffix بالكامل (تعتبر
  `2.4.49rc1` و`2.4.49` ومتساويين تمامًا) — ده تحفظ متعمد وموثق، مش محاولة
  لفهم ترتيب الـ pre-releases (اللي محتاج معرفة بقواعد semver الخاصة بكل
  مشروع، مش حاجة عامة ممكن نفترضها بأمان).
