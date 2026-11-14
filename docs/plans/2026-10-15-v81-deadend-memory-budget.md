# خطة v81: الذاكرة السلبية (Dead-End Memory) + وازن ميزانية الجولات

التاريخ: 2026-10-15 · الاقتراح المركزي الخامس · النسخة المستهدفة: 0.6.0

## المشكلة

v80 أعطت المشروع ذاكرة إيجابية (`IntelStore`: الكلاسات المُثبتة لكل هدف) وذكرة
تغطية (حزم الكلاسات الناقصة)، لكن الصياد ما زال أعمى تجاه الفشل: **لا شيء يُسجَّل
عن المسارات والكلاسات التي حُسمت سلبًا بالفعل**. كل جولة جديدة قد تعيد حرق
ميزانيتها على نفس (class, endpoint) الذي أثبتت جولة سابقة أنه نظيف، والحلقة
لا تفرّق بين "جولة هادئة تستحق فرصة rehypothesize أخرى" و"هدف ميت نتائجه
المعروفة سلفًا".

## الاقتراح المركزي

**ذاكرة سلبية معلنة عبر الجلسات + وازن ميزانية إشاري**: متجر `DeadEndStore`
يحفظ أزواج (vuln_class, endpoint) التي حُسمت نظيفة بنتيجة منفذة حقيقية،
و`hunt_budget` يحوّل نسبة المآزيق إلى توصية بعدد جولات rehypothesize المسموح
عند غياب دليل جديد. كلاهما advisory بالكامل: التخفيض يعيد الترتيب ولا يحذف،
والتوصية تقلّل الجولات فقط (أرضية 1، لا تتجاوز السقف أبدًا)، ولا بوابة
تُتجاوز ولا طلب يُصنع من هنا.

قيود صارمة موروثة من v80:

* لا شيء يدخل المتجر إلا نتيجة منفذة حاسمة (`clean`، أو `executed` مع
  `vulnerable` falsy). المحظور/غير المحسوم/المؤكد الثغرة لا يدخل أبدًا.
* التخفيض على seeds الـadvisory فقط (intel/packs)؛ فرضيات الاكتشاف والفجوات
  ذات الدليل الطازج لا تُخفَّض أبدًا: الذاكرة السلبية لا تكبح دليلًا جديدًا.
* كلاس مُثبت سابقًا على الهدف (intel verified) لا يُخفَّض أبدًا.
* ملف تالف → ذاكرة فارغة بلا انهيار؛ حفظ ذري؛ redact لكل نص؛ بلا استعلامات
  ولا أسرار؛ حدود صارمة (64 origin / 48 pair لكل origin).
* فشل الذاكرة السلبية لا يكسر جولة أبدًا (نفس عقد intel).

## بنية الملفات

* CREATE `src/webpent/autonomous/hunt_deadends.py` — `DeadEndStore`
  (تحميل/حفظ ذري، `update_from_state`، `penalty_for`، `dead_end_ratio`).
* CREATE `src/webpent/autonomous/hunt_budget.py` — دوال نقية:
  `recommend_rehypothesize_rounds(ratio)` و `recommend_round_budget(max_iterations, ratio)`.
* MODIFY `hunt_orchestrator.py` — حقن `deadends`، تحديث في LEARN، تخفيض
  advisory في `_merge_advisory_seeds`، سقف جولات الهدوء في الحلقة.
* MODIFY `hunt_runtime.py` — تمرير `deadends` في `wire_orchestrator` و
  `run_wired_hunt`.
* MODIFY `cli/commands.py` — خيار `hunt-auto --deadends` + حفظ بعد الجولة.
* MODIFY `autonomous/__init__.py` — تصدير `DeadEndStore` ودالتي الميزانية.

### Task 1: `DeadEndStore`
Files: create `src/webpent/autonomous/hunt_deadends.py`
1. اكتب الاختبارات الفاشلة في `tests/test_hunt_deadends.py`:
   `PYTHONPATH=src /home/thaura/venv/bin/python -m pytest tests/test_hunt_deadends.py -x`
   — ت تغطي: دخول النتائج الحاسمة السلبية فقط؛ رفض confirmed/vulnerable؛
   بلا أسرار ولا قيم استعلام؛ الحدود؛ ملف تالف → فارغ؛ حفظ ذري؛
   `penalty_for` (مطابقة زوجية 0.25، كلاس-مستوى 0.10 بعد زوجين)؛
   `dead_end_ratio` في [0,1]؛ فشل المتجر لا يكسر الجولة.
2. نفّذ الوحدة على نمط `hunt_intel.py` (نفس `_normalize_url`، redact،
   tempfile.mkstemp + os.replace، حذف الأقدم عند تجاوز MAX_ORIGINS).
3. أخضر + المجموعة الكاملة.

### Task 2: `hunt_budget`
Files: create `src/webpent/autonomous/hunt_budget.py`, `tests/test_hunt_budget.py`
1. اختبارات: النقاء والحتمية؛ النطاق [floor, base]؛ ratio=0 → base؛
   ratio=1 → floor؛ clamp للقيم خارج [0,1]؛
   `recommend_round_budget` أرضية 1 وسقف max_iterations.
2. التنفيذ: `max(floor, min(base, int(base*(1-ratio)+0.5)))` (تقريب نصف-أعلى
   محتمد) و`max(1, int(max_iterations*(1-0.5*ratio)+0.5))`.
3. أخضر.

### Task 3: تكامل المُنسّق
Files: modify `hunt_orchestrator.py`, `tests/test_hunt_intel.py`
1. اختبار فاشل: seeds الـadvisory المطابقة لزوج ميت تُخفَّض أولويتها لكنها
   تبقى في القائمة؛ فرضية discovery طازجة بنفس الكلاس لا تُخفَّض؛
   كلاس مُثبت في intel لا يُخفَّض.
2. اختبار فاشل: هدف نسبة ميّته عالية + جولات هادئة متتالية → الجولة تتوقف
   earlier بـ NO_NEW_EVIDENCE مع reason موثق `budget_capped_rehypothesis`،
   ودون deadends تظل السلوك القديم كما هو.
3. التنفيذ: حقل `self.deadends` + عدّاد `_quiet_rounds` يُصفَّر عند دليل
   جديد؛ تخفيض في `_merge_advisory_seeds` مع عدّاد في detail؛ سقف الهدوء
   يُفعَّل فقط عند وجود المتجر (صفر تأثير على الاختبارات القائمة).
4. أخضر + المجموعة الكاملة.

### Task 4: الربط و CLI
Files: modify `hunt_runtime.py`, `cli/commands.py`, `autonomous/__init__.py`,
`tests/test_autonomous_hunt_cli.py`
1. اختبار CLI فاشل: `--deadends path` يُنشئ الملف بعد الجولة ويبقى الرد
   محدودًا؛ ملف dead-ends تالف → الجولة تجري محدودة كما لو كانت فارغة.
2. التنفيذ: تمرير في `wire_orchestrator`/`run_wired_hunt`؛ خيار Typer؛
   بناء المتجر وحفظه بعد `run_wired_hunt`؛ تصدير الأسماء الجديدة.
3. أخضر + المجموعة الكاملة.

### Task 5: الإصدار
Files: modify `pyproject.toml`, `src/webpent/__init__.py`,
`tests/test_release_packaging.py`, `CHANGELOG.md`,
`docs/vip_autonomous_bug_hunter_traceability.md`, `README.md`
1. 0.6.0 في الملفات الثلاثة؛ مدخل CHANGELOG عربي؛ صف v81 في جدول التتبع
   مع بوابة الإصدار؛ سطر README.
2. إعادة توليد `docs/direct_io_inventory.json` عبر `scan_direct_io(Path("src"))`
   ومراجعة الـdiff (تحركات أسطر متوقعة فقط).
3. المجموعة الكاملة خضراء + ruff نظيف على الملفات الملموسة + ZIP جديد.

## معيار الإنجاز

* كل اختبار v80 + الاختبارات الجديدة خضراء (متوقع ≥ 2360).
* ruff نظيف على الملفات الجديدة والمعدّلة.
* direct-IO 4/4 بعد إعادة التوليد بمراجعة diff.
* ZIP `webpent_v81_autonomous_bug_hunter.zip` (~5.9M) مُسلَّم.

## سجل التنفيذ

التاريخ: 2026-10-15 · كل المهام نفذت بأسلوب repro-first (اختبار أحمر ثم تنفيذ ثم أخضر).

**Task 1 — `DeadEndStore`:** `tests/test_hunt_deadends.py` كُتب أولًا وأكد الأحمر
(9 اختبارات: دخول النتائج الحاسمة السلبية فقط، رفض confirmed/vulnerable/blocked/
inconclusive، بلا أسرار ولا قيم استعلام في الملف المحفوظ، الحدود 64/48، تراكم
hits للتكرارات، roundtrip + ملف تالف/خطأ نوع → متجر فارغ، حفظ ذري بلا temp
litter، `penalty_for` زوجي/كلاس-مستوي/أجنبي، `dead_end_ratio` محدودة، وحالات
outcomes فارغة/سيئة لا تغيّر شيئًا). ثم `hunt_deadends.py` على نمط `hunt_intel.py`
بالضبط. أخضر.

**Task 2 — `hunt_budget`:** `tests/test_hunt_budget.py` أحمر أولًا (5 اختبارات:
ratio=0 → base، ratio=1 → floor، رتيبة غير تزايدية ومحدودة، clamp وحتمية،
أرضية 1 لا صفر لكل (iterations, ratio)). التنفيذ دالّتان نقيتان فقط. أخضر.

**Task 3 — تكامل المُنسّق:** 5 اختبارات جديدة في `tests/test_hunt_intel.py`
(قسم "v81: dead-end memory integration"): تخفيض seeds الـadvisory المطابقة مع
بقاءها في القائمة وظهور `dead_end_demoted` في phase trace؛ كلاس مُثبت في intel
لا يُخفَّض (أولويته كما هي وبلا علامة dead-end)؛ بذرة discovery طازجة بنفس
الكلاس لا تُخفَّض (اختبار يستدعي `_merge_discovery_hypotheses` مباشرة لأن
`_phase_discover` يستبدل الحقن)؛ هدف نسبة ميّته 1.0 (16 زوجًا) يتوقف بعد جولة
منفذة واحدة بـ `budget_capped_rehypothesis` وrecommended_rounds=1؛ ودون متجر
يبقى السلوك القديم (جولتان ثم NO_NEW_EVIDENCE). أخضر مع صفر تعديل على
اختبارات v80 القائمة.

**Task 4 — الربط و CLI:** اختباران في `tests/test_autonomous_hunt_cli.py`
(المجموع 12): `--deadends` يُنشئ الملف بعد الجولة (exit 3 بلا تفويض،
المستند `{}`)؛ ملف تالف → الجولة تجري محدودة ويُعاد كتابة الملف `{}`.
التنفيذ: `wire_orchestrator`/`run_wired_hunt` تمرران `deadends`؛ خيار Typer
مع help يذكر أن التأثير advisory re-ranking فقط لا كبح دليل؛ حفظ المتجر بعد
الجولة؛ تصدير `DeadEndStore` ودالتي الميزانية من `autonomous/__init__.py`.
أخضر.

**Task 5 — الإصدار والجرد:** 0.6.0 في `pyproject.toml` و`src/webpent/__init__.py`
و`tests/test_release_packaging.py`؛ مدخل CHANGELOG عربي؛ صف v81 في جدول
التتبع؛ سطر README. جرد direct-IO أُعيد توليده مرتين (الأولى: 639 → 641،
سجلّا not_applicable getattr جديدان في `hunt_deadends.py`؛ الثانية بعد
إصلاحات ruff I001/SIM105: 4 تحركات أسطر فقط في `hunt_orchestrator.py`)؛
اختبارات الجرد 4/4 خضراء.

**بوابة الإصدار النهائية (طازجة، نفس الجلسة):** المجموعة الكاملة
`PLAYWRIGHT_BROWSERS_PATH=/home/thaura/pw-browsers PYTHONPATH=src pytest tests/ -q`
→ **2362 passed, 0 failures** في 120.58s. ruff نظيف على كل الملفات الجديدة
والمعدلة (استثناء: `cli/commands.py` يحمل B008/E501 على أسطر pre-existing
بنمط typer المعمول به في الملف كله — نفس النمط على خيار v80 `--intel` —
وأسطر v81 نفسها نظيفة). عدد الاختبارات الجديدة 21 (9 deadends + 5 budget +
5 intel + 2 CLI) = 2341 + 21 = 2362 مطابق تمامًا.

**تصحيح موثق أثناء الإغلاق:** سجل التتبع وREADME كتبا أولًا "2361 / 20 new
tests" تقديرًا قبل الجرد الدقيق؛ صُححا إلى 2362/21 بعد عدّ دوال الاختبار
فعليًا ومطابقته بعملية التشغيل الطازجة.

**الخلاصة:** معيار الإنجاز المحقق بالكامل (≥2360 متوقع، الواقع 2362؛ ruff
نظيف؛ جرد 4/4 بلا انحراف جديد؛ ZIP `webpent_v81_autonomous_bug_hunter.zip`
مُسلَّم).
