# الاقتراح المركزي الرابع: ذاكرة تعبر الجلسات + تغطية المدققات الناقصة (v80)

التاريخ: 2026-10-15. الفكرة: المحرك الحالي يبدأ كل جولة من الصفر،
وكلاسات حقيقية (SSTI/XXE/SSRF/نسخ احتياطية) بلا تغطية في جدول الأجندة،
والتفويض يُفحص مرة واحدة عند البدء. v80 يعالج الثلاثة.

## القواعد الثابتة (تمسّك بها كل مهمة)
- الذكاء المُخزن advisory فقط: يولّد seeds فرضيات بلا ادعاء نتيجة.
- لا أسرار ولا قيم استعلام في أي ملف ذكاء: أصل الهدف + مسارات فقط،
  بيانات اعتماد تُشطب، كل نص عبر `redact`.
- ملف ذكاء تالف → يُهمل بصمت مع سطر لوج، لا انهيار جولة.
- الحزم الجديدة candidates: status ثابت "missing-validator" حتى يوجد
  proof bundle حقيقي؛ لا يصرّفها المحرك إثباتًا أبدًا.

## Task 1 — ذاكرة استخبارات لكل هدف (`autonomous/hunt_intel.py`)
Files: create `src/webpent/autonomous/hunt_intel.py`, update
`autonomous/__init__.py`, create `tests/test_hunt_intel.py`
1. `IntelStore(persist_path)`: JSON واحد مفاتيحه origins.
   سجل الorigin: `verified_classes` (من proof bundles فقط، عدّاد
   لكل vuln_class)، `endpoint_hints` (مسارات بلا استعلام، بلا بيانات
   اعتماد، حد 32)، `updated_at`. حدود: 64 origin كحد أقصى (الأقدم
   يُحذف)، كل نص عبر redact.
2. `update_from_state(state)`: يستخرج من `state.proof_bundles` فقط
   (المُتحقق منه حصريًا) بفضل وصول متسامح على المفاتيح؛ لا يلمس
   findings المرشحة.
3. `hypothesis_seeds(origin, cap=8)`: seeds advisory بنفس شكل seeds
   الـreplanning (vuln_class، priority ≤ 0.75، rationale، advisory=True)
   — الأولوية للكلاسات المثبتة سابقًا (احتمال إعادة العثور أعلى).
4. `load()` صارم: JSON تالف/نوع خاطئ → store فارغ + سطر لوج؛
   `save()` ذري عبر ملف مؤقت + rename.
5. الربط: `wire_orchestrator(..., intel: IntelStore | None = None)`;
   في نهاية `_phase_learn` إن وُجد intel: تحديث + حفظ؛ في
   `_phase_rehypothesize` إن وُجد: دمج seeds الذاكرة مع seeds الفجوات
   (بلا تجاوز الحد 8 الإجمالي، ذكاء أولًا ثم فجوات).
6. الاختبارات: تحديث من bundles فقط، redaction (لا hunter2 ولا قيم
   استعلام)، حدود، تخزين/تحميل دائري، ملف تالف يُهمل، دمج seeds،
   بلا intel لا يتغير السلوك.

## Task 2 — حزم تغطية المدققات (`autonomous/coverage_packs.py`)
Files: create `src/webpent/autonomous/coverage_packs.py`, update
`autonomous/__init__.py`, create `tests/test_coverage_packs.py`
1. `CoveragePack`: `class_label`، `probes` (أوصاف probe advisory)،
   `required_oracles`، `status="missing-validator"` ثابت.
2. `PACKS`: SSTI، XXE، SSRF/OOB، BACKUP_FILES — أربع حزم بأوصاف
   probe محددة (بدون أي payload فعلي قابل للتنفيذ؛ أوصاف اكتشاف و
   متطلبات oracle: OOB callback أو replay مثبت).
3. `pack_ledger_entries(seen_classes)`: صفوف جدول تغطية (صافي/مفقود
   حسب ما اختُبر)، `pack_hypothesis_seeds(cap)` لأجندة الجولة.
4. الربط: `_phase_plan`/`build_discovery_agenda` (نقطة واحدة) تضيف
   صفوف الledger؛ seeds الحزم تُدمج في rehypothesize بعد ذكاء
   الهدف ثم فجوات الجولة، بلا تجاوز السقف.
5. الاختبارات: الشكل، الصدق (لا صف يُصبح "confirmed" بلا bundle
   حقيقي)، الدمج لا يتجاوز السقف، الاستيراد عبر `__init__`.

## Task 3 — إعادة فحص التفويض داخل الحلقة
Files: `autonomous/hunt_runtime.py`, `cli/commands.py`,
`tests/test_hunt_intel.py` (قسم) و`tests/test_autonomous_hunt_cli.py`
1. `wire_orchestrator(..., auth_recheck: Callable[[], str | None] | None)`:
   تُستدعى أول كل دورة؛ إرجاع نص رفض → الجولة تتوقف BLOCKED مع
   stop_reason جديد `AUTHORIZATION_REVOKED` وstate.reason الرسالة.
2. CLI: `hunt-auto` يمرر recheck يستخدم `verify_authorization` على
   نفس الملف (يعيد القراءة كل دورة: تعديل الملف أثناء الجولة يُلقي
   بها — صارم ومقصود).
3. الاختبارات: recheck يرفض في الدورة الثانية → BLOCKED، recheck None
   لا يغير شيئًا، وCLI: ملف يُستبدل بمحتوى منتهي بين الدورتين → exit 1.

## Task 4 — هندسة الإصدار
1. النسخة 0.5.0: `pyproject.toml` + `__init__` + تحديث
   `test_release_packaging` + إدخال CHANGELOG.
2. صف traceability v80 + سطر README + بوابات الإصدار كاملة
   (pytest/ruff/direct-IO/ZIP).

## معيار الإنجاز
- ذكاء هدف يُحفظ ويُقرأ ويغير seeds الجولة القادمة فعليًا (اختبار
  يثبت الفرق بين جولة بلا ذكاء وجولة به).
- كلاسات SSTI/XXE/SSRF/BACKUP لها صفوف تغطية ظاهرة في الأجندة.
- انتهاء التفويض في منتصف جولة يوقفها BLOCKED ولا طلب بعده.
- بوابات الإصدار خضراء بأدلة حديثة.


## سجل التنفيذ (أدلة حديثة — 2026-10-15)
- الاختبارات الجديدة: `tests/test_hunt_intel.py` (14) و
  `tests/test_coverage_packs.py` (4) و +2 في
  `test_autonomous_hunt_cli.py` (استبدال ملف التفويض بين الدورتات →
  exit 2، و--intel يُنشئ ويحفظ store مفاتيحه الorigin).
- معيار الإنجاز (الفرق بين جولة بلا ذكاء وجولة به) مثبت باختبار
  `test_intel_changes_the_next_round_hypotheses`: الجولتان متطابقتان
  إلا في seeds `advisory:intel:*`.
- البوابات: 2337 passed / 0 failed (كامل الـsuite)، Ruff نظيف على كل
  ملف ملموس، direct-IO 4/4 بعد إعادة توليد متعمدة بمراجعة diff
  (637 → 639: كل المواقع الجديدة getattr dynamic_resolution في وحدات
  advisory فقط)، ZIP أعيد بناؤه.

### النقد الذاتي على v80 (تم إصلاحه كلดورة repro-first)
- CR-1: seeds الحزم كانت بأولوية 0.75 مسطحة بلا أي دليل — كانت ستفوق
  في الترتيب seeds الذاكرة المدعومة بإثبات (0.5-0.75). صُححت إلى ≤ 0.5.
- CR-2: جولة بلا أي proof bundle كانت تنشئ سجل origin فارغًا يلوث ذاكرة
  الـ64 origin. صُحح: لا سجل بلا أدلة.
- CR-4: روابط bundles من origin آخر كانت تدخل hints الهدف. صُحح:
  الفلترة per-origin صارمة.
- CR-5: بوابة التفويض في الحلقة كانت تلتقط AuthorizationError فقط؛ أي
  فشل آخر (أذونات/حذف الملف بصيغة غير متوقعة) كان قد يُسقط الجولة
  بخطأ بدل إيقافها BLOCKED. صُحح: fail-closed على أي استثناء.
- CR-3: سطران ميتان في update_from_state (حساب origin مرتين). حُذفا.
- التوثيق: اختبار CLI --intel كان يفترض سجلًا فارغًا؛ حُدّث ليعكس
  السلوك الصحيح بعد CR-2 (المستند = {}).
- الأدلة النهائية: 2341 passed / 0 failed، Ruff نظيف على الملفات
  الملموسة، direct-IO 4/4 (639 → 639، إزاحة أسطر فقط).
