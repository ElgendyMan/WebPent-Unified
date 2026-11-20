# الاقتراح المركزي الثالث: حزمة النشر — من مشروع إلى منتج (2026-10-15)

webpent بنى قدرات المحرك كاملة (حلقة، اكتشاف تكيفي، إصلاح ذكي) لكنه
لسه غير قابل للنشر كمنتج: لا بوابة تفويض إلزامية عند التشغيل الفعلي،
لا تقرير ارتباط قابل للتسليم لصاحب الهدف، لا هندسة إصدار (نسخة موحدة،
CHANGELOG، اختبار تثبيت)، لا دليل عمليات. هذا الاقتراح يغلق فجوة النشر
بالضبط، بأربع مراحل.

## مبادئ ثابتة (غير قابلة للتفاوض)

- **التفويض بوابة صلبة لا إرشاد**: hunt-auto بدون تفويض صالح لا يرسل
  طلبًا واحدًا — خروج برمز 1 برسالة واضحة. (dry-run معفي لأنه لا يلمس
  الشبكة.)
- **التقرير machine-derived فقط**: مولّد التقرير دالة نقية فوق
  `to_report_json()` الحالي؛ لا يخترع نتيجة، وكل قسم يحمل non_claim
  إن وُجد في المصدر، والـHTML self-contained بلا أي مورد خارجي،
  وredaction-safe (يستخدم الـpayload المخفّى كما هو).
- **صدق الإصدار**: رقم النسخة مصدر واحد، وCHANGELOG يوثق ما بُني فعليًا
  بالتواريخ، والاختبار يثبت التثبيت.

## المراحل

### Task 1 — بوابة التفويض `autonomous/authorization.py`
1. `EngagementAuthorization` (frozen dataclass): `target_origin`,
   `scope` (قائمة origins), `operator`, `authorization_reference`,
   `expires_at` (datetime اختياري).
2. `verify_authorization(target_url, auth, now=None) -> (ok, reason)`:
   مطابقة origin-level مع strip الـuserinfo، ورفض المنتهي تاريخه،
   ورفض scope الفارغ، وreason صريح في كل رفض.
3. `load_authorization(path) -> EngagementAuthorization`: JSON صارم
   برسائل خطأ قابلة للفهم (حقل ناقص، تاريخ فاسد، JSON فاسد).
4. اختبارات: قبول صالح، رفض mismatch، رفض منتهي، رفض scope فارغ،
   رفض JSON فاسد/ناقص.

### Task 2 — توصيل البوابة في `hunt-auto`
1. خيار `--authorization PATH` إلزامي إلا مع `--dry-run`.
2. التحقق بعد بناء الـruntime وقبل `run_wired_hunt`؛ رفض → exit 1.
3. تحديث `test_hunt_auto_stops_bounded_without_target_knowledge`
   (يمرر تفويضًا صالحًا) + اختبار CLI جديد: بدون تفويض → exit 1 ولا
   تشغيل.
Done-when: الاختبارات خضراء والرفض يحدث قبل أي طلب.

### Task 3 — مولّد تقرير الارتباط `reporting/engagement_report.py`
1. `build_engagement_report(payload, fmt) -> {content, fmt, non_claim}`
   دالة نقية فوق `to_report_json()`: Markdown وHTML.
2. أقسام: رأس metadata، executive_summary، priority_dashboard (جدول)،
   findings (جدول: id/title/severity/vuln_class فقط)، remediation
   non_claim، hypothesis_origins، discovery_summary. القسم الغائب
   يُتخطى بلا اختراع.
3. HTML: `html.escape` على كل نص، CSS inline، صفر موارد خارجية.
4. خيار `--report PATH` في hunt-auto (HTML لـ.html وإلا Markdown).
5. اختبارات: أقسام موجودة/غائبة، عدم تسريب قيم query في التقرير،
   عدم وجود `src=` أو `href="http` خارجي في HTML، وجود non_claim،
   هروب النصوص.

### Task 4 — هندسة الإصدار
1. النسخة 0.4.0 في `pyproject.toml` وفي `webpent/__init__.py`
   (مصدران متزامنان ب اختبار يثبت التطابق).
2. `CHANGELOG.md` بتاريخ 2026-10-14/15: v60→v77.1 ملخص صادق.
3. اختبار تثبيت الدخان: `pip install -e . --no-deps` في venv المشروع
   ثم `webpent --help` و`webpent hunt-auto --help` يعملان.

### Task 5 — دليل النشر `docs/deployment_guide.md`
عربي: المتطلبات، التثبيت، عقد التفويض (مثال JSON)، runbook
(dry-run → مفوّض → تقرير)، حدود الصدق، استكشاف الأخطاء.

### Task 6 — بوابات الإصدار
خطة موثقة + صف traceability + سطر README + pytest كاملة + ruff +
جرد direct-IO + ZIP محدث.

## سجل التنفيذ (2026-10-15)

جميع المهام الست نُفذت بالكامل، والأدلة حديثة من نفس يوم الإغلاق:

- **Task 1-2 (بوابة التفويض + ربط CLI)**: `autonomous/authorization.py`
  + `--authorization/-A` في `hunt-auto`. بلا تفويض صالح لا يُرسل طلب
  واحد (exit 1)، و`--dry-run` معفي. 11 اختبارًا في
  `test_engagement_authorization.py` + 3 اختبارات بوابة في
  `test_autonomous_hunt_cli.py`.
- **Task 3 (تقرير الارتباط)**: `reporting/engagement_report.py` +
  `--report`. 7 اختبارات في `test_engagement_report.py` تشمل
  self-contained HTML والتهريب وعدم ظهور قيم الاستعلام.
- **Task 4 (هندسة الإصدار)**: 0.4.0 متزامن، `CHANGELOG.md`، 3 اختبارات
  `test_release_packaging.py`، دخان تثبيت ناجح (`webpent hunt-auto
  --help` يعرض الراويتين).
- **Task 5 (دليل النشر)**: `docs/deployment_guide.md` عربي كامل.
- **Task 6 (بوابات الإصدار)**:
  - pytest كاملة: **2311 passed, 0 failed**
    (`PLAYWRIGHT_BROWSERS_PATH=/home/thaura/pw-browsers
    PYTHONPATH=src /home/thaura/venv/bin/python -m pytest -q`).
  - ruff: نظيف على كل الملفات الجديدة (أُصلحت 3 خطوط E501 في
    `engagement_report.py`)؛ B008 في `commands.py` هي اتفاقية Typer
    قائمة في الملف كله (14 حالة، 11 سابقة) ولم تُمس.
  - direct-IO: انحراف سطري فقط في `commands.py` (موقعا `__import__`
    1540-1541 → 1587-1588)، أُعيد توليد الجرد عمدًا بمراجعة diff:
    **صفر مواقع IO جديدة**. 4/4 اختبارات G-02 ناجحة.
  - صف traceability v78 + سطر README 0.4.0/2311.
  - ZIP: `webpent_v78_autonomous_bug_hunter.zip`.
