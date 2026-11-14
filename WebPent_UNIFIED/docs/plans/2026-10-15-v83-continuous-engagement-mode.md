# خطة v83 — وضع الارتباط المستمر CEM (Continuous Engagement Mode)

**التاريخ:** 2026-10-15 · **الإصدار المستهدف:** 0.8.0 (v83) · **الحالة:** قيد التنفيذ

## الفكرة

النقلة من "أداة بتتحقق مرة" إلى "حارس ساكن بيعيش مع الهدف": مراقبة تغيّرات
الهدف على مدى أسابيع وشهور، والتفاعل مع كل تغيير مهم بحملة مركزة، مع ذاكرة
طولية تتعلم إيقاع الهدف، وواجهة مشغّل بتقرير يومي وأوامر تحكم.

## القيود الموروثة (خط الدم — لا ينكسر)

1. **advisory فقط:** كل وحدة ترتب وتعلّق ولا تُرقّي دليلًا ولا تكتم دليلًا
   طازجًا؛ بوابة الـ proof المختومة هي سلطة الترقية الوحيدة.
2. **لا سلطة تنفيذ جديدة ولا شبكة من الداخل:** كل جالب خارجي `fetch_*`
   محقون قابل للاستبدال بـdouble في الاختبارات؛ **لا خيوط ولا عمليات ولا
   sleep ولا daemon:** "الاستمرارية" تُنفّذ كدورة pure
   `run_cem_cycle(state, *, now)` يستدعيها المشغّل أو مجدول خارجي (cron) —
   هذا ربط مقصود ومعلن لمبدأ لا سلطة تنفيذ جديدة، والاختبار يجري دورات
   متتالية بمحاكاة 72 ساعة على `now` الاصطناعي.
3. **كل الزمن محقون:** لا دالة زمن حقيقية داخل المنطق؛ `now` باراميتر.
4. **redact لكل نص محفوظ**؛ لا أسرار ولا قيم queries.
5. **حدود صارمة** لكل مخزن (snapshots لكل هدف، فرضيات، دروس، أسطر audit).
6. **ملف تالف/مفقود → فارغ/افتراضي، ولا استثناء أبدًا**؛ فشل وحدة لا يكسر
   الدورة.
7. **النطاق أمر مقدس:** ما خارج النطاق يُسجَّل "observed but out-of-scope"
   ولا يُلمس أبدًا.

## قرارات معمارية (ربط الاقتراح بمعمارياتنا)

- **التخزين JSON ذري** بنفس انضباط IntelStore/DeadEndStore بدل SQLite —
  نفس ضمانات الفساد والحفظ، وأقل اعتماديات؛ يُوثق هذا كانحراف مقصود.
- **الزمن:** epoch float محقون؛ التقويم (ساعات النشاط، أيام الأسبوع) يُشتق
  منه بـUTC الحتمي.
- **معيارا النجاح 1 و8** (72 ساعة تشغيل فعلي / 7 أيام بلا إنذارات كاذبة
  على هدف حقيقي) **معايير تشغيلية للمشغّل على هدف مفوّض**، لا تُثبت داخل
  sandbox؛ مقابلها داخل الشفرة: دورة idempotent، سقف ميزانية محتمد، تصنيف
  صارم noise/signal، واختبار محاكاة 72 ساعة (12 دورة × 6 ساعات) يثبت
  استقرار الحالة والحدود — ويُوثق ذلك بصراحة في تقرير الارتباط.

## الحزمة والملفات

حزمة جديدة `src/webpent/autonomous/cem/` ووحدة لكل بند، بالترتيب:

### الموجة 1 — Watchtower (برج المراقبة)
- **T1 · U-CEM-1 محرك اللقطات** `snapshot.py`
  `build_snapshot(target_id, *, now, sections...)` (بصمة sha256 قياسية،
  redact، حدود) + `SnapshotStore` (64 لقطة/هدف، حفظ ذري، فساد → فارغ،
  `latest()` و`series()`).
- **T2 · U-CEM-2 محرك الفروق** `diff_engine.py`
  تصنيف NOISE / SIGNAL-LOW / SIGNAL-HIGH / CRITICAL بمقارنة زوج لقطات +
  تاريخ endpoints للـreappearance؛ إعدادات الـYAML قوائم قابلة للتخصيص
  (`load_signal_config`، فساد → defaults).
- **T3 · U-CEM-3 كاشف انحراف النطاق** `scope_drift.py` — subdomain خارج
  النطاق يُلاحَظ ولا يُلمس، تغيّر ملكية IP وتبدّل مزوّد الشهادة → alert.
- **T4 · U-CEM-4 المجدول المهذب** `scheduler.py` + `config/cem_schedule.yaml`
  — `parse_active_hours` (يدعم الالتفاف حول منتصف الليل)، سقف طلبات/يوم
  مع تدوير اليوم، `KillSwitch` مخزن دائم فوري المفعول، فرملة طوارئ على
  ارتفاع زمن الاستجابة.
- **T4b · `cycle.py`** — `run_cem_cycle(state, *, now, fetchers...)`:
  دورة واحدة pure تربط المراقبة → الفرق → الحارس → الأفعال المقترحة،
  وتُثبت الاختبارات أنها idempotent وآمنة التكرار (محاكاة 72 ساعة).

### الموجة 2 — Reactor (المفاعل)
- **T5 · U-CEM-5 مفاعل التغيّر** `reactor.py` — mini-campaign عند
  signal-high/critical فقط بميزانية 10% من اليومية لكل حملة (سقف 4
  حملات)، مع ربط advisory بالـlessons وبالذاكرة العابرة للأهداف.
- **T6 · U-CEM-6 مراقب الانحدارات** `regression_watch.py` +
  `config/regression_watch.yaml` — حالة كل finding
  (active/fixed/regressed/deferred)، فاصل إعادة اختبار، سقف retests،
  auto-defer عند اختفاء endpoint، alert عند الرجوع.
- **T7 · U-CEM-7 بروتوكول الاستدعاء** `wake_up.py` — عند signal-critical
  على هدف نائم: استيقاظ بميزانية حملة كاملة مقتطعة بأمان من المتبقي
  (لا سلبية أبدًا)، ثم عودة للسكون.

### الموجة 3 — الذاكرة الطويلة
- **T8 · U-CEM-8 سجل الدروس الزمني** `temporal_lessons.py` — عمر افتراضي
  (TTL 90 يوم)، تقوٍ عند التأكيد وتراجع عند الإنكار، سياق موسمي
  (شهور) بنافذة مراقبة مكثفة، تقاعد تحت قوة 0.3.
- **T9 · U-CEM-9 كاشف إيقاع النشر** `deployment_rhythm.py` — هيستوغرام
  ساعات/أيام النشر من سلسلة لقطات، ونسبة الانحدارات خلال 24 ساعة بعد
  نشر.
- **T10 · U-CEM-10 مجمّع الفرضيات النائمة** `dormant_pool.py` — فرضية
  نائمة بشرط تنبيه (`blocked_on` كtipo تغيّر)، تُفعّل عند تحقق الشرط في
  diff report، تقاعد بعد 120 يومًا، حد 32.

### الموجة 4 — واجهة المشغّل
- **T11 · U-CEM-11 التقرير اليومي** `digest.py` — Markdown + JSON من حالة
  CEM (لقطات، تغيّرات، حملات، findings، انحدارات، ميزانية، تنبيهات نطاق)
  بأقسام محتمدة وredact.
- **T12 · U-CEM-12 أوامر المشغّل** `src/webpent/cli/cem.py` (Typer sub-app
  `webpent cem`) — start/pause/resume/status/digest/kill — كلها عمليات على
  ملفات حالة محلية فقط (لا daemon يُشغَّل من CLI؛ start يسجّل الهدف
  ويكتب audit log، والمجدول الخارجي هو من يستدعي الدورات)، مع `audit_log`
  JSON-lines محتمد (آخر 1000 سطر) وredact. الأوامر كلها تُسجَّل في audit.

### الختام
- **T13 · الإقفال** — تصدير الحزمة من `autonomous/__init__.py`؛ الإصدار
  0.8.0 في pyproject + `webpent/__init__` + اختبار الحزم؛ CHANGELOG عربي؛
  صف v83 في تقرير الارتباط وسطر حالة README؛ تجديد جرد direct-IO بمراجعة
  diff؛ مجموعة كاملة خضراء؛ Ruff نظيف على الملموس؛ ZIP
  `webpent_v83_continuous_engagement_mode.zip`؛ تعبئة سجل التنفيذ.

## معايير الإقفال داخل الشفرة (التي أستطيع إثباتها هنا)

- كل وحدة لها اختبارات عقد؛ المجموعة الكاملة خضراء (أساس 2437 + الجديد).
- صفر تجاوز نطاق في الاختبارات (out-of-scope لا يدخل touchable أبدًا).
- سقوف الميزانية والـkill switch مُثبتة بالاختبار (الإيقاف فوري في نفس
  الدورة).
- محاكاة 72 ساعة (12 دورة) بلا فشل وبلا نمو غير محتمد.
- Ruff نظيف على كل ملف جديد/ملموس، وجرد direct-IO بلا انحراف.

## سجل التنفيذ (تم 2026-10-15)

| المهمة | الملف/الملفات | الاختبارات | الحالة |
|---|---|---|---|
| T1 · محرك اللقطات | `cem/snapshot.py` | `test_cem_snapshot.py` 10/10 | ✅ |
| T2 · محرك الـdiff | `cem/diff_engine.py` + `config/cem_schedule.yaml` | `test_cem_diff_engine.py` 12/12 | ✅ |
| T3 · انجراف النطاق | `cem/scope_drift.py` | `test_cem_scope_drift.py` 9/9 | ✅ |
| T4 · المجدول المهذب | `cem/scheduler.py` | `test_cem_scheduler.py` 10/10 | ✅ |
| T4b · دورة الاشتباك + محاكاة 72 ساعة | `cem/cycle.py` | `test_cem_cycle.py` 10/10 (منها 12 دورة × 6 ساعات) | ✅ |
| T5 · المفاعل | `cem/reactor.py` | `test_cem_reactor.py` 9/9 | ✅ |
| T6 · مراقبة الانحدار | `cem/regression_watch.py` + `config/regression_watch.yaml` | `test_cem_regression_watch.py` 9/9 | ✅ |
| T7 · بروتوكول الاستيقاظ | `cem/wake_up.py` | `test_cem_wake_up.py` 6/6 | ✅ |
| T8 · سجل الدروس الزمنية | `cem/temporal_lessons.py` | `test_cem_temporal_lessons.py` 9/9 | ✅ |
| T9 · إيقاع النشر | `cem/deployment_rhythm.py` | `test_cem_deployment_rhythm.py` 7/7 | ✅ |
| T10 · بركة الفرضيات النائمة | `cem/dormant_pool.py` | `test_cem_dormant_pool.py` 7/7 | ✅ |
| T11 · التقرير اليومي | `cem/digest.py` | `test_cem_digest.py` 7/7 | ✅ |
| T12 · أوامر المشغّل | `cli/cem.py` + تسجيل `webpent cem` في `cli/commands.py` | `test_cem_cli.py` 9/9 | ✅ |
| T13 · الإقفال | exports، الإصدار 0.8.0، CHANGELOG، الارتباط، README، جرد direct-IO | انظر أدلة البوابة أدناه | ✅ |

**إصلاح حقيقي واحد اكتُشف أثناء التنفيذ:** اختبار الـdigest كشف ثغرة في
`redact()` الموروثة — `Authorization: Bearer <token>` كانت تُستهلك كلمة
"Bearer" بفرع authorization العام فيتسرب الـtoken نفسه. أُصلحت من
المنبع بإضافة بديل مخصص `authorization\s*[:=]\s*bearer\s+\S+` قبل الفرع
العام في `hunt_contracts.py`، والمجموعة كاملة خضراء بعدها.

## أدلة بوابة الإقفال (جديدة، 2026-10-15)

- المجموعة الكاملة: `pytest tests/ -q` → **2551 passed, 0 failures**
  (أساس 2437 + 114 جديدة في 125.63 ثانية).
- Ruff: `All checks passed!` على 13 ملف اختبار + 13 ملف مصدر لـCEM
  (`cem/` كاملًا، `cli/cem.py`، `autonomous/__init__.py`،
  `test_cem_*.py`)؛ و`cli/commands.py` و`hunt_contracts.py`: 38 مقابل
  38 خطأ أساسيًا — صفر أخطاء جديدة في الملفات الملموسة القديمة.
- جرد direct-IO: 641 → 643 سجلًا (سجل واحد جديد `not_applicable`
  `dynamic_resolution` لخطاف `reactor.propose` Advisory في
  `cem/cycle.py` + انتقالات أسطر في `cli/commands.py`)، واختبارات بوابة
  G-02 الأربعة خضراء بعد كل تعديل مصدر.
- الإصدار: `pyproject.toml` + `webpent/__init__.py` +
  `test_release_packaging.py` كلها 0.8.0.
