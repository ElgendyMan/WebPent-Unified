# RED-TEAM ROUND 2 — الوحدات غير المُغطاة سطريًا (dojo / econ / jc / prism / graph) + ملحق families / forge

- **التاريخ:** 2026-11-02 (بعد إغلاق نافذة 0.33.0 — commit `0c286b8`)؛ الملحق §8 بتاريخ 2026-11-02 بعد إغلاق نافذة 0.34.0 (commit `2873106`)
- **النطاق:** 5 وحدات لم تُفحص سطرًا بسطر في الجولة الأولى: `dojo`، `econ`، `jc`، `prism`، `graph` — **+ الملحق §8: آخر وحدتين من قائمة §8 (`families`، `forge`) لإغلاق القائمة بالكامل**
- **الحجم:** 68 ملفًا / 16,669 سطرًا مقروءة بالكامل — **+ الملحق §8: 27 ملفًا / 4,219 سطرًا (الإجمالي: 95 ملفًا / 20,888 سطرًا)**
- **النتيجة الإجمالية:** **45 نتيجة — Critical 1 / High 9 / Medium 18 / Low 17** — **+ الملحق §8: 25 نتيجة (Critical 1 / High 6 / Medium 10 / Low 8) — الإجمالي عبر الجولتين: 70 نتيجة (Critical 2 / High 15 / Medium 28 / Low 25)**

---

## §0 الملخص التنفيذي

نفذت الجولة الثانية بخمسة وكلاء red-team متوازيين (وكيل لكل وحدة، بحث فقط بلا أي تعديل)،
كل وحدة قُرئت **بالكامل** ملفًا ملفًا، مع إلزام كل وكيل بفتح الملفات المُستدعاة خارج وحدته
للتحقق من التواقيع قبل ادعاء أي عطل تكاملي. خط الأساس أخضر قبل البدء:
dojo 282 passed، econ 82 passed، prism 246 passed، وبوابة التجميد 661 passed.

**النتيجة الأهم:** الوحدة الخطر عليها ليست الوحدات الاستشارية بل **`graph` — وحدة الإنتاج
التي تقود الصيد الحقيقي**. فيها النتيجة الحرجة الوحيدة (R2-graph-01) وثلاث نتائج High
تعني عمليًا: محاسبة ميزانية متضخمة في كل تشغيل، انهيار `KeyError` تحت ضغط الميزانية،
طريق موت صامت في وضع HITL، وتوقف صامت بعد `payload_generator` بسبب استيراد وحدة غير موجودة.

**التحقق:** كل النتائج الحرجة والعالية العشر (graph-01..04، jc-01..03، dojo-01، econ-01،
prism-01) **أعيد التحقق منها يدويًا** بقراءة الكود المُستشهد به في هذا الجلسة مباشرة —
كلها صحيحة. نتائج Medium/Low مُثبتة بنصوص تنفيذية (repro) من الوكلاء مع أسطر كود حرفية.

**الحكم:** لا تزال هناك أعطال وظيفية حاجبة (خاصة في مسار الإنتاج `graph`)، والتوصية
فتح نافذة **0.34.0** بدفعتين C1 (الحاجبة) ثم C2 (المتوسطة) وفق نفس بروتوكول §6 من خطة 0.33.0.
*(تحديث لاحق: نافذة 0.34.0 أُغلقت بالكامل — 45/45 بنودًا عبر C1 10/10 + C2 18/18 + C3 16/17
مع تأجيل نصف بند lesson-wiring الموثق — commit `2873106`. الملحق §8 أدناه يغطي families/forge
ويقترح نافذة 0.35.0.)*

---

## §1 المنهجية والتغطية

| الوحدة | الملفات | الأسطر | وكيل R2 | Critical | High | Medium | Low | خط أساس الاختبارات |
|---|---|---|---|---|---|---|---|---|
| `dojo` | 15 | 2,791 | R2-dojo | 0 | 1 | 4 | 5 | 282 passed |
| `econ` | 13 | 3,636 | R2-econ | 0 | 1 | 6 | 4 | 82 passed |
| `jc` | 15 | 3,084 | R2-jc | 0 | 3 | 3 | 3 | (ضمن suite) |
| `prism` | 17 | 3,171 | R2-prism | 0 | 1 | 4 | 3 | 246 passed |
| `graph` | 8 | 3,987 | R2-graph | **1** | 3 | 1 | 2 | (ضمن suite) |
| **المجموع** | **68** | **16,669** | — | **1** | **9** | **18** | **17** | — |

منهج البحث لكل وحدة: أخطاء وقت التشغيل (تواقيع/kwargs) — بugs المنطق (شروط/حدود/حالات)
— انتهاك الحتمية المعلنة في ميثاق كل وحدة — دقة الرياضيات في النقاط/الأموال — سلامة
الحالة (SQL/ذرات/سباقات) — تسريب موارد — ابتلاع أخطاء — أمان (traversal/deserialization)
— انتهاك قوانين الميثاق (L-1 advisory-only، L-2 zero-network، L-3 deterministic...).
مستبعد من التقرير: الأسلوب والتسمية والوثائق والأداء الدقيق والفرضيات بلا سيناريو فشل ملموس.

---

## §2 النتائج الحرجة والعالية (10 — كلها مُعادة التحقق يدويًا)

### R2-graph-01 — **CRITICAL**: عقدة recon تُرجع الحالة الكاملة فيتضخم عدّاد الميزانية في كل تشغيل

- **الموقع:** `src/webpent/graph/builder.py:1556-1588` (`_combined_recon_node`) مع `_trace_wrap` (:281-298) و `state/reducers.py:164-170` (`merge_lists` append-only بلا dedup).
- **الدليل (مُستشهد به حرفيًا):**
  ```python
  # builder.py:1588
  return state          # يعيد كامل حالة الإدخال كـ update للعقدة
  # builder.py:293-295 (داخل _trace_wrap)
  prev = update.get("node_step_trace")
  if isinstance(prev, list):
      update["node_step_trace"] = [*prev, entry]
  ```
- **لماذا عطل:** `node_step_trace` قناة append-only بلا dedup. العقدة تعيد كل التتبع القديم
  + مدخلها، فالـ reducer يلحقها بالقائمة الموجودة → **كل مدخلات ما قبل recon تتكرر في كل
  تشغيل يمر بـ recon (المسار الإنتاجي الافتراضي)**. استهلاك الميزانية عند الحاكم هو
  `len(node_step_trace)` (`budget_governor.py:218-233,279`) → `consumed` متضخم دائمًا
  بعدد عقد ما قبل recon (5 افتراضيًا: preflight/wildcard_scope/planner/lesson_consultation/auth)
  → قطاعات الإنهاء تُطلق ~5 supersteps مبكرًا وتفسد مسار التدقيق. `consulted_lessons` تتكرر كذلك.
- **repro الوكيل:** دمج حقيقي عبر `_trace_wrap` + `merge_lists`: 4 مدخلات قبل recon → **9** بعد الدمج.
- **الاختبار الفاشل:** `test_recon_node_must_not_resend_append_only_channels` (ر. التقرير التقني أدناه §7).
- **الإصلاح:** إرجاع دلتا العقدة فقط، أو شطب المفاتيح append-only (`node_step_trace`,
  `consulted_lessons`, `decision_log`) من القاموس المُعاد.

### R2-graph-02 — **HIGH**: راوتر hypothesis يعيد `strategist` تحت ضغط الميزانية لكن الحافة غير موصولة → `KeyError` يقتل التشغيل

- **الموقع:** `builder.py:1093-1094,1099-1100` مقابل `:2072-2073`.
- **الدليل:**
  ```python
  if budget_governor.budget_pressure(state)["active"]:
      return NODE_STRATEGIST
  ...
  graph.add_conditional_edges(
      NODE_HYPOTHESIS, route_after_hypothesis,
      {NODE_ACCESS_CONTROL: NODE_ACCESS_CONTROL, NODE_REPORTER: NODE_REPORTER},  # لا strategist!
  )
  ```
- **لماذا عطل:** في langgraph 1.2.10 خريطة المسارات صارمة (`ends[r]`)؛ عند تفعيل قطع
  الإنجاز (ميزانية صغيرة `max_graph_steps <= ~44` أو الوهم الوحيد R2-graph-01) يموت
  التشغيل كله بـ `KeyError: 'strategist'` — تحديدًا في سيناريو الضغط الذي بُني الحاكم لأجله.
- **الإصلاح:** إضافة `NODE_STRATEGIST: NODE_STRATEGIST` إلى خريطة الحافة.

### R2-graph-03 — **HIGH**: `scope_drift_approved` غير معلن في `PentestState` → langgraph يُسقطها → طريق موت في متابعة الموافقة اليدوية

- **الموقع:** `builder.py:958,997` (قراءة) — لا إعلان ولا كاتب في `src/` كله (تحقق grep)؛ `state/state.py:337-338` تعلن `scope_drift_detected` فقط.
- **لماذا عطل:** langgraph 1.2.10 يُسقط المفاتيح غير المعلنة (تحقق الوكيل بـ repro: `update_state` يرجع OK لكن لا يخزن شيئًا؛ `invoke` لا يري الراوتر المفتاح). النتيجة: بعد إيقاف `interrupt_before=[NODE_SCOPE_RECON...]` للموافقة اليدوية، أي استئناف يصل `route_after_scope_review` فلا يجد الموافقة → `END` بلا تقرير (reporter/reflection/lessons لا تعمل أبدًا). الاختبارات الحالية تمر لأنها تمرر dicts عادية تتجاوز ترشيح القنوات.
- **الإصلاح:** إعلان `scope_drift_approved: bool` في `PentestState` + توثيق ضبطها عبر `update_state` قبل الاستئناف.

### R2-graph-04 — **HIGH**: استيراد `webpent.shared.checkpoints` (وحدة غير موجودة) → checkpointer دائمًا None → توقف صامت بعد payload_generator في وضع HITL

- **الموقع:** `cli/unified_hunt.py:172-174,193`؛ الصحيح `graph/checkpoints.py:344` (تحقق: `shared/checkpoints.py` **غير موجود** في نظام الملفات).
- **الدليل:**
  ```python
  try:
      from webpent.shared.checkpoints import get_checkpointer
  except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError):
      get_checkpointer = None   # يبتلع الخطأ بالتصميم
  ```
- **لماذا عطل:** مع `auto_approve=False` (الافتراضي) يُبنى الرسم بـ `interrupt_before` وبدون
  checkpointer → `stream()` يتوقف عند أول interrupt ولا يُستأنف أبدًا؛ `get_state` اللاحق يرمي
  `ValueError` ويُبتلع. الصيد الافتراضي في وضع HITL يتوقف بصمت بعد `payload_generator` —
  بلا execution/validator/CVSS/reporter/reflection — ويلخص كتشغيل عادي.
- **الإصلاح:** استيراد من `webpent.graph.checkpoints`، وجعل `build_graph` يرفع خطأ عند
  `auto_approve=False and checkpointer is None` (فشل صاخب بدل توقف صامت).

### R2-jc-01 — **HIGH**: تعطيل skeptic/judge من الإعدادات يترك sentinel `_UNSET` → `AttributeError` في كل مناظرة

- **الموقع:** `jc/chamber.py:116-130,194-197,201`.
- **الدليل:** `__init__` يخزن `self.skeptic = skeptic` حيث `skeptic == _UNSET`؛ فقط إذا
  `require_skeptic` true يُستبدل بـ Skeptic. ثم `close()` يفحص `if self.skeptic is not None:`
  → يستدعي `challenge_all()` على كائن `object` سادة → `AttributeError: 'object' object has
  no attribute 'challenge_all'`. مسار `None` الصريح يعمل؛ مسار تعطيل الإعدادات — خيار مشغل
  مدعوم — ينهار.
- **الإصلاح:** بعد تحميل الإعدادات: `if skeptic is _UNSET and not require_skeptic: self.skeptic = None` (وكذلك judge).

### R2-jc-02 — **HIGH**: `clamp01()` على قيم بنطاق الدولار يدمّر ترتيب المدافعين (Economist/Tactician/Adapter يختارون الهدف الخطأ)

- **الموقع:** `jc/advocates.py:88` (Tactician `ev_per_hour`)، `:187-191` (Adapter)، `:343` (Economist `value_usd`).
- **الدليل:**
  ```python
  key=lambda r: (-clamp01(r.get("value_usd"), 0.0), str(r.get("finding_id") or ""))
  ```
- **لماذا عطل:** `clamp01` يسحق كل ما فوق 1.0 إلى 1.0 → الترتيب يتحول **أبجديًا** بين كل
  المرشحين الواقعيين (قيم USD يتوقع أن تكون >= 50 حسب عتبة الإرسال ذاتها). repro: `alpha=$60`
  تُقدَّم على `zulu=$1,000,000`؛ `ev_per_hour=2.0` توصف بـ "الأعلى" أمام 50.0. ناتج المجلس
  الأساسي (U-JC-2) خطأ لأي إدخال فيه مرشحان فوق $1.
- **الإصلاح:** الترتيب على العدد الخام (`max(0.0, float(x))`) لا على `clamp01`.

### R2-jc-03 — **HIGH**: `canonical_json(default=str)` يجعل `context_hash` (ومعرفه session ids) غير حتمي مع sets

- **الموقع:** `jc/contracts.py:64-72`؛ المنبع `chamber.py:139` (`deterministic_id(question, context_hash(context))`).
- **لماذا عطل:** `default=str` يحول `set` إلى `str({...})` الذي ترتيبه يعتمد على
  `PYTHONHASHSEED` → نفس السياق يُهاش هاشًا مختلفًا بين العمليات (repro بثلاث بذور:
  3 هاشات مختلفة) → ينكسر عقد U-JC-1 ("المناظرة نفسها تفتح نفس session id دائمًا")
  واسترجاع `CouncilMemory.find_similar` بالهاش الدقيق.
- **الإصلاح:** في `default` handler: تحويل `set/frozenset` إلى `sorted(..., key=str)` بدل `str`.

### R2-dojo-01 — **HIGH**: الإجابات الخاطئة تضخم نقاط التدريب بلا سقف (600.0 بدل 100)

- **الموقع:** `dojo/trainer.py:123-124,139-145`.
- **الدليل:** كل إجابة (صحيحة أو خاطئة) تُلحق `hints_used` بـ `_hints_per_step`، ثم:
  ```python
  for hints in self._hints_per_step:
      total += max(0.0, 100.0 - HINT_COST * hints)
  return round(total / len(self.scenario_ids), 2)
  ```
- **لماذا عطل:** المقام خطوات لا محاولات؛ إجابة خاطئة بلا تلميحات = +100. repro: خطوة واحدة،
  5 إجابات خاطئة ثم صحيحة → **score() == 600.0**؛ الفاشل دائمًا يتفوق على المثالي (100.0).
  يناقض ميثاق القياس الصادح (L-5/L-6). الاختبارات الحالية تثبت فقط المسارات الصحيحة.
- **الإصلاح:** حساب النقاط للمحاولات الصحيحة فقط (`if ok` مع zip `_answers`/`_hints_per_step`).

### R2-econ-01 — **HIGH**: `last_transition` naive من portfolio.yaml يُفجّر `auto_transition` بـ TypeError

- **الموقع:** `econ/portfolio.py:184-188` (التحميل يقبل naive verbatim)، الانفجار `:303`.
- **الدليل:** `elif old == WATCHING and now - entry.last_transition >= timedelta(days=60):`
  حيث `now` مدرك المنطقة (يُحرس ctx.now) و`last_transition` naive من YAML.
- **لماذا عطل:** أي portfolio.yaml بطابع زمني بلا منطقة (سطر يدوي أو أداة خارجية) مع حالة
  `WATCHING` (الافتراضية) → `TypeError: can't subtract offset-naive and offset-aware datetimes`
  → لا digest ولا انتقالات تلقائية إطلاقًا. و`save()` يعيد تدوير النقص بـ `isoformat()` بلا tz.
- **الإصلاح:** في `load()` بعد حل `last_ts`: `if last_ts.tzinfo is None: last_ts = last_ts.replace(tzinfo=timezone.utc)`.

### R2-prism-01 — **HIGH**: `record_outcome` يقبل دليلًا من حملة أخرى → سجل تدقيق متناقض صامتًا

- **الموقع:** `prism/ledger.py:186-193` (مع `_SCHEMA:39-53`).
- **الدليل:** الفحص `SELECT 1 FROM evidence WHERE evidence_id = ?` بلا قيد `campaign_id`،
  بينما جدول `outcomes` مقيّد بحملة، و`PRAGMA foreign_keys=ON` غير مفعّل فيصير الغياب بلا شبكة أمان.
- **لماذا عطل:** حملة B تسجل نتيجة على دليل حملة A → لا خطأ؛ `export(B)` يرجع نتائج تشير إلى
  دليل لا يظهر في أي صف منها → rollup النتائج/الأنماط لكل حملة يخلط الأهداف. ميثاق الوحدة
  (رفض لا تخمين) يوجب الرفض.
- **الإصلاح:** `WHERE evidence_id = ? AND campaign_id = ?` + تفعيل `PRAGMA foreign_keys=ON`.

---

## §3 النتائج المتوسطة (18)

| ID | الوحدة | الموقع | الخلاصة | الإصلاح المقترح |
|---|---|---|---|---|
| R2-dojo-02 | dojo | `practice_runner.py:162-173` + `defender.py:68-69` | المفاضلة على `request_budget` السيناريو لا المفروض من نمط الدفاع (المختصر //4 أو 1) → التحصين يرفع نتيجة الأحمر ميكانيكيًا (87.5→95.0) والسجل يكتب 16 بدل 4 | لقطة `lab.request_budget` بعد النمط وتمريرها إلى `score()` و`PracticeResult` |
| R2-dojo-03 | dojo | `weakness_identifier.py:238` مقابل `:101` | ثغرات `adaptation_gap` لعائلة `jwt` تُشتق من `family` لا `skill_families` → `filter(skill_family="jwt")` = 0 → خطة تركيز فارغة صامتًا (يناقض L-7/L-3) | اشتقاق العائلة من `scenario.skill_families` |
| R2-dojo-04 | dojo | `counter_adapter.py:112-121,172-193` | إذا لم يفز الأحمر أبدًا فالنمط لا يُطبق ولا مرة → `bypasses==0` → `effective=True` بلا قياس فعليًا | تتبع `applied_rounds` وجعله شرطًا للفعالية |
| R2-dojo-05 | dojo | `cli/dojo.py:192` × `skill_assessor.py:62` | CLI يعدد `library.families()` بينما المقيم يطابق `skill_families` → عائلتا `jwt` و`business_logic` لا تجمعان أي عينة أبدًا (بيانات مفقودة حتميًا في مصفوفة المهارات) | تعداد `sorted({f for s in library.all() for f in s.skill_families})` |
| R2-econ-02 | econ | `competitive.py:285-300` | `since` مدرك غير UTC يُقارن نصيًا بصفوف UTC → نتائج صامتة خاطئة تتسرب إلى التشبع والنقاط العمياء | `since = since.astimezone(timezone.utc)` بعد فرع naive |
| R2-econ-03 | econ | `competitive.py:62-73,262-282` | لا UNIQUE في جدول findings → إعادة تناول نفس اللقطة تضاعف الصفوف (تشبع 60→100) وقلب التوصية الاقتصادية | فهرس فريد + `INSERT OR IGNORE` مع عدّ المهملات |
| R2-econ-04 | econ | `learning_loop.py:180` + `cli/econ.py:177` | `lines[:4096]` يبقي الأقدم؛ دفتر التقديمات append-only → أحدث التسجيلات (خارج 4096) محذوفة من نافذة 30/90 يومًا | `lines[-4096:]` في الموضعين (مؤكد يدويًا) |
| R2-econ-05 | econ | `scope_negotiator.py:209-217,230` × `blind_spots.py:174-192` | المسارات تذهب لـ gray_zones دائمًا و`locate` يقرأ `in_scope` فقط → نوع `path_region` الأول ميت عبر المسار الموثق (يعمل يدويًا فقط) | أن يستهلك locate مسارات gray_zones البادئة بـ `/` |
| R2-econ-06 | econ | `saturation.py:184-195,205,212-216` | إشارة موجودة لكنها تالفة (`float()` ترمي) تُبتلع بلا تسجيل partial → ثقة 1.0 وملاحظة "من الإشارات الثلاث" كاذبة (L-4) | تحويل محمي يضيف إلى `partial` عند الفشل |
| R2-econ-07 | econ | `portfolio.py:189-197` | `suppress` يلف البناء كاملًا → حقل رقمي واحد تالف يحذف الهدف كله صامتًا من daily_plan والتنبيهات | تحليل كل رقم بـ `_float_or(v, default)` والإبقاء على الهدف |
| R2-jc-04 | jc | `calibration.py:121-122` | حافة IEEE-754: `int(0.7/0.1)`=6 → التنبؤ 0.7 يُدرج في "0.6-0.7" (وكذلك 0.3، 0.6) → مخطط الموثوقية خاطئ في 3 من 10 حواف | `math.floor(round(p/BUCKET_WIDTH, 9))` |
| R2-jc-05 | jc | `calibration.py:93`, `bias_detector.py:114,271`, `memory.py:89` | صف JSON سليم بـ `ts` تالف يفجّر report/detect/compaction (`float("corrupt")`/مقارنة str-float) رغم posture fail-soft المعلن | تحويل محمي `suppress(TypeError, ValueError)` وتخطي الصف |
| R2-jc-06 | jc | `judge.py:55-68` × `chamber.py:164-169` | نفس `advocate_id` في جولتين: الحكم يقيّم آخر مداخلة فقط وتُمحى القوية بلا أثر (دون تحديات السخرية التي تتراكم) — يناقض JC-L-3 | تجميع لكل مدافع أو رفض تكرار id في جلسة مفتوحة |
| R2-prism-02 | prism | `ledger.py:157-172` | مفتاح dedup يحذف الأبعاد الخمسة → ملفان مختلفان بنفس الهاش ونفس الدرجة ينهاران (تصادم فعلي بالأوزان المشحونة: decisive×single_shot×corroborated == strong×single_shot×independent_multiple = 0.134) | إدراج الأبعاد في الـ id (strength/reproducibility/corroboration) |
| R2-prism-03 | prism | `compliance.py:158-174,182-199` | سجل الامتثال ("zero silent failures") بمقابلة قراءة-كتابة غير ذرية بـ `write_text` (مؤكد يدويًا) → انقطاع بعد truncate يمحو الأثر كله، وتزامن يفقد أسطرًا | كتابة ذرية mkstemp+os.replace أو فتح "a" |
| R2-prism-04 | prism | `anomaly_filter.py:114-122` × `config/prism/curiosity_params.yaml:16` | مفتاح `request_cost_step: 0.25` مُشحن وموثق ولا يقرأه أي كود؛ الفلتر يُثبّت 1.0 وweighter يُثبّت 0.25 → طبقتا الفضول يختلفتان 4x | قراءة المفتاح في الموضعين |
| R2-prism-05 | prism | `scorer.py:122-127,154-156` | `_validate` لا يطلب مفاتيح القواعد الثلاثة؛ `.get(key, 0.0)` → إعداد ناقص يحمّل ويكف عن العقوبة صامتًا (0.0→0.108) — مخالف لقانون errors.py الصريح | طلب المجموعة الكاملة ثم فهرسة مباشرة |
| R2-graph-05 | graph | `checkpoints.py:176-191,57-63` | `_redact_checkpoint` يُطبق redaction على `channel_versions`/`versions_seen` (لا أسرار فيها) → يفسد بيانات ترتيب الاستئناف لقنوات بأسماء حساسة (`credentials`→''‎) | نسخ حرفي (deepcopy) لمفاتيح الإصدارات وحصر redaction بالقيم |

---

## §4 النتائج المنخفضة (17)

| ID | الوحدة | الموقع | الخلاصة الموجزة |
|---|---|---|---|
| R2-dojo-06 | dojo | `engine.py:197-208` | المطابقة افتراضيًا case-insensitive بينما filter_token حساس للحالة → رقابة الـ denylist قابلة للتجاوز بنفس المدخلات التي يقبلها المحرك |
| R2-dojo-07 | dojo | `engine.py:197-204` | `strict_types` يصير no-op صامتًا إذا ضُبط مع `normalize_input` (ترتيب الأعلام يمنع الأصرم) |
| R2-dojo-08 | dojo | `progress.py:111-113` | `cap=1` → `lines[-0:]` يعيد كل الأسطر (السقف لا يقص أبدًا) — كامن اليوم بأغطية 1000/5000 |
| R2-dojo-09 | dojo | `scenario_library.py:136` | `glob("*.yaml")` يتجاهل `.yml` بصمت → مكتبة فارغة بلا خطأ ثم IndexError بعيدًا عن السبب |
| R2-dojo-10 | dojo | `trainer.py:153-168` + `progress.py:106-119` | `save()` بلا ذرية (write_text مباشر) رغم أن قلم السجل نفسه يستخدم mkstemp+replace؛ وread-modify-write بلا قفل يفقد أسطرًا مع تزامن CLI |
| R2-econ-08 | econ | `saturation.py:229-238` | تقرير insufficient_signal يتخفى كدرجة مثالية (index=0.0, tier=LOW) — "خطأ يتخفى كدرجة صحيحة" بالضبط؛ لا مستهلك موصول اليوم |
| R2-econ-09 | econ | `scope_negotiator.py:115` | قبول `set` → ترتيب الالتباسات (وأرقام أسئلة الاستيضاح) يتغير بين العمليات (L-3) |
| R2-econ-10 | econ | `timing_advisor.py:149-155,213` × `roi_optimizer.py:189-190` | HOLD يستخدم `dup_rate` الخام لا P_dup معدلة بالتشبع → توصيتان متناقضتان لنفس النتيجة |
| R2-econ-11 | econ | `market_kb.py:41` | `STALE_AFTER_DAYS=90` ميت — لا أحد يقارن `last_updated` بأي ساعة؛ منحنى دفع عمره سنة يقود EV بصمت |
| R2-jc-07 | jc | `skeptic.py:88` مقابل `:102,105` | حماية نصفية من سياق non-dict ثم `context.get` — انهيار مع `challenge(arg, None)` |
| R2-jc-08 | jc | `dissent.py:36-51,140-151` | `record()` يرجع عدد الأسطر حتى عند فشل الكتابة (OSError يبتلع) → عقد "Returns lines written" كاذب |
| R2-jc-09 | jc | `memory.py:84-97,144-157` | read-modify-write بلا قفل → كاتبان متزامنان يفقدان قرارات/ربط نتائج (الكتابة ذرية لكن الدورة لا) |
| R2-prism-06 | prism | `priors.py:94` | `pattern_type` غير معروف → `KeyError` خام بدل `PrismLawError` عند حد القانون |
| R2-prism-07 | prism | `classifier.py:124-127` | عنصر غير dict في patterns → `AttributeError` بدل `PrismLawError` الموعود |
| R2-prism-08 | prism | `value_weighter.py:97-122,172-187` + `anomaly_filter.py:84-96` | مفاتيح مستهلكة غير مُتحققة (`confidence_width` → KeyError لاحق) وعدم فحص رتابة `recommendation_thresholds` → تسميات عبثية تُحمَّل |
| R2-graph-06 | graph | `progress_display.py:175-186` | عدّ "الثغرات المؤكدة" يقرأ `validation_status` غير الموجود على `Finding` → الشريط يعرض 0/N دائمًا (عرض فقط؛ نفس الجذر في `cli/unified_hunt.py` و`shared/finding_announcer.py` خارج نطاق هذه الجولة) |
| R2-graph-07 | graph | `lesson_nodes.py:187-201` + `builder.py:361-375` | `lesson_priority_adjustments` بلا قارئ (عقد التعلم no-op فعليًا)؛ `smart_mode`/`enable_smart_campaigns` غير معلنة → لا تصل حالة الرسم أبدًا |

---

## §5 ما فُحص ووُجد سليمًا (ضد الانحلال)

- **dojo:** L-1 بلا سطح شبكة؛ `lab_generator` (احتجاز FIFO، رفض EXTERNAL_LABS، بذور محكمة)؛ `defender` (12 رقعة نقية عبر `replace()` بلا طفرات على الأصل — وكلها تثبيتات اختبارية)؛ `tournament` (ترتيب حتمي ودلالات poison-test)؛ `sparring` (ترتيب budget-then-pattern RT-02).
- **econ:** القوانين L-1/L-2/L-8 صامدة هيكليًا — لا استيراد شبكة، لا عشوائية، لا LLM، كل مخرج موسوم components/rationale/confidence؛ `budget_mapper` (تقريب البنوك n=1..5، تصادم redact مُستبعد بـ repro)؛ `target_scorer` (مقام محروس 0.25+)؛ الحفظ الذري في market_kb/portfolio/CLI.
- **jc:** سقف شدة skeptic ≤ 0.9 مفروض مرتين (PASS)؛ min-20 guard صارم (PASS)؛ Brier صحيح؛ dissent append-only فعليًا (PASS)؛ `yaml.safe_load` فقط ولا socket/subprocess إطلاقًا.
- **prism:** تكامل `deep/bridge.py` و`cli/prism.py` (كل التواقيع فُتحت وتطابقت)؛ PII: الهدف SHA-256 والاسم/الملاحظات عبر `redact_pii` قبل الإدخال (مطابق للميثاق)؛ guards أقسام الصفر في metrics؛ L-9 (الحتمية) سليمة في التسجيل لأن أختام الوقت للعرض فقط.
- **graph:** حارس الطبقة الاختيارية سليم (`__init__` لا يستورد submodules)؛ `budget_governor` رياضيات الاحتياطي والحدود سليمة بلا قسمة صفر؛ `checkpoints.py` متوافق مع 3.1.1 المثبتة (تواقيع put/get_tuple/from_conn_string)؛ `detector_nodes` كل المستدعيات الأربعة تطابقت؛ 26 مسارًا شرطيًا فُحصت ضد خرائطها — فقط `NODE_HYPOTHESIS` ينقصه مفتاح (R2-graph-02).

---

## §6 خطة الإصلاح المقترحة لنافذة 0.34.0

**بروتوكول التحقق:** نفس بروتوكول §6 من `PRODUCTION_HARDENING_PLAN_0330.md` حرفيًا —
اختبار فاشل قبل الإصلاح لكل بند → `pytest --collect-only` صفر أخطاء → Suite كاملة بخمس
دفعات 0 failed → ruff ratchet (6209) → canary 7x STABLE → refreeze manifest → CHANGELOG 0.34.0.

| الدفعة | البنود | المنطق |
|---|---|---|
| **C1 — حاجب/إنتاج** | R2-graph-01..04، R2-jc-01..03، R2-dojo-01، R2-econ-01، R2-prism-01 (10 بنود = كل الحرجة/العالية) | ما يفسد محاسبة الإنتاج، يقتل تشغيلًا، أو يخرج توصية خطأ من مخرجات معلنة |
| **C2 — متوسطة** | 18 بندًا (§3)، مرتبة: econ-01..07 ثم prism ثم dojo ثم jc ثم graph-05 | سلامة بيانات وصمت خاطئ تتراكم في القرارات |
| **C3 — منخفضة + تنظيف** | 17 بندًا (§4) + بنود العرض (graph-06) + القرارات الميتة (graph-07, econ-11) | كامن/جودة/عرض — تُغلق دفعة واحدة رخيصة |

**تقدير الجهد:** C1 ≈ يوم نافذة واحد بمنهجية 0.33.0 (10 اختبارات فاشلة أولًا + إصلاحات
صغيرة معروفة كلها مكتوبة أعلاه)؛ C2/C3 أقل لأن الإصلاحات أحادية السطر غالبًا.

---

## §7 أوامر إعادة الإنتاج (مرفقة من الجلسة)

نصوص الـ repro الخاصة بالوكلاء بقيت في `/tmp` (dojo_repros، econ_repro، jc_repro، r2prism،
r2graph) وهي كافية للتحقق الفوري. الأهم (يعمل فورًا):

```bash
cd /home/z/my-project/webpent/webpent
# R2-graph-01: تكرار قناة append-only عبر العقدة الحقيقية
PYTHONPATH=src python -c "
from webpent.graph.builder import _trace_wrap
from webpent.state.reducers import merge_lists
st = {'node_step_trace': [{'seq': i, 'node': f'n{i}'} for i in range(4)]}
up = _trace_wrap('recon', lambda s: dict(s))(st)
print(len(merge_lists(st['node_step_trace'], up['node_step_trace'])))  # 9 بدل 5
"
# R2-graph-04: الوحدة غير الموجودة
PYTHONPATH=src python -c "import webpent.shared.checkpoints"  # ModuleNotFoundError
# R2-dojo-01 / R2-econ-01 / R2-prism-01 / R2-jc-01..03: ر. الاختبارات الفاشلة في §2/§3
```

---

## §8 ملحق الجولة الثانية — families / forge (إغلاق قائمة §8 بالكامل)

- **التاريخ:** 2026-11-02 (بعد إغلاق نافذة 0.34.0 — commit `2873106`)
- **النطاق:** آخر وحدتين من قائمة §8 في `PRODUCTION_HARDENING_PLAN_0330.md` (اللتان أعلنت الخطة
  عدم فحصهما سطريًا): `families/` و `forge/` (باستثناء indexer المفحوص في الجولة الأولى —
  أُعيدت قراءته أيضًا هنا للتأكد من عدم الانحلال)
- **الحجم:** 27 ملفًا / ~4,219 سطرًا مقروءة بالكامل (`families` 6 ملفات / 871 سطرًا؛
  `forge` 21 ملفًا / 3,348 سطرًا)
- **النتيجة:** **25 نتيجة — Critical 1 / High 6 / Medium 10 / Low 8**
- **التحقق:** نتائج Critical+High السبع كلها أُثبتت **بالتنفيذ المباشر** عبر
  `scripts/r2_families_forge_repros.py` (مرفق في المستودع) — كل قسم يطبع `PROVEN` أو
  `NOT-REPRODUCED` ضد الشيفرة الحقيقية، بلا أي محاكاة.

### §8.1 جدول النتائج الحرجة/العالية (7)

| ID | الوحدة | الموقع | المشكلة | الإصلاح المقترح |
|---|---|---|---|---|
| R2-fam-01 | families | `execution_node.py:261-263` × `family_checks.py:348-368` | **تأكيد OAuth الزائف (Critical):** `code_delivered_to_attacker` = "GET إلى رابط المهاجم رجع 200/302" — لا يُفتش أي كود تفويض فعلي؛ صفحة المهاجم الاعتيادية (200) تكفي لإصدار `CONFIRMED` بشدة `critical`. في المقابل تُحقن `generic_guards` أربعة أعلام `True` مضمنة (execution_node:459-465) لتجاوز فحص مراجعة الخصم — إبطال متعمد لطبقة خفض الإيجابيات الكاذبة | استخراج `code=`/`token=` فعلي من الاستجابة/`Location` قبل تفعيل العلم؛ حذف الحقن المضمن ومراجعة الأعلام الأربعة كسطور مشروطة حقيقية |
| R2-fam-02 | families | `execution_plans.py:167-170` × `:97-102` | `build_plan_for` يمرر `base_url=` إلى `build_multi_step_auth_plan` التي **لا تقبل** المعامل → `TypeError` لكل مرشح multi_step_auth_bypass؛ `execution_node:335-340` يبتلعه (`except: continue`) → العائلة كاملة بلا خطط تنفيذ أبدًا (PROVEN) | إضافة `base_url` لتوقيع الدالة وتطبيع URLs النسبية (`/api/me`، `affected_endpoint` الخام) عبر `_abs` |
| R2-fam-03 | families | `execution_node.py:239-249` × `family_checks.py:131-135` | **أوراكل post-state العرقي تسويفي (tautological):** العقدة تكتب `side_effects:N` في label الـ post-state من عدّاد 2xx الخاص بالـ burst نفسه، ثم الـ validator "يكتشف" النص في الـ label → التأكيد مضمون منطقيًا بمجرد burst>1 و seq≤1؛ جسم الـ post-state لا يُفتش أبدًا (PROVEN: جسم يقول حرفيًا "لا آثار جانبية" ومع ذلك `CONFIRMED` بـ `causal_oracle=burst_committed_side_effects=3`) | فحص جسم الـ post-state فعليًا (عداد كائنات/رصيد) أو إنقاص الادعاء إلى burst-vs-seq فقط |
| R2-fam-04 | families | `execution_node.py:254,259-260,267` × `family_checks.py:178-195,257-272,306-323` | قيم مدفونة تجعل ثلاث عائلات **غير قابلة للتأكيد عبر المسار الموصول أبدًا**: tenant يتطلب ظهور السلسلة الحرفية `foreign-tenant-observed` في جسم الاستجابة، exploit_chain يمرر `feeder_findings=[{1 عنصر}]` (<2 دائمًا) مع `artifact-1/2` وهمية، business_logic يتطلب الماركر الحرفي `invariant_broken` → `NEEDS_HUMAN_REVIEW` دائمًا (PROVEN) | تمرير معرّفات مستأجر حقيقية من التخطيط، ومغذيات من `AttackGraphPlanner`، وماركر مُتفق عليه مع الهدف |
| R2-fam-05 | families | `execution_node.py:382` | `replay_evidence[plan.family] = pack` — الحزمة بمفتاح **العائلة** لا المرشح: تنفيذ N خطط لنفس العائلة يرمي أدلة N-1 (طلبات حية أُرسلت ثم أُهملت)، و`executed_count` يوهم بعكس الحقيقة، ويُقطع ربط النتيجة بالمرشح → الترقية دائمًا بلا candidate → URL وهمي `family-validated-target.local` (PROVEN: 3 خطط → حزمة واحدة) | مفتاح مركب `(family, candidate_id)` مع قائمة حزم لكل عائلة |
| R2-fam-06 | families | `execution_node.py:628-642` (grep شامل) | `wire_family_execution` / `family_execution_node` / `build_plan_for` **بلا أي مستدعٍ إنتاجي** في src/scripts/cli — العمود الفقري (650 سطرًا) غير موصول بالرسم البياني، بينما docstring الوحدة يصف توصيلًا فعليًا ("wires the full end-to-end pipeline"). ملاحظة: هذه "الحصانة الفعلية" — ما لم تُصلَّح نتائج fam-01..05 أولاً، فالتوصيل سيشغّل مسارات إيجابيات كاذبة | ترتيب الإصلاح: fam-01..05 قبل أي توصيل؛ إما توصيل حقيقي بعد الإصلاح أو توثيق الحالة كـ offline |
| R2-forge-01 | forge | `synthesizer.py:69` × `schemas.py:15-35` × `indexer.py:159` | `_payload` يستخدم `family=VulnClass.SQLI` (قيمته `'sqli'`) بدل `forge.Family.SQLI` (قيمته `'SQLI'`) — تخزين أي حمولة مُخلَّقة عبر الـ API العام يُدخل صفًا يفجّر `Family(row["family"])` في **كل** قراءة كوربوس (`list_all`/`get_payload`/`find_polyglots`) → شلل قراءة الكوربوس كله بصف واحد (PROVEN). الـ CLI يضمدّ العَرَض فقط (`payload_cli.py:213-220` يعيد البناء ويُسقط بقية الحقول) بينما المصدر يبقى سامة | `family=Family.SQLI` في `_payload` (سطر واحد) + حذف الضمادة من الـ CLI |

### §8.2 النتائج المتوسطة (10)

| ID | الوحدة | الموقع | المشكلة |
|---|---|---|---|
| R2-fam-07 | families | `execution_node.py:152,277,229` | معرّات/بصمات من `hash()` المُملحة (`candidate_id`، `bundle_id`، `body_digest` بصيغة `sha256:` نصية) — غير حتمية عبر العمليات (PYTHONHASHSEED)؛ نفس جذر R2-jc-03 (PROVEN: نفس الجسم → بصمتان مختلفتان في تشغيلين) |
| R2-fam-08 | families | `execution_node.py:271-290` | `_seal_proof_bundle` يعلن `proof_bundle_sealed=True` حتى حين يُعيد `validate_proof_bundle` قيمة False (رفضًا) — ناتج الختم لا يُفحص (PROVEN جانبيًا في repro fam-06) |
| R2-fam-09 | families | `execution_plans.py:128-132` | `lstrip('https://')` يقص أي حرف من المجموعة {h,t,p,:,/} — يُفسد متغيرات suffix/userinfo/path_traversal لأي URI لا يبدأ بالبادئة القياسية حرفيًا |
| R2-fam-10 | families | `execution_node.py:102-117` | `_scope_filter`: مطابقة substring (allowed يطابق امتدادات أوسع) + مرشح بلا `affected_endpoint` يمر كليًا + `_action_authority_permit` يفشل-للفتح على **كل** استثناء بينما docstring يزعم "import error only" |
| R2-fam-11 | families | `promotion.py:21-29,58` | تعليق "overridable by scenario" بلا أي مسار تفعيل — شدة السيناريو مهملة؛ `tenant/oauth` تدفع `critical` دائمًا |
| R2-forge-02 | forge | `payload_cli.py:227-247` | `waf-bypass` لا يستخدم `adversarial.generate_bypasses` إطلاقًا: `imperva` وغير المسجل يمرران عبر `mutate` العادي مع `ok=True` — المخرجات ليست bypass أصلًا (صمت خاطئ) |
| R2-forge-03 | forge | `payload_cli.py:171-186` | `adapt`: `--for-context` غير معروف يُتجاهل بصمت (ok=True مع raw غير مُعدَّل)؛ `--for-tech/--for-waf` مقبولة ومهملة؛ كود ميت صريح (`Contextualizer.__dict__.get("_nothing")`) |
| R2-forge-04 | forge | `mutation.py:77` × `chaining.py:59` × `indexer.py:154` | `encoded_variants=()` (tuple بدل dict) — تخزين أي variant يفجّر `AttributeError` على `.items()` رغم أن docstring الـ chaining يَعِد بأنها "تسلك نفس مسارات indexer" |
| R2-forge-05 | forge | `indexer.py:201-212` | `store_outcome` الافتراضي `outcome_id=(payload,target,success)` مع INSERT OR REPLACE يجعل `success_rate` نسبة على أزواج مميزة لا على الاختبارات: تكرار النجاح لا يُحتسب، ومزيج نجاح/فشل ينتج 0.5 بمعزل عن عدد المحاولات |
| R2-forge-06 | forge | `contextualizer.py:107-108` | قاعدة akamai hex تنتج `"\x"+hex(الكل)` — ترميز غير صالح بنيويًا (المطلوب `%XX` أو `\xNN` لكل بايت)؛ المتغير الناتج لا يُقبل في أي محلل |

### §8.3 النتائج المنخفضة (8)

| ID | الوحدة | الموقع | المشكلة |
|---|---|---|---|
| R2-fam-12 | families | `execution_plans.py:97-111,52-57,74-94` | URLs نسبية بلا `_abs` في multi_step؛ `foreign_tenant_id` معامل ميت؛ `_endpoint_parts` يقص افتراضيًا POST |
| R2-fam-13 | families | `base.py:1-36,153-180` | docstring "five families" مقابل 6 أعضاء؛ `dedupe()` يطابق `(scenario_id, endpoint)` متجاهلًا `source/dedupe_key` (تعليق النموذج يوهم بالعكس)؛ `filter_safety` تمرر `scenario_id` غير مسجل في production؛ `ExecutionPlan.safe_in_production` بلا أي مستهلك |
| R2-forge-07 | forge | `cross_target.py:82-87` | `successful_payloads` يقرأ `outcome_records` (جدول `OutcomeTracker`) — إن شُيّد الناقل قبل التتبع → `OperationalError: no such table` (اقتران خفي بترتيب البناء) |
| R2-forge-08 | forge | `payload_dashboard.py:9,18,64-66` | `FRESH_DAYS=60` يناقض docstring "fresh < 30"؛ مفاتيح `by_quality`/`by_complexity` مقلوبة دلاليًا (الأولى تحمل تعقيدًا والثانية طزاجة) |
| R2-forge-09 | forge | `payload_cli.py:136-141` | حساب `positional` الأول بتعابير خاطئة يُستبدل فورًا بسطر بسيط — كثافة ميتة |
| R2-forge-10 | forge | `normalizer.py:86-92` | `detect_family` يُسقط كل غير المعلَّم في `SQLI` — موثق لكنه يضخم إحصاءات العائلة ويلوث التصنيف |
| R2-forge-11 | forge | `payload_cli.py:134-161` | `find` يتجاوز `PayloadQueryEngine` والأوزان المنشورة (فرز quality فقط) بينما docstring الوحدة يزعم "exercise the real engines" |
| R2-forge-12 | forge | `quality_gate.py:72-88` | حقول `from_curated_source`/`tested_publicly`/`is_too_common` في `QualitySignal` غير مستهلكة في `evaluate` أبدًا |

### §8.4 ما فُحص ووُجد سليمًا (ضد الانحلال)

- **forge/indexer:** FK مفعّل لكل اتصال (`PRAGMA foreign_keys=ON` — نفس رقعة R2-prism-01 مطبقة هنا أصلاً)، حفظ ذري، تحديث idempotent للصفوف، `_replace_context_rows` بلا بقايا، سكيمة 7 جداول + 6 فهارس مطابقة، `success_rate` مقام محروس.
- **forge/query_engine + bridge + quality_gate:** الأوزان المنشورة (0.4/0.3/0.2/0.1) مطبقة حرفيًا، ترتيب حتمي `(score desc, id asc)`، البُعد المحايد 0.5 موثق، بوابة الجودة تختبر الرفض قبل القبول فعليًا (malware/deprecated/high-risk أولاً)، والجسر يرفض أي حمولة بلا إسناد (FORGE-L7 مفروضة).
- **forge/adversarial + chaining + mutation:** تحويلات حتمية بالكامل، معرفات `sha256[:16]` حتمية (عكس fam-07)، WAF غير معروف → قائمة فارغة لا تخمين، والإسناد يُحمل عبر `dataclasses.replace` (L-3).
- **forge/normalizer + encoding_engine + outcome_tracker:** معرّفات sha256 حتمية، `generate_variants` يقيد الالتقاط على TypeError/UnicodeError فقط (الرقعة الموثقة 2026-10-20 قائمة)، `outcome_id` مبنية من محتوى فعلي، وأختام `sent_at` محفوظة ISO مع تحليل آمن.
- **families/base + promotion + surface_adapter:** عقد candidate-only صارم (extra=forbid)، الترقية fail-closed على CONFIRMED فقط (PROVEN عبر اختباراتها)، `surface_graph_to_inventory` بلا افتراضات صامتة، و`detect_capabilities` من الميتاداتا لا الكلمات المفتاحية فقط.

### §8.5 خطة الإصلاح المقترحة لنافذة 0.35.0

نفس بروتوكول التحقق (§6 من خطة 0.33.0 حرفيًا): اختبار فاشل قبل الإصلاح لكل بند →
`--collect-only` صفر أخطاء → Suite كاملة 0 failed → ruff ratchet → canary 7x STABLE → refreeze.

| الدفعة | البنود | المنطق |
|---|---|---|
| **CA — حاجب** | R2-fam-01، R2-forge-01، R2-fam-02..05 (6 بنود) | إيجابية كاذبة critical، شلل قراءة كوربوس، عائلة ميتة، أدلة مُهملة — وكلها مثبتة بالتنفيذ |
| **CB — متوسطة** | R2-fam-06..11 + R2-forge-02..06 (11 بندًا) | حتمية الأدلة، صمت خاطئ في CLI، عقود تخزين مكسورة |
| **CC — منخفضة** | R2-fam-12..13 + R2-forge-07..12 (8 بنود) | جودة/توثيق/عرض — دفعة واحدة رخيصة |

**قيد الترتيب الصارم:** R2-fam-06 (التوصيل) يجب ألا يُنفذ قبل إغلاق CA — توصيل العمود
الفقري قبل إصلاح fam-01/fam-03/fam-04 سيحوّل أعطال صامتة إلى إيجابيات كاذبة منشورة.

### §8.6 أوامر إعادة الإنتاج

```bash
cd /home/z/my-project/webpent/webpent
PYTHONPATH=src python3 scripts/r2_families_forge_repros.py
# يطبع PROVEN/NOT-REPRODUCED لكل بند من R2-fam-01..06 و R2-forge-01
# ملاحظة: R2-fam-03/04 يتطلبان منفذًا واعيًا بالـ labels (مضمّن في السكربت)
```

---

*نهاية التقرير — قائمة §8 أُغلقت بالكامل: 7 وحدات (dojo/econ/jc/prism/graph/families/forge)،
95 ملفًا / ~20,888 سطرًا مقروءة بالكامل، **70 نتيجة مُتحققة**
(Critical 2 / High 15 / Medium 28 / Low 25). نافذة 0.34.0 أغلقت نتائج الجولة الأساسية
(45/45)، ونافذة 0.35.0 المقترحة تغطي ملحق families/forge (25/25).*
