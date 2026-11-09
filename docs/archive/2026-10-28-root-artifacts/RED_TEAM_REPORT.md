# تقرير Red Team — مراجعة نقدية لتعديلات Team 1 (2026-10)

مراجعة صارمة، مُجراة بنفسي على نفس التعديلات التسعة الموثّقة في `TEAM1_MERGE_NOTES.md`، بهدف واحد: إيجاد كل عيب حقيقي قبل ما المستخدم يدمج الكود. لا تجميل، لا تبرير للقرارات السابقة لمجرد أنني من كتبها — كل finding هنا إما مُثبَت بقراءة الكود الفعلي وتتبّع مسار التنفيذ، أو مُعلَّم صراحة كاحتمال نظري غير مؤكَّد تجريبيًا.

**منهجية:** قراءة كامل كل دالة مُعدَّلة أو مُضافة، تتبّع كل نقطة استدعاء، ومحاكاة سيناريوهات فشل ملموسة (ضوضاء شبكية، SPA fallback routing، WAF/reverse-proxy معالجة TRACE، إلخ) بدل الاكتفاء بقراءة سطحية. لم أُشغِّل كل سيناريو تجريبيًا فعليًا (الوقت لا يسمح) — أي ادّعاء غير مُشغَّل تجريبيًا مُعلَّم كذلك صراحة.

---

## الخلاصة التنفيذية

| # | الملف | الخطورة | المشكلة باختصار | الحالة |
|---|---|---|---|---|
| 1 | `validator/active_checks.py` | **عالية** | الـ negative control في `validate_race_condition` ضعيف بالبناء — يقارن TRACE-متزامن ضد POST-تسلسلي بدل مقارنته بمعيار مستقل | **تم الإصلاح** |
| 2 | `hypothesis_analyzer/agent.py` | **عالية** | `_nosql_operator_hypotheses` يغطي query string فقط، لا يغطي POST body (الموضع الأشيع لحقن NoSQL في APIs حديثة) | **تم الإصلاح جزئيًا** (انظر التفاصيل) |
| 3 | `business_logic_fuzzer/agent.py` | متوسطة | `causal_signal` بلا margin — فرق نجاح واحد فقط كافٍ للترقية، حساس للضوضاء الشبكية | **تم الإصلاح** |
| 4 | `api_testing/agent.py` | متوسطة | احتمال تكرار نفس الـ finding مرتين إذا تطابقت استجابة مرشَّحَي host-root وapp-root (سيناريو SPA/catch-all) | **تم الإصلاح** |
| 5 | `hypothesis_analyzer/agent.py` | منخفضة | `$lt`/`$gt` يطابقان قبل `$lte`/`$gte` (substring matching، ترتيب القائمة) — mislabeling في الوصف فقط | **تم الإصلاح** |
| 6 | `subdomain_takeover/agent.py` | منخفضة (موثَّقة) | بعض الـ body markers الجديدة (anima، strikingly، help-juice) عامة نسبيًا | **لم تُعدَّل — قرار واعٍ، مُبرَّر أدناه** |
| 7 | `business_logic_fuzzer/agent.py` | بسيطة (دفاعية) | threads الـ burst المتزامن بلا `daemon=True` | **تم الإصلاح** |
| 8 | `cli/git_source.py` | بسيطة | فشل `git init` نفسه لا يُنظِّف `destination` | **تم الإصلاح** |
| 9 | `hypothesis_analyzer/agent.py` | تافهة (cosmetic) | `results[:2]` في `_nosql_operator_hypotheses` كود ميت — التصميم لا يصل أبدًا لأكثر من نتيجة واحدة | **تم التوثيق فقط (لا تأثير وظيفي)** |

---

## التفاصيل

### 1. [عالية] Negative control ضعيف بالبناء في `validate_race_condition`

**الملف:** `src/webpent/agents/validator/active_checks.py` (كود موجود من قبل هذا السبرنت — لم أكتبه، لكن الـ replay producer الذي بنيته هذا السبرنت هو ما **يُفعِّل** هذا المسار لأول مرة؛ قبل ذلك كانت الثغرة "ميتة" لأن `evidence["race_replay"]` لم يكن يُملأ أبدًا).

**الكود الحالي (قبل الإصلاح):**
```python
negative_control_complete = bool(
    metrics_valid
    and independent_control
    and negative_successes <= baseline_successes
)
```

**المشكلة:** هذا الشرط يقارن `negative_successes` (عدد نجاحات TRACE **المتزامن**) ضد `baseline_successes` (عدد نجاحات POST **التسلسلي**) — مقارنة بين كميتين لا علاقة منطقية مباشرة بينهما. في السيناريو الأشيع عمليًا — أي خادم/framework/WAF يرفض TRACE بالكامل بغض النظر عن أي شيء (وهذا هو السلوك المتوقع لـ TRACE في الإنتاج) — فإن `negative_successes = 0`، و`0 <= baseline_successes` صحيح **دائمًا تقريبًا** (طالما `baseline_successes >= 0`، وهو ما يضمنه `metrics_valid` أصلًا). النتيجة: `negative_control_complete` يصبح **True في الغالبية الساحقة من الحالات الواقعية بصرف النظر عن قوة الدليل الفعلي** — فلا يضيف حماية مستقلة حقيقية فوق `causal_signal` وحده، رغم أن الـ evidence bundle المُرسَل للمستخدم يصف الحالة بأنها "negative control مستقل أكّد عدم التكرار" — وهو وصف لا يعكس ضعف الاختبار الفعلي.

هذا **ليس** مسارًا ينتج false positives من تلقاء نفسه (لأن `causal_signal` — المقارنة الأساسية candidate > baseline — ما زال شرطًا مطلوبًا ومستقلًا)، لكنه يُضعِف ادّعاء "استقلالية" الدليل الذي يُسلَّم للمستخدم كجزء من `Tool-Confirmed`.

**الإصلاح المطبَّق:** استبدال المقارنة بمعيار مستقل فعليًا: `negative_successes` يجب أن تكون صغيرة في حد ذاتها (≤1، أي لا تكرار يُذكر في TRACE نفسها)، بدل مقارنتها بـ baseline غير ذي صلة. هذا يجعل الـ negative control يختبر فعليًا "هل آلية الـ burst نفسها تُنتج نجاحات زائفة متعددة؟" — وهو السؤال الذي صُمِّم من أجله أصلًا.

---

### 2. [عالية] `_nosql_operator_hypotheses` لا يغطي POST body

**الملف:** `src/webpent/agents/hypothesis_analyzer/agent.py`

**المشكلة:** الدالة توقيعها `_nosql_operator_hypotheses(url: str)` — تفحص فقط query string الخاص بالـ URL. السطح النمطي الأشيع فعليًا لحقن NoSQL في REST/GraphQL APIs حديثة هو **جسم طلب POST بصيغة JSON** (مثال: `{"username": {"$ne": "admin"}}`)، وليس query string. هذا يعني أن التغطية الفعلية لفئة `nosql_injection` — التي كان الهدف المُعلَن منها "سد فجوة فئة يتيمة بالكامل" — محدودة فعليًا بالحالة الأقل شيوعًا.

**ملاحظة تخفيفية (مُتحقَّق منها بقراءة الكود):** الدالة تتضمن fallback لمسح `raw_query` (بعد `unquote`) إن فشلت مطابقة أسماء الـ parameters — وهذا يُغطّي جزئيًا وبشكل غير مقصود حالة JSON مُدمَّج داخل قيمة query parameter واحدة (مثل `?filter={"age":{"$gt":0}}` مُرمَّز URL-encoded)، لأن الـ operator يبقى ظاهرًا في النص الخام بعد فك الترميز. لكن هذا لا يغطي جسم طلب POST منفصل عن الـ URL.

**الإصلاح المطبَّق:** إضافة دالة مكمِّلة `_nosql_operator_body_hypotheses(form_data)` تفحص قيم حقول POST (ليس فقط أسماءها كما تفعل `_generic_form_field_hypotheses` الموجودة) بحثًا عن نفس صيغ الـ operator — ودمجها في نفس نقطة التوليد العامة حيث تتوفر بيانات form. هذا توسيع حقيقي وليس إعادة هيكلة؛ الدالة الأصلية (query-string) بقيت كما هي بلا تغيير في سلوكها.

---

### 3. [متوسطة] `causal_signal` بلا margin إحصائي

**الملف:** `src/webpent/agents/validator/active_checks.py`

**المشكلة:** `causal_signal = bool(metrics_valid and candidate_successes > baseline_successes)` — أي فرق موجب، ولو بمقدار نجاح واحد فقط من أصل burst كامل (مثال: 10 مقابل 9)، كافٍ لاعتبار الإشارة "سببية". بناءً على خبرة عامة بسلوك الشبكات، هذا حساس جدًا للضوضاء العشوائية (timeout عرضي واحد أثناء الإرسال التسلسلي الأبطأ، أو rate-limiting خفيف) أكثر من كونه دليلًا قويًا على TOCTOU حقيقي — خصوصًا أن النتيجة تُرقَّى مباشرة إلى `Tool-Confirmed` (أعلى درجة ثقة في النظام) لا `Needs Human Review`.

**الإصلاح المطبَّق:** رفع الشرط إلى فرق لا يقل عن 2 (`candidate_successes - baseline_successes >= 2`) بدل `> 0`. هذا لا يُسقِط race conditions حقيقية (فجوة TOCTOU حقيقية عادة تُنتج فرقًا واضحًا متعدد النجاحات لا نجاحًا واحدًا زائدًا)، لكنه يرفع عتبة الدليل المطلوب للترقية التلقائية.

---

### 4. [متوسطة] تكرار محتمل لنفس الـ finding عبر مرشَّحَي URL

**الملف:** `src/webpent/agents/api_testing/agent.py`

**المشكلة:** بعد إدخال `_iter_path_url_candidates`، كل مسار مخمَّن قد يُجرَّب على مرشَّحين (host-root وapp-root-preserving). في تطبيقات تستخدم SPA routing مع catch-all fallback (نمط شائع فعليًا — أي مسار غير معروف يُعاد توجيهه لنفس الصفحة الرئيسية)، من الممكن أن يُنتج **كلا** المرشَّحين نفس الاستجابة الإيجابية (مثلًا كلاهما "ناجح" في اختبار JWT alg=none إن كان التطبيق يوجّه كل شيء لنفس الـ handler). بما أن الحلقات الأربع (`_probe_graphql`, `_probe_jwt_alg_none`, `_probe_jwt_key_confusion`, `_probe_mass_assignment`) لم تكن مصمَّمة أصلًا (قبل هذا السبرنت) للتعامل مع أكثر من محاولة واحدة لكل path، فمن المحتمل — لم أُثبِت هذا بتشغيل فعلي، إنما بقراءة بنية الحلقات — أن يُسجَّل finding مرتين لنفس الثغرة المنطقية بمسارين مختلفين (`url` مختلف) لنفس `path`.

**أثر إضافي غير وظيفي:** تضاعف عدد الطلبات الفعلية المُرسلة (حتى 2×) لكل مسار مخمَّن حين يكون للـ `base_url` بادئة تطبيق — ملحوظ تحديدًا في `_probe_jwt_key_confusion` حيث الحلقة متداخلة أصلًا (لكل PEM variant × لكل مسار)، فقد يرتفع عدد الطلبات من N×M إلى حتى N×M×2.

**الإصلاح المطبَّق:** في كل من الحلقات الأربع، إضافة `break` بعد أول نجاح/finding لنفس `path` بدل الاستمرار لتجربة المرشَّح الثاني. هذا يحل المشكلتين معًا (تكرار الـ finding وتضاعف الطلبات) دون تغيير منطق الاكتشاف نفسه — ما زال كلا المرشَّحين يُجرَّب حتى أول نجاح، تمامًا كما صُمِّم الإصلاح الأصلي (ترك الاستجابة الحقيقية تقرر)؛ الفرق فقط أنه بمجرد الحصول على دليل كافٍ لا داعي لطلب إضافي على نفس الـ path.

---

### 5. [منخفضة] Mislabeling في مطابقة NoSQL operators (`$lt` قبل `$lte`)

**الملف:** `src/webpent/agents/hypothesis_analyzer/agent.py`

**المشكلة:** `_NOSQL_OPERATOR_FRAGMENTS = ("$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin", ...)` تُفحَص بالترتيب عبر `operator in lowered` (مطابقة substring). بما أن `"$lt"` هي بادئة (prefix) حرفية لـ `"$lte"`، وبما أن `"$lt"` تسبق `"$lte"` في القائمة، فإن أي parameter يحمل operator `$lte` الحقيقي سيُطابَق خطأً كـ `"$lt"` (المطابقة الأولى في الحلقة الداخلية تفوز، والحلقة لا تبحث عن أطول تطابق). نفس المشكلة بالضبط بين `$gt`/`$gte`. **هذا لا يُفقِد الاكتشاف** (لا يزال finding يُولَّد بصورة صحيحة لفئة `nosql_injection`) لكنه يُسجِّل اسم operator غير دقيق في نص الـ `reason` الذي يراه المستخدم.

**الإصلاح المطبَّق:** إعادة ترتيب الفحص ليجرِّب أطول الأنماط أولًا (`$gte`/`$lte`/`$nin` قبل `$gt`/`$lt`/`$in`) بدل الاعتماد على ترتيب التعريف التاريخي.

---

### 6. [منخفضة — موثَّقة، غير مُعدَّلة] عمومية بعض الـ body markers الجديدة

**الملف:** `src/webpent/agents/subdomain_takeover/agent.py`

**المشكلة:** من بين الـ 15 مزوّدًا الجدد، ثلاثة markers عامة بما يكفي لتتطابق نظريًا مع صفحات 404 عادية غير مرتبطة بالاستيلاء الفعلي:
- `anima`: `"The page you were looking for does not exist."` — صياغة قريبة جدًا من رسائل 404 افتراضية شائعة في عدة أطر عمل.
- `strikingly`: `"PAGE NOT FOUND."` — عامة جدًا.
- `help-juice`: `"We could not find what you're looking for."` — عامة.

بدرجة أقل: `bitbucket` (`"Repository not found"`), `surge-sh` (`"project not found"`), `gemfury` (`"404: This page could not be found."`), `agile-crm` (`"Sorry, this page is no longer available."`).

**لماذا لم أُعدِّل هذا:** المخاطرة الفعلية مخفَّفة بطبقتين مستقلتين موجودتين فعلًا في التصميم الأصلي (قبل هذا السبرنت): (أ) الـ body marker لا يُفحَص أصلًا إلا بعد أن يتطابق الـ CNAME الفعلي للمضيف مع نطاق المزوّد المحدَّد (`strikinglydns.com`, `animaapp.io`, إلخ) — فليس أي موقع في الإنترنت يصل لمرحلة فحص الـ body، فقط مضيفات مُفوَّضة فعليًا لهذا المزوّد تحديدًا؛ (ب) أي finding من هذا المكشاف يُصنَّف دائمًا `confidence_level="Needs Human Review"` صراحة (وليس `Tool-Confirmed`)، مع `promotion_guard: "blocked_missing_negative_control_and_ownership_proof"` في الـ evidence bundle — أي أن أقصى أثر لأي false positive هنا هو عنصر يحتاج مراجعة بشرية، لا ادّعاء مؤكَّد يُضلِّل تقريرًا نهائيًا. تعديل الكود لمعالجة هذا (مثل فرض حد أدنى لطول الـ marker) كان سيضيف تعقيدًا حقيقيًا (تمييز تعسفي بين markers "قوية" و"ضعيفة") مقابل فائدة محدودة بالنظر إلى الحمايتين الموجودتين. **القرار: توثيق بدل تعديل.**

---

### 7. [بسيطة — دفاعية] Threads الـ burst المتزامن بلا `daemon=True`

**الملف:** `src/webpent/agents/business_logic_fuzzer/agent.py`، دالة `_send_concurrent_burst`

**المشكلة:** `threading.Thread(target=..., args=(_worker,))` — بلا `daemon=True`. مع وجود `t.join(timeout=30.0)` والـ httpx client الداخلي بـ `timeout=10.0`، فإن تعلُّق thread لفترة أطول من ذلك نادر جدًا في الممارسة، لكنه ليس مستحيلًا نظريًا (طبقة شبكية متوسطة معطوبة، إلخ). في حال حدوثه، الـ thread غير-daemon يبقى حيًا في الخلفية بدل أن يُنهى تلقائيًا مع العملية الرئيسية.

**الإصلاح المطبَّق:** إضافة `daemon=True` كدفاع إضافي بسيط، بلا أي تغيير سلوكي آخر.

---

### 8. [بسيطة] فشل `git init` لا يُنظِّف `destination`

**الملف:** `src/webpent/cli/git_source.py`

**المشكلة:** خطوات fallback الأربع (`init`, `remote add`, `fetch`, `checkout`) محاطة بـ `try/except GitSourceError: shutil.rmtree(...); raise` — لكن فحص `init.returncode != 0` والرفع المقابل يقعان **قبل** بداية هذا الـ `try` (الفحص الأول في التسلسل)، فإذا فشل `init` نفسه، لا يحدث أي تنظيف لـ `destination` (التي قد يكون `git init` أنشأها جزئيًا).

**الإصلاح المطبَّق:** نقل فحص `init.returncode` ليكون أول سطر داخل نفس كتلة `try`، بحيث تُغطّى الحالات الأربع كلها بنفس منطق التنظيف الموحَّد.

---

### 9. [تافهة] `results[:2]` كود ميت في `_nosql_operator_hypotheses`

**الملف:** `src/webpent/agents/hypothesis_analyzer/agent.py`

بنية الحلقتين (`if results: break` في اللوحة الخارجية، ومسار الـ raw-query fallback محاط بـ `if not results:`) تضمن أن `results` لا يحتوي أبدًا أكثر من عنصر واحد قبل الوصول لسطر `return results[:2]` — فالـ slice توثيق مُضلِّل (يوحي بإمكانية إرجاع نتيجتين) أكثر منه منطقًا فعليًا. **لم يُعدَّل** — لا تأثير وظيفي، والتغيير الوحيد الممكن (حذف الـ slice أو السماح فعليًا بنتيجتين من مصدرين مختلفين) يستدعي قرار تصميمي (هل نريد فعلًا الإبلاغ عن أكثر من parameter مشبوه في نفس الـ URL؟) أتركه للمستخدم بدل افتراضه من تلقاء نفسي. مذكور هنا للشفافية فقط.

---

## خطة الإصلاح (بالترتيب الذي نُفِّذ به)

1. `active_checks.py::validate_race_condition` — إصلاح الـ negative control (finding #1) + إضافة margin لـ causal_signal (finding #3). نفس الدالة، تعديل واحد مُجمَّع.
2. `hypothesis_analyzer/agent.py` — إضافة `_nosql_operator_body_hypotheses` لتغطية POST body (finding #2) + إعادة ترتيب `_NOSQL_OPERATOR_FRAGMENTS` لحل الـ mislabeling (finding #5).
3. `api_testing/agent.py` — إضافة `break` بعد أول نجاح في الحلقات الأربع لمنع تكرار الـ findings وتقليل حجم الطلبات (finding #4).
4. `business_logic_fuzzer/agent.py` — إضافة `daemon=True` (finding #7).
5. `cli/git_source.py` — نقل فحص `init` داخل نطاق التنظيف الموحَّد (finding #8).
6. تشغيل `py_compile` + `ruff check` على كل ملف مُعدَّل، وتشغيل أي اختبارات ذات صلة متاحة.
7. تحديث `TEAM1_MERGE_NOTES.md` بقسم يوثّق هذه الإصلاحات (لأنها تعديلات لاحقة على ما كان موثَّقًا فيه أصلًا).
8. تحديث الزيب المُسلَّم للمستخدم بكل الملفات المُعدَّلة (بما فيها `active_checks.py` الذي لم يكن ضمن مجموعة الملفات الأصلية) وبهذا التقرير نفسه.
