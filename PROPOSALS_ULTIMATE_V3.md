# PROPOSALS_ULTIMATE_V3 — من صياد أوتوماتيكي إلى صياد يتعلم من السوق

التاريخ: 2026-10-31
الفرع: `donorC-side`
الأساس: كل اقتراحات `PROPOSALS_ULTIMATE_V2.md` الاثني عشر منفذة ومجمّدة (HEAD `c6492f9`، الـ anchor الأخير `8d6a3efb…`).
هذا الملف هو **الجولة الثالثة**: كل اقتراح هنا يقيس فجوة في حلقة **الملاحظة والتعلم والتسليم** — الأداة بتصطاد، لكنها لا تتعلم من رد فعل السوق، ولا تخبر صاحبها في الوقت المناسب، ولا تسلّم تقريرًا بصيغة المنصة التي تدفع عليها.

---

## §0. قراءة صادقة للجاهزية الحالية (قبل الاقتراحات)

ما هو موجود **فعليًا** ولازم ما نقترحش تكرارًا له (نتيجة grep بتاريخ 2026-10-31):

- التعلم داخل الحملة: `attack_memory`, `reflection`, `payload_optimizer` — وبعد V2 §11: `learning/technique_library.py` (مكتبة تقنيات عبر الحملات من بيانات **داخلية** فقط) و`learning/campaign_dedupe.py`
- منطق الأعمال: `business_logic/` فيه `invariant_checker`, `state_transition`, `workflow_analyzer`, `abuse_case_generator`, `scenarios` — لكنه **محلل ثابت ووصفي**: لا يلاعب قيمًا مالية حقيقية في سيناريوهات متعددة الخطوات، ولا يربط النتائج بـ chain v3 كأدلة
- WAF: `waf_detector` (بصمة) و`recon/payload_advisor` و`payload_library` — لكن لا يوجد **محرك تهرب تكيفي** يعدّل البايلود استجابةً لرفض الـ WAF الفعلي
- الإشعارات: `integrations/webhook.py` — webhook واحد عام، متوافق جزئيًا مع Slack/Discord **بلا تنسيق خاص لكل منصة**، بلا ملخص يومي، وبلا بوابات شدة (severity gate)
- الجدولة/الاستئناف: `resume/` (استئناف نقطة توقف يدوي) — لا يوجد **مجدول حملات** بموعد وسقف استيقاظ تلقائي
- التقارير: `reporter/bounty_report.py`, `export.py`, `poc_export.py`, `cvss_engine`, `executive_summary` — تقرير webpent الخاص، **لا يوجد مُصدِّر بصيغة HackerOne/Bugcrowd الرسمية**
- الأسرار: فحوصات عرضية في `js_analyzer` — لا توجد **مكتبة أنماط موحدة** للـ API keys مع تحليل عشوائية، ولا تصنيف مؤكد/مشتبه به
- Takeover: لا يوجد أي موديول takeover (grep: صفر نتائج لـ cname/takeover في recon/)
- GraphQL: `graphql_testing` موجود (V1) — لكن بلا batching/field suggestion/depth attacks
- إعادة الفحص: لا يوجد أي مراقب regression (grep: صفر نتائج)

قاعدة عمل لكل اقتراح: قبل أي سطر كود، `grep` للتأكد إن الموديول مش موجود فعلًا، وتُسجل نتيجة الفحص في أول commit للاقتراح.

---

## §1. حلقة التغذية من السوق (feedback loop) — الأداة تتعلم من ردود الشركات

**الفجوة:** §11 تعلم من بيانات داخلية (نجاح بايلود). الحلقة المفقودة: نتيجة التقرير **الخارجية** — الشركة قبلت (bounty/severity) أو قلبت (duplicate/NFA/informative). هذا هو الإشارة الوحيدة التي تقيس جودة الأداة على السوق فعليًا، ومصدر الأولويات الحقيقي.

**التصميم:**

- موديول جديد `src/webpent/learning/feedback_loop.py`:
  - `OutcomeRecord`: سجل واحد (finding_ref, campaign_id, platform_report_id, outcome ∈ {accepted, duplicate, nfa, informative, spam}, bounty_usd, severity_offered, operator_note, recorded_at) — JSONL append-only (سجل غير قابل للتعديل، التذييل فقط)
  - `record_outcome(...)`: fail-closed على outcome غير معروف؛ bounty_usd >= 0 فقط
  - `class_stats(vuln_class)`: إحصاء لكل فئة (عدد التقارير، معدل القبول، إجمالي المكافآت) — مرجع لـ `targeting/selector.py` كـ reward إضافي (اختياري، flag منفصل)
  - `worst_classes(k)`: الفئات الأكثر قلبًا للتقارير — تُطبع في ملخص الحملة كتحذير واعٍ (لا تحظر تلقائي أبدًا: القرار للمشغّل)
- **الخصوصية:** الملف محلي بالكامل (`feedback_outcomes_path`)؛ لا يُرسل شيء لأي طرف.
- التكامل: `bounty_report` يذكر إحصاءات الحلقة في ملخصه (flag-gated)؛ `campaign_dedupe` يستخدم تقارير `duplicate` السابقة كقائمة انتباه إضافية (annotate فقط).

**الملفات الجديدة:** `src/webpent/learning/feedback_loop.py`، `src/webpent/config/settings.py` (حقلان)، `tests/test_feedback_loop.py`.

**الـ flag:** `enable_feedback_loop` (افتراضي False) + `feedback_outcomes_path` (نص فارغ = معطل حتى مع العلم).

**الاختبارات:** التذييل والتشغيل fail-closed (outcome غير معروف، bounty سالب، encoding تالف، JSON تالف)، إحصاءات دقيقة على fixture، worst_classes ترتيب، flag-off = لا قراءة ولا كتابة أصلًا.

**معيار النجاح:** سجلات outcome محفوظة كـ JSONL تُقرأ كإحصاءات صحيحة، ولا يوجد أي مسار كود يكتب الملف بدون العلم.

---

## §2. محرك تلاعب منطق الأعمال (business logic fuzzer) — الديناميكي لا الوصفي

**الفجوة:** `business_logic/` الحالي يصف التدفقات. الصياد الحقيقي يلاعب القيم **المالية والعدّادات** في تدفق متعدد الخطوات: تعديل سعر قبل الدفع، استخدام الكوبون مرتين، إعادة خطوة إتمام الشراء (replay)، طلب الاسترجاع قبل التسليم.

**التصميم:**

- موديول جديد `src/webpent/business_logic/value_fuzzer.py`:
  - `MoneyValue` / `CountValue` / `IdValue`: أنواع قيم قابلة للتلاعب (مثال: price 100 → 0.01، -1، 1e-9، "100.0000001"، سلسلة "100؛ سعر 0")
  - `FlowPlan`: خطة تدفق من `workflow_analyzer` (خطوات مرتبة، حقول، قيم مرجعية)
  - `mutation_set(value)`: مجموعة تحويلات محددة مسبقًا (صفر، سالب، كسور دقيقة، صفير أعداد كبيرة، حقن نوع، إعادة إرسال خطوة) — قائمة مكتوبة يدويًا وموثقة، **لا توليد LLM هنا** (قابلية التنبؤ والمراجعة)
  - `run_plan(plan, executor, ledger)`: ينفذ التعديلات عبر `executor` المُحقن، كل طلب يمر عبر `request_ledger` + `spend_governor` + `scope_enforcer` إجباري
  - كل ملاحظة: (خطوة، حقل، قيمة أصلية، قيمة معدلة، استجابة، هل انتهى التدفق بحالة "ناجحة-غير متوقعة") — الفارق بين "نجح الطلب" و"نجح بسعر معدل" هو الاختبار
- **فشل مغلق:** بدون `enable_logic_fuzzing` لا خطة تُنفذ؛ خطوات خارج نطاق `scope_enforcer` تُرفض قبل الإرسال مع `inconclusive: out_of_scope`.
- التكامل: النتائج تدخل chain v3 كـ artifacts (نوع جديد `ART_LOGIC_MUTATION`)؛ المحقق موجود في `verification/`.

**الملفات الجديدة:** `src/webpent/business_logic/value_fuzzer.py`، `src/webpent/config/settings.py` (حقلان)، `tests/test_logic_value_fuzzer.py` (executor وهمي بالكامل — لا شبكة أبدًا).

**الـ flag:** `enable_logic_fuzzing` (افتراضي False) + `logic_fuzz_max_mutations` (سقف افتراضي 50).

**الاختبارات:** مجموعات التحويل على أنواع القيم، تنفيذ خطة بالكامل عبر executor وهمي، سقف التعديلات، رفض خارج النطاق قبل الإرسال، التكامل مع الـ ledger (كل طلب مسجل)، لا ملاحظة تُعلَّم "Tool-Confirmed" بدون تحقق المحقق.

**معيار النجاح:** سيناريو دمية (تدفق شراء على fixture محلي) يُكتشف فيه "سعر معدّل → نجاح" ويدخل الـ chain كدليل، بينما التدفق الطبيعي لا يُعلَّم إيجابيًا كاذبًا.

---

## §3. التهرب التكيفي من الـ WAF (adaptive evasion) — يعدّل استجابةً للرفض

**الفجوة:** عندنا بصمة WAF ومكتبة بايلودات. الصياد يتكيف: لو الطلب انرفع (403/429/block)، جرب تحويلاً — حالة أحرف، ترميز URL مزدوج، تعليقات SQL، فواصل JSON — وسجل أي تحويل نفع، وأعد استخدامه في الجلسة.

**التصميم:**

- موديول جديد `src/webpent/waf_evasion/adaptive.py`:
  - `transform_registry`: قائمة تحويلات نصية مكتوبة (uppercase hex، double-url-encode، inline comment، json-unicode-escape، space-substitution، وغيرها) — كل واحدة دالة نقية (str → str)، قابلة للاختبار بالكامل بلا شبكة
  - `AdaptiveClient.send_with_adaptation(request_fn, payload, context)`: يرسل الأصلية؛ عند رفض WAF موثق (حسب بصمة `waf_detector`) يدور على التحويلات **بترتيب ذاكرة الجلسة** (المحوّلات الناجحة أولًا — نفس نمط §11 لكن داخل الحملة)؛ كل محاولة تُسجل في الـ ledger
  - `BackoffPolicy`: على 429/تكرار الحجب يبطئ (فاصل أُسّي بسقف) — **التهرب ليس عنيفًا**: أقصى عدد محاولات لكل طلب (`max_attempts` افتراضي 3) ثم يستسلم ويسجل `inconclusive: waf_blocked`
- **الحدود الأخلاقية المكتوبة في الموديول:** التهرب هنا يخدم اختبار تفويض مكتسب فقط؛ لا يعمل خارج `scope_enforcer`، ويحترم `kill_switch` وحد الـ ledger مثل أي إرسال.
- التكامل: مستهلكه الأول `agents/payload_optimizer/agent.py` (بدل الرفض النهائي يجرب التكيف) و`race_conditions/` و`validators/` عبر دالة واحدة مشتركة.

**الملفات الجديدة:** `src/webpent/waf_evasion/__init__.py`، `src/webpent/waf_evasion/adaptive.py`، `src/webpent/config/settings.py` (حقلان)، `tests/test_waf_adaptive.py` (request_fn وهمي يرفض ثم يقبل — لا شبكة).

**الـ flag:** `enable_waf_adaptive` (افتراضي False) + `waf_adaptive_max_attempts` (افتراضي 3، سقف صلب 5).

**الاختبارات:** كل تحويل دالة نقي (فوق/تحت، idempotency معكوس)، دورة رفض→تحويل→قبول بالذاكرة، سقف المحاولات ثم `inconclusive`، backoff أُسّي بسقف، تحترم الـ kill switch (رفض إرسال أثناء تفعيله).

**معيار النجاح:** fixture يرفض البايلود الخام ويقبل أحد التحويلات — المحرك يعيد استخدامه في المحاولة التالية من الذاكرة دون إعادة تجربة كل التحويلات.

---

## §4. التنبيهات الفورية لكل منصة (notifications) — الخبر يوصلك

**الفجوة:** `webhook.py` موجود لكنه عام: بلا تنسيق لكل منصة، بلا بوابة شدة، بلا ملخص يومي. صاحب الأداة لا يفتح البث كل ساعة.

**التصميم:**

- توسيع `src/webpent/integrations/notifications.py` (جديد):
  - `formatters/slack.py`, `formatters/discord.py`, `formatters/telegram.py` (جنب webhook العام الموجود): كل مُنسّق يبني نص/رسوم المنصة الأصلية (attachments/embeds/parse_mode) من Finding — نقيات قابلة للاختبار بلا شبكة
  - `severity_gate(finding)`: تمرير فقط فوق العتبة (`notify_min_severity`، افتراضي "high") — الـ low/info تُجمع في الملخص اليومي فقط
  - `daily_digest(...)`: ملخص واحد (عدد الاكتشافات بالفئة والشدة، أعلى 3 أدلة) — يُجمَّع في الذاكرة/القرص المحلي ويُدفع عند الطلب أو عند إغلاق الحملة، **لا مؤقتات خلفية طالما الأداة ليست خدمة دائمة**
  - `dispatch(...)`: fail-soft للإرسال (فشل منصة لا يكسر الحملة) مع سجل محاولات؛ كل إرسال يمر عبر `request_ledger`
- **الخصوصية:** عناوين الويبهوك أسرار — تُقرأ من البيئة فقط (`*_WEBHOOK_URL`)، لا تُسجل في أي log، ولا تدخل evidence bundle.

**الملفات الجديدة:** `src/webpent/integrations/notifications/{__init__,dispatch,daily_digest}.py` + `formatters/{slack,discord,telegram}.py`، `src/webpent/config/settings.py` (ثلاثة حقول)، `tests/test_notifications.py`.

**الـ flag:** `enable_notifications` (افتراضي False) + `notify_min_severity` (افتراضي high) + `notify_channels` (JSON: قائمة المنصات المضبوطة).

**الاختبارات:** كل مُنسّق على fixture Finding (بنية الرسالة الصحيحة لكل منصة)، بوابة الشدة (تحت العتبة → بلا إرسال فوري)، digest مبني من أحدث الاكتشافات، فشل الإرسال fail-soft مع سجل، لا إرسال أبدًا والـ flag off.

**معيار النجاح:** إرسال فعلي ضد خادم HTTP محلي (fixture) يصل بصيغة المنصة الصحيحة، والعتبة تعمل كما هو موثق.

---

## §5. مجدول الحملات غير المراقب (campaign scheduler) — تشتغل وأنت نايم

**الفجوة:** الحملة تُشغَّل يدويًا وتُستأنف يدويًا (`resume/`). الصياد يريد: "شغّل حملة X كل ليلة على الهدف Y حتى سقف Z".

**التصميم:**

- موديول جديد `src/webpent/scheduler/campaign_scheduler.py`:
  - `ScheduledCampaign`: (target_ref, program_brief_path, schedule ∈ {once, daily, weekly}, start_at, budget_usd_cap, wallclock_minutes_cap, max_findings_cap) — محفوظة في JSONL محلي
  - **لا daemon دائم**: التنفيذ عبر أمر CLI واحد (`webpent scheduler run-due`) يقرأ ما استحق الآن وينفذه — cron/systemd/مهمة خارجية هي من يوقّعه (نفس فلسفة §4: الأداة ليست خدمة دائمة)
  - كل استيقاظ: يحمّل آخر checkpoint عبر `resume/` الموجود، ويحترم سقوفه: أي سقف يُلام → إيقاف نظيف مع `stop_reason` في الحالة
  - `StateFile`: حالة كل حملة مجدولة (last_run, next_due, cumulative_spend, stop_reason) — تُكتب ذرّيًا
  - تكامل إجباري: `scope_enforcer` يُعاد التحقق منه عند كل استيقاظ (النطاق قد يتغير بين الليل والصباح) — تغيّر النطاق → إيقاف فوري، لا استئناف خارج النطاق
- **الحد:** لا حملة تبدأ والـ kill switch مفعل.

**الملفات الجديدة:** `src/webpent/scheduler/{__init__,campaign_scheduler}.py`، إضافة أمر CLI في `cli/`، `src/webpent/config/settings.py` (حقلان)، `tests/test_scheduler.py`.

**الـ flag:** `enable_scheduler` (افتراضي False) + `scheduler_state_path`.

**الاختبارات:** جدولة once/daily واستحقاق زمني صحيح، السقوف (ميزانية/زمن/عدد) توقف نظيف مع stop_reason، فحص النطاق عند الاستيقاظ يوقف عند التغيير، كتابة حالة ذرّية، kill switch يمنع البدء، flag off = لا قراءة ولا تنفيذ.

**معيار النجاح:** حملة مجدولة على fixture محلي تُنفذ ضمن سقفها وتكتب حالة صحيحة تقرأها الدعوة التالية.

---

## §6. مُصدِّر التقارير بصيغة المنصات (platform report export)

**الفجوة:** التقرير النهائي ملك webpent. التقديم الفعلي يكون في HackerOne/Bugcrowd/Intigriti بصيغة نصية موحدة: عنوان، CVSS، خطوات، impact، PoC.

**التصميم:**

- موديول جديد `src/webpent/reporter/platform_export.py`:
  - `export_finding(finding, platform) → str`: Markdown بنية المنصة (العنوان بخط المنصة، جدول CVSS، "Steps to Reproduce" مرقمة، "Impact"، مرفقات باسم الملفات) — نص جاهز للصق، **لا استدعاء API للمنصات** (المشغّل يلصق بنفسه — بلا رموز وصول لأي طرف)
  - `export_bundle_zip(finding, bundle)`: التقرير + evidence bundle الموجود في zip واحد
  - قوالب لكل منصة موثقة الاختبارات؛ الحقول الناقصة (مثال:CVSS ناقص) → عنصر ناقص واضح `missing: cvss_vector` بدل التخمين
- فشل مغلق: platform غير معروف → `platform_export_unsupported`.

**الملفات الجديدة:** `src/webpent/reporter/platform_export.py`، `src/webpent/config/settings.py` (حقل واحد)، `tests/test_platform_export.py`.

**الـ flag:** `enable_platform_export` (افتراضي False — قراءة فقط لكن نحافظ على نمط واحد).

**الاختبارات:** قوالب المنصات الثلاث على fixture كامل (بنية الأقسام الصحيحة)، الحقل الناقص لا يُخترع أبدًا، رفض منصة غير معروفة، zip يحوي التقرير + الأدلة، والـ flag off يرفض.

**معيار النجاح:** تقرير fixture يُصدَّر بصيغة HackerOne ويحتوي كل أقسامها المعروفة دون حقل مخترع.

---

## §7. كاشف الأسرار المتسربة (secrets scanner) بمكتبة أنماط موحدة

**الفجوة:** فحوصات عرضية في `js_analyzer`. الصياد يفحص JS/backups/`/.git` ضد مكتبة أنماط معروفة (AWS, GCP, Stripe, Slack, JWT, GitHub) + تحليل عشوائية (Shannon) للنصوص المرشحة، مع تفريق **مؤكد** (pattern متطابق بصيغة البادئة الرسمية) عن **مشتبه به** (عشوائية عالية + سياق).

**التصميم:**

- موديول جديد `src/webpent/secrets_scanner/scanner.py`:
  - `PATTERN_LIBRARY`: قائمة ثابتة موثقة المصدر (بادئات رسمية معروفة: `AKIA`, `sk_live_`, `ghp_`, `xoxb-`, ...) + regex لكل نمط + مستوى الثقة
  - `shannon_entropy(s)`: للمرشحين ذوي العشوائية العالية بلا نمط معروف → "suspected" فقط
  - `scan_text(text, source_hint) → list[SecretHit]`: (kind, confidence ∈ {confirmed, suspected}, span, source) — **القيم الحساسة تُخفَّى (mask) في كل مخرجات**: أول 4 وآخر 4 أحرف فقط
  - نقاط الفحص: JS المكتشفة (`js_discovery`)، response bodies، وروابط شائعة للنسخ الاحتياطية (**فقط داخل النطاق** — scope_enforcer إجباري)
  - التكامل: النتائج findings من فئة "exposed_secret" بسرعة خطورة حسب الثقة؛ confirmed → Tool-Confirmed مسار المحقق الموجود
- **قاعدة صارمة:** القيم الكاملة لا تُطبع أبدًا في اللوج أو التقرير — mask دائمًا؛ الأصل في evidence bundle المشفر فقط.

**الملفات الجديدة:** `src/webpent/secrets_scanner/{__init__,scanner}.py`، `src/webpent/config/settings.py` (حقلان)، `tests/test_secrets_scanner.py` (قيم fixture وهمية بالكامل).

**الـ flag:** `enable_secrets_scanner` (افتراضي False) + `secrets_min_entropy` (افتراضي 3.5).

**الاختبارات:** كل نمط في المكتبة يُكتشف ببادئة صحيحة (confirmed)، عشوائية عالية بلا نمط → suspected، عشوائية منخفضة → لا شيء، mask في كل المخرجات (لا قيمة كاملة في أي سطر مخرج)، رفض مسح خارج النطاق، flag off = صفر عمل.

**معيار النجاح:** صفحة fixture تحتوي مفتاحًا وهميًا ببادئة AWS تُكتشف confirmed ومُقنَّع، ومفتاح عشوائي بلا بادئة → suspected، ولا يظهر الأصل كاملًا في أي مخرج.

---

## §8. كاشف Subdomain Takeover — مكسب سريع بأرضية موجودة

**الفجوة:** صفر موديول takeover (grep). الأرضية موجودة: recon DNS + OAST من V2.

**التصميم:**

- موديول جديد `src/webpent/recon/takeover.py`:
  - `FINGERPRINTS`: جدول بصمات خدمات معروفة (رسائل 404/NXDOMAIN المميزة: "There isn't a GitHub Pages site here", "Bucket Not Found", " NoSuchBucket", Heroku "No such app" ...) — ثابت، موثق، قابل للتوسعة
  - `check_host(host) → TakeoverVerdict`: يتساءل DNS عن CNAME معلق → يجلب HTTP → يطابق البصمة → verdict ∈ {not_vulnerable, match_fingerprint (سبب واضح), inconclusive}
  - **لا تسجيل حسابات ولا إثبات نشط في V3-الجولة الأولى:** التقرير ببصمة مطابقة + دليل (الـ CNAME + جسم 404) كافٍ للتقديم؛ الإثبات النشط يبقى توثيقًا يدويًا للمشغّل
  - كل فحص عبر `request_ledger`، داخل النطاق فقط

**الملفات الجديدة:** `src/webpent/recon/takeover.py`، `src/webpent/config/settings.py` (حقلان)، `tests/test_takeover.py` (DNS/HTTP stubs بالكامل).

**الـ flag:** `enable_takeover_scan` (افتراضي False) + `takeover_concurrency` (افتراضي 4).

**الاختبارات:** مطابقة بصمة على fixture (GitHub Pages/Bucket)، CNAME سليم + 404 غير مطابق → not_vulnerable، غياب DNS → inconclusive لا claim، احترام النطاق والـ ledger، التزامن محدود بالـ flag.

**معيار النجاح:** fixture DNS stub بسجل معلق وبصمة GitHub Pages → verdict دقيق مع دليل مُلحق بالتقرير.

---

## §9. GraphQL عميق (batching, suggestions, depth) — V1 كان سطحًا

**الفجوة:** `graphql_testing` من V1 يغطي introspection والاستعلامات الأساسية. المفقود: **API batching** (مصفوفة عمليات في طلب واحد → تجاوز حد المعدل)، **field suggestions** (`Did you mean "email"?` → اكتشاف الحقول الخاصة)، **هجمات العمق** (استعلام متداخل يجهد المحلل)، **alias flood**.

**التصميم:**

- توسيع `src/webpent/graphql_testing/deep.py` (جديد):
  - `build_batch_operation(queries, n)`: مصفوفة JSON للفحص هل الخادم ينفذها جميعًا (→ تجاوز الحد) — الاكتشاف فقط، لا إغراق: سقف n افتراضي 10
  - `suggestion_probe(field_guess)`: حقل غير موجود → قراءة اقتراحات الرد → اكتشاف أسماء حقول حقيقية (مثل "passwordHash")
  - `depth_probe(depth)`: استعلام متداخل متصاعد (سقف افتراضي 8) — يقيس هل الخادم يفرض حد عمق أم لا، مع مهلة قصيرة وإيقاف عند بطء ملحوظ
  - كل شيء عبر الـ ledger والنطاق إجباري

**الملفات الجديدة:** `src/webpent/graphql_testing/deep.py`، `src/webpent/config/settings.py` (حقلان)، `tests/test_graphql_deep.py` (خادم GraphQL وهمي بالكامل).

**الـ flag:** `enable_graphql_deep` (افتراضي False) + `graphql_deep_max_batch` (افتراضي 10).

**الاختبارات:** بناء batch صحيح، اكتشاف تنفيذ batch → finding، استخراج اقتراحات من ردود وهمية، سقوف العمق والbatch، لا إغراق (عدد الطلبات محدود ومرصود بالـ ledger).

**معيار النجاح:** خادم وهمي ينفذ batch ويسرب اقتراحات → نتيجتان مكتشفان بطلبات معدودة موثقة.

---

## §10. مراقب إعادة الفحص (regression monitor) — مراقبة الثغرات المقبولة

**الفجوة:** الثغرة المقبولة تُنسى. الشركات تصلح ثم يرجع الخلل (regression). الصياد الذي يلاحظ رجوع الثغرة يقدم تقريرًا جديدًا عالي القيمة.

**التصميم:**

- موديول جديد `src/webpent/monitor/regression_monitor.py`:
  - `WatchRecord`: (finding_ref, vuln_class, endpoint, fingerprint, last_state ∈ {vulnerable, fixed, unverifiable}, last_checked_at) — JSONL محلي
  - `fingerprint(finding)`: بصمة قابلة لإعادة التحقق (فئة + مسار + معلمات مفتاحية) — نفس فلسفة tokenize في §11
  - `recheck(record)`: يعيد اختبار الحمولة المرجعية المسجلة فقط (لا استكشاف جديد) عبر نفس مسار `verification/`؛ النتيجة تحدّث الحالة مع طابع زمني
  - `diff_report()`: ما رجع (vulnerable من جديد) — قائمة مرشحين لتقرير regression للمشغّل
  - **الحدود:** يعيد اختبار ما سبق تأكيده فقط؛ لا يبدأ استكشافًا جديدًا؛ داخل النطاق والـ ledger والسقوف

**الملفات الجديدة:** `src/webpent/monitor/{__init__,regression_monitor}.py`، `src/webpent/config/settings.py` (حقلان)، `tests/test_regression_monitor.py`.

**الـ flag:** `enable_regression_monitor` (افتراضي False) + `regression_watch_path`.

**الاختبارات:** بصمة مستقرة للحالة المكافئة، إعادة فحص عبر verifier وهمي (vulnerable→fixed→vulnerable) تحدّث الحالات بالترتيب، رفض إعادة فحص خارج النطاق، diff_report يعود بالرجوع فقط، flag off = صفر عمل.

**معيار النجاح:** دورة كاملة على fixture: ثغرة مقبولة → رقابت → يتغير رد الخادم → الحالة تتقلب بدقة وتظهر في diff_report.

---

## §13. ترتيب التنفيذ (لماذا هذا الترتيب)

| # | الاقتراح | الجهد | يعتمد على | لماذا هنا |
|---|----------|-------|-----------|-----------|
| 1 | §1 Feedback loop | S | §11 V2 | الحلقة الخارجية أولًا: بيانات السوق تقيس كل ما بعدها |
| 2 | §2 Logic fuzzer | L | — | أعلى قيمة اكتشاف مالية في الجولة |
| 3 | §3 WAF adaptive | M | §11 V2 (نمط الذاكرة) | يرفع نسبة الاختراق في كل الفئات |
| 4 | §4 Notifications | S | — | مكسب فوري لتجربة الاستخدام |
| 5 | §5 Scheduler | M | resume + §4 | تشغيل غير مراقب يحتاج تنبيهات |
| 6 | §6 Platform export | S | evidence bundle | تسليم جاهز للصق بعد كل ما سبق |
| 7 | §7 Secrets scanner | M | js_discovery | فئة مكافآت كاملة جديدة |
| 8 | §8 Takeover | S | recon DNS | سريع ومكتمل الأرضية |
| 9 | §9 GraphQL deep | M | graphql_testing V1 | تعميق فئة موجودة |
| 10 | §10 Regression | S | verification | إغلاق الحلقة: ما قبلته نراقبه |

القاعدة نفسها: كل اقتراح — flag جديد افتراضي False، فشل مغلق، اختبارات ملحقة، وبعد أي تعديل على ملفات مجمّدة: إعادة تجميد Item جديد ببروتوكول PRE/POST_HASHES. اقتراح واحد = commit واحد (أو أكثر)، ولا يُدمج اقتراحان في commit واحد.

---

## §14. ملاحظة ختامية

V2 أعطت الأداة عينًا (OAST، متصفح، خرائط) ومخًا (اختيار وتعلم). V3 تربطها **بالسوق**: تتعلم من قبول ورفض التقارير (§1)، تطارد الفئة التي تدفع أعلى المكافآت (§2)، تخترق الأنظمة المحمية قانونيًا (§3)، وتبلغك وتسلّمك بصيغة المنصة (§4-§6) ثم تكمل دورة الحياة (§7-§10). بعد هذه الجولة، جملة "ينافس الشركات" يملكها مشروعك من غير مدير — بل من غير إنسان واقف بينها وبين الهدف.
