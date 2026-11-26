# UM-DR-50 P0.2 — FIRST RESPONSE MAP (خريطة الاستجابة الأولى)

التاريخ: 2026-11-26 · المصدر: الكود الحي عند `901f192` (رأس main المستعاد) حصرًا —
لا وثائق قديمة. كل رقم أدناه مقيس بالأمر نفسه على الشجرة الحية.

---

## 1) رأس الشجرة الفعلي والفرع

| البند | القيمة الحية |
|---|---|
| HEAD = origin/main | `901f192a301c6729db802aab5ddbea6d243ace20` |
| طبيعة الاستعادة | **fast-forward نظيف** (`7f3807a..901f192`، بلا force-push) — تحقق `merge-base --is-ancestor 7f3807a 901f192` = YES |
| ما تحتويه السلسلة المستعادة | 32 commit فوق طرف 45: نوافذ 46 (A–K) + 47 (الدمج + W) + 48 (D/C5/Q) + 49 كاملة |
| CI | run `45757557346` انطلق على `901f192` — **أول run في التاريخ على هذه الشجرة** (قبل الاستعادة: 6 فشول متتالية على سلسلة 49 غير المنشورة + run نجاح وحيد على شجرة 45 القديمة `7f3807a`) |
| الوسوم | `v0.47.0` → `89ed209` (نافذة 48) · `v0.48.0` → `901f192` (رأس السلسلة) — كلاهما داخل السلسلة المستعادة |
| Releases منشورة | **لا Release لـv0.47.0 ولا v0.48.0** (آخر Release: v0.46.0 بتاريخ 2026-11-25T04:24) |

**السبب الجذري لانهيار النشر (المشخّص من الطقس الحي):** رفعة نافذة 49 الأخيرة
جرت من **HEAD منفصل** (detached) — أمر الدفع رفع الـobjects لكن مؤشر main
المحلي بقي على طرف نافذة 45، فانسحب remote main إلى `7f3807a` بعد إعادة
المزامنة. الوسم `v0.48.0` (المدفوع مستقلًا) هو ما حفظ سلسلة 49 كاملة من
الضياع. النتيجة: كل أدلة 49 مربوطة بـ`66fec2d` — commit أُعيدت كتابته
لاحقًا (force-push في نفس النافذة) فصار **يتيمًا** في أي استنساخ نظيف.

## 2) فشول CI الحية (بأرقامها)

| run | SHA | النتيجة | السبب الجذري (من الخطة، يُعاد فحصه في P3.1 على الشجرة المستعادة) |
|---|---|---|---|
| 45649523217 | dd4cb32 | failure | فشول نافذة 48 السبعة (thaw/إصدار/أدلة) |
| 45652046537 | 742723f | failure | نفس السلسلة |
| 45671860299 | e2d8891 | failure | نفس السلسلة |
| 45673831332 | d62a151 | failure | نفس السلسلة |
| 45674801102 | 863942c | failure | uv.lock غير متزامن |
| 45681000513 | 66fec2d | failure | `__init__.py` drift + Dockerfile 0.40.1 + BUILD_INFO غير مربوط بأدلة قابلة للحل |
| 45597152161 | 89ed209 | failure (canary) | nightly canary — `STABLE=False`، السبب الجذري في P3.3 |

**ملاحظة مصالحة (كما طلبت الخطة):** أرقام الخطة كُتبت على لقطة `89ed2095`
وقسمها "ست فشول متتالية" تحدّث قبل run النجاح على `7f3807a` — كل فحص هنا
بدأ من الشجرة الحية، والأرقام أعلاه هي الحية الآن.

## 3) كل المسارات النشطة التي ترسل طلبات شبكة (المخفي والديناميكي مشمولين)

### 3.1 الطبقة المحكومة (عبر العقد المركزي)
- **`shared/http.py` (1821 سطرًا)** — العقد المركزي للـHTTP: `SSRFPinningTransport`
  (تثبيت IP ضد rebinding)، حاجز redirect، قائمة حظر loopback/private/link-local/
  metadata (`169.254.0.0/16`...)، بوابات rate، loopback-trusted بمفتاح صريح
  (`set_loopback_trusted_endpoint`). كل عملاء httpx في الشجرة يُبنون منه.
- **`shared/engagement_scope.py` (821 سطرًا)** — عقد التفويض: `OriginPolicy`
  (أصل/منفذ/مسار غير ملتبس)، `EngagementToken`، فحص `_is_strictly_valid_host`.
- مسارات العدسات تمر به: `LaneObservation._request` (detection_lanes_48:187)
  يرفع `set_engagement_target_hosts(*target_scope)` بلا استثناء للمرسل.

### 3.2 النواقل خارج العقد (مواضع الخطر — مدخل المرحلة 1)
| الموضع | الطبيعة | الخطر |
|---|---|---|
| `production/detection_lanes_48.py:1006` | **socket عاري** (D5 raw-path) | يحل الوجهة بنفسه (`socket.create_connection((host, port))`) — لا تثبيت IP، لا فحص rebinding، لا سقف حجم رد (يقرأ حتى الإغلاق)، Host header يُبنى يدويًا |
| `agents/request_smuggling/agent.py:110` | socket عاري | نفس الفئة — مطلوب للـsmuggling الحقيقي لكنه خارج عقد التفويض |
| `shared/h2_race.py:153` | socket عاري | **يُثبّت IP مسبقًا** (`pinned_ip` — نمط جيد جزئيًا) لكنه خارج العقد الموحد |
| `oast/server.py:288` | UDP socket | استماع فقط، الربط الافتراضي 127.0.0.1 — خطر منخفض لكنه غير مسجل في جرد النقل |
| `benchmark/fixtures/runner.py:124` | socket عاري | أداة قياس معملية — خارج مسار الإنتاج لكنها في نفس الشجرة |
| أدوات subprocess الشبكية | sqlmap/nmap/nuclei/gau/arjun (10+ ملفات) | تنفيذ خارجي بشبكة خاصة بها — لا يمر أي منها بعقد التفويض |
| Playwright (7 ملفات: crawler/validator/authentication/execution_sandbox/payload_generator/pentest_worker/protocol_depth) | متصفح | نقل شبكي كامل خارج httpx — يعتمد على حواجز مستقلة (اختبارات m1a موجودة) |
| الاستيراد الديناميكي | 6 ملفات (campaign_worker/context_authority/js_discovery/...) | `importlib` — يجب أن يظهر في جرد النقل الديناميكي (الكتل موجودة في secondary_io_scanner لكنها غير موصولة كجرد إلزامي) |

**النتيجة الحاسمة للمرحلة 1:** يوجد **عقد نقل مركزي ممتاز** (http.py +
engagement_scope.py) لكن **أربعة نواقل عارية تعمل خارجه** — وD5 منها
يستخدم socket عاريًا في مسار كشف إنتاجي، والتعليق في الكود نفسه يقول
"the scope invariant holds" بينما لا يوجد فحص rebinding ولا سقف حجم ولا
قرار سياسة مسجل — **ادعاء بلا آلية**.

## 4) كل مسارات إنشاء/ترقية النتائج

- **المسار الكانوني (سليم):** الفرضيات/العائلات → `families/promotion.py` →
  `verify_replay_evidence` (سلطة CausalGuard) → ProofBundle مختوم →
  `mark Tool-Confirmed` — مسجل في `APPROVED_TOOL_CONFIRMED_WRITERS`
  (اختبار `test_all_literal_writers_are_registered`).
- **الانتهاك (هدف المرحلة 2):** `production/detection_lanes_48.py:1326-1333`
  — `_lane_result()` يكتب `confidence_level="Tool-Confirmed"` **مباشرة** عند
  `verdict.passed`. رُخّص追溯يًا في نافذة 49 بتعليق "routes every candidate
  through verify_replay_evidence" — **توسيع استثناء، وهو بالضبط ما تمنعه
  الخطة (P0.2/قانون 7)**. البديل المعماري: خطوط الكشف تصدر candidates+أدلة
  فقط، والترقية عبر `families/promotion.py` نفسه.
- منشئو `Finding(` آخرون (9 ملفات) — يصدرون مرشحين فقط ما لم يمرّوا بالسلطة.

## 5) طوبولوجيا graph الإنتاجية

- الدخول: `cli/` (unified_hunt, apex, bounty, dojo, cem, econ...) →
  `production/modern_spine.py` / `composite_workflows.py` → العدسات والمسارات.
- عقد الحملة: `campaign_worker` (يستورد ديناميكيًا) + `stateful_discovery`.
- الدماغ: `brain_engine` + `brain_watchdog` + `research_memory_store` (نافذة 47،
  موصولة فعلًا — "wired" — ببوابة `enable_brain_engine`).
- مسارات 48: `detection_lanes_48` (خمسة: workflow-skip/framing-differential/
  graphql-cross-identity/tenant-override/redirect-policy + قناة raw-path)
  ببوابة `enable_umdr48_lanes`.

## 6) الميزات المعطلة افتراضيًا (مقيسة من settings.py)

| العلم | الافتراضي | الدلالة |
|---|---|---|
| `enable_umdr48_lanes` | **False** (settings.py:771) | مسارات كشف 48 معطلة افتراضيًا — قرار تعليق مستمر صحيح |
| `enable_brain_engine` | **False** (settings.py:786) | الدماغ موصول لكنه مطفأ افتراضيًا — ينتظر إثبات OFF/ON (المرحلة 4) |

## 7) أعلى الفجوات المعمارية خطرًا (مرتبة)

1. **نواقل عارية خارج عقد التفويض** (§3.2) — أعلى خطر: أي كشف في HTML/JS
   لا يمنح تفويضًا، لكن socket العاري لا يعرف ذلك أصلًا.
2. **انتهاك سلطة التأكيد في `_lane_result`** (§4) — كتابة Tool-Confirmed
   خارج المسار الكانوني برخصة追溯ية.
3. **أدلة مربوطة بـSHA يتيم** — البنية السابقة كلها (BUILD_INFO/أدلة 49)
   تشير لـ`66fec2d` غير الموجود — يجب إعادة الربط بشجرة حية (P3.2/P3.5).
4. **لا اختبار دائم لقابلية حل SHAs الأدلة** — كارثة 49 كانت ستُمسك ببوابة
   `test_evidence_revisions_resolvable` (P3.4).
5. جرد النقل موجود كأدوات (`secondary_io_scanner`/`direct_io_inventory`)
   لكنه **غير موصول كبوابة CI إلزامية** على الاستنساخ النظيف.

## 8) نوافذ التنفيذ المقترحة وتبعياتها

| نافذة | المحتوى | يعتمد على |
|---|---|---|
| W1 (المرحلة 1) | عقد النقل العاري الكامل: توحيد الأربعة عبر عقد تفويض واحد + الاختبارات العدائية السبعة + تعطيل D5 العاري على engagements حقيقية | لا شيء (أول نافذة) |
| W2 (المرحلة 2) | إزالة كتابة Tool-Confirmed من `_lane_result` + الترقية عبر `families/promotion.py` | W1 (لأن ترقية العدسات تحتاج ناقلها سليمًا) |
| W3 (المرحلة 3) | إعادة ربط BUILD_INFO/الأدلة بـ`901f192` الحية + canary + اختبارا P3.4 الدائمان + Release v0.48.0 | W1+W2 (الإصدار لا يُنشر وبوابة أمنية مفتوحة) |
| W4+ (المراحل 4–9) | العقل OFF/ON بالأرقام، الحلقة الموحدة، العائلات A–E، الأداء، التقارير، الاعتماد | W3 |

## 9) كيفية التحقق من إتمام كل نافذة

- **W1:** جرد نقل كامل (الأدوات الموجودة موصولة كبوابة) + الاختبارات السبعة
  خضراء **بـrun_id منشور** + D5 العاري معطل على engagements حقيقية (اختبار
  يفشل عند محاولة تفعيله خارج معمل معزول مصرّح).
- **W2:** `test_all_literal_writers_are_registered` واختبار AST يمران
  **بقائمة كتاب أصغر أو كما هي** (لا إضافات) + ترقية كل finding للعدسات عبر
  الخدمة الكانونية فقط.
- **W3:** CI أخضر بـrun_id على commit الإصدار بالضبط + Release منشور +
  `test_evidence_revisions_resolvable` أخضر داخل CI (fetch-depth: 0).
- **W4+:** بوابة كل مرحلة كما في نص البعثة، وG1–G8 كلها بروابط raw مفحوصة.

## حالة اللغة الصادقة
`P0.2 = VERIFIED` (كل رقم أعلاه من أمر حي على `901f192`؛ الأوامر في سجل الجلسة).
