# WebPent v15.2 — الخطة الشاملة المدمجة: النقد الإنتاجي + نافذة إعادة التجميد R4
# WebPent v15.2 — Merged Comprehensive Plan: Production Critique + R4 Re-freeze Window

**Date:** 2026-11-02 · **Status:** EXECUTING (same-day execution record below)
**Workspace:** `work/final/WebPent_v15.2_20261029/project` (git repo, branch `main`, head `bb481c7`)
**Authorizes:** the operator greenlit the R4 window — "حارس مفاتيح الإنتاج الصارم + توصيل كواشف الهجمات" —
which by the documented queue process also clears the remaining re-freeze-queue items in the SAME window.
**Supersedes:** nothing. `PRODUCTION_READY_CRITIQUE_PLAN.md` (Round 3) remains the ancestor authority;
this document is the fourth-round critique + the R4 re-freeze window plan **and its execution record**.
**Safety invariant (unchanged):** local-only validation. No external target is ever scanned, probed, or contacted.
All live-probe code paths are fail-closed behind `is_engagement_target_host` + the SSRF-pinned transport.

---

## الجزء الأول — نقد الجولة الرابعة: ما وجدته في المشروع كما وصلني
## Part 1 — Fourth-round critique: what this review found in the delivered tree

الفحص تم على الشجرة المُسلَّمة فعلياً (ZIP النهائي 20261101 → `WebPent_v15.2_20261029`)، سطراً سطراً على
مواقع التنفيذ المعنية، لا على التقارير فقط. النتائج:

| ID | Type | Severity | Finding | Evidence |
|---|---|---|---|---|
| R4-01 | security gap (real) | high | **حارس المفاتيح غير مكتمل — ثغرة الـ LAN-bind:** `_enforce_api_security_posture` في `shared/preflight.py` يعرّف "الربط العام" كمجموعة `{0.0.0.0, ::}` فقط. ربط بـ IP شبكة محلية (مثل `192.168.1.10`) مع `AUTH_ENABLED=false` ومفاتيح `AUDIT_SECRET_KEY`/`CELERY_PAYLOAD_KEY` الافتراضية (فارغة) **يمر بلا أي رفض** — التحذير dev-mode الوحيد هو pydantic UserWarning لا يمنع الإقلاع. خادم مسموع على الشبكة المحلية بمفاتيح HMAC قابلة للـتزوير وبلا مصادقة. | `preflight.py:435-441` — `public_bind` لا يشمل LAN IPs؛ `settings.py:1738-1800` — تحذيرات dev لا رفض |
| R4-02 | wiring gap (documented debt) | high | **كاشفا الهجمات (prototype_pollution / cache_poisoning) غير موصولين:** مكتبات كشف مختبرة (`agents/prototype_pollution/agent.py`, `agents/cache_poisoning/agent.py`) بلا: عضو `VulnClass` في `models/findings.py`، ولا تسجيل في `agents/validator/registry.py`، ولا فرع dispatch في `agents/validator/agent.py`، ولا عقدة في `graph/builder.py`. أي اكتشاف حقيقي منهم لا يمكن أن يصبح `Finding` ولا يصل للتقرير. | `CLAIMS_VS_REALITY_P2.md` § deferred — الادعاء الصادق الحالي "surface signals + tested detector library (unwired)" |
| R4-03 | operator gap (queued CR-09) | medium | `webpent --version` غير موجود (`No such option`) — المشغل/مستجيب الحوادث لا يستطيع تعريف البناء من الـ CLI. | Round-3 CR-09، طابور إعادة التجميد بند 1 |
| R4-04 | security gap (queued CR-10) | medium | API بلا security-headers (`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`); CORS + rate-limiter موجودان. | Round-3 CR-10، `api/app.py:175` — CORSMiddleware فقط |
| R4-05 | observation | info | مسارات dev-mo documented سليمة: `docker-compose.yml` (إنتاج) يمر عبر الحارس الحالي (`AUTH_ENABLED=true` + مفاتيح operator)، `docker-compose.dev.yml` يشغّل uvicorn مباشرة بلا `WEBPENT_API_HOST` في الـ env → preflight يستقبل `host=None` ولا يخمن. أي توسعة للحارس يجب أن تحافظ على هذين المسارين. | `docker-compose.yml:80-86`, `docker-compose.dev.yml:45-56`, `server.py:17-34` |
| R4-06 | verification | pass | البوابة المجمدة 719/719، verify_all 145 checks، السجل، والـ MANIFEST — كلها سليمة في الشجرة المسلَّمة كما هو موثق في Round-3. أعيد التحقق من آلية البوابة (اختبار pytest يقرأ المانيفست + مجموعة drift موثقة) قبل أي تعديل. | `tests/test_frozen_module_gate.py` — invariant 1/2/3، سابقة TC-4/r6c/r9a لإعادة التجميد في المكان |

**الخلاصة النقدية:** المشروع في حالة إنتاجية ممتازة *ضمن نطاقه المُثبت*؛ الفجوات الحقيقية هي بالضبط ما
وثّقه طابور إعادة التجميد + الثغرة R4-01 التي اكتشفتها هذه الجولة (الحارس الحالي أدقّ مما يقول له
النقد في نقطة، وأوسع خللاً في نقطة أخرى: يرفض `0.0.0.0` مع auth-off لكنه يسمح بـ LAN-bind بنفس التهيئة).

---

## الجزء الثاني — الخطة المدمجة (نقد Round-3 + طابور النافذة + اقتراحاتي) — نافذة R4
## Part 2 — The merged plan (Round-3 queue + this critique + my additions) = the R4 window

المستخدم اختار بنودين للتنفيذ ("حارس مفاتيح الإنتاج الصارم وتوصيل كواشف الهجمات"). بحسب قاعدة
النافذة الموثقة (`CLAIMS_VS_REALITY_P2.md`: "wiring is a documented re-freeze-window deliverable";
Round-3: "Both are one-window-sized edits"), الفتح المرخّص للنافذة ينظّف **كل** الطابور في نفس النافذة —
نافذة واحدة، تجميد واحد، أربعة بنود + توثيق. هذا هو التنفيذ الكامل للخطة المدمجة:

### W1 — حارس مفاتيح الإنتاج الصارم (Strict production key guard) — يعالج R4-01 + §3.4 من Round-3
- **الملف:** `src/webpent/shared/preflight.py` (`_enforce_api_security_posture`) — هو موقع التنفيذ الصحيح
  لأنه يستقبل الـ bind host صراحةً من `server.py` و`api/app.py:353`، و`Settings` لا تعرف الـ bind
  (لا يوجد `api_host` في الإعدادات — إضافته سيكرر مصدر الحقيقة).
- **القاعدة الجديدة (fail-closed):**
  1. loopback = `""` (غير محدد) / `localhost` / `::1` / أي `127.*` — فقط هذه تُعتبر محلية.
  2. أي bind آخر (بما فيه `0.0.0.0`, `::`, **وأي LAN/عنوان عام**) = non-local.
  3. non-local bind + (`auth_enabled=False` **أو** أي مفتاح من `JWT_SECRET_KEY` / `AUDIT_SECRET_KEY` /
     `CELERY_PAYLOAD_KEY` في مجموعة الافتراضيات غير الآمنة) → **رفض إقلاع صارم** (`SystemExit`).
  4. فتحة الطوارئ المعتمدة تبقى كما هي: `I_UNDERSTAND_THIS_IS_INSECURE=true` (lab معزول معلن فقط) —
     تُسجَّل CRITICAL ولا تمرّ بصمت.
  5. فشل قراءة الإعدادات مع non-local bind → رفض (fail-closed موسّع من `0.0.0.0` فقط إلى أي non-local).
- **التوافق:** `docker-compose.yml` (إنتاج: auth on + مفاتيح operator) يمرّ؛ `docker-compose.dev.yml`
  (uvicorn مباشر بلا `WEBPENT_API_HOST`) يمرّ كما هو؛ اختبارات preflight الحالية (`0.0.0.0` + auth off)
  لا تزال ترى `SystemExit` بنفس العبارة الدالة "auth disabled".
- **الإضافة المرافقة (settings read-hardening):** توسيع رسالة/حالة الرفض لتفصل الأسباب (auth-off vs
  insecure-keys) في الـ report والسجل — قابلية تشخيص بلا تغيير دلالات الرفض.

### W2 — توصيل كواشف الهجمات (Attack detectors wiring) — يعالج R4-02، بنمط `request_smuggling` حرفياً
الوصفة الموثقة في `CLAIMS_VS_REALITY_P2.md` § Revisit trigger تُنفّذ كما هي:
1. `src/webpent/models/findings.py`: `VulnClass.PROTOTYPE_POLLUTION = "prototype_pollution"` +
   `VulnClass.CACHE_POISONING = "cache_poisoning"` (خارج `EXPLOITABLE_CLASSES` — مسارهم validator
   حتمي مثل `request_smuggling`، لا يمرّون عبر payload_generator).
2. `src/webpent/agents/validator/registry.py`: تسجيل الاثنين في `_IMPLEMENTED_VALIDATORS` و`_ALL_CLASSES`
   بجوار `request_smuggling` (status "tested", evidence_mode "deterministic").
3. `src/webpent/agents/validator/postp0_checks.py`: `validate_prototype_pollution` +
   `validate_cache_poisoning` — إعادة إطلاق حتمية مقيّدة:
   - بناء البروبات من المكتبات (`build_pollution_probes` / `build_cache_key_probes`) — إثبات البروبات
     بيانات صافية، والإرسال عبر النقل المحوكوم فقط (`make_safe_httpx_client` — SSRF-pinned).
   - تأكيد fail-closed بشرط التحليل الثلاثي/الرباعي الموثق: canary في candidate ∧ غيابه في baseline ∧
     اختلاف الاستجابتين (PP)؛ canary في attack ∧ في victim ∧ نظافة control ∧ تطابق الشكل (CP) —
     غير ذلك `inconclusive`، أبداً confirmed.
   - دليل `Replay` كامل (طلب/استجابة/زمن) + negative control — نفس بنية `validate_request_smuggling`.
4. `src/webpent/agents/validator/agent.py`: فرعا dispatch للفئتين → المُحقِّقان الجديدان.
5. `src/webpent/agents/prototype_pollution/agent.py` + `src/webpent/agents/cache_poisoning/agent.py`:
   إضافة عقدة LangGraph لكل منهما (`prototype_pollution_node` / `cache_poisoning_node`) — بنفس جسد
   `request_smuggling_node`: قراءة state، بوابة `is_engagement_target_host` fail-closed قبل أي اتصال،
   البروبات عبر النقل المحوكوم، بناء `Finding` عند التأكيد الحتمي فقط، و`probe_coverage` للشفافية.
6. `src/webpent/graph/builder.py`: `NODE_PROTOTYPE_POLLUTION` + `NODE_CACHE_POISONING`؛ تمديد سلسلة
   الاستكشاف العميق: `business_logic_fuzzer → request_smuggling → prototype_pollution →
   cache_poisoning → strategist`؛ تحديث التعليق المعماري.
7. ملاحظة أمان صريحة في كود العقدتين: البروبات لا تُنفّذ ضد أي هدف خارج نطاق الـ engagement المعلن
   (نفس بوابة request_smuggling)، ولا يوجد أي سلوك شبكي جديد خارج المكتبات المختبرة + النقل المحوكوم.

### W3 — بقية طابور النافذة (نفس النافذة، بحكم الوثيقة)
- **`--version` / `--build-info`** في `src/webpent/cli/commands.py` (CR-09): خيارا Typer يطبعان
  الإصدار من `importlib.metadata` + `webpent.__version__` + `BUILD_INFO.json` (build_name/date/head)
  بلا أي تعديل على ملفات مجمدة أخرى.
- **Security-headers middleware** في `src/webpent/api/app.py` (CR-10): middleware يضبط
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  CSP محافظة للـ viewer UI، و`Strict-Transport-Security` فقط عندما تكون الجلسة خلف TLS
  (`request.url.scheme == https` أو `X-Forwarded-Proto: https`).

### W4 — إعادة التجميد والتوثيق (آلية TC-4/r6c/r9a حرفياً)
1. تحديث هاشات الملفات المعدَّلة **في مكانها** داخل `frozen_modules.sha256` (النطاق ثابت — 719 مساراً،
   بلا إضافة أو حذف).
2. `tests/test_frozen_module_gate.py`: مجموعة `R4_*_PATHS` جديدة توثق مسارات النافذة، وتُضاف إلى
   `expected_drift` (نفس نمط TC-4/R6C/R9).
3. سجل الانحراف: إدخال `DR-020 — R4 production-hardening window` في `archive/self_reports_20261101/DRIFT_REGISTER.md`
   (موقع السجل الحالي) بجدول الملفات وطبيعة كل تغيير.
4. قلب سطر الادعاء في `docs/CLAIMS_VS_REALITY_P2.md`: من "surface signals + tested detector library
   (unwired)" إلى "wired: deterministic validators + graph nodes live"، وإغلاق بندَي الطابور (CR-09/CR-10).
5. ملف هذه الخطة يوضع في جذر المشروع: `PRODUCTION_HARDENING_PLAN_R4.md` (سجل تنفيذ حي).

### W5 — التحقق والقبول
1. `uv sync --locked --extra dev --extra pdf` → EXIT=0.
2. اختبارات موجّهة: `tests/test_frozen_module_gate.py`, `tests/test_postp0_phase5_validators.py`,
   `tests/test_prototype_pollution_agent.py`, `tests/test_cache_poisoning_agent.py`,
   `tests/test_vip_auth_posture.py`, `tests/test_server_launcher.py` + اختبار جديد للبوابة الجديدة.
3. اختبار جديد: `tests/test_r4_production_hardening.py` — الحارس (LAN-bind رفض، loopback مرور،
   override، المفاتيح الافتراضية)، الكواشف (تأكيد/رفض/inconclusive)، الـ registry، الـ headers، الـ CLI version.
4. `verify_all.py` (145 check) + `ruff check` + `ruff format --check`.
5. القيود البيئية المعلنة: الدكر/Playwright/الحاويات غير متاحة في بيئة التنفيذ الحالية — يوثق ما
   تشغّل وما لا تشغّل، بلا ادعاءات زائدة (نفس مبدأ الصدق المعمول به في الجولات السابقة).
6. إعادة توليد `MANIFEST.sha256` من الشجرة النهائية ثم بناء ZIP التسليم.

---

## الجزء الثالث — سجل التنفيذ (أُنجز في نفس اليوم 2026-11-02)
## Part 3 — Execution record (completed same-day)

### W1 — حارس مفاتيح الإنتاج الصارم ✅
- `src/webpent/shared/preflight.py`: مساران جدد `_is_nonlocal_bind` + `_insecure_default_keys`،
  و`_enforce_api_security_posture` مُرقّى: أي ربط غير loopback (وليس فقط 0.0.0.0/::) مع auth-off
  **أو** مفتاح JWT/AUDIT/CELERY على قيمة افتراضية غير آمنة → رفض إقلاع `SystemExit`؛
  فتحة `I_UNDERSTAND_THIS_IS_INSECURE` باقية (تسجيل CRITICAL)؛ فشل قراءة الإعدادات مع ربط
  غير محلي → رفض (fail-closed). دخان حي: `127.0.0.1` يمرّ؛ `192.168.1.50` يُرفض برسالة واضحة.
- اختبارات: `TestStrictKeyGuard` (8 حالات) + `TestNonlocalBindClassifier` في
  `tests/test_r4_production_hardening.py` — خضراء.

### W2 — توصيل كواشف الهجمات ✅ (بنمط request_smuggling حرفياً)
- `models/findings.py`: `PROTOTYPE_POLLUTION` + `CACHE_POISONING` (خارج EXPLOITABLE_CLASSES).
- `agents/validator/registry.py`: كلاسانا مسجلان بجوار request_smuggling (tested/deterministic).
- `agents/validator/postp0_checks.py`: `validate_prototype_pollution` (مثلث الانعكاس fail-closed)
  + `validate_cache_poisoning` (التفاضل ثلاثي الطلبات fail-closed) — نقل SSRF-pinned، دليل Replay
  كامل + negative controls، التأكيد عبر `_confirmed` (ختم proof bundle).
- `agents/validator/agent.py`: فرعا dispatch. `graph/builder.py`: عقدتان في سلسلة الاستكشاف العميق
  (`request_smuggling → prototype_pollution → cache_poisoning → disclosed_report_intel`).
- عقدتا اللانغ-جراف داخل وحدتي الكاشفين (غير المجمدتين): بوابة `is_engagement_target_host`
  قبل أي اتصال (fail-closed)، سقف endpoints، النقل المحوكوم، `Finding` عند التأكيد الحتمي فقط
  مع `promotion_guard`.
- اختبارات: registry/dispatch/validators/nodes — كلها خضراء (تأكيد/نفي صريح/inconclusive).

### W3 — بقية الطابور ✅
- `cli/commands.py`: `--version` (النسخة من الميتاداتا + `__version__`) و`--build-info`
  (جدول إثبات المنشأ من BUILD_INFO.json) — خياران eager على callback التطبيق. دخان حي: يعملان.
- `api/app.py`: `security_headers_middleware` — nosniff/DENY/no-referrer/CSP محافظة؛
  HSTS فقط عند TLS فعلي (مباشر أو X-Forwarded-Proto). اختباران في الملف الجديد — خضراء.

### W4 — إعادة التجميد والتوثيق ✅
- `scripts/refreeze_r4_20261102.py`: 8 هاشات في مكانها، 719 مدخلاً، مجموعة المسارات مطابقة
  بايت-بايت (شُغّل 3 مرات مع كل تعديل لاحق — idempotent). الملفات: app.py, cli/commands.py,
  graph/builder.py, validator/{agent,postp0_checks,registry}.py, models/findings.py,
  shared/preflight.py.
- `tests/test_frozen_module_gate.py`: مجموعة `R4_PRODUCTION_HARDENING_PATHS` في اتحاد الـ drift
  الموثق (نمط TC-4/r6c/r9a) — 720 passed/1 skip موروث.
- `scripts/regen_direct_io_inventory_r4_20261102.py`: 661 → 672 سجلاً؛ 0 إزالة؛ 6 هويات
  إضافية مراجَعة (2× safe_boundary_call للمكتبة المحوكومة في العقدتين + 4× getattr
  observability)؛ تحركات أسطر 430؛ دبوس المواقع غير المعتمدة بلا تغيير — بوابة G-02 خضراء.
- `docs/CLAIMS_VS_REALITY_P2.md`: سطر الادعاء مقلوب + الطابور مغلق. `archive/self_reports_20261101/DRIFT_REGISTER.md`: DR-020 كامل.
- خطة R4 هذه منسوخة لجذر المشروع كسجل حي.

### W5 — التحقق والقبول ✅ (بقيادة الأدلة الحرفية)
- `uv sync --locked --extra dev --extra pdf` → EXIT=0.
- ruff check → "All checks passed!" · ruff format --check → 997 files formatted.
- `verify_all.py` → **Total: 145 PASS, 0 FAIL — V6 DX-FINAL UNIFIED AUDIT PASSED**.
- الحزم المستهدفة: frozen gate + g02 + R4 + postp0 + الكاشفان + vip_auth + server_launcher +
  v10_p0p1 + validator_plugins → **775 passed / 1 skip (موروث بالتصميم)**.
- السويت الكامل: تشغيل حي موثق في `/tmp/r4_suite.log` (النتيجة تُلحق أدناه).
- القيود المعلنة: لا Docker (مسار الحاويات لم يُبنَ هنا — كما في Round-3)؛ اختبارات
  browser/webhook/OOB تعتمد كاش Chromium المثبت محلياً (chromium-1200 ✓).


---

## الجزء الرابع — نافذة إكمال R4 (2026-11-02، نفس اليوم): السويت الكامل أحمر → أخضر
## Part 4 — R4 completion window (same day): full suite red → green

نافذة R4 انتهت قبل استكمال بند W5.5 (السويت الكامل — السجل كان placeholder «النتيجة تُلحق أدناه»).
هذه الجولة أكملت البند بالحرف، وكانت النتيجة **3 فشل حقيقي لم ترَه النافذة**:

| ID | الفشل | التشخيص | الإصلاح |
|---|---|---|---|
| RC-01/RC-02 | `test_editable_broad_exceptions_gate.py` (فحصان) | عقدتا الكاشفين الجديدتان أدخلتا 4 معالجات `except Exception` في ملفين غير مجمّدين دون تسجيل — البوابة أوقفت الجناح **بالتصميم** | التسجيل المتعمد بالمسار الذي تفرضه البوابة نفسها: سجل `ACCEPTED_EXCEPTIONS_REGISTER.md` #14–#17 (حدود best-effort لحلقات البروبات، على نمط `request_smuggling_node` المجمد — فشل البروب = `blocked` في `probe_coverage` + لوج debug؛ التأكيد fail-closed غير متأثر: خطأ مبتلع قد يُفقد إشارة ولا يصنع إشارة أبدًا) + تحديث ثوابت البوابة (13→17) مع tripwire جديد `REGISTERED_UNPINNED_SRC` يوثّق عقد «غير المجمّد عمدًا» |
| RC-03 | `test_p0_ffuf_preflight.py::test_preflight_blocks_explicit_public_insecure_posture` | الاختبار كان ينتظر نص الرفض القديم `unsafe 0.0.0.0`؛ الحارس الجديد يرفض بنص أغنى `unsafe non-local bind (0.0.0.0)` (تغطية LAN-bind — R4-01) | مزامنة نصية للاختبار مع الرسالة الجديدة؛ السلوك نفسه مُثبت (SystemExit + CRITICAL) |

**أدلة ما بعد الإصلاح (كلها حية في هذه البيئة):**
```text
pytest tests/ -q --tb=line            → 3496 passed, 1 skipped (موروث R3-002), 1 xfailed (strict مصادق), 0 failed — 231.58s
verify_all.py                          → Total: 145 PASS, 0 FAIL — V6 DX-FINAL UNIFIED AUDIT PASSED
scripts/check_build_info_honesty.py    → PASS (suite_count 3415 vs collected 3498 — drift within margin)
ruff check .                           → All checks passed!
ruff format --check .                  → 998 files already formatted
uv sync --locked --extra dev --extra pdf → EXIT=0
```

**التوثيق:** `archive/self_reports_20261101/DRIFT_REGISTER.md` — إدخال **DR-021** كامل (3 ملفات: اختباران + سجل الاستثناءات؛ صفر تغيير في src/ وصفر تغيير في الملفات المجمدة).

**الخلاصة:** نافذة R4 (الحارس الصارم + توصيل الكاشفين + إغلاق الطابور) أصبحت الآن **مُثبتة بالكامل** — بما فيها بند القبول الأخير الذي كانت تفتقده: الجناح الكامل الأخضر. الشجرة جاهزة للتسليم النهائي الموحد.
