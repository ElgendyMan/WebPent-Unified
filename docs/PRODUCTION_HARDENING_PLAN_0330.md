# PRODUCTION_HARDENING_PLAN_0330 — خطة عمل شاملة لتجهيز WebPent للإنتاج

> **النافذة:** 0.33.0 — إعلان التاريخ: 2026-11-01
> **الأساس:** الحالة 0.32.0 (commit 2bf0e01، manifest 659، ruff 6209، suite 6740)
> **المنهجية:** مراجعة نقدية شاملة بالأدلة — لا بند في هذه الخطة بلا ملف وسطر ومسار تلوّث (taint path) أو سيناريو فشل مُتحقَّق منه بالقراءة أو بالتنفيذ الفعلي.

---

## 0) ملخص تنفيذي

فُحص المشروع بالكامل (961 ملف مصدري / 249,699 سطرًا + 563 ملف اختبار) عبر أربع قنوات متوازية:

| قناة الفحص | النتيجة الرقمية |
|---|---|
| compileall (صياغة) | 0 أخطاء |
| ruff (القواعد الافتراضية + S/PTH/DTZ/TRY/PERF) | 6,209 (تحت السقف 6,250) — من بينها **3× F821 حقيقية، 2× F402، 1× E722** |
| bandit -r src/webpent | 198 ملاحظة: 0 حرجة، 32 متوسطة (B608×12, B108×13, B104×3, B310×1, B314×1) — **كل B608 تم فرزها يدويًا: إيجابيات كاذبة** |
| الاختبارات الكاملة (5 دفعات، 6740 مجمَّع) | **6734 passed / 0 failed / 3 skipped / 3 xfailed** — مطابقة تمامًا لسجل 0.32.0 |
| مراجعة منطقية عميقة (ab_lab/campaign/autonomous/brain/cli) | 15+ ملاحظة، أثقلها **HIGH واحد مُتحقَّق منه بالتنفيذ** |
| مراجعة أمنية red-team (api/service/auth/tools/validation) | 10 ملاحظات: **0 حرجة/عالية**، 3 متوسطة تلامس حدود قابلة للاستغلال |
| مراجعة صلابة تشغيلية (core/adapters/workers/persistence) | 14 ملاحظة، أثقلها **2× HIGH** (مسار LLM pool ميت + تسريب httpx) |

**الخلاصة الصريحة:** البنية الأمنية للإطار ناضجة (سلسلة SSRF، subprocess مُسمَح-به بالقائمة، auth بلا بيانات افتراضية، hard-stops للإعدادات) — **لا توجد ثغرة حرجة أو عالية خطورة من النوع القابل للاستغلال المباشر**. لكن الحالة **ليست جاهزة إنتاجًا 100%** بسبب: (أ) خطأين HIGH يعطّلان وظيفتين فعليتين (A/B لأي هدف ثانٍ في نفس الأسبوع، وبئر مزوّدي LLM بالكامل)، (ب) 3 حدود أمنية متوسطة تحتاج إغلاقًا وقائيًا، (ج) ~20 عيبًا منطقيًا/تشغيليًا متوسطًا من شأنها أن تعطّل صيدًا طويلًا أو تفسد حالته، (د) فجوات صحة صورة Docker والبيئة.

كل بند أدناه يحمل: الموقع الدقيق، السيناريو، الإصلاح، وبروتوكول التحقق.

---

## 1) سجل النتائج — أولاً P0 (حاجبة إنتاج مباشرة)

### F-01 [HIGH | مُتحقَّق بالتنفيذ] تصادم `run_id` في ab_lab: الهدف الثاني لنفس العميل في نفس الأسبوع يُسقط `open_week` نهائيًا
- **الموقع:** `src/webpent/memory/ab_lab.py:402`
- **الجذر:** `run_id = f"{week_key}-{arm}-{client_id[:24]}"` — لا يضمّ `target_url`.
- **السيناريو (مُثبت):** `open_week(client_id="acme", target1)` ثم `open_week(client_id="acme", target2)` في نفس أسبوع ISO ⇒ `sqlite3.IntegrityError: UNIQUE constraint failed: ab_runs.run_id`، ويُعمل rollback لصف الأسبوع، فكل إعادة محاولة تفشل بنفس الطريقة — الهدف الثاني **لا يمكن اختباره A/B إطلاقًا**. `cli/ops.py:815-819` يلتقط `ValueError` فقط ⇒ يظهر للمشغّل traceback خام.
- **الإصلاح:** ضمّ خلاصة الهدف في المعرّف: `f"{week_key}-{arm}-{client_id[:16]}-{sha256(target_url)[:8]}"` (مع اختبار ترحيل لبيانات قديمة إن وُجدت).
- **التحقق:** اختبار جديد `test_open_week_second_target_same_week` يفتح أسبوعين-هدفين لنفس العميل ويؤكد 4 صفوف `ab_runs` مستقلة؛ واختبار CLI أن الخطأ يُقدَّم كرسالة مشغّل لا traceback.

### F-02 [HIGH | مُتحقَّق بالتنفيذ] بئر مزوّدي LLM ميت وظيفيًا: `ProviderPool` يستدعي `OpenAICompatibleProvider` بوسائط غير موجودة
- **الموقع:** `src/webpent/llm_researcher/providers/pool.py:217` مقابل `openai_compatible.py:14-20`
- **الجذر:** `OpenAICompatibleProvider(api_key=key, base_url=base_url, model=model, policy_hash=...)` بينما التوقيع `(model, prompt_version_hash="", api_key_env=..., base_url_env=..., org_env=...)` ⇒ `TypeError: unexpected keyword argument 'api_key'` في **كل** استدعاء.
- **السيناريو:** الـbare `except Exception` (pool.py:237) يحوّلها لفشل slot؛ كل الslots تدور إلى circuit-open؛ النتيجة `RuntimeError("REAL_API_UNAVAILABLE")` **حتى مع مفاتيح صحيحة مهيأة** — بلا أي إشارة أن السبب كسر عقد داخلي.
- **الإصلاح:** البناء الصحيح: `OpenAICompatibleProvider(model=model, api_key_env=slot.env_var_name, base_url_env=slot.base_url_env)` ثم ضبط `provider.prompt_version_hash = self.policy_hash`، أو توسيع `__init__` بقبول `api_key/base_url` صراحةً.
- **التحقق:** اختبار يبني pool بمزوّد مزيف (fake httpx transport) ويُثبت `generate()` ناجح واحد؛ واختبار أن فشل slot واحد لا يفتح الدائرة على الكل.

### F-03 [HIGH | robustness] تسريب `httpx.Client` لكل مزوّد لكل استدعاء — استنزاف sockets/FDs في الصيد الطويل
- **الموقع:** `src/webpent/llm_researcher/providers/openai_compatible.py:37`
- **السيناريو:** `self._client = httpx.Client(...)` بلا `close()` ولا `__exit__` ولا أي تنظيف؛ `ProviderPool.generate` يبني **مزوّدًا جديدًا لكل استدعاء LLM** ⇒ تسريب connection pool كامل لكل نداء حتى يمرّ GC.
- **الإصلاح:** دعم context-manager + إغلاق في `finally`، أو مشاركة client واحد طويل العمر لكل slot.
- **التحقق:** اختبار `ResourceWarning`/عدّاد FDs قبل/بعد 100 نداء لا يزيد.

### F-04 [MEDIUM | أمني — حدود استغلال] مسار التراجع عن عميل HTTP الآمن يُسقط حماية SSRF كاملة للهدف المرخّص
- **الموقع:** `src/webpent/production/modern_spine.py:585-591` (ونفس النمط 673-677)
- **السيناريو:** `make_safe_httpx_client` (نقل DNS-pinning + حظر الشبكة الخاصة) يتراجع عند **أي** استثناء غير-SSRF (ImportError/TypeError/...) إلى `httpx.Client` خام بلا تثبيت DNS ولا blocklist — يفقد الحماية للهدف الوحيد الذي كان ينبغي تثبيته. `follow_redirects=False` يحدّ ولا يلغي.
- **الإصلاح:** حذف الfallback نهائيًا، أو قصره على origins loopback حرفيًا مع إبقاء `SSRFPinningTransport` في المسار.
- **التحقق:** اختبار يحقن `ImportError` في مسار المصنع ويؤكد رفض الاستمرار بعميل خام (fail-closed).

### F-05 [MEDIUM | أمني] نقطتا `/api/v1/workers/status` و`/workers/health` بلا اعتماد مصادقة
- **الموقع:** `src/webpent/api/workers_status.py:332-333 و 396-397`
- **السيناريو:** مع `auth_enabled=True` يستطيع متخفٍّ حصر أسماء workers Celery وعدد الاشتباكات النشطة وأزمنة التشغيل (استطلاع بنية تحتية وتوقيت هجوم على فترة خمول الأسطول).
- **الإصلاح:** `user: User = Depends(require_viewer())` على المسارين.
- **التحقق:** اختبار API: 401 بدون توكن، 200 بمشاهِد مرخّص.

### F-06 [MEDIUM | أمني] باب قبول الفحص لا يمنع الأهداف الخاصة/link-local من جهة الخادم
- **الموقع:** `src/webpent/api/app.py:727-733` + `shared/engagement_scope.py:359-378` + `shared/http.py:559-602`
- **السيناريو (taint path):** مستخدم admin/service-role ⇒ `POST /api/v1/scans {"url":"http://169.254.169.254/..."}` ⇒ worker يستدعي `set_engagement_target_hosts` ⇒ host الهدف يصبح **المفتاح الوحيد** الذي يفتح blocklist الـSSRF ⇒ الوكيل يزحف metadata السحابة/الشبكة الداخلية. العقد الصحيح موجود أصلًا في `shared/target_spec.py:77,140` (`allow_private_target=False` افتراضيًا يتطلب `authorization.user_confirmed`) — لكن مسار API/worker لا يفرضه أبدًا.
- **الإصلاح:** عند الإرسال: اشتراط flag تأكيد صريح من المشغّل للأهداف غير-العامة، ورفض `169.254.0.0/16` metadata **غير مشروط**.
- **التحقق:** اختبار API: قبول الرفض 422 لهدف خاص بلا تأكيد؛ واختبار worker أن metadata IP لا يدخل قائمة engagement أبدًا.

### F-07 [P0-بيئة] صحة الصورة: لا `.dockerignore` ⇒ `COPY . .` يخبز `webpent.db` و36MB docs وreports وtests داخل صورة الإنتاج
- **الموقع:** جذر المستودع (لا `.dockerignore`)، `Dockerfile:58`
- **السيناريو:** قاعدة بيانات engagement فعلية (`webpent.db` في الجذر) + تقارير وأدلة وأدلة اختبار تُدمج في الطبقات — تضخيم هائل للصورة واحتمال تسريب بيانات اشتباك داخل طبقات الصورة القابلة للاستخراج.
- **الإصلاح:** `.dockerignore` يمنع: `webpent.db*`, `reports/`, `docs/`, `tests/`, `evidence/`, `__pycache__/`, `.env*` (إلا `.env.example` لو لزم), `*.sqlite3*`.
- **التحقق:** `docker build` ثم `docker history`/`dive` يؤكد غياب المسارات أعلاه.

---

## 2) سجل النتائج — ثانيًا P1 (عيب منطقي/تشغيلي يفسد صيدًا طويلًا)

| # | الشدة | الموقع | العيب (سيناريو مُتحقَّق) | الإصلاح |
|---|---|---|---|---|
| P1-01 | MEDIUM | `autonomous/hunt_orchestrator.py:731-754` | عدّاد "الجولات الهادئة المتتالية" لا يُصفَّر أبدًا في الجولات المُنتِجة (التصفير الوحيد على مسار `break` ميت) ⇒ جولة منتِجة واحدة بين هادئتين تُنهي الصيد `NO_NEW_EVIDENCE` مبكرًا | صفّر `self._quiet_rounds = 0` كلما `has_new_evidence_since` صحيح |
| P1-02 | MEDIUM | `memory/ab_lab.py:433→496` | فجوة check-then-act: `_next_due_run` تختار تحت الـRLock ثم تُفرجه، ووضع `running` يجري بعد إعادة الاكتساب ⇒ نداءا `tick()` متوازيان ينفذان **نفس** النافذة مرتين (سياسة "متسلسل لا متوازٍ" منتهكة) | حجز الشرط: `UPDATE ab_runs SET status='running' WHERE run_id=? AND status='planned'` وإلغاء لو `rowcount==0` |
| P1-03 | MEDIUM | `memory/ab_lab.py:393-394` | إعادة `open_week` بمعاملات **مختلفة** (mode/authorization_ref) تُقبل بصمت وتُهمل ⇒ النافذة تنفّذ تحت تفويض قديم | قارن المعاملات: حدّث الصف أو ارفض عند التعارض |
| P1-04 | MEDIUM | `memory/db.py:903-907, 993` | حماية OOB-clobber في `save_finding` داخل-العملية فقط (لا `BEGIN IMMEDIATE`) رغم أن `mark_oob_confirmed` نفسه يعترف بحدود الـthreading.Lock ⇒ worker A يطأ تأكيد worker B (انتكاس V10 P1-10 عبر العمليات) | افتح `save_finding` بـ`BEGIN IMMEDIATE`، وانقل الإشعار بعد-الالتزام خارج القفل (1095-1112 داخل القفل حاليًا) |
| P1-05 | MEDIUM | `brain/ev_scheduler.py:22-24` | أرضية منع-الجوع تتجاوز سقف الميزانية: `total_budget=3` على 10 فرضيات ⇒ منح مجموعها 10 | اقتصر الأرضية على أعلى `total_budget // FLOOR` فرضية |
| P1-06 | MEDIUM | `autonomous/hunt_memory.py:63-78` | `_load` يبني Entry بالتوقيع الممرّر **دون `verify_signature()`** رغم أن العقد ينص على رفض المزوَّر ⇒ ذاكرة مزوَّرة تُصدَّق عند القراءة | تحقق التوقيع بعد البناء وتجاوز الصف غير الصحيح |
| P1-07 | MEDIUM | `autonomous/hunt_memory.py:106-107` | عند سقف 512 المدخل: `return` **قبل** الupsert ⇒ تحديث نتيجة نمط قائم (vulnerable→clean) يُهمل بصمت — التصحيح مستحيل | افحص `key in self._entries` قبل الشرط السقفي أو أخلخ الأقدم |
| P1-08 | MEDIUM | `hunt_orchestrator.py:451-483` عبر `ab_lab.py:480-481` | تشغيل `running` منهار يحجب رأس الصف **للأبد**: `_next_due_run` تختار أقدم أسبوع غير-نهائي دائمًا وترجع `None` على `running` ⇒ لا أسبوع أحدث يُجدول أبدًا حتى reset يدوي | اعتبر `running` الأطول من timeout فاشلًا، أو اختر أقدم أسبوع **يمتلك فعلًا** due run |
| P1-09 | MEDIUM | `campaign/executor/pivot_engine.py:39,102,112` | `Any` مستخدم في 3 تشرحات بلا استيراد (F821) — كامن الآن بفضل `from __future__ import annotations`، ينفجر `NameError` مع أول `get_type_hints`/تقييم تشريح | `from typing import Any` |
| P1-10 | MEDIUM | `autonomous_hunter.py:247-252` | درجة `MEDIUM` في سلّم التصعيد **ميتة**: الشرط `conf>=1` يلتقطه فرع HIGH السابق ⇒ كل finding هامشي-مؤكد يُبلَّغ HIGH | اعكس الترتيب: `impact != NONE → HIGH` ثم `conf >= 1 → MEDIUM` |
| P1-11 | MEDIUM | `autonomous_hunter.py:298-301` | فرض النطاق بـsubstring: `any(s in url ...)` ⇒ `https://notexample.com/` و`https://evil.com/?u=example.com` و`https://example.com@evil.com/` تمر جميعها رغم عقد "لا يغادر النطاق المرخّص أبدًا" | `urlsplit().hostname` ومقارنة نطاق مسجّل: `== s` أو `endswith("." + s)` |
| P1-12 | MEDIUM | `core/infrastructure.py:155` | كتابة checkpoint غير-ذرّية: مقاطعة بين truncate وdump ⇒ `resume()` ينهار `JSONDecodeError` للأبد — والكلاس يملك `FileBackup` لا يستخدمه `_checkpoint` إطلاقًا | اكتب `path + ".tmp"` ثم `os.replace()`، وارجع لأحدث backup عند فساد التحميل |
| P1-13 | MEDIUM | نمط ×3: `live_hunter/world_model.py:101-127`، `deep_recon.py:219`، `research_loop.py:25,106` | الحدود تُفرض بـ`raise RuntimeError` في عمق المحرك ⇒ هدف بعِملاقات >2000 يقتل الجلسة كاملة بدل التدهور المؤدب | evict حلقي (مثل TrafficInterceptor) أو ارجع `stop_reason` (كما يفعل `research_state.py:68-79`) |
| P1-14 | MEDIUM | `adapters/controlled_target/adapter.py:610-612, 188-194` | check-then-act بلا قفل على ميزانية الطلبات لsingleton عالمي `CONTROLLED_TARGET_ADAPTER` ⇒ تجاوز `max_requests` بـN-1؛ وتسابق `start()` يسرّب `ThreadingHTTPServer` | غلّف الفحص/الزيادة و`start()` بـ`threading.Lock` |
| P1-15 | MEDIUM | `llm_researcher/interface.py:197,203,208` | `ResearchMemory.observations` تنمو للأبد رغم docstring "Bounded" (القراءة فقط تقتطع `[-30:]`/`[-50:]`) ⇒ نمو RAM ثابت في صيد طويل | `deque(maxlen=500)` أو اقتطاع عند الكتابة |
| P1-16 | MEDIUM | `browser_crawler.py:95` | عمل قابل للفشل داخل `finally:` **قبل** إغلاق المتصفح ⇒ استثناء `analyze_javascript` يتخطى `close_campaign` ويحجب الاستثناء الأصلي ويُسرّب Chromium | أغلق الحملة أولًا / لفّ التحليل بـtry مستقل |
| P1-17 | MEDIUM | `workers/pentest_worker.py:286` → `shared/persistent_finding_ledger.py:167` | كتابة sqlite عبر-العمليات بلا `journal_mode=WAL` ولا `busy_timeout` (قفل داخل-العملية فقط) ⇒ `database is locked` بعد 30s تحت دمج متزامن يضيّع شبكة الأمان | `PRAGMA journal_mode=WAL` + `PRAGMA busy_timeout=5000` في `_ensure_schema` |

---

## 3) سجل النتائج — ثالثًا P2 (نظافة/تصلّب — تُغلق في نفس النافذة إن اتسعت)

| # | الموقع | العيب | الإصلاح |
|---|---|---|---|
| P2-01 | `workers/pentest_worker.py:747-764` | رسالة الخطأ ترشد لـ`WEBPENT_TASK_CRYPTO_KEY` — **متغير لا يقرؤه أي سطر في الكود**؛ الحقيقي `CELERY_PAYLOAD_KEY` (settings.py:1886-1888) ⇒ مشغّل يتبع الرسالة لا يصلح شيئًا أبدًا | صحّح الاسم في الرسالتين |
| P2-02 | `service/api.py:42,71,121` | `_check_owner` يفحص `is_admin` بينما `User` يملك `is_global_admin` ⇒ دائمًا False: فشل-مغلق لكن `/service/health` 403 للأدمن الحقيقي (authz معطّل وظيفيًا) | `user.is_global_admin or user.role == "admin"` |
| P2-03 | `config/settings.py:2008-2009` | `trusted_proxy_ips` افتراضيًا يشمل نطاقات Docker bridge ⇒ أي حاوية على الجسر تزوّر `X-Forwarded-For` وتسمّم مفتاح rate-limit والتحقيق IP | الافتراضي loopback فقط؛ الـCIDRs إعداد مشغّل صريح |
| P2-04 | `api/auth.py:429-440` | تعداد أسماء المستخدمين عبر توقيت bcrypt (مجهول: فوري؛ موجود: ~100-300ms) | تحقق من dummy-hash ثابت للمستخدم المجهول |
| P2-05 | `api/scan_registry.py:393-421` | `claim_resume_capability`: SELECT-then-UPDATE بقفل داخل-العملية فقط ⇒ عاملان API كلاهما يُحدّث (أسوأ حالة: إرسال سيرة مزدوج — لا replay) | `UPDATE ... WHERE resume_consumed_at IS NULL AND (lease IS NULL OR lease < ?)` وافحص `rowcount` |
| P2-06 | `apex/executor.py:197` | `ET.fromstring` على خرج أدوات يحتوي محتوى متأثرًا بالهدف؛ التعليق `no entities` **غير دقيق** (ET يوسّع الكيانات الداخلية)؛ expat الحديث يحدّ billion-laughs والخرج مقيد 8MB ⇒ خطر منخفض لكن تعليق مضمول خطأ | `defusedxml.ElementTree` وصحّح التعليق |
| P2-07 | `adapters/controlled_target/adapter.py:757` | `urllib.request.urlopen` بلا allowlist مخططات (B310) — مسار target متعمد لكن file:/ وcustom schemes مفتوحة | اسمح http/https صراحةً |
| P2-08 | 13 موضعًا B108 (`service/*`, `cli/commands.py`, `egaie/*`, `vulns/file_upload.py`, `production/validators.py`, `apex/sandbox.py`) | مجلدات `/tmp` ثابتة-قابلة-للتنبؤ (`/tmp/webpent-service` إلخ) — على مضيف مشترك استبدال/سباق symlink؛ و`service.sqlite` يُنشأ world-readable (بدل 0700/0600 المطبقة في `production/*`) | `tempfile.mkdtemp` أو جذر `~/.webpent/service` مع `0o700` |
| P2-09 | `recon/auth_handler.py:32` | `except:` عريان (E722) يبتلع كل شيء بما فيه KeyboardInterrupt | `except Exception` مع تضييق |
| P2-10 | `causal_reasoning_v2/causal_adapter_v2.py:160`، `production/advisory_registration.py:283` | F402: متغير حلقة يظلّل استيرادًا (`field`) — سليم حاليًا لكنه فخ تعديل | أعد تسمية متغير الحلقة |
| P2-11 | `agents/validator/agent.py:980` | B025: `ImportError` مكررة في tuple الاستثناءات (لا أثر وظيفي — لخبطة قراءة) | أزل التكرار |
| P2-12 | `recon/session_recovery.py:198`، `recon/identity_discovery.py:708` | إعادة محاولة بلا backoff (حتى 8 بمسار ضيق) ⇒ دفقة سريعة على هدف متعثر | `time.sleep(2**attempt)` |
| P2-13 | `browser_crawler.py` / `autonomous_crawler.py` | Ctrl-C يرمي الخريطة السطحية المبنية (لا SIGINT wiring في حلقات الصيد؛ `ShutdownHandler` موجود بلا ربط) | التقط `KeyboardInterrupt` في `crawl()` وارجع نتيجة جزئية `stop_reason="interrupted"` |
| P2-14 | `autonomous/campaign_ledger.py:69-74` | سقف 1MB للسطر no-op: "الاقتطاع" يعيد serialization **لنفس** البيانات + حقلين إضافيين (أكبر!) | استبدل القيم الضخمة بـplaceholder قبل الدمج |
| P2-15 | `brain/curiosity.py:9` | `_CONFIG_PATH` يشير إلى `src/config/…` غير الموجودة ⇒ ضبط المشغّل لـ`curiosity_params.yaml` يُهمل بصمت منذ الذاكرة | ثبّت المسار على جذر المستودع (اج walk-up لـpyproject.toml كما db.py) |
| P2-16 | `recon/traffic_interceptor.py:35` | أجسام JS خام حتى ~1GB بالذاكرة (2000 حدث × 500KB) | digest + معاينة مقيدة في الأحداث؛ مرّر الجسم كاملًا للتحليل عابرًا |
| P2-17 | `recon/auth_handler.py:21` | صفحة Playwright login بلا `try/finally: p.close()` ⇒ تراكم صفحات في استرداد الجلسات المتكرر | أغلق في finally |
| P2-18 | `reporter/poc_recorder.py:335` | `write_text` بلا `encoding="utf-8"` (الوحيد في النطاق) ⇒ cp1252 على Windows ينهار على metadata غير-ASCII من الهدف | أضف الترميز |
| P2-19 | `llm_researcher/key_pool.py:133` | `.llm_keys.json` فاسد ⇒ `KeyPool.load()` ينهار بلا معالجة (الـCLI يعمل traceback) | التقط JSONDecodeError/OSError → `{}` مع تحذير |
| P2-20 | `autonomous_hunter.py:191-202` | `detect_behavior_change` يقارن مفاتيح التوقيع **الجديد** فقط ⇒ مؤشر دفاع اختفى (WAF off) لا يُحسب أبدًا | كرّر على اتحاد المجموعتين |
| P2-21 | `hunt_state.py:90-99` | بصمة الأدلة بطول السجلات فقط ⇒ استبدال finding بنفس العدد يُقرأ "لا جديد" | ضمّ خلاصات المحتوى للبصمة |
| P2-22 | `brain/ev_scheduler.py:31` + `lessons.py:1006` | طفح global `FAMILY_BASE_RATES` عبر الحملات المتزامنة؛ و`-> UUID` تعيد `None` عند moderation drop | اجعل الحالة per-campaign؛ صحّح التشرح أو النوع |

---

## 4) اقتراحات أمنية من وجهة نظري (proactive — ما أرى أنه يجب إضافته ليكتمل المشروع)

هذه ليست ثغرات قائمة بل **تصلّب وقائي** يرفع سقف الأمان لدرجة "production-complete" من وجهة نظري:

### أ. سلسلة التوريد والبيئة (أعلى أولوية عملية — مستندة لما شاهدته اليوم)
1. **ملف constraints + ترتيب تثبيت موثّق**: اليوم أثبتنا هشاشة المصالحة — تثبيت `langgraph` أنزل `rich/uvicorn` عن النُسخ المثبّتة، وتعارضات pip check تتراكم. أضف `requirements.constraints.txt` (يجمّد كل pin من pyproject) ووثّق أمر التثبيت الوحيد الصحيح: `pip install -e . -c requirements.constraints.txt`. وتحقيق: `pip check` صفر تعارضات webpent في الcanary.
2. **بوابة تجميع الاختبارات**: 77 خطأ تجميع صامتة حصلت اليوم حين غابت الoptional deps. أضف خطوة canary: `pytest --collect-only tests -q` يجب أن ترجع **0 errors** — وأي خطأ تجميع فشل بوابة (يفصل "بيئة ناقصة" عن "كود مكسور" قبل تشغيل أي اختبار).
3. **عزل بقايا بيئة**: اختبار التركيب A-01 انفجر اليوم من وحدة `cuda` متبقية. وثّق في runbook مسار الفرز: "أي `a01_unaccounted_top_level` غير فارغ ⇒ قارن مع snapshot site-packages المرجعي، وامسح البقايا" — واختياريًا اجعل الاختبار يطبع أصل الوحدة المذنبة (`module.__file__`) في رسالة الفشل لتقصير الفرز.

### ب. حدود الأمان (طبقات فوق ما هو قائم)
4. **قائمة مخططات على كل عميل خروج**: F-07/P2-07 تلمس الجزء المرئي؛ القاعدة العامة: أي `urlopen`/`httpx` جديد يمرّ بمصنع واحد (`make_safe_httpx_client`) — أضف اختبار معمارية يمنع merge أي استيراد `httpx.Client(`/`urlopen(` خارج وحدة `shared/http.py` (مثل نمط direct-I/O inventory القائم — امتدده ليشمل "any raw HTTP client").
5. **Rate-limit مفعّل افتراضيًا على `/token`** حتى في lab (حاليًا off افتراضيًا) — يقطع تعداد المستخدمين (P2-04) والقوة الغاشمة من البداية لا بعد الإعداد.
6. **Security headers + CORS صارم افتراضيًا** على سطح FastAPI: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store` على كل `/api/v1/*` — التوكنات في الجسم لا يجب أن تُخبّأ بروكسي.
7. **فصل صلاحيات القراءة/الكتابة على الـAPI**: `require_viewer()` موجود — اجعل كل route إما viewer أو operator **مصرّحًا به صراحةً** في اختبار تعاقد واحد يجري مصفوفة (endpoint × role → expected 401/403/200)؛ أي endpoint جديد بلا صف في المصفوفة يفشل الاختبار. هذا يمنع انزلاق F-05 مستقبلًا بنيويًا لا رقعيًا.
8. **تشفير الأدلة عند السكون (اختياري ولكنه يكمل القصة)**: التقارير وevidence bundles تحتوي payloads وطلبات مصادقة حقيقية — طبقة `age`/Fernet اختيارية بمفتاح `WEBPENT_EVIDENCE_KEY` للمخرجات خارج الاشتباك المرخّص، مع القاعدة: بلا مفتاح ⇒ تنبيه preflight وليس فشلًا.

### ج. ضبط الجودة المستمر
9. **secrets scanning في CI** (gitleaks/trufflehog) على كل PR + pre-commit محلي — المشروع يمنع الأسرار في الكود بـhard-stops؛ الفحص التلقائي يغلق ثقب "اللصق المؤقت قبل الرفع".
10. **pip-audit كبوابة مكررة** (الملفات موجودة: `docs/pip_audit_release.json` إلخ) — اجعلها خطوة canary دورية بأرشيف JSON مؤرخ لكل نافذة، مع allowlist موثّق (نموذج chromadb PYSEC الحالي).
11. **Fuzzing موجّه لمحلل النطاق والpayload pipeline**: hypothesis/Atheris على `scope` parser و`validation/` — P1-11 (substring bypass) نوع الثغرات التي يلتقطها fuzzing قبل المراجعة: خاصية "أي URL يجب أن يكون داخل النطاق المرخّص أو استثناء".
12. **توسيع ruff ratchet بالقواعد المكتشفة**: أضف `F821,F402,E722,B025` إلى القواعد المفعّلة في pyproject (أصلًا 6209 < 6250 ⇒ استيعابها لا يكسر السقف بعد إصلاح الستة الموجودة)، فتُمنع عودة نفس العائلة.

---

## 5) ما هو ممتاز ويجب عدم كسره (حفظ من الانحدار)

1. **سلسلة SSRF في `shared/http.py`** — نقل DNS موثّع، فشل-مغلق على فشل التثبيت، blocklist شاملة (IPv4-mapped IPv6/NAT64/CGNAT)، رفض `verify=False` صراحةً. الاستثناءان الوحيدان موثّقان في F-04/P2-07.
2. **`tools/utils/subprocess.py`** — argv قوائم فقط (TypeError على str)، `shell=False`، allowlist تنفيذي، PDEATHSIG + قتل مجموعة العمليات. لا `shell=True`/`os.system`/`eval`/`pickle.loads` في src إطلاقًا (bandit + مراجعة يدوية).
3. **سلسلة المصادقة** — لا بيانات افتراضية، JWT بـiss/aud/iat/nbf/jti + إبطال token-version في DB، throttling على اسم-مُجزَّأ، resume capability بـHMAC أحادي الاستخدام TTL ≤900s و`compare_digest`.
4. **Hard-stops الإعدادات + preflight** — منع أسرار ضعيفة مع auth_enabled، منع bind عام بلا override صريح، فرض `rediss://` وCORS صريح في staging/production.
5. **نظافة ملفات وبيانات** — `TargetWorkspace` يقيّد كل مكون مسار بdigest، `0o600/0o700` في production/*، SQL مُعامل بالكامل (كل B608 إيجابيات كاذبة بعد فرز يدوي)، Fernet للبيانات المصرفية للمشغّل، وأدوات redact قبل أي evidence persistence.
6. **قانون الأدلة الرتيب في db.py** — إعادة فحص REFUTED على كل مسار كتابة، OOB replay-idempotent، `BEGIN IMMEDIATE` في الكُتّاب الحساسين-للعمليات المتعددة (يُستكمل على `save_finding` — P1-04).
7. **`evaluate_ab_pair`** — حساب `Fraction` دقيق عند الحدود (0.10 بالضبط ⇒ proven لا 0.0999…) وحراسة القسمة على صفر — نموذج يُحتذى في باقي القرارات الرقمية.

---

## 6) بروتوكول التحقق الموحّد (كل بند يخرج لا يمرّ بدون)

لكن بند في P0/P1: **اختبار جديد فاشل قبل الإصلاح، ناجح بعده** (يُوثَّق اسمه في رسالة الcommit) + إعادة الأبواب التالية:

1. `pytest --collect-only tests -q` ⇒ 0 errors (بوابة جديدة — اقتراح 3أ-2)
2. المنظومة الكاملة على 5 دفعات ⇒ مطابقة 6740، 0 failed (الرقم يعدّل بالاختبارات المضافة وتُحدَّث خريطة الدفعات)
3. `check_ruff_ratchet.py` ⇒ ≤ 6250 بعد استيعاب القواعد الجديدة (اقتراح 3ج-12)
4. canary 7x ⇒ STABLE exit 0 (بعد إصلاح F-01/F-02 تصبح تدخينة الأدوات ab/llm جزءًا فعليًا من المسار)
5. refreeze manifest (ست يتغير ملفات P0/P1) + توثيق نافذة UNFREEZE في `docs/UNFREEZE_FILES_*`
6. CHANGELOG entry بالنافذة 0.33.0 وربط كل معرّف F-/P1-/P2- بـcommit.

---

## 7) ترتيب التنفيذ المقترح (4 دفعات داخل نافذة واحدة)

| الدفعة | المحتوى | مبرر الترتيب |
|---|---|---|
| **B1 — وظيفي حاجب** | F-01، F-02، F-03، P1-09 (Any) | إصلاح ما يعطّل وظائف معلنة (A/B ثنائي-الأهداف، بئر LLM) قبل أي شيء — واختباراتها تعزل نفسها |
| **B2 — حدود أمنية** | F-04، F-05، F-06، P2-02، P2-04، P2-05 | إغلاق الاستغلال-الممكن والauthz المعطل ثم المصفوفة الأمنية (اقتراح 3ب-7) تحسم عدم-الانزلاق |
| **B3 — صلابة الصيد الطويل** | P1-01…P1-08، P1-10…P1-17 | عيوب الذاكرة/التزامن/الحدود التي تظهر فقط في الصيد الطويل — أكبر كتلة، قابلة للتوازي داخليًا |
| **B4 — نظافة + صورة + اقتراحات** | F-07، P2-01…P2-22، اقتراحات 3أ/3ب/3ج | التصلّب الوقائي والبوابات الجديدة تقفل النافذة |

**معيار الإقفال (DoD) للنافذة 0.33.0:** كل بنود B1/B2 مغلقة ببروتوكول §6، وB3 مغلقة بنسبة 100%، وB4 بحد أدنى F-07 + الاقتراحات 3أ-1/3أ-2/3ج-12 (البقية يُسمح ترحيلها لنافذة 0.34.0 بقرار موثّق)، مع canary 7x STABLE وsuite أخضر كامل وCHANGELOG وdelivery zip جديد باسم `webpent_ULTIMATE_0.33.0_hardening_<date>.zip`.

---

## 8) ملحق — أدلة الفحص (قابلة لإعادة الإنتاج)

```bash
# الاختبارات (5 دفعات — نمط 0.32.0 نفسه)
PYTHONPATH=src python3 -m pytest tests/*.py  -q -p no:cacheprovider --tb=line   # دفعتان: أول 170 ثم البقية
PYTHONPATH=src python3 -m pytest tests/oracle tests/dojo tests/prism tests/jc          -q ...
PYTHONPATH=src python3 -m pytest tests/forge tests/apex tests/deep tests/campaign tests/egaie -q ...
PYTHONPATH=src python3 -m pytest tests/bridge tests/econ tests/lab tests/vip tests/ground_truth -q ...
PYTHONPATH=src python3 -m pytest tests/scenario_lab tests/team1_acceptance -q ...
# → 6740 collected = 6734 passed / 0 failed / 3 skipped / 3 xfailed

# الاستاتيكي
python3 -m compileall -q src/webpent            # 0 أخطاء
ruff check src/webpent --statistics              # 6209 (سقف 6250)
ruff check src/webpent --select F821,F402,E722,B025   # 6 مواضع (§3/§2)
bandit -r src/webpent -q -f json                 # 198: 0C/32M — B608×12 كلها إيجابيات كاذبة بعد الفرز اليدوي

# ملاحظة بيئة (مُوثّقة لأنها ستتكرر عند أي مشغّل):
# تثبيت الoptional deps (langgraph/langchain-core/bcrypt/celery/…) بعد تدوير بيئة
# ينسّق السلسلة؛ الأوامر الصحيحة ومطابقة الpins موثقة في §4-أ-1.
```

**حدود هذا الفحص (صراحةً):** المراجعة العميقة غطّت ~60% من الوحدات (الحرجة) ولم تغطِّ سطريًا: `dojo/`, `econ/`, `jc/`, `prism/`, `graph/`, `families/`, `forge/` (باستثناء indexer) — هذه تُغطى بالبوابات أعلاه ضمنيًا (الاختبارات) ويوصى بجولة red-team موالية لها في نافذة لاحقة إن اتسع الوقت.

---

## 9) سجل التنفيذ (execution record — 2026-11-01)

النافذة أُغلقت بالكامل وفق بروتوكول §6:

| البند | الحالة |
|---|---|
| B1 (F-01, F-02, F-03, P1-09) | ✅ مُنفذ باختبارات b1 (10) |
| B2 (F-04…F-06, P2-02/04/05) | ✅ مُنفذ باختبارات b2 (12) |
| B3 (P1-01…P1-17) | ✅ مُنفذ بالكامل باختبارات b3 (21) |
| B4 الحد الأدنى (F-07, 3أ-1, 3أ-2) | ✅ `.dockerignore` + `requirements.constraints.txt` + بوابة تجميع في canary |
| P2 سريعة (01/09/10/11/18) | ✅ مُنفذة |
| **إصلاح انحدار داخل-النافذة** | ✅ F-04 كشف أن `execute_real_request` لم يسجل هدف الاشتراك أبدًا (كان يعتمد على الraw fallback) — أُصلح بآلية الengagement-allowlist + `guard_redirects=False`؛ الدليل: 15 اختبار team1 فشلوا قبل الإصلاح ونجحوا بعده |
| التجميع | 6783، 0 أخطاء |
| المنظومة الكاملة | 6776 passed / 0 failed / 4 skipped / 3 xfailed (6 دفعات) |
| ruff ratchet | 6209 = 6209 (F821/F402/E722/B025 خرجت كليًا) |
| الmanifest | 659 مُجمّدًا (23 معلن التغيير، 8 مجموعة thaw جديدة) |
| جرد direct-I/O | 815 → 814 (deltas معلنة، صفر raw-transport جديد) |
| canary | 7x STABLE + ruff clean + collection clean (6783/0) |
| التسليم | `webpent_ULTIMATE_0.33.0_hardening_20261101.zip` (3767 ملفًا) |

الأدلة: `docs/FULL_SUITE_EVIDENCE_0330_HARDENING_CHUNKED.txt`،
`reports/canary/CANARY_7X_20261101_0.33.0.json|.md`،
`docs/UNFREEZE_FILES_0330_HARDENING.md`، `scripts/refreeze_manifest_0330_hardening.py`،
`scripts/regen_direct_io_inventory_0330_hardening.py`.
