# PROPOSALS_ULTIMATE_V4 — اقتراحات الجولة الرابعة (2026-11-01)

المرحلة: بعد اكتمال V3 (§1–§10، 10 commits، سلسلة مرساة سليمة).
المبدأ الثابت نفسه: اقتراح واحد = commit واحد، كل ميزة flag-gated افتراضيًا
مغلقة، بوابات النطاق + ledger إجبارية قبل أي شبكة، نقل الشبكة محقون (موديولات
لا تملك transport)، إعادة تثبيت مرساة (re-freeze) لكل تعديل على ملفات مجمدة،
وكل اختبار بـ stubs — صفر شبكة من العملية. الترتيب التنفيذي في §13.

---

## §1 — Security Header & CSP Auditor

**الفكرة**: تحليل رؤوس الاستجابة الأمنية (CSP, HSTS, X-Frame-Options,
Referrer-Policy, Permissions-Policy) وإخراج فجوات موثقة مع اقتراحات
تحايد لكل فجوة — كشف سلبي من الـ response نفسه.

- **الملفات**: `src/webpent/auditor/headers.py` (جديد)، اختبارات
  `tests/test_header_auditor.py`.
- **الواجهة**: `audit_headers(headers: Mapping) -> list[HeaderGap]` —
  نقية بلا شبكة إطلاقًا؛ `HeaderGap(header, gap_code, severity,
  bypass_hint)` مفردة مجمّدة fail-closed.
- **تحليل CSP**: parse حقيقي للتوجيهات (`default-src`, `script-src`,
  `unsafe-inline`, `unsafe-eval`, wildcards `*`, `data:` في script-src،
  نطاقات تابعة لطرف ثالث مسموح عرضًا) → درجة تقديرية لقابلية التحايد.
  كل استنتاج موثق برمز فجوة، لا ادعاء ثغرة إلا بالدليل التوجيهي نفسه.
- **الحدود**: الاستنتاج "احتمال تحايد" لا "قابل للاستغلال"؛ الموديول
  لا يرسل أي طلب — يأخذ الرؤوس جاهزة من استجابة محقونة.
- **Flags**: `enable_header_audit` (False).
- **الاختبارات** (~22): CSP بلا توجيهات، unsafe-inline، wildcard،
  هجين آمن، مفردة fail-closed، حتمية.

## §2 — OpenAPI/Swagger Discovery & Endpoint Harness

**الفكرة**: اكتشاف مواصفات API المكشوفة (`/openapi.json`,
`/swagger.json`, `/api-docs`, مسارات شائعة من wordlist صغير ثابت) ثم
تحويل المواصفة إلى قائمة نقاط نهاية جاهزة للاختبار (path + method +
params من الـ schema).

- **الملفات**: `src/webpent/api_discovery/{__init__.py, openapi.py}`.
- **الواجهة**: `discover_spec(endpoints, *, fetch, scope_checker,
  ledger) -> SpecResult` — المرشحون من قائمة ثابتة (≤ 12 مسارًا)؛ كل
  URL يمر scope + ledger **قبل** أي fetch؛ `parse_spec(body) ->
  list[EndpointPlan]` نقية (التحقق JSON/YAML بمكتبة موجودة أو fallback
  يدوي مفاتيح paths/methods)؛ كل EndpointPlan(method, path, params,
  auth_hint) قابل للتغذية لمحركات موجودة.
- **الحدود**: الاكتشاف فقط — لا إرسال طلبات فعلية للنقاط المكتشفة هنا؛
  التنفيذ لاحقًا عبر المحركات الموجودة وبواباتها الكاملة.
- **Flags**: `enable_api_discovery` (False).
- **الاختبارات** (~24): بوابات، مواصفة صالحة/تالفة/ضخمة، تحويل نقاط،
  رفض مسارات خارج النطاق قبل الـ fetch، حتمية.

## §3 — JWT Abuse Lab (detection-only)

**الفكرة**: تحليل توكنات JWT المسجلة بالفعل في findings/payloads: خوارزمية
`none`، `kid` injection (أنماط)، مفاتيح HMAC ضعيفة (فحص قاموس صغير)،
`exp` غائب/بعيد جدًا، audience صادر. **القراءة والتحليل فقط** — لا توقيع
توكنات مقبولة ولا إعادة إصدار.

- **الملفات**: `src/webpent/auth_analyzer/{__init__.py, jwt_lab.py}`.
- **الواجهة**: `analyze_token(token: str) -> list[JwtIssue]` نقية؛
  فك base64url الـ header/payload، فحوصات هيكلية ثابتة. `weak_secret`
  يفحص فقط قائمة أسرار وهمية/شائعة محلية (≤ 40) — إيجابي = مطابقة
  HMAC فعلية على التوكن المعطى.
- **الحدود الصادقة**: لا توليد توكنات موقعة، لا اتصال، الإيجابيات
  "أدلة ضعف توقيع" يتحقق منها المشغل يدويًا. القيم الحساسة تُقنَّع
  (أول 4 + آخر 4) في كل مخرجات — عقد الـ §7 من V3.
- **Flags**: `enable_jwt_lab` (False).
- **الاختبارات** (~26): كل فحص، قناع القيم، رفض توكن تالف، حتمية.

## §4 — OAuth/OIDC Flow Auditor (passive)

**الفكرة**: من عناوين إعادة توجيه المسجلة في الـ ledger (لا طلبات
جديدة): كشف `redirect_uri` فضفاض (wildcards، نطاقات مختلفة مقبولة عبر
فروق قياسية)، `state` غائب في التحويلات، توكن في fragment. تحليل
سجلي محض — صفر طلبات.

- **الملفات**: `src/webpent/auth_analyzer/oauth_audit.py`.
- **الواجهة**: `audit_ledger_rows(rows) -> list[OAuthIssue]` نقية على
  صفوف الـ ledger الحالية (method, url) — الفحص شكل URL ومعاملاته.
- **الحدود**: نتائج "أنماط تستحق فحصًا يدويًا"، لا ادعاء استغلال.
- **Flags**: `enable_oauth_audit` (False).
- **الاختبارات** (~18): كل نمط، غياب state، token في fragment،
  بلا نتائج = قائمة فارغة صادقة، حتمية.

## §5 — IDOR Candidate Detector (differential, capped)

**الفكرة**: مع اثنين من endpoints/معرفات مسجلين مسبقًا في findings،
إعادة طلبية تفاضلية محدودة (طلب واحد لكل معرف، سقف 2N طلبات، N ≤ 10)
لمقارنة حجم/هيكل الاستجابة — مرشِح IDOR يُراجع يدويًا، لا قرار.

- **الملفات**: `src/webpent/idor/{__init__.py, detector.py}`.
- **الواجهة**: `compare_objects(url_a, url_b, *, fetch, scope_checker,
  ledger) -> DiffResult` — بوابات كاملة لكل طلب؛ المقارنة
  (status, length, hash-of-structure) فقط، لا محتوى يُخزَّن كاملًا
  (مقتطف ≤ 200 حرف مع قناع).
- **الحدود**: نتيجة `similar` / `different` / `inconclusive` — لا
  "vulnerable" أبدًا؛ السقف صلب.
- **Flags**: `enable_idor_probe` (False).
- **الاختبارات** (~20): بوابات، سقف، حالات الفروق الثلاث، قناع
  المقتطف، حتمية.

## §6 — Request Smuggling Probe (CL.TE / TE.CL markers, safe)

**الفكرة**: الكشف التفاضلي الآمن: طلبان بمهلة قياس وتحديد زمني —
بدون إغراق، سقف 4 طلبات لكل هدف، والمُوازِن الملاحَظ من الاستجابة
(تأخير/حجب) يُقرأ كـ "بنية تستحق فحصًا يدويًا".

- **الملفات**: `src/webpent/probes/smuggling.py`.
- **الواجهة**: `probe_target(url, *, send_raw, scope_checker, ledger)
  -> SmuggleResult` — `send_raw` محقون؛ أنماط CL.TE/TE.CL القياسية
  بمحددات فريدة لا تُدخل محتوى سيئًا؛ سقف طلبات صلب 4.
- **الحدود**: الكشف فقط، لا استغلال بوابة/جلسة أحد؛ نتيجة
  `candidate` / `no_evidence` / `inconclusive`.
- **Flags**: `enable_smuggling_probe` (False).
- **الاختبارات** (~22): كل نمط، سقف، بوابات، حتمية.

## §7 — CRLF & Header Injection Fuzzer

**الفكرة**: حقن CRLF في معاملات المرشحين (من findings الحالية) عبر
محرك الملاحظة OAST الموجود (Proposal 3): marker فريد + مسار OAST،
ومراقبة وصول callback = دليل حقن. سقف محاولات صلب.

- **الملفات**: `src/webpent/probes/crlf.py`.
- **الواجهة**: توقيع موحّد مع بقية المحركات: مرشحون من قائمة، سقف
  `crlf_max_attempts` (10)، كل محاولة scope + ledger، OAST محقون.
- **Flags**: `enable_crlf_probe` (False), `crlf_max_attempts` (10).
- **الاختبارات** (~20).

## §8 — Prototype Pollution Fuzzer (JS)

**الفكرة**: حمولات `__proto__`/`constructor.prototype` القياسية في
معاملات JSON، والكشف عبر: (أ) مرجعية كائن ملوث في استجابة منعكسة،
(ب) callback OAST بعد حمولة client-side. سقف حمولات صلب، مقتطفات
مقنعة.

- **الملفات**: `src/webpent/probes/proto_pollution.py`.
- **الواجهة**: `build_payloads() -> tuple[str, ...]` ثابتة موثقة +
  `probe(url, payloads, *, send, scope_checker, ledger, oast) ->
  PollutionResult` — سقف من الـ settings.
- **Flags**: `enable_proto_pollution` (False),
  `proto_pollution_max_payloads` (12).
- **الاختبارات** (~20).

## §9 — Report Quality Scorer & Duplicate Predictor

**الفكرة**: قبل التسليم: تقييم جودة تقرير (اكتمال الخطوات، دليل
request/response، أثر محدد، CVSS) بدرجة 0–100 مع فجوات مسمّاة، وتوقع
احتمالية التكرار بمقارنة (فئة + endpoint path pattern + معامل) مع
سجل findings السابق محليًا.

- **الملفات**: `src/webpent/reporter/quality_scorer.py`.
- **الواجهة**: `score_report(finding) -> QualityScore(score, gaps,
  duplicate_risk)` نقية — نفس أسلوب §6 V3 (لا API خارجي أبدًا،
  missing يبقى `missing: <field>` ولا يُخترع).
- **الحدود**: التوقع إرشادي محلي من السجل الخاص بالمشغل فقط.
- **Flags**: `enable_report_scorer` (False).
- **الاختبارات** (~24): كل محور، فجوات، حتمية، missing-contract.

## §10 — Learned Target Vocabulary (wordmap من النتائج)

**الفكرة**: بناء قاموس كلمات مستهدف من الـ findings والـ ledger
السابقة (معاملات شائعة في هذا الهدف، أنماط مسارات) → يغذي wordlists
المحركات تلقائيًا (اختياريًا). تعلم محلي من بيانات المشغل فقط.

- **الملفات**: `src/webpent/learning/wordmap.py` (حزمة learning موجودة
  من V3-§1 — إضافة ملف جديد فقط).
- **الواجهة**: `build_wordmap(ledger_rows, findings) -> dict` نقية +
  `top_terms(wordmap, kind, n)` مرتبة حتميًا (tie-break أبجدي)؛ القاموس
  JSONL حفظ آمن atomic مثل §5 V3. أسماء معاملات/مسارات فقط — لا قيم
  حمولات تُعاد.
- **الحدود**: يُقرأ فقط عند تشغيل flag، ولا يعدّل سلوك محرك إلا
  بتشغيل flag مستقل لكل محرك مستهلك.
- **Flags**: `enable_wordmap` (False), `wordmap_path` ("").
- **الاختبارات** (~22): بناء، ترتيب حتمي، حفظ/تحميل، رفض تالف، flags.

## §11 — Campaign Orchestrator v2 (DAG of stages)

**الفكرة**: توسيع مجدول V3-§5: تعريف حملة كـ DAG مراحل (recon →
fuzz → verify → report) مع اعتماديات، وسقف ميزانية لكل مرحلة،
وإيقاف نظيف عند فشل مرحلة اعتمادية. بناء على SchedulerStateFile
وRunOutcome الموجودين، بلا تعديل سلوكهما.

- **الملفات**: `src/webpent/scheduler/dag.py`.
- **الواجهة**: `StagePlan(name, depends, engine, cap)` مجمّدة،
  `CampaignDag.from_dict` fail-closed (يمنع الدورات واعتماديات
  المجهول)، `run_dag(dag, runners, *, budget) -> DagReport` — ترتيب
  تنفيذ طوبولوجي حتمي (tie-break أبجدي)، فشل مرحلة = إيقاف الفروع
  التابعة فقط، سقف ميزانية تراكمي.
- **الحدود**: المحرك نفسه لا يرسل شيئًا — runners محقونة، البوابات
  تبقى في المحركات.
- **Flags**: `enable_campaign_dag` (False).
- **الاختبارات** (~26): دورة مرفوضة، اعتماد مجهول، ترتيب حتمي،
  إيقاف فرعي، ميزانية، fail-closed.

## §12 — Self-Critique Gate قبل التسليم

**الفكرة**: بوابة أخيرة قبل تلميح أي finding للمشغل: قائمة فحوصات
صادقة (هل الدليل request كامل؟ هل النتيجة غير قابلة للتفسير البديل؟
هل السقف/النطاق موثق؟ هل الصفوف المقنّعة لم تسرب قيمة كاملة؟) —
تقرير pass/gaps بلا إعادة كتابة finding.

- **الملفات**: `src/webpent/reporter/self_critique.py`.
- **الواجهة**: `critique(finding, context) -> CritiqueReport(ok, gaps)`
  نقية على model_dump — لا شبكة، لا تعديل، القيم المقنّعة فحصها
  regex كامل-قيمة (لا first4+last4 يخرج كاملًا).
- **Flags**: `enable_self_critique` (False).
- **الاختبارات** (~20): كل فحص، تسريب قيمة كاملة = gap قاطع، حتمية.

---

## §13 — ترتيب التنفيذ والأولوية

الترتيب: §1 headers → §2 api-discovery → §3 jwt-lab → §4 oauth-audit →
§5 idor → §6 smuggling → §7 crlf → §8 proto-pollution → §9 scorer →
§10 wordmap → §11 dag → §12 self-critique.

المنطق: أول أربع مراحل مكاسب سريعة بأرضيات نقية/سجلية منخفضة المخاطر؛
وسط الخطة فاحصات محدودة السقف بأبواب كاملة؛ الأخيرة طبقة جودة وأتمتة
تبني على كل ما قبلها. كل قسم نفس البروتوكول: كود → اختبارات →
مجموعة كاملة مطابقة للـ baseline → re-freeze item رقم 38+ → commit
واحد → بوابات خضراء بعد الـ commit.
