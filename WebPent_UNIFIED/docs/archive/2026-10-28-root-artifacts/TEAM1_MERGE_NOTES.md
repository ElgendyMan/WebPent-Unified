# ملاحظات الدمج — Team 1 (Detection Depth Sprint، 2026-10)

هذا الملف مرجع تقني دقيق لكل ما أُضيف أو أُصلح في هذا الفرع من العمل (Team 1)، لاستخدامه في دمج هذا الفرع مع فرع Team 2 على نفس الكودبيز. لكل ملف: الحالة قبل التعديل، الحل بالتفصيل (أسماء الدوال/الثوابت/أرقام الأسطر التقريبية)، طريقة التحقق الفعلية، وأي نقطة تستحق انتباهًا خاصًا أثناء الدمج (تعارض محتمل مع تعديل مواز، أو قرار معماري يستحق مراجعة).

المنهجية المتبعة طوال هذا السبرنت: كل بند في خطة العمل الأصلية (`WEBPENT_TEAM1_DETECTION_DEPTH.md`) تم **التحقق منه في الكود الفعلي الحالي أولاً** قبل التنفيذ، وليس تنفيذه حرفيًا — الخطة كانت مكتوبة على نسخة أقدم من الكودبيز، وبعض بنودها ثبت أنها إما تحققت جزئيًا من قبل فريق سابق، أو غير صحيحة من الأساس (انظر القسم 3 أدناه، وهي الحالة الأهم).

> **قبل الدمج:** لا يوجد git repo في هذه النسخة (`git status` غير متاح)، فجرد الملفات المعدَّلة هنا يعتمد على `find . -newer BASELINE_HASH.txt`. إن كان فرع Team 2 يستخدم Git، فأفضل مسار دمج هو تطبيق الاختلافات ملفًا بملف بالاستعانة بالتفاصيل أدناه بدل نسخ-استبدال كامل، تحسبًا لتعديلات متوازية من Team 2 على نفس الملفات.

---

## 1. ملفات جديدة بالكامل

### `src/webpent/shared/url_resolution.py`

دالة واحدة مُصدَّرة: `resolve_url_candidates(base_url: str, path: str) -> list[str]`.

**لماذا أُنشئت:** كان هناك نسختان متطابقتان حرفيًا (byte-for-byte) من دالة خاصة اسمها `_resolve_url()`، واحدة في `agents/api_testing/agent.py` وأخرى في `agents/validator/structural_checks.py`. كلتاهما كانتا تفترض أن "أول segment في مسار الـ base URL هو جذر التطبيق دائمًا" — افتراض صحيح لـ DVWA (كل شيء تحت `/dvwa/`) لكنه خاطئ لأي API حقيقي بلا بادئة تطبيق (`https://api.example.com/v3/login` ليس "متجذرًا" في `/v3/`؛ هذا مجرد أول segment في مسار مسطّح).

**المنطق (مختصر، التفاصيل الكاملة في docstring الملف نفسه):**
```python
def resolve_url_candidates(base_url: str, path: str) -> list[str]:
    if path.startswith(("http://", "https://")):
        return [path]                              # مطلق بالفعل — بلا تغيير
    if not path.startswith("/"):
        return [urljoin(base_url, path)]            # نسبي — بلا غموض، urljoin عادي
    # path يبدأ بـ "/": حتى مرشّحين، جذر-الـhost أولًا
    host_root_url = ...          # RFC 3986 القياسي: المسار المطلق يستبدل كامل مسار الـ base
    app_root_preserved_url = ... # نمط DVWA: المسار المطلق يُلحق بعد أول segment في الـ base
    if app_root_preserved_url == host_root_url:
        return [host_root_url]   # لا بادئة تطبيق أصلًا — مرشح واحد لا داعي لتكراره
    return [host_root_url, app_root_preserved_url]
```

**نقطة مهمة للدمج:** هذا الملف مخصص فقط لحالة "مسار **مخمَّن** يُراد تجربته" (مثل `/api/v1/me` كمسار شائع افتراضيًا). وهو **غير مناسب** لمسار **مُكتشَف فعليًا** من صفحة حية (`<script src>`, `<form action>`) — تلك الحالة محسومة 100% بقواعد المتصفح القياسية (RFC 3986 من جذر الـ host مباشرة، بلا أي احتمال "تطبيق مجذَّر") وتُحل بـ `urljoin` عادي مباشرة، كما في `structural_checks.py` أدناه. لو كان لدى Team 2 أي كود جديد يحتاج حل مسار، يجب تصنيف الحالة أولًا (مخمَّن vs. مُكتشَف) قبل اختيار أي الدالتين يستخدم.

---

## 2. تعديلات حسب الملف

### 2.1 `src/webpent/agents/business_logic_fuzzer/agent.py` — مولّد replay مُصرَّح لـ race_condition

**المشكلة (مؤكدة بـ `grep -rn "race_replay" src/`):** الـ validator `validate_race_condition` (في `agents/validator/active_checks.py`) يرفض تأكيد أي finding من مجرد عدد نجاحات في burst متزامن؛ يتطلب صراحة `evidence["race_replay"]` بمفاتيح `baseline`/`candidate`/`negative_control`، وكان docstring الـ validator نفسه يذكر أن هذه يجب أن تُملأ بواسطة "a separate authorized replay producer". لم يكن هذا المنتِج موجودًا في أي مكان بالكودبيز — أي finding من نوع race_condition كان عالقًا بنيويًا عند `Needs Human Review` مهما كان الـ race حقيقيًا بالفعل.

**الحل — ثوابت جديدة (أعلى الملف، بعد `_MAX_FLOW_STEPS`):**
```python
_MAX_RACE_REPLAYS = 5                       # حد أقصى للـ endpoints التي تُجرى لها replay إضافية في كل engagement
_RACE_NEGATIVE_CONTROL_METHOD = "TRACE"     # فعل HTTP لا يُفترض أن يُعالَج كـ state-changing أبدًا
```

**الحل — دوال جديدة:**
- `_detailed_request(url, method, form_data, cookies=None, *, observation_role="candidate")` — طلب واحد محكوم بـ rate governor وSSRF guard، يُرجع observation dict كامل (`target_backed`, `observation_role`, `target_fingerprint`, `request_digest`, `response_digest`, `body_sha256`, …) بالشكل الذي يتطلبه **كلا** من `validate_race_condition`/`_normalise_race_observation` **و** `shared/verifier.py::_target_observation_ok` للترقية الصارمة. لا يرفع استثناء أبدًا؛ عند أي فشل نقل يُرجع observation بـ `target_backed: False` و`status_code: 0`.
- `_send_sequential_burst(url, method, form_data, cookies=None, count=_BURST_SIZE, *, observation_role="baseline")` — نفس عدد الطلبات لكن **واحدًا تلو الآخر**، لا بالتزامن. هذا هو "الذراع الأساسي" (baseline) للمقارنة: عملية state-changing تُستهلك مرة واحدة (كوبون، صوت انتخاب، سحب رصيد) يُفترض أن تنجح مرة واحدة فقط تحت حركة عادية غير متزامنة.
- `_send_concurrent_burst(...)` — كانت موجودة من قبل بوظيفة الـ burst المتزامن الأصلي؛ تم تعديلها لتُرجع نفس شكل الـ observation الكامل أعلاه بدل رمز حالة مجرد، بحيث يمكن إعادة استخدام نتيجتها مباشرة كـ `candidate` observation (أو، بتبديل الـ method إلى `TRACE` و`observation_role="negative_control"`، كـ negative control) دون burst إضافي.

**الاستخدام (داخل حلقة race-condition الموجودة، بعد رصد `success_count > 1` في الـ burst المتزامن الأصلي):** إن لم يتجاوز `race_replays_used` الحد `_MAX_RACE_REPLAYS`، يُشغَّل `_send_sequential_burst` (baseline) و`_send_concurrent_burst` بـ method=TRACE (negative control)، ثم تُبنى:
```python
evidence["race_replay"] = {
    "baseline": first_baseline, "candidate": first_candidate,
    "negative_control": first_negative,
    "baseline_successes": ..., "candidate_successes": ..., "negative_control_successes": ...,
    "burst_size": ..., "independent_control": True,
}
```
التنفيذ محاط بـ `try/except` واسع: فشل مولّد الـ replay لا يُسقط الـ finding الأصلي (المبني على الـ burst المتزامن وحده) — يبقى كما كان قبل هذا التعديل، فقط بلا `race_replay` evidence، ويُسجَّل تحذير بالسبب.

**لماذا `TRACE` تحديدًا كـ negative control:** أي معالج REST/form طبيعي يرفض TRACE (405/501/400، أو لا يصل أصلًا إلى كود state-changing) بصرف النظر عن المصادقة أو محتوى النموذج، دون أي افتراض مسبق عمّا يجعل body "غير صالح" لهذا الـ endpoint تحديدًا. لو "نجح" TRACE أكثر من مرة أيضًا، فالمشتبه به هو آلية الـ burst/threading نفسها، لا قفل الهدف.

**التحقق الفعلي:** بُني سيناريو حي (سيرفر HTTP محلي فيه endpoint race حقيقي غير محمي بقفل + endpoint آخر محمي) — السيناريو غير المحمي وصل فعليًا إلى `Tool-Confirmed`، والمحمي أرجع صفر findings (لا false positive).

---

### 2.2 `src/webpent/agents/hypothesis_analyzer/agent.py` — فك الارتباط بـ DVWA + حقن NoSQL

#### أ) إضافة: منطق فرضيات لفئة `nosql_injection` (كانت "يتيمة" بالكامل)

**المشكلة (مؤكدة بالبحث عن `VulnClass.NOSQL_INJECTION` في كل `agents/` و`shared/`):** الفئة لها validator حي في `validator/postp0_checks.py` وعضو كامل في `VulnClass`، لكن لا يوجد أي مكان يُنتج **فرضية** (hypothesis) لها أصلًا لكي يختبرها الـ validator.

**لماذا هي مختلفة بنيويًا عن بقية `_PARAM_NAME_SIGNALS`:** السطح النمطي لحقن MongoDB/CouchDB ليس كلمة مفتاحية في **اسم** parameter (مثل `id`→SQLI، `file`→LFI في الجدول الموجود)، بل **صيغة operator داخل بنية الـ parameter نفسها** — مثل `?username[$ne]=admin` أو `?age[$gt]=0`. لذا لزم جدول ومطابق منفصلان (التوقيع البنيوي مختلف: operator-in-key، لا keyword-in-name).

**الكود الجديد (قرب نهاية الملف، قبل `_generic_form_field_hypotheses`):**
```python
_NOSQL_OPERATOR_FRAGMENTS: tuple[str, ...] = (
    "$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin", "$regex",
    "$where", "$exists", "$or", "$and", "$not", "$all", "$elemmatch",
)

def _nosql_operator_hypotheses(url: str) -> list[tuple[str, str, str]]:
    ...
```
يفحص أولًا مفاتيح `parse_qs(parsed.query, keep_blank_values=True)` — حيث تبقى الأقواس جزءًا من اسم المفتاح في `?username[$ne]=admin` فتصبح `username[$ne]` نفسها قابلة للمطابقة مباشرة — ثم يتراجع (fallback) إلى مسح substring على raw query string (بعد `unquote`) للحالات التي تُفكِّك فيها مكتبة HTTP أو بروكسي أقواس المفتاح بشكل مختلف. يُستدعى من داخل القائمة العامة للإشارات (نفس موضع `_generic_parameter_hypotheses` و`_generic_path_parameter_hypotheses`) — أي يعمل لكل endpoint تلقائيًا، بلا اعتماد على أسماء DVWA.

#### ب) فك الارتباط بـ DVWA في `_VULN_PATH_PATTERNS` و`_SEGMENT_SAFE_PATTERNS`

**ملاحظة سياقية مهمة:** التعليق الموجود فعليًا في الكود فوق هذا الجدول (`# TEAM-1 Phase 4 — GENERIC, target-agnostic hypothesis producers`) يوثّق أن جولة سابقة (قبل هذا السبرنت) كانت قد بَنَت بالفعل "منتِجين عامّين" (generic structural producers) يعملون **أولًا** لكل endpoint ويجعلون جدول DVWA هذا "مُكمِّلاً فقط" (complementary only) — أي أن جزءًا كبيرًا من مشكلة "الارتباط بـ DVWA" كان قد حُلّ من قبل. الفجوة الحقيقية المتبقية التي تناولها هذا السبرنت كانت محصورة في substring matching على 3 كلمات بعينها.

**حُذف بالكامل:** إدخال `sqli_blind` من `_VULN_PATH_PATTERNS` (قرب "SQLi paths — validator dispatches to run_sqlmap"). كان مطابقة substring حرفية لمسار DVWA الحرفي `/vulnerabilities/sqli_blind/`، مُظلَّل بالكامل أصلًا بإدخال `sqli` العام الذي يوجّه لنفس معالجة `VulnClass.SQLI` — حذفه لا يُفقد أي تغطية على هدف حقيقي.

**نُقلت (لا حُذفت) إلى `_SEGMENT_SAFE_PATTERNS`:** `weak_id`, `authorisation` (بالتهجئة البريطانية كما تسميها DVWA حرفيًا)، `cryptography`. هذه الثلاثة **مرتبطة فعليًا بـ validators بنيوية حقيقية** (`_validate_weak_session`, `_validate_auth_bypass`, `_validate_cryptography`)، فحذفها كان سيُعطِّل المحفِّز الوحيد لهذه الـ validators عبر المسار. بدلًا من ذلك نُقلت من مطابقة substring (`في أي مكان بالمسار`) إلى مطابقة segment كاملة (`_SEGMENT_SAFE_PATTERNS` — segment المسار يجب أن يساوي الكلمة تمامًا):
```python
_SEGMENT_SAFE_PATTERNS: frozenset[str] = frozenset(
    {"fi", "api", "csp", "brute", "weak_id", "authorisation", "cryptography"}
)
```
**الثغرة التي أُغلقت فعليًا:** قبل هذا التعديل، مسار حقيقي على هدف غير-DVWA مثل `/api/v2/authorisation-service/` أو `/docs/cryptography-101/` كان يولّد فرضية AUTH_BYPASS/CRYPTOGRAPHY بثقة قصوى (`deterministic_match=True`، يتجاوز عتبة confidence-score العادية تمامًا) لمجرد احتواء المسار على تلك الأحرف كـ substring — لا علاقة له بالضرورة بالثغرة الفعلية.

**نقطة للدمج:** إن كان Team 2 قد عدَّل نفس الجدولين (`_VULN_PATH_PATTERNS` أو `_SEGMENT_SAFE_PATTERNS`) بإضافات أخرى، فالدمج يجب أن يكون دمج إضافات لا استبدال كامل — كلا التعديلين هنا جراحيان (حذف إدخال واحد، نقل ثلاثة) ولا يُفترض أن يتعارضا مع إضافة فئات جديدة من Team 2.

---

### 2.3 `src/webpent/agents/subdomain_takeover/agent.py` — من 6 إلى 21 مزوّد

**المصدر:** `fingerprints.json` من مستودع `EdOverflow/can-i-take-over-xyz` (استُنسخ بـ `git clone` محليًا وقُرئ مباشرة — وليس من الذاكرة التدريبية)، تمت تصفيته على إدخالات `"vulnerable": true` فقط مع CNAME موثّق وfingerprint نصّي مميّز.

**الإضافات الخمسة عشر** إلى `_PROVIDER_SIGNATURES` (قاموس `provider -> (cname_markers_tuple, body_markers_tuple)`):
`wordpress-com`, `bitbucket`, `ghost-io`, `help-scout`, `help-juice`, `readme-io`, `surge-sh`, `uberflip`, `jetbrains-youtrack`, `strikingly`, `hatenablog`, `anima`, `agile-crm`, `gemfury`, `surveysparrow`.

> **⚠️ الأهم في هذا الملف بأكمله:** خطة العمل الأصلية طلبت إضافة **Fastly, Zendesk, Unbounce, CloudFront**. المصدر الرسمي يؤكد أن هذه الأربعة مُدرَجة صراحة بـ `"vulnerable": false` (fingerprint Fastly مثلًا هو صفحة خطأ عادية، لا حالة "غير مُطالَب بها" قابلة للاستيلاء؛ Zendesk's "Help Center Closed" حالة تعطيل مقصودة لا ثغرة؛ CloudFront's `ViewerCertificateException` خطأ إعداد TLS). **لم تُضَف** — إضافتها كانت ستُنتج false positives حقيقية على أي هدف يستخدم هذه الخدمات بشكل طبيعي. هذا ليس "الخطة كانت قديمة" بل "الخطة كانت خاطئة من حيث المضمون التقني" — **مهم أن يطّلع عليه من يراجع/يدمج** حتى لا تُعاد إضافتها لاحقًا بافتراض أن حذفها كان سهوًا.
>
> استُبعدت أيضًا عمدًا (لا CNAME موثّق في المصدر الرسمي لها، فرفضتُ تخمين دومين): **Shopify, Tumblr, Cargo Collective**. واستُبعد Ngrok وإدخالات `HTTP_STATUS`-only الأخرى في المصدر لأن شكل بصمتها (رمز حالة HTTP مجرد، أو regex بلا substring ثابت كافٍ) لا يناسب نموذج هذا المكشاف القائم على مطابقة نص جسم الاستجابة.

**نقطة للدمج:** لو Team 2 أضاف مزوّدين آخرين لنفس القاموس، فالدمج بسيط (دمج مفاتيح القاموس) ما دام أي مزوّد جديد من Team 2 مُتحقَّق منه بنفس المعيار (مصدر `vulnerable: true` موثّق، لا تخمين) — يُستحسن مطابقة كل إضافة من Team 2 ضد `fingerprints.json` بنفس الطريقة قبل القبول، خصوصًا لو كانت تشمل أيًا من الأربعة المستبعدة أعلاه.

---

### 2.4 `src/webpent/agents/cloud_storage/agent.py` — من 3 إلى 7 مزوّدين

**الإضافات:** DigitalOcean Spaces، Cloudflare R2، Backblaze B2، Alibaba OSS — الأربعة موثّقون رسميًا من قِبل مزوّديهم كمتوافقين مع S3 API لعمليات الـ listing (`ListObjects`/`ListBucketResult`)، فأُعيد استخدام نفس فحص evidence المستخدم لـ AWS S3 (شكل XML `<ListBucketResult>`/`<Key>`) دون اختراع markers جديدة.

**`_BUCKET_HOST_RE`:** أُضيفت 4 بدائل لاحقة جديدة للـ regex: `digitaloceanspaces\.com`, `r2\.cloudflarestorage\.com`, `backblazeb2\.com`, `aliyuncs\.com`. تنبيه مُوثَّق بكومنت: استُخدم تحديدًا `r2.cloudflarestorage.com` (endpoint الـ API الفعلي الذي يُرجع listing) وليس `*.r2.dev` (alias عام للتقديم المباشر لكائن واحد، لا يمكنه أبدًا إرجاع listing حتى لو كان الـ bucket عامًا).

**`_provider_hint(host)`:** 4 فروع جديدة أُضيفت، **ويجب أن تُنفَّذ قبل** فحص `aws-s3` الموجود مسبقًا:
```python
if "digitaloceanspaces.com" in lower: return "digitalocean-spaces"
if "r2.cloudflarestorage.com" in lower: return "cloudflare-r2"
if "backblazeb2.com" in lower: return "backblaze-b2"
if "aliyuncs.com" in lower: return "alibaba-oss"
if "amazonaws.com" in lower or lower.startswith("s3.") or ".s3." in lower: return "aws-s3"  # موجود مسبقًا
```
**باگ حقيقي أُمسك به بالاختبار وأُصلح بإعادة الترتيب:** شرط `aws-s3` الأصلي (`lower.startswith("s3.")`) واسع بما يكفي ليُصنِّف `s3.us-west-002.backblazeb2.com` (hostname حقيقي لـ Backblaze B2 يبدأ بـ "s3." لكنه ليس AWS) كـ `aws-s3` خطأً. لو كان Team 2 قد عدّل هذه الدالة بترتيب مختلف، **يجب التأكد عند الدمج أن فحوصات المزوّدين الأربعة الجديدة تبقى قبل الفحص الواسع لـ aws-s3**، وإلا يرجع الباگ.

**`_S3_COMPATIBLE_PROVIDERS = frozenset({"digitalocean-spaces", "cloudflare-r2", "backblaze-b2", "alibaba-oss"})`** (ثابت جديد) — يُستخدم في `_listing_evidence()` لتجنّب تكرار نفس فحص XML أربع مرات؛ أي مزوّد في هذه المجموعة يُطابَق بنفس شرط `aws-s3` (`<listbucketresult` + `<key>` في الجسم)، ويُعلَّم الدليل باسم `f"{provider.replace('-', '_')}_listbucketresult_with_key"`.

**التحقق الفعلي الكامل (end-to-end):** سيرفر `ThreadingHTTPServer` حقيقي — الحالة الإيجابية أنتجت Finding واحد موسوم بشكل صحيح بالضبط، وعنصر تحكم سلبي (403، ليس listing) أنتج صفر findings.

---

### 2.5 `src/webpent/agents/api_testing/agent.py` — استخدام `resolve_url_candidates`

**حُذفت** دالة `_resolve_url()` الخاصة القديمة (DVWA-only) بالكامل من هذا الملف.

**دالة مساعدة جديدة** (أعلى الملف، بعد الـ imports):
```python
def _iter_path_url_candidates(base_url: str, paths: Iterable[str]) -> Iterator[tuple[str, str]]:
    for path in paths:
        for url in resolve_url_candidates(base_url, path):
            yield path, url
```
صُمِّمت كبديل drop-in لا يغيّر جسم أي حلقة موجودة — فقط شكل الحلقة الخارجية تغيّر من `for path in X: url = _resolve_url(base_url, path)` إلى `for path, url in _iter_path_url_candidates(base_url, X):`.

**4 مواضع استدعاء مُحدَّثة** بهذا النمط:
- `_probe_graphql` (حلقة على `_GRAPHQL_PATHS`)
- `_probe_jwt_alg_none` (حلقة على مسارات محتملة مثل `/rest/user/whoami`)
- `_probe_jwt_key_confusion` (حلقة متداخلة: لكل `pem_variant` → لكل مرشّح URL)
- `_probe_mass_assignment` (حلقة على `["/api/v1/user", "/api/v1/users/me", "/api/user", "/api/profile"]`)

لأن كل مسار مخمَّن قد يُرجع الآن مرشَّحًا واحدًا أو اثنين، فجسم كل حلقة قد يُنفَّذ الآن مرة أو مرتين لكل path بدل مرة واحدة دائمًا — سلوك مقصود (هذا هو جوهر الإصلاح: تجربة كلا الاحتمالين وترك استجابة HTTP الفعلية تقرر)، وليس تكرارًا غير مقصود لنفس الطلب.

**التحقق الفعلي:** سيرفر HTTP محلي فيه endpoint حقيقي على جذر الـ host (بلا app-prefix)، مع `base_url` يحمل app-prefix وهميًا (`/fakeapp/dashboard`) — `_probe_jwt_alg_none()` وجد الـ endpoint رغم ذلك (مستحيل بالكود القديم). وبالتوازي، تأكّد أن السيناريو الأصلي (DVWA الحقيقي، حيث الـ endpoint فعلًا تحت app prefix) ما زال يعمل 100% بلا أي regression.

---

### 2.6 `src/webpent/agents/validator/structural_checks.py` — استخدام `urljoin` مباشر

**حُذفت** نفس نسخة `_resolve_url()` الخاصة من هذا الملف أيضًا، واستُبدل كلا موضعي استخدامها بـ `urljoin` القياسي مباشرة:
- في `validate_javascript`: `script_url = urljoin(base_url, src)` (بدل `_resolve_url(base_url, src)`).
- في موضع تحليل نموذج HTML (استخراج `form action`): `form_action = urljoin(finding.url, form_match.group(1))`.

**السبب أن هذا الملف يختلف جوهريًا عن `api_testing/agent.py`:** المسارات هنا **لم تُخمَّن** — هي مستخرَجة فعليًا من `<script src="...">` أو `<form action="...">` موجودين بالفعل على صفحة حقيقية حيّة. هذه حالة محسومة 100% بقواعد المتصفح القياسية (RFC 3986 من جذر الـ host، بلا أي "ربما مُجذَّر تحت تطبيق") — فاستخدام `urljoin` مباشرة هنا **تحسين صافٍ بلا أي مقايضة**، ولا حاجة لإرجاع مرشَّحين متعددين كما في الملف السابق.

> ⚠️ **ملاحظة صغيرة متبقية لمن يراجع الدمج:** سطر تعليق قديم (قبل هذا التعديل) في نفس الملف ما زال يقول حرفيًا *"P1-5: API issue — structural API probe (urljoin fix already in `_resolve_url`)"* فوق دالة `validate_api_issue`. هذا التعليق أصبح مُضلِّلًا تقنيًا الآن بما أن `_resolve_url` لم تعد موجودة في الملف أصلًا؛ لم يُعدَّل لأنه خارج نطاق هذا السبرنت تحديدًا (لا يُشير لمنطق مُعدَّل في هذا السبرنت) لكن يستحق تصحيحًا سريعًا (أو حذفًا) عند الدمج لتجنّب التباس مستقبلي.

**التحقق الفعلي:** سيرفر HTTP + كائن `Finding` مُنشأ يدويًا — `validate_javascript()` وجد بنجاح `<script src="/js/dangerous.js">` خطِرًا يعيش على جذر الـ host حتى والصفحة الحاوية له على مسار بنمط DVWA (`/dvwa/vulnerabilities/javascript/`). وتأكيد مستقل (بـ `urljoin()` وحدها، بلا Finding) أن نمط DVWA الحقيقي (script tags تُصرِّح بـ `/dvwa/` صراحة في نفسها) لم يتأثر.

---

### 2.7 `tests/test_v10_p1_rca_followup.py` — تحديث اختبارات `_resolve_url` القديمة

كانت `class TestApiTestingUrlJoinFix` تستورد `_resolve_url` مباشرة من `api_testing.agent` — وهذه الدالة محذوفة الآن عمدًا. الاختبارات **حُدِّثت لا حُذفت** لتختبر `resolve_url_candidates()` الجديدة بدلًا منها:
- `test_resolve_url_candidates_preserves_dvwa_prefix` (إعادة تسمية — الضمانة الأصلية: حفظ بادئة `/dvwa/` ما زالت مُغطّاة).
- `test_resolve_url_candidates_also_offers_host_root` (**اختبار جديد** — يتأكد أن مرشَّح جذر-الـhost يُرجَع أيضًا، وهو بالضبط السلوك الجديد الذي لم يكن موجودًا في `_resolve_url` القديمة).
- `test_resolve_url_candidates_absolute_url_unchanged` (إعادة تسمية، نفس الضمانة السابقة).

تشغيل هذا الملف مع 3 ملفات اختبار أخرى ذات صلة: **106 نجح** (كانت 103 ناجح + 2 فاشل قبل التحديث).

---

### 2.8 `knowledge_sources.yaml` — توسعة تغطية PayloadsAllTheThings من 4 إلى 29 مسار

المصدر الأول (`swisskyrepo/PayloadsAllTheThings`, commit مثبّت `434cc897f9b1e561f3804631e40643e6c82c3d14`, `doc_type: payload`) كان يحتوي على 4 إدخالات `paths` فقط (xss, sqli, ssrf, lfi/rfi) يغطون 4 فئات فقط من حوالي 30 قيمة `VulnClass` موجودة فعليًا في المشروع. تم توسيعه إلى **29 إدخال path** يغطي الآن 26 فئة فريدة (بعض الفئات، مثل `jwt_weakness`/`jwt_key_confusion` أو `auth_bypass`، تتقاسم أكثر من صفحة مصدر مرتبطة موضوعيًا — مثال: صفحتا "OAuth Misconfiguration" و"SAML Injection" يُشار كلتاهما إلى `auth_bypass`). **كل مسار أُضيف تم التحقق من وجوده الفعلي** (ملف `README.md` حاضر وغير فارغ) عند نفس الـ commit المثبَّت قبل إضافته — لا مسار واحد مُخمَّن.

**أهمية هذا التعديل تحديدًا:** هذا هو العامل الأعلى تأثيرًا على "ذكاء" نظام الـ payloads (`payload_generator/agent.py::_retrieve_payload_reference`) — فالدالة لا يمكنها إرجاع payloads مجتمعية حقيقية إلا لفئة ثغرة لها بالفعل مسار مُستوعَب (ingested) هنا؛ أي فئة أخرى كانت تتراجع صامتة إلى اعتماد LLM على الذاكرة التدريبية وحدها بلا أي أرضية RAG فعلية.

**نقطة للدمج:** لو Team 2 أضاف إدخالات `paths` أخرى لنفس المصدر، فالدمج دمج قائمة (لا استبدال) — فقط تأكد أن أي إضافة من Team 2 اجتازت نفس شرط "تحقق الوجود الفعلي عند الـ commit المثبَّت" قبل القبول، وأن تشغيل `scripts/ingest_payloads.py --dry-run` بعد الدمج لا يُبلغ عن مسار مفقود.

---

### 2.9 `src/webpent/agents/payload_generator/agent.py` — استدلال تقني بسيط من امتداد الملف

**ثابت جديد:**
```python
_STACK_URL_EXTENSION_HINTS: dict[str, str] = {
    ".php": "php", ".php3": "php", ".php4": "php", ".php5": "php", ".phtml": "php",
}
```
**دالة جديدة:** `_infer_stack_from_url(url: str) -> str | None` — مطابقة نصّية صِرفة على امتداد مسار الـ URL، بلا اعتماد على recon أو شبكة أو حالة إضافية. ترجع `None` حين لا تعطي الامتداد أي إشارة (يجب أن يُعامَل الاستدعاء ذلك كـ "لا تُرشِّح" لا "لا يوجد stack").

**لماذا "php" فقط حاليًا (وليس بنية عامة لاكتشاف أي stack):** `search_knowledge()` تطبّق فلتر الـ stack بشكل **إقصائي** (exclusive) — تمرير stack لا توجد له chunks مُستوعَبة لهذه الفئة يُرجع صفر نتائج، أسوأ من عدم تمرير stack أصلًا (حيث ترجع الـ chunks العامة). المسار الوحيد الذي يملك فعليًا محتوى مُوسَّم بـ stack في `knowledge_sources.yaml` حاليًا هو "php" (صفحة File Inclusion، تغطي lfi وrfi معًا) — لذا بقيت هذه دالة إشارة ضيّقة ومُتحقَّق منها، لا مُستكشِف stack عام.

**نقطة الاستخدام (في الدالة الرئيسية لتوليد الـ payload):**
```python
stack_hint = None
if str(finding.vuln_class) in {VulnClass.LFI.value, VulnClass.RFI.value}:
    stack_hint = _infer_stack_from_url(finding.url)
payload_reference = _retrieve_payload_reference(finding, stack=stack_hint)
```
مُقيَّد بفئتَي `LFI`/`RFI` فقط حاليًا — يسحب تقنيات LFI/RFI الخاصة بـ PHP wrapper (`php://filter`, `php://input`, `data://`) أولًا عندما يُستدلّ أن الهدف PHP، بلا أي تغيير في سلوك أي فئة أخرى (تبقى تبحث في المحتوى العام/غير المُوسَّم تمامًا كما كانت).

**نقطة للدمج (مهمة إن كان Team 2 وسَّع الـ knowledge pack بمحتوى مُوسَّم بـ stacks أخرى):** `_STACK_URL_EXTENSION_HINTS` والفلتر في نقطة الاستخدام (`{VulnClass.LFI.value, VulnClass.RFI.value}`) مرتبطان ببعضهما عمدًا — الكومنت فوق الثابت يذكر صراحة "extend the extension map and the gate together if more stack-tagged corpus entries are added later". لو أضاف Team 2 مثلًا محتوى مُوسَّمًا بـ `nodejs` أو `java` في `knowledge_sources.yaml`، فيجب توسيع كلا الطرفين معًا (الامتدادات + شرط الفئة في نقطة الاستدعاء)، وإلا سيُبنى stack hint لا يُستخدَم أبدًا، أو — الأخطر — سيُستخدَم stack لا يوجد له محتوى مُستوعَب فيُرجع صفر نتائج بدل fallback للعام.

---

### 2.10 `src/webpent/cli/git_source.py` — إصلاح حقيقي: استنساخ عند تثبيت على commit SHA

**المشكلة (مؤكدة تجريبيًا بـ SHA حقيقي مثبَّت من `knowledge_sources.yaml`):** `git clone --branch <ref>` يحل `ref` فقط مقابل مراجع الفرع/الوسم (branch/tag) المُعلنة من الـ remote — يفشل بخطأ "Remote branch `<ref>` not found in upstream origin" عند تمرير commit SHA خام. وهذا بالضبط ما يُمرِّره كل استدعاء في الكودبيز (جميع المصادر في `knowledge_sources.yaml` مثبَّتة بـ commit SHA لا بفرع).

**الحل:** `--branch` يُجرَّب أولًا كما كان (بلا تغيير، للحالة الشائعة/السريعة لفرع أو وسم حقيقي). عند الفشل فقط، ودون وجود `ref` أصلًا يُرفَع الخطأ القديم كما كان (لا يوجد سيناريو fallback لمسار بلا ref محدد). عند وجود `ref` وفشل `--branch`، يُنفَّذ تسلسل بديل محقَّق يدويًا مقابل GitHub فعليًا: `git init` (فارغ) → `git remote add origin <url>` → `git fetch --depth 1 origin <ref>` → `git checkout --quiet FETCH_HEAD`. هذا التسلسل يحل commit SHA أو فرعًا أو وسمًا بنفس الطريقة تمامًا، بخلاف `--branch` الذي يفهم الفروع/الأوسمة فقط.

كل فشل في أي خطوة من خطوات الـ fallback يُبلَّغ برسالة خطأ واحدة مركَّبة تحتوي **سبب فشل المحاولة الأولى (`--branch`) وسبب فشل خطوة الـ fallback معًا**، مقصوصة لآخر 300-500 حرف من كل، لتجنّب إخفاء أيّ من السببين عن المُشغِّل عند التشخيص.

**تأثير هذا الإصلاح:** مباشر على مسار `scripts/ingest_payloads.py` بأكمله — أي مصدر `git_repo` في `knowledge_sources.yaml` (وكلها مثبَّتة بـ commit SHA لا فرع، بما في ذلك التوسعة في القسم 2.8 أعلاه) كان سيفشل استنساخه بالكامل قبل هذا الإصلاح.

---

### 2.11 `src/webpent/agents/validator/postp0_checks.py` — لم يحتج تعديلًا مباشرًا لتوسعة subdomain_takeover

**ملاحظة توثيقية مهمة لا إصلاح فعلي:** هذا الملف يحتوي على `validate_subdomain_takeover()` التي تعيد التحقق من finding الاستيلاء على نطاق فرعي. استيراده هو:
```python
from webpent.agents.subdomain_takeover.agent import _PROVIDER_SIGNATURES, _resolve_cname
```
أي أنه **يستورد نفس القاموس المشترك مباشرة** من `subdomain_takeover/agent.py` بدل الاحتفاظ بنسخة مكررة خاصة به. نتيجة ذلك: توسعة `_PROVIDER_SIGNATURES` من 6 إلى 21 مزوّدًا (القسم 2.3 أعلاه) انعكست هنا **تلقائيًا بلا أي تعديل إضافي مطلوب في هذا الملف** — لا يوجد خطر ازدواج منطق أو حاجة لمزامنة يدوية بين الملفين.

> ⚠️ هذا الملف **مُسجَّل كمعدَّل** في جرد `find -newer BASELINE_HASH.txt` رغم عدم وجود أي تعليق `TEAM-1` داخله يوثّق سببًا محددًا، وتعديله (إن وُجد فعليًا خارج ما ذُكر أعلاه) غير موثَّق بدقة في سجل هذه الجلسة. **لا يوجد لديّ ما يبرر الجزم بمحتوى أي تعديل إضافي هنا** — يُستحسن أن تُشغِّل `diff` ضد نسخة Team 2 أو النسخة الأصلية إن كانت متاحة لديك، بدل الافتراض أن الملف بلا تغيير إضافي.

---

### 2.12 `src/webpent/shared/jwt_deep_testing.py` — **غير موثَّق بدقة، يحتاج مراجعتك**

هذا الملف **مُسجَّل كمعدَّل** في نفس الجرد (`find -newer BASELINE_HASH.txt`)، وكان ضمن الملفات التي اجتازت فحوصات `py_compile` و`ruff check` في الفحص النهائي. لكن لا يحتوي الملف على أي تعليق مؤرَّخ 2026-10 أو موسوم بـ `TEAM-1` يوثّق تعديلًا محددًا، ولم يتبقَّ في سجل هذه الجلسة تفصيل دقيق لما تغيَّر فيه بالضبط (كان ضمن دفعة أقدم من السبرنت ذاته، قبل نقطة انقطاع في السياق).

**لن أخمّن محتوى هذا التعديل.** إن كانت لديك نسخة أصلية (قبل بداية هذا السبرنت) للمقارنة، فذلك أدق طريق للتأكد من حجم ونوع أي تغيير هنا قبل اعتماده في الدمج.

---

## 3. الخلاصة الأهم لمن يراجع الدمج

**الخطة الأصلية لم تكن قديمة فقط في موضعين — كانت خاطئة تقنيًا:**
1. اقتراح إضافة Fastly/Zendesk/Unbounce/CloudFront لمكشاف الاستيلاء على النطاقات الفرعية، بينما المصدر الرسمي (`can-i-take-over-xyz`) يُصنِّفهم صراحة كـ"غير قابلين للاستيلاء" — تنفيذها حرفيًا كان سيُنتج false positives فعلية على أي هدف يستخدم هذه الخدمات الشائعة جدًا.
2. وصف مشكلة `_VULN_PATH_PATTERNS` كـ"الآلية الأساسية" لتوليد الفرضيات دون الانتباه إلى أن جولة سابقة (موثّقة في الكود نفسه بتعليق "TEAM-1 Phase 4") كانت قد بنت بالفعل منتِجين عامّين يعملون أولًا ويجعلون هذا الجدول مُكمِّلًا فقط.

كلا الموضعين تم التحقق منهما تجريبيًا قبل أي تنفيذ، لا افتراضهما من القراءة فقط.

---

## 4. جدول ملخص الملفات

| الملف | نوع التغيير | السطر التقريبي للتعديل الرئيسي |
|---|---|---|
| `src/webpent/shared/url_resolution.py` | **جديد بالكامل** | — |
| `src/webpent/agents/business_logic_fuzzer/agent.py` | إضافة (مولّد replay) | ~46-59 (ثوابت)، ~265-450 (دوال)، ~788-844 (تكامل) |
| `src/webpent/agents/hypothesis_analyzer/agent.py` | إضافة + تعديل جراحي | ~584-593 (حذف sqli_blind)، ~725-758 (SEGMENT_SAFE)، ~1026-1090 (nosql) |
| `src/webpent/agents/subdomain_takeover/agent.py` | إضافة (15 مزوّد) | ~25-103 |
| `src/webpent/agents/cloud_storage/agent.py` | إضافة (4 مزوّدين) + إصلاح ترتيب | ~22-138 |
| `src/webpent/agents/api_testing/agent.py` | تعديل بنيوي (resolve) | ~33، ~43-61، 4 مواضع استدعاء |
| `src/webpent/agents/validator/structural_checks.py` | تعديل بنيوي (urljoin) | ~112-129، ~474، ~1094 |
| `tests/test_v10_p1_rca_followup.py` | تحديث اختبارات | `TestApiTestingUrlJoinFix` |
| `knowledge_sources.yaml` | توسعة بيانات (4→29 path) | ~22-131 |
| `src/webpent/agents/payload_generator/agent.py` | إضافة (stack hint) | ~297-333، ~539-542 |
| `src/webpent/cli/git_source.py` | إصلاح باگ (Sprint الأصلي) + إصلاح باگ ثانٍ (Red Team، انظر §6) | ~72-151، ~117-132 |
| `src/webpent/agents/validator/postp0_checks.py` | **لا تعديل مباشر مطلوب** (يرث التوسعة عبر import) | ~645-648 |
| `src/webpent/shared/jwt_deep_testing.py` | **غير موثَّق — يحتاج مراجعتك** | — |
| `src/webpent/agents/validator/active_checks.py` | **جديد لمجموعة التعديل** (لم يكن ضمن الـ 13 ملف الأصليين؛ أُضيف في مرحلة Red Team، انظر §6) | ~31-38، ~543-588 |

---

## 5. حالة الفحص النهائي (مرجع سريع)

- **Syntax:** `py_compile` نظيف على كل الملفات أعلاه.
- **Lint:** صفر أخطاء ruff جديدة؛ 13 تحذيرًا موجودًا مسبقًا (أغلبها line-too-long) تم التأكد سطرًا سطرًا أنها خارج أي نطاق مُعدَّل في هذا السبرنت.
- **Test suite الكامل (3214 اختبار):** 3188 نجح، 25 فشل — جميعها مُصنَّفة فرديًا:
  - 11 فشلًا متوقعًا تمامًا (`test_frozen_module_gate` ×10 + `test_g02_direct_io_inventory` ×1): بوابات baseline/artifact تتأكد أن الملفات الأصلية لم تُعدَّل. بما أن التعديل هنا متعمَّد، يجب **تحديث `frozen_modules.sha256` و`docs/direct_io_inventory.json` يدويًا بعد مراجعة واعتماد الدمج** — رسائل الفشل نفسها تنص على أن هذا إجراء متعمَّد لا عطب.
  - 14 فشلًا بيئيًا بحتًا في بيئة العمل الخاصة بهذه الجلسة (DNS resolution غير متاح لـ `lab.local`/`example.com`، أو `ModuleNotFoundError` في subprocess منفصل لأن الحزمة غير مثبَّتة فيه بـ pip، أو اختلاف نسخة `typer`) — تم التأكد فرديًا (بما في ذلك تجربة إضافة DNS entry مؤقت ومراقبة تغيّر شكل الخطأ) أن ولا واحدًا منها يلمس أي دالة مُعدَّلة في هذا السبرنت.

> **ملحق لاحق (مرحلة Red Team، 2026-10):** بعد كتابة هذا القسم بيوم تقريبًا، أُجريت مراجعة ذاتية صارمة (red team) على كل الكود أعلاه، أسفرت عن 9 ملاحظات، 6 منها نُفِّذت فعليًا كتعديلات كود (بما فيها ملف **جديد** لمجموعة التعديل: `validator/active_checks.py`). التفاصيل الكاملة — المشكلة، الحل، التحقق التجريبي — في القسم 6 أدناه و`RED_TEAM_REPORT.md`. حالة الاختبارات بعد هذه المرحلة: **112 نجح، 2 فشل بيئيًا (`lab.local` DNS، غير مرتبط بأي تعديل Red Team — مُفصَّل في §6.7)**، على عينة الاختبارات المرتبطة مباشرة بالملفات الخمسة المعدَّلة في هذه المرحلة.

---

## 6. مرحلة Red Team (2026-10) — مراجعة ذاتية صارمة + إصلاحات

هذا القسم توثيق لمرحلة منفصلة تمامًا عن سبرنت "Detection Depth" أعلاه: مراجعة ذاتية صارمة (red team) طُلبت صراحة على كل الكود المذكور في الأقسام 1-5، بهدف استخراج كل انتقاد وكل مشكلة وكل تحسين ممكن، ثم تنفيذ كل ما يستحق التنفيذ فعليًا — لا توصيات بلا تنفيذ. التقرير الكامل بكل التفاصيل السردية (المشكلة، لماذا تهم، سيناريو الفشل الملموس) في `RED_TEAM_REPORT.md` بجذر المستودع؛ هذا القسم هو **الخلاصة الموجّهة للدمج**: أي سطر تغيّر، في أي ملف، ولماذا، وكيف تحقَّقتُ أنه صحيح.

**جدول الحالة الكامل (9 ملاحظات):**

| # | الملف | الخطورة | الحالة |
|---|---|---|---|
| 1 | `validator/active_checks.py` | عالية | **نُفِّذ** — انظر §6.1 |
| 2 | `hypothesis_analyzer/agent.py` | عالية | **نُفِّذ** — انظر §6.2 |
| 3 | `validator/active_checks.py` | متوسطة | **نُفِّذ** (نفس تعديل #1) — انظر §6.1 |
| 4 | `api_testing/agent.py` | متوسطة | **نُفِّذ جزئيًا** (حلقة واحدة من 4 احتاجت تعديلًا فعليًا؛ الثلاث الباقية كانت محميّة بالفعل) — انظر §6.3 |
| 5 | `hypothesis_analyzer/agent.py` | منخفضة | **نُفِّذ** — انظر §6.2 |
| 6 | `subdomain_takeover/agent.py` | منخفضة | **لم يُعدَّل — قرار واعٍ موثَّق**، انظر §6.6 |
| 7 | `business_logic_fuzzer/agent.py` | بسيطة (دفاعية) | **نُفِّذ** — انظر §6.4 |
| 8 | `cli/git_source.py` | بسيطة | **نُفِّذ** — انظر §6.5 |
| 9 | `hypothesis_analyzer/agent.py` | تافهة | **لم يُعدَّل — موثَّق فقط**، انظر §6.6 |

### 6.1 `src/webpent/agents/validator/active_checks.py` — إصلاح الـ negative control + إضافة margin (findings #1، #3)

**هذا الملف جديد بالكامل لمجموعة التعديل** — لم يكن من الـ 13 ملفًا الأصليين لسبرنت Detection Depth؛ أُضيف هنا لأن تفعيل `evidence["race_replay"]` في §2.1 (الذي كان معطّلاً تمامًا قبل هذا السبرنت) جعل ضعفًا كامنًا في هذا الـ validator — موجودًا من قبل أي تعديل من Team 1 — نافذ المفعول لأول مرة.

**المشكلة (دالة `validate_race_condition`، كانت قبل التعديل):**
```python
causal_signal = bool(metrics_valid and candidate_successes > baseline_successes)
negative_control_complete = bool(
    metrics_valid and independent_control and negative_successes <= baseline_successes
)
```
فرق نجاح واحد فقط (`candidate_successes - baseline_successes == 1`) كافٍ لتفعيل `causal_signal` — حساس جدًا لضوضاء الشبكة العادية. وشرط الـ negative control كان يقارن `negative_successes` (TRACE، يُرسَل بالتوازي) بـ `baseline_successes` (POST الحقيقي، يُرسَل تسلسليًا) — كميتان بلا علاقة منطقية مباشرة؛ في الحالة الشائعة حيث يُرفض TRACE كليًا من طبقة النقل (`negative_successes == 0`)، الشرط يتحقق تلقائيًا تقريبًا دائمًا، فلا يضيف حماية مستقلة حقيقية.

**الحل المطبَّق:**
```python
_MIN_CAUSAL_DIFFERENTIAL = 2       # ثابت على مستوى الملف، أعلى الملف
_MAX_NEGATIVE_CONTROL_SUCCESSES = 1  # ثابت على مستوى الملف، أعلى الملف
...
causal_signal = bool(
    metrics_valid
    and (candidate_successes - baseline_successes) >= _MIN_CAUSAL_DIFFERENTIAL
)
negative_control_complete = bool(
    metrics_valid
    and independent_control
    and negative_successes <= _MAX_NEGATIVE_CONTROL_SUCCESSES
)
```
الـ negative control الآن خاصية بـ `negative_successes` **وحدها** (هل آلية الـ burst نفسها تنتج نجاحات زائفة متعددة لفعل لم يُصمَّم الهدف لمعاملته كمُغيِّر-حالة؟) بدل مقارنتها بمعيار غير ذي صلة.

**ملاحظة بنيوية (اكتُشفت أثناء إصلاح تحذير ruff `N806`):** في أول تنفيذ، عُرِّف الثابتان كمتغيرَين محليين (`UPPER_CASE`) داخل الدالة — صحيح وظيفيًا، لكن ruff يرفضه بحق (`N806`: الأحرف الكبيرة محجوزة لثوابت على مستوى الملف لا المتغيرات المحلية). نُقلا لأعلى الملف كثوابت حقيقية؛ أُعيد التحقق التجريبي الكامل بعد النقل للتأكد أن إعادة الهيكلة لم تغيّر أي سلوك (التفاصيل أدناه) — لم تتغيّر أي نتيجة.

**التحقق التجريبي (وليس قراءة كود فقط):** بُنيت 5 سيناريوهات `Finding` كاملة (بما فيها `_target_fingerprint()` حقيقي محسوب من نفس دالة `shared/verifier.py`، وdigests فريدة لكل observation، و`scope_context`/`identity_context` كاملين) ومُرِّرت مباشرة على `validate_race_condition()`:

| فرق النجاح | `negative_successes` | متوقَّع | النتيجة الفعلية |
|---|---|---|---|
| 1 | 0 | رفض عند هذا الفحص تحديدًا | ✅ `causal_signal_and_negative_control_required` |
| 2 (الحد الجديد) | 0 | عبور هذا الفحص | ✅ عبر، توقَّف لاحقًا عند طبقة أعمق عامة (`proof_bundle_promotion_contract_failed`، خارج نطاق هذا الإصلاح) |
| 0 | 0 | رفض | ✅ `causal_signal_and_negative_control_required` |
| — (فرق=3) | 1 (الحد الجديد) | عبور | ✅ عبر لنفس الطبقة الأعمق |
| — (فرق=3) | 2 | رفض | ✅ `causal_signal_and_negative_control_required` |

المقارنة بين "السيناريوهات المتوقَّع رفضها تتوقف بالضبط عند هذا الفحص" و"السيناريوهات المتوقَّع نجاحها تعبر هذا الفحص بالتحديد وتفشل فقط عند طبقة عامة أعمق (غير خاصة بـ race_condition)" هي دليل تجريبي كافٍ على صحة التعديل دون الحاجة لبناء mock كامل يُرضي طبقة الـ proof-bundle (التي تتطلب حقولًا عامة لكل أنواع الـ findings، خارج نطاق هذا الإصلاح المحدد).

**نقطة للدمج:** لو كان لدى Team 2 أي تعديل مواز على نفس الدالة (خصوصًا لو لمس `causal_signal`/`negative_control_complete`)، القيم الجديدة للثابتين (`2` و`1`) قرار تصميمي صريح موثَّق هنا بسببه الكامل — ناقشوه بدل افتراض رقم واحد صحيح.

---

### 6.2 `src/webpent/agents/hypothesis_analyzer/agent.py` — تغطية NoSQL لجسم POST + إصلاح ترتيب المطابقة (findings #2، #5)

**المشكلة #2:** `_nosql_operator_hypotheses()` تفحص query string فقط — لا تغطي جسم POST، رغم أنه الموضع الأشيع لحقن NoSQL في REST APIs حديثة مبنية على MongoDB (مثل `POST /search {"query": "..."}`).

**الحل المطبَّق (إضافة 3 مُدخلات جديدة في `_FORM_FIELD_SIGNALS`، الجدول الموجود مسبقًا الذي يربط أسماء حقول النماذج بأصناف ثغرات):**
```python
("filter", VulnClass.NOSQL_INJECTION.value, "filter/query field in form body"),
("query", VulnClass.NOSQL_INJECTION.value, "filter/query field in form body"),
("search", VulnClass.NOSQL_INJECTION.value, "filter/query field in form body"),
```
**قرار تصميمي مهم:** هذا **ليس** دالة مطابقة substring جديدة. كاشف الـ query-string يبحث عن صياغة operator حرفية (`$ne`, `$gt`, ...) موجودة بالفعل في URL مُكتشف — لكن حقل نموذج مُكتشف من HTML حي لا يحتوي أبدًا هذه الصياغة بذاته (المهاجم يضيفها وقت الطلب، لا مؤلف الصفحة وقت القالب). الإشارة المفيدة هنا هي **اسم الحقل نفسه**، تمامًا مثل كل صف آخر في هذا الجدول، ومطابَقة بنفس `_matches_param_name()` الموجودة مسبقًا والمستخدمة لكل صف آخر — **لا منطق substring جديد**، وبالتالي لا يمكن أن تتكرر مشكلة `$lt`/`$lte` (أدناه) هنا.

**المشكلة #5:**
```python
_NOSQL_OPERATOR_FRAGMENTS: tuple[str, ...] = (
    "$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin", "$regex", ...
)
```
تُفحص هذه بالترتيب عبر `operator in lowered` (مطابقة substring) مع `break` عند أول تطابق. بما أن `"$lt"` بادئة حرفية لـ `"$lte"` وتسبقها في القائمة، أي `$lte` حقيقي في اسم parameter يُسجَّل خطأً كـ `"$lt"` في نص الـ reasoning (نفس المشكلة بالضبط بين `$gt`/`$gte`). **لا يُفقِد الاكتشاف** — الـ finding يُنشأ بشكل صحيح لفئة `nosql_injection` — لكنه يُسجّل اسم operator غير دقيق.

**الحل المطبَّق:**
```python
_NOSQL_OPERATOR_FRAGMENTS: tuple[str, ...] = (
    "$ne", "$gte", "$gt", "$lte", "$lt", "$nin", "$in", "$regex",
    "$where", "$exists", "$or", "$and", "$not", "$all", "$elemmatch",
)
```
الأطول أولًا (`$gte`/`$lte`/`$nin` قبل `$gt`/`$lt`/`$in`). `$regex`/`$elemmatch` بلا شقيق أقصر في هذه القائمة، فموضعهما لم يتأثر.

**التحقق:** `py_compile` نظيف؛ اختبار مباشر لكل الـ operators الستة المتأثرة (`$lte`,`$gte`,`$lt`,`$gt`,`$nin`,`$in`) يؤكد عدم وجود mislabeling؛ اختبار لحقول `filter`/`query`/`search` الجديدة يؤكد `nosql_injection` بلا تصادم زائف مع مُدخلات أخرى في نفس الجدول (مثل `username` الموجود مسبقًا)؛ إعادة تشغيل `tests/test_p0_p1_active_validators.py` + `tests/test_v58_post_form_hypotheses.py` + `tests/test_team1_non_dvwa_hypotheses.py` + `tests/test_team1_hypothesis_portfolio.py` (24 اختبارًا) — **24 نجح، صفر فشل**، فلا انحدار (regression) في أي من الحقلين المتأثرين.

---

### 6.3 `src/webpent/agents/api_testing/agent.py` — تكرار محتمل للـ finding عبر مرشَّحَي URL (finding #4)

**المشكلة:** بعد إدخال `_iter_path_url_candidates()` (سبرنت Detection Depth الأصلي، §2.6)، كل مسار مخمَّن قد يُجرَّب على مرشَّحين (host-root وapp-root-preserving) لنفس المسار المنطقي. على تطبيق SPA catch-all، قد يُنتج **كلا** المرشَّحين نفس الاستجابة الإيجابية — تكرار محتمل لنفس الـ finding بمسارين (`url`) مختلفين لنفس `path`.

**مراجعة فعلية للحلقات الأربع كشفت أن 3 منها كانت محميّة بالفعل، من قبل هذا السبرنت، بآليات مختلفة — تعديل فعلي كان مطلوبًا في واحدة فقط:**

| الدالة | الحالة قبل المراجعة | الإجراء |
|---|---|---|
| `_probe_graphql` | **بلا أي حماية** — الحلقة تواصل لكل `(path, url)` بلا قيد | **عُدِّلت فعليًا** (تفاصيل أدناه) |
| `_probe_jwt_alg_none` | `break` كامل من الحلقة بأكملها عند أول نجاح (أي `path`، أي `url`) — موجود مسبقًا، أقوى من المطلوب | وُثِّقت بتعليق فقط، بلا تعديل وظيفي |
| `_probe_jwt_key_confusion` | `return findings` كامل من الدالة بأكملها عند أول نجاح — موجود مسبقًا، أقوى من المطلوب | وُثِّقت بتعليق فقط، بلا تعديل وظيفي |
| `_probe_mass_assignment` | `seen_fields: set[str]` عالمي عبر كل مرشَّحي الدالة (وليس محصورًا بـ `path` واحد) — موجود مسبقًا، يمنع التكرار كأثر جانبي | وُثِّقت بتعليق فقط، بلا تعديل وظيفي |

**الحل المطبَّق في `_probe_graphql` فقط:**
```python
_matched_paths: set[str] = set()
for path, url in _iter_path_url_candidates(base_url, _GRAPHQL_PATHS):
    if path in _matched_paths:
        continue
    ...
    # عند نجاح الـ Finding:
    _matched_paths.add(path)
```
**قرار دقيق متعمَّد:** هذا تخطٍّ على مستوى `path` **وليس** `break` كامل من الحلقة الخارجية — لو فشل المرشَّح الأول (host-root) لمسار `/graphql`، المرشَّح الثاني (app-root) لنفس المسار لا يزال يُجرَّب بلا تغيير؛ التخطي يحدث فقط بعد **نجاح** مؤكَّد لنفس الـ `path`. وبما أن `_GRAPHQL_PATHS` تضم 6 مسارات منطقية مختلفة تمامًا (`/graphql`, `/api/graphql`, `/v1/graphql`, ...)، التخطي لا يمنع فحص أي مسار آخر — كل ثغرة حقيقية على endpoint منفصل لا تزال تُسجَّل كـ finding مستقل.

**التحقق التجريبي:** بناء سيناريو كامل بـ mock لـ `make_safe_httpx_client` حيث `base_url` له بادئة تطبيق (`/dvwa/...`) فيُنتج `_iter_path_url_candidates` مرشَّحين لمسار `/graphql`، وكلاهما مُهيَّآن للرد بنجاح introspection — تمامًا سيناريو SPA/catch-all الموصوف في التقرير:
```
Total findings: 1          # لا تكرار رغم مرشَّحين إيجابيين
Requests made: 12          # المرشَّح الثاني لـ /graphql لم يُرسَل أصلًا (تخطٍّ قبل أي طلب شبكي)
```
والحلقة واصلت فعليًا تجربة باقي الـ 5 مسارات (10 طلبات إضافية لمرشَّحَيها) — إثبات مباشر أن التخطي محصور بـ `path` ولا يوقف الحلقة بأكملها.

---

### 6.4 `src/webpent/agents/business_logic_fuzzer/agent.py` — `daemon=True` دفاعي (finding #7)

**المشكلة:** `threading.Thread(target=contextvars.copy_context().run, args=(_worker,))` بلا `daemon=True` في `_send_concurrent_burst`. مع `t.join(timeout=30.0)` والـ httpx client الداخلي بـ `timeout=10.0`، تعلُّق thread أطول من ذلك نادر عمليًا لكن ليس مستحيلًا نظريًا (طبقة شبكية وسيطة معطوبة، إلخ). لو حدث، thread غير-daemon يبقى حيًا في الخلفية بدل أن يُنهى تلقائيًا مع العملية الرئيسية.

**الحل المطبَّق:**
```python
threading.Thread(target=contextvars.copy_context().run, args=(_worker,), daemon=True)
```
دفاع إضافي بسيط، بلا أي تغيير سلوكي آخر. **ليس له علاقة** بإصلاح `contextvars.copy_context()` non-reentrancy الموجود مسبقًا (موثَّق بتعليق "V9 P1 FIX" في نفس الدالة) — ذاك إصلاح مختلف تمامًا كان صحيحًا بالفعل عند المراجعة.

---

### 6.5 `src/webpent/cli/git_source.py` — فشل `git init` لا يُنظِّف `destination` (finding #8)

**المشكلة:** خطوات fallback الأربع (`init`, `remote add`, `fetch`, `checkout`) محاطة بـ `try/except GitSourceError: shutil.rmtree(...); raise` — لكن فحص `init.returncode != 0` والرفع المقابل كانا يقعان **قبل** بداية هذا الـ `try`. فشل `init` نفسه لم يكن يُنظِّف `destination` (التي قد يكون `git init` أنشأها جزئيًا قبل الفشل).

**الحل المطبَّق:** نقل استدعاء `init` وفحصه ليكونا أول سطرين داخل نفس كتلة `try` الموجودة، فتُغطَّى الحالات الأربع كلها بنفس منطق التنظيف الموحَّد:
```python
destination.parent.mkdir(parents=True, exist_ok=True)
try:
    init = _run_git(["init", "--quiet", "--", str(destination)], ...)
    if init.returncode != 0:
        raise GitSourceError(...)
    remote = _run_git(["remote", "add", "origin", url], ...)
    # ... (fetch, checkout — بلا تغيير)
except GitSourceError:
    shutil.rmtree(destination, ignore_errors=True)
    raise
```

**التحقق التجريبي (أهم إصلاح للتحقق منه تجريبيًا، لأنه يلمس تنظيف الملفات):** سكريبتان مستقلان باستخدام `unittest.mock.patch` على `_run_git`:
1. **سيناريو فشل `init` عمدًا** (بعد فشل الـ clone الأساسي، لإجبار المسار على fallback): `GitSourceError` تُرفع كما هو متوقَّع، و`destination.exists()` ترجع `False` بعدها — **التنظيف يعمل الآن**.
2. **سيناريو النجاح الكامل** (كل الخطوات الأربع تنجح): الدالة ترجع `destination` بشكل صحيح، بلا أي انحدار في المسار السعيد.

---

### 6.6 قرارات عدم التعديل (findings #6، #9)

**#6 — `subdomain_takeover/agent.py`، عمومية بعض الـ body markers الجديدة:** ثلاثة markers من بين 15 مزوّدًا جديدًا (`anima`, `strikingly`, `help-juice`) عامة بما يكفي لتتطابق نظريًا مع صفحات 404 عادية غير مرتبطة. **لم يُعدَّل** لأن طبقتين مستقلتين موجودتين مسبقًا (قبل هذا السبرنت) تُخففان المخاطرة فعليًا: (أ) الـ body marker لا يُفحص إلا بعد تطابق CNAME الفعلي مع نطاق المزوّد المحدَّد تحديدًا — ليس أي موقع يصل لمرحلة فحص الـ body؛ (ب) أي finding من هذا المكشاف يُصنَّف دائمًا صراحةً `confidence_level="Needs Human Review"` مع `promotion_guard` محدَّد في الـ evidence — أقصى أثر لأي false positive هنا عنصر يحتاج مراجعة بشرية، لا ادّعاء مؤكَّد. تعديل الكود هنا (فرض حد أدنى لطول الـ marker مثلًا) كان سيضيف تمييزًا تعسفيًا بفائدة محدودة أمام الحمايتين الموجودتين.

**#9 — `hypothesis_analyzer/agent.py`، `results[:2]` كود ميت في `_nosql_operator_hypotheses`:** بنية الحلقتين تضمن أن `results` لا يحتوي أبدًا أكثر من عنصر واحد قبل `return results[:2]` — الـ slice توثيق مُضلِّل أكثر منه منطقًا فعليًا. **لم يُعدَّل** — لا تأثير وظيفي، والتغيير الممكن الوحيد (حذف الـ slice أو السماح فعليًا بنتيجتين من مصدرين مختلفين) قرار تصميمي (هل نريد الإبلاغ عن أكثر من parameter مشبوه في نفس الـ URL؟) تُرك لك بدل افتراضه.

---

### 6.7 حالة الفحص بعد مرحلة Red Team

- **Syntax:** `py_compile` نظيف على كل الملفات الخمسة المعدَّلة في هذه المرحلة (`active_checks.py`, `hypothesis_analyzer/agent.py`, `api_testing/agent.py`, `business_logic_fuzzer/agent.py`, `git_source.py`).
- **Lint:** صفر أخطاء ruff **جديدة** من هذه المرحلة. فُحص كل خطأ ظهر بعد التعديل سطرًا سطرًا: 2 كانا من تعديلاتي فعليًا (`N806` على الثابتين في `active_checks.py`) وأُصلحا فورًا (§6.1)؛ الباقي (13 خطأ، معظمها line-too-long + حالة واحدة `B007` وحالتان `N806` في دالة `DeepReconEngine` غير ذات صلة) مؤكَّد أنها موجودة مسبقًا وبعيدة تمامًا عن أي سطر لمسته هذه المرحلة.
- **اختبارات:** 15 ملف اختبار مرتبط مباشرة (بالاستيراد) بالملفات الخمسة المعدَّلة — **112 نجح، 2 فشل**. الفشلان (`test_jwt_confusion_confirms_on_alg_none_acceptance` و`test_jwt_confusion_explicit_negative` في `tests/test_postp0_phase5_validators.py`) **ليسا من هذه المرحلة ولا من Team 1 على الإطلاق**: تم التأكد مباشرة (بتشغيل الدالة المُختبَرة يدويًا خارج pytest) أن `validate_jwt_key_confusion()` في `validator/postp0_checks.py` — ملف لم يُعدَّل في أي مرحلة من مراحل هذا السبرنت — تحاول اكتشاف مفتاح JWKS عبر شبكة فعلية من مضيف الاختبار الوهمي `lab.local`، وهو غير قابل للـ DNS resolution في بيئة هذه الجلسة (`SSRF transport: blocked direct request... lab.local`؛ `reason: jwks_public_key_not_discoverable`). نفس النمط بالضبط الموثَّق مسبقًا في §5 لـ 14 اختبارًا آخر بنفس السبب. الاختبار نفسه يبدو ناقصًا (لا يعمل monkeypatch لخطوة اكتشاف JWKS، فقط لخطوة `_jwt_status` اللاحقة) — يستحق مراجعة منفصلة لا علاقة لها بـ Team 1.
