# UM-DR-48 — MISS_MAP: خريطة الفجوة للعائلات الخمس الصامتة (قانون 6)

> **المصدر:** run files الـ47 الفعلية (`deliverables/umdr47/measurement_run_files/`) —
> كل رقم أدناه مقروء بالكود من السجلات، لا من الذاكرة. الملف هو بوابة فتح
> Phases D وC5: لا كود قبل هذه الخريطة.
>
> **الحكم العام المسبق:** العائلات الخمس وصلها العرض الصحيح (المسارات) لكن
> **لم يُنتَج دليل التأكيد المطلوب** — الكاشف يفحص السطح ولا يكمل العقد.
> الحقيقة الحاسمة الموحدة: **CausalGuard استُدعي 0 مرات في كل عائلة صامتة**
> (قِيسَ من `causal_guard_invocations` في السجلات) مقابل 2/2 CONFIRMED في
> idor_bola. الفجوة ليست "لا نرى المسار" بل "لا نبني الدليل الذي يفتح البوابة".

---

## 0) البصمة العامة (من السجلات، لكل العائلات الصامتة)

| المؤشر | idor_bola (تعمل) | العائلات الخمس الصامتة |
|---|---|---|
| طلبات للحملة | 108 | 94–116 |
| `causal_guard_invocations` | **2** | **0** |
| `guard_verdicts` CONFIRMED | 2 | 0 |
| وصول `User_B` للمسار المستهدف | نعم (GET anchor كـ User_B) | جزئي (انظر لكل عائلة) |

آلية عمل idor_bola (لماذا نجحت): الـBOLA lane تبني زوج الهويات
(owner GET ينجح / User_B GET نفس المورد) → differential تحت CausalGuard →
CONFIRMED. أي عائلة تفتقر لمولّد هذا الزوج تبقى صامتة مهما مشت المسارات.

---

## 1) workflow_abuse — GT-WF-1

- **عقد الإثبات المطلوب:** مورد ينتقل لحالة `shipped` **بلا تمرير بـ`approved`**
  (state-before/after): `POST /api/orders/ORD-W-101/ship` كـowner يعيد
  `{"status":"shipped","skipped_approval":true}` في المتأثر، و409
  workflow violation في الآمن.
- **ما أُرسل فعلًا (run1):** `GET /api/orders/ORD-W-101/ship` ×1 و
  `GET /api/orders/ORD-W-555/ship` ×0 — **GET على endpoint تعريفه POST-only**.
  إجمالي POSTs على مسارات orders: **0** (الـ9 POSTs ذهبت كلها لمسارات
  graphql المزعومة `/graphql /api/graphql /v1/graphql /query /graphiql`).
- **البروب المفقود بالتحديد:** تسلسل POST حالة: `POST .../ship` مباشرة
  (skip) مع قراءة الحالة قبل/بعد (`GET .../ORD-W-101` قبل وبعد)، وزوج
  الضبط `POST .../approve` (admin) ثم `ship`.
- **فجوة التوقيع:** لا يوجد كاشف workflow-skip يعمل POST تسلسلي ويقارن
  الحالة النهائية بالمسار المصرح به. الكاشفات الحالية GET-first؛ مسارات
  "actions" لا تُعامل كآلة حالات.
- **لماذا يُبنى في هذه النافذة:** الآلة المطلوبة صغيرة وموجودة نصفيها:
  SKG يسجل `workflow_observations` (transitions) والـlab يعلن الحالات في
  الردود. المخطط: D1 (استخراج workflow_skip_candidates من SKG → تنفيذ
  التسلسل → مقارنة الحالة النهائية → differential CausalGuard).

## 2) request_smuggling — GT-SMUG-1

- **عقد الإثبات المطلوب:** POST إلى `/api/echo` يحمل **كلا** من
  `Content-Length` و`Transfer-Encoding: chunked` — الرد المتأثر يوثق
  `framing_used: chunked` + `bytes_beyond_content_length > 0`؛ الآمن
  يرفض بـ400.
- **ما أُرسل فعلًا:** `GET /api/echo` ×4 (الرد: 405 POST-only + hint).
  **صفر POST** إلى echo. الـ9 POSTs ذهبت لمسارات graphql وهمية.
- **البروب المفقود بالتحديد:** بروب تفاوت التفسير المزدوج: طلب POST واحد
  بترويسات CL+TE متضاربة (أو زوج CL.CL وTE.TE) على نفس الـendpoint،
  والقبول على "الرد الأمامي يوثق التفسير المستخدم".
- **فجوة التوقيع:** لا يوجد كاشف framing-differential يبني طلب خام
  بترويستَي طول. الكاشف الموجود (request_smuggling agent) يعمل على
  رصد response-splitting من تفسيرات جاهزة، لا يولّد زوج CL/TE بنفسه
  على endpoint echo عادي.
- **لماذا يُبنى في هذه النافذة:** الـlab يعلن نفسه أوراكل صادقًا في
  الرد (يفصّل framing_used و bytes_beyond). بروب واحد POST + قراءة
  الحقلين = دليل مزدوج المصدر (طلب مختوم + رد موثق).

## 3) graphql_oracle — GT-GQL-1

- **عقد الإثبات المطلوب:** `POST /graphql` بـquery
  `invoice(id:"INV-G-303")` بصلاحية أقل (User_B) يعيد فاتورة User_A
  (الresolver لا يفرض ownership في المتأثر)؛ في الآمن errors. الدليل:
  اختلاف بيانات بين هوية المالك والهوية الأدنى على نفس الـoperation.
- **ما أُرسل فعلًا:** 11 hits على `/graphql` (7 GET + **4 POST**) —
  الـPOSTs أُرسلت لكن من **User_A فقط** (مالك INV-G-303 نفسه)، لا يوجد
  POST واحد من User_B. الـdocs تعلن example_queries حرفيًا.
- **البروب المفقود بالتحديد:** إعادة تشغيل الـoperation المُستخرج من
  introspection/docs **بالهوية الأقل صلاحية** (User_B) — نفس نمط زوج
  الهويات الذي نجح في idor_bola لكن على قناة GraphQL.
- **فجوة التوقيع:** مسار GraphQL في المحرك يكتشف الـendpoint ويطلق
  introspection لكن **لا يمرر الهويات البديلة** إلى executor الـGraphQL؛
  زوج الهويات موجود كخاصية في الـinvocation (`identity_profiles`) لكن
  الـGraphQL lane لا يستهلكه.
- **لماذا يُبنى في هذه النافذة:** F2.3 أدخل operations إلى SKG كسجلات؛
  ناقص فقط: تنفيذ الـoperation بهوية ثانية ومقارنة. نفس differential
  engine لـidor مع مصدر "operation" بدل "REST path".

## 4) tenant_confusion — GT-TEN-1

- **عقد الإثبات المطلوب:** `GET /api/tenant/profiles/PROF-T2-55` بجلسة
  User_A (tenant T1) **+ ترويسة `X-Tenant-ID: T2`** يعيد بيانات T2 مع
  `"tenant_source": "client_header"` (المتأثر)؛ الآمن يتجاهل الترويسة
  ويعيد 403. الدليل: مورد tenant-A قرأه principal تابع لـtenant-B
  بإشارة source=header.
- **ما أُرسل فعلًا:** وصل المستهدف 6 مرات — منها `User_B` مرة واحدة
  (**B تابع لـT2 أصلًا → 200 مشروع، ليس الثغرة**) وUser_A بلا الترويسة
  (403). **صفر طلبات بترويسة X-Tenant-ID** — والـdocs يعلن الترويسة
  صراحة (`"headers": {"X-Tenant-ID": "tenant context (accepted)"}`).
- **البروب المفقود بالتحديد:** تبديل **معرّف السياق** (header) مع تثبيت
  الهوية: طلبات User_A × {بلا ترويسة، T1، T2} على مورد T2 — الفرق
  403→200 مع tenant_source=client_header هو التوقيع.
- **فجوة التوقيه:** كاشف BOLA يبدّل **الهوية** (جلسة) ولا يبدّل
  **مُحدِّد النطاق** (header/subdomain/route prefix). لا يوجد مفهوم
  "tenant-context override" في أي lane.
- **لماذا يُبنى في هذه النافذة:** نفس زوج idor + بُعد تبديل واحد
  (ترويسة مُعلنة في الردود). الـlab نفسه يوثق source في الرد —
  differential جاهز للالتقاط.

## 5) redirect_scope_bypass — GT-RED-1 + GT-RED-2 (6 FN)

- **عقد الإثبات المطلوب:**
  - (a) open redirect: `GET /api/redirect?url=<out-of-scope-origin>/x`
    يعيد 302 لموقع خارج النطاق — الدليل: الوجهة النهائية الفعلية مقابل
    قائمة النطاق المصرح (الـbattery توفر out-of-scope origin مخصص).
  - (b) scope bypass: `GET /public/../admin/reports` يعيد التقرير
    **بدون بوابة admin** (`"router_note": "normalized path served
    without admin gate"`) بينما `/admin/reports` المباشر يفرضها.
- **ما أُرسل فعلًا:** 9 hits على `/api/redirect` **كلها بلا `?url=`**
  (صفر قيمة معاملة)، و`/admin/reports` مباشرةً عدة مرات، **وصفر طلبات
  traversal** رغم أن الـlanding يعرض `/public/../admin/reports` كرابط
  حرفي.
- **البروب المفقود بالتحديد:** (a) تمرير قيم url مُتحكم بها (خارجية
  +ترويسات scheme) وقراءة Location النهائي؛ (b) إعادة إرسال الرابط
  الحرفي الموجود في الـcrawl (الـcrawler يطبّعه فيسقط `..`) بمسار خام.
- **فجوة التوقيع:** الـcrawler **يطبّع المسارات قبل الطلب** فيفقد
  `..` الحرفي؛ ولا يوجد redirect-tree walker يتتبع القفزات ويقارن
  الوجهة بالنطاق. الكاشف يرى 302 كـ"سلوك عادي".
- **لماذا يُبنى في هذه النافذة:** العقد مزدوج لكنهما ميكانيكيان:
  (a) walker بقفزات محدودة يقرأ Location ويحكم بالنطاق (المعلن في
  الـscope policy نفسها)؛ (b) قناة raw-path للروابط المكتشفة
  (إعادة الإرسال الحرفي) — والـlab يميز نفسه بالرد (router_note).

---

## 6) P0.3 — خريطة السلاسل الصامتة (W5 = 0 بالأثر)

- **ما هو المطلوب لاشتعال W5:** `chain_step_hypotheses` تُنبثق فقط عندما
  يؤلّف SKG سلاسل (≥2 علاقات قابلة للربط: identity→resource→action)،
  والبوابة التسلسلية تفتح خطوة بعد إثبات الخطوة السابقة.
- **الأثر الفعلي (من بنية البطارية):** الـlabs الست كلها **عائلات
  أحادية العيب معلنة** — عيب واحد لكل lab (لا يوجد lab يحمل عيبين
  قابلين للتركيب أصلًا). حتى لو اشتغل المخطط مثاليًا: `compose_attack_chains`
  لن يجد سلسلة ≥2 على fixtures لا تحمل إلا عيبًا واحدًا.
- **التحقق بالأثر لا بالتخمين:** على الـrun files، `w5_steps_total=0`
  في كل حملة، وw4 (coverage tasks) وصل 180 — أي أن الاستنتاج يعمل
  ويملأ المهام، لكن **المدخل (chains) فارغ لأن الأرض نفسها لا تحمل
  سلاسل**. الآلة ليست معطلة؛ **المنضدة بلا سلاسل**.
- **القرار (C5.1):** توسعة البطارية v2 بقسم سلاسل معلن — fixture واحد
  يحمل عيبين قابلين للتركيب (workflow-skip يكشف مورد IDOR + تدفق OAuth
  يمنح صلاحية تُستغل بـGraphQL mutation) — بتوسيع معلن كتطور للبطارية
  (لا تلاعب): ground truth مُعلن قبل التشغيل، والـvariant الآمن يثبت
  العزل.

## 7) خلاصة ترتيب العمل (بوابة D وC5 تفتحان الآن)

| العائلة | الفجوة الأساسية | خط D | شكل الدليل المفتاح للـCausalGuard |
|---|---|---|---|
| workflow_abuse | POST تسلسلي + مقارنة حالة | D1 | state-before/after + skipped_approval |
| request_smuggling | توليد CL/TE الخام | D2 | framing_used + bytes_beyond (رد موثق) |
| graphql_oracle | تنفيذ operation بهوية أدنى | D3 | data differential بين هويتين |
| tenant_confusion | تبديل مُحدِّد النطاق (header) | D4 | 403→200 + tenant_source=client_header |
| redirect_scope_bypass | walker + raw-path | D5 | Location خارج النطاق / router_note |
| السلاسل | أرض بلا سلاسل مركبة | C5 | بطارية v2: عيبان قابلان للتركيب |

**كل الفجوات الخمس تشترك في جذر واحد:** المحرك يملك آلية differential
 واحدة (تبديل الهوية على GET) ولا يملك الآلات الأربع الأخرى (تسلسل
 الحالة، التوليد الخام للترويسات، تنفيذ العمليات بهوية ثانية، تبديل
 سياق النطاق). D1–D5 تُنشئ هذه الآلات تحت CausalGuard — كل واحدة بعقد
 إثبات معلن قبل الكود.
