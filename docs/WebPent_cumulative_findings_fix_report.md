# WebPent — تقرير إصلاح تراكم نتائج الفحوص

## الملخص التنفيذي

كان سبب ظهور ثغرتين مختلفتين في كل تشغيل أن النظام كان يعرض نتائج الـ`thread_id` الأخير فقط. وبما أن كل تشغيل جديد كان يحصل على UUID جديد، كانت النتائج السابقة موجودة في قاعدة البيانات لكنها غير داخلة في projection المعروض للمستخدم. النتيجة الظاهرة كانت **آخر run فقط** وليست مجموع نتائج الـengagement.

تم إصلاح ذلك بإضافة **cumulative engagement projection**: كل تشغيل لنفس الهدف ونفس العميل يحصل تلقائيًا على engagement scope ثابت، ثم تُجمع نتائج جميع الـruns المرتبطة بهذا الـscope، مع deduplication ثابت واختيار أقوى نسخة من كل finding منطقيًا.

> الإصلاح لا يخترع ثغرات ولا يرفع confidence تلقائيًا؛ هو يصلح العرض والتجميع فقط. الـconfirmed findings تظل محتاجة دليل قابل لإعادة الإنتاج.

## السبب الجذري

| المسار | السلوك السابق | الأثر |
|---|---|---|
| CLI | يعرض `final_state["findings"]` فقط | اختفاء نتائج runs السابقة من شاشة CLI |
| API findings | يستدعي `get_findings_by_thread(thread_id)` | endpoint يعرض آخر thread فقط |
| risk summary | يحسب المخاطر من آخر thread فقط | الأرقام تتغير بشكل مضلل بين التشغيلات |
| reporter | يبني التقرير من state الحالي فقط | report.html وreport.json لا يعكسان تاريخ engagement |
| engagement identity | thread UUID جديد في كل run | عدم وجود scope منطقي ثابت للتجميع |

## الإصلاحات المنفذة

### 1. Stable engagement scope

أضيفت الدالة `default_engagement_id()` في:

```text
src/webpent/shared/finding_aggregation.py
```

إذا لم يمرر المستخدم `--engagement-id` في CLI أو `engagement_id` في API، يتم اشتقاق scope ثابت من:

```text
target URL + client_id
```

يتم تخزين digest مختصر فقط، ولا يتم تخزين credentials أو secrets داخل scope.

### 2. CLI support

أضيف الخيار:

```bash
webpent scan --url http://127.0.0.1:8000 --engagement-id waptlab-main
```

السلوك الجديد:

- نفس target ونفس `client_id` بدون `--engagement-id`: يتم التجميع تلقائيًا.
- `--engagement-id waptlab-main`: كل تشغيل يحمل هذا الاسم يدخل في نفس التاريخ التراكمي.
- قيمة جديدة مثل `--engagement-id waptlab-baseline-2`: تبدأ scope منفصلًا.
- `--thread-id` ما زال مخصصًا لاستئناف checkpoint، وليس لتحديد تاريخ engagement.

الـCLI يسجل run في registry، يحفظ findings الحالية مع thread ID، ثم يعرض projection تراكميًا بعد deduplication.

### 3. API cumulative findings

تم تعديل endpoint التالي:

```text
GET /api/v1/scans/{thread_id}/findings
```

ليجمع كل threads التابعة لنفس `engagement_id` مع الحفاظ على owner/client isolation. تم تعديل `risk-summary` بنفس الطريقة، لذلك أرقام severity وconfidence أصبحت cumulative أيضًا.

تم الحفاظ على authorization القائم؛ لا يتم جمع نتائج engagements لمستخدم أو عميل آخر.

### 4. Reporter cumulative exports

قبل إنشاء Markdown/HTML/JSON/PDF، يحاول reporter قراءة findings التاريخية من نفس engagement scope ودمجها مع نتائج الـrun الحالي. عند تعذر قاعدة البيانات أو registry، يستخدم state الحالي كـfallback ولا يفشل الـscan بسبب مشكلة في projection.

### 5. Stable deduplication

أضيفت طبقة:

```text
src/webpent/shared/finding_aggregation.py
```

وتقوم بالآتي:

1. الاحتفاظ بالـfindings المختلفة من runs مختلفة.
2. اعتبار نفس vulnerability class والعنوان والـendpoint المنطقي finding واحدة.
3. تجاهل قيم query الديناميكية مثل `q=1` و`q=2` عند تكوين fingerprint، مع الاحتفاظ بأسماء المعاملات.
4. اختيار أقوى نسخة عند تكرار نفس finding؛ النسخة `Tool-Confirmed` لا يتم استبدالها بمرشح `Pending`.
5. الحفاظ على ordering deterministic ليسهل مقارنة التقارير.

## أمثلة السلوك الجديد

| التشغيل | findings الجديدة | المجموع المعروض |
|---|---:|---:|
| Run 1 | IDOR | 1 |
| Run 2 | Stored XSS | 2 |
| Run 3 | نفس IDOR مرة أخرى | 2، وليس 3 |
| Run 4 | SQLi confirmed لنفس endpoint المرشح | 3، مع الاحتفاظ بالنسخة الأقوى |

إذًا العدد **يزيد عند اكتشاف finding جديدة**، ولا يزيد بسبب تكرار نفس finding. وقد ينخفض فقط إذا استخدم المستخدم engagement scope جديدًا أو قام بتنظيف قاعدة البيانات عمدًا.

## اختبارات التحقق

تم تشغيل:

```text
Full pytest: 670 passed, 94 warnings
Ruff على الملفات المعدلة: All checks passed
```

وأضيفت اختبارات مخصصة في:

```text
tests/test_finding_aggregation.py
```

وتثبت:

- تراكم findings المختلفة عبر runs.
- عدم استبدال confirmed finding بمرشح أضعف.
- deterministic fingerprint.
- عزل stable engagement scope حسب client.

## الملفات المعدلة الرئيسية

```text
src/webpent/shared/finding_aggregation.py
src/webpent/memory/db.py
src/webpent/api/scan_registry.py
src/webpent/api/app.py
src/webpent/cli/__init__.py
src/webpent/agents/reporter/agent.py
tests/test_finding_aggregation.py
```

لم يتم تعديل WAPTLab.

## ملاحظة مهمة بخصوص عدد ثغرات WAPTLab

هذا الإصلاح يعالج **فقدان النتائج بين التشغيلات**، لكنه لا يحول candidate finding إلى confirmed vulnerability تلقائيًا. لذلك لا يصح اعتبار التراكم وحده اكتشافًا للـ20 ثغرة. يجب تشغيل WebPent مرة أخرى على WAPTLab بنفس `engagement_id`، ثم مراجعة النتائج المجمعة والأدلة القابلة لإعادة الإنتاج.

كما أن qualification الحية لم تُعد في هذه الجولة إذا ظل Docker Server غير متاح. التصنيف الحالي يظل:

> **Autonomous Candidate / Early Beta**

وليس Release A أو VIP Autonomous Bug Hunter.
