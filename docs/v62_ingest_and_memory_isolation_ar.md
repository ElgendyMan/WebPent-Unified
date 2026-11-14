# WebPent v62 — إصلاح ingest وعزل ذاكرة الدروس

## الملخص التنفيذي

تم تنفيذ الإصلاحين المطلوبين على نسخة WebPent الموجودة في `/home/ubuntu/webpent_v60`. أصبح أمر ingest يقبل نوع `payload`، وأصبح قادرًا على جلب مستودع Git عام عبر HTTPS بعملية shallow clone قبل ingest. كما تم فرض عزل الدروس advisory lessons حسب `client_id` و`engagement_id` في التخزين والاسترجاع، مع اعتماد سياسة **fail-closed** عند غياب أي من المعرّفين.

لا يعتمد wrapper الجلب على shell، ولا يسمح بروابط HTTPS تحتوي credentials، ويمنع prompts التفاعلية من Git، ويستخدم `--depth 1` و`--no-tags`، مع timeout وتنظيف checkout المؤقت بعد انتهاء ingest. كذلك يمنع مسار ingest من الخروج خارج checkout عند تمرير path نسبي أو عند وجود symlink يحاول تجاوز حدود المستودع.

## التغييرات المنفذة

| المجال | التغيير | الأثر الأمني أو التشغيلي |
|---|---|---|
| CLI ingest | إضافة `payload` إلى choices الخاصة بـ`--type` | يمكن وسم PayloadsAllTheThings وSecLists كمصادر payloads مستقلة في metadata |
| Git source | إضافة `cli/git_source.py` مع `clone_repository()` | جلب shallow وغير تفاعلي، بدون shell، وبدون credentials مضمّنة |
| ingest من Git | إضافة `--git-url` و`--git-ref` و`--git-dir` | يدعم checkout مؤقتًا افتراضيًا أو مجلدًا يحدده المستخدم |
| path containment | التحقق من أن target النهائي داخل checkout | منع `..` وabsolute paths وsymlink escape |
| state scope | إضافة `client_id` و`engagement_id` إلى state وinitial state | تمرير نطاق الذاكرة من API/CLI إلى reflection وhypothesis analyzer |
| lesson storage | رفض حفظ lesson بدون المعرّفين | لا يتم إنشاء lesson غير قابلة للعزل |
| lesson retrieval | بناء filter مركب مطابق للـclient والـengagement | لا يتم إرجاع درس من عميل أو engagement مختلف |
| API | إتاحة `client_id` و`engagement_id` في `ScanRequest` | `engagement_id` الافتراضي يساوي `thread_id`، وغياب `client_id` يجعل الذاكرة fail-closed |

## أمثلة الاستخدام

### Ingest محلي لنوع payload

```bash
webpent-ingest ./PayloadsAllTheThings --type payload
```

### Ingest من مستودع Git عام

```bash
webpent-ingest \
  --git-url https://github.com/swisskyrepo/PayloadsAllTheThings.git \
  --type payload
```

يمكن تحديد branch أو tag باستخدام `--git-ref`. وإذا تم استخدام `--git-dir` يجب أن يكون المسار غير موجود مسبقًا؛ أما في الوضع الافتراضي فيتم إنشاء checkout مؤقت وتنظيفه تلقائيًا بعد اكتمال العملية.

```bash
webpent-ingest ./XSS \
  --git-url https://github.com/swisskyrepo/PayloadsAllTheThings.git \
  --git-ref master \
  --type payload
```

### نطاق API

يمكن إرسال `client_id` و`engagement_id` في طلب إنشاء scan. إذا لم يتم إرسال `engagement_id`، يستخدم worker قيمة `thread_id` التي أنشأها الخادم. أما إذا لم يوجد `client_id`، فلا يسمح مسار الذاكرة بحفظ أو استرجاع lessons؛ وهذا مقصود لمنع الخلط بين العملاء.

```json
{
  "url": "https://example.test",
  "client_id": "client-a",
  "engagement_id": "engagement-2026-08-17"
}
```

## سياسة العزل

يتم قبول lesson فقط عندما تحتوي metadata على قيمتين غير فارغتين:

```text
client_id=<stable client scope>
engagement_id=<logical engagement scope>
```

ويتم الاسترجاع بفلتر مركب يطابق القيمتين معًا. لذلك فإن تطابق `client_id` وحده لا يكفي، وتطابق `engagement_id` وحده لا يكفي. أي request ناقص النطاق يرجع نتيجة فارغة بدل تنفيذ بحث غير مفلتر. هذا يحمي legacy checkpoints أيضًا لأن الحقول nullable في state، لكن retrieval لا يفترض وجود scope غير موثوق.

## الاختبارات والتحقق

تم تنفيذ الاختبارات التالية بعد آخر تعديل:

| الفحص | النتيجة |
|---|---:|
| Compileall على `src` و`tests` | ناجح |
| Regression suite الجديدة واختبارات memory boundary | `24 passed` |
| Full pytest suite | `453 passed, 78 warnings` |
| اختبار parser لقبول `--type payload` | ناجح |
| اختبار Git URL validation | ناجح |
| اختبار shallow clone و`GIT_TERMINAL_PROMPT=0` و`shell=False` | ناجح |
| اختبار منع credentials داخل URL | ناجح |
| اختبار exact client/engagement lesson filter | ناجح |
| اختبار fail-closed عند غياب scope | ناجح |
| اختبار fallback من `engagement_id` إلى `thread_id` | ناجح |

التحذيرات المتبقية صادرة من dependencies وإعدادات التطوير الحالية، وليست failures. فحص Ruff للملفات المرتبطة ما زال يعرض بعض مخالفات baseline قديمة في `api.py` و`pentest_worker.py`، خصوصًا قواعد FastAPI `B008` وبعض الأسطر القديمة في status/error-handling؛ لم يتم تغيير منطقها ضمن هذا الإصلاح.

## الملفات الرئيسية

- [`src/webpent/cli/ingest.py`](../src/webpent/cli/ingest.py): خيارات payload وGit ingest.
- [`src/webpent/cli/git_source.py`](../src/webpent/cli/git_source.py): wrapper التحقق والجلب الآمن.
- [`src/webpent/memory/vectorstore.py`](../src/webpent/memory/vectorstore.py): تخزين واسترجاع lessons مع scope filter.
- [`src/webpent/state/state.py`](../src/webpent/state/state.py): حقول client وengagement في state.
- [`src/webpent/state/initial_state.py`](../src/webpent/state/initial_state.py): إنشاء scope مع fallback آمن.
- [`src/webpent/agents/reflection/agent.py`](../src/webpent/agents/reflection/agent.py): حفظ lessons scoped.
- [`src/webpent/agents/hypothesis_analyzer/agent.py`](../src/webpent/agents/hypothesis_analyzer/agent.py): retrieval scoped فقط.
- [`src/webpent/api/app.py`](../src/webpent/api/app.py): استقبال scope وتمريره إلى worker.
- [`src/webpent/workers/pentest_worker.py`](../src/webpent/workers/pentest_worker.py): تمرير scope إلى initial state.
- [`tests/test_v62_ingest_and_memory_isolation.py`](../tests/test_v62_ingest_and_memory_isolation.py): اختبارات الإصلاحات الجديدة.

## ملاحظة تشغيلية

الـGit wrapper مخصص لمستودعات عامة عبر HTTPS. لا يخزن credentials ولا ينفذ hooks أو shell commands من محتوى المستودع. محتوى المستودع يظل data للـingest فقط، ولا يتحول تلقائيًا إلى تعليمات تنفيذ أو finding مؤكد.

## المراجع الداخلية

[1]: ../src/webpent/cli/ingest.py "CLI ingest implementation"

[2]: ../src/webpent/cli/git_source.py "Safe Git source wrapper"

[3]: ../src/webpent/memory/vectorstore.py "Vector store lesson isolation"

[4]: ../tests/test_v62_ingest_and_memory_isolation.py "v62 regression tests"
