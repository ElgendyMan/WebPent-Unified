# WebPent Curated RAG Knowledge Pack

هذه الحزمة هي corpus محلي مُنسّق للاستخدام **الإرشادي فقط** داخل WebPent. وهي مقسمة إلى methodologies وrepositories وreports وwriteups وscenarios، وكل ملف يحتوي على مصادره العامة وحدود استخدامه. لا يُعامل أي نص فيها كدليل على ثغرة في الهدف؛ الإثبات يظل معتمدًا على السلوك المرصود والـcausal signal والـnegative control.

## المحتوى

| النوع | الغرض التشغيلي | أمثلة داخل الحزمة |
|---|---|---|
| `methodology` | تنظيم مراحل الاختبار، التحقق، وإعداد التقرير | OWASP WSTG، NIST SP 800-115، ASVS |
| `repository` | تعريف مستودعات عامة مفيدة ومجالات استخدامها | WSTG، PayloadsAllTheThings، SecLists، nuclei-templates |
| `report` | تحسين شكل التقرير وحقول الدليل وقابلية إعادة الإنتاج | evidence contract، finding lifecycle |
| `writeup` | ربط فئات الثغرات بأنماط تحقق تعليمية موثقة | PortSwigger Academy topics |
| `scenario` | حالات اختبار قانونية ومحددة النطاق | BAC، SQLi، XSS، SSRF، GraphQL |

## الإدخال والاستدعاء

الإدخال ليس تلقائيًا عند تشغيل الخدمة. يُشغّل المشغّل مسار bootstrap يدويًا بعد مراجعة `knowledge_sources.yaml`:

```bash
PYTHONPATH=src python scripts/ingest_payloads.py \
  --manifest knowledge_pack/manifest.yaml \
  --dry-run

PYTHONPATH=src python scripts/ingest_payloads.py \
  --manifest knowledge_pack/manifest.yaml
```

أثناء التشغيل، يضيف المسار metadata مثل `type` و`category` و`stack` و`source_url` و`source_id`. أما وقت الفحص، فالـplanner يستدعي `methodology` و`repository` و`scenario`، والـhypothesis analyzer يستدعي `writeup` و`report` و`scenario` بالإضافة إلى الأنواع الأخرى. يتم deduplicate النتائج ووضع حد أقصى لحجم السياق قبل تمريره إلى prompt.

> **Trust boundary:** محتوى الـRAG غير موثوق من منظور الـLLM، لذلك يجب أن يمر عبر `safe_prompt_format` ويظهر داخل `<untrusted_data>...</untrusted_data>`. لا يرفع هذا المحتوى finding ولا يغيّر graph topology ولا يمنح إذنًا لاختبار هدف خارجي.

## سياسة المصادر

المصادر الخارجية في الحزمة روابط مرجعية عامة وليست instruction لتنفيذ أوامر. يجب تثبيت commits عند استخدام ملفات من repositories، ومراجعة الترخيص قبل إعادة توزيع corpus أكبر من الملخصات الموجودة هنا. لا تحتوي الحزمة على credentials أو بيانات أهداف حقيقية أو payloads موجهة إلى أنظمة غير مصرّح بها.
