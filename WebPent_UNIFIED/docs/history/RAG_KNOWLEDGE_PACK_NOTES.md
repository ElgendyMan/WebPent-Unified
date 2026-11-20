# RAG Knowledge Pack Delivery Notes

## ما تم إضافته

تمت إضافة corpus محلي منظم تحت `knowledge_pack/` بخمسة أنواع: methodology وrepository وreport وwriteup وscenario. يتضمن corpus ملخصات مراجَعة وروابط عامة إلى OWASP WSTG وNIST SP 800-115 وOWASP ASVS وPortSwigger Web Security Academy وrepositories مثل PayloadsAllTheThings وSecLists وnuclei-templates، بالإضافة إلى سيناريوهات BAC/IDOR وSQLi وXSS وSSRF وGraphQL مخصصة للـlabs المصرح بها.

## طريقة الإدخال

الـmanifest الافتراضي `knowledge_sources.yaml` أصبح يشير إلى الملفات المحلية. كما يوجد manifest مستقل `knowledge_pack/manifest.yaml` للتشغيل المحدود:

```bash
PYTHONPATH=src python scripts/ingest_payloads.py \
  --manifest knowledge_pack/manifest.yaml \
  --dry-run

PYTHONPATH=src python scripts/ingest_payloads.py \
  --manifest knowledge_pack/manifest.yaml \
  --chunk-size 900 \
  --chunk-overlap 90
```

المسار يرفض absolute paths وpath traversal، ويضيف `source_id` و`source_url` و`source_path` و`type` و`category` و`stack` و`trust_note`. إعادة الإدخال idempotent حسب `source_id`؛ إعادة التشغيل التحققية أعادت `Fetched: 5`, `Ingested: 0`, `Chunks: 0` بعد أن كانت أول عملية قد أضافت **10 chunks** بلا failures.

## الاستدعاء الفعلي

`webpent.shared.knowledge_retrieval.retrieve_knowledge_context` يستدعي Chroma لكل نوع بشكل bounded، يزيل التكرار، يضع markers للـtype/provenance، ويقص الناتج إلى حد أقصى قبل إدخاله داخل safe prompt boundary. الـplanner يستدعي methodology وrepository وscenario، والـhypothesis analyzer يستدعي writeup وreport وscenario مع الأنواع الإضافية الموجودة في المسار القديم.

تم تشغيل `scripts/verify_rag_knowledge_pack.py` بعد الإدخال. كل نوع أعاد **2 direct hits**، وظهر marker النوع داخل helper context:

| النوع | Direct hits | Helper context | Marker |
|---|---:|---:|---|
| methodology | 2 | 1178 حرفًا | نعم |
| repository | 2 | 1177 حرفًا | نعم |
| report | 2 | 1169 حرفًا | نعم |
| writeup | 2 | 1171 حرفًا | نعم |
| scenario | 2 | 1173 حرفًا | نعم |

النتيجة الخام محفوظة في `artifacts/rag_knowledge_pack_verify.json`.

## حدود الأمان

المحتوى Advisory فقط ولا يثبت vulnerability ولا يرفع candidate إلى confirmed. كل finding ما زال يتطلب behavior فعليًا وcausal signal وnegative control وevidence قابلًا لإعادة الإنتاج. لا يتم تشغيل تعليمات أو scripts من الـRAG لمجرد استرجاعها، ولا توجد credentials أو target responses داخل الحزمة. لم يتم تعديل WAPTLab أو Juice Shop.
