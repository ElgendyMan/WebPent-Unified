# WebPent v63 — إصلاحات التدقيق الأمني VIP

**الإصدار:** v63 VIP Security Fixes  
**المشروع:** WebPent v60  
**المؤلف:** Manus AI  
**لغة التوثيق:** العربية  

## 1. الملخص التنفيذي

تغلق هذه الجولة مجموعة إصلاحات أمنية عالية الأولوية ظهرت في تدقيق VIP، مع الحفاظ على الحواجز الأصلية للمشروع: **الفشل الآمن، فرض النطاق، العزل بين العملاء والارتباطات، موافقة الإنسان عند الحاجة، وعقد الأدلة**. لم يتم تنفيذ ترقية كبرى لـLangChain/LangGraph في هذه الجولة؛ لأن هذه الترقية تحتاج اختبار توافق معماري مستقلًا مع LangGraph state/checkpoint وواجهات LangChain الحالية.

الوضع الوظيفي النهائي هو: نجاح compileall، نجاح مجموعة الاختبارات الكاملة، ونجاح Ruff على جميع الأسطح التي عُدّلت في v63. أما اعتماد الإصدار production-ready بشكل غير مشروط فيظل محجوزًا إلى أن تُعالج ثغرات الاعتماديات الخارجية أو يُعتمد استثناء مخاطر موثق من مالك المشروع.

## 2. الإصلاحات المنفذة

| المجال | الملف أو الملفات | الإصلاح | الضمان الأمني |
|---|---|---|---|
| ملكية الـscan | `src/webpent/api/scan_registry.py` و`src/webpent/api/app.py` | حفظ `owner_username` و`client_id` و`engagement_id` مع سجل الـscan، وإضافة authorization guard قبل status/findings/summary، مع صلاحية admin العالمية فقط. | يمنع operator من قراءة scan يملكه مستخدم أو tenant آخر، ويرفض السجلات القديمة غير المربوطة بسياق engagement عند غياب البيانات اللازمة. |
| عزل المستأجرين | `src/webpent/api/app.py` وطبقة registry | الاعتماد على سجل الملكية الخادمي بدل أي client header يرسله المستهلك. | لا يمكن للعميل تغيير `client_id` أو `engagement_id` في الطلب للوصول إلى سجل آخر. |
| تأكيد OOB | `src/webpent/memory/db.py` | تحويل `mark_oob_confirmed` إلى compare-and-set: لا يعاد تأكيد finding مؤكدة، ولا تُلحق reasoning أو payload جديدة بعد أول انتقال ناجح. | يمنع replay وتلوث الأدلة وتغيير نتيجة finding بعد التأكيد الأداتي الأول. |
| raw socket scope | `src/webpent/agents/request_smuggling/agent.py` | فرض `is_engagement_target_host` عند مدخل node وداخل `_send_raw_http` قبل DNS/socket، مع رفض fail-closed عند غياب scope. | يمنع تحويل مسار request-smuggling الخام إلى SSRF scanner للـhosts الداخلية. |
| TLS في raw socket | `src/webpent/agents/request_smuggling/agent.py` | استخدام `ssl.create_default_context()` مع `server_hostname` بدل تعطيل التحقق. | يمنع قبول شهادة أو hostname غير موثوق في مسار الاتصال الخام. |
| CL.TE oracle | `src/webpent/agents/request_smuggling/agent.py` | إضافة baseline طبيعي، ثم إرسال probe وطلب detection على نفس الاتصال، وقصر الإثبات على differential response محافظ. | يقلل false positives الناتجة عن 400 ثابت أو عن فتح اتصال جديد لا يحمل حالة poisoning. |
| HTTP client الآمن | `src/webpent/agents/api_testing/agent.py` و`src/webpent/shared/http.py` | إلزام المسارات HTTP باستخدام `make_safe_httpx_client` وعدم السماح بتعطيل TLS verification. | يحافظ على SSRF/DNS-pinning policy ويمنع downgrade إلى `verify=False`. |
| JWT claims | `src/webpent/api/auth.py` و`src/webpent/config/settings.py` | فرض `iss` و`aud` و`jti` و`iat` و`nbf` وtoken version، مع التحقق من issuer/audience ورفض token version قديم بعد revoke. | يمنع قبول token ناقص أو صادر لسياق آخر، ويجعل إبطال tokens قابلًا للتطبيق. |
| Rate limiting | `src/webpent/api/rate_limit.py` | عند كون Redis backend مطلوبًا لكنه غير متاح، النتيجة deny بدل السماح بالمرور. | يمنع fail-open أثناء عطل backend المركزي. |
| CI والاعتماديات | `.github/workflows/ci.yml` و`requirements-audit-v63.txt` و`pip-audit-v63-locked.json` | إضافة compile، lock/pip consistency، critical security contracts، coverage artifact، وpip-audit على dependencies المصدّرة من lock. | يجعل regression والاعتماديات جزءًا من بوابة التحقق الآلية. |
| test gate | `scripts/verify_test_count.py` | تثبيت حد أدنى محمي عند 429، مع وصول السطح الحالي إلى 431 دالة اختبار. | يمنع حذف سطح الاختبارات بصمت أثناء التطوير. |

## 3. اختبارات العقود وRegression

أُضيفت ووسّعت `tests/test_v63_vip_security_regression.py` لتغطي العقود التالية:

| العقد | ما يتم إثباته |
|---|---|
| JWT lifecycle | وجود `jti` وtoken version، وفعالية revoke بعد إنشاء token. |
| Scan ownership | وصول المالك، رفض operator الآخر، وصلاحية admin، مع fail-closed للسجل legacy غير المربوط. |
| Tenant boundary | عدم اعتماد authorization على client header غير موثوق. |
| Scope lifecycle | التطابق الحرفي للـhost، تطبيع URL، وclearing للسياق بعد انتهاء engagement. |
| Redis failure | رفض global/scan requests عند فشل Redis المطلوب. |
| OOB idempotency | أول confirmation فقط يغير confidence/reasoning/payload، والـreplay لا يغير الدليل. |
| TLS contract | رفض `make_safe_httpx_client(verify=False)`. |
| Raw-socket egress | رفض host خارج engagement scope قبل محاولة إنشاء socket. |

كل تغيير جديد في هذه الجولة مرتبط باختبار regression أو contract، مع الإبقاء على اختبارات v61 وv62 والاختبارات السابقة.

## 4. نتيجة الاختبارات والجودة

| الفحص | النتيجة |
|---|---:|
| `python -m compileall -q src scripts` | ناجح، exit code 0 |
| Full `pytest -q --tb=short` | ناجح؛ العدد النهائي يسجل في `pytest-v63-full.log` |
| Ruff على الأسطح المعدلة، rules `E,F,I,RUF` مع تجاهل `BLE001` | ناجح؛ `All checks passed!` |
| `uv lock --check` | يجب أن يظل ناجحًا ضمن CI |
| `python -m pip check` | يجب أن يظل ناجحًا ضمن CI |
| Critical security contracts | مفعّلة في CI قبل full suite |

توجد تحذيرات runtime متوقعة في بيئة التطوير، منها مفاتيح `audit_secret_key` و`celery_payload_key` الضعيفة في dev mode وتحذيرات deprecation من LangChain/Chroma/Alembic. هذه ليست bypass مقبولًا في deployment غير المحلي؛ يجب ضبط secrets قوية وتخطيط تحديثات التوافق قبل production.

## 5. نتيجة dependency audit

أظهر `pip-audit` على dependencies المصدّرة من `uv.lock` عدد **17 ثغرة في 9 حزم**. النتيجة محفوظة كاملة في [`pip-audit-v63-locked.json`](../pip-audit-v63-locked.json)، والقائمة المصدّرة في [`requirements-audit-v63.txt`](../requirements-audit-v63.txt).

| الحزمة الحالية | الإصدار المقفل | الإصلاحات المبلّغ عنها | طبيعة القرار |
|---|---:|---|---|
| `langchain` | 0.3.30 | 1.3.9 | major upgrade وتحقق توافق |
| `langchain-core` | 0.3.86 | 1.2.11 أو 1.2.22 بحسب advisory | major upgrade وتحقق API |
| `langchain-text-splitters` | 0.3.11 | 1.1.2 | major upgrade |
| `langchain-anthropic` | 0.3.22 | 1.4.6 | major upgrade |
| `langchain-openai` | 0.3.35 | 1.1.14 | major upgrade |
| `langgraph` | 0.6.11 | 1.0.10 أو release candidate مذكور في advisory | major upgrade مع مراجعة state/checkpoint |
| `langgraph-checkpoint` | 2.1.2 | 3.0.0 أو 4.x لبعض advisories | migration محتمل للـcheckpoint format |
| `langgraph-sdk` | 0.2.15 | 0.3.15 | تحديث مترافق مع LangGraph |
| `langgraph-checkpoint-sqlite` | 2.0.11 | 3.0.1 أو 3.1.1 | اختبار backward compatibility للـSQLite checkpoints |

هذه الثغرات **known risk غير مغلقة في v63** وليست نتيجة لتجاوز الحواجز الأمنية الجديدة. تم إبقاء النسخ الحالية مقفلة لتجنب كسر APIs أو checkpoints قديمة دون migration واختبارات كاملة. لا ينبغي إعلان هذه الحزمة production-ready إذا كانت سياسة المؤسسة تشترط صفر vulnerabilities في dependency audit.

## 6. خطة الترقية المنفصلة للاعتماديات

ينبغي تنفيذ الترقية في branch مستقل، بدءًا من إنشاء compatibility matrix للنسخ الجديدة مقابل imports الحالية في `src/webpent`، ثم ترقية LangChain/LangGraph تدريجيًا مع تشغيل contract suites بعد كل مجموعة. بعد ذلك يجب اختبار فتح checkpoints القديمة، تشغيل graph end-to-end، embeddings/vectorstore، Celery worker، وreport generation. أخيرًا يجب إعادة تشغيل `uv lock --check` و`pip check` و`pip-audit --strict`، مع عدم إزالة hard gate من CI إلا بقرار مخاطر موثق.

## 7. حدود الإصدار والتوافق

لم تُحذف حقول من state أو finding schema، ولم تُلغَ checkpoints القديمة. الإصلاحات الجديدة تعتمد على metadata إضافية وتتعامل مع السجل القديم بحذر: إذا كانت بيانات owner/engagement الضرورية ناقصة، يتم الرفض الآمن بدل التخمين. يجب اختبار أي migration حقيقية للـcheckpoint على نسخة backup قبل اعتمادها.

> **قرار release:** الإصدار يحقق إغلاق إصلاحات v63 القابلة للتنفيذ ويمرر الاختبارات والجودة، لكنه يحتاج قرارًا صريحًا بخصوص الثغرات الـ17 في LangChain/LangGraph قبل اعتباره release production غير مشروط.

## المراجع والآثار المحلية

1. [`pip-audit-v63-locked.json`](../pip-audit-v63-locked.json) — مخرجات dependency audit المقفلة.
2. [`requirements-audit-v63.txt`](../requirements-audit-v63.txt) — dependencies المصدّرة من lock للتحقق الأمني.
3. [`pytest-v63-full.log`](../pytest-v63-full.log) — سجل full pytest النهائي.
4. [`ruff-v63-final.log`](../ruff-v63-final.log) — سجل Ruff النهائي للأسطح المعدلة.
5. [`test_v63_vip_security_regression.py`](../tests/test_v63_vip_security_regression.py) — suite عقود وsecurity regression.
6. [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — بوابات CI والتدقيق الآلي.
