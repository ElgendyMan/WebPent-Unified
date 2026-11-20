# WebPent LLM Production Readiness Review

**التاريخ:** 2026-08-21

**النطاق:** تدقيق تكامل مزودي ونماذج LLM المختلفة، توافق adapters، fallback، circuit breaker، doctor، prompt boundaries، وإعدادات OpenAI-compatible/local.

## الحكم المختصر

التكامل أصبح **جاهزًا من ناحية التصميم البرمجي والـfailure isolation** لاستخدام نماذج مختلفة، بشرط أن يضبط المشغّل `model` و`base URL` وAPI key الخاصة بالمزوّد نفسه، وأن يمرّر provider عبر `scripts/doctor.py` قبل qualification. لا يمكن إثبات أن كل provider خارجي يعمل فعليًا من داخل هذه البيئة لأن مفاتيح هذه الخدمات غير متاحة، ولا يجوز اعتبار نجاح بناء client أو وجود مفتاح وحده إثباتًا لصحة endpoint/model.

النتيجة الأهم هي أن فشل LLM لم يعد سببًا مقبولًا لاختراع Finding أو كسر المسح كله: provider الذي يفشل أثناء `invoke` يُسجّل في circuit breaker عند أخطاء الحالة الدائمة، ويُترك الاستثناء للـfallback chain، وتظل النتيجة deterministic عندما يدعمها الـnode. أمّا النص الذي ينتجه النموذج فليس evidence ولا يرقّي Finding وحده.

> لا توجد آلية آمنة أو مقبولة لتجاوز guardrails الخاصة بمزوّد LLM. تم تحسين prompt boundaries لتقليل prompt injection وجعل البيانات الخارجية غير موثوقة، وليس لتجاوز حماية النموذج أو إخفاء محتوى عن مزوّده.

## الإصلاحات المنفذة

| المجال | ما تم إصلاحه | الأثر التشغيلي |
|---|---|---|
| Provider invoke failure | إضافة `_ProviderGuardedRunnable` لتسجيل أخطاء `invoke` و`ainvoke` مع إبقاء exception متاحًا لـ`with_fallbacks` | فشل المفتاح أو quota أو model error لا يبقى مخفيًا داخل cache، والـfallback يستمر |
| Circuit breaker | trip فقط عند status codes حقيقية مثل 400/401/403/404/429، وعدم الاعتماد على substring داخل نص الخطأ | تقليل false positives، مع عدم تعطيل provider مؤقتًا بسبب 5xx عابر |
| Cloudflare adapter | تمرير `request_timeout`, `max_tokens`, و`max_retries=0` إلى الحقول الفعلية للـadapter | منع silently-ignored configuration في هذا provider |
| OpenAI-compatible | دعم `OPENAI_BASE_URL` وalias `OPENAI_API_BASE`، و`OPENAI_MODEL` | تشغيل OpenAI أو endpoint متوافق مع نفس adapter مع model قابل للضبط |
| Local endpoint | دعم `LOCAL_LLM_ENABLED`, `LOCAL_LLM_URL`, `LOCAL_LLM_MODEL`، وإدخاله opt-in في نهاية fallback chains | لا توجد اتصالات local افتراضيًا ولا latency غير مقصودة |
| Doctor | جعل الفحص يستخدم نفس router/model/base-url overrides، ورفض أي رد غير `OK` صريح، وإصلاح hard timeout الذي كان ينتظر thread المعلّق | doctor لا يعلن provider healthy بسبب `not ok` أو prose عشوائي، ولا يضلل المستخدم بشأن timeout |
| Preflight | إظهار resolved fallback chains و`effective_endpoints` بدون secrets | رؤية model/endpoint الفعليين قبل التشغيل |
| Prompt safety | تغليف بيانات الهدف ونتائج الأدوات كـuntrusted data، ومعالجة encoded/nested/homoglyph tags وJSON escaping | تقليل قدرة البيانات غير الموثوقة على تغيير system boundary |
| Documentation | تحديث README و`.env.example` بأسماء الإعدادات الفعلية وشرح fallback والحدود | تقليل أخطاء التشغيل الناتجة عن إعداد legacy غير مستخدم |

## الـprompts وحدود الثقة

تمت مراجعة طبقة prompt المركزية ومسارات planner وbusiness-impact وreporter. المسار الصحيح هو أن system instruction ثابتة، بينما target data وtool output وRAG context تدخل كبيانات غير موثوقة. تم إضافة regression للـencoded tags والـnested payloads والـhomoglyphs، مع الحفاظ على النص العربي وعدم تحويل محتوى LLM إلى evidence.

هذه الضوابط لا تعني أن النموذج سيطيع كل prompt أو أن provider مختلفًا سيعيد نفس الصيغة. النموذج قد يرفض الطلب، قد يعيد نصًا بدل JSON، أو قد يعيد JSON ناقصًا. لذلك يجب أن يظل parsing fail-closed، وأن يظل deterministic fallback هو المسار النهائي عند فشل التحليل. لا تتم ترقية Finding إلا بسلوك فعلي، و`causal_signal`، و`negative_control`، وعقود الأدلة القائمة في WebPent.

## إعداد provider أو model مختلف

يستخدم المشغّل الإعدادات التالية في `.env`، ولا يجوز نسخ اسم model من provider إلى provider آخر دون الرجوع إلى catalog الخاص بالمزوّد:

```dotenv
# OpenAI أو endpoint متوافق
OPENAI_API_KEY=replace_me
OPENAI_BASE_URL=https://api.openai.com/v1
# alias متوافق أيضًا: OPENAI_API_BASE
OPENAI_MODEL=

# Ollama أو خادم OpenAI-compatible محلي، مع تفعيل صريح
LOCAL_LLM_ENABLED=false
LOCAL_LLM_URL=http://localhost:11434/v1
LOCAL_LLM_API_KEY=local-runtime
LOCAL_LLM_MODEL=llama3.1:8b

LLM_REQUEST_TIMEOUT=60
LLM_MAX_TOKENS=4096
```

عند استخدام endpoint خارجي، يجب أن يكون `OPENAI_BASE_URL` هو endpoint الحقيقي وأن يكون `OPENAI_MODEL` مدعومًا فيه. وعند استخدام local، يجب تفعيل `LOCAL_LLM_ENABLED=true` فقط بعد التأكد أن الخادم يستجيب وأن اسم النموذج محمّل. إذا فشل local، لا ينبغي أن يوقف cloud fallback chain، والعكس صحيح.

## الاختبارات المنفذة

| الاختبار | النتيجة |
|---|---:|
| اختبارات LLM المركزة، doctor، prompt boundaries، router، cache، preflight | 23 passed |
| اختبارات المشروع الكاملة | **1120 passed, 0 failures** |
| Ruff على المشروع كله | **نجح، 0 errors** |
| compileall على `src` و`scripts` | **نجح** |
| `git diff --check` | **نجح** |
| provider failure أثناء invoke مع fallback | **مثبت بـregression** |
| circuit breaker عند status code حقيقي | **مثبت بـregression** |
| OpenAI/local endpoint وmodel overrides | **مثبت بدون network** |
| OpenAI API base alias | **مثبت بـregression** |
| doctor: `not ok` لا يساوي نجاحًا | **مثبت بـregression** |
| prompt boundary مع encoded/nested/homoglyph input | **مثبت بـregression** |

## نتيجة doctor في البيئة الحالية

تم تشغيل doctor الحقيقي بدون اختلاق credentials. النتيجة كانت أن معظم providers `MISSING_KEY`، بينما provider المسجّل له مفتاح البيئة فشل في invoke بسبب model غير مدعوم في الـproxy الحالي. لذلك لا يوجد provider حي مثبت في هذه البيئة، ولا يجوز استخدام هذه النتيجة لإعلان أن كل external provider جاهز.

هذا ليس فشلًا في deterministic scan path؛ لكنه يعني أن LLM enrichment يحتاج provider key وmodel/base URL صحيحين قبل qualification. بعد وضع credentials حقيقية لمزوّد معين، يجب تشغيل:

```bash
PYTHONPATH=src python scripts/doctor.py --json
```

ولا تعتبر provider جاهزًا إلا إذا ظهر `ACTIVE` في doctor ونجح invoke الحقيقي. إذا ظهر `FAILING`، صحّح model أو endpoint أو quota بدل تعطيل guardrails أو تحويل الخطأ إلى نتيجة.

## ما تم إثباته وما لم يتم إثباته

| البند | الحالة |
|---|---|
| اختلاف model/provider لا يكسر router عند غياب المفتاح أو فشل invoke | مثبت باختبارات محلية |
| fallback لا يتوقف عند provider failure | مثبت باختبار invoke-time |
| prompt boundaries تعزل البيانات غير الموثوقة | مثبت ضمن الحالات المختبرة |
| كل provider خارجي يعمل بمفتاح حقيقي | غير مثبت؛ لا توجد credentials لكل provider |
| كل model ID في preference tables صالح دائمًا | غير مضمون؛ catalog المزوّد يتغير ويجب التحقق بالـdoctor |
| Structured output متطابق بين كل providers | غير مضمون؛ يجب أن يقبل parser الفشل ويستخدم fallback |
| تجاوز حماية LLM | غير مطلوب وغير مدعى؛ لا يتم تجاوز guardrails |
| أن LLM وحده سيزيد عدد findings أو يؤكدها | غير مضمون؛ evidence pipeline deterministic وLLM advisory |

## توصية التشغيل

قبل production، انسخ `.env.example` إلى إعداد سري خارج Git، ضع مفاتيح أقل صلاحية ممكنة، اضبط model/base URL لكل provider، وشغّل doctor في نفس environment الذي سيشغّل scan. استخدم `LLM_ENABLED=false` في offline qualification إذا كان المطلوب اختبار deterministic path، ولا تعتبر وجود API key أو نجاح إنشاء client confirmation كافية.

النسخة الحالية **production-ready من ناحية التوافق والـfallback والحدود الأمنية البرمجية**، مع بقاء qualification الحي لكل provider مسؤولية deployment-specific لا يمكن ادعاؤها مسبقًا.
