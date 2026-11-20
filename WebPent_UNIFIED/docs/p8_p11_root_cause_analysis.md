# تحليل السبب الجذري لفشل P8–P11

**المشروع:** WebPent v61/v72

**النطاق:** التحليل مبني على تشغيلات محلية مصرح بها فقط، وعلى artifacts المسجلة في المستودع. لا يعتبر أي finding Pending ثغرة مؤكدة، ولا يحول اختبارات العقود أو fixtures إلى إثبات حي.

**القرار الحالي:** `NOT_QUALIFIED` للترقية إلى `VIP_QUALIFIED`، مع حالة هندسية عملية `ENGINEERING_READY`.

## الخلاصة التنفيذية

الفشل ليس ناتجًا عن انهيار واحد في النظام. هناك سلسلتان مستقلتان من الـblockers:

1. **P8/P10:** لا يوجد workflow حي صالح أنتج observations target-backed للـbaseline وcandidate وnegative control. لذلك توقف P8 مبكرًا قبل causal signal، ولم تبدأ P10 live benchmark أصلًا.
2. **P9:** الـruntime الأساسي يعمل، لكن الاختبار المنفذ أثبت فقط health وqueue distribution ورفض resume غير صالح. لم يُثبت valid resume أو killed-worker redelivery أو lease contention أو broker idempotency أو TLS أو live redaction/retention.
3. **P11:** فشل مقصود وصحيح في release gate؛ فحوصات الكود والهندسة مرت، لكن البوابة تضيف blockers صريحة تمنع الترقية عند غياب P9/P10 الحيّين.

```text
HEAD=48e29c3 (master == origin/master)
working_tree=?? .venv/ فقط، غير متتبع ولم يدخل commit
P8 stop_reason=baseline_observation_missing_or_unusable
P9 qualification_status=not_qualified
P10 passed=false, live_benchmark_runs=0
P11 hard_checks_passed=true, passed=false
current_promotion_state=ENGINEERING_READY
```

## مصفوفة الأسباب الجذرية

| البوابة | النتيجة الفعلية | السبب الجذري | نوع المشكلة | أثرها |
|---|---|---|---|---|
| P8 | توقف عند `baseline_observation_missing_or_unusable` | الـgeneric browser proof runner لا يملك workflow typed متوافقًا مع واجهة الـSPA المستخدمة، والـreceipt الناتج لا يمر عقد observation | فجوة تكامل/ملاءمة workflow، وليست ثغرة في الهدف | candidate وnegative control لم يُشغّلا؛ causal signal وProofBundle لم يُنشآ |
| P9 | health smoke ناجح، qualification فاشلة | تم اختبار invalid resume والـqueue فقط، دون تجربة valid capability مع crash/redelivery وlease/broker semantics | نقص evidence تشغيلية موزعة | لا يمكن إثبات الاستئناف الآمن أو exactly-once/idempotency في broker |
| P10 | blocked live | WAPTLab أعاد 403 في health-only probes، والتسجيل الطبيعي وصل إلى OTP لكن لم تتوفر هوية authenticated طبيعية؛ لم يبدأ scan | blocker بيئي/تشغيلي مصرح به | لا توجد 3 جولات benchmark حية قابلة للمقارنة |
| P11 | checks خضراء لكن `passed=false` | gate يضيف blockers ثابتة عند غياب live WAPTLab campaign وlive Docker/worker qualification | governance/release gate يعمل كما صُمم | يمنع ادعاء VIP رغم نجاح regression suite |

## P8: السبب الجذري بالتفصيل

### نقطة التوقف الأولى

`BrowserProofRunner.run()` يتحقق أولًا من صحة probes وscope والجلسة، ثم ينفذ replay للأدوار الثلاثة. بعد كل replay يستخرج observation من receipt. إذا لم تكن الحالة `completed` أو `executed`، أو لم يكن observation target-backed وreplayable، أو غابت digests الأساسية، يرجع runner مباشرةً بخطأ role-specific وينهي الجولة قبل تشغيل أي causal predicate أو verifier.[1]

القيم الفعلية كانت:

```json
{
  "candidate_and_negative_control": "not_reached",
  "causal_signal": null,
  "negative_control": null,
  "proof_bundle": null,
  "verify_seal": null,
  "replay_status": null,
  "stop_reason": "baseline_observation_missing_or_unusable"
}
```

### لماذا فشل baseline في Juice Shop

الـhandler العام ينفذ `operation=validate_input`: يبحث عن input مرئي، يملؤه بقيمة probe، ثم يتطلب submit button. أُضيف fallback ضيق للضغط على Enter، لكنه يسمح فقط بـ`input[type=search]`.[2] فحص Juice Shop الحي أظهر أن حقل البحث داخل الـSPA هو `input[type=text]` تابعًا لـ`APP-MAT-SEARCH-BAR` وله semantics خاصة بالواجهة، وليس `input[type=search]` قياسيًا ولا form submit تقليديًا. لذلك فإن توسيع fallback لكل text input سيخاطر بإرسال بيانات إلى account-like أو forms غير مقصودة، ويكسر مبدأ fail-closed.

إذًا السبب الدقيق هو **عدم توافق abstraction العامة `validate_input` مع event semantics الخاصة بـJuice Shop**، وليس أن Juice Shop أثبت أو نفى ثغرة. كما أن ظهور `TargetClosedError` في بعض مسارات الـharness يمثل ضوضاء lifecycle/cleanup ثانوية؛ الحكم الرسمي ظل fail-closed ولم يحولها إلى proof.

حتى لو تم تجاوز baseline، فـP8 لا ينجح تلقائيًا. يجب أن تتغير observations target-backed بين baseline وcandidate، وأن يكون negative control مستقلًا، وأن يظهر non-dialog causal delta، ثم ينجح verifier في provenance وscope وidentity وseal وreplay.[3]

### ما لا يصح اعتباره إصلاحًا

لا يصح تحويل كل `input[type=text]` إلى submit-on-Enter، ولا اعتبار تغير DOM أو ظهور dialog وحده causal signal، ولا ترقية API hypothesis إلى confirmed بسبب اسم path. الإصلاح الصحيح هو workflow typed خاص بالـSPA، يحدد selector/event semantics وexpected safe query، ويعيد network/DOM receipts bounded؛ وبعد ذلك فقط تُترك البوابات الصارمة لتقرر إن كان الدليل كافيًا.

## P9: السبب الجذري بالتفصيل

### ما نجح فعلًا

تم إثبات أن API وRedis وworkerين يعملون، وأن رسائل `resume_pentest_task` وُزعت على العاملين، وأن invalid/missing capability رُفضت قبل target I/O. كما نجح probe منفصل لاحتكار SQLite ledger عبر عمليتين، ونجح controlled restart للعامل.

### لماذا ظهرت PermissionError

ظهور أربع حالات `FAILURE` بنوع `PermissionError` ليس bug في الحماية. `resume_pentest_task()` يقرأ سجل الـscan، ثم يمرر capability إلى `verify_resume_capability_detailed()`. عند غياب capability أو عدم معرفة thread أو فشل signature/timestamp/binding، يرفع `ResumeCapabilityDeniedError` مع reason code آمن قبل إعادة بناء workspace أو الوصول إلى target.[4] هذا يثبت **الرفض الآمن** فقط، وليس النجاح في resume.

### الأدلة الناقصة التي تمنع P9

| الاختبار المطلوب | الحالة الحالية | لماذا لا يكفي الموجود |
|---|---:|---|
| valid signed resume | غير مثبت | كل dispatch الحي كان invalid/missing |
| checkpoint ثم resume | غير مثبت | لم تُستأنف مهمة harmless من checkpoint حقيقي |
| killed-worker redelivery | غير مثبت | controlled restart ليس قتلًا أثناء تنفيذ task مع redelivery |
| two-worker lease contention | غير مثبت | queue distribution لا يثبت أن lease واحدًا فقط فاز |
| broker-level idempotency | غير مثبت | SQLite ledger probe target-free وليس Redis/Celery broker proof |
| retry exhaustion وDLQ | غير مثبت live | policy وDLQ metadata موجودان، لكن `webpent_dlq_qualified=false` |
| TLS | غير مثبت | Redis يعمل بــplaintext lab override و`tls_enforced=false` |
| live log redaction/retention | غير مثبت | توجد contract classes، لا evidence تشغيلية promoted |

إعدادات مثل `task_acks_late=True` و`worker_prefetch_multiplier=1` و`task_reject_on_worker_lost=True` مفيدة كأساس reliability، لكنها declarations/configuration وليست برهانًا على سلوك broker تحت crash.[5]

## P10: السبب الجذري بالتفصيل

WAPTLab تم التواصل معه محليًا فقط. في ثلاث جولات health-only، أعادت `/health` و`/` و`/login` الحالة `403` مع نتائج متطابقة. المتصفح الطبيعي وصل إلى registration/OTP، لكن لم تتوفر هوية authenticated طبيعية، ولم يُستخدم bypass، ولم يبدأ scan. لذلك فشل P10 عند prerequisite availability/authenticated workflow، لا عند precision أو recall.

الـartifact الحالي يخلط نوعين يجب فصلُهما ذهنيًا:

| النوع | ما يثبته |
|---|---|
| health-only runtime probe | الهدف المحلي موجود لكنه يحجب المسارات المطلوبة بـ403 |
| `waptlab_qualification_report.json` | ملخص fixture/mock من ثلاث جولات؛ لا يثبت target contact أو live campaign |

الـbenchmark نفسه يشترط أن تكون كل runs `findings_are_live` حتى يصبح `live_qualification_proven=true`.[6] كما أن P10 يحتاج ثلاث جولات مستقلة، وكل finding قابلًا للتتبع إلى target-backed observations وcausal signal وnegative control وsealed/replayable ProofBundle. لا توجد حاليًا أي live benchmark run مكتملة (`live_benchmark_runs=0`).

الـ403 لا يجوز تجاوزه بتعديل WAPTLab أو bypass OTP/CAPTCHA/MFA أو قراءة database/mail internals. المسار الصحيح هو هوية lab-provisioned أو إدخال طبيعي للكود عبر خطوة user-controlled، ثم إعادة benchmark مع artifacts منفصلة.

## P11: السبب الجذري بالتفصيل

P11 ليس فشلًا في compile أو test أو lint. الـartifact يثبت أن `compileall` وRuff وfull pytest وG-02 وrelease-manifest verification مرت، وأن `hard_checks_passed=true`. مع ذلك، `passed=false` لأن `_build_gate_report()` يضيف صراحةً blockerين عند غياب live WAPTLab campaign وworker/live Docker qualification.[7]

هذا السلوك صحيح من منظور governance؛ لو تحولت P11 إلى passed بمجرد نجاح الاختبارات المحلية، لأمكن إصدار VIP دون P8/P9/P10 target-backed evidence. لذلك يجب عدم إزالة blockers من gate كحل شكلي، وعدم تغيير `VIP_QUALIFIED` يدويًا.

## ترتيب الإصلاحات المطلوب

### الأولوية 1: إغلاق P8 بطريقة typed وليست generic

أنشئ adapter/workflow خاصًا بواجهة SPA المصرح بها، لا fallback عامًا لكل text input. يجب أن يحدد selector موثقًا، event action محددًا، probe values ephemeral، وnetwork/DOM receipt bounded. شغّل baseline وcandidate وnegative control على نفس engagement مع request digests مختلفة، ثم مرر النتائج إلى verifier المركزي. النجاح لا يُعلن إلا بعد `verify_seal()` وreplay.

### الأولوية 2: تنفيذ P9 positive distributed test

أنشئ task harmless target-free يكتب checkpoint bounded، ثم اختبر valid signed capability، resume، قتل worker أثناء التنفيذ، redelivery، lease contention بين عاملين، broker idempotency، retry exhaustion/DLQ، وredaction/retention. يجب توثيق Redis TLS في profile qualification منفصل؛ plaintext override يظل lab smoke فقط.

### الأولوية 3: توفير P10 authenticated lab identity طبيعيًا

لا تعدّل WAPTLab ولا تتجاوز OTP. استخدم lab-provisioned identity أو أكمل الإدخال الطبيعي عبر user-controlled browser step. بعد توفر الهوية، شغّل ثلاث جولات مع seed/image digest/target fingerprint/artifacts مستقلة، واحتفظ بكل finding Pending ما لم يمر proof contract كاملًا.

### الأولوية 4: إعادة P11 بعد إغلاق dependencies

بعد نجاح P8 live proof وP9 distributed qualification وP10 three-run benchmark، أعد تشغيل gate بالكامل ثم تحقق من manifest النهائي. لا يكفي أن تصبح checks الخضراء أكثر عددًا؛ يجب أن تختفي blockers live من مصدرها وبأدلة مستقلة قابلة للمراجعة.

## القرار النهائي

المشروع حاليًا قوي هندسيًا في fail-closed contracts والـoffline regression، لكنه ليس Autonomous Bug Hunter مؤهلًا بدرجة VIP. السبب الرئيسي ليس قلة عدد الـfindings؛ بل غياب سلسلة إثبات حي مكتملة وقابلة للإعادة. **P8 متوقف عند adapter/workflow mismatch، P9 ناقصه distributed positive evidence، P10 متوقف عند availability/auth identity، وP11 يمنع الترقية عمدًا حتى تُغلق P8–P10.**

## المراجع

[1]: https://github.com/ElgendyMan/webpent-v61/blob/master/src/webpent/shared/browser_proof_runner.py "BrowserProofRunner strict observation gate"

[2]: https://github.com/ElgendyMan/webpent-v61/blob/master/src/webpent/shared/playwright_adapter.py "Playwright validate_input handler"

[3]: https://github.com/ElgendyMan/webpent-v61/blob/master/src/webpent/shared/verifier.py "Central replay, seal, provenance, and proof verification"

[4]: https://github.com/ElgendyMan/webpent-v61/blob/master/src/webpent/workers/pentest_worker.py "Celery resume_pentest_task and fail-closed capability denial"

[5]: https://github.com/ElgendyMan/webpent-v61/blob/master/src/webpent/workers/observability.py "Reliability policy and live qualification boundary"

[6]: https://github.com/ElgendyMan/webpent-v61/blob/master/src/webpent/benchmark/qualification.py "Benchmark live qualification aggregation"

[7]: https://github.com/ElgendyMan/webpent-v61/blob/master/scripts/run_vip_quality_gate.py "VIP release gate blocker logic"

[8]: https://github.com/ElgendyMan/webpent-v61/blob/master/docs/p8_p11_execution_evidence.json "P8–P11 execution evidence artifact"

[9]: https://github.com/ElgendyMan/webpent-v61/blob/master/docs/p9_distributed_runtime_evidence.json "P9 distributed runtime evidence artifact"

[10]: https://github.com/ElgendyMan/webpent-v61/blob/master/docs/p10_benchmark_gate.json "P10 benchmark gate artifact"

[11]: https://github.com/ElgendyMan/webpent-v61/blob/master/docs/vip_quality_gate.json "P11 VIP quality gate artifact"

---

**المؤلف:** Manus AI

**ملاحظة:** هذا التقرير تحليل فقط؛ لم يتم تعديل source أو تشغيل scan جديد أثناء إعداده.
