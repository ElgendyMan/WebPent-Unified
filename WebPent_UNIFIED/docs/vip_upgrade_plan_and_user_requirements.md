# خطة ترقية WebPent من NOT_QUALIFIED إلى VIP_QUALIFIED

**النطاق:** WebPent يعمل على أهداف single-target مصرح بها، مع Juice Shop المحلي كهدف التحقق الأساسي، وWAPTLab كمسار منفصل لا يدخل في أدلة Juice Shop.
**القاعدة الحاكمة:** لا يتم إعلان `VIP_QUALIFIED` إلا بعد نجاح P8 وP9 وP10 وP11 بأدلة حية قابلة للتحقق وإعادة التشغيل. الـmocks والـunit tests والـsuccessful proof الواحد لا تكفي وحدها.

## 1. نقطة البداية الحالية

المشروع في حالة قوية هندسيًا، لكن ليس مؤهلًا رسميًا. طبقة TargetSpec والـscope والـCLI والـProofBundle والـdynamic gate موجودة، وP8 مثبتة لنطاق Juice Shop search workflow محدد. أما P9 فما زالت تنقصها متطلبات distributed production-like، وP10 ما زالت تفتقد benchmark مستقلًا واسعًا مع ground truth وmetrics. لذلك فإن الترقية المطلوبة ليست إعادة بناء المشروع، بل **إغلاق فجوات الأدلة والتشغيل والقياس**.

| المجال | الحالة الحالية | ما يلزم للوصول إلى qualification |
|---|---|---|
| TargetSpec/scope safety | منفذ ومختبر | لا تغيير جوهري؛ regression ومراجعة مستقلة |
| P8 evidence | ناجح لنطاق workflow واحد | تثبيت provenance، وربط كل finding مؤكد بـcausal signal وnegative control وseal/replay |
| P9 runtime | checkpoint/redelivery/retry/DLQ مثبتة جزئيًا | إكمال الستة blockers الحية ثم إعادة التشغيل من clean environment |
| P10 benchmark | XSS workflow واحد، metrics `null` | ground truth مستقل، class/workflow coverage، 3 runs معزولة، metrics |
| P11 gate | fail-closed ويمنع الترقية | يمر فقط بعد نجاح P9 وP10 ثم independent review |

## 2. قرار البنية التحتية المطلوبة

متطلبات P9 تشمل Docker/Redis/Celery وTLS وbackup/restore وعمليات workers. لذلك يلزم تشغيل طويل ومضبوط، وليس الاعتماد على sandbox مؤقت لجلسة واحدة. يوجد مساران عمليان:

| الخيار | المزايا | المقابل | التكلفة/المتطلبات |
|---|---|---|---|
| تشغيل على جهاز محمد المحلي | أقل تكلفة، مناسب للاب محلي حساس، تحكم كامل في Docker والشبكة | الجهاز يجب أن يظل متاحًا أثناء التجارب، ولا توجد خدمة 24/7 مستقلة | بدون تكلفة إضافية؛ Docker Compose وRedis TLS وشهادة محلية |
| خادم Ubuntu مستمر | workers وRedis والـbackup يظلون متاحين بعد انتهاء الجلسة، مناسب للتجارب المتكررة | يحتاج إدارة secrets/firewall/backup، وتكلفة شهرية | يبدأ عادة من **10 دولارات شهريًا**؛ يحتاج Docker وقرص كافٍ |

مسار WebDev المُدار أخف للتطبيقات العادية، لكنه ليس الخيار المناسب هنا إذا كان acceptance يتطلب Docker وRedis TLS وعمليات OS-level وworker processes منفصلة. لا نحتاج إلى Gmail credentials أو حسابات bug-bounty أو أهداف عامة لإغلاق هذه الخطة؛ كل الاختبارات المطلوبة يمكن تنفيذها على اللابات المحلية.

## 3. Phase P9 — Distributed Qualification

### Sprint P9.1 — Lease contention حقيقي

سيتم تشغيل عاملين أو أكثر عبر broker واحد مع task متعمد طويل بما يكفي لخلق contention حقيقي على نفس engagement/task. يجب أن يثبت artifact أن worker واحدًا فقط امتلك lease، وأن العامل الآخر لم ينفذ side effect مكررًا، وأن lease expiry/reacquisition لا يسبب duplication. يجب أن يكون الاختبار عبر مسار Celery/Broker الفعلي، لا عبر استدعاء ledger مباشرة.

**Gate P9.1:** يرفض gate أي run لا يحتوي worker identities، lease owner transitions، broker delivery identifiers المـredacted، وside-effect count قابلًا للتحقق.

### Sprint P9.2 — Broker idempotency منفصلة

يجب فصل إثبات broker-level idempotency عن SQLite idempotency. سيتم تكرار delivery أو محاكاة redelivery عبر worker crash، ثم التحقق من أن task identity أو idempotency key تمنع إعادة الأثر الجانبي. لا يجوز اعتبار checkpoint المحلي وحده إثباتًا لهذا الشرط.

**Gate P9.2:** نفس logical task ينتج side effect واحدًا فقط عبر broker redelivery، مع سجل durable لا يحتوي payload خامًا أو secrets.

### Sprint P9.3 — Redis TLS عبر `rediss://`

سيتم إنشاء profile TLS محلي بشهادة CA وشهادات server/client مخصصة للمختبر، ثم تشغيل broker والworkers عبر `rediss://`. سيتم التحقق من certificate validation، ورفض plaintext profile في وضع qualification، وتسجيل configuration fingerprint فقط دون private keys.

**Gate P9.3:** `tls_enforced=true` لا تُقبل إلا إذا فشل الاتصال عند استخدام plaintext أو certificate غير صالح، ونجح الاتصال عبر `rediss://` مع التحقق من الشهادة.

### Sprint P9.4 — Live redaction وretention

سيتم اختبار سجلات worker/broker وartifacts أثناء task ناجحة وفاشلة وretry/DLQ. يجب التأكد آليًا من عدم ظهور tokens/passwords/cookies/headers/raw bodies، ومن أن retention policy تحذف أو تُنقّي السجلات حسب مدة محددة. سيتم الاحتفاظ بالhashes والmetadata فقط.

**Gate P9.4:** secret scan على logs وartifacts + اختبار retention بعد expiry + fail-closed عند اكتشاف marker حساس.

### Sprint P9.5 — Backup/restore drill

سيتم إنشاء backup مشفّر للـledger والـqualification metadata، ثم restore في workspace معزول، والتحقق من hashes والـcheckpoint وDLQ projection وعدم وجود cross-engagement contamination. لا تُحفظ credentials أو raw target traffic في النسخة.

**Gate P9.5:** restore ينجح من backup مستقل، وتكون النتيجة deterministic ومطابقة للـhashes المتوقعة مع إثبات العزل.

### Sprint P9.6 — P9 clean-room rerun

بعد نجاح الـsprints السابقة، تُعاد التجربة من بيئة نظيفة بنفس profile وconfiguration manifest. يتم حفظ artifact واحد signed/sealed يضم كل الشروط الستة، ثم يراجعه verifier مستقل.

**Gate P9 النهائي:** كل الشروط التالية `true` في artifact واحد قابل للتحقق: `multi_worker_lease_contention`، `broker_idempotency`، `tls_enforced`، `logs_redacted`، `retention_policy_verified`، `backup_restore`.

## 4. Phase P10 — Independent Benchmark

### Sprint P10.1 — اعتماد ground truth

يتم إنشاء mapping مستقل بين challenge/case identifier في Juice Shop وبين vulnerability class وworkflow وexpected oracle. المصدر المستقل يكون metadata/catalog للاب أو ملف cases مُراجع، وليس output WebPent نفسه. يجب أن يحتوي mapping على version وhash وreviewer وscope، مع فصل واضح بين ground truth وdetector output.

### Sprint P10.2 — تحديد benchmark scope

للوصول إلى qualification قابلة للدفاع، أقترح بدء benchmark محدود لكنه متنوع، مثل **10–12 vulnerability classes/workflows** التي يمكن اختبارها بأمان محليًا، بدل الادعاء بتغطية كل catalog مرة واحدة. يمكن توسيعه لاحقًا إلى catalog كامل. كل case يجب أن يحدد precondition، safe probe، expected signal، negative control، وcleanup.

### Sprint P10.3 — ثلاث runs معزولة

يتم تشغيل ثلاث جولات مستقلة على target state معروف، مع engagement/workspace/artifact منفصل لكل جولة. لا يتم نقل cookies أو state أو findings بين الجولات. يجب تسجيل image digest وtarget fingerprint وcase-map hash وrun id فقط.

**Gate P10.3:** رفض الجولة إذا تداخلت workspaces أو تغيّر target state دون تسجيل أو لم يمكن إعادة تشغيل proof.

### Sprint P10.4 — قياس النتائج

لكل case يتم حساب TP وFP وFN، ثم:

```text
precision = TP / (TP + FP)
recall = TP / (TP + FN)
class_coverage = classes_with_valid_ground_truth_and_run / total_ground_truth_classes
```

يجب أن تكون metrics ناتجة من raw evaluation داخلي محمي، بينما artifact المنشور يحتوي aggregates وhashes فقط. الحالات غير القابلة للاختبار تُوسم `out_of_scope` ولا تُحوّل إلى نجاح أو فشل مصطنع.

**Gate P10 النهائي:** ground truth approved، ثلاث runs معزولة، proof strict لكل confirmed case، metrics غير `null`، ووجود سجل صريح للحالات missed وfalse-positive وout-of-scope.

## 5. Phase P8 — تثبيت الدليل القابل للتوسع

لن نعيد بناء P8؛ سيتم توسيع ما هو موجود بطريقة محافظة. لكل finding داخل benchmark يجب أن يوجد baseline وcandidate وindependent negative control، target-backed causal signal، central sealed ProofBundle، `verify_seal=true`، وcentral replay ناجح. يجب بقاء payloads والـraw bodies والـcookies خارج artifacts المنشورة، واستخدام digests وredacted metadata فقط.

**Gate P8 النهائي:** لا finding ينتقل إلى confirmed إلا إذا اجتاز predicate المركب كاملًا. أي نقص يتحول إلى `unconfirmed` أو `needs_review` ولا يتم احتسابه TP.

## 6. Phase P11 — Final VIP Gate

سيتم تعديل أو تثبيت gate ليقرأ artifacts الموقعة من P8/P9/P10، ويتحقق من freshness وschema وhashes وtarget isolation، ثم يشغّل source tests وG-02 وRuff وcompileall وBandit وpip-audit وsecret scan وrelease manifest. لا يجوز للـgate قبول `p9_distributed_runtime_evidence.json` أو `juice_shop_qualification_report.json` بناءً على وجود الملف فقط؛ يجب أن تكون predicates المطلوبة truthy وقابلة للتحقق.

**Gate P11 النهائي:**

```text
source_checks = passed
security_checks = passed
p8_strict_evidence = passed
p9_all_required_checks = passed
p10_benchmark = passed
artifact_integrity = passed
independent_review = passed
VIP_QUALIFIED = true
```

إذا فشل أي عنصر، تكون النتيجة `NOT_QUALIFIED` مع أسماء blockers الدقيقة، دون manual override.

## 7. ما أنفذه أنا داخل المشروع

أستطيع تنفيذ تغييرات source/tests/docs/gate التالية داخل المشروع: بناء P9 lease-contention harness آمن، إضافة Redis TLS Compose profile، إضافة broker-idempotency assertions، بناء redaction/retention tests، إضافة backup/restore verifier، بناء schema وvalidator لـground truth، توليد benchmark runner وmetrics calculator، فصل workspaces، تحديث P11 predicates، تشغيل الاختبارات المحلية، تحديث README والـartifacts، وإنشاء commits ورفعها إلى GitHub.

أستطيع أيضًا تنفيذ live validation على Juice Shop loopback فقط إذا كانت الحاوية المحلية متاحة، مع عدم استخدام حسابات حقيقية أو OTP أو أهداف عامة أو OAST أو raw response logging.

## 8. المطلوب من محمد

لا تحتاج إلى إرسال Gmail password أو cookies أو OTP أو مفاتيح bug-bounty. المطلوب منك فقط:

| المطلوب | لماذا؟ |
|---|---|
| تأكيد أن Juice Shop المحلي هو target المصرح به وأن نطاق الاختبار يظل loopback | authorization وscope evidence |
| اختيار بيئة التشغيل: جهازك المحلي أو خادم Ubuntu مستمر | P9 يحتاج Docker/Redis/workers متاحين أثناء الاختبار |
| توفير موارد كافية، ويفضل 4 GB RAM على الأقل للتجارب المتوازية | منع memory pressure عند تشغيل Redis وworkers وbrowser tests |
| تحديد benchmark scope: بداية مقترحة 10–12 classes/workflows أو catalog كامل | تحديد حجم ground truth والمدة |
| اعتماد policy للـretention، مثل مدة الاحتفاظ بالـmetadata والـlogs | إغلاق P9.4 بشكل قابل للقياس |
| اعتماد أن backup test سيكون محليًا ومشفرًا وبدون secrets خام | إغلاق P9.5 |
| إجراء independent review نهائي أو تعيين reviewer | شرط نزاهة P11 وليس مجرد test داخلي |

إذا اخترت تشغيله على جهازك، يجب أن يظل الجهاز متصلًا أثناء P9/P10. وإذا اخترت خادمًا مستمرًا، يلزم تزويد عنوانه أو ربطه بالجلسة وإعداد firewall يسمح فقط بالترافيك الضروري بين WebPent وRedis واللاب المحلي. لا يلزم فتح Juice Shop أو Redis على الإنترنت.

## 9. ترتيب التنفيذ والـdefinition of done

الترتيب الإلزامي هو: أولًا P9 infrastructure/evidence، ثم P10 ground truth/benchmark، ثم إعادة P8 على كل benchmark case، ثم P11 final gate، ثم independent review. لا نبدأ بزيادة عدد detectors أو شراء API keys قبل إغلاق هذه الأسس؛ لأن كثرة findings بلا oracle وproof ستزيد false positives ولن تقرّب المشروع من qualification.

تُعتبر الترقية مكتملة فقط عندما تكون الملفات التالية موجودة ومتحققة:

```text
docs/p9_distributed_runtime_evidence.json
  all six required checks = true

docs/juice_shop_qualification_report.json
  p10_passed = true
  approved_ground_truth = true
  precision/recall/class_coverage != null
  three isolated runs = true

docs/p8_p11_execution_evidence.json
  p8_strict_evidence = true
  p9_all_required_checks = true
  p10_benchmark = true

 docs/vip_quality_gate.json
  passed = true
  hard_checks_passed = true
  blockers = []

 docs/release_manifest.json
  verify = true
```

## 10. التقييم المتوقع بعد الترقية

إذا نُفذت P9 وP10 كما هو موضح، فلن يكون النجاح مجرد ارتفاع رقمي في التقييم، بل انتقالًا قابلًا للدفاع من `NOT_QUALIFIED` إلى `VIP_QUALIFIED`. أما قبل ذلك، فالتقييم العادل يظل نضجًا هندسيًا مرتفعًا مع qualification رسمية غير مكتملة.

**الخلاصة العملية:** من جهتي أستطيع تنفيذ أغلب الـsource work والـharnesses والـvalidators والاختبارات والـartifacts. المطلوب منك ليس credentials؛ المطلوب هو اختيار بيئة التشغيل، اعتماد نطاق benchmark وسياسة retention/backup، وتوفير موافقة صريحة على target المحلي وindependent review نهائي. بعد هذه القرارات يمكن بدء Sprint P9.1 مباشرة.

---

**المؤلف:** Manus AI
