# خطة تنفيذية محكمة لإغلاق قصور P8–P11

**المشروع:** WebPent

**الهدف:** الانتقال من `ENGINEERING_READY / NOT_QUALIFIED` إلى `VIP_QUALIFIED` فقط بعد إثبات حي قابل للإعادة، دون ترقية أي mock أو contract test أو heuristic إلى finding مؤكدة.

**النطاق التنفيذي:** Juice Shop المحلي على `127.0.0.1` هو الهدف العملي الحالي. يجب أن يظل كل تشغيل loopback-only. WAPTLab يظل artifact مستقلًا ولا يُستبدل أو يُعاد تفسيره كدليل Juice Shop.

> **قاعدة حاكمة:** لا يتم إصلاح الفشل بإضعاف SSRF/origin guard أو توسيع selectors بصورة عامة أو تجاوز OTP/CAPTCHA/MFA أو قراءة cookies/DB/mail internals. الإصلاح المقبول هو الذي يزيد قابلية الإثبات مع بقاء fail-closed قائمًا.

## 1. تعريف النجاح النهائي

لا تُرفع حالة المشروع إلى `VIP_QUALIFIED` إلا إذا تحققت الشروط التالية كلها:

| المجال | شرط القبول النهائي |
|---|---|
| P8 | ثلاث observations حية target-backed: baseline وcandidate وnegative control، مع request digests مختلفة، causal signal مبني على target response/network/DOM facts، negative control مستقل، central ProofBundle، `verify_seal=true`، وreplay ناجح |
| P9 | valid resume مثبت، checkpoint/resume مثبت، lease contention بين عاملين، killed-worker redelivery، broker-level idempotency، retry exhaustion/DLQ، TLS qualification، live redaction/retention، وعدم وجود target I/O غير مصرح |
| P10 | ثلاث benchmark runs مستقلة على نفس image digest وground-truth موثق، وكل finding confirmed يملك ProofBundle صالحًا؛ تُحسب precision/recall والتغطية وfalse positives/negatives دون خلط fixtures |
| P11 | full regression وRuff وcompileall وG-02 وsecurity checks وrelease manifest/reverification، مع تحقق آلي من صلاحية P8/P9/P10 artifacts وحداثتها واتساقها؛ صفر blockers حرجة |

أي شرط ناقص يعيد النتيجة إلى `NOT_QUALIFIED`، حتى لو نجحت كل الاختبارات الأخرى.

## 2. ضوابط لا يجوز كسرها

يجب تثبيت الضوابط الآتية قبل بدء أي إصلاح:

| الضابط | التطبيق الإلزامي |
|---|---|
| عزل الأهداف | engagement وworkspace وsession وRAG وartifacts منفصلة لكل target/run |
| حدود الشبكة | السماح فقط بـ`127.0.0.1` ومنافذ اللاب المعلنة؛ منع public targets وOAST وprovider I/O |
| المصادقة | استخدام هوية lab-provisioned أو حساب synthetic محلي طبيعي؛ ممنوع bypass أو استخراج OTP أو session/DB bypass |
| الأدلة | digests وmetadata bounded فقط؛ ممنوع raw bodies وheaders وcookies وpasswords وtokens |
| الترقية | لا يصدر validator وحده confirmed finding؛ الـverifier المركزي هو صاحب قرار seal/replay |
| rollback | كل تغيير في commit مستقل، مع targeted tests قبل الانتقال للمرحلة التالية؛ فشل gate يوقف المرحلة ولا يبرر تخفيف الشروط |
| provenance | كل artifact يحدد target origin، image digest، engagement ID، run ID، commit SHA، tool versions، وtimestamp |

## 3. بوابة الصفر: Baseline وتهيئة القياس

### Sprint 0-A — تجميد الحالة

يُنشأ branch عمل منفصل وتُحفظ baseline hashes دون حذف أو reset أو force-push. يجب تسجيل commit الحالي، حالة working tree، versions الخاصة بـPython/Playwright/Chromium/httpx/nuclei/katana، وDocker image digest.

يُمنع إدخال `.venv` أو أي runtime cache إلى Git. كل artifact جديد يجب أن يكون JSON/Markdown صغيرًا، خاليًا من الأسرار، ولا يستبدل artifacts WAPTLab القديمة.

### Sprint 0-B — تعريف schemas وmetrics

قبل تعديل السلوك، تُثبت schemas الآتية:

1. `BrowserObservation`: role، target fingerprint، request digest، response digest، status، bounded network count، DOM digest، replayable.
2. `ProofBundle`: engagement/finding/hypothesis، scope/identity provenance، causal basis، negative-control independence، seal metadata، replay metadata.
3. `DistributedRunEvidence`: task IDs hashed/bounded، worker IDs، lease outcome، ack/redelivery، retry/DLQ outcome، TLS mode، redaction/retention result.
4. `BenchmarkRun`: target digest، seed/state digest، ground-truth reference، findings، ProofBundle references، safety counters، stop reason.

### Gate G0 — Baseline integrity

يمر G0 فقط إذا كانت حالة Git قابلة للمراجعة، artifacts صالحة JSON، target loopback-only، ولا يوجد target خارجي في network logs. عند الفشل: لا تعديل في منطق P8–P11؛ يتم إصلاح baseline أولًا.

## 4. P8 — إصلاح browser proof وtyped workflow

### Root cause المراد إغلاقه

الـgeneric `validate_input` يفترض input مرئيًا وsubmit control تقليديًا. Juice Shop يستخدم SPA search semantics مختلفة؛ لذلك baseline لا ينتج receipt usable، ويتوقف `BrowserProofRunner` عند `baseline_observation_missing_or_unusable` قبل candidate وnegative control.[1] [2]

### Sprint 8-A — فصل workflow typed عن generic form validation

يُضاف عقد typed مثل `BrowserWorkflowSpec` أو equivalent يحدد صراحة:

- selector أو role المسموح به.
- نوع العملية: search/query أو form submission، وليس operation عامًا واحدًا لكل الصفحات.
- event المطلوب: Enter أو click أو submit، مع whitelist صريحة.
- maximum input length وsafe probe format.
- expected same-origin paths فقط.
- account-like detection: وجود password أو login/account markers يوقف العملية ولا يتحول إلى bypass.

بالنسبة إلى Juice Shop، يُكتب workflow خاص بالـsearch overlay بناءً على DOM observed فعليًا، وليس selector heuristic واسعًا. لا يُسمح بأن يتعامل `input[type=text]` كله معاملة search.

### Sprint 8-B — receipts target-backed قابلة لإعادة التشغيل

يجب أن يعيد كل replay receipt الحالة `completed` أو `executed`، وأن يحتوي على target fingerprint وrequest/response digests وrole الصحيح و`target_backed=true` و`replayable=true`. يجب تسجيل network/DOM deltas bounded فقط، دون raw bodies أو headers.

يجب إصلاح lifecycle cleanup بحيث لا تُخفي `TargetClosedError` سببًا أصليًا ولا تُنتج receipt ناقصة. الاستثناءات تُحوّل إلى diagnostic code آمن، ويُضمن إغلاق page/context/browser بعد جمع receipt دون race.

### Sprint 8-C — تشغيل الثلاثية وإثبات السببية

يُنفذ نفس workflow في ثلاث مرات مستقلة داخل نفس engagement:

| الدور | الغرض | شرط مستقل |
|---|---|---|
| baseline | السلوك الطبيعي بقيمة benign | receipt usable وtarget-backed |
| candidate | القيمة المرشحة للاختبار | request digest مختلف وdelta قابل للقياس |
| negative control | قيمة/مسار غير مؤثر مستقل | request digest مختلف عن candidate وعدم ظهور نفس causal effect |

الـcausal predicate يجب أن يعتمد على facts قابلة للحساب من response/network/DOM، لا على dialog أو LLM assertion أو اسم route. بعد ذلك فقط يُستدعى verifier المركزي لإنشاء bundle، ثم `verify_seal()`، ثم replay من bundle جديد/نفس metadata دون تغيير target state غير المصرح.

### اختبارات P8 الإلزامية

يجب إضافة أو تثبيت اختبارات للحالات التالية:

- search typed workflow يعمل فقط مع selector/type المعلن.
- أي password field أو account-like form مرفوض fail-closed.
- text input غير المعلن لا يُرسل Enter تلقائيًا.
- baseline receipt ناقص يوقف قبل candidate.
- candidate وnegative control لهما request digests مختلفة.
- target fingerprint mismatch مرفوض.
- dialog-only delta مرفوض.
- causal predicate فارغ أو غير حقيقي مرفوض.
- verifier يرفض missing provenance/scope/identity.
- seal failure وreplay failure يمنعان promotion.
- session/engagement binding لا يسمحان بإعادة استخدام browser session.

### Gate G8 — P8 evidence gate

يُحفظ artifact جديد مثل `docs/juice_shop_p8_run_<id>.json` ولا يُكتب فوق WAPTLab. يمر G8 فقط عند تحقق كل الحقول التالية:

```text
baseline.status in {completed, executed}
candidate.status in {completed, executed}
negative_control.status in {completed, executed}
all observations target_backed=true and replayable=true
candidate.request_digest != negative_control.request_digest
causal_signal=true
negative_control_complete=true
verify_seal=true
replay_status=passed
raw_response_bodies_saved=false
out_of_scope_attempts=0
```

إذا فشل أي شرط، يُسجل `stop_reason` المحدد وتظل النتيجة `NOT_QUALIFIED`.

## 5. P9 — استكمال distributed runtime qualification

### Root cause المراد إغلاقه

الـruntime smoke أثبت Redis PONG وعاملين وqueue distribution ورفض invalid resume. لكنه لم يثبت valid resume أو checkpoint recovery أو killed-worker redelivery أو lease/broker semantics أو TLS أو live log/retention.[3] [4]

### Sprint 9-A — harmless positive resume task

تُضاف مهمة target-free مملوكة للمشروع، deterministic وقصيرة، تكتب checkpoint bounded وتحتوي idempotency key. يجب أن تمر السلسلة التالية:

1. إصدار signed capability صحيحة بــthread/owner/client/engagement binding.
2. التحقق من capability بنجاح.
3. بدء task وإنشاء checkpoint.
4. إيقاف مؤقت controlled عند نقطة معروفة.
5. تنفيذ resume مرة واحدة بنجاح.
6. رفض إعادة استخدام نفس capability بعد الاستهلاك.
7. التحقق أن target I/O = صفر.

اختبار invalid capability الحالي يبقى regression أمنيًا ولا يُستبدل بالاختبار الإيجابي.

### Sprint 9-B — lease contention وbroker idempotency

يُشغل عاملان حقيقيان على نفس queue ونفس harmless task. يجب إثبات أن:

- عاملًا واحدًا فقط يحصل على lease.
- العامل الآخر يحصل على duplicate/lease-denied bounded result.
- نفس idempotency key لا ينفذ side effect مرتين.
- النتيجة محفوظة في backend/broker path الحقيقي، لا في SQLite probe فقط.
- كل event يملك task ID وworker ID وlease outcome دون payload أو secret.

### Sprint 9-C — killed-worker redelivery وresume

تُنفذ task قابلة للإيقاف في نقطة قبل acknowledgment. يُقتل worker المحدد أثناء التنفيذ، ثم يُراقب broker redelivery إلى worker آخر. لا يُعتبر النجاح مجرد عودة worker بعد restart؛ يجب إثبات redelivery، استئناف checkpoint، وعدم تكرار side effect.

### Sprint 9-D — retry/DLQ وTLS وobservability

يجب تنفيذ تشغيل حي لـretryable error حتى exhaustion، والتحقق من دخول الرسالة إلى DLQ فعليًا مع metadata redacted. إعداد `webpent_dlq_queue` أو policy في الكود لا يساوي DLQ qualification.

يُنشأ profile qualification منفصل لـRedis TLS؛ plaintext lab override يظل smoke فقط ولا يمرر P9. تُجرى اختبارات live تثبت أن logs لا تحتوي payloads أو tokens أو cookies وأن retention bounded ومطبق فعليًا، لا مجرد `WorkerObservability` in-process snapshot.

### Gate G9 — P9 distributed gate

يُقبل P9 فقط إذا كان artifact يثبت، في تشغيلات حية قابلة للإعادة:

```text
valid_resume=true
checkpoint_created=true
resume_completed=true
capability_consume_once=true
lease_winner_count=1
lease_loser_count>=1
killed_worker_redelivered=true
side_effect_count=1
broker_idempotency=true
retry_exhaustion=true
dlq_received=true
tls_enforced=true
live_log_redaction=true
live_retention_enforced=true
target_contacted=false
```

أي `false` في lease/crash/broker/TLS/redaction/retention يبقي `qualification_status=not_qualified`.

## 6. P10 — benchmark حي على Juice Shop

### Sprint 10-A — إعداد benchmark قابل للقياس

بما أن Juice Shop ليس WAPTLab catalog ثابتًا من 20 حالة في artifact الحالي، يجب أولًا تعريف ground truth مستقل وموثق. لكل case يجب تسجيل vulnerability class وendpoint/interaction وseed/state prerequisite وexpected safe verification signal. لا يجوز بناء ground truth من findings التي أنتجها WebPent نفسه فقط.

يُنشأ artifact جديد مثل `docs/juice_shop_qualification_report.json`، ولا يُعاد استخدام `docs/p10_benchmark_gate.json` الخاص بـWAPTLab.

### Sprint 10-B — target preflight

قبل benchmark:

- تشغيل image digest ثابت وتسجيله.
- التأكد من binding إلى `127.0.0.1` فقط.
- التحقق من HTTP status عبر health/root دون حفظ bodies.
- إنشاء engagement/workspace/session/RAG جديد لكل run.
- التأكد من عدم وجود external links أو OAST/provider calls.
- اختيار anonymous read-only workflow أولًا.
- عند الحاجة إلى auth، استخدام synthetic local identity أو lab-provisioned identity بالمسار الطبيعي فقط؛ ممنوع OTP bypass أو DB/session extraction.

### Sprint 10-C — ثلاث جولات مستقلة

تُنفذ ثلاث runs منفصلة بنفس commit/image digest وبحالة target معزولة. كل run يحتاج:

1. discovery bounded.
2. hypotheses مع evidence source.
3. validator class-specific.
4. P8 ProofBundle لكل confirmed case فقط.
5. negative control مستقل لكل proof.
6. seal/replay verification.
7. safety counters: out-of-scope attempts، unauthorized attempts، target mutation، budget، stop reason.

يجب تصنيف كل نتيجة إلى `confirmed` أو `pending` أو `inconclusive` أو `not_scanned`. لا يُحسب `Potential API_ISSUE` أو fingerprint أو Swagger exposure كـconfirmed vulnerability دون validator وProofBundle.

### Sprint 10-D — metrics والمراجعة

تُحسب precision وrecall وclass coverage وfalse positives/negatives وproof/replay agreement من ground truth، مع الاحتفاظ بالـraw count bounded ودون raw response disclosure. أي run ناقصة live provenance تُستبعد من qualification بدل ملء الحقول افتراضيًا.

### Gate G10 — P10 benchmark gate

يمر G10 فقط عند:

```text
run_count=3
all runs use same approved image digest
all runs have independent engagement/run IDs
all live runs have target_contacted=true
all confirmed findings have valid ProofBundle
all ProofBundles have verify_seal=true and replay_status=passed
negative controls complete for every confirmed case
all_runs_target_unchanged=true unless explicitly approved mutation case
live_qualification_proven=true
precision/recall/class coverage measured, not blocked_live
mock_promoted=false
```

إذا تعذر auth الطبيعي، يتوقف G10 بـ`blocked_live` ولا يُستخدم bypass لإكماله.

## 7. P11 — جعل release gate يعتمد على الأدلة الفعلية

### Sprint 11-A — ربط gate بالـartifacts

يظل P11 مانعًا للترقية عند غياب P8/P9/P10. لكن بدل الاعتماد على blockers ثابتة فقط، يجب أن يتحقق آليًا من:

- schema/version وhash لكل artifact.
- commit SHA وtarget digest وtimestamp freshness.
- consistency بين engagement ID في P8 وP10.
- صلاحية ProofBundles وseal/replay.
- P9 distributed evidence وTLS وredaction/retention.
- عدم وجود fixture/mock artifact في مسار live qualification.
- عدم وجود deleted files أو unexpected target changes.

لا تُزال blockers كحل شكلي؛ تُغلق فقط عندما يثبت artifact المقابل الشرط الحقيقي.

### Sprint 11-B — release verification

يُشغّل بالترتيب:

```text
compileall
ruff check src tests scripts
full pytest
G-02 official regeneration and verification
security checks: bandit/pip-audit/SBOM as configured
P8 artifact verification
P9 artifact verification
P10 artifact verification
build_release_manifest.py
verify_release_artifacts.py
run_vip_quality_gate.py
```

يجب أن يطابق manifest آخر source tree بعد آخر refresh، وأن يظل `target_contacted` في checks التي يجب أن تكون offline = `false`.

### Gate G11 — VIP promotion

القرار النهائي آلي وغير قابل للتجاوز:

```text
all source/release checks=true
P8_GATE=true
P9_GATE=true
P10_GATE=true
artifact schemas valid=true
artifact provenance consistent=true
manifest verified=true
known_blockers=[]
passed=true
VIP_QUALIFIED=true
```

إذا كانت الاختبارات خضراء لكن `known_blockers` غير فارغة، تكون النتيجة الصحيحة `ENGINEERING_READY` أو `EVIDENCE_READY` حسب الحالة، وليس VIP.

## 8. Dependency graph وترتيب التنفيذ

| الترتيب | المرحلة | تعتمد على | ناتجها |
|---:|---|---|---|
| 0 | Baseline/G0 | لا شيء | baseline hashes وschemas وrun IDs |
| 1 | P8 typed workflow | G0 | observations وProofBundle حي أو stop reason دقيق |
| 2 | P9 positive distributed runtime | G0 | distributed evidence مكتمل |
| 3 | P10 benchmark | G8 وG9 وground truth | ثلاث live runs وmetrics |
| 4 | P11 release gate | G8 وG9 وG10 | قرار promotion قابل للمراجعة |
| 5 | Independent review | كل ما سبق | موافقة ثانية أو blocker جديد |

لا تبدأ P10 قبل إغلاق G8 وG9؛ وإلا ستنتج benchmark غير قابل للتأهل. ولا تبدأ P11 promotion قبل اكتمال artifacts الثلاثة.

## 9. مصفوفة الاختبارات المطلوبة

| الطبقة | اختبارات إلزامية |
|---|---|
| Unit | selectors، probe digest، receipt schema، causal predicate، capability binding، lease/idempotency helpers |
| Contract | fail-closed guards، verifier provenance، seal/replay، redaction، retention، artifact schema |
| Integration | real Chromium على loopback، Redis/Celery عاملان، checkpoint/resume، DLQ، TLS profile |
| Fault injection | killed worker، duplicate delivery، timeout/retry، stale capability، corrupted bundle، changed target digest |
| End-to-end | P8 الثلاثي، P9 qualification، P10 three-run benchmark، P11 final gate |
| Negative tests | external origin، sibling path غير مسموح، account-like form، identical negative request، mock-only benchmark، missing seal |

## 10. قواعد الإيقاف والـrollback

يتوقف التنفيذ فورًا عند حدوث أي من الآتي: اتصال خارج loopback، selector يرسل input إلى account-like form، ظهور raw secret في log/artifact، target mutation غير معلنة، عدم اتساق target/image digest، أو محاولة تحويل fixture إلى live evidence.

كل إصلاح source يكون في commit مستقل. إذا فشل targeted test أو G8/G9/G10، يُعاد آخر commit الخاص بالمرحلة فقط عبر revert عادي، دون `reset --hard` أو حذف artifacts. تُحفظ failure artifact مع السبب والدالة المسؤولة، ثم تُصلح المرحلة نفسها قبل الانتقال.

## 11. تعريف النتائج المتوقعة

| النتيجة | معناها |
|---|---|
| `ENGINEERING_READY` | source contracts وregression سليمة، لكن live proof غير كافٍ |
| `EVIDENCE_READY` | proof artifacts جزئيًا سليمة، لكن benchmark أو distributed gate غير مكتمل |
| `BENCHMARK_QUALIFIED` | P10 حي مكتمل، لكن P9 distributed أو release review ناقص |
| `DISTRIBUTED_QUALIFIED` | P9 حي مكتمل، لكن P10 أو release review ناقص |
| `VIP_QUALIFIED` | P8/P9/P10/P11 كلها ناجحة مع provenance وreplay وmanifest ومراجعة مستقلة |

## 12. Deliverables النهائية

عند إغلاق الخطة يجب أن يحتوي المستودع على:

- `docs/p8_p11_remediation_execution_plan.md`.
- ثلاثة artifacts P8 مستقلة أو artifact مجمع يحوي run IDs والـProofBundles.
- `docs/p9_distributed_runtime_evidence.json` محدثًا بأدلة live حقيقية، لا contract-only.
- `docs/juice_shop_qualification_report.json` منفصل عن WAPTLab.
- artifacts hashes وrelease manifest وverification output.
- test logs مختصرة bounded وخالية من الأسرار.
- README يشرح أوامر reproduction وحدود النطاق وحالات `NOT_QUALIFIED`.
- commit history واضح بدون deletions غير مبررة أو force-push.

## الخلاصة التنفيذية

المشكلة لا تُحل بزيادة عدد الأدوات أو عدد الـfindings. الإصلاح المحكم هو بناء سلسلة مترابطة: **typed browser workflow → ثلاث observations حقيقية → causal/negative proof → seal/replay → distributed runtime evidence → ثلاث benchmark runs → release gate مستقل**. أي اختصار لهذه السلسلة قد يعطي تقريرًا أكثر امتلاءً، لكنه لن يحول WebPent إلى VIP Smart Autonomous Bug Hunter مؤهلًا فعليًا.

## المراجع

[1]: https://github.com/ElgendyMan/webpent-v61/blob/master/src/webpent/shared/browser_proof_runner.py "BrowserProofRunner strict three-observation flow"

[2]: https://github.com/ElgendyMan/webpent-v61/blob/master/src/webpent/shared/playwright_adapter.py "Playwright typed input and bounded observation handler"

[3]: https://github.com/ElgendyMan/webpent-v61/blob/master/src/webpent/shared/resume_capability.py "Fail-closed signed resume capability verification"

[4]: https://github.com/ElgendyMan/webpent-v61/blob/master/src/webpent/workers/pentest_worker.py "Celery resume task and capability denial path"

[5]: https://github.com/ElgendyMan/webpent-v61/blob/master/src/webpent/shared/verifier.py "Central proof, seal, provenance, and replay verifier"

[6]: https://github.com/ElgendyMan/webpent-v61/blob/master/src/webpent/benchmark/qualification.py "Benchmark live qualification aggregation"

[7]: https://github.com/ElgendyMan/webpent-v61/blob/master/scripts/run_vip_quality_gate.py "VIP release gate and blocker logic"

---

**المؤلف:** Manus AI

**الحالة عند كتابة الخطة:** الخطة لم تُنفذ بعد؛ هذه وثيقة تنفيذ ومعايير قبول، وليست ادعاءً بإغلاق P8–P11.
