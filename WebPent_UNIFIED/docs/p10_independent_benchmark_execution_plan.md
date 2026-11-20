# خطة تنفيذ P10 Independent Benchmark لـWebPent

**الهدف:** نقل P10 من `partial_not_approved_for_recall` إلى benchmark مستقل قابل للمراجعة، يثبت coverage أوسع عبر ثلاث جولات معزولة، ويحسب `precision` و`recall` و`class coverage` و`FP` و`FN` بدون خلط ground truth بنتائج WebPent أو تصنيع نتائج غير قابلة للإثبات.

**النطاق:** Juice Shop محلي مصرح به على `127.0.0.1` فقط. لا WAPTLab، ولا أهداف عامة، ولا OAST، ولا OTP/MFA/CAPTCHA bypass، ولا credentials حقيقية، ولا حفظ raw response bodies أو headers أو cookies أو payloads في artifacts المنشورة.

## 1. تعريفات لا بد من تثبيتها قبل التنفيذ

يجب فصل ثلاثة أشياء نهائيًا:

| العنصر | معناه | مصدره |
|---|---|---|
| Ground truth | الحالات التي نعرف مسبقًا أنها موجودة أو غير موجودة في نطاق benchmark، مع expected class وworkflow وoracle | catalog/metadata مستقل ومراجع يدويًا |
| Detector output | ما قاله WebPent عن الحالة بعد تشغيله | WebPent run artifact |
| Evidence verdict | هل الدليل الصارم أثبت finding محددًا أم لا | P8 verifier وProofBundle |

لا يجوز أن يُنشأ ground truth من findings التي اكتشفها WebPent، وإلا أصبح التقييم دائريًا. ولا يجوز اعتبار finding `candidate` مساويًا لـTP؛ لا يدخل TP إلا إذا طابق case في ground truth واجتاز proof predicate الكامل.

## 2. Phase 1 — Benchmark scope وcase registry

### Sprint 1.1 — اختيار النطاق

نبدأ بنطاق متنوع قابل للإنجاز، وليس catalog كاملًا بلا proof. النطاق المقترح هو **10–12 case/workflow من 6–8 vulnerability classes على الأقل**، بشرط أن تكون كل الحالات قابلة للاختبار الآمن محليًا وأن يكون لها oracle واضح. بعد إغلاق هذا النطاق يمكن توسيعه تدريجيًا.

التنوع أهم من مجرد زيادة العدد. يجب ألا تكون كل الحالات XSS variants؛ يلزم توزيع يختبر مسارات browser وHTTP وstateful logic وpassive analysis، مع استبعاد أي case لا يمكن إثباته دون bypass أو exposure غير ضروري.

### Sprint 1.2 — تصميم case registry

يُنشأ ملف versioned مثل `benchmarks/juice_shop/ground_truth.v1.json` أو SQLite registry مستقل، ويحتوي لكل case على metadata فقط:

```json
{
  "benchmark_id": "juice-shop-v1",
  "case_id": "js-xss-search-001",
  "vulnerability_class": "xss",
  "workflow_id": "juice-shop-mat-search",
  "target_component": "search",
  "expected_status": "in_scope",
  "oracle_type": "dialog_or_dom_marker",
  "precondition_class": "public_local_lab",
  "safe_probe_policy": "typed_workflow_only",
  "negative_control_id": "js-xss-search-negative-001",
  "mapping_source": "independent_catalog_record",
  "mapping_version": "v1",
  "case_hash": "sha256:..."
}
```

يُمنع وضع payload خام، cookie، token، response body أو header في هذا الملف. يمكن تخزين probe template معرفًا باسم أو hash، بينما التنفيذ المحلي يستخدمه ephemeral فقط.

### Gate 1 — Scope completeness

لا ننتقل قبل تحقق الآتي:

| الشرط | معيار القبول |
|---|---|
| case IDs | فريدة وثابتة وversioned |
| class diversity | 6–8 classes على الأقل داخل النطاق المقترح |
| expected status | كل case موسومة `in_scope` أو `out_of_scope` بسبب موثق |
| oracle | كل `in_scope` case لها oracle قابل للملاحظة بشكل آمن |
| negative control | لكل workflow مؤثر negative control مستقل |
| target isolation | كل case تشير إلى Juice Shop المحلي فقط |
| independence | mapping لا يعتمد على WebPent output |

إذا فشلت حالة في oracle أو safety تُوسم `out_of_scope` ولا تُحتسب تلقائيًا كـFN.

## 3. Phase 2 — Independent ground truth

### Sprint 2.1 — جمع المصدر المستقل

يتم أخذ case identity وclass mapping من مصدر مستقل عن detector، مثل catalog/metadata المقدم مع نسخة Juice Shop المثبتة أو سجل benchmark مُراجع. يجب تسجيل image digest ونسخة catalog وhash للـmapping. لا يكفي أن نكتب يدويًا أن case موجودة دون مصدر أو مراجعة.

الـground truth يجب أن يحدد هل الحالة موجودة في target state المحدد، وليس فقط أن challenge يحمل اسمًا معينًا. لذلك لكل case يجب توثيق:

1. `case_id` و`vulnerability_class`.
2. endpoint أو component identifier بشكل غير سري.
3. precondition المطلوبة.
4. expected safe oracle.
5. هل الحالة قابلة للاختبار في الوضع المحدد أم `out_of_scope`.
6. version/hash للمصدر.
7. reviewer ووقت الاعتماد.

### Sprint 2.2 — مراجعة الاستقلال

تُجرى مراجعة مزدوجة: reviewer يراجع mapping قبل رؤية detector results، ثم reviewer ثانٍ يطابق الحالات مع target metadata. تحفظ النتيجة كـapproval record يحتوي hashes وidentities فقط.

**ممنوع:** تعديل ground truth بعد رؤية نتائج WebPent بهدف تحسين metrics. إذا تغيرت النسخة أو target state، يُنشأ `benchmark_id` جديد وتُعاد runs الثلاث.

### Gate 2 — Ground truth integrity

يمر gate فقط إذا:

```text
ground_truth_source != WebPent output
mapping_version موجود
mapping_sha256 موجود
reviewer_approval موجود
case IDs فريدة
كل case لها class وworkflow وoracle أو سبب out_of_scope
```

أي malformed JSON أو duplicate case أو missing hash يؤدي إلى `NOT_QUALIFIED`، وليس إلى تخطي الحالة.

## 4. Phase 3 — Coverage matrix وsafe oracles

### Sprint 3.1 — Coverage matrix

ينشأ جدول يربط كل case بالـclass والـworkflow ونوع النقل والـoracle وحالة الاختبار:

| case | class | workflow | transport | oracle | negative control | run-1 | run-2 | run-3 |
|---|---|---|---|---|---|---|---|---|
| case-001 | XSS | typed search | browser+HTTP | dialog/DOM differential | yes | pending | pending | pending |
| case-002 | SQLi | approved query workflow | HTTP | safe differential | yes | pending | pending | pending |
| case-003 | IDOR/BOLA | object selector | HTTP | authorized object differential | yes | pending | pending | pending |

لا يتم إدراج class لمجرد وجود اسمها في catalog؛ يجب أن تكون لها case قابلة للتنفيذ وoracle وproof policy. `class_coverage` يُحسب على classes التي لها ground truth approved وrun result صالح.

### Sprint 3.2 — Oracle contract

لكل workflow يتم تحديد:

- baseline observation.
- candidate observation.
- independent negative control.
- causal signal المطلوب.
- proof bundle fields المطلوبة.
- cleanup/reset rule.
- maximum request and time budget.

الـoracle يجب أن يكون target-backed وقابلًا للتكرار. لا يُقبل status code عام وحده إذا كان يمكن أن ينتج من أخطاء transport أو rate limiting. ولا يُقبل log message من detector نفسه كدليل على target behavior.

### Sprint 3.3 — Safe case adapters

يتم بناء adapter محدود لكل workflow، لا generic arbitrary input. كل adapter يمر عبر TargetSpec وScopeValidator وRequestBudget، ويرفض redirect أو host أو port خارج النطاق. أي حالة تحتاج login أو OTP أو تجاوزًا أمنيًا تُراجع منفصلًا؛ لا يتم توسيعها بالقوة داخل benchmark.

### Gate 3 — Coverage readiness

يمر gate إذا كان لكل `in_scope` case:

```text
case mapping + class + workflow + safe oracle + negative control
TargetSpec admission passed
cleanup/reset defined
strict proof predicate defined
```

ويصدر gate تقرير coverage قبل التشغيل يوضح الحالات الداخلة والخارجة وأسباب الاستبعاد.

## 5. Phase 4 — ثلاث runs معزولة

### Sprint 4.1 — تجهيز isolation

لكل run يتم إنشاء:

```text
benchmark_id
run_id
engagement_id
workspace_id
artifact_namespace
starting_target_fingerprint
image_digest
case_map_hash
```

كل run تستخدم workspace وartifact namespace مستقلين. لا تتم مشاركة cookies أو browser profiles أو session files أو mutable state بين runs. إذا كانت الحالة تحتاج target reset، يتم reset موثق قبل بداية كل run، ولا تستخدم نتائج run سابقة كـbaseline.

### Sprint 4.2 — تنفيذ run واحدة

التسلسل داخل كل run:

1. تحقق من target fingerprint وimage digest.
2. تحقق من ground_truth hash وbenchmark version.
3. نفّذ baseline لكل case.
4. نفّذ candidate عبر adapter المسموح فقط.
5. نفّذ negative control مستقلًا.
6. دع WebPent ينتج detector output.
7. مرّر candidate findings إلى P8 verifier.
8. خزّن aggregates وhashes فقط.
9. نفّذ cleanup/reset.
10. seal artifact وأثبت replay metadata.

إذا فشلت run بسبب environment أو timeout، تُسجل `run_status=invalid_environment` أو `incomplete` مع السبب، ولا تُحوّل تلقائيًا إلى FN.

### Sprint 4.3 — تكرار run-2 وrun-3

لا تبدأ الجولة التالية إلا بعد التأكد من عزل السابقة. يجب أن تكون case map وtarget version ثابتتين، أو يُنشأ benchmark version جديد. يفضل تغيير ترتيب cases بين الجولات لتقليل أثر order bias، مع بقاء نفس expected labels.

### Gate 4 — Three-run isolation

يمر gate إذا:

| الشرط | معيار القبول |
|---|---|
| عدد الجولات | 3 runs مكتملة وصالحة |
| isolation | لا artifact/workspace/session overlap |
| target state | fingerprint/image digest مطابق أو drift موثق ومرفوض للدمج |
| case set | نفس ground truth version في الجولات الثلاث |
| proof | كل confirmed case لها strict proof أو سبب non-confirmation |
| data hygiene | لا secrets/raw bodies/raw headers/cookies في artifacts |

## 6. Phase 5 — تحويل النتائج إلى labels

يجب إنشاء evaluation table داخل مساحة محلية محمية، لا يُنشر منها إلا aggregates:

| run | case_id | ground_truth_label | detector_label | evidence_label | evaluation_label |
|---|---|---|---|---|---|
| run-1 | case-001 | vulnerable | confirmed | proof_passed | TP |
| run-1 | case-002 | vulnerable | no_finding | none | FN |
| run-1 | case-003 | not_vulnerable | confirmed | proof_passed | FP |

قواعد التصنيف:

- **TP:** ground truth يقول `in_scope/vulnerable`، وWebPent أعلن finding مطابقًا، وP8 proof predicate نجح.
- **FN:** ground truth يقول `in_scope/vulnerable`، والـrun صالح، لكن WebPent لم ينتج finding مؤكدًا أو فشل في الوصول إلى proof المطلوبة.
- **FP:** ground truth يقول `not_vulnerable` أو case غير موجودة في target state، ومع ذلك أعلن WebPent finding مؤكدًا مع proof غير صحيحة أو mapping غير مطابق. Candidate غير المؤكد لا يُعتبر FP confirmed؛ يسجل كـcandidate/noise منفصلًا، مع إمكانية تقرير `candidate_fp` تشخيصيًا.
- **Invalid run:** فشل بيئة أو target drift أو artifact corruption؛ لا يدخل denominator قبل إعادة run.
- **Out of scope:** حالة لم تعتمد آمنة/قابلة للاختبار؛ لا تدخل precision/recall، لكنها تظهر في تقرير coverage كاستبعاد صريح.

هذه القواعد تمنع تضخيم النتائج: finding بلا proof لا يصبح TP، وحالة لم تُختبر بسبب target drift لا تصبح FN.

## 7. Phase 6 — حساب metrics

### Sprint 6.1 — Metrics لكل run

لـكل run صالح:

```text
TP_run = عدد الحالات المصنفة TP
FP_run = عدد الحالات المصنفة FP
FN_run = عدد الحالات المصنفة FN

precision_run = TP_run / (TP_run + FP_run)
recall_run = TP_run / (TP_run + FN_run)
```

إذا كان المقام صفرًا، تُسجل القيمة `null` مع `undefined_reason=zero_denominator`؛ لا يتم تحويلها إلى صفر أو واحد.

### Sprint 6.2 — Aggregated metrics

يجب نشر طريقتين بوضوح:

1. **Micro aggregation:** جمع TP/FP/FN عبر runs الثلاث ثم تطبيق المعادلة.
2. **Macro aggregation:** متوسط metrics الخاصة بكل run صالح، مع ذكر عدد runs الداخلة.

```text
precision_micro = sum(TP) / (sum(TP) + sum(FP))
recall_micro = sum(TP) / (sum(TP) + sum(FN))
precision_macro = mean(precision_run_i)
recall_macro = mean(recall_run_i)
```

لا نخلط micro وmacro في رقم واحد دون تسمية. الـartifact النهائي يحتوي counts وformula version وrounding policy.

### Sprint 6.3 — Class coverage

يتم حسابها على ground truth classes المعتمدة:

```text
class_coverage = عدد الـclasses التي لها case صالحة ونتيجة proof/evaluation في runs الثلاث / عدد classes المعتمدة في benchmark scope
```

يجب تقرير coverage بطريقتين إذا احتاج الأمر:

```text
case_coverage = valid evaluated cases / approved in-scope cases
class_coverage = classes represented by valid evaluated cases / approved classes
```

وجود class في catalog دون case صالحة لا يزيد numerator. ووجود case واحدة من class لا يعني بالضرورة تغطية كل workflows الخاصة بها؛ لذلك يجب عرض matrix تفصيلية أيضًا.

## 8. Phase 7 — Artifact schema والـvalidator

ينشأ artifact مثل `docs/juice_shop_p10_benchmark_v1.json` يحتوي على:

```json
{
  "schema_version": "p10-benchmark-v1",
  "benchmark_id": "juice-shop-v1",
  "target": {
    "scope": "127.0.0.1:3000",
    "image_digest": "sha256:...",
    "target_fingerprint": "sha256:..."
  },
  "ground_truth": {
    "source_id": "independent-catalog",
    "mapping_version": "v1",
    "mapping_sha256": "sha256:...",
    "approved": true,
    "case_count": 12,
    "class_count": 8
  },
  "runs": [
    {
      "run_id": "run-1",
      "isolated": true,
      "status": "valid",
      "case_count": 12,
      "artifact_sha256": "sha256:..."
    }
  ],
  "metrics": {
    "micro": {"tp": 0, "fp": 0, "fn": 0, "precision": null, "recall": null},
    "macro": {"precision": null, "recall": null},
    "case_coverage": null,
    "class_coverage": null
  },
  "p10_passed": false,
  "blocking_reasons": []
}
```

القيم أعلاه مجرد schema illustration وليست نتائج. لا يتم تغييرها إلى نتائج حقيقية إلا بعد تنفيذ runs الفعلية. الـvalidator يجب أن يرفض malformed JSON، duplicate run IDs، missing mapping hash، `approved=false`، runs غير المعزولة، metrics غير القابلة لإعادة الحساب، أو أي raw-secret marker.

## 9. Phase 8 — P10 gates النهائية

### Gate P10-A — Ground truth

```text
ground_truth.approved == true
mapping_sha256 موجود
source مستقل عن WebPent
case/class/workflow/oracle كاملة
```

### Gate P10-B — Coverage

```text
>= 10 approved in-scope cases
>= 6 vulnerability classes
كل case لها safe adapter وnegative control
out_of_scope reasons مكتوبة
```

يمكن تغيير الأرقام حسب scope المعتمد، لكن يجب تثبيتها قبل تشغيل run-1 ولا يجوز تخفيفها بعد رؤية النتائج.

### Gate P10-C — Runs

```text
عدد valid runs == 3
كل run معزولة
same benchmark version/hash
same target image/fingerprint أو drift مرفوض
strict proof records موجودة
```

### Gate P10-D — Metrics

```text
TP/FP/FN قابلة لإعادة الحساب
precision وrecall ليست null إلا بسبب zero denominator موثق
class_coverage ليست null
invalid/out_of_scope لا تدخل denominator
FP وFN مدعومتان بسجل case-level
```

### Gate P10-E — Fail-closed integration

يقوم `run_vip_quality_gate.py` بقراءة artifact والتحقق من كل predicates. وجود الملف أو وجود ثلاث runs فقط لا يكفي. عند فشل أي شرط يجب أن يخرج:

```text
p10_passed=false
hard_checks_passed=false
blockers=[...]
```

وعند النجاح فقط:

```text
p10_passed=true
blockers=[]
```

## 10. ترتيب التنفيذ العملي

الترتيب المقترح هو:

1. بناء schema وvalidator وcase registry.
2. اعتماد ground truth مستقل وتثبيت hash/version.
3. اختيار 10–12 case عبر 6–8 classes وتوثيق الحالات المستبعدة.
4. بناء safe adapters وoracles وnegative controls.
5. إضافة isolation checks للـworkspace/browser/session/artifact.
6. تنفيذ run-1 فقط والتحقق من صحة artifact قبل تكرارها.
7. تنفيذ run-2 ثم run-3 بنفس mapping والtarget state.
8. تشغيل evaluator وحساب case-level labels وTP/FP/FN.
9. حساب micro/macro metrics وcoverage.
10. تشغيل P10 gate ثم P11 gate.
11. إجراء review مستقل قبل أي promotion.

## 11. ما يمكن تنفيذه داخل WebPent وما يحتاج موافقة

### أستطيع تنفيذه داخل المشروع

أستطيع إضافة schema وvalidator وcase registry format، وبناء coverage matrix، وsafe adapter contracts، وrun isolation checks، وevaluator deterministic، وحساب metrics، واختبارات malformed/mixed artifacts، وربط كل ذلك بـP10/P11، ثم تشغيله على Juice Shop loopback وحفظ artifacts redacted وتحديث README.

### المطلوب منك

تحتاج فقط إلى اعتماد benchmark scope النهائي، والموافقة على الحالات والـclasses التي تدخل، وتأكيد أن target المحلي ثابت ومصرح به، وتحديد من سيعمل independent review. لا تحتاج إلى إرسال Gmail credentials أو OTP أو cookies أو tokens. أي case تحتاج هذه الأسرار أو bypass تُستبعد ولا تُجبر داخل benchmark.

## 12. Definition of Done

لا يُعتبر P10 مكتملًا إلا عندما يتحقق كل الآتي في artifact واحد:

```text
ground_truth.approved = true
ground_truth.source_is_independent = true
case_count >= approved_scope_minimum
class_count >= approved_class_minimum
valid_runs = 3
all_runs_isolated = true
mapping_hash ثابت عبر runs
TP/FP/FN case-level records موجودة
precision_micro قابلة لإعادة الحساب
recall_micro قابلة لإعادة الحساب
class_coverage قابلة لإعادة الحساب
out_of_scope وinvalid runs مستبعدة بأسباب واضحة
no raw bodies/headers/cookies/secrets
p10_passed = true
```

بعدها فقط يُسمح لـP11 أن يقيّم artifact كـP10 passed. إذا فشل شرط واحد، تظل الحالة `NOT_QUALIFIED` مع blocker مسمى.

## References

[1]: https://github.com/ElgendyMan/webpent-v61/blob/master/docs/juice_shop_qualification_report.json "Current Juice Shop qualification report"

[2]: https://github.com/ElgendyMan/webpent-v61/blob/master/scripts/run_vip_quality_gate.py "Dynamic VIP quality gate"

[3]: https://github.com/OWASP/juice-shop "OWASP Juice Shop project"

---

**المؤلف:** Manus AI
