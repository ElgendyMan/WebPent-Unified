# Target Adapter Review Packet v1

## الغرض

هذا المستند هو قالب مراجعة مستقل لأي `TargetAdapter` جديد. هو **ليس approval**، ولا يثبت وجود ثغرة، ولا يسمح بتسجيل metrics أو ترقية finding. يظل packet في `draft` أو `pending` قبل المراجعة؛ وبعدها يمكن أن ينتقل إلى `mapping_approved` أو `qualified_for_runs` قبل التشغيل، بينما لا تصبح حالة `approved` ممكنة إلا بعد مراجعة النتائج الفعلية.

الهدف من packet هو منع انتقال تفاصيل target إلى الطبقات المشتركة، ومنع تحويل وجود route أو HTTP `200` أو DOM observation إلى causal proof. الـadapter يملك facts الخاصة بالهدف والتنفيذ المسموح، بينما يظل `ProofBundle` وverification وreplay مركزيًا وعامًا.

## بوابات القبول

| البوابة | المطلوب | الفشل المغلق |
|---|---|---|
| الهوية والنطاق | target identity وorigin وscope digest موثقة ومطابقة للـengagement | لا registry lookup ولا browser proof |
| عزل التنفيذ | كل selector أو route أو payload assumption داخل adapter أو target-owned module | رفض packet أو رفض التنفيذ |
| workflow contract | كل workflow له ID مراجع، وكل `typed_search` له callable executor داخل allowlist | `typed_workflow_executor_missing` أو equivalent |
| case mapping | كل case يملك operation وworkflow وoracle وsemantic profile واضحين | case غير قابل للـscoring |
| oracle semantics | oracle يحدد target-backed causal signal، وليس مجرد observation أو precondition | لا `ProofBundle` ولا TP |
| negative control | negative control مستقل ومحدد مسبقًا، ويستطيع التمييز عن baseline | proof غير مكتمل |
| replay/seal | ثلاث ملاحظات معزولة، central verification، seal، وإعادة تشغيل قابلة للمقارنة | metrics تظل `null` |
| safety | لا credentials أو cookies أو raw bodies أو OAST/SSRF/auth bypass أو actions غير معتمدة | العملية محجوبة |
| الاستقلال | reviewer مستقل يثبت hashes ويرى mapping والعقد والنتائج | `approval_decision=pending` |

## متطلبات case وworkflow

يجب أن يطابق كل case أحد العمليات العامة المسموح بها في العقد الحالي، مثل `navigate` أو `typed_search`. لا يجوز أن يضيف adapter مسارًا عامًا جديدًا بمجرد وضع selector في handler مشترك. إذا احتاج case إلى browser I/O typed، يجب أن يكون `workflow_id` موجودًا في `workflow_ids()` وأن يعيد `workflow_executors()` callable لهذا الـID. أما workflow غير typed فلا يحتاج executor تلقائيًا، لكن يجب أن يظل allowlisted ومراجعًا.

يجب أن يحدد الـcase oracle contract مستقلًا عن implementation. الوصف المقبول يجيب عن الأسئلة التالية: ما الإشارة التي لا يمكن تفسيرها إلا بوجود السلوك الأمني المقصود؟ ما negative control الذي يتوقع غياب الإشارة؟ ما حدود الاستنتاج؟ وما الذي سيبقى `not_scored` إذا لم تظهر causal signal؟ وجود endpoint أو route أو status code وحده ليس oracle.

## evidence contract

لا يجوز للـadapter أو runner حفظ أو طباعة request body أو response body أو headers أو cookies أو credentials أو payloads الخام أو screenshots. الـevidence المسموح هو metadata منقح ومحدود، ومؤشرات semantic مسجلة عبر المسار المركزي. يجب أن يحتوي كل candidate قابل للترقية على causal signal وnegative control وcentral sealed ProofBundle ونتيجة `verify_seal()` و`replay_status`.

غياب أي عنصر من هذه العناصر يعني أن النتيجة observation أو blocked أو inconclusive، وليس finding مؤكدًا. لا يجوز اعتبار `null` فشلًا قابلًا للتعويض بأرقام تقديرية، ولا يجوز عدّ الحالات `out_of_scope` كـFN.

## reviewer packet lifecycle

| الحالة | المعنى |
|---|---|
| `draft` | القالب غير مكتمل ولم يدخل مراجعة مستقلة |
| `pending` | mapping والعقود جاهزة للمراجعة، ولا توجد approval بعد |
| `mapping_approved` | reviewer وافق على case mapping والعقود فقط؛ لا live qualification |
| `qualified_for_runs` | reviewer أغلق mapping ووافق على بدء runs المحددة؛ لا يعني نجاح P10 |
| `approved` | نتيجة reviewer النهائية بعد رؤية النتائج الفعلية والـhashes |
| `rejected` | mapping أو oracle أو safety posture مرفوض |
| `out_of_scope` (case disposition) | الحالة مستبعدة صراحة ولا تدخل في TP/FP/FN؛ ليست packet status مستقلة |

أي packet لا يملك `reviewed_mapping_sha256` و`reviewed_oracle_contract_sha256` وقرارًا محددًا لكل case يجب أن يفشل مغلقًا في qualification tooling. كما يجب أن تكون هوية target وscope والمرجع authorization غير فارغة في أي حالة مغلقة، وأن يطابق `mapping_status` و`expected_disposition` وreview disposition نفس القرار لكل case. حالات `mapping_approved` و`qualified_for_runs` هي pre-run approvals ولا يجوز أن ترى نتائج التشغيل؛ أما `approved` فهي final approval ولا تمر إلا بعد رؤية النتائج الفعلية، مع authorization مسجل في `live_runs`. ولمنع traceability الشكلية، يجب أن يحتوي final `approved` على ثلاث `run_ids` مختلفة، و`proof_bundle_ids`، و`run_case_matrix` يغطي كل approved case في كل run، و`replay_statuses` التي تساوي `passed` لكل run، و`verify_seal_results` التي تساوي `true` لكل run. هذه الحقول تثبت اكتمال metadata المرجعية فقط؛ الـchecker لا يتحقق من محتوى ProofBundle نفسه ولا ينشئ evidence، ولذلك لا يرفع P10 أو VIP وحده.

يوجد checker محلي deterministic لهذا العقد، ويمكن تمرير packet محدد أو استخدام template الافتراضي:

```bash
PYTHONPATH=src:integrations/bbscout/src .venv/bin/python \\
  scripts/check_target_adapter_review_packet.py

PYTHONPATH=src:integrations/bbscout/src .venv/bin/python \\
  scripts/check_target_adapter_review_packet.py path/to/review_packet.json
```

الـchecker يراجع packet metadata فقط، ولا يتصل بأي target ولا ينشئ evidence.

## ما لا يثبته هذا packet

إنشاء هذا القالب لا يضيف target جديدًا، ولا يشغل WAPTLab أو Juice Shop، ولا ينشئ حسابات أو credentials، ولا ينتج evidence، ولا يرفع حالة P9 أو P10 أو VIP. الخطوة التالية بعد اكتماله هي اختيار target محلي مصرح به، ثم تقديم mapping وsafe cases قابلة للمراجعة، ثم تشغيل bounded runs فقط بعد إغلاق governance gate.
