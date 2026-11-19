# WebPent Evidence Quality Classification

## الهدف

أضيفت طبقة حتمية مستقلة لتصنيف جودة أدلة الـfindings. الطبقة لا تستبدل `confidence_level` ولا تقوم بترقية finding تلقائيًا؛ وظيفتها أن تشرح هل الدليل **مؤكد**، **مدعوم جزئيًا**، **يحتاج مراجعة بشرية**، أم **غير مؤكد**.

## عقد التوكيد

لا يُصنَّف finding على أنه `confirmed` في Evidence Quality إلا عند اجتماع العناصر التالية:

| الإشارة | معناها |
|---|---|
| `causal_signal` | تغيّر الاستجابة مرتبط سببيًا بالمدخل أو الحالة المختبرة، وليس مجرد اختلاف شكلي. |
| `negative_control_complete` | تم تنفيذ control سلبي مناسب، مثل هوية غير مالكة أو طلب غير مصرح، وكانت النتيجة متسقة مع الفرضية. |
| `sealed_proof_bundle` | حزمة إثبات مغلقة وصالحة اجتازت `validate_proof_bundle` مع اشتراط negative control. |
| `reproducible_evidence` | يوجد replay أو request/response أو evidence bounded يمكن للمراجع إعادته. |

إذا كان أحد هذه العناصر ناقصًا، فلا يحدث confirmation صامت. النتيجة تكون `needs_human_review` عند وجود إشارات مفيدة، أو `unconfirmed` عند غياب دليل سببي قابل للتكرار. أما وجود إشارة متناقضة فيجبر التصنيف على `unconfirmed` ويجعل الدرجة صفرًا.

## التصنيفات

| التصنيف | الاستخدام |
|---|---|
| `confirmed` | كل عقد التوكيد مكتمل، ووسم finding هو `Tool-Confirmed`. |
| `supported` | توجد ملاحظة قابلة للتكرار، لكن لا يوجد ما يكفي للتوكيد السببي. |
| `needs_human_review` | توجد إشارة سببية أو control أو proof جزئي، لكن العقد غير مكتمل. |
| `unconfirmed` | لا يوجد دليل قابل للتكرار، أو توجد إشارة تناقض نتيجة التحقق. |
| `clean` | أداة التحقق اشتغلت وأفادت بعدم وجود finding في هذا المسار. |
| `not_scanned` | لم يكتمل الفحص، ولا يجوز تفسير الحالة كـclean. |

## التقارير والدمج

يحتوي كل عنصر في `quality_gate.findings` على `evidence_classification` و`evidence_score` و`evidence_present_signals` و`evidence_missing_signals` و`evidence_reasons`. كما أضيفت إلى الـcanonical report data العدادات التالية:

- `evidence_confirmed_count`
- `evidence_review_count`
- `evidence_unconfirmed_count`
- `evidence_classification_counts`

وعند الدمج بين تشغيلات متعددة، أصبحت جودة الدليل جزءًا من ترتيب القوة. لذلك لا يمكن لنتيجة تحمل وسمًا قويًا شكليًا، لكنها تفتقد causal/negative/proof، أن تتغلب تلقائيًا على نتيجة ذات evidence قابل للتكرار.

## الخصوصية والتوافق الخلفي

التقييم لا يستدعي LLM ولا يرسل طلبات إضافية ولا يحتفظ بقيم payloads أو bodies داخل assessment. يضاف annotation محدود داخل evidence، بينما تظل حقول `confidence` و`confidence_level` وعقود التقارير القديمة كما هي. التوكيد الفعلي ما زال محكومًا ببوابات validator الحالية، بما فيها fail-closed واشتراط causal signal وnegative control وproof bundle في المسارات الصارمة.

لم يتم تعديل WAPTLab أو Juice Shop.

## التحقق

اجتازت النسخة بعد التعديل:

- `1056 passed`
- Ruff: `All checks passed!`
- `python -m compileall -q src scripts tests`
- `git diff --check`

ظهرت تحذيرات dependency وdev-secret الموجودة مسبقًا في الاختبارات، لكنها لم تسبب فشلًا ولم تُستخدم لاتخاذ قرار توكيد.
