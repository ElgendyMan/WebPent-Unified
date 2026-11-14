# Golden Benchmark Contract

## الغرض

هذا الـbenchmark يقيس صحة طبقة التقييم بصورة deterministic من خلال حالات contract معلنة داخل `webpent.benchmark.golden`. الحالات ليست نتائج WAPTLab ولا findings حية، ولا تنفذ network أو browser أو LLM أو credential I/O.

## ما الذي يقيسه

يتم حساب **precision** و**recall** و**false-discovery rate** و**evidence quality** و**reproducibility** لكل حالة. تُحسب **false-positive rate (FPR)** فقط عند تمرير `negative_case_ids` تمثل universe سلبية معلنة؛ عند غيابها تكون القيمة `0.0` بمعنى أن المقام غير معروف، وليس بمعنى أن الجولة خالية من false positives. ولقياس false positives بين التوقعات فقط استُخدم الاسم الصريح `false_discovery_rate`.

| الحالة | الغرض | ما تثبته | ما لا تثبته |
|---|---|---|---|
| `complete-evidence-and-replay` | baseline صحيح | حسابات كاملة وإعادة إنتاج ثابتة | وجود ثغرة في target حي |
| `incomplete-evidence-and-drift` | negative/control case | missed case وfalse discovery ونقص evidence وعدم reproducibility | confirmation أو proof حقيقي |

## قواعد التشغيل

يجب أن تظل الحالات محددة بمفاتيح case صريحة، وأن تكون نتائجها قابلة للتكرار. لا يجوز تحويل predicted أو candidate إلى confirmed، ولا استخدام benchmark كبديل عن causal signal وindependent negative control وsealed/replayable ProofBundle. أي qualification حي يظل منفصلًا ويحتاج target-backed evidence موثقًا داخل WAPTLab المصرح فقط.

## بوابة confirmation في metrics

يُحتسب finding داخل `confirmed` أو repeatability فقط إذا كان status المؤكد مصحوبًا بـ`causal_signal=true` و`negative_control_complete=true` و`proof_bundle_sealed=true`. أما status المؤكد الذي يفتقد أيًا من هذه الضوابط فيظهر تشخيصيًا تحت `confirmed_unverified` ولا يدخل في precision أو recall أو repeatability. هذا القياس لا يخلق ProofBundle ولا يثبت target-backed evidence؛ إنه يمنع benchmark من مكافأة label غير مدعوم.

## التحقق

بوابة Phase 10 الحالية: اختبارات benchmark وqualification وrelease contracts اجتازت، وتأكدت بوابات Ruff وcompileall و`git diff --check`؛ full regression النهائي لهذه الدورة موثق في `VIP_INTEGRATED_EXECUTION_STATUS.md`.
