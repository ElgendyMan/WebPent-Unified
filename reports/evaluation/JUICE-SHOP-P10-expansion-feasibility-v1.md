# Juice Shop P10 Expansion Feasibility v1

## القرار الحالي

تم تنفيذ مرحلة feasibility على نسخة Juice Shop المحلية `20.2.0`، source commit `1618a611b173b4bf114028e6e02549950606e29d`، وعلى WebPent revision `31d0707dc896697a7bd17a83ce1e0114d4a3b24d`. التنفيذ كان source inspection وbounded read-only triage فقط. لم يتم تشغيل Official P10 Runs، ولم يتم تعديل frozen ground truth.

المجموعة oracle-approved تظل 3 cases و3 classes. المطلوب 10 cases و6 classes، ولذلك gap الحسابي هو 7 cases و3 classes. هذا gap لا يتحول إلى approval بمجرد وجود challenge metadata أو route أو source vulnerability snippet.

## نتائج المرشحين

| المسار | الفئة المحتملة | نتيجة الفحص | القرار |
|---|---|---|---|
| Frontend Typosquatting / static component surface | Vulnerable Components | challenge metadata موجود، لكن exact served artifact وsemantic vulnerable-component predicate غير مثبتين من source/runtime contract | `needs_profile_and_source_proof` |
| Sensitive document/static resource | Sensitive Data Exposure | قد يضيف case لا class؛ public reachability أو source presence لا يكفيان لإثبات exposure vulnerability | `needs_target_mapping_and_oracle_review` |
| SQL/UNION injection | Injection | source يوضح crafted input وquery influence؛ إثبات causal signal يحتاج payload، وهو خارج read-only no-payload contract الحالي | `blocked_no_safe_contract` |
| Broken access control / cross-user state | Broken Access Control | challenge semantics تتطلب هوية/حالة مستخدم آخر أو mutation؛ غير مسموح auth bypass أو state mutation في هذه المرحلة | `blocked_precondition_or_mutation` |
| Directory listing / forgotten backup / misplaced signature | Existing Sensitive Data/Observability rows | preconditions أو mapping runtime غير مثبتة بصورة آمنة؛ لا توجد promotion | `blocked` |
| Policy / scoreboard / well-known policy | Miscellaneous/policy | policy أو route existence ليست vulnerability predicate مستقلة | `out_of_scope` |

## شروط تنفيذ عقد جديد

أي مسار `needs_profile_and_source_proof` يظل draft ولا يدخل scoring. قبل أي implementation يجب أن يثبت source-to-target mapping ثابتًا، وsafe precondition، وbaseline/candidate، وindependent negative control، وsemantic causal predicate، وcentral verifier، وredacted sealed ProofBundle، و`verify_seal()` وreplay، ثم regression وbefore/after comparison ومراجعة مستقلة.

بالنسبة لمرشح Vulnerable Components، الخطوة الآمنة التالية هي بناء source evidence للـasset exactness داخل adapter/profile فقط، ثم contract review مستقل قبل أي runtime assertion. لا يجوز استخدام route reachability أو package name وحده كـfinding.

بالنسبة لـInjection وBroken Access Control، لا يوجد في هذه المرحلة عقد read-only آمن يثبت vulnerability semantics. يظل القرار `blocked` بدل تنفيذ payload أو إنشاء حسابات أو تغيير state.

## أثر النتائج على P10

حتى في السيناريو النظري الذي يُعتمد فيه access-log وأربع حالات إضافية، لا يتم الوصول إلى 10/6 إلا إذا نتجت ثلاث فئات جديدة من أدلة مستقلة فعلية. لا يجوز استخدام الحالات `blocked` أو `out_of_scope` لسد الفجوة، ولا يجوز تعديل frozen ground truth أو evaluator لتغيير الرقم.

## بوابات الإغلاق

تظل `official_isolated_p10_runs_authorized=false`، وGovernance status هو `PENDING_INDEPENDENT_GOVERNANCE_SIGNOFF`. لا يبدأ أي run رسمي قبل اعتماد reviewer مستقل للمجموعة النهائية، ثم تحقق 10 cases و6 classes، ثم وجود proof contract كامل لكل حالة.
