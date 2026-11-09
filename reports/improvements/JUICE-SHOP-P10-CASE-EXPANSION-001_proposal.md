# JUICE-SHOP-P10-CASE-EXPANSION-001 — Proposal

## الحالة والنطاق

هذا المقترح يحوّل gap الحالي للوصول إلى الحد الأدنى الرسمي لـP10 إلى مسار تنفيذ مضبوط، لكنه **ليس موافقة حوكمية** ولا يضيف أي حالة إلى final approved scoring set. نطاقه Juice Shop المحلي المصرح به فقط، مع إبقاء `official_isolated_p10_runs_authorized=false`.

الحالة الحالية هي 3 حالات و3 فئات معتمدة oracle، مقابل حد أدنى قدره 10 حالات و6 فئات. يلزم إثبات 7 حالات إضافية و3 فئات إضافية، لكن هذا رقم تخطيطي فقط. لا تُحتسب أي حالة إلا بعد إثبات العقد كاملًا واعتمادها من reviewer مستقل.

## المشكلة والسبب الجذري

الفجوة ليست مجرد نقص في عدد الصفوف. الحالات الحالية خارج مجموعة الـ3 المقبولة إما تحتاج حسم mapping/oracle، أو precondition غير آمن/غير متاح، أو تمثل observation أو policy/route semantics لا تثبت vulnerability predicate. إضافة rows أو إعادة تصنيف الحالات إداريًا ستنتج ground-truth drift وfalse positives وتخالف fail-closed governance.

## خطة التنفيذ

### Gate A — الحوكمة والـprovenance

يتم أولًا تسليم corrected Governance Packet إلى reviewer مستقل حقيقي. يراجع reviewer archive provenance، ويفصل بين Juice Shop source commit وWebPent source-manifest commit، ويحسم access-log mapping، ويعيد اعتماد current oracle contract، ويثبت قرارات الحالات الثماني غير scoring. يظل هذا المسار pending ما لم يصل signed decision حقيقي؛ لا يتم إنشاء reviewer identity أو توقيع بالنيابة عنه.

### Gate B — إغلاق access-log

لا تدخل `juice.access_log_disclosure.v1` في scoring قبل حسم الفرق بين `/ftp/access.log` في frozen ground truth و`/support/logs/access.log.<UTC-date>` في المصدر الحالي. بعد قرار reviewer فقط يمكن تثبيت mapping الصحيح في artifact governed منفصل، ثم إعادة تشغيل baseline/candidate/negative-control مع proof sealing وreplay.

### Gate C — candidate feasibility

يتم فحص المرشحين target-local عبر GET/read-only فقط. يسمح الفحص بتسجيل metadata redacted مثل status family وcontent-type family وbounded length bucket، ولا يسمح بحفظ raw body أو headers أو cookies أو credentials. أي مرشح يحتاج payload أو auth bypass أو state mutation أو external callback يبقى `blocked`.

### Gate D — عقود جديدة قابلة للإثبات

المرشح الوحيد القابل للتحقيق مبدئيًا ضمن القراءة فقط هو static dependency/component surface لتحدي Vulnerable Components، بشرط وجود source proof للـasset exactness وsemantic predicate أقوى من مجرد public asset reachability. تُدرس حالات Sensitive Data Exposure كحالات إضافية فقط إذا ظهر resource mapping حقيقي وcausal predicate صالح. أما Injection وBroken Access Control فتظل blocked حاليًا لأن إثباتهما يتطلب crafted input أو state/identity boundary غير متاح ضمن السياسة الحالية.

### Gate E — contract implementation

أي contract جديد يُكتب target-local داخل Juice Shop adapter/profile، ويجب أن يحتوي على safe precondition وbaseline/candidate وindependent negative control وsemantic causal predicate وcentral verifier وsealed/replayable ProofBundle واختبارات redaction وneutrality وrollback. لا يُعدل Generic Core أو frozen P10 artifacts لتناسب Juice Shop.

### Gate F — إعادة الاختبار والمقارنة

تُعاد كل حالة بنفس target version وsource revision وpolicy وcase protocol. تحفظ المقارنة TP/FP/FN وprecision/recall كـ`null` إن كانت governance أو threshold gates غير مكتملة. لا تعتبر blocked أو out_of_scope FN، ولا تعتبر route reachability أو source presence finding.

### Gate G — threshold review

بعد اعتماد كل حالة مستقلًا، تُحسب المجموعة النهائية من artifacts الفعلية فقط. لا يُفتح official run gate إلا إذا كان reviewer signoff مثبتًا، والـapproved set المجمد يحتوي على 10 حالات على الأقل و6 فئات على الأقل، وكل حالة تحمل causal oracle وnegative control وsafe precondition وProofBundle صالحًا مع sealing وverify_seal وreplay.

## candidate matrix

| المرشح | الفئة المحتملة | الحالة الحالية | سبب عدم العد الآن | شرط الترقية |
|---|---|---|---|---|
| Access-log | Observability Failures | Pending governance | mapping وcurrent oracle يحتاجان اعتمادًا | signed reviewer decision + rerun كامل |
| Static dependency/component surface | Vulnerable Components | Needs profile/source proof | asset existence لا يثبت vulnerability | source proof + semantic predicate + proof bundle |
| Sensitive document resource | Sensitive Data Exposure | Candidate only | يحتاج mapping وcausal semantics | safe GET + independent control + approval |
| SQL injection probe | Injection | Blocked | payload/crafted input خارج read-only contract | عقد سلامة مستقل وموافقة صريحة قبل أي execution |
| Cross-user state boundary | Broken Access Control | Blocked | يحتاج identity/state أو mutation | precondition آمن ومصرح + oracle مستقل |
| Directory/backup/signature rows | Existing blocked | Blocked | preconditions/runtime غير مثبتة | resource readable safely + causal oracle |
| Policy/scoreboard rows | Existing out_of_scope | Out of scope | ليست vulnerability predicates | لا تُرقى إداريًا |

## معايير القبول

يُقبل أي contract جديد فقط إذا أثبت target-backed candidate signal، وnegative-control separation، وسلامة precondition، وcentral verification، وعدم تسريب raw data، و`verify_seal()` وreplay، واختبارات regression، ومقارنة before/after، ثم حصل على independent governance approval. عدد الحالات والفئات لا يُحدّث في frozen ground truth قبل هذا التسلسل.

## rollback

إذا فشل أي gate، تُعاد الحالة إلى `blocked` أو `observation-only` أو `needs_human_review` حسب الدليل. لا يتم force-push أو history rewrite أو حذف artifacts. يمكن rollback لأي adapter/profile contract جديد عبر revert للـcommit المستقل، مع إبقاء failure record والـevidence redacted للمراجعة.

## القرار الحالي

المقترح **جاهز للمراجعة المستقلة**، لكنه لا يفتح Official P10 Runs ولا يعلن P10/P9/VIP qualification. المجموعة الحالية تظل 3 cases و3 classes، والفجوة الفعلية 7 cases و3 classes. أي انتقال إلى 10/6 يجب أن ينتج من عقود مثبتة ومراجعة مستقلة، لا من تعديل أرقام أو ground truth.
