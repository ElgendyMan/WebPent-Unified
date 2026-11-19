# Autonomous Security Research Operating System (ASROS) Core v1

## الغرض والنطاق

ASROS هو طبقة reasoning وresearch intelligence additive فوق WebPent وAREX. وظيفته تحسين فهم التطبيق، ترتيب attack surfaces، بناء سلاسل حجة، التعلم من نتائج الحملة، ومراجعة جودة المسار قبل وبعد التنفيذ. لا يملك ASROS سلطة تنفيذ transport أو إنشاء Finding أو تغيير policy أو تجاوز oracle.

النطاق التشغيلي المعتمد لهذا الإصدار هو **controlled local loopback فقط**. أي تنفيذ فعلي يظل خلف العقود الحالية مثل `ActionAuthority` و`CampaignExecutor` و`GenericCaseRunner` وproof verifier. وحدات ASROS نفسها لا تنفذ network requests، ولا تنشئ credentials أو sessions، ولا تستخدم callbacks أو external targets، ولا تنفذ state mutation أو shell actions.

## Security World Model

يمثل `SecurityWorldModel` طبقات business intent، security invariants، وbehavior model. كل عنصر يحمل evidence lineage وconfidence وsource وfreshness. غياب evidence references أو عدم اتساق المصدر يسبب رفضًا fail-closed. النموذج advisory؛ وجود deviation لا يعني vulnerability.

| الطبقة | أمثلة | شرط الثقة |
|---|---|---|
| Business intent | workflow، ownership، trust assumption | مصدر مسجل وlineage قابل للتتبع |
| Security invariant | منع وصول مستخدم لمورد مالك آخر، role boundary | صياغة قابلة للاختبار، وليست claim نهائيًا |
| Behavior model | expected، observed، deviation | ملاحظات فعلية أو حالة blocked موثقة |

## Research Reasoning Engine

يستقبل reasoning engine world model وattack graph وmemory وpast observations، ثم ينتج `ResearchArgumentChain` advisory. السلسلة مرتبة ومختومة hash، وتتكون من observation ثم reasoning ثم hypothesis ثم validation. سلامة السلسلة تمنع reorder أو تعديلًا صامتًا. `self_validation` مرفوض، وقرار reasoning لا يساوي confirmation.

أي انتقال إلى نتيجة مؤكدة خارج هذا المستوى يتطلب causal oracle مستقلًا، negative control مستقلًا، central verification، وsealed/replayable proof references وفق العقود القائمة.

## Adaptive Strategy وDynamic Attack Surface Map

تُرتب الأسطح حتميًا بحسب business impact وprivilege sensitivity وdata sensitivity وcomplexity وunknown behavior وprevious evidence. نتائج low-value أو repeated failure تخفض أولوية المسار وتدفع الخطة نحو workflow أو relationship أو trust-boundary analysis. التكيّف ينتج توصية advisory فقط ولا يغير scope أو budget أو authority.

الـdynamic map لا يرسل requests، ولا يستنتج vulnerability من route reachability أو HTTP status أو health response. كل سطح بلا evidence كافٍ يبقى unknown أو blocked.

## Vulnerability Knowledge Graph وResearcher Memory

يقدم knowledge graph عقدًا typed للفئات، attack patterns، prerequisites، evidence patterns، وvalidation strategies، مع علاقات `commonly_related` و`prerequisite_of` و`discovered_by` و`disproved_by`. البحث prerequisite-aware advisory ولا ينشئ Finding.

تمت ترقية الذاكرة إلى researcher memory مع تصنيف decisions وchains وsuccessful/failed paths وlimitations وoracle failures. الذاكرة معزولة exact-target/exact-engagement، وتخضع للـredaction والميزانية. لا يحدث cross-target leakage ولا تتحول الذاكرة إلى authority.

## Quality Controller

يعمل Quality Controller كـsenior-review simulation bounded.

قبل التنفيذ، يراجع ضعف الفرضية، الافتراضات غير المثبتة، كفاية preconditions، ومسار الإثبات المتوقع. بعد التنفيذ، يراجع evidence quality، overclaiming، وجود causal proof، ووجود negative control. يخرج verdict advisory مثل `proceed` أو `revise` أو `block`؛ ولا يستطيع اعتماد vulnerability، تجاوز policy، أو override oracle.

## أدوار التعاون

الأدوار الخمسة هي Application Analyst، Authorization Analyst، Adversarial Reasoner، Evidence Scientist، وResearch Manager. كل دور ينتج proposals أو artifacts advisory فقط. لا يوجد role يستطيع تنفيذ transport، إنشاء Finding، تغيير policy، أو استبدال oracle المركزي.

## Advanced Controlled Benchmark

يستخدم benchmark artifact مسجلًا من controlled local campaign ولا يعيد تشغيل target أو يرسل requests. يسجل الحد الأدنى المطلوب من الفئات: IDOR، privilege escalation، business logic، وinformation disclosure. في الإصدار الحالي، IDOR فقط لديه candidate/control observations وcausal proof مسجلان؛ الفئات الثلاث الأخرى تبقى blocked لعدم وجود fixture محلي معتمد كامل، ولا تدخل في TP/FN/clean scoring.

يتم قياس hypothesis quality وresearch efficiency وevidence quality وunnecessary exploration reduction على summaries المسجلة فقط. هذه metrics مختبرية محدودة ولا تمثل real-world detection rate أو qualification.

## Safety وGovernance

| الضابط | قيمة الإصدار |
|---|---|
| network scope | loopback/local controlled only |
| methods | GET-only عند التنفيذ الفعلي |
| external network | false |
| credentials/login/tokens | false |
| callbacks | false |
| state mutation/destructive actions | false |
| persistent daemon/service | false |
| official P10 authorization | false |
| P10/P9/VIP | NOT_QUALIFIED |
| Bug Bounty | BLOCKED |
| human signoff | false |

## Acceptance وLimitations

تمت إضافة اختبارات consistency وinvariant reasoning وadaptive planning وmemory isolation وagent boundaries وreasoning-chain integrity وevidence-quality checks، إضافة إلى benchmark regression. نجاح هذه الاختبارات يثبت سلامة التصميم والتنفيذ المحلي bounded، وليس استقلالية عامة على targets خارجية ولا detection-quality portability ولا VIP qualification.

أي توسعة تتطلب credentials أو login أو mutation أو target خارجي أو تعديل frozen ground truth أو policy أو thresholds يجب أن تتوقف وتتحول إلى Owner Decision Packet منفصل.
