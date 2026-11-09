# Autonomous Controller Gap Analysis

**Baseline commit:** `28194f66da866237512eb8eac4702bc4958c5fd3`  
**Baseline quality:** 764 tests passed, 130 warnings, compileall passed, Ruff passed.  
**Scope:** تحليل ساكن/runtime للنسخة الحالية فقط. لم يتم تعديل WAPTLab أو Juice Shop، ولم يتم تنفيذ أي feature نتيجة هذا الملف وحده.

## ملخص تنفيذي

المكونات الأساسية التي ذكرتها الخطتان **موجودة جزئيًا بالفعل** داخل `shared/research_intelligence.py` و`shared/campaign_executor.py` و`shared/coverage_ledger.py`، وليست غائبة بالكامل. لكن وجودها الحالي لا يساوي Smart Research Loop مكتملًا: بعضها dataclass/projection، وبعضها runtime-reachable فقط داخل `smart_campaigns_node`، بينما ما يزال التنفيذ العام موجّهًا بواسطة graph routes وحملات محددة. لذلك سيتركز التنفيذ التالي على **عقود typed، wiring additive، active information gathering، القرار الموحد، والاختبارات** بدل إنشاء نسخ مكررة من نفس القدرات.

## جدول التتبع

| Capability | Exists | Evidence in code/tests | Missing or limitation | Action decision |
|---|---|---|---|---|
| Research state / `ResearchContext` | جزئي | `shared/research_intelligence.py:545-652` يحتوي `ResearchSession` مع objective، theory، ledgers، gaps، graph، actions، criteria؛ `from_state()` و`as_dict()` موجودان. | ليس Pydantic model؛ لا يوجد contract عام باسم `ResearchContext` يغطي known facts، unknowns، current action، budget، checkpoint validation، وengagement-safe reconstruction لكل graph path. | **احتفظ بالموجود وأضف additive Pydantic-compatible context contract أو adapter** بعد إضافة tests للserialization/checkpoint/isolation. |
| Knowledge Gap Engine | جزئي/موصول | `shared/research_intelligence.py:188-333` يعرف `KnowledgeGapEngine` ويشتق owner/authorization gaps؛ `agents/smart_campaigns/agent.py:321-345` يستدعيه runtime. `tests/test_v91_research_intelligence.py` يغطي owner/denial gap. | العائلات محدودة؛ derivation يعتمد أساسًا على object-like URLs و`bac_coverage_gaps`؛ لا توجد typed prerequisites أو invalidation واسعة؛ engine لا يستقبل target model/coverage/failed paths كعقود مستقلة. | **توسيع محافظ** للعائلات والعقود فقط حيث تثبت tests gap، مع بقاء Knowledge Gap غير قابل للتحول إلى finding. |
| Candidate Action contract | جزئي | `InformationAction` في `research_intelligence.py:68-129` typed dataclass، fingerprint وredaction؛ `CampaignTask`/`ActionRequest` في `campaign_executor.py` يمرران authority/executor. | لا يوجد schema واحد Pydantic يربط action type، exact target/scope، hypothesis/gap IDs، prerequisites، policy requirements، budget، capability، approval، وreplay identity. LLM proposal لا يمر بعقد موحد مستقل قبل التخطيط. | **أضف contract additive ومحوّلًا واضحًا** إلى `InformationAction`/`CampaignTask`، مع reject/fail-closed tests للـextra/out-of-scope/missing fields. |
| Next Best Action | جزئي/مزدوج | `SmartNextBestActionEngine` في `research_intelligence.py:346-411` يحسب utility لعناصر `InformationAction` ويعاقب duplicate؛ `campaign_executor.py:166-219` يحتوي engine آخر لترتيب `CampaignTask`; `smart_campaigns_node:350-405` يستعمل الاثنين في مسارين. | لا توجد decision surface موحدة تشمل discovery، identity، workflow، baseline، negative control، payload، validator، proof replay، safe stop، coverage، failed memory، والميزانية في trace واحد. engine الحالي الأول لا يطبق صراحة likelihood/impact كقيم من state، والثاني خاص بالـCampaignTask. | **توحيد القرار عبر facade additive** أو adapter دون حذف أي engine قديم، وتسجيل score components/reason/dependency/failed-path penalties. |
| Active Information Gathering | غير مكتمل runtime | `smart_campaigns_node:324-345` ينتج `smart_information_actions` proposals فقط؛ `smart_campaigns_execution_node` ينفذ campaign tasks محدودة وليس generic gap-resolution actions. | لا توجد خدمة typed تسير Gap → Policy/Scope/Cost filters → execution → observation → knowledge update؛ لا يوجد generic resolver يعيد فتح gap بعد observation. | **تنفيذ طبقة bounded resolver** تمر عبر `ActionAuthority`/`ActionExecutor` ولا تنشئ raw I/O أو unrestricted scanning. |
| Failed Path / Negative Knowledge | جزئي | `NegativeEvidence` و`NegativeEvidenceLedger` في `research_intelligence.py:435-543` يفرضان `client_id` ويتيحان same-client cross-engagement policy؛ `ResearchSession.record_negative()` يسجل ledger. Tests تغطي isolation/expiry. | `SmartNextBestActionEngine` لا يقرأ ledger مباشرة؛ لا يوجد reusable `FailedPath` contract مع exact observed result/control/state/revisit conditions، ولا integration يخفّض score ثم يعيد الفتح عند evidence/state/identity change. | **إضافة adapter/penalty policy** واختبارات reopen conditions، مع عدم اعتبار negative evidence نفيًا عامًا للعائلة. |
| Coverage-driven scheduling | جزئي/passive | `shared/coverage_ledger.py:55-80` يعرف `CoverageIntelligence`; `project()` و`gaps()` يعتمدان proof/campaign outcomes، ويضيفان research coverage counters في `83-165`. | الملف يصرح صراحة أنه projection-only؛ coverage لا تدخل فعليًا في اختيار action إلا قيمة ثابتة/محدودة داخل smart planning؛ لا يوجد `SurfaceCoverage` typed model بمراحل discovered/authenticated/reachable/tested/validated وغيرها. | **إضافة decision-facing SurfaceCoverage adapter** مع الحفاظ على projection الحالي وعدم جعله authority. |
| Research Session / rabbit-hole | جزئي | `ResearchSession` runtime ينشأ في `smart_campaigns_node`; graph يحتوي rabbit-hole وtests قديمة. | session لا يقود rabbit-hole entry/exit/depth/budget كعقد عام؛ لا يوجد pause/resume workflow يربط contradictions وalternative action end-to-end. | **ربط additive session lifecycle** واختبارات pause/resume، دون تغيير default graph أو legacy behavior. |
| Causal Attack Graph | جزئي/passive | `models/attack_graph.py:17-68` يعرف typed Pydantic nodes/edges؛ `shared/attack_graph.py` يبني graph؛ `agents/attack_graph/agent.py` يضيف projection اختياريًا. | graph لا يثبت causal precondition→action→effect→evidence transition ولا يؤثر في next action؛ edge existence لا يرقى إلى finding، وهذا صحيح أمنيًا لكنه يترك decision gap. | **إضافة causal edge contract/adapter** مع evidence refs وtyped edge kinds، ثم feed آمن للقرار دون promotion. |
| Novel behavior detection | غير ظاهر كـfirst-class component | توجد `hypotheses` وdevil’s advocate/validator في graph، لكن لم يظهر detector مستقل يشتق authorization asymmetry/state/parser/workflow anomalies إلى hypothesis. | لا توجد Observation → NovelBehaviorHypothesis contract ولا same proof gates. | **تنفيذ لاحقًا بعد core loop** كطبقة advisory additive، مع test يثبت أنها لا تنشئ finding مباشرة. |
| Decision-aware RAG | جزئي/غير مثبت | `shared/knowledge_retrieval.py` وplanner/hypothesis analyzer يستعملان RAG مع provenance وbounded context. | لا يوجد contract يلزم query بإرفاق current hypothesis، technology، gap، surface، objective ويقيس decision relevance؛ RAG ما زال advisory فقط، وهو invariant يجب الحفاظ عليه. | **إضافة query-context adapter وretrieval evaluation**، لا تغيير authority boundary. |
| LLM reliability/evaluation layer | جزئي | توجد حماية prompt/untrusted-data وcached helper وschema/policy tests في v61؛ planner/crawler يمران عبر cached helper. | لا يوجد evaluation suite موحد يختبر malformed JSON، hallucinated endpoint، out-of-scope/unsafe/missing prerequisite/duplicate/contradiction وprompt injection من target/RAG عبر Schema→Sanitization→Scope→Policy→Capability→Budget. | **إضافة validator/evaluation harness** للـproposal contracts، دون إعطاء LLM صلاحية التنفيذ أو confirmation. |
| Autonomous Controller | موجود لكن bounded/partial | `shared/autonomous_controller.py:23-143` ينفذ plan→gate→execute عبر injected handler و`ActionExecutor`؛ safe-stops بدون handler/executor. `graph/builder.py:667-680` يدخل controller فقط إذا `state['enable_autonomous_controller'] is True` ثم يعود إلى strategist. `tests/test_v94_autonomous_controller.py` تغطي safe-stop/executor/proof. | ليس research brain مستقلًا؛ يعتمد على prebuilt `smart_campaigns` tasks، يختار أول task فقط، لا يحدّث knowledge gaps/coverage/negative ledger بشكل عام، ولا يملك broad replan loop عبر كل action classes. | **إبقاء controller opt-in false default**، وإضافة research-loop facade وstress tests بدل استبداله أو فتحه افتراضيًا. |
| Central action/policy/proof boundary | موجود/قوي نسبيًا | `ActionAuthority` و`ActionExecutor` في `shared/campaign_executor.py`؛ smart execution يمرر authority/executor؛ proof bundle outcomes موجودة. | يلزم إثبات أن كل new research action يتم تحويله لهذا boundary وأن confirmation persistence ترفض proof الناقص في كل المسارات الجديدة. | **إعادة استخدام الموجود وإضافة contract tests فقط**. |
| Secure runtime/scope | جزئي وموجود أساسًا | capability manifest fail-closed؛ same-origin checks في smart execution؛ settings secure flags موجودة. | baseline ما يزال ينتج weak dev-secret warnings؛ redirect/DNS/raw-I/O coverage تحتاج manifest/runtime tests موحدة. | **triage لاحقًا**؛ لا نكسر local tests، لكن نمنع وصف production-ready قبل إغلاق warnings/gates. |

## Runtime call map

المسار الحالي ليس loop بحث عامًا. عند تفعيل smart profile، يدخل `route_after_disclosed_report_intel()` إلى `smart_campaigns`; ثم `smart_campaigns_node()` يبني campaign tasks، يشتق gaps، ويرتب information proposals وcampaign tasks. بعد ذلك ينفذ `smart_campaigns_execution_node()` عددًا محدودًا من المهام من خلال `ActionAuthority` و`ActionExecutor`. لا ينتقل إلى `autonomous_controller` إلا إذا كان `enable_autonomous_controller` مساويًا لـ`True` في state، وبعده يعود graph إلى `strategist`.

بالتالي، الدليل الحالي يثبت أن **مكونات research intelligence runtime-reachable داخل مسار Smart Campaigns**، لكنه لا يثبت أن النظام أصبح بعدُ research engine عامًا أو أنه يكتشف/يؤكد كل family تلقائيًا. هذا التصنيف مهم لمنع تضخيم claims في README والتقرير.

## Safety invariants confirmed before implementation

| Invariant | Baseline finding |
|---|---|
| `enable_idor_enumeration=False` افتراضيًا | يجب الحفاظ عليه؛ لم يُطلب تغييره. |
| `enable_autonomous_controller=False` افتراضيًا | graph لا يمرر controller إلا مع state flag صريح؛ يجب الحفاظ عليه. |
| عدم تعديل WAPTLab/Juice Shop | سيظل كل العمل داخل WebPent والـfixtures/benchmarks. |
| لا confirmation من heuristic/RAG/graph edge | proof/validator boundary موجودة، وستظل إلزامية. |
| additive وfail-closed | كل التوسعات القادمة ستكون adapters/models/tests، مع safe-stop عند نقص capability أو handler. |
| client/engagement isolation | ledger يرفض record بلا client ويقيّد cross-engagement؛ يجب توسيع الاختبارات لا تخفيفها. |

## قرار التنفيذ بعد الـaudit

الفجوات الحقيقية التي تستحق التنفيذ أولًا هي: **ResearchContext typed adapter، CandidateAction schema، active gap-resolution service، unified next-action decision trace، failed-path integration، decision-facing coverage، session lifecycle، causal transition contract، novel behavior hypotheses، decision-aware RAG context، وLLM adversarial evaluation**. لن يتم إنشاء `KnowledgeGapEngine` أو `ResearchSession` أو `CapabilityRegistry` أو `CoverageIntelligence` ثانية، لأن الأدلة تثبت وجودها بالفعل.

## Evidence files

- `audit/autonomous_upgrade_baseline.json`
- `audit/autonomous_upgrade_baseline_raw.txt`
- `audit/autonomous_controller_symbol_map.txt`
- `src/webpent/shared/research_intelligence.py`
- `src/webpent/shared/autonomous_controller.py`
- `src/webpent/shared/capability_manifest.py`
- `src/webpent/shared/campaign_executor.py`
- `src/webpent/shared/coverage_ledger.py`
- `src/webpent/models/attack_graph.py`
- `src/webpent/graph/builder.py`
- `tests/test_v91_research_intelligence.py`
- `tests/test_v94_autonomous_controller.py`
