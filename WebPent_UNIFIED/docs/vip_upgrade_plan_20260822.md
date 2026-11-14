# WebPent VIP Upgrade Assessment and Execution Plan — 2026-08-22

## الحكم الحالي

WebPent ليس **VIP Smart Autonomous Bug Hunter** بشكل كامل حتى الآن. التصنيف المسؤول هو **Advanced Candidate / Evidence-Aware Bounded Autonomous Bug Hunter**: البنية المحلية قوية وتحتوي execution plane موحدًا، authorisation fail-closed، scope runtime موحدًا، planning وknowledge-gap feedback، identity/workflow contracts، وتدفقًا يحافظ على causal evidence وnegative controls وProofBundles. لكن لقب VIP النهائي يتطلب qualification مرتبطة بـtarget، إعادة تشغيل قابلة للقياس، precision/recall benchmark، browser وmulti-identity qualification، وdistributed failure qualification؛ وهذه ليست نتائج يمكن استنتاجها من unit tests أو mock fixtures.

## baseline المرصود

| المجال | الحالة الحالية | الدليل |
|---|---|---|
| Full regression | قوي | 1306 passed، 235 warnings في quality gate الحالي |
| Ruff وcompileall | ناجحان | بوابة VIP الحالية |
| G-02 direct-I/O | ناجح محليًا | 63 سجلًا، primary/secondary agreement، و`external_target_contacted=false` |
| Capability catalog | جزئي لكنه صريح | 25 tested، 7 offline-fixture، 2 missing-validator (`race_condition` و`unknown`) |
| Evidence policy | مطبق fail-closed محليًا | causal signal + negative control + sealed ProofBundle مطلوبة قبل confirmation |
| Scope isolation | قوي محليًا | نفس `ScopeRuntimeHandle` بين crawler وtakeover وعدم تسريبه إلى state/checkpoint |
| Unified verifier | فشل حالي يجب إصلاحه | U1d يعتمد regex قديمًا لا يتعرف على `ARG BASE_IMAGE=webpent-base:latest` ثم `FROM ${BASE_IMAGE}` |
| Dependency audit | blocked بيئيًا | `pip-audit --strict` فشل بـ`No space left on device` أثناء إنشاء virtual environment مؤقتة |
| Live qualification | غير منفذة | ممنوعة في هذه الدورة؛ لا WAPTLab ولا Juice Shop |
| Distributed qualification | غير منفذة | Docker/Redis/Celery/PostgreSQL fault qualification تحتاج بيئة تشغيل مؤهلة |

## الفجوات المؤثرة في قرار VIP

| الأولوية | الفجوة | لماذا تؤثر | الحل المقترح |
|---:|---|---|---|
| P0 | Unified audit false negative في Dockerfile | يجعل release gate يفشل رغم أن Dockerfile يدعم default base image عبر ARG | جعل الفحص semantic: يتحقق من default `BASE_IMAGE` ومن مروره إلى `FROM`، مع اختبار regression للفحص نفسه |
| P0 | عدم توفر مساحة كافية لـpip-audit strict | يمنع بوابة dependency/SBOM من إصدار verdict موثوق | تنظيف caches وtemporary envs قبل الفحص، تشغيل audit في job مع مساحة معلنة، وترك الفشل blocker بدل تحويله إلى pass |
| P0 | غياب live target qualification | لا يمكن إثبات عدد findings أو confirmation أو precision محليًا فقط | عند السماح لاحقًا: ثلاث clean runs على target مصرح به، reset بين runs، causal/negative-control/ProofBundle gates، وعدم إدخال mock evidence في live totals |
| P1 | distributed worker qualification غير مكتملة | recovery/idempotency قد تبدو صحيحة محليًا دون broker/worker failure حقيقي | fault-injection suite في topology مؤهلة: crash، redelivery، lease expiry، DLQ، resume، migration، consume-once |
| P1 | browser وmulti-identity غير live-qualified | عقود identity/session موجودة، لكن session preservation وIDOR replay الحقيقيين غير مثبتين | resettable local fixture أولًا، ثم target qualification لاحقًا بثلاث هويات على الأقل، مع owner/foreign/role negative controls |
| P1 | external-tool value غير benchmarked | adapters الحالية آمنة لكنها لا تثبت زيادة coverage | كل adapter يمر عبر ActionExecutor وhealth check وbounded output، ثم ablation benchmark مستقل؛ لا direct-I/O جديد خارج G-02 inventory |
| P2 | `race_condition` بلا causal oracle | لا يجوز تحويل timing heuristic إلى confirmation | إضافة oracle typed حقيقي فقط إذا توفر local deterministic causality؛ وإلا يبقى missing-validator |
| P2 | `unknown` | catch-all قد يسبب false positives | إبقاؤه missing-validator دائمًا؛ ممنوع generic heuristic validator |
| P2 | release attestation غير موقعة | local artifacts لا تثبت provenance كاملة | signed manifest/attestation في CI بعد تثبيت dependency audit والـDocker digest |
| P2 | warnings/dependency drift | لا تكسر الاختبارات لكنها تؤثر على production readiness | تحديث dependencies تدريجيًا مع regression، خصوصًا LangChain/HuggingFace وPydantic/Chroma، دون توسيع نطاق هذه الدورة بلا evidence |

## ما سيتم تنفيذه في loop الحالية

1. إصلاح U1d داخل `verify_all.py` كفحص دلالي لا كتحوير Dockerfile، لأن المشكلة في audit expression وليست في default build behavior.
2. إضافة اختبار regression يثبت قبول الصيغة الحالية ورفض صيغة base image غير المعتمدة.
3. تشغيل focused tests ثم Ruff ثم full regression ثم `verify_all.py` وG-02 وcapability report.
4. إعادة تشغيل quality gate مع تسجيل فشل pip-audit كما هو إن ظل سبب البيئة قائمًا؛ لا يتم إخفاء blocker ولا تحويله إلى نجاح اصطناعي.
5. فحص working tree وartifacts، ثم commit/push وZIP نظيف إذا اجتازت التغييرات البوابات المحلية.
6. تحديث هذا التقرير بتصنيف نهائي evidence-based.

## شروط الخروج من loop

تخرج loop الحالية فقط عند استقرار التعديل المحلي: لا test failures، Ruff بلا أخطاء، verify_all بلا false negative معروف، G-02 pass مع `external_target_contacted=false`، artifacts متزامنة، وworking tree نظيف بعد commit. لا تُعلن VIP نهائيًا في هذه الدورة إذا بقي live أو distributed qualification blocked؛ سيتم تسجيل ذلك كـblocked capability لا كـclean result.

## الإضافات اللاحقة المقترحة

بعد السماح ببيئة qualification مصرح بها، الأولوية العملية هي بناء benchmark harness resettable يحفظ ground truth وcausal traces وnegative controls وProofBundles، ثم تشغيل ablation يقارن native-only مقابل adapters، ثم distributed fault tests، ثم signed release attestation. أما Neo4j GraphRAG وhierarchical dynamic spawning وcompliance reporting فتنفذ لاحقًا كطبقات فوق الـexisting KnowledgeGapEngine وCoverageLedger، وليس كأنظمة موازية أو مصادر evidence جديدة.
