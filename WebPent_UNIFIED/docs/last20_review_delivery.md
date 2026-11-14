# Last-20 Review Delivery Report

## النطاق والقيود

تمت مراجعة متطلبات آخر 20 ملفًا ضمن السياق الموروث، مع اعتبار `pasted_content_2.txt` و`pasted_content_3.txt` المرجعين الحاكمين. هذه الدورة لم تشغّل WAPTLab أو Juice Shop، ولم تنفذ أي اتصال HTTP أو DNS أو subprocess تجاه target خارجي. لا توجد في هذا التقرير أي ترقية إلى `Tool-Confirmed` أو `Confirmed`؛ قواعد `causal signal + negative control + replayable ProofBundle` ما زالت حاكمة.

## التعديل المنفذ

أصبح `ScopeRuntimeHandle` كائنًا runtime-only، immutable، ومبنيًا من نفس `CompiledScope` الذي تُنتجه عملية wildcard compilation. يقوم `RuntimeFactory.create()` ببنائه تلقائيًا عند تمرير `raw_scope_entries`، بينما يمرر `build_initial_state()` هذه الإدخالات إلى factory. لا يتم إدخال الـhandle إلى `PentestState` أو checkpoint؛ state يحتفظ فقط بالـprojection الآمن و`scope_runtime_fingerprint`.

يستهلك crawler الـhandle الحي لتصفية endpoints المكتشفة، ويستهلكه subdomain-takeover لتصفية hosts قبل أي verifier call. عند غياب الـhandle يستمر fallback legacy إلى state/Target contract، وهو backward-compatible، لكن لا يوجد fallback يوسع النطاق. الاختبار التكميلي يثبت أن crawler وtakeover يستعملان نفس instance، وأن host خارج النطاق لا يصل إلى verifier، وأن projection الناتج لا يحتوي `scope_runtime_handle`.

## مصفوفة الحالة

| البند | الحالة | الدليل الحالي |
|---|---|---|
| strict wildcard compilation والـanchored regex | Implemented and runtime-proven | اختبارات `tests/test_wildcard_scope.py` الحالية |
| explicit out-of-scope precedence | Implemented and runtime-proven | اختبار precedence الموجود وfull regression |
| RuntimeFactory dependency injection | Implemented and runtime-proven | full regression وruntime spine tests |
| initial-state wiring | Implemented and runtime-proven | full regression وinitial-state contracts |
| crawler authoritative scope consumption | Implemented and runtime-proven | اختبار same-instance الجديد |
| takeover authoritative scope consumption | Implemented and runtime-proven | اختبار same-instance الجديد |
| same compiled scope instance بين المستهلكين | Implemented and runtime-proven | `test_same_runtime_scope_handle_is_consumed_by_takeover_without_state_leak` |
| out-of-scope negative evidence | Implemented and runtime-proven | نفس الاختبار ومسار takeover ledger |
| عدم تسريب handle إلى state/checkpoint | Implemented and runtime-proven | state projection assertion وcheckpoint regression |
| identity provisioning والـcomposite vault key | Implemented but not live-qualified in this delta | اختبارات identity الحالية؛ لا qualification live |
| checkpoint resume identity restoration | Implemented but not live-qualified in this delta | اختبارات checkpoint الحالية؛ لا qualification live |
| causal verification وnegative control وProofBundle | Implemented but not live-qualified | enforced contracts وexport normalization؛ لا target qualification |
| direct-I/O inventory | Implemented and runtime-proven statically | `docs/direct_io_inventory.json` و`docs/DIRECT_IO_INVENTORY.md`، 63 سجلًا |
| G-02 runtime gate | Implemented and runtime-proven | `check_g02_runtime.py`: passed، 63 primary records |
| external target contact في هذه الدورة | Not performed | `external_target_contacted=false` |
| live qualification على WAPTLab/Juice Shop | Blocked by explicit review constraint | لم يتم تشغيل أي منهما |
| VIP Smart Autonomous Bug Hunter كحكم نهائي | Implemented but not live-qualified / not yet VIP-qualified | لا يجوز إعلان VIP قبل live gates وProofBundles |

## بوابات التحقق

| البوابة | النتيجة |
|---|---:|
| focused wildcard + identity tests | 31 passed |
| full regression | 1306 passed، 235 warnings |
| Ruff على الملفات المعدلة | All checks passed، 0 errors |
| direct-I/O inventory | 63 records |
| G-02 runtime | passed |
| external target contacted | false |
| WAPTLab/Juice Shop | not run |

تحذيرات الاختبارات الموجودة هي تحذيرات إعداد dev/deprecation في dependencies، وليست failures. لم يتم تخفيف verifier، ولم تتم إضافة fallback لـ`engagement_id`، وتظل قيمة `unknown` missing-validator وفق التصميم fail-closed.

## الملفات المتغيرة

التغيير الوظيفي موجود في `src/webpent/shared/wildcard_scope.py` و`src/webpent/shared/runtime.py` و`src/webpent/state/initial_state.py` و`src/webpent/agents/crawler/agent.py` و`src/webpent/agents/subdomain_takeover/agent.py`. أضيف اختبار integration في `tests/test_wildcard_scope.py`. أُعيد توليد `docs/direct_io_inventory.json` و`docs/DIRECT_IO_INVENTORY.md` و`docs/capability_report.json`. كما أضيفت قائمة المتطلبات الحاكمة في `docs/last20_governing_requirements.md`.

## قرار الإصدار

هذه الدورة تغلق فجوة **live scope dependency injection بين crawler وtakeover** وتثبتها محليًا بطريقة deterministic وبدون target contact. التصنيف المسؤول للنسخة يظل **Advanced Candidate / Evidence-Aware Bounded Autonomous Bug Hunter**، وليس VIP Smart Autonomous Bug Hunter؛ السبب ليس فشل الاختبارات، بل أن live qualification الشاملة ممنوعة صراحةً في هذه المراجعة ولم تُنتج ProofBundles حقيقية من target حي.
