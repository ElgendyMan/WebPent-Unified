# WebPent v60 — WAPTLab Validation Report

**Author:** Manus AI  
**Date:** 18 August 2026  
**Target:** Local, authorized WAPTLab clone at commit `00de7bdb25a45938eb1b3d6711bf342c7cefb7b7`  
**WebPent build:** v60 VIP re-audited baseline, extended during this validation loop

## Executive conclusion

تم تنفيذ الاختبار داخل الـsandbox فقط، مع إبقاء مستودع WAPTLab بدون أي تعديل. تشغيل WAPTLab الحقيقي تعذر بسبب قيد kernel في البيئة يمنع Docker من إنشاء bridge endpoint لغياب `iptables raw table`. لذلك لا يتم تقديم أي نتيجة على أنها **live-confirmed على WAPTLab**. بدلًا من ذلك، تم استخدام مصدر WAPTLab نفسه كـstatic ground truth، ثم تم تشغيل WebPent على mock loopback مستقل يحاكي الأسطح المطلوبة، مع استعمال validators الفعلية وengagement scope الرسمي.

النتيجة النهائية للـmock-backed direct matrix هي **5 حالات Tool-Confirmed** و**15 حالة Candidate/Human Review أو Not Scanned**. هذا الرقم لا يعني أن WAPTLab نفسه يحتوي على خمس ثغرات مؤكدة runtime؛ معناه أن WebPent أثبت قدرته على تأكيد خمس فئات عبر differential evidence على fixture محلي مضبوط. أما حالات SSRF وIDOR وXXE/XSLT وXSS وSQLi التي تحتاج OOB callback أو هويتين أو browser/context proof أو أدوات متخصصة، فتم إبقاؤها محافظة ولم تُرفع إلى confirmation وهمي.

| القياس | النتيجة | معنى النتيجة |
|---|---:|---|
| WAPTLab source files modified | 0 | لم يتم تعديل الهدف مطلقًا |
| Live WAPTLab runtime confirmations | 0 | Docker runtime blocked by sandbox kernel constraint |
| Graph baseline findings | 9 | منها 3 tool-confirmed على الـmock graph run و6 تحتاج human review |
| Final direct mock matrix | 20/20 campaigns exercised | 5 tool-confirmed، و15 candidate/review أو not-scanned |
| Full pytest | 633 passed, 66 warnings | كل regression suite أخضر |
| Test functions | 594 | أعلى من الحد الأدنى 537 |
| Ruff on modified files | Passed | لا توجد مخالفات على الملفات المعدلة |
| Compileall | Passed | لا توجد أخطاء syntax/import compile |

## Environment and safety boundary

تم clone نسخة WAPTLab كما هي، ومحاولة تشغيل Docker/Compose داخل بيئة معزولة. فشل startup قبل تشغيل التطبيق بسبب قيد kernel متعلق بجدول iptables `raw`. تم تسجيل القيد في [`waptlab_runtime_constraint.md`](waptlab_runtime_constraint.md)، كما تم توثيق الأدلة الساكنة في [`waptlab_static_ground_truth.md`](waptlab_static_ground_truth.md). لم يتم استخدام أي target خارجي، ولم يتم تنفيذ callback أو redirect خارج loopback من خلال WebPent.

الـmock موجود فقط لاختبار WebPent داخل مستودعه، ويستمع على `127.0.0.1`. جميع الطلبات تمر عبر HTTP helper وengagement-scope allowlist. وقد ظهر في الاختبار أن OriginPolicy منع redirect إلى `evil.example` بدل متابعته، وهو السلوك الأمني المطلوب.

## Final twenty-campaign matrix

الجدول التالي يجمع بين static ground truth من WAPTLab ونتيجة direct matrix الأخيرة المحفوظة في [`waptlab_mock_matrix.json`](waptlab_mock_matrix.json). عبارة **Tool-Confirmed** هنا تعني تأكيدًا على mock fixture فقط، وليس تأكيدًا live على WAPTLab.

| # | Campaign | Static/source expectation | Final WebPent matrix result | Evidence boundary |
|---:|---|---|---|---|
| 1 | Header-assisted SQLi | Header/query/logging surface موجود في المصدر | Needs Human Review | يحتاج SQLi differential أو oracle خاص بالـquery/log path |
| 2 | CSV ingestion SQLi | CSV path فيه string-built SQL branch | Needs Human Review | لم يتم إعلان SQLi بدون differential قابل للإعادة |
| 3 | JWT-encoded path traversal | JWT path يُفك ويُضم إلى storage path بدون canonicalization | Tool-Confirmed | marker `root:x` ظهر بعد controlled traversal replay على mock |
| 4 | Double-slash open redirect | redirect surface موجود | Not Scanned | OriginPolicy منع out-of-scope redirect؛ لم يتم تجاوز الحاجز |
| 5 | OAuth redirect URI validation | `redirect_uri` يقبل فحص suffix ضعيفًا ويستخدم `redirect()->away()` | Not Scanned | يحتاج إثبات redirect محلي أو reviewer مع الحفاظ على scope |
| 6 | Download IDOR | `/crm/download/{id}` يقرأ object بدون ownership check في المصدر | Needs Human Review | 200 public object candidate؛ owner-vs-foreign وnegative control مطلوبان |
| 7 | Tenant context switching | `db` query parameter يغير Elasticsearch context/index | Needs Human Review | heuristic صار يلتقط dashboard object surface، لكن confirmation تحتاج هويتين/tenant oracle |
| 8 | Training-email SSTI | source path defensive/allow-listed، والحملة target عام | Tool-Confirmed | harmless `{{17*23}}` أعاد `391` على mock فقط |
| 9 | Export-flow SSTI | user-controlled values تصل إلى `Blade::render()` في المصدر | Tool-Confirmed | harmless arithmetic differential أعاد `391` على mock فقط |
| 10 | Swagger URL SSRF | URL/configUrl fetch surface مع redirects في المصدر | Needs Human Review | replay/OOB callback غير متاح؛ private/out-of-scope controls بقيت فعالة |
| 11 | Image-fetch SSRF | image URL fetch يتبع redirects بعد hostname filtering ضعيف | Needs Human Review | يحتاج callback أو in-scope internal oracle |
| 12 | Stored profile XSS | description يُخزّن ويُعرض unescaped في المصدر | Needs Human Review | يحتاج store ثم readback/browser-context proof |
| 13 | Quoted-field XSS | name/email يصلان إلى attribute/form contexts | Needs Human Review | يحتاج context-specific browser rendering evidence |
| 14 | Elasticsearch snapshot traversal | URL-decoded path يحتفظ بـ`..` بعد snapshot validation | Needs Human Review | candidate structural surface؛ لا confirmation بدون bounded response oracle |
| 15 | Public backup disclosure | `.env`, backup, logs وartifacts surfaces متوقعة | Tool-Confirmed | bounded public artifact marker على mock؛ لا secret inventory claim |
| 16 | Laravel APP_DEBUG | runtime-dependent، وWAPTLab compose يضبط `APP_DEBUG=false` | Tool-Confirmed (mock only) | Laravel-style 500 trace marker على mock؛ لا يُسقط runtime override الحقيقي |
| 17 | Outdated frontend component | package/build assets هي source of truth | Needs Human Review | passive JavaScript intelligence لا يساوي vulnerability confirmation |
| 18 | Exposed Elasticsearch dependency | published ES ports/version surface في compose | Needs Human Review | يحتاج service-level runtime banner and exposure verification |
| 19 | OOB XXE | XML parser enables external entities/DTD features في المصدر | Needs Human Review | OOB callback غير متاح عمدًا داخل الاختبار |
| 20 | XSLT/XXE injection | XML/XSLT input يصل إلى `XSLTProcessor` مع document/copy-of surface | Needs Human Review | يحتاج controlled parser proof وcallback-safe oracle |

## What changed in WebPent

تمت التحسينات بأقل نطاق ممكن، مع الحفاظ على العقود السابقة وعدم تغيير `User` dataclass أو API contracts. أضيفت path heuristics أكثر تحديدًا لأسطح object/artifact/template/XML/SSRF/JavaScript بدل تحويل endpoints غير المصنفة تلقائيًا إلى XSS. كما تم توصيل `info_disclosure` و`idor` بالـstructural validator registry مع إبقاء campaign-level multi-step proof gaps كـhuman-review حتى لا ينخفض عدد فجوات الـVIP السبعة بشكل مصطنع.

تم تحسين info-disclosure validator لالتقاط Laravel-style debug traces على HTTP 5xx فقط عند وجود markers حساسة، مع إبقاء 404/500 العادي Clean. وتم إصلاح rabbit-hole mapping حتى backup/archive/log/dump/source artifacts تظل `info_disclosure` بدل تحويلها إلى SSRF. كذلك تم تعديل prioritization للسماح بترقية info-disclosure فقط عند وجود deterministic validator evidence.

أضيفت `scripts/run_waptlab_mock_matrix.py` لتشغيل validators الفعلية على عشرين probe محليًا مع scope allowlist رسمي. وأضيف `scripts/waptlab_mock.py` كـfixture اختبار مستقل، من غير أن يكون نسخة معدلة من WAPTLab. الـmock يفك form-urlencoded values في SSTI/CSV probes، ويستخدم منفذ التشغيل الحالي في الروابط حتى لا تختلط نتائج التشغيلات السابقة.

## False-positive and proof-loop policy

الـProof loop اتبع قاعدة ثابتة: لا توجد confirmation إلا عند وجود marker أو differential خاص بالفئة، reproducible، وغائب عن baseline. حالات IDOR لا تتأكد بمجرد HTTP 200؛ يجب وجود owner-vs-foreign identity matrix وnegative control. حالات SSRF لا تتأكد بمجرد قبول URL؛ يجب وجود in-scope internal oracle أو callback مصرح. حالات XXE/OOB تحتاج callback-capable proof. حالات XSS المخزنة تحتاج write/readback وcontext-aware rendering. لذلك بقيت هذه الحالات Candidate/Human Review بدل إدخال false positives في التقرير.

## Quality gates

تم تشغيل full suite بعد آخر تعديل، وكانت النتيجة **633 passed و66 warnings**. تم تشغيل Ruff على الملفات المعدلة فقط، ونجح compileall. كما تم تشغيل `verify_test_count.py --minimum 537`، وكانت النتيجة **594 test functions**. التحذيرات الحالية مرتبطة أساسًا بإصدارات LangChain/Pydantic وبـdev secrets الافتراضية، وهي موثقة ضمن baseline السابق ولم تمنع الاختبارات.

| Gate | Result |
|---|---|
| Full pytest | PASS — 633 passed |
| Test count | PASS — 594 functions |
| Ruff modified files | PASS |
| Python compileall | PASS |
| WAPTLab source unchanged | PASS — 0 source modifications |
| Scope safety | PASS — loopback allowlist; out-of-scope redirect blocked |
| Live runtime requirement | BLOCKED — Docker kernel iptables constraint, documented |

## Deliverables and supporting evidence

النتيجة الأساسية موجودة في هذا التقرير، مع matrix JSON قابل للمعالجة الآلية، وcoverage ledger، وcatalog YAML، وbaseline manifest، وreproducibility artifact، وPython dependency inventory، وstatic ground truth، وruntime constraint note. التقرير لا يخلط بين evidence الساكن، evidence الخاص بالـmock، وlive runtime evidence.

- [`waptlab_mock_matrix.json`](waptlab_mock_matrix.json)
- [`waptlab_coverage_ledger.json`](waptlab_coverage_ledger.json)
- [`waptlab_vulnerability_catalog.yml`](waptlab_vulnerability_catalog.yml)
- [`waptlab_baseline_manifest.json`](waptlab_baseline_manifest.json)
- [`waptlab_mock_reproducibility.json`](waptlab_mock_reproducibility.json)
- [`python_environment_inventory.json`](python_environment_inventory.json)
- [`waptlab_static_ground_truth.md`](waptlab_static_ground_truth.md)
- [`waptlab_runtime_constraint.md`](waptlab_runtime_constraint.md)
- [`vip_quality_gate.json`](vip_quality_gate.json)
- [`waptlab_regression.json`](waptlab_regression.json)

## References

[1]: https://github.com/selimwdev/WAPTLab "WAPTLab source repository"
[2]: ../src/webpent/agents/validator/active_checks.py "WebPent bounded active validators"
[3]: ../src/webpent/agents/validator/structural_checks.py "WebPent deterministic structural validators"
[4]: ../scripts/run_waptlab_mock_matrix.py "WebPent WAPTLab mock-backed matrix harness"
[5]: waptlab_static_ground_truth.md "WAPTLab static ground truth captured locally"
[6]: waptlab_runtime_constraint.md "Documented Docker runtime constraint"
