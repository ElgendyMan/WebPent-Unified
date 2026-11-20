# WebPent — V75 Engineering Maturity Scorecard

## الغرض وحدود الحكم

هذا المستند يعرّف مقياسًا هندسيًا شفافًا لـmaturity مشروع WebPent. الرقم ليس نسبة اكتشاف ثغرات، وليس عددًا تراكميًا للـfindings، وليس بديلًا عن qualification الخاصة بـVIP. لا يُسمح بتحويل candidate أو inventory أو نتيجة human review إلى confirmed finding.

> **الحكم الحالي:** WebPent حقق **76/100 في maturity الهندسية** وفق هذا المقياس، لكنه ما زال **NOT QUALIFIED كـVIP Smart Autonomous Bug Hunter**؛ لأن التشغيلات الحية، بما فيها جولة LLM الأخيرة، لم تثبت أي strict confirmed أو ProofBundle promoted.

## طريقة الحساب

المقياس موزون إلى ستة مكونات، ومجموع أوزانها 100 نقطة. النقاط الممنوحة لكل مكون لا تتجاوز وزنه، وتُمنح فقط عند وجود دليل قابل للمراجعة في الاختبارات أو artifacts أو commit pushed.

| المكوّن | الوزن | النقاط المتحققة | الحالة |
|---|---:|---:|---|
| Build وrelease quality | 20 | 20 | Verified |
| Scope وexecution safety | 20 | 20 | Verified |
| Discovery وcampaign coverage | 20 | 12 | Partially verified |
| Validator وproof completeness | 20 | 8 | Contract present; live proof missing |
| Autonomy وrecovery | 10 | 9 | Verified with end-to-end gap |
| Runtime qualification | 10 | 7 | Completed isolated smokes; not VIP-qualified |
| **الإجمالي** | **100** | **76** | **Engineering target reached** |

> **الحساب:** `20 + 20 + 12 + 8 + 9 + 7 = 76`.

## الأدلة الأحدث

| المجال | الدليل القابل للمراجعة |
|---|---|
| Regression | `1638 passed` و`6 skipped` في آخر full regression، مع نجاح Ruff وcompileall و`git diff --check` وsecret audit وG-02 checker |
| G-02 | direct-I/O inventory deterministic واختبارات G-02 المستهدفة ناجحة |
| Lifecycle | regression يمنع بقاء child tool orphan عند موت orchestrator الأب، مع parent-death safeguard |
| Scope وauthority | Security Invariant Suite تغطي dot-segments/encoded traversal، authority denials، ledger states، engagement continuity، وProofBundle promotion |
| LLM boundary | structured tuple inputs تعامل كبيانات غير موثوقة، وdiagnostics لا تعيد secrets؛ provider-aware overrides اختُبرت محليًا، وLLM failure يرجع إلى fallback ولا يرقّي evidence |
| Benchmark | golden benchmark offline-contract يفصل FDR عن FPR ولا يدّعي live discovery |
| Runtime smoke | WAPTLab محلي مصرح به: جولة LLM مستقلة أنتجت 1 candidate و0 confirmations؛ Chromium متاح، بينما typed browser handler وأدوات httpx/nuclei/katana ما زالت gaps |
| Reports | جولة WAPTLab LLM صدّرت `report.json` و`report.html` و`report.md`؛ PDF تخطّى بسبب غياب renderer في البيئة، ولم يُعتبر ذلك نجاحًا زائفًا |
| Discovery limit | التشغيلات التاريخية المنفصلة احتوت WAPTLab: 4 وJuice Shop: 6 candidates؛ الجولة LLM الجديدة WAPTLab: 1 candidate. الأرقام ليست confirmations تراكمية |
| Proof limit | `strict_confirmed=0`، و`promoted ProofBundles=0` |
| Source provenance | أحدث source commit المنشور قبل توثيق هذه الجولة هو `8f83c7a`، ويضيف provider-aware model overrides؛ التوثيق يضيف readiness artifact لهذه الجولة |

## نتائج اللابات المحلية المصرح بها

تم تشغيل WAPTLab وJuice Shop تاريخيًا في workspaces وengagements منفصلة داخل شبكات Docker داخلية، مع عدم استخدام credentials أو signup أو targets عامة. كما شُغّلت جولة WAPTLab مستقلة مع LLM مفعّل و`smart-observe` وworkspace جديد. في جميع الجولات لم يتم احتساب أي candidate كـconfirmed.

| مقياس qualification | النتيجة |
|---|---:|
| Lab runs completed | 3 target-separated runs، منها جولة WAPTLab واحدة مع LLM |
| Qualifying runs completed | 0 |
| Scan completed | Yes في أحدث smoke |
| Target reachable | Yes |
| Live target executed | Yes |
| Candidate rows | historical: WAPTLab: 4؛ Juice Shop: 6. LLM-enabled WAPTLab: 1 |
| Strict confirmed | 0 |
| Promoted ProofBundles | 0 |
| Qualification status | NOT QUALIFIED |

الحالات التشغيلية الموجودة في التقرير تشمل `tentative` و`pending` و`needs human review`، بالإضافة إلى سجلات campaign مثل `not_observed` و`missing-validator`. هذه ليست strict findings ولا تدخل في confirmation count.

## لماذا لا يساوي 76% حالة VIP؟

حالة VIP تتطلب دليلًا أقوى من جودة البناء أو اكتمال التقرير. الترقية الصارمة تحتاج **target-backed causal signal**، و**independent negative control**، و**sealed/replayable ProofBundle**، ثم replay ناجح، وبشكل قابل للتكرار عبر جولات qualification المطلوبة. التشغيلات الحالية أثبتت أن provider fallback وredaction يعملان بدون ترقية تلقائية، لكنها لم تثبت causal proof لأي finding؛ لذلك الإبقاء على `NOT QUALIFIED` هو الحكم الصحيح fail-closed.

كما أن فجوات التغطية مثل `not_observed` و`missing-validator` ليست findings. لا يجوز سدها بتخمين routes أو بإرسال transport غير مصرح أو بتغيير قواعد promotion.

## الخطوات المتبقية للوصول إلى VIP فعليًا

الخطوة التالية ليست تشغيل جولات عشوائية. يجب أولًا جعل smoke مكتملًا ينتج ProofBundle حقيقيًا لكل ترقية مرشحة، مع causal signal وnegative control وsealed replay. بعد نجاح ذلك فقط تُجرى الجولات الثلاث المطلوبة بنفس thresholds، وتُحسب precision وreproducibility من artifacts مستقلة. إلى أن يحدث ذلك، يظل المشروع في حالة **engineering maturity target reached / VIP qualification pending**.

## مراجع داخلية

| المرجع | الغرض |
|---|---|
| [`v75_maturity_scorecard.json`](./v75_maturity_scorecard.json) | المصدر الآلي للأوزان والنقاط والحكم |
| [`RELIABILITY_RELEASE_GATES.md`](./RELIABILITY_RELEASE_GATES.md) | نتائج reliability وworker/release gates |
| [`GOLDEN_BENCHMARK.md`](./GOLDEN_BENCHMARK.md) | عقد benchmark والـmetrics offline |
| [`SECURITY_INVARIANT_SUITE.md`](./SECURITY_INVARIANT_SUITE.md) | اختبارات السلطة والنطاق والحالات والأدلة |
| [`V97_EXECUTION_STATUS.md`](./V97_EXECUTION_STATUS.md) | التقرير التاريخي السابق وحالته NOT QUALIFIED |
| [`direct_io_inventory.json`](./direct_io_inventory.json) | inventory deterministic الخاص بـG-02 |
| `/home/ubuntu/upload/webpent_phase10_1882b42/` | artifact runtime خارج Git للـsmoke الأخير |
