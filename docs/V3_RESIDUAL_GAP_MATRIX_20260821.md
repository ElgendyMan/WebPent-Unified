# WebPent v3 Residual Gap Matrix

هذه المصفوفة هي سجل العمل التنفيذي لخطة `webpent_v3_strict_ai_executable_vip_implementation.md`. لا تُغلق أي فجوة بالوثائق وحدها؛ الإغلاق يحتاج code path فعليًا، اختبار قبول، وartifact runtime قابل للمراجعة.

آخر مراجعة: 2026-08-21، working tree يتضمن تنقيح production الحالي قبل commit الإصدار النهائي.

آخر بوابات محلية مثبتة: **1108 passed، 0 failures، Ruff=0، compileall=pass، diff-check=pass**؛ ونجح `pip-audit` على lock-derived external requirements وCompose config بمتغيرات production مؤقتة.

| ID | الفجوة | الوضع الحالي المثبت | البوابة | الحالة | معيار الإغلاق المتبقي |
|---|---|---|---|---|---|
| G-01 | لا يحصل كل graph node على RuntimeContext جامع | `build_initial_state` ينشئ RuntimeContext واحدًا لكل تشغيل، ويضعه في PentestState مع `campaign_id`; CLI/worker يستفيدان من نفس entrypoint، وcheckpoint boundary يخزن descriptor فقط ويعيد live context عند resume. Regression في runtime spine وSQLite checkpoint نجحا. | G2 | **CLOSED** | إبقاء أي node لا يستهلك context صراحةً fail-closed؛ لا توجد فجوة حقن متبقية في entrypoint/resume contract |
| G-02 | ActionExecutor لا يملك كل transports مركزيًا | كل transport الفعلي صار مسجلًا في `docs/direct_io_inventory.json` و`docs/DIRECT_IO_INVENTORY.md`: HTTP sync/async، Playwright، raw TCP/DNS، subprocess، مع توثيق API/GraphQL/upload/OOB كـlogical HTTP transports. اختبار G-02 يطابق source AST مع artifact ويمنع unclassified أو غير allowlisted sites. | G2 | **CLOSED** | qualification الحية لكل capability تظل منفصلة؛ لا confirmation بدون verifier/ProofBundle |
| G-03 | ProofBundle ليس mandatory عالميًا | `normalize_finding_for_export` يفرض promotion gate في كل مسارات التصدير، ويخفض Tool-Confirmed غير المدعوم بـProofBundle إلى Needs Human Review، مع regressions. | G7 | **CLOSED** | لا توجد فجوة في export promotion؛ أي enforcement إضافي خارج exporter يحتاج qualification مستقلة وليس ادعاءً جديدًا |
| G-04 | proof engine يخطط ولا يفرض promotion | normalization المركزي في report quality/export يفرض causal signal/negative-control/ProofBundle contract على التصنيف المصدّر، ويحوّل الحالة غير المدعومة إلى Needs Human Review مع سبب قابل للمراجعة. | G7 | **CLOSED** | qualification الحية لا تزال مطلوبة لإثبات المزيد من الحالات، ولا تُحوّل candidate إلى confirmed تلقائيًا |
| G-05 | AutonomousController غير موصول بالكامل | controller bounded وموجود، ويتطلب context وhandler؛ graph wiring لا يضمن injected context لكل مسار | G5 | **PARTIAL** | graph-level injection، recovery events، bounded parallel independent actions، وcoverage closure artifact |
| G-06 | Smart/VIP profile opt-in وlegacy defaults | `profile_requires_proof_bundle` مربوط بـinitial_state وreporter؛ VIP/authorized profiles تفرض proof bundle وidempotency، مع بقاء legacy compatibility صريحة. | G1/G5 | **CLOSED** | لا fallback صامت داخل VIP؛ legacy يظل مسار توافق معلنًا فقط |
| G-07 | secure defaults غير production-grade بكل المسارات | Settings تفرض CORS صريحًا، rate limiting، Redis TLS، TLS verification، وhard-stop للـnon-lab عند الإعدادات غير الآمنة، مع regression config matrix. | G1 | **CLOSED** | lab compatibility لا تُعد production posture؛ يجب عدم تشغيل non-lab بإعدادات dev غير صريحة |
| G-08 | direct I/O inventory غير محكوم بCI allowlist | `tests/test_g02_direct_io_inventory.py` (Sprint I-1b B.3: now EXISTS and wired into CI) re-runs `src/webpent/shared/direct_io_inventory.py:scan_direct_io()` on src/ and fails on drift from the recorded artifact `docs/direct_io_inventory.json`; `APPROVED_DIRECT_FILES` governs raw imports/calls with logical transport contracts. NOTE: `scripts/scan_direct_io.py` cited in the original row never existed — the scanner is the module function above. OPEN SUB-GAP (fail-closed PIN, tracked): exactly 18 raw-transport records (15 distinct identities) in 8 files are not in any approval list; pinned by tests/test_g02_direct_io_inventory.py::test_unapproved_site_gap_is_pinned_fail_closed_on_new_sites — any NEW unapproved site fails the build. Pending security-engineering adjudication. | G2 | **CLOSED (drift gate + unapproved-site pin); approval of the 18 known sites is an open security work item** | أي transport جديد يتطلب إعادة توليد artifact ومراجعة allowlist؛ qualification التشغيلية لا تُستنتج من static inventory وحده |
| G-09 | discovery graph/intent/browser/body/schema coverage غير live-qualified | HTTP وJS discovery وsurface provenance تحسنت، بما فيها bounded route materialization؛ qualification الحية لم تثبت كل أنواع surface | G3 | **PARTIAL** | live artifact يثبت browser/API/GraphQL/body/multipart provenance مع replay-safe records |
| G-10 | identity/tenant/object/workflow replay غير موحد | multi-identity وbasket object provenance وfail-closed identity guard موجودة جزئيًا؛ WAPTLab أثبت IDOR واحدًا، وJuice Shop لم يثبت strict في آخر run بسبب OOM | G4 | **PARTIAL** | second identity + two objects + tenant state + cleanup + replay/evidence artifacts في qualification مستقلة |
| G-11 | knowledge gaps وNBA وautonomous recovery غير مكتملة | engines وsmart campaigns وbounded replanning موجودة، لكن evidence أن graph يغلق gaps عبر recovery غير مكتمل | G5 | **OPEN** | typed gaps، expected information gain، recovery loop، negative evidence، وartifact لكل round |
| G-12 | validators المعقدة ناقصة | validator registry وcontracts موجودة، لكن كل classes المطلوبة في الخطة ليست qualified end-to-end | G6 | **OPEN** | plugin contract لكل class مع oracle/control/cleanup/replay/proof وnegative tests |
| G-13 | external adapters وcapability image غير qualified | nuclei/dalfox وغيرها لها wrappers/fallbacks وcapability report؛ end-to-end executable/version/hash/health qualification ناقصة | G8 | **PARTIAL** | health/version/hash/fallback evidence لكل capability داخل image نفسها |
| G-14 | Celery/Redis/resume/multi-worker/Docker qualification ناقصة | عقود واختبارات جزئية موجودة، لكن critical-path live Docker/worker qualification غير مكتملة | G8 | **PARTIAL** | consume-once، fencing، crash recovery، secure transport، وDocker E2E artifact |
| G-15 | precision/recall/reproducibility غير مقاسة live | WAPTLab v5: 35 findings و1 Tool-Confirmed IDOR مع evidence bundle؛ Juice Shop v17: 72 findings و0 strict، والجولة ترافقت مع Node heap OOM؛ لا توجد 3 clean runs كاملة مع ground truth | G9/G10 | **OPEN** | ground truth موثق + 3 clean runs + precision/recall/reproducibility hashes |
| G-16 | prompt-injection/direct transport adversarial tests غير مكتملة | توجد security regressions scope/cookie/marker/infra، لكن تغطية prompt/tool/evidence/secrets/promotion bypass ليست كاملة | G1/G5/G9 | **PARTIAL** | adversarial matrix كاملة مع فشل آمن لكل bypass class |
| G-17 | release artifacts والقرار النهائي غير مكتملين | manifest/SBOM/Bandit/preflight/capability/qualification/quality-gate artifacts محدثة، والـgate يظل صادقًا `passed=false` بسبب blockers الحية. production readiness report وhandoff محدثان، والـZIP النهائي يجب إعادة بنائه بعد commit هذا التنقيح. | G10 | **CLOSED** | artifact contract مغلق؛ live worker/Docker qualification وoperator signing وbackup/restore evidence ما زالت تشغيلية |

## النتائج الحية المثبتة

| المعمل | الجولة | Findings | Tool-Confirmed | Evidence bundles | ملاحظة |
|---|---:|---:|---:|---:|---|
| WAPTLab | v5 | 35 | 1 | 1 | IDOR مؤكد بأدلة causal signal وnegative control |
| Juice Shop | v17 | 72 | 0 | 0 | لا strict confirmation؛ المسح تأثر بـNode.js heap OOM |

## قاعدة الحالة

`OPEN` يعني أن التنفيذ أو الإثبات ناقص. `PARTIAL` يعني أن جزءًا من العقد موجود لكن qualification أو enforcement أو artifact ناقص. لا تتحول الفجوة إلى `CLOSED` إلا بعد اختبار قبول وartifact قابل لإعادة المراجعة.

## ترتيب التنفيذ التالي

1. إغلاق artifacts وrelease manifest وrollback evidence وتحديث quality gate.
2. توحيد graph-level RuntimeContext ومنع fallback الصامت.
3. جعل ProofBundle/promotion gate مركزيًا، ثم إكمال direct-I/O inventory — **تم إغلاق G-02 وG-08 بالـAST artifact وCI contract** (Sprint I-1b: drift gate + unapproved-site pin مفعلين؛ 18 sites معروفين بانتظار adjudication).
4. تشغيل worker/Docker qualification والـlive clean runs فقط بعد ثبات البوابات المحلية.
5. عدم إعلان VIP Smart Autonomous Bug Hunter قبل تحقق G0–G10 فعليًا.
