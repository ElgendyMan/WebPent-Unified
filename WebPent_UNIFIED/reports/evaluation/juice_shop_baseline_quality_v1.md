# Juice Shop Local Baseline Quality Run v1

## Decision scope

هذا التقرير يوثّق **baseline محليًا مصرحًا به ومحصورًا في loopback** لنسخة Juice Shop المحلية، وليس اعتماد P10 أو VIP. التشغيل استخدم WebPent full-run harness والـground-truth mapping الحالي، وسجّل metadata وdigests فقط؛ لم تُحفظ response bodies أو headers أو cookies أو credentials أو probe values.

## Reproducibility checkpoint

| Item | Result |
|---|---|
| Run ID | `baseline-20260826-01` |
| Target | `http://127.0.0.1:3000` |
| Juice Shop package | `20.2.0` |
| Local source commit | `1618a611b173b4bf114028e6e02549950606e29d` |
| Ground-truth mapping | `docs/juice_shop_p10_ground_truth_v1.json` |
| Independent source/catalog snapshot | `audit/juice_shop_ground_truth_snapshot_v1.json` |
| Live catalog | available; HTTP 200; body digest only |
| Target contact | `true` |
| Approved mapped cases executed | `11 / 11` |
| Central store | `true` |
| Central ProofBundle seal verification | `true` |
| Central replay | `true` |
| Qualification claim | `none` |

## Baseline outcome

| Outcome | Cases | Case IDs |
|---|---:|---|
| Proof-backed confirmation | 3 | `juice.error_handling.v1`, `juice.exposed_metrics.v1`, `juice.local_xss.v1` |
| Observation-only | 4 | `juice.directory_listing.v1`, `juice.public_scoreboard_route.v1`, `juice.security_policy.v1`, `juice.well_known_security_policy.v1` |
| Blocked by precondition | 4 | `juice.access_log_disclosure.v1`, `juice.forgotten_backup.v1`, `juice.misplaced_signature_file.v1`, `juice.privacy_policy_proof.v1` |
| Approved mapping cases | 11 | All approved mapped cases were contacted/accounted for |

The three proof-backed cases produced target-backed baseline/candidate/negative-control observations and centrally sealed/replayable ProofBundles. The `local_xss` result used the reviewed DOM-safe workflow. The error and metrics cases used the registered semantic profiles. The four blocked cases were fail-closed and did not create findings. The four observation-only cases were deliberately not promoted because route/resource existence or metadata is not itself a causal vulnerability proof.

## Evaluator decision

The evaluator returned `p10_passed=false` and withheld precision, recall, case coverage, and class coverage. This is the correct fail-closed result because the current independent oracle review accepts only three cases/classes and the acceptance contract requires a larger approved set plus three isolated runs. The eight remaining approved-mapping cases are **not scored** and are **not false negatives**.

| Metric | Baseline value |
|---|---:|
| Approved oracle cases | 3 |
| Approved vulnerability classes | 3 |
| Not-scored expected cases | 8 |
| True positives used for official metrics | 0 |
| False positives | 0 |
| False negatives | 0 |
| Precision | `null` |
| Recall | `null` |
| Case coverage | `null` |
| Class coverage | `null` |
| P10 | `NOT_QUALIFIED` |

## Diagnose

لا توجد FN أو FP قابلة للاعتماد في هذا baseline، لأن metrics محجوبة عمدًا قبل إغلاق oracle approval وتشغيل المجموعة الكاملة. ولا توجد confirmation ضعيفة ضمن الحالات الثلاث proof-backed: كل واحدة مرّت central verifier وseal/replay، بينما الحالات الأخرى توقفت أو بقيت observation-only وفق العقد.

القصور الفعلي target-local في **coverage of causal oracle contracts and safe preconditions**. تحديدًا، الحالات الثماني تحتاج إما semantic causal oracle مستقلًا أو precondition آمنًا قابلًا للتحقيق مع negative control مستقل، قبل أن تصبح مؤهلة للـProofBundle. لا يوجد مبرر لتعديل Generic Core أو Proof Pipeline بناءً على هذه النتيجة.

## Improvement decision

تُغلق حلقة baseline الحالية عند التشخيص ولا تُعلن improvement code change. الخطوة الصحيحة التالية هي إعداد واعتماد contracts منفصلة للحالات الثماني فقط، مع الحفاظ على:

- metadata/DOM-safe evidence؛
- independent negative control؛
- target-backed observations؛
- central sealing and replay؛
- عدم اعتبار HTTP 200 أو resource existence finding؛
- عدم إدخال authenticated, external-destination, state-changing, أو raw-data workflows؛
- عدم تغيير Generic Core أو frozen P10 artifacts.

بعد اعتماد هذه contracts فقط يمكن بدء **Improve → Re-test → Compare** للحالات المعنية. لا يجوز تحويل نتيجة هذا baseline إلى P10/VIP qualification.

## Evidence references

- Run artifact: `audit/juice_shop_baseline_quality_run_v1.json`
- Evaluator artifact: `audit/juice_shop_baseline_quality_evaluation_v1.json`
- Independent source/catalog snapshot: `audit/juice_shop_ground_truth_snapshot_v1.json`
- Ground truth mapping: `docs/juice_shop_p10_ground_truth_v1.json`
- Full-run harness: `scripts/run_juice_shop_p10_full.py`
- Evaluator: `scripts/evaluate_juice_shop_p10.py`
