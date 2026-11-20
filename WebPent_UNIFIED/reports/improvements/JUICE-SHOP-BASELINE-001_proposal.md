# Improvement Proposal — JUICE-SHOP-BASELINE-001

## Status

`diagnosed_pending_contract_approval`

هذا proposal مبني على baseline محلي فعلي لـJuice Shop، لكنه **ليس** موافقة تنفيذية ولا P10 qualification. لا يوجد FN أو FP معتمد في baseline لأن evaluator حجب metrics وفق ground-truth gate.

## Observed gap

تم تشغيل 11 حالة mapping-approved/accounted-for. ثلاث حالات فقط تملك oracle semantics قادرة على إنتاج proof-backed confirmation حاليًا: `juice.error_handling.v1`, `juice.exposed_metrics.v1`, و`juice.local_xss.v1`. ثلاث حالات بقيت observation-only، وخمس حالات توقفت `blocked_by_precondition`.

هذا ليس فشلًا في GenericCaseRunner أو Proof Pipeline. السبب الجذري هو أن الحالات الثماني غير scoring لا تملك حاليًا contract مستقلًا مكتملًا يجمع vulnerability semantics، target-backed causal signal، negative control، وsealed/replayable proof ضمن نطاق read-only الآمن.

## Proposed bounded improvement

لكل حالة من الحالات الثماني، يجب تقديم contract منفصل يحدد بوضوح:

1. semantic predicate يثبت vulnerability semantics ولا يعتمد على HTTP status أو endpoint existence وحدهما؛
2. baseline/candidate/control observation roles؛
3. independent negative-control path داخل نفس target scope؛
4. target fingerprint وrequest/response digests دون raw body/header/cookie retention؛
5. safe precondition لا يتطلب credentials أو state mutation أو external destination؛
6. central verifier integration فقط، مع `verify_seal()` وreplay؛
7. regression tests للحالات blocked وsuccess، مع fail-closed behavior؛
8. rollback criterion: إزالة target-local adapter change تعيد السلوك السابق دون تعديل Generic Core.

## Exclusions

الـproposal لا يضيف payloads أو auth workflows أو external redirects أو SSRF/OAST أو state-changing actions. لا يعيد تصنيف observation-only أو blocked cases كـFN، ولا يغيّر ground-truth approval counts يدويًا، ولا يغيّر Generic Core أو frozen P10 artifacts.

## Acceptance gates

| Gate | Required condition |
|---|---|
| Contract review | independent approval لكل oracle predicate قبل التنفيذ |
| Safety | loopback/read-only، no credentials، no raw sensitive data |
| Causality | baseline/candidate/control target-backed وبفروق قابلة للتفسير |
| Proof | central verifier، sealed bundle، `verify_seal()=true`، replay=true |
| Regression | blocked baseline محفوظ وready/success path مثبت حيث ينطبق |
| Comparison | same conditions before/after، دون metrics قبل إغلاق oracle gate |
| Qualification | لا P10/VIP claim من هذا proposal وحده |

## Next decision

قبل أي code change، تُراجع وتُعتمد contracts المرشحة بشكل مستقل. إن لم يمكن بناء causal oracle آمن لحالة معينة، تبقى `not_scored` أو `blocked_by_precondition` ولا تُحتسب FN.
