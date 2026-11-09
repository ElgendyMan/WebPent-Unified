# Bounded Autonomy and Knowledge-Gap Contract

## Scope

هذا العقد يصف orchestration فقط. لا يمنح controller صلاحية transport، ولا ينشئ target scope، ولا يحوّل hypothesis أو knowledge gap إلى finding. كل action فعلي يمر عبر `ActionExecutor` ثم `ActionAuthority`، وتظل confirmation مشروطة بـtarget-backed causal signal وindependent negative control وsealed/replayable ProofBundle.

## Deterministic bounds

| Boundary | Contract | Fail-closed result |
|---|---|---|
| Controller iterations | `max_iterations` و`iterations` محصوران في 1..10، وتُحترم قيمة الاستدعاء الأقل | `iteration_budget_exhausted` |
| Action cost | `ActionBudgetState.limit` محصور في 0..1000، ولا يُنفَّذ batch إذا تجاوز التكلفة المتبقية | `action_budget_exhausted` |
| Replanning | `replans_limit` و`max_recovery_attempts` محصوران، والـretry لا يحدث إلا لفشل infrastructure | `recovery_budget_exhausted` |
| Duplicate action | idempotency signature تمنع تكرار نفس action داخل invocation | `same_action_repeated` |
| Information gain | task تحت threshold لا يُنفّذ | `expected_information_gain_below_threshold` |
| No progress | إذا لم يضف التنفيذ evidence أو state delta يتوقف controller | `no_new_evidence_or_state_delta` |
| Contradictory control | negative-control contradiction يوقف الاستكشاف ولا يرقّي finding | `negative_control_contradicts_theory` |

## Knowledge gaps

Knowledge gaps هي عناصر تخطيط أو قياس coverage فقط. لا تُعد observed surface، ولا تمنح validator أو capability، ولا تبرر transport من غير same-origin observed reference وpreconditions مثبتة. أي gap بلا evidence مرجعي أو capability متاحة يبقى gap أو blocked task.

## Recovery

Recovery يعيد التخطيط فقط بعد `infrastructure_failure` وبحد attempts صريح. لا يُعاد تشغيل policy-denied أو blocked-by-precondition كأنه transient failure، ولا تُزال بوابات scope أو authority أو proof أثناء recovery. كل محاولة تُسجل في `recovery_events` ببيانات redacted فقط.

## Evidence interpretation

`executed` يعني أن action مرّ عبر executor، وليس أنه finding confirmed. لا يضيف controller causal graph edge إلا عند اكتمال proof promotion contract، ولا تُحسب candidates أو coverage plans أو offline fixtures كـstrict confirmation.

## Verification

العقد مغطى باختبارات `tests/test_autonomy_contracts.py` و`tests/test_v94_autonomous_controller.py` و`tests/test_vip_recovery_loop.py`، بما في ذلك budget exhaustion، bounded recovery، duplicate-action stop، prerequisite blocking، وno-progress stop.
