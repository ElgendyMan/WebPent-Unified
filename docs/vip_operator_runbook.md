# WebPent VIP Operator Runbook

## Scope

هذا الدليل يصف تشغيل WebPent في بيئة مصرح بها فقط. هذه النسخة لا تتصل بـWAPTLab تلقائيًا، ولا تعتبر أي artifact محلي تأهيلًا حيًا. كل finding يحتاج causal signal وnegative control وProofBundle قابلًا لإعادة التشغيل قبل أن يصل إلى Tool-Confirmed.

## Preflight

1. تحقق من commit والـworking tree والـrelease manifest والـSBOM.
2. شغّل `python verify_all.py`، الاختبارات الكاملة، Ruff، و`compileall`.
3. تأكد أن destructive actions مرفوضة دائمًا، وأن نطاق الهدف وengagement/client isolation صحيحان.
4. استخدم credentials أو cookies من vault/CLI فقط؛ لا تضعها في report أو artifact أو command history.
5. تحقق من أن OOB receiver، إن كان مطلوبًا، مصرح به ومقيد بالـengagement.
6. لا تبدأ أي live run إذا فشل preflight أو كان manifest hash غير متطابق.

## Execution policy

- `authorized-active` لا يلغي destructive deny.
- كل action يمر عبر ActionAuthority وscope/approval/budget/idempotency checks.
- Tool failure ينتج `infrastructure_failure` أو `inconclusive`، وليس confirmation.
- الـLLM fallback يشرح القرار أو يقترح research، لكنه لا يخلق evidence ولا يرفع confidence.
- لا تستخدم offline fixtures كبديل عن target behavior.

## Pause/resume

عند rate limit، auth expiry، OOB uncertainty، أو evidence gap: أوقف المسار، احفظ checkpoint، احفظ redacted trace، وجدولة retry bounded فقط إذا كان policy يسمح. عند الاستئناف أعد التحقق من scope والـengagement والـvault state؛ لا تعيد إرسال action غير idempotent دون reservation/ledger check.

## Reporting

انشر فقط findings التي تحمل request context، response evidence، causal signal، negative control، replay metadata، وredacted ProofBundle. افصل `Tool-Confirmed` عن `Needs Human Review` و`Not Scanned`. لا تستخدم عدد findings التراكمي لتحقيق acceptance؛ القياس الحي يجب أن يكون داخل دورة واحدة.

## Release stop conditions

أوقف التسليم إذا فشل أي gate، ظهر secret في artifact، تغير manifest بعد بنائه، أو كان توقيع operator مطلوبًا ولم يُرفق. الأرشيف المحلي لا يصبح release candidate إلا بعد تحقق hash والـredaction.

## Current-cycle boundary

لم يتم تشغيل WAPTLab في دورة إعداد هذا الدليل. لذلك live qualification، precision/recall على ground truth حي، وإثبات 15–20 Tool-Confirmed غير متاحين في هذا artifact.
