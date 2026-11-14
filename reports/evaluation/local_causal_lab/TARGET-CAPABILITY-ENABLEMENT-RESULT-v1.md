# Target Capability Enablement + First Real Causal Confirmation

## Final decision

النتيجة الرسمية للـmilestone هي **BLOCKED عند capability preflight**. تم تنفيذ وتحقق WebGoat causal experiment profile الجديد، لكن لم تتوفر capability آمنة ومصرح بها توفر owner وattacker `LessonSession` مستقلتين، وموردًا owner-owned قابلًا لإعادة الضبط، وملاحظة authorization دلالية، وnegative control مستقل. لذلك لم يتم إرسال أي request، ولم يتم إنشاء target-backed CONFIRMED finding.

> لم يتم تحويل غياب الدليل إلى confirmation. عدم وجود target-backed ProofBundle هنا نتيجة fail-closed صحيحة، وليس فشلًا في detection quality.

## What was executed

تم تحليل source/runtime provenance محليًا، والتحقق من profile الجديد الذي يستخدم baseline/candidate/negative-control definitions مختلفة عن flow B2/B2.1 التاريخي. تم تشغيل اختبارات profile وreadiness، ثم اختبارات causal/verifier/security التي تثبت حجب non-CONFIRMED bundle وإعادة التحقق من origin/seal/replay metadata. لم تتم إعادة تشغيل flow القديم، ولم يتم استخدام login أو credentials أو bypass أو state mutation أو external target.

| البند | النتيجة |
|---|---|
| WebGoat source/runtime alignment | `runtime_digest_verified=true`; source commit وjar digest مثبتان |
| Network scope | Loopback-only policy verified |
| Profile tests | 6 passed |
| Causal/verifier/security regression | 23 passed |
| Corrected combined target/proof gate | 29 passed |
| Target preconditions | `false` |
| Target-backed observations | `0` |
| Oracle decision | `BLOCKED` |
| Target-backed ProofBundles | `0` |
| Successful target replay | `0` |
| Scoring promotion | `false` |

## Capability gap

الـsource الحالي يربط الموارد بهوية `LessonSession` الحالية، ولا يوفر ضمن النطاق المعتمد آلية target-local آمنة لإنشاء حالتي owner/attacker مستقلتين مع resource disposable وreset/state hash. endpoint الخاص بالـlogin يغيّر session state، واستخدامه أو توفير credentials يحتاج موافقة مالك صريحة منفصلة، وليس جزءًا من هذا التنفيذ.

إعادة فتح المسار تحتاج capability معتمدة ومحدودة توفر synthetic owner، synthetic attacker، opaque owner-owned resource، ownership relation قابلة للملاحظة، snapshot/restore حتمي، baseline owner ناجحًا، candidate attacker على نفس resource، وnegative control مستقل. يجب أن تكون الملاحظة semantic وليست status/redirect/route/source-only.

## ProofBundle and replay result

لم توجد observations فعلية، ولذلك لم يُستدعَ مسار بناء target-backed ProofBundle ولم يُنشأ seal مصطنع. اختبارات الـcentral verifier أثبتت أن حالات `BLOCKED` وغياب observations لا تُرقّى إلى scoring bundle، وأن replay يتحقق من origin وdecision وinvariant وevidence references وdigest عند وجود bundle صالح.

## Case Registry preparation

تم إنشاء structure توثيقي فقط يضم vulnerability-class registry، approved-case schema، evidence maturity levels، وpromotion workflow. الحالة الحالية `webgoat.idor.view_other_profile.causal-vnext` مسجلة كـ`L1_SOURCE_CANDIDATE` و`BLOCKED`، وليست approved scoring case.

## Gate results

| Gate | Result |
|---|---|
| `git diff --check` | PASS |
| `compileall` | PASS |
| Ruff | PASS |
| Corrected targeted regression | PASS: 29 passed |
| Full pytest | 2005 passed, 4 historical failures |
| G-02 direct-I/O | PASS |
| Generic neutrality | PASS |
| Tracked secret scan | PASS |
| Release provenance validator | PASS |

الأخطاء الأربعة في full pytest هي `approval_source_hash_mismatch` التاريخية الخاصة بـOption B. تم إبقاؤها fail-closed، ولم يتم تعديل historical approval source أو validator لإخفائها.

## Governance boundary

تظل `official_isolated_p10_runs_authorized=false`، و`P10/P9/VIP=NOT_QUALIFIED`، وBug Bounty=`BLOCKED`، و`human_independent_signoff_obtained=false`. الـBLOCKED case لا تُحسب TP أو FP أو FN أو clean، ولا ترفع أي metric لجودة الكشف.
