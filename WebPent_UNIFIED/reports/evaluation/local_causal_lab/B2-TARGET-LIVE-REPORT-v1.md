# B2 Target-Live Local Causal Lab Report v1

## Executive result

تم تنفيذ النطاق المصرح به داخل اللاب المحلي فقط بعد استيراد موافقة المالك من `pasted_content.txt` بالـSHA-256 التالي:

`b3284fde9ca1c61ad93d54bc974a60a598b50079141392ab589df1d23f3c0737`

أصبح WebGoat target-live **جاهزًا من ناحية runtime/build alignment**، وتم تنفيذ دورة GET-only bounded على حالة IDOR. لكن الـnormal application authentication لم يُنتج جلسة LessonSession صالحة للحالة؛ لذلك كانت الملاحظات الثلاثة redirects متطابقة دلاليًا، وصنّف الـcausal oracle النتيجة `INCONCLUSIVE`. لم يتم إنشاء ProofBundle scoring أو promotion.

ظل crAPI `BLOCKED` لأن requester/owner fixture injection وreset القابلين للتحقق غير متاحين بدون state mutation أو credential/token material خارج ما أمكن إثباته بأمان.

> هذه النتيجة ليست Official P10، ولا تغيّر أي بوابة P10/P9/VIP أو Bug Bounty.

## Execution matrix

| Target / case | Runtime readiness | Observations | Oracle | Evidence | Final classification |
|---|---|---|---|---|---|
| WebGoat IDOR | Ready; source revision وjar وloopback service alignment مثبتة | Baseline/candidate/independent control نفذت كـGET؛ كلّها HTTP 302 بدون lesson completion | Evaluated؛ causal signal=false | Raw bodies/cookies غير محفوظة؛ ProofBundle withheld | `INCONCLUSIVE` |
| WebGoat path traversal | لم يُنفذ | لا يوجد safe target-local canary route مثبت؛ raw traversal ممنوع | Not evaluated | لا يوجد | `BLOCKED` |
| crAPI object-access cases | غير جاهز | لا توجد requester/owner observations | Not evaluated | لا يوجد | `BLOCKED` |

## WebGoat attestation

تم إثبات العناصر التالية قبل إرسال طلبات الحالة:

| Check | Result |
|---|---|
| Source revision | `7517acca95d9851da706452454c223dd13545ef4` |
| Built artifact | `/tmp/webgoat-source/target/webgoat-2026.2-SNAPSHOT.jar` |
| Artifact SHA-256 | `694626342150c1263288834fd722ec636639a36c92a68fc6a62154823dec8edb` |
| Java 25 binary SHA-256 | `7380ce48ed5013735d2c8414db54adb8f981e7933ff594bd36f3baccddaafba3` |
| Service cwd | `/tmp/webgoat-source` |
| Open jar file descriptor | Verified |
| Listener | `[::ffff:127.0.0.1]:8080` |
| Service-to-build alignment | Attested |

## Safety and evidence handling

تم استخدام loopback فقط. الـcandidate/control requests كانت GET-only. تم تنفيذ bootstrap في الذاكرة فقط، ولم يتم حفظ credentials أو session cookies أو raw response bodies. تم حفظ semantic metadata وbody digests فقط.

بسبب فشل الـcausal predicate، لم يتم إنشاء ProofBundle مختوم. هذا مقصود؛ وجود observations وحده لا يبرر seal أو scoring عندما تكون النتيجة inconclusive.

## What was completed

تم تنفيذ وتوثيق target-local B2 runner، وتثبيت approval import hash، وإعادة تشغيل WebGoat من الـjar المثبت مع context path الصحيح، والتحقق من service-to-build alignment، ثم تنفيذ baseline/candidate/independent negative control، وcausal evaluation، وcleanup metadata.

تم أيضًا الحفاظ على جميع invariants: `official_isolated_p10_runs_authorized=false`، و`P10/P9/VIP=NOT_QUALIFIED`، و`Bug Bounty=BLOCKED`، وعدم promotion إلى scoring.

## Remaining blockers

أول blocker هو أن WebGoat يحتاج application authentication/session state إضافية حتى تصل الطلبات إلى `LessonSession` الخاصة بـIDOR؛ الـredirects الحالية لا تصل إلى lesson oracle، ولذلك لا يمكن اعتبار الحالة confirmed أو clean.

ثاني blocker هو عدم وجود safe canary route معتمد لـWebGoat path traversal بدون raw traversal أو filesystem risk.

ثالث blocker هو عدم توفر requester/owner fixture injection وreset قابلين لإعادة الاختبار في crAPI دون state mutation أو credential/token material إضافي.

الخطوة التالية الآمنة هي رفع هذه النتائج للمالك كقرار: إما اعتماد آلية target-local fixture/session injection أكثر تحديدًا، أو إبقاء الحالات الثلاثة blocked/inconclusive. لا ينبغي إعادة تشغيل نفس الدورة أو فتح P10 قبل تغير هذه الشروط.
