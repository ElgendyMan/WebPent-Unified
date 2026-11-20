# Target-Live Fixture/Session Injection Owner Decision Packet v1

## Decision status

> **PENDING_OWNER_APPROVAL** — هذا packet طلب قرار منفصل ومحدد من المالك، وليس تصريح تنفيذ.

الغرض هو تقييم ما إذا كان مسموحًا بتصميم آلية target-local disposable لإدخال synthetic requester/owner state داخل fixtures مع الحفاظ على Option B فقط. لا يفتح هذا packet Official P10 أو scoring أو Bug Bounty أو أي target خارجي.

## Current governance invariants

| Control | Current value |
|---|---|
| Official isolated P10 authorization | `false` |
| Human independent signoff | `false` |
| P10 / P9 / VIP | `NOT_QUALIFIED` |
| Bug Bounty | `BLOCKED` |
| Scoring promotion | `false` |
| Option B | `LAB_NOT_READY / PRECONDITION_BLOCKED` |
| Execution gate | `CLOSED` |

## Requested scope

القرار المطلوب هو السماح أو الرفض، لكل target/case على حدة، لآلية test-only local injection خارج مسار HTTP المعتاد، داخل instance أو fixture disposable على loopback فقط. ستستخدم الآلية opaque identities باسم `synthetic_owner_a` و`synthetic_requester_b`، وopaque canaries، وtyped descriptors فقط.

لا يشمل الطلب real credentials أو accounts أو passwords أو OTP/MFA/CAPTCHA bypass أو login/signup أو token/cookie/Authorization material أو auth bypass أو application POST/PUT/PATCH/DELETE أو reset endpoint أو report creation أو external callbacks/OAST أو internet services أو تغيير Ground Truth أو thresholds أو Generic Core أو qualification state.

## Evidence and current blockers

| Target | Provenance | Target-live status | Blocking reason |
|---|---|---|---|
| WebGoat | Source revision `7517acca95d9851da706452454c223dd13545ef4`; built artifact hash recorded; Java 25 path recorded | Not ready | Service-to-build alignment is not attested; IDOR requires a POST-established HTTP session; no safe GET-only session hook was found; no bounded canary route for path traversal was found |
| crAPI | Source revision `73d309cc8f28bbdeed31dbb35f05dba8354de3c9`; local image RepoDigests recorded | Not ready | Active-container alignment is not attested for authorization; object-access routes require authenticated requester context; no non-credential request-context injection hook was found |

The existence of a source pin or local image RepoDigest does not, by itself, authorize live fixture injection or prove that the active service uses the pinned artifact.

## Proposed mechanisms requiring a decision

### WebGoat IDOR

السماح، إن وافق المالك، بإدخال LessonSession attribute typed داخل disposable WebGoat test fixture فقط، بدون استدعاء `IDORLogin` وبدون HTTP POST. النطاق يقتصر على IDOR profile GET candidate/control routes. يجب إثبات source/build alignment، pre/post state hashes، session-fixture descriptor، وindependent negative-control descriptor. إذا احتاج التنفيذ HTTP login أو تعديل target غير test-only، يظل case `BLOCKED`.

### WebGoat path traversal

السماح، إن وافق المالك، بآلية test-only bounded canary route/adapter فقط إذا ثبتت source-backed semantics بدون raw traversal markers، encoded traversal، arbitrary filesystem path، أو host-file access. إذا لم يوجد هذا المسار الآمن، يظل case `BLOCKED` حتى بعد الموافقة.

### crAPI object access

السماح، إن وافق المالك، بإدخال typed requester/owner principals وopaque object canaries داخل isolated target fixture، دون HTTP authentication أو token generation أو application mutation. يلزم active-container image attestation، fixture schema/version hash، pre/post state hashes، وrequest-context binding غير مكشوف كـuser token. إذا ظل التطبيق يحتاج Authorization header/token أو stateful application setup، تظل كل الحالات `BLOCKED`.

## Required readiness proof

قبل أي request يجب أن تكون كل القيم التالية `true` في target-live scope، وليس offline harness scope فقط:

```text
preconditions_ready = true
fixture_ready = true
identity_model_ready = true
reset_verified = true
runtime_digest_verified = true
network_scope_verified = true
target_live_preconditions_ready = true
```

يجب أن يثبت الـfixture snapshot/restore، pre-state/post-state hashes، cleanup، وغياب raw body/header/cookie/token/canary persistence. لا يتم تشغيل candidate/control أو إنشاء ProofBundle عند غياب أي flag أو عند وجود digest drift أو oracle ambiguity.

## Stop conditions and rollback

يتوقف التنفيذ فورًا عند الحاجة إلى login أو signup أو credentials أو token/cookie/Authorization material أو mutation أو reset endpoint أو redirect أو external callback أو raw traversal أو arbitrary filesystem access أو عدم تطابق state hash أو غياب independent control.

Rollback يرفض mechanism المقترح، يحذف disposable fixture state فقط، يوقف أي disposable service، ويحتفظ بالـtyped blocker record دون raw data. لا يُسمح بأي تغيير دائم في target runtime أو بيانات المستخدم.

## Decision requested

الموافقة، إن صدرت، يجب أن تكون صريحة لكل target/case، ولا يُفسر الصمت كموافقة. لا يوجد تنفيذ قبل القرار، ولا يتغير هذا packet إلى execution authorization تلقائيًا.

**AI review:** non-human attributable technical review فقط.
**Human independent signoff:** `false`.
