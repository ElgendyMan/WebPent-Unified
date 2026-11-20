# مصفوفة مطابقة WebPent v63 مع تقرير التدقيق وخارطة VIP

## الحكم التنفيذي

المراجعة الحالية لا تؤيد القول إن كل ما ورد في الملفين نُفذ وأُغلق. إصدار v63 أغلق مجموعة مهمة من إصلاحات Security Foundation، لكنه لا يحقق كل متطلبات تقرير التدقيق ولا Definition of Done الخاصة بالنسخة VIP. توجد فجوات أمنية فعلية، أهمها worker resume authorization، عزل admin عبر tenants، Redis/Celery TLS وACL، وجود session material داخل state/checkpoints، وغياب state-machine/telemetry/coverage contracts الشاملة.

## Findings من تقرير التدقيق

| البند | الحالة الحالية | الدليل | الحكم |
|---|---|---|---|
| F-001 ownership/tenant binding | جزئي | `scan_registry.py` يخزن owner/client/engagement، و`app.py` يحمي status/findings/risk/approve | لم يُغلق: admin عابر للـtenant مسموح، و`resume_pentest_task(thread_id)` لا يتحقق worker-side من capability أو owner/tenant |
| F-002 OOB replay/integrity | جزئي | compare-and-set في `db.py` وper-finding token في `app.py` | لم يُغلق بالكامل: لا event-id/nonce/TTL/event ledger، ولا فصل GET discovery عن POST confirmation، ولا binding كامل لعقد evidence |
| F-003 raw socket TLS/scope | جزئي إلى جيد | TLS verification مفروض واختبار out-of-scope host موجود | لم يُغلق بالكامل: scope gate المستخدم في raw path لا يمثل كل scheme/host/effective-port/path policy الموحدة |
| F-004 CL.TE false positive | مُحسن وليس مغلقًا | baseline وsame-connection combined exchange وnegative behavior | لا يوجد proof front-end/back-end حقيقي أو positive/negative fixture كامل يبرر Tool-Confirmed؛ يجب أن يبقى Needs Human Review عند الإشارة غير الحاسمة |
| F-005 raw HTTP client invariant | مغلق في المسارات المفحوصة | `api_testing` يستخدم `make_safe_httpx_client`، واختبارات TLS موجودة | يحتاج architecture test يمنع عودة raw constructors في agents الجديدة |
| F-006 Redis/Celery transport | غير مغلق | `docker-compose.yml` يستخدم `redis://` في API/worker/rate limiter | لا توجد rediss/CA validation/ACL/queue isolation/task envelope enforcement كاملة |
| F-007 secrets في state/checkpoint | غير مغلق | `initial_state.py` ينسخ credentials/session_cookies/identity_profiles إلى state؛ schema يصرح باستمرارها | task crypto يحمي password في بعض مسارات broker فقط، لكنه لا يزيل cookies/identity material من checkpoints |
| F-008 JWT claims/revocation | مغلق إلى حد كبير | issuer/audience/jti/iat/nbf/token-version وregression tests | لا يزال refresh rotation/key rotation خارج نطاق v63، لكن finding الأصلي الأساسي مغلق |
| F-009 direct launch/preflight | غير مغلق | `server.py` يثبت `0.0.0.0:8000` ولا يستدعي `run_preflight()` | يوجد configuration drift بين direct launch وsecure compose |
| F-010 Redis failure rate limiting | مغلق لمسارات limiter المفحوصة | fail-closed behavior وregression test | readiness/circuit-breaker ومنع scan jobs عند غياب dependency ليست شاملة |
| F-011 broad exception swallowing | غير مغلق | ما زالت أنماط `except/pass` و`except/continue` في worker/agents/shared | لا توجد exception taxonomy وNodeRun/partial coverage telemetry شاملة |
| F-012 git/subprocess threat model | جزئي | HTTPS-only shallow clone، no-shell، no hooks، timeout | لا توجد sandbox/quotas/absolute command allowlist/revision pinning شاملة لكل subprocess tools |

## خارطة VIP

المراحل 0–4 غير مكتملة بالكامل: CI والـlockfile وdependency audit تحسنت، لكن SAST policy وsecurity modes/threat-model delivery، secret references، policy kernel الموحد، وconfirmation contracts لكل vulnerability class لم تُبنَ بالكامل. المراحل 5–12 (state machine/autonomy reliability، complex target operating system، ترقية كل agents، controlled exploitation، benchmark lab، observability، secure integrations، staged release strategy) هي roadmap مستقبلية وليست مخرجات v63 الحالية.

## Definition of Done للـVIP

لا يمكن اعتمادها حاليًا؛ البنود المتعلقة بالعزل الكامل، egress kernel الموحد، عدم وجود secrets في checkpoints، coverage report/node states، worker resume/cancel idempotency، multi-host target manifest، contracts/metrics لكل agent، autonomous loop bounded/observable، وbenchmark false-positive gates لم تتحقق جميعًا.

هذا الملف هو baseline للمراجعة قبل الإصلاحات اللاحقة، وليس إعلانًا بأن الإصدار VIP مكتمل.

## المراجع المحلية

- `/home/ubuntu/upload/pasted_content_2.txt` — تقرير التدقيق الأمني الأصلي.
- `/home/ubuntu/upload/pasted_content_3.txt` — خارطة VIP ومعايير القبول.
- `src/webpent/api/app.py` — API authorization وscan dispatch.
- `src/webpent/api/scan_registry.py` — registry ownership metadata.
- `src/webpent/workers/pentest_worker.py` — run/resume worker lifecycle.
- `src/webpent/state/state.py` و`src/webpent/state/initial_state.py` — checkpoint schema وإدخال auth material.
- `docker-compose.yml` — broker/rate-limit deployment configuration.
- `tests/test_v63_vip_security_regression.py` — regression coverage الحالية.

## القرار

الإصدار الحالي مناسب كـ **Security Foundation candidate للـlab أو authorized staging** بعد مراجعة deployment، لكنه ليس **VIP production-ready** ولا يجوز وصفه بأنه أغلق كل مشاكل الملفين.
