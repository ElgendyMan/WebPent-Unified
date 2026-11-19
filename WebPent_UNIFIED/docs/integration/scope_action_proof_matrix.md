# Scope / Action / Proof Matrix

## ScopeCompiler

| البعد | قاعدة القرار | مخرجات typed |
|---|---|---|
| scheme | schemes الموجودة في normalized include rules فقط | allow أو deny_out_of_scope |
| host | exact host أو wildcard مضبوط؛ wildcard لا يطابق apex أو sibling تلقائيًا | allow/deny_out_of_scope |
| port | المنفذ المقيد يطابق المنفذ الفعلي؛ default ports لا تُفترض عند وجود قيد صريح | allow/deny_out_of_scope |
| path | include/exclude path rules تُطبق بعد canonical URL parsing | allow/deny_out_of_scope |
| userinfo | URLs التي تحمل userinfo لا تُمرر بصمت | deny_ambiguous |
| method | method restrictions جزء من rule، وليست صلاحية عامة | allow_with_constraints/deny_policy |
| action class | read-only/active/destructive policy تُحترم قبل handler | allow_with_constraints/deny_policy |
| redirect chain | كل hop يجب أن يظل ضمن scope؛ hop خارج النطاق يحجب العملية | deny_out_of_scope |
| package state | expiry/revocation/status قبل matching | deny_expired/deny_revoked |

## ActionAuthority

لا ينشئ `ActionAuthority` أي transport. يستقبل `ActionRequest` وhandler موجودًا من المسار المركزي، ويفحص capability، idempotency، origin/policy، package identity/digest، ثم `ScopeCompiler` عند وجود package. لا يستطيع caller تمرير URL جديد أو تغيير package continuity عبر metadata غير موجودة في القائمة البيضاء.

| مرحلة | شرط | نتيجة الفشل |
|---|---|---|
| admission binding | package verified، fresh، non-revoked، confirmation exact | action blocked |
| identity | `target_package_id` و`target_package_sha256` يطابقان runtime context | action blocked |
| scope | URL/method/action/redirect chain مسموحة | `deny_*` typed |
| capability | capability available وغير محجوبة بالسياسة | blocked/inconclusive knowledge gap |
| handler | ينفذ فقط بعد كل gates | لا direct-I/O bypass |
| ledger/proof | يسجل redacted continuity وdecision | قابل للتدقيق |

## Proof continuity

| المصدر | الحقول المسموحة | الوجهة |
|---|---|---|
| package projection | package id، package/content SHA، scope/policy/capability digests، signature/status | runtime/state |
| action request | نفس identity/digests وscope/policy decisions بعد redaction | action ledger/record |
| verifier | causal signal، neutral negative control، package continuity | verification result |
| ProofBundle | package identity وdigests داخل seal payload | sealed proof |
| reporter | top-level `target_package_continuity` بدون raw package أو secrets | MD/HTML/JSON/PDF data + audit hash |

**Invariant:** candidate، mock، timeout، 403/429، missing capability، tool error، أو proof ناقص لا يصبح `confirmed` ولا `clean`.
