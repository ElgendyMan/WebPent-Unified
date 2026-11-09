# WebPent v3 Threat Model

## النطاق

هذا النموذج يغطي WebPent أثناء اختبار أهداف محلية مصرح بها مثل WAPTLab وJuice Shop، بما في ذلك graph nodes، HTTP/browser/API/GraphQL/upload/OOB/subprocess adapters، Celery/Redis، ProofBundle، التقارير، وLLM-assisted hypothesis generation.

> محتوى الهدف، HTML، JavaScript، API responses، الملفات، banners، وLLM hypotheses بيانات غير موثوقة؛ لا يجوز لها تغيير scope أو policy أو promotion.

## الأصول الحساسة

| الأصل | أثر التسريب أو العبث |
|---|---|
| credentials/cookies/tokens/CSRF/browser storage | takeover أو cross-tenant access |
| target scope and authorization | اختبار أصل غير مصرح به أو SSRF |
| raw requests/responses and payloads | تسريب أسرار وبيانات عملاء |
| ProofBundle/hash chain | توكيد findings غير صحيح أو إنكار الدليل |
| action ledger/idempotency/budgets | تكرار تنفيذ أو تجاوز rate/risk |
| Celery/Redis task payloads | تسريب credentials أو إعادة تنفيذ مهمة |
| LLM prompts and tool outputs | prompt injection أو تسريب policy |
| ground truth and qualification artifacts | تزوير precision/recall/reproducibility |

## حدود الثقة

| الحدود | الخطر الرئيسي | التحكم المطلوب |
|---|---|---|
| operator → CLI/API | malformed profile أو auth-off | schema validation وsecure profile hard-stop |
| graph node → runtime | raw client أو legacy fallback | RuntimeContext injection وblocked_by_configuration |
| executor → transport | scope/redirect/SSRF escape | central policy + resolver + re-check redirect |
| target content → LLM/planner | prompt injection | typed untrusted input boundaries |
| worker → broker | credential exposure/duplicate claim | encryption، TLS، lease/fencing، idempotency |
| validator → promotion | heuristic confirmation | baseline + negative control + causal oracle + sealed proof |
| report/export → consumer | false clean أو secret leak | status taxonomy، redaction، report quality gate |
| qualification harness → lab | source mutation أو invalid metrics | clean reset، image/seed hashes، event ledger |

## تهديدات وأولوية الاختبار

| التهديد | الأولوية | معيار الرفض |
|---|---:|---|
| redirect إلى host/port خارج scope | P0 | أي redirect escape يُرفض ولا يُسجل clean |
| DNS rebinding/private/link-local ambiguity | P0 | resolver fail-closed عند ambiguity أو change |
| unregistered transport/direct I/O | P0 | CI يفشل أو التنفيذ blocked |
| tool_confirmed بلا sealed ProofBundle | P0 | promotion gate يرفضه |
| missing/inconclusive capability يتحول إلى clean | P0 | الحالة تبقى blocked/inconclusive |
| prompt injection يغير scope أو validator أو evidence | P0 | policy state لا يتغير، وevent يسجل block |
| cross-tenant response acceptance | P0 | negative control يفشل والfinding غير confirmed |
| duplicate worker execution | P1 | idempotency/ledger يمنع duplicate |
| secrets في logs/reports/bundles | P1 | redaction test يفشل البناء |
| insecure production defaults | P1 | startup hard-stop |
| crash أثناء claim/resume | P1 | lease expiry وconsume-once recovery |

## بوابات القبول الأمنية

لا يُعتبر G1 أو G2 ناجحًا بسبب unit tests فقط. يلزم تشغيل adversarial tests ضد scope/redirect/DNS/prompt/secret/duplicate paths، ثم إثبات أن الأحداث والتقارير تحفظ blocker ولا تنتج false clean أو unsupported confirmation.
