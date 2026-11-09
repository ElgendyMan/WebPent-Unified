# Verification Matrix — Target Package v2

| المحور | الحالة المختبرة | السلوك المتوقع | النتيجة |
|---|---|---|---:|
| package builder | package حقيقية مبنية من bbscout | قبول canonical package مع فصل source digest عن content digest | PASS |
| content integrity | تغيير package بعد حساب digest | رفض `content_digest_mismatch` | PASS |
| source provenance | source response hash صحيح شكليًا لكنه مختلف عن content hash | الاحتفاظ به كـsource evidence وعدم مقارنته بـcontent hash | PASS |
| detached signature | Ed25519 signature صحيحة ومفتاحها في trusted map runtime-only | `signature_state=verified` وقابلية engagement consumption | PASS |
| detached signature | unsigned-local-mvp | local validation فقط، رفض execution/engagement | PASS |
| detached signature | مفتاح عام خاطئ أو signature تالفة | fail-closed | PASS |
| freshness | package منتهية | `deny_expired`/blocked preflight | PASS |
| revocation | package revoked | `deny_revoked`/blocked preflight | PASS |
| confirmation | confirmation ناقصة أو digest مختلف | رفض قبل lease/action | PASS |
| secret redaction | secret-like field في package projection | admission rejection وعدم تسريب القيمة | PASS |
| one-time lease | consume package مرتين بنفس أو engagement مختلف | أول consume فقط؛ الثاني conflict/reject | PASS |
| scope | apex مقابل wildcard subdomain | القرار يطابق rule ولا يوسع scope | PASS |
| scope | sibling host خارج wildcard | `deny_out_of_scope` | PASS |
| scope | port/path/scheme mismatch | deny أو allow_with_constraints حسب العقد | PASS |
| scope | userinfo/ambiguous encoding | deny_ambiguous | PASS |
| scope | redirect chain فيها hop خارج النطاق | deny_out_of_scope | PASS |
| action identity | missing package id/SHA أو mismatch | reject قبل handler | PASS |
| capability | local manifest لا يملك capability مطلوبًا | structured knowledge gap/blocked capability، لا clean | PASS |
| proof | causal signal بلا negative control | لا promotion إلى confirmed | PASS |
| proof | baseline/candidate/negative control ليست observations target-backed مستقلة | promotion reject | PASS |
| proof | target fingerprint أو validator/engagement continuity غير متطابق | promotion reject | PASS |
| proof | sealed ProofBundle أو replay payload تم العبث به | replay/seal verification reject | PASS |
| proof | package continuity ناقصة في proof input | promotion reject | PASS |
| report | package-backed report | top-level redacted continuity تدخل audit/master hash | PASS |
| validator | replay callers تحمل package context | verifier/proof يحمل identity/digests | PASS |
| validator | active replay | baseline + candidate + independent negative-control observations مع request/response digests وredacted metadata | PASS |
| legacy | no package / `not_provided` | المسار legacy يبقى متوافقًا ولا يُفتح bypass package | PASS |
| CLI intake | package path + confirmation + trusted public-key map | admission/lease قبل graph، ورفض mismatch قبل التشغيل | PASS |
| API dispatch | bounded `ScanRequest` package fields | validation أولية ثم handoff للworker دون تسجيل raw package | PASS |
| worker first-run | package + confirmation + public trust map | إعادة تحقق فعلية قبل أول graph node وتمرير projection/binding redacted | PASS |
| worker resume/redelivery | binding وlease موجودان | continuity check دون lease consume ثانٍ | PASS |
| checkpoint/report redaction | raw package/signature/trust material | لا تظهر في checkpoint أو projection أو التقرير | PASS |

## Evidence

التغطية موجودة في `tests/test_target_package_integration.py` و`tests/test_target_package_v2_hardening.py` و`tests/test_v96_strict_verifier.py` و`tests/test_p0_p1_active_validators.py` وentrypoint/checkpoint tests المرتبطة. كل الاختبارات تعمل offline ولا ترسل HTTP أو browser أو provider requests؛ اختبار worker يستخدم graph/storage mocks لإثبات ترتيب البوابة فقط. نتيجة package/entrypoint/hardening focused gate: **35 passed، 2 warnings**. نتيجة proof-focused verifier/active gate: **30 passed، 8 warnings**. نتيجة WebPent الكاملة: **1382 passed، 294 warnings**.

## Interpretation

هذه المصفوفة تثبت contracts وgates الداخلية، ولا تثبت فعالية اكتشاف ثغرات على WAPTLab أو Juice Shop، ولا تثبت distributed/Celery qualification أو VIP promotion.
