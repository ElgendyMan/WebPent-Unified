# WebPent Production Hardening Checklist

هذا checklist يصف متطلبات ما قبل النشر ولا يعني أن كل بند تم تنفيذه أو اختباره في بيئة إنتاج فعلية. يجب إرفاق evidence لكل بند قبل تغيير الوضع من Smart Research Beta إلى production.

## Scope وauthorization

| الضابط | شرط الإغلاق | دليل مطلوب | الحالة الحالية |
|---|---|---|---|
| Exact target scope | scheme/host/port/path محددة ومطبّعة | signed engagement policy وruntime trace | موجود في policy layer؛ يحتاج إثبات تشغيل إنتاجي مستقل |
| Redirect/DNS controls | منع الخروج من origin المصرح أو إعادة التحقق بعد redirect | integration tests وblocked redirect log | fail-closed contract موجود؛ qualification runtime مطلوبة |
| Destructive actions | `auto_approve=false` ورفض state-changing actions دون approval | approval audit وnegative tests | موجود افتراضيًا |
| Autonomous controller | `enable_autonomous_controller=false` افتراضيًا | config snapshot | مغلق افتراضيًا |

## Secrets وdata handling

| الضابط | شرط الإغلاق | دليل مطلوب |
|---|---|---|
| Secret injection | كل JWT/audit/Celery/webhook/OOB secret من secret manager أو environment | deployment manifest وrotation record |
| Redaction | لا tokens/passwords/cookies/raw headers في logs أو findings أو checkpoints | redaction tests وsample logs |
| Encryption | TLS للخدمات الخارجية وRedis عند الحاجة، وتشفير قواعد البيانات/backups | TLS scan وbackup policy |
| Retention | retention وsecure deletion للـrequests/responses والـbenchmark artifacts | retention configuration |
| Access isolation | client_id وengagement_id enforced في lessons وretrieval | isolation tests وtenant review |

## Runtime وworker safety

| الضابط | شرط الإغلاق | دليل مطلوب |
|---|---|---|
| Resource budgets | timeout، retry، concurrency، payload، response-size، وdepth bounds محددة | config snapshot وload test |
| Celery/Redis | authentication، TLS، queue isolation، ومراقبة stuck tasks | deployment test وalert rules |
| Browser workers | sandboxing، download restrictions، وبدون credentials مشتركة | browser profile policy |
| Persistence | Chroma/SQLite backup وrestore test، وعدم إدخال runtime DB في Git/ZIP | restore transcript |
| Failure behavior | provider/tool/LLM failure يظهر `not_scanned` أو `inconclusive` ولا يتحول إلى success | fault-injection test |

## Evidence وquality

| الضابط | شرط الإغلاق | دليل مطلوب |
|---|---|---|
| ProofBundle | كل confirmed finding لها replayable proof، provenance، causal signal، وnegative control | benchmark output |
| Duplicate semantics | stable finding key وset semantics داخل engagement | repeat-run test |
| Precision/recall | ثلاث qualification runs مستقلة من reset نظيف | signed benchmark result files |
| Human review | findings الحساسة وdestructive/identity actions لها reviewer trail | approval records |
| Report quality | scope، baseline، observed behavior، limitations، remediation، وredaction موجودة | JSON/HTML report review |

## CI وrelease gates

قبل الدمج أو النشر يجب تشغيل:

```bash
python -m compileall src -q
pytest tests -q --tb=short
ruff check src tests benchmarks scripts --line-length 100 --output-format concise
python scripts/doctor.py --json
```

ويجب إضافة dependency/SBOM scanning، secret scanning، static analysis، container image scanning، وtest run منفصل مع `LLM_ENABLED=false` و`DISABLE_RAG=true`. لا تُقبل نتيجة CI إذا وُجد scope violation، duplicate execution، silent precondition failure، أو confirmation بلا required controls.

## Current assessment

الاختبارات المحلية الحالية تثبت **789 passed وRuff = 0 وcompileall ناجح** وتثبت العقود fail-closed. لكنها لا تعوّض عن deployment review، load test، backup/restore، qualification runs، أو security scan خارجي. لذلك تظل حالة المشروع **Smart Research Beta** حتى إغلاق الأدلة التشغيلية أعلاه.
