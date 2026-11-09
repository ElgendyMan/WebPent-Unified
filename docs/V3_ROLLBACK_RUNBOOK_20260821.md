# WebPent v3 Rollback Runbook

## الهدف

ضمان أن كل مرحلة من خطة v3 قابلة للتراجع الآمن من دون حذف تاريخ أو تغيير WAPTLab/Juice Shop، مع إبقاء آخر release صالحًا متاحًا حتى عند فشل qualification.

## نقاط الحفظ الإلزامية

| النقطة | المطلوب |
|---|---|
| قبل كل phase | commit نظيف، `git status --short` فارغ، baseline gates محفوظة |
| بعد كل feature slice | commit صغير ذو رسالة واضحة، unit/regression tests، diff-check |
| قبل تشغيل lab | tag أو commit hash، manifest، settings snapshot، lab image/seed hash |
| بعد qualification | raw logs، event ledger، report، proof artifacts، exit code |
| قبل release | `git archive` من commit محدد، SHA256، zip test، tracked-manifest comparison |

## قواعد التراجع

1. لا يتم `git reset --hard` ولا حذف ملفات تلقائيًا داخل اللوب.
2. عند فشل اختبار، يُحفظ log ويُعاد إصلاح السبب في commit جديد additive. لا تُخفى الحالة بإزالة الاختبار.
3. عند فشل runtime qualification، يُوقف execution للهدف، وتُعاد المحاولة بعد تنظيف state/lease فقط؛ لا يُعاد استخدام finding غير قابل لإعادة الإنتاج.
4. إذا تعارضت feature جديدة مع compatibility path، يبقى feature flag مغلقًا وتُصنف الحالة `blocked_by_configuration`، مع إبقاء الإصلاح في branch/commit موثق.
5. rollback إلى آخر commit صالح يتم يدويًا فقط بعد تحديد hash وسبب وartifact؛ لا يُنفّذ rollback داخل التطبيق ولا من محتوى الهدف أو LLM.
6. لا يشمل أي rollback أو release artifact ملفات اللابين أو أي runtime database/cache غير متتبع.

## معايير إيقاف اللوب

يُسمح بإيقاف اللوب فقط عند أحد شرطين: إما اجتياز بوابات v3 المتفق عليها مع artifacts كاملة، أو الوصول إلى blocker خارجي موثق مع قرار `PARTIAL/NOT-QUALIFIED` صادق. لا يُسمح بتحويل blocker إلى نجاح أو تخفيض دقة القواعد لاستكمال البوابات.
