# Production Qualification Contract

يوفر `webpent.production` projection حتميًا لتقييم أدلة التشغيل التي يمررها مشغّل أو harness خارجي. هو **ليس** health probe ولا يبدأ Docker أو Redis أو Celery، ولا يقرأ secrets، ولا يتصل بأي target.

| المجال | الدليل المطلوب |
| --- | --- |
| Infrastructure | Docker وRedis وCelery worker health مثبتة من بيئة التشغيل نفسها. |
| Distributed safety | lease contention بين workers، crash/restart recovery، checkpoint resume، وcross-process idempotency مثبتة بأدلة مستقلة. |
| Security operations | secrets externalized، TLS enforced، logs redacted، وretention policy declared. |
| Target safety | target unchanged، وعدم وجود external target contact أثناء qualification غير الحية. |

يظل التقرير `not_qualified` عند غياب أي check أو عند وجود target contact. لا يكفي نجاح Python unit tests أو SQLite المحلي لإثبات distributed qualification. كذلك لا يجوز استخدام التقرير لإسناد confirmation لثغرة؛ confirmation منفصل ويظل مشروطًا بـcausal signal وnegative control وProofBundle المركزي sealed/replayable ونجاح replay.

في الإصدار الحالي لا توجد نتيجة تشغيل production موزعة محفوظة في المستودع؛ لذلك يجب اعتبار أي qualification live **غير مثبتة** إلى أن تُرفق artifacts صريحة تشمل إصدارات الحاويات، worker logs المنزوعة الأسرار، lease/idempotency evidence، وcheckpoint continuity.
