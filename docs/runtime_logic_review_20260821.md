# WebPent Runtime & Logic Review — 2026-08-21

## النطاق

تمت مراجعة مسارات تشغيل Celery وresume، persistence للـfindings، عزل owner/client، قراءة الـledger من API، وحدود checkpoint/runtime context. لم يتم تعديل WAPTLab أو Juice Shop، ولم يتم تنفيذ أي qualification حي أثناء هذه المراجعة.

## العيب المثبت والإصلاح

كان `_persist_findings()` يدعم fallback صحيحًا من `final_state` إلى `owner_username` و`client_id` الممررين من caller، لكن عدة مسارات داخل `run_pentest_task` لم تكن تمرر هذين الحقلين أصلًا. لذلك كانت حالات redelivery، وGraphRecursionError recovery، وsoft-timeout، وcompleted persistence، وzombie-running persistence معرضة للكتابة في partition غير مقصودة إذا كان checkpoint قديمًا أو ناقصًا في scope.

تم إصلاح المسارات الخمسة لتستخدم caller scope صراحةً، مع الإبقاء على سلوك backward-compatible عندما تكون القيم غير متاحة. كما أُضيف regression test يتأكد أن checkpoint الذي يحتوي `owner_username=None` و`client_id=None` لا يطغى على scope الممرر من caller، وأن merge إلى الـledger يستقبل `alice` و`client-a` كما هو متوقع.

| المسار | الحالة قبل الإصلاح | الحالة بعد الإصلاح |
|---|---|---|
| Celery redelivery | scope caller غير ممرر | owner/client ممرران إلى persistence |
| GraphRecursionError recovery | scope caller غير ممرر | owner/client ممرران إلى persistence |
| Soft-timeout | scope caller غير ممرر | owner/client ممرران إلى persistence |
| Completed terminal persistence | scope caller غير ممرر | owner/client ممرران إلى persistence |
| Zombie-running guard | scope caller غير ممرر | owner/client ممرران إلى persistence |
| Resume paths | كانت ممررة بالفعل | بقيت ممررة مع regression coverage |

## التحقق

| البوابة | النتيجة |
|---|---:|
| الاختبارات الكاملة | `1112 passed`, `0 failures` |
| اختبارات worker وscope المستهدفة | `51 passed` |
| Ruff | `All checks passed` |
| `compileall` على `src` و`scripts` | نجح |
| `git diff --check` | نجح |
| Bandit high severity | نجح |
| pip-audit strict وSBOM | نجح، لا توجد ثغرات معروفة في dependencies المفحوصة |

## حالة quality gate

كل hard checks في `docs/vip_quality_gate.json` نجحت، لكن artifact يظل `passed=false` عمدًا بسبب blockers خارجية موثقة: qualification العامل والـDocker الحي غير متاحين في البيئة الحالية، وWAPTLab في هذا gate ممثل بعقد محلي فقط وليس بحملة حية مؤكدة. لذلك لا يجوز تفسير نتيجة gate على أنها تأكيد لعدد findings أو Tool-Confirmed findings في مختبر حي.

> النتيجة الحالية تثبت سلامة الإصلاحات واختبارات المشروع، لكنها لا تثبت qualification حيًا على WAPTLab أو Juice Shop.

## Git والتسليم

تم اعتماد الإصلاحات في commitين متتاليين على branch `master`، ثم دفعهما إلى المستودع `ElgendyMan/webpent-v61`. يجب بناء ZIP النهائي من `git archive` بعد آخر commit فقط، حتى لا تدخل ملفات working tree غير ملتزمة.

## حدود متبقية

ما زالت qualification الحية تعتمد على توفر Docker والخدمات المحلية وحسابات المختبر. لا توجد confirmation جديدة يمكن نسبتها إلى هذه المراجعة، ولم تتم ترقية أي finding اعتمادًا على heuristic أو على artifact mock.
