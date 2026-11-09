# دليل النشر والعمليات — WebPent Autonomous Bug Hunter v0.4.0

هذا الدليل للتشغيل الفعلي على هدف مفوَّض. كل ما يلمس شبكة يمر عبر
بوابة التفويض الإلزامية، وكل ما يُنتجه المحرك advisory إلا الأدلة
المُتحقق منها داخل الحلقة.

## 1. المتطلبات

- Python 3.12، وvenv مخصص للمشروع.
- تعتمد حزمة النشر على `pyproject.toml` نفسه؛ لا ملفات إعداد خارجية.
- Playwright يحتاج متصفحًا محليًا (للاختبارات فقط: `PLAYWRIGHT_BROWSERS_PATH`).

## 2. التثبيت

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
webpent --help            # يجب أن يطبع قائمة الأوامر
webpent hunt-auto --help  # يجب أن يعرض --authorization و--report
```

## 3. عقد التفويض (إلزامي لأي تشغيل فعلي)

`hunt-auto` بدون `--authorization` يرفض التشغيل فورًا برمز 1 ولا يرسل
أي طلب. ملف التفويض JSON بالشكل التالي:

```json
{
  "target_origin": "https://lab.example",
  "scope": ["https://api.lab.example"],
  "operator": "ops@example.corp",
  "authorization_reference": "AUTH-2026-10-15",
  "expires_at": "2026-10-30T00:00:00+00:00",
  "notes": "Written permission ref in engagement folder."
}
```

القواعد: المطابقة على مستوى origin فقط (scheme + host[:port]، والبيانات
الاعتمادية في الـURL تُشطب دائمًا)، والمنتهي الصلاحية يُرفض حتى لو طابق
النطاق، والـscope الفارغ يُرفض لأنه لا يفوّض شيئًا. `expires_at` اختياري
لكن موصى به. حد معروف: التفويض يُفحص عند بدء التشغيل فقط؛ جولة تطول
فوق وقت الانتهاء لا تُعاد مراجعتها في منتصف التنفيذ — اجعل صلاحية
التفويض أطول من الجولة المتوقعة بهامش آمن.

## 4. Runbook

```bash
# 1) جفاف: يربط الـruntime الكامل ويقرر الجاهزية بلا طلب واحد
webpent hunt-auto --url https://lab.example/ --engagement-id e-1 --dry-run

# 2) تشغيل مفوَّض: كل فعل يمر عبر بوابات scope/authority/budget/proof
webpent hunt-auto --url https://lab.example/ --engagement-id e-1 \
  --authorization ./authorization.json --mode safe-smart \
  --output report.json --report report.html

# 3) التسليم: report.html للتسليم لصاحب الهدف، report.json للمعالجة
```

رموز الخروج: 0 اكتمل بحكم صادر، 1 رفض إعدادات أو تفويض، 3 توقف محدود
بلا حكم (bounded inconclusive).

## 5. حدود الصدق (اقرأها قبل التسليم)

- تقرير الارتباط machine-derived فقط: يعرض ما أنتجه الـhunt من
  findings وguidance، ولا يضمن اكتمال التغطية، ولا يدّعي نتيجة عن شيء
  لم يُصطد. سطر non_claim في كل قسم يكرر ذلك للقارئ.
- الإرشاد الإصلاحي advisory: قوائم التحقق تعليمات لبشر، والمحرك لا
  ينفذها ولا يعيد الاختبار منها.
- الأدلة داخل الحلقة وحدها هي ما اُكتسب إعادة تشغيل وتحقق؛ كل ما
  عداها candidate أو guidance.

## 6. استكشاف الأخطاء

- `Authorization refused: target origin ... outside the authorized scope`:
  الـURL لا يطابق target_origin ولا أي عنصر scope؛ صحح الملف لا الهدف.
- `Authorization refused: ... expired`: جدّد التفويض المكتوب ثم أعد
  التشغيل؛ لا يوجد تجاوز لهذه البوابة.
- `Runtime blocked`: خطأ إعداد الـruntime نفسه، برسالة من `G-02`.

## 7. النشر Rootless (D-1 — 0.28.0)

وضعان تشغيليان للحاوية، كلاهما موثق ومُتحقق منه وقت التشغيل:

### المسار الافتراضي (root → gosu، بلا تغيير)

الحاوية تبدأ root، تعالج ملكية مسارات الـbind-mount، ثم تسقط الصلاحيات.
منذ 0.28.0 السقوط **مُتحقق منه fail-closed**: قبل الـexec يشغّل الـentrypoint
`id -u` عبر gosu باسم الهدف ويقارن الناتج — فشل أو mismatch = رفض بدء
التطبيق (exit 1). سطر الدليل في سجل الحاوية عند كل إقلاع:

```
entrypoint.sh: privilege drop VERIFIED (uid=1000, gid=1000).
```

لو رأيت `FATAL — privilege-drop probe failed` أو `FATAL — privilege drop
did not land` فهذه بوابة أمان تعمل كما صُممت: صورة الأساس انكسرت gosu
أو الهوية لم تُسلَّم — لا تتجاوزها، أصلح الصورة.

### وضع Rootless (اختياري)

لمنع root في أي لحظة من عمر الحاوية:

```bash
export WEBPENT_UID="$(id -u)"
export WEBPENT_GID="$(id -g)"
docker compose -f docker-compose.yml -f docker-compose.rootless.yml up -d
```

- الـoverride يفرض الهوية بـ`:?` fail-fast — التصدير الصريح إلزامي (فخ
  `${UID:-1000}` الصامت هو أصل علة الملكية التي يعالجها الـentrypoint).
- الـentrypoint يعلن `ROOTLESS MODE` وينفّذ الأمر مباشرة بلا gosu.
- المقايضة المعلنة: لا معالجة ملكية آلية — ملكية مسارات الـbind-mount
  (`./runtime`، `./memory`، `./output`) مسؤولية المشغل قبل التشغيل.
