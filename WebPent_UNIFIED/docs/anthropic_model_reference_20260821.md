# Anthropic model reference

تمت مراجعة صفحات Anthropic الرسمية في 2026-08-21 قبل اعتماد default model في WebPent.

- Models overview: https://platform.claude.com/docs/en/about-claude/models/overview
- Claude Sonnet 4.6 announcement: https://www.anthropic.com/news/claude-sonnet-4-6

يعرض جدول **Latest models comparison** في صفحة Models Overview الرسمية أن:

- Claude Sonnet 5 يستخدم Claude API ID: `claude-sonnet-5`.
- Claude API alias: `claude-sonnet-5`.

وتذكر الصفحة الرسمية أن Claude Sonnet 4.6 أُعلن في 17 فبراير 2026، بينما صفحة النماذج الحالية تعرض Sonnet 5 ضمن النماذج الأحدث. لذلك يستخدم WebPent `claude-sonnet-5` كـdefault Anthropic ID، مع إبقاء fallback واختيار المشغّل وruntime model-catalog كما هي.

تظل أهلية الحساب وتوفر النموذج ومفتاح API مسائل runtime يجب التحقق منها عبر provider model catalog؛ هذا المرجع لا يثبت توفر مفتاح أو نجاح طلب حي. لم يُستخدم أي API key ولم تُرسل أي مطالبة خارجية أثناء هذا التغيير.

## Scope and safety

لم يتم الاتصال بـWAPTLab أو Juice Shop. التغيير يقتصر على توثيق model default والتهيئة والاختبارات المحلية المطابقة.

## Authoritative API enumeration

عند الحاجة إلى التحقق من النماذج المتاحة لحساب محدد، يجب استخدام Models API الرسمي للحساب بدل افتراض التوفر من الاسم فقط:

- https://platform.claude.com/docs/en/api/models/list
