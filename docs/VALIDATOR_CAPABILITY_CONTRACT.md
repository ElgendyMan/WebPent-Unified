# Validator Capability Contract

## الغرض

هذا المستند يعرّف حدود registry الخاصة بالـvalidators. وجود campaign أو surface أو نتيجة LLM لا يعني أن هناك validator قادرًا على تأكيد ثغرة. لا يتم اعتبار النتيجة `confirmed` إلا عبر المسار المركزي الذي يثبت causal signal وnegative control وsealed/replayable ProofBundle.

## حالات القدرة

| الحالة | `validator_id` | المعنى التشغيلي | هل تسمح بترقية strict confirmation؟ |
|---|---|---|---|
| `tested` | موجود | validator deterministic مسجل ويمكنه الدخول في مسار التحقق، مع بقاء بوابات الدليل والإثبات إلزامية | لا، وحدها غير كافية |
| `offline-fixture` | يبدأ بـ`offline-fixture:` | عقد fixture أو اختبار offline فقط، وليس دليلًا على target حي | لا |
| `missing-validator` | فارغ | لا يوجد مسار deterministic صالح لهذه الفئة | لا؛ تبقى Human Review أو gap |

## قواعد fail-closed

يجب أن تحقق كل campaign عقد plugin الكامل: stages ثابتة، preconditions، action plan، baseline، negative control، causal oracle، cleanup، proof schema، replay function، وconfidence policy. أي contract ناقص يُبلّغ كـ`incomplete-contract` ولا يُستبدل باستدعاء LLM أو heuristic.

يتم بناء registry من تعريفات campaigns والـvalidator registry. إذا كانت الفئة غير مسجلة، فإن `validator_id_for()` يعيد `None`، ويُنتج `capability_for()` حالة `missing-validator`. أما معرفات offline فلا تُعامل كمعرفات live، وتظل evidence mode الخاصة بها `offline-contract`.

## حدود ما تثبته الاختبارات

اختبارات `tests/test_vip_validator_plugins.py` و`tests/test_v97_campaign_registry.py` تثبت ثبات عدد campaigns، وضوح gaps، عدم الخلط بين offline وlive، وعدم تحويل ledger status أو evidence metadata إلى confirmation. هذه الاختبارات لا تثبت أن WAPTLab يحتوي هذه الأسطح ولا تثبت نجاح exploit على أي target.

اختبارات `tests/security_invariants/` تختبر أن حدود authority وscope وledger وpackage/proof continuity لا يمكن تجاوزها. وتبقى qualification الحية مستقلة، وتتطلب run مكتملًا ونتائج target-backed قابلة لإعادة التشغيل وفق manifest الرسمي.

## Acceptance criteria

لا يُسمح بإغلاق gap إلا بإضافة validator deterministic حقيقي واختبارات causal/negative-control/replay مناسبة، ثم مرور release gates كاملة. لا يجوز تغيير `missing-validator` إلى `tested` بتعديل registry فقط، ولا يجوز عدّ campaign inventory أو observed surface أو candidate كـconfirmed finding.
