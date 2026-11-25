# UM-DR-49 P0.1 — جدول مسارات raw لكل وثائق 47/48

> كل مسار يفتح raw على main. القاعدة: روابط تُفتح واحدًا واحدًا.

## نافذة 47 (v0.46.0)
| الوثيقة | المسار raw |
|---|---|
| تقرير القياس | deliverables/umdr47/MEASUREMENT_REPORT.md |
| تقرير الفرق | deliverables/umdr47/DELTA_REPORT.md |
| قبول Ultimate | deliverables/umdr47/ULTIMATE_ACCEPTANCE.md |
| إقفال المراحل | deliverables/umdr47/PHASE_CLOSEOUT.md |
| إثبات التوصيل | deliverables/umdr47/WIRING_PROOF.md |
| سجلات القياس | deliverables/umdr47/measurement_run_files/ (24 ملف) |

## نافذة 48 (v0.47.0)
| الوثيقة | المسار raw |
|---|---|
| الإقفال | deliverables/umdr48/CLOSEOUT.md |
| خريطة الفجوة (التشخيص) | deliverables/umdr48/MISS_MAP.md |
| خطة التنفيذ | deliverables/umdr48/EXECUTION_PLAN.md |
| القياس النهائي | deliverables/umdr48/MEASUREMENT_V2.json |
| دفتر الهدر | deliverables/umdr48/WASTE_LEDGER.json |
| المتانة S1-S4 | deliverables/umdr48/STRESS_RESULTS.json |
| سجلات الحملات الخام | deliverables/umdr48/run_files_v2/ (50 ملف) |

## إصلاح CI بعد الإقفال (49 P0.1)
| البند | المرجع |
|---|---|
| canary كان 7/7 أحمر على main | 89ed209: test_frozen_file_byte_identical[http_discovery.py] |
| الإصلاح + الرفع | dd4cb32 — إعلان http_discovery.py في نافذة thaw 48؛ canary 7/7 أخضر محليًا |
