# UM-DR-49 — GOVERNANCE_INDEX: فهرس الحوكمة الكامل للنافذة

> كل مسار يفتح raw على main بعد الرفعة النهائية. القاعدة: روابط
> تُفتح واحدًا واحدًا.

## وثائق القرار والتسليم (deliverables/umdr49/)

| الوثيقة | المحتوى | المسار raw |
|---|---|---|
| RAW_LINKS | جدول مسارات 47/48 + إصلاح CI | deliverables/umdr49/RAW_LINKS.md |
| SMOKE_AND_AUTHORIZATION | البيانات الحية + التفويض + بروفة safe-stop | deliverables/umdr49/SMOKE_AND_AUTHORIZATION.md |
| REAL_BASELINE | خط الأساس الصادق W1 (0/25) | deliverables/umdr49/REAL_BASELINE.md |
| GAP_TAXONOMY | تصنيف الفجوات الأربع | deliverables/umdr49/GAP_TAXONOMY.md |
| REAL_DELTA | دلتا W2 المقيسة + فجوة LLM | deliverables/umdr49/REAL_DELTA.md |
| W3_ROBUSTNESS_CONTINUITY_SCALE | العدائية/الاستمرارية/المقياس | deliverables/umdr49/W3_ROBUSTNESS_CONTINUITY_SCALE.md |
| VIP_ULTIMATE_CERTIFICATION | قرار بيان النضج + الفجوات الست | deliverables/umdr49/VIP_ULTIMATE_CERTIFICATION.md |
| CLOSEOUT | هذا الإقفال | deliverables/umdr49/CLOSEOUT.md |

## كتالوجات الحقيقة العامة (truth_catalogs/)

| الكتالوج | البنود/المُسقط | المسار raw |
|---|---|---|
| Juice Shop (من /api/Challenges للتطبيق نفسه) | 118/15 | deliverables/umdr49/truth_catalogs/juiceshop_truth.json |
| WebGoat (من دروس الـrelease jar) | 29/10 | deliverables/umdr49/truth_catalogs/webgoat_truth.json |
| DVWA (من شجرة المصدر) | 19/6 | deliverables/umdr49/truth_catalogs/dvwa_truth.json |

## السجلات الخام للحملات (run_files/)

| السجل | القياس | المسار raw |
|---|---|---|
| juiceshop_run1..7 | الحملات العمياء + تفعيل jsintel | deliverables/umdr49/run_files/juiceshop_run*.json |
| webgoat_run1 | الحملة العمياء (فجوة هوية) | deliverables/umdr49/run_files/webgoat_run1.json |
| learning_pair | زوج N/N+1 (تعلم مستقر) | deliverables/umdr49/run_files/learning_pair.json |
| adversarial | 18×429 + 4×500، FP=0 | deliverables/umdr49/run_files/adversarial.json |
| continuous | قتل/استئناف صفر تكرار | deliverables/umdr49/run_files/continuous.json |
| scale_dual_app | تطبيقان، صفر تسرب | deliverables/umdr49/run_files/scale_dual_app.json |

## الكود والبوابات

| البند | المسار raw |
|---|---|
| سكربت الحملة الموحد (قانون الصفر-معرفة) | scripts/umdr49_real_campaign.py |
| بوابة الصفر-معرفة (grep-gate) | scripts/umdr49_zero_knowledge_gate.py |
| كتالوج الحقيقة (البناء) | scripts/umdr49_truth_catalogs.py + scripts/umdr49_juiceshop_truth.py |
| زوج التعلم | scripts/umdr49_learning_pair.py |
| العدائية | scripts/umdr49_adversarial.py |
| الاستمرارية | scripts/umdr49_continuous.py |
| المقياس | scripts/umdr49_scale_dual.py |
| إعادة توليد الجرد | scripts/regen_direct_io_inventory_0480_umdr49.py |
| اختبار حدود المنافذ (5) | tests/test_umdr49_scope_port_boundary.py |
| compose المعامل (بيئة المالك) | deploy/umdr49/docker-compose.yml + reset_labs.sh + scopes |
| الـworkflow الليلي (المسار الكنسي) | .github/workflows/umdr49_real_battery.yml |

## الإصلاحات المندمجة في main (بالأرقام)

| الإصلاح | الـcommit |
|---|---|
| canary heal (http_discovery thaw) | dd4cb32 |
| P0 كامل (scope port + سجلات 48 + كتالوجات) | 742723f |
| W1+W2 (الأساس + الإسقاط + التلوث + evolution) | e2d8891 |
| W3 + الإقفال + v0.48.0 | (الرفعة النهائية) |
