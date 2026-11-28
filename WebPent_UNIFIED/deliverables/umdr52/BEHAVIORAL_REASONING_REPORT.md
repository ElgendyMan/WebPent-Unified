# BEHAVIORAL_REASONING_REPORT — UM-DR-52 W1

**ما بُني:** طبقة الاستدلال السلوكي ولوجيك الأعمال (`src/webpent/researcher/behavioral_layer.py`) — استخراج آلة الحالات من الحركة المرصودة (حالات/انتقالات/شروط مسبقة/حالة المورد قبل-بعد)، نموذج الأمن الحي فوق SKG (Users/Roles/Resources/Sessions/Workflows/Parameters/Trust Boundaries ككيانات أولى)، الأسئلة الخمسة المقاسة (إجابة من النموذج قياسًا أو «غير مرصود» — لا اختراع)، تعدين الـInvariants (وصول عابر للملكية، تخطي workflow، حالة مورد غير مشروعة)، وكشف التناقض (المعلَن مقابل السلوك الفعلي) مع تمييز نقاط الاعتراض في الـSSOT.

**ما الذي تغيّر في القرارات — بالقياس:**
1. الميداني (Juice Shop، 3 runs/sذرع، عزل بعملية منفصلة): تغيّر ORDER (بصمات `2ad59ee5456d3eeb`→`383288d57538dd88`) و+2 فرضيات حتمية في المسبح (`W1_FIELD_BRAIN_DELTA.json`).
2. الـfixture المعتمد: انقلابا قرار (`defer→abandon` على `/api/transfer` و`/api/profile`) عبر مسار القرار الحقيقي (`estimate_priority_inputs` → صيغة W3 → خريطة `p/(p+k)` → `recommend_action(priority_score=...)`) (`W1_FIXTURE_DECISION_DELTA.json`).
3. الاستهلاك في المحرك: `ctx.behavioral` (كثافة الانتقالات→EIG، دعم التناقض→الثقة، السطح المحمي بـinvariant→الأثر) — كل حدّ no-op عند غياب الدليل (`brain_engine.py`).

**الانضباط:** كل قاعدة مستنتجة `Inference` تدخل المسبح كـ`InvariantHypothesis` بشرائط مسبقة وتجربة مميِّزة عبر مسار الفرضيات القانوني حصرًا؛ لا مسار جانبي للتنفيذ؛ CausalGuard سلطة التأكيد الوحيدة؛ فشل الطبقة يتحلل إلى no-op لا فشل مفتوح. اختبارات الانحدار 19/19 (`tests/test_umdr52_w1_behavioral.py`).

**الحدود المعلنة:** انقلاب OUTCOME قيس على الfixture؛ Juice Shop أظهر ORDER+pool فقط في هذا الشكل الهدف — مقاسًا، لا مخفيًا.
