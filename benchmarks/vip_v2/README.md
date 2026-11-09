# WebPent VIP v2 Offline Qualification

هذا المجلد يعرّف **fixtures وmanifest فقط** لقياس طبقة البحث الذكي بشكل قابل للتكرار داخل بيئة offline. لا يحتوي على نتائج تشغيل، ولا ينفذ network أو browser أو provider calls، ولا يثبت أن WAPTLab أو Juice Shop تم اختبارهما.

## Contract

يجب تمرير `QualificationFixture` وrunner حتمي injected إلى `qualify_vip_v2`. ويجب تنفيذ **ثلاث repetitions مستقلة على الأقل**. يتم حساب discovery من `candidate_case_ids`، بينما تعتمد proof rate وreplay success rate فقط على `proof_case_ids` و`replay_case_ids` التي يقدمها الـrunner بعد تحقق مستقل. لا تتحول candidate findings إلى confirmed تلقائيًا.

كل confirmation ما زال مشروطًا بمسار المشروع المركزي: causal signal من target، negative control مستقل، ProofBundle مركزي sealed/replayable، ونجاح replay. أي نتيجة ناقصة تظل candidate أو needs review.

## Files

| الملف | الغرض |
| --- | --- |
| `manifest.json` | تعريف schema والـrelease gates وحدود السلامة. |
| `scenarios.json` | أسطح وسيناريوهات report-safe بلا payloads أو أسرار أو نتائج. |
| `../vip_v1/expected_findings.json` | مصدر truth معلن لإجراء مقارنة case-key عندما يمرره المستخدم أو الـrunner صراحة. |

## Honest reporting

القيمة `results: null` مقصودة. لا يجوز إنشاء تقرير qualification يدّعي تغطية أو عدد findings اعتمادًا على manifest أو scenario definitions وحدها. يجب إرفاق runs صريحة وartifacts قابلة للمراجعة، مع إبقاء `live_qualification_proven` غير مثبت إلى أن توجد أدلة تشغيل live مصرح بها.
