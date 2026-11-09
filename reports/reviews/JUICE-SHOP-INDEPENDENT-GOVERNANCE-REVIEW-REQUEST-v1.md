# Juice Shop Independent Governance Review Request v1

**Status:** `PENDING_INDEPENDENT_GOVERNANCE_SIGNOFF`

**Scope:** مراجعة حوكمة مستقلة لحزمة Juice Shop المحلية فقط. لا يصرح هذا المستند بتشغيل Official P10 Runs ولا يمثل approval أو qualification.

## المطلوب من المراجع المستقل

يجب أن يكون المراجع شخصًا حقيقيًا مستقلًا عن بناء detector output وتعديل النتائج. عليه تثبيت هويته المهنية أو اسمه القابل للتحقق، وتاريخ المراجعة، ونطاق ما راجعه، والـcommit والـhashes التي اعتمد عليها.

يراجع المراجع `docs/juice_shop_governance_decision_v1.json`، و`docs/juice_shop_p10_ground_truth_v1.json`، و`docs/p10_oracle_semantics_decision_v1.json`، و`docs/juice_shop_source_ground_truth_manifest_v1.json`، و`docs/juice_shop_loopback_runtime_manifest_v1.json`، و`docs/release_manifest.json`، و`docs/release_manifest_provenance_v1.json`، إلى جانب evidence والـcandidate decisions.

## قرارات إلزامية منفصلة

| الموضوع | القرار المطلوب |
|---|---|
| Archive provenance | تأكيد أن release manifest وprovenance sidecar وarchive قابلة للتحقق وإعادة البناء |
| Source identity | الفصل بين Juice Shop source commit وWebPent manifest/release commit |
| Access-log mapping | حسم الفرق بين frozen `/ftp/access.log` وsource `/support/logs/access.log.<UTC-date>` |
| Oracle contract | إعادة اعتماد current canonical oracle contract أو رفضه مع سبب محدد |
| الحالات الثماني غير scoring | قرار مستقل لكل حالة: approved أو blocked أو observation-only أو rejected أو out_of_scope |
| Final scoring set | تثبيت cases/classes المعتمدة فقط دون احتساب الحالات غير المثبتة |
| Run gate | يظل `official_isolated_p10_runs_authorized=false` ما لم تتحقق coverage والـevidence gates كاملة |

## قواعد fail-closed

لا يجوز للمراجع تحويل internal pre-review إلى independent approval. لا يجوز تعديل frozen ground truth لإخفاء drift، ولا ترقية candidate بلا causal predicate وnegative control وcentral verification وsealed/replayable ProofBundle. وحتى بعد signoff، لا تُعتبر P10 مؤهلة قبل الوصول إلى 10 cases و6 classes وتشغيل ثلاث جولات معزولة صالحة.

## الحالة الحالية

لا يوجد reviewer مستقل مسجل في هذه الحزمة حتى تاريخ 2026-08-27. لذلك يظل هذا المستند **طلب مراجعة** وليس نتيجة مراجعة، وتظل P10/P9/VIP `NOT_QUALIFIED` وBug Bounty `BLOCKED`.
