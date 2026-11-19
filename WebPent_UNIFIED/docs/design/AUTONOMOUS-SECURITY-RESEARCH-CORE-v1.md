# Autonomous Security Research Core Upgrade v1

## النطاق والهدف

هذا milestone يضيف طبقة **Autonomous Security Research Intelligence** فوق العقود الحالية في WebPent. الطبقة الجديدة تفهم target model، تبني attack graph، تولد hypotheses مرتبة، تختار research task ذات قيمة معلوماتية أعلى، وتحتفظ بذاكرة reasoning معزولة لكل target. كل هذه المكونات **advisory**؛ لا تمنح صلاحية تنفيذ أو إثبات أو ترقية finding.

> أي inference أو potential chain يظل غير مثبت إلى أن يمر عبر target-backed observations والـcausal oracle والـcentral verifier والـsealed/replayable ProofBundle الموجودة أصلًا.

## المكوّنات المنفذة

| المكوّن | التنفيذ | الحد الأمني |
|---|---|---|
| Target Knowledge Model v2 | `webpent.knowledge.model_v2` | entities/relations/observations مع lineage وconfidence وtimestamp وlifecycle وhash حتمي |
| Attack Graph Engine | `webpent.attack_graph.engine` | graph typed حتمي؛ العلاقات غير المثبتة لا تُنتج recommendation مؤكدة |
| Vulnerability Chain Reasoning | `webpent.attack_graph.chain_reasoning` | يحتفظ بالحالة `potential` و`validation_required` ولا يدّعي exploitation |
| Hypothesis Generator | `webpent.research.hypothesis_generator` | patterns قابلة للحقن، ranking حتمي، لا requests ولا payloads ولا promotion |
| Research Planner | `webpent.research.planner` | queue advisory تعتمد على priority/risk/information gain/cost/capability |
| Security Reasoning Memory | `webpent.shared.security_reasoning_memory` | isolation مركب من engagement وtarget، redaction، bounded records، لا execution authority |
| Evidence-Aware Loop | `webpent.research_engine.evidence_aware_loop` | scope/authority/budget/capability/evidence gates، fail-closed |
| Core Evaluation | `webpent.benchmark.research_intelligence` | قياس controlled فقط؛ لا real-world detection rate ولا qualification effect |

## دورة التشغيل المقيدة

الدورة المنطقية هي:

```text
Observe admitted data
  -> update target knowledge
  -> generate hypotheses
  -> rank hypotheses
  -> select advisory research task
  -> require scope/authority/budget/capability/evidence gates
  -> hand off to existing safe execution and proof contracts
  -> update confidence and isolated memory
  -> choose next advisory task
```

`EvidenceAwareAgentLoop` لا ينفّذ الخطوة الشبكية بنفسه. إذا غاب scope authorization أو capability المطلوبة أو evidence المطلوبة، يعيد `blocked` أو `ready` بسبب واضح. وحتى عند وجود central proof، تبقى `finding_promotion_allowed=false` و`proof_authority=false` داخل هذه الطبقة.

## الذاكرة والعزل

كل record يحمل `target_scope = engagement_id:target_id`. لا يمكن لـtarget B استرجاع record أُنشئ داخل target A لأن retrieval يمر عبر boundary المعزول. تُحفظ summaries وreferences redacted فقط، ولا تُحفظ cookies أو tokens أو raw request/response bodies. IDs مبنية على digest حتمي للمحتوى المنظف، ولذلك يمكن إعادة الاختبار دون الاعتماد على UUID عشوائي.

## chain reasoning

الـchain engine يربط observations والعلاقات typed مثل `exposes` و`depends_on` و`can_access`. عندما توجد سلسلة منطقية، تكون النتيجة `potential` فقط، مع `validation_required=true`. لا تتحول السلسلة إلى confirmed finding إلا عبر مسار الإثبات المركزي القائم خارج هذا engine.

## التقييم الداخلي

تمت إضافة `ResearchIntelligenceReport` وrunner حتمي ينتج:

| المقياس | المعنى |
|---|---|
| `research_efficiency` | قيمة information gain المسجلة بالنسبة إلى requests المستخدمة في controlled cases |
| `hypothesis_quality` | تطابق ترتيب hypotheses مع expected rank في الحالات التي تحتوي ground truth للترتيب |
| `evidence_quality` | متوسط جودة evidence المسجلة في case summaries |
| `validation_accuracy` | يُحسب فقط للحالات التي تملك ground-truth outcome؛ وإلا يبقى `null` |
| `proof_completeness` | نسبة الحالات التي تملك proof complete flag |

التقرير الحالي في `reports/evaluation/research_intelligence/CORE-EVALUATION-v1.json` controlled ومحصور في target محلي اصطناعي. لذلك `real_world_detection_rate_measured=false` و`qualification_effect=false` عمدًا.

## الاختبارات والحوكمة

تغطي regression suites graph consistency، chain potential state، hypothesis determinism، planner decisions، memory isolation/redaction، evidence lineage، loop policy enforcement، وevaluation determinism. لم يتم تعديل frozen ground truth أو thresholds أو authority modes، ولم يتم فتح Official P10 أو Bug Bounty، ولا توجد أي claim بأن WebPent أصبح VIP-qualified نتيجة هذا milestone.

الحالة الحوكمية النهائية تظل:

| البوابة | الحالة |
|---|---|
| Official isolated P10 runs | `false` |
| P10 | `NOT_QUALIFIED` |
| P9 | `NOT_QUALIFIED` |
| VIP | `NOT_QUALIFIED` |
| Bug Bounty / external targets | `BLOCKED` |
| Human independent signoff | `false` |

هذا milestone يثبت ترقية هندسية في **research intelligence core** داخل نطاق controlled، ولا يثبت detection quality عامة أو portability إنتاجية أو أهلية رسمية.
