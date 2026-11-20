# WebPent VIP Smart Research Benchmark v1

هذا benchmark **versioned وauthorized-lab-only**. مصدر الحقيقة للـWAPTLab هو `docs/waptlab_vulnerability_catalog.yml`؛ أما `expected_findings.json` فيحمل عقد الدليل المطلوبة لكل class ولا يثبت أن تشغيلًا حيًا اكتشفها.

## القياس

يقبل القياس finding فقط إذا كانت حالته `confirmed` أو `tool-confirmed`، ومعها `causal_signal` و`negative_control_complete` و`proof_bundle_sealed`. تُحسب المفاتيح بمبدأ set semantics، لذلك لا تضخم النتائج المكررة precision أو recall. استخدم:

```bash
PYTHONPATH=src:. .venv/bin/python scripts/evaluate_benchmark.py \
  --benchmark benchmarks/vip_v1/expected_findings.json \
  --observed path/to/observed_findings.json \
  --output benchmark_result.json
```

ملف observed يجب أن يكون JSON array أو كائنًا يحتوي على `findings`. لا تُعتبر نتائج الاختبارات الوحدوية أو fixture المحلية تقريرًا عن WAPTLab recall.

## السيناريوهات

يغطي `scenarios.json` المسارات الخمسة المطلوبة: discovery إلى confirmation، فشل hypothesis ثم gap resolution، رفض false positive، causal chaining مع validation مستقل، واستمرار الحملة عند غياب LLM عبر fallback deterministic. كل scenario يطلب artifacts صريحة ولا يسمح بتعديل target.

## Reset وscope

يجب أن يبدأ كل تشغيل benchmark من reset نظيف للمعمل المحلي المصرح به، مع identity وtenant وorigin موثقة في engagement policy. لا يعدّل WebPent أي ملف من WAPTLab أو Juice Shop، ولا يخزن credentials أو cookies أو OTP أو raw secrets في findings أو logs أو checkpoints. أي action خارج exact scheme/host/port/path وprofile المصرح به يُرفض fail-closed.

## Release interpretation

هذا artifact يثبت قابلية القياس والعقود فقط. لا يجوز وصف WebPent بأنه VIP Smart Autonomous Bug Hunter قبل ثلاث qualification runs محلية مستقلة تحقق بوابات الخطة: 15/20 confirmations، precision لا تقل عن 90%، reproducibility لا تقل عن 95%، ProofBundle coverage بنسبة 100%، ولا scope violations أو duplicate executions أو silent precondition failures. قبل ذلك الوصف الصحيح هو **Evidence-Aware Bounded Autonomous Bug Hunter / Smart Research Beta**.
