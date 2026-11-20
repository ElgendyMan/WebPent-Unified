# WebPent v3 Qualification Harness — 2026-08-21

## Purpose

هذا الـharness هو عقد qualification الحي لمشروع WebPent. يلتقط كل تشغيل في مجلد مستقل، ويثبت commit المشروع، commit المختبر عندما يتاح، image digests، source/config seed fingerprints، capability manifest، campaign plan، execution events، وملفات التقارير الناتجة.

> **قاعدة التأكيد:** لا يُحتسب finding كـ`strict_confirmed` لمجرد أن التقرير كتب `Tool-Confirmed`. يلزم وجود causal signal صريح، وnegative control مكتمل، وsealed evidence/proof bundle، ودليل قابل لإعادة التشغيل. الحالات الناقصة تبقى candidate أو `Needs Human Review`.

## تشغيل harness

```bash
cd /tmp/webpent_v72_git_recovered
export PYTHONPATH="$PWD/src:$PWD"

.venv/bin/python scripts/qualification_harness.py \
  --target waptlab \
  --url http://127.0.0.1:8000 \
  --creds-file /tmp/waptlab_creds.json \
  --output-root /tmp/webpent_runs/v3_qualification_waptlab_v1 \
  --runs 1

.venv/bin/python scripts/qualification_harness.py \
  --target juice-shop \
  --url http://127.0.0.1:3000 \
  --creds-file /tmp/juice_creds.json \
  --output-root /tmp/webpent_runs/v3_qualification_juice_v1 \
  --runs 1
```

يمكن استخدام `--reset-between-runs` مع WAPTLab فقط. هذا الخيار يستعمل compose المحلي الثابت `/tmp/WAPTLab_readonly/docker-compose.yml` مع `down -v` ثم `up -d --build`. لا يقبل الـharness أوامر shell عشوائية، ولا يغيّر ملفات مصدر المختبر. عند غياب reset أو عدم إثباته، يظل seed fingerprint موثقًا باعتباره source/config fingerprint وليس دليلًا على reset حي.

## Artifacts

لكل تشغيل ينتج harness `qualification_run.json` و`scan.log` داخل مجلد مستقل. وفي نهاية مجموعة التشغيل ينتج `qualification_matrix.json`. تحتوي run record على `target_modified=false`، metadata للـcontainers، hashes، command plan، tool manifest، report path، execution events، ومؤشرات `reported_confirmed` و`strict_confirmed`.

## Metrics contract

| Metric | Definition |
|---|---|
| `findings_total` | كل العناصر التي صدرت في التقرير، مع إبقاء `Clean` ظاهرًا بوصفه detector result لا finding قابلًا للتصعيد. |
| `reported_confirmed` | العناصر التي حمل تقريرها label `Tool-Confirmed` بعد scan. |
| `strict_confirmed` | subset من `reported_confirmed` يمر بعقد causal + negative control + sealed bundle + reproducible evidence. |
| `precision` | لا تُحسب تلقائيًا من static source catalog؛ تحتاج live case mapping صريحًا. |
| `recall` | لا تُحسب تلقائيًا من static source evidence؛ تحتاج seeded/live truth mapping قابلًا للمراجعة. |
| `reproducibility` | تقاطع strict-confirmed IDs بين runs مقسومًا على اتحادها، عندما توجد strict confirmations. |

## Qualification decision

الوضع الافتراضي للحarness هو `not-qualified` إلى أن تتوفر ثلاثة clean runs، وتكون target state/reset وscope وcleanup قابلة للتدقيق، ويوجد truth mapping حي صريح يسمح بقياس precision/recall. هذا السلوك مقصود حتى لا يتحول عدد findings أو label قديم إلى ادعاء VIP confirmation.

غياب أداة مثل `katana` أو `sqlmap` لا يُحتسب finding، بل يظهر في capability manifest كـblocked أو fallback. كما أن `No automated validation tool available` و`Needs Human Review` لا يُحوّلان إلى confirmed تلقائيًا.
