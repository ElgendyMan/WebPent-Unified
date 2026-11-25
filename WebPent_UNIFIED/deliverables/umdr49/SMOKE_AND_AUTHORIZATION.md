# UM-DR-49 P0.2/P0.3 — smoke + التفويض + بروفة safe-stop

## P0.2 — smoke (bring-up في أقل من دقيقتين — مُقاس)
| التطبيق | الإصدار المثبت | المنفذ | الحالة |
|---|---|---|---|
| Juice Shop | v20.4.0 (الحزمة المُغلّفة node22 linux x64) | 127.0.0.1:3000 | **HTTP 200** |
| WebGoat | v2023.5 (release jar) | 127.0.0.1:8080 (+WebWolf 8888) | **HTTP 302→login** |
| DVWA | master clone | — | **غير قابل للتوفير في هذه البيئة** (لا docker daemon، وapt بلا صلاحية root لـphp+mariadb) — فجوة بيئية رقمية في الشهادة |

القطع المُسلّمة لبيئة المالك: deploy/umdr49/docker-compose.yml (صور
مثبتة بالdigest + شبكة معزولة + health checks) + reset_labs.sh
(--docker/--native) + .github/workflows/umdr49_real_battery.yml
(nightly/manual فقط — خارج بوابة الـpush حسب سياسة الـCI في البرومبت).

## P0.3 — إطار التفويض
- scope files: deploy/umdr49/{juiceshop,webgoat,dvwa}.scope (default-deny)
- authorization: "umdr49-owner-approved-local-lab" — الأهداف الثلاثة
  أهداف معتمدة من المالك بهذا البرومبت (تطبيقات تدريب محلية معزولة)

## بروفة safe-stop — وجدت عيبًا حقيقيًا وأصلحته
**الاختبار:** استهداف http://127.0.0.1:9999 بملف نطاق يسمح فقط
http://127.0.0.1:3000 — النتيجة المنتظرة: رفض بصفر طلبات.
**النتيجة الأولى:** الحملة **نُفذت وأرسلت طلبات** لغير النطاق!
**السبب الجذري:** قواعد scope_file تطابق المضيف فقط وتتجاهل المنفذ
كليًا (إدخال :3000 يسمح بكل منافذ المضيف — عكس عقد الـOriginPolicy
الموثقة).
**الإصلاح:** إدخال يحمل منفذًا صريحًا يقيّد المطابقة به؛ إدخال بلا
منفذ يطابق منفذ الـscheme الافتراضي فقط.
**البروفة بعد الإصلاح:** رفض fail-closed بصفر طلبات —
"target is outside the supplied scope file: scope_file_target_url_not_in_scope".
**اختبارات الانحدار:** tests/test_umdr49_scope_port_boundary.py (5).
