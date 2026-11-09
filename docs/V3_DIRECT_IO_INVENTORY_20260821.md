# WebPent v3 Direct-I/O Inventory

**الغرض:** تسجيل كل موضع فعلي للـHTTP/browser/socket/subprocess I/O وبناء allowlist قابلة للتحقق آليًا. هذه الوثيقة لا تمنح استثناءات تلقائية؛ كل entry يحتاج boundary contract واختبار policy مكافئ.

> الحالة الحالية: **CLOSED للـstatic inventory/allowlist contract**. الـruntime qualification لكل capability منفصلة ولم تُستنتج من هذا الإغلاق.

## مصادر التنفيذ الحالية

| الفئة | المواضع الحالية | الملاحظة |
|---|---|---|
| HTTP transport | `shared/http.py`, `shared/http_discovery.py`, `shared/httpx_client.py` وأي wrappers تحت `shared/` | يجب أن تمر scope/SSRF/redirect/resolver من policy موحدة |
| Browser | `shared/browser.py` وPlaywright agents | يجب تسجيل navigation/form/upload/network observation عبر executor |
| Subprocess tools | `tools/utils/subprocess.py` ثم `tools/exploitation/{dalfox,phpggc,sqlmap,ysoserial}.py` و`tools/recon/{ffuf,httpx,katana,nuclei,subfinder}.py` | wrapper مركزي موجود، لكن registration وevent/proof ownership يحتاجان G2 |
| Socket/OOB | OOB helpers وraw transport candidates | يجب قصر listeners على interfaces/ports مصرح بها واختبارها محليًا |
| File I/O | artifact/report/export/ingest/memory modules | يجب redaction وengagement isolation وعدم إدخال ملفات target كتعليمات |
| Broker/worker | Celery task dispatch وRedis helpers | يجب encrypt payload، TLS في non-local، idempotency وfencing |
| Database | SQLite action ledger وstate/report stores | يجب transaction boundaries وresume/crash tests |

## قواعد allowlist المقترحة

1. لا يُسمح باستدعاء `requests`, `httpx`, `urllib`, `aiohttp`, Playwright، socket، أو subprocess من agent جديد مباشرة.
2. أدوات CLI لا تُشغّل إلا عبر `webpent.tools.utils.subprocess.run_command` أو adapter مسجل يثبت `shell=False` وargument allowlist وtarget policy.
3. Browser actions لا تُنفّذ من node مباشرة؛ يلزم browser adapter يربط action/identity/tenant/correlation ID بالـActionExecutor.
4. أي socket/OOB capability غير مسجلة تعود `blocked_by_capability` ولا تعود `clean`.
5. CI يجب أن يفشل عند إضافة direct-I/O خارج manifest معتمد، ويجب أن يحتوي كل استثناء على اختبار يثبت scope وredaction وbudget وevent logging.

## الوضع الحالي

يولّد `scripts/scan_direct_io.py` inventory AST كاملًا إلى `docs/direct_io_inventory.json`، ويُنتج `scripts/render_direct_io_inventory.py` النسخة المقروءة `docs/DIRECT_IO_INVENTORY.md`. يغطي artifact كل direct imports/calls المكتشفة حاليًا، مع تمييز HTTP sync/async وPlaywright وraw TCP/DNS وsubprocess، وتوثيق API وGraphQL وfile-upload وOOB كـlogical HTTP transports. الاستثناءات الخام محكومة بـ`APPROVED_DIRECT_FILES`.

## اختبار القبول المنفذ

`tests/test_g02_direct_io_inventory.py` يطابق artifact مع source AST حرفيًا، ويتحقق من تطابق logical contracts وallowlist، ويرفض transport غير مصنف أو record مكرر. لذلك يفشل CI إذا أضيف direct-I/O جديد دون إعادة توليد ومراجعة artifact. أما اختبارات scope/host/redirect ورفض capability غير المسجلة فتبقى runtime policy gates مستقلة، ولا تُعد نتيجة static inventory وحدها qualification حية.
