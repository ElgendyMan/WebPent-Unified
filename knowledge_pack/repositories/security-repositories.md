# Security Repository Catalog

هذا catalog يصف repositories عامة يمكن استخدامها لتوجيه اختيار المنهجية أو corpus، وليس لتبرير اختبار هدف غير مصرح به. عند ingest لملفات فعلية يجب استخدام commit pinned والتحقق من المسار والترخيص.

| Repository | الاستخدام داخل WebPent | المصدر الرسمي | ملاحظة الثقة |
|---|---|---|---|
| OWASP WSTG | منهجية اختبار تطبيقات الويب وchecklists | [github.com/OWASP/wstg](https://github.com/OWASP/wstg) | مرجع منهجي؛ لا يثبت finding |
| OWASP ASVS | متطلبات تحقق قابلة للتحويل إلى verification questions | [github.com/OWASP/ASVS](https://github.com/OWASP/ASVS) | معيار تحقق؛ يجب ربطه بسلوك مرصود |
| PayloadsAllTheThings | corpus payload/advisory حسب الفئة | [github.com/swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | محتوى community؛ يُستخدم كاقتراح bounded فقط |
| SecLists | wordlists وfuzzing corpus | [github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) | لا يُشغّل تلقائيًا خارج scope؛ الحجم والمسار يحتاجان ضبطًا |
| nuclei-templates | أمثلة templates لاختبارات قابلة للمراجعة | [github.com/projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | templates تحتاج review وscope وnegative control |
| PortSwigger Web Security Academy | labs وموضوعات write-up تعليمية | [portswigger.net/web-security/all-materials](https://portswigger.net/web-security/all-materials) | تدريب قانوني داخل labs؛ ليس ترخيصًا لهدف خارجي |
| OWASP Juice Shop | target تدريبي محلي وسيناريوهات تعليمية | [github.com/juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | استخدمه فقط كـlab؛ لا يتم تعديله ضمن هذه الحزمة |
| WAPTLab | target المستخدم في الاختبارات الداخلية السابقة | [github.com/selimwdev/WAPTLab](https://github.com/selimwdev/WAPTLab) | مرجع lab فقط؛ لا تعدّل repository أو ملفات التشغيل |

## سياسة الاستخدام

يُفضّل إدخال summaries صغيرة ومراجَعة إلى knowledge pack، أو إدخال مسارات محددة من commit ثابت. لا يقوم WebPent بتشغيل تعليمات أو scripts من repository لمجرد أنها استُرجعت من RAG. أي template أو payload يمر عبر قواعد scope وrate limits وvalidator، ولا يتحول إلى finding بلا evidence.

## حقول provenance المقترحة

كل entry مستورد من repository يحمل `source_repo` و`source_commit` و`source_path` و`source_url` و`license_note` و`trust_note`. هذه الحقول تمنع خلط معرفة corpus مع target observations، وتُظهر للمراجع لماذا ظهر السياق في planner أو hypothesis analyzer.
