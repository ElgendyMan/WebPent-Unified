# Controlled Local IDOR Target v1

## الغرض والنطاق

هذا الهدف **تطبيق محلي purpose-built ومقصود أن يكون vulnerable** لاختبار دورة WebPent من طرف إلى طرف: target readiness، baseline، candidate، independent negative control، causal oracle، central verification، sealing، وreplay. لا يمثل هذا الهدف تطبيقًا خارجيًا أو عميلًا حقيقيًا، ولا يثبت جودة الاكتشاف في العالم الحقيقي، ولا يفتح P10 أو P9 أو VIP.

الخادم يُنشأ داخل العملية باستخدام `ThreadingHTTPServer` ويرتبط فقط بـ`127.0.0.1` على منفذ ephemeral. الـcontext manager يضمن `shutdown()` و`server_close()` وjoin للخيط في `finally`/الخروج. لا توجد خدمة دائمة أو scheduler أو callback أو Docker أو اتصال خارجي.

## النموذج الحتمي

يحوي الـfixture أربع قيم opaque داخل الذاكرة فقط: synthetic owner actor، synthetic attacker actor، resource مملوك للمالك، وresource محمي غير متعلق بالمالك. `GET` لا يغير الحالة. `reset()` يعيد نفس snapshot ويثبت hash حتميًا؛ لا يتم حفظ raw response body أو cookie أو token أو credential.

المسار الوحيد المقصود هو `/controlled/resources/{opaque_resource_id}`. يمرر الاختبار actor selector synthetic غير سري في query parameter. يسمح التطبيق للمالك بقراءة مورده، ويسمح attacker عمدًا بقراءة مورد المالك (IDOR)، لكنه يمنع attacker من قراءة unrelated protected resource. أي actor أو route أو method غير معتمد يظل مرفوضًا، وPOST/PUT/DELETE ترجع `405`.

## TargetSpec والـauthorization

يُبنى `TargetSpec` بعد بدء الخادم، ويثبت `http://127.0.0.1:{ephemeral_port}`، `allow_private_target=True`، `auth_mode=unauthenticated`، و`user_confirmed=True` داخل authorization record لأن التفويض هنا خاص بالهدف المحلي المصمم لهذا الاختبار. لا توجد real credentials أو login أو token generation. `ScopeValidator` يُستخدم قبل كل GET، بينما adapter يفرض route grammar الدقيقة فوق host/port scope.

## التجربة السببية

التجربة ثابتة من ثلاث قراءات شبكة فعلية:

| الدور | الهوية | المورد | التوقع |
|---|---|---|---|
| baseline | synthetic owner | owner-owned resource | allowed؛ invariant holds |
| candidate | synthetic attacker | owner-owned resource | allowed بشكل غير صحيح؛ invariant violated |
| negative control | synthetic attacker | unrelated protected resource | denied؛ invariant holds |

لا يعتمد القرار على HTTP status وحده. كل observation تحمل `target_backed=true` و`evidence_origin=target_runtime` وrequest/response digests وsemantic signals تشمل actor role، resource relation، authorization expectation، outcome، وinvariant. `OracleEngine` لا يصدر `CONFIRMED` إلا إذا اختلف candidate دلاليًا عن baseline والـcontrol وحقق violation مع بقاء baseline/control على invariant.

## الإثبات وإعادة التشغيل

يُمرر causal result إلى `verify_replay_evidence()` مع target fingerprint، target identity، target context hash، campaign/run IDs، vulnerability class، scope/identity context، وredacted observations. لا يُنشأ proof إلا للـ`CONFIRMED` مع observations الثلاث الفعلية. الناتج ProofBundle من نوع `target_runtime`، `target_backed=true`، sealed، وreplayable؛ mismatch في run/context/refs/oracle/seal يفشل replay.

هذا ProofBundle **technical validation evidence فقط**. الـcase مسجل على أنه `approved_scoring_case=false` و`qualification_effect=false`، ولا يضاف إلى approved scoring set تلقائيًا. تظل `official_isolated_p10_runs_authorized=false` و`human_independent_signoff_obtained=false` وP10/P9/VIP `NOT_QUALIFIED` وBug Bounty `BLOCKED`.

## الاختبارات والحدود

الاختبارات تثبت loopback-only registration، رفض origins خارجية، GET-only semantics، reset determinism، ownership oracle، ثلاث GET observations، target-runtime provenance، seal/verify/replay، ورفض governance promotion. أي توسيع إلى WebGoat أو crAPI أو credentials أو mutation أو external target يحتاج قرار owner منفصل؛ لا يقوم هذا adapter بتقديم صلاحيات أو bypasses لذلك.
