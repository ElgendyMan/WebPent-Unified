# UM-DR-34 LLM Redaction and Checkpoint Report

**Phases 6–7 deliverables — credential protection at the provider
boundary and checkpoint safe failure.** Implementation:
`shared/untrusted_content.py`, `shared/redaction.py`,
`graph/checkpoints.py` (re-pinned per DR-009).

---

## 1. Provider boundary architecture (preserved)

* `_ProviderGuardedRunnable.invoke()/ainvoke()` (`shared/llm.py:935/:963`)
  remain the final provider-side choke points and still call
  `secure_llm_input()` immediately before provider I/O. Untouched.
* Every model from `get_llm` is wrapped before fallback composition;
  failover members are themselves the wrapped objects.
* Batch/stream/abatch/astream route through the guarded
  invoke/ainvoke by Runnable inheritance — now PINNED BY TEST (the
  baseline had zero coverage of these paths; a future override can no
  longer silently bypass: `TestProviderGuardedRunnable` fails closed).
* `UntrustedContent` unchanged: target-controlled content reaches the
  provider only as the label+structural-facts projection
  (`to_prompt_fragment`); raw text is reachable only via the explicit
  `raw_for_deterministic_validation()` review path. Pinned again by
  `TestUntrustedContentProjection`.

## 2. The secure_llm_input recursion defect (§6.1) — fixed

Baseline: the Mapping branch recursed values but **never applied the
credential-key check to mapping keys** — only `secure_prompt_value`'s
Mapping branch checked keys, so a dict reaching the boundary at top
level or through a list passed with `{"sessionid": ...}`,
`{"cookie": ...}` keys completely unchecked (empirically verified
pre-fix).

Fix: the Mapping branch now applies `_credential_key` to EVERY key
together with its value, at every nesting level, and raises
`PromptCredentialLeakError` fail-closed. Pinned by
`TestSecureLlmInputKeyCheck` (top-level, nested, list/tuple nesting).

## 3. Cookie-name families (§6.2)

`_CREDENTIAL_KEY_RE` extended (delimiter-bounded, case-insensitive,
space/dot-normalized) with the recognized session-cookie families:
`PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId` (via dot
normalization), `sessionid`/`SESSIONID`, `session_id`, `sid`,
`connect.sid`/`connect_sid`, `sessid`, `csrftoken`/`csrf_token`/
`xsrf_token`, `refresh_token`, `id_token`, `auth_token`,
`private_key`, `client_secret` — plus `cookies` (plural).

No over-redaction: benign fields (`user_id`, `consideration`,
`resident`, `insight`) still pass untouched — pinned by
`test_benign_application_fields_not_over_redacted`.

Message clones: `additional_kwargs` and `tool_calls` are now
sanitized on the cloned message (some providers serialize them into
the request); frozen/immutable variants drop the attribute
(fail-closed) rather than pass it through unchecked.

## 4. General redaction helper (§6.4)

`shared/redaction.py::redact_value` is now **key-aware**: a value
under a sensitive dictionary key is redacted WHOLE (e.g. an opaque
session value under `PHPSESSID`), not only when it matches an embedded
`k=v`/bearer/cookie string form. The checkpoint-specific redaction in
`graph/checkpoints.py` (its own key-aware `_redact_value`) is
unchanged and remains authoritative for persisted channels.

One pinned legacy expectation was updated (documented, strictly
stronger contract): `tests/test_byte_level.py` expected
`Cookie: "session=[REDACTED]"` (prefix preserved); the key-aware
contract redacts the entire header value — `"session=abc"` never
survives in any form.

## 5. Checkpoint safe failure (§7)

Baseline: `_redact_channel("runtime_context", ...)` caught EVERY
exception and persisted `{}` silently; on resume,
`RuntimeFactory.from_descriptor({})` rebuilt a **blank runtime**
(budget/kill-switch accounting reset) or dropped the channel — an
undebuggable false-success resume. No log line existed anywhere.

The new contract (all pinned by
`tests/test_umdr34_checkpoint_safety.py`):

1. Never persist raw runtime secrets as a fallback (unchanged).
2. A redaction failure emits a **structured, secret-free ERROR event**
   (channel + exception CLASS only — a hidden-secret test proves the
   marker value never appears in any log record).
3. The persisted artifact carries an explicit
   `{"runtime_context_status": "degraded", "degraded_reason": <class>}`
   marker — it can never be mistaken for a valid empty context.
4. The restore path detects the degraded marker, **refuses to rebuild
   a runtime from it**, drops the channel, and logs the degradation
   loudly — no silent resume-as-if-complete, no false success.
5. Secret channels stay emptied; vault-only secret restore and the
   fail-closed restoration error path are unchanged.
6. A VALID runtime context still descriptors and restores exactly as
   before (no availability regression).

## 6. What was NOT changed

The `UntrustedContent` architecture, the provider guard wiring, the
checkpoint vault sealing, the secret channels, `graph/checkpoints.py`'s
own `_redact_value` — all byte-preserved in behavior; only the
`runtime_context` failure branch and the documented redaction
strengthening changed.
