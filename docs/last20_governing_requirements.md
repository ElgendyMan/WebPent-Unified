# Last-20 Governing Requirements Checklist

## pasted_content_2 / G-02

The historical G-02 plan requires: reproducible baseline inventory; explicit transport coverage including HTTP/WebSocket/browser/subprocess/shell/cloud/SSH; dynamic import detection; alias normalization; unknown-indirect fail-closed behavior; an independent secondary scanner; runtime invariant and mutation gates; pre-commit/CI artifact enforcement; structured narrow expiring allowlist; ActionExecutor/adapter registration prerequisite; ProofBundle event per approved action; typed capability gaps instead of clean results; and release evidence. Acceptance gates G02-A through G02-J include inventory, coverage, independence, runtime safety, governance, CI, runtime wiring, evidence, capability truthfulness, and regression.

## pasted_content_3 / identity and wildcard

Identity must be default-off, scope checked before submission and again before following verification links, transport-agnostic for Gmail API/IMAP, bounded by timeout and signup budget, redaction-safe, engagement-scoped in the vault, excluded from checkpoints/reports, and consumed downstream by authentication/access-control/business-logic. Required gates include scope respect, verification-link rescope, report non-leak, same identity reuse across login pages, TTL expiry, and mailbox failure as inconclusive.

Wildcard scope must compile strict anchored regexes, preserve explicit out-of-scope precedence, feed the existing target scope object, be consumed by takeover and crawler, record out-of-scope discoveries as negative evidence, and have an integration proof that both consumers use the same compiled scope object.

## Full VIP acceptance boundary

No live qualification or confirmation may be claimed without causal signal + negative control + replayable ProofBundle. WAPTLab and Juice Shop must not be run in this review. The final classification must separate runtime-proven, implemented-but-not-live-qualified, partial, design-only, blocked-by-capability, and not-implemented. Until all live gates pass, release label remains Advanced Candidate / Evidence-Aware Bounded Autonomous Bug Hunter, not VIP Smart Autonomous Bug Hunter.
