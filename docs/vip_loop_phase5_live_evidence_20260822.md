# VIP Loop — Phase 5 Live Evidence (2026-08-22)

## Scope and authorization

This phase used only the authorized local Juice Shop and WAPTLab environments. No lab source was modified. Credentials and session cookies remained under `/tmp` and are not part of release artifacts.

## Juice Shop r5

The run used a fresh qualification workspace and engagement, `authorized-active` mode/profile, `--no-llm`, and the local Juice Shop URL. The target was contacted successfully. The run duration was 227.405 seconds and the recorded container image digest was `sha256:73c53fbf442e8337b3ea3d98c7e8550308854701ebdfce4cc39768f36b75430e`.

| Metric | Result |
|---|---:|
| Total reported findings | 59 |
| Candidate | 52 |
| Needs Human Review | 4 |
| Not Scanned | 3 |
| Reported confirmed | 0 |
| Strict confirmed | 0 |
| Sealed/replayable ProofBundles | 0 |
| Target modified | False |

The 59 entries are **not confirmed vulnerabilities**. The strict verifier recorded no causal-signal/negative-control/replay-complete promotion, and the run therefore produces zero Tool-Confirmed findings. This is a successful evidence-preserving negative result, not a claim that Juice Shop is clean.

## WAPTLab

The local WAPTLab service was listening on port 8000. Plain HTTP requests from the bounded health probe returned `403 Access blocked`, while the Chromium-rendered `/login` and `/register` pages were readable. Registration requires sending an email verification code; no signup, OTP bypass, or external mailbox operation was performed.

An existing test-only cookie fixture under `/tmp` was used for one bounded harness attempt after adding optional, target-agnostic `--cookie-file` support. The process produced no workspace artifact or report after more than seven minutes and was stopped. It is therefore **inconclusive/blocked**, not a live WAPTLab result and not evidence of findings.

The repository's existing WAPTLab qualification report remains explicit: `live_qualification=false`, `target_contacted=false`, `status=mock_reproducible`, and `final_confirmed_minimum=0`. Mock `tool_confirmed_count=5` values are not live confirmations because runtime fields and target-backed ProofBundles are absent.

## Current qualification conclusion

Phase 5 does not satisfy VIP qualification. Juice Shop demonstrated target contact and 59 safely non-promoted observations, but zero strict confirmations. WAPTLab remains blocked by access/auth/runtime completion and has no live ProofBundle evidence. No target-specific production behavior was added; the only qualification-harness change is optional cookie-file plumbing with values excluded from logs and artifacts.
