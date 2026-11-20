# WebPent Lab Comparison — 2026-08-22

## Scope and execution conditions

This comparison contains two independent clean engagements. WAPTLab and OWASP Juice Shop were run locally only. LLM analysis was disabled to keep the run deterministic and to avoid consuming an external model quota. No finding is treated as confirmed unless a causal signal, a completed negative control, and a persisted ProofBundle are present.

WAPTLab was scanned at `http://127.0.0.1:8000` with the lab allowlisted user-agent and engagement `waptlab-live-20260822-r2`. Juice Shop was scanned at the container address `http://172.17.0.2:3000` with engagement `juice-shop-live-20260822`, because Docker's host publication on `127.0.0.1:3000` accepted a listener but did not complete the HTTP connection from the sandbox host. The direct container address returned HTTP 200 and was used only within the local Docker network.

## Results

| Target | Raw findings | Tool-Confirmed | Needs Human Review | Pending | Not Scanned | ProofBundles observed in CLI output |
|---|---:|---:|---:|---:|---:|---:|
| WAPTLab | 14 | 0 | 4 | 10 | 0 | 0 |
| OWASP Juice Shop | 64 | 0 | 7 | 54 | 3 | 0 |

### WAPTLab breakdown

The 14 findings were four `Needs Human Review` items (one XXE and three SSTI) plus ten `Pending` XSS candidates. No `Tool-Confirmed` finding or ProofBundle was emitted in this run.

### Juice Shop breakdown

The 64 findings were two `Needs Human Review` SSTI items, one `Needs Human Review` XXE item, four `Needs Human Review` API-issue items, three `Not Scanned` API-issue items, and 54 `Pending` XSS candidates. No `Tool-Confirmed` finding or ProofBundle was emitted in this run.

## Fix applied during qualification

The first WAPTLab live run exposed a checkpoint serialization failure caused by a live `RuntimeContext` containing an `RLock` being deep-copied through nested checkpoint metadata. The checkpoint redaction boundary was changed so live `RuntimeContext` instances at any nesting level are projected to a checkpoint-safe descriptor before generic copying. A regression test covers channel values, metadata, and nested values. The WAPTLab run was then repeated successfully after the fix.

## Interpretation

The raw finding count increased substantially on Juice Shop, but the evidence gate correctly kept all findings below Tool-Confirmed. The current live result therefore demonstrates discovery breadth and safe uncertainty handling, not confirmed vulnerability accuracy. The main remaining qualification gap is the validator path: browser/API causal verification, negative controls, and persisted ProofBundles must be produced on these targets before any finding can be promoted to Tool-Confirmed.

The scan also reports that some Juice Shop challenges depend on unavailable external services (for example Alchemy and a local LLM endpoint). Those challenge families are treated as coverage limitations, not as findings.

## Safety and integrity controls

No WAPTLab or Juice Shop source code was modified. The engagements used separate IDs and were not merged for this comparison. Scope and SSRF controls remained enabled. No heuristic promotion was used, and `unknown` remained fail-closed as a missing-validator state.
