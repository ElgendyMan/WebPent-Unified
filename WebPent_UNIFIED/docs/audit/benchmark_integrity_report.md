# Benchmark Integrity Report

| Benchmark | Ground truth independent? | Detector sees truth before decision? | Negative cases? | Adversarial cases? | Replayable? | Audit conclusion |
|---|---|---|---|---|---|---|
| DCVU v1 | Yes, controlled synthetic facts | No, through the intended observation boundary | Yes | Limited | Framework and historical artifacts | Valid controlled capability benchmark; not real-target proof |
| RTA v1 | Target specs and local fixture truth are separated within the harness | No, observation is produced from local HTTP behavior | Yes, in the local harness | Misleading response/partial access cases are modeled | Generic mechanisms exist; case-specific coverage is incomplete | Valid local lifecycle assessment; detection-quality portability remains unproven |
| IRTA v2 | Generator contracts are separate from benchmark execution | No in the design; no live detector execution was fabricated | Contract support exists | Four mutation modes exist | Deterministic inputs are replayable; no live proof bundle was minted | Benchmark readiness and anti-overfitting infrastructure, not a quality result |

## Mandatory integrity answers

DCVU has independent controlled ground truth and negative cases. RTA has bounded local ground truth and negative-control mechanisms, but accepted live case-specific evidence is incomplete. IRTA v2 preserves the separation and adds independent target generation and mutation contracts; its unexecuted case slots remain blocked. In no benchmark is route reachability, HTTP 200, lesson completion, or fixture presence treated as a vulnerability.

No blocked, observation-only, inconclusive, or unsupported outcome is converted to TP, FN, clean, or confirmed. Metrics are only meaningful for cases with valid causal contracts, candidate/control observations, and replayable evidence.
