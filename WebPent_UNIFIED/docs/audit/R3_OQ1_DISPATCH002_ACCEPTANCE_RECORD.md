# R5 — OQ-1 CLOSURE RECORD: Dispatch #002 acceptance criteria (A1–A10)

Dispatch #005 rider R5 requires Dispatch #002's canonical A1–A10 text to be
committed into the repo audit record, closing R2-V's escalated open question
OQ-1. This file is that audit record.

## Disposition: PARTIAL — reconstructed-with-provenance; canonical text still outstanding

R2-V (R2V_VERIFICATION_REPORT_20261005.md, §OQ-1) escalated with cause:
"the canonical text of Dispatch #002's A1–A10 is not in session/on disk"
and recommended "the Orchestrator holds the canonical text and should
attach it to the R3 record." Dispatch #005 lists Dispatch #002 among the
provided inputs, but its verbatim text is not present in the session
record or on disk; TEAM-CODE constraint C1 (zero hallucination) forbids
presenting a fabrication as canonical.

What IS on disk (independently verifiable provenance): R2-V's §V6
acceptance walk quotes four of the ten criteria verbatim-enough to record:

| # | Recorded text (provenance: R2V_VERIFICATION_REPORT_20261005.md §V6 table) |
|---|---|
| A1 | "every FIX-NOW item verified-present-with-contracts OR escalated with frozen-target justification" |
| A5 | "bandit: no new findings untriaged" |
| A8 | "operator-visible changes documented" |
| A10 | "single-command replay of every claim" |

The remaining six (A2, A3, A4, A6, A7, A9) are NOT recoverable from any
on-disk R2-era record. They are registered here as absent-by-provenance;
the C1–C9 constraint battery was used by R2-V as the verified proxy for
the remaining criteria (per its own §V6 note).

## Carry-forward (registered, not silently dropped)

OQ-1 remains OPEN at P3 severity, narrowed: "supply canonical text for
Dispatch #002 A2/A3/A4/A6/A7/A9". R3-V (Dispatch #006) should verify this
record's provenance claims (one command: grep the quoted strings in
R2V_VERIFICATION_REPORT_20261005.md) and the Orchestrator should attach
the canonical text at the next ruling record.

## R3's own acceptance criteria

R3's acceptance criteria are defined by Dispatch #005 §8 (A1–A12) and are
recorded verbatim in EVIDENCE_REPORT_20261005_v7.md §9 (shipped in this
package), so the R3-V cycle does not inherit the same gap.
