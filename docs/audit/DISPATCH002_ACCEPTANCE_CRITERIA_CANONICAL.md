# DISPATCH #002 ACCEPTANCE CRITERIA — CANONICAL TEXT (OQ-1 CLOSURE, RIDER R2)

> **Provenance (Dispatch #009, §8):** This file commits the canonical text of
> the Dispatch #002 acceptance criteria A1–A10 verbatim, as ordered by the
> M2-impl charter (G2 rider R2), closing OQ-1 ("canonical A1–A10 commit").
> The prior reconstruction in `R3_OQ1_DISPATCH002_ACCEPTANCE_RECORD.md` is
> **superseded by this canonical text**. Provenance chain: Dispatch #002,
> Sprint R2 charter, Orchestrator-held record; re-issued verbatim in
> Dispatch #009 §8.

## A1–A10 (verbatim from Dispatch #002)

A1 — Every FIX-NOW item landed with passing contract tests, OR has an
     escalated dossier with a frozen-target justification.
A2 — Frozen manifest N/N byte-identical; zero frozen modifications.
A3 — Zero semantic changes to any Trust Spine component (C3 list).
A4 — All pre-existing tests pass; test count grew only; every modified
     pre-existing test is listed with justification.
A5 — bandit 0 HIGH maintained; any new LOW/MED triaged in the register.
A6 — Zero new dependencies; zero network activity; zero target execution.
A7 — Every change is fail-closed direction only (tightens/removes
     authority; never adds/loosens).
A8 — Docs updated for operator-visible changes.
A9 — The sprint's deliverable ZIP verifies from fresh extraction (tree
     diff + frozen manifest + contract tests + real-browser smoke).
A10 — Every claim in the report is reproducible by a single command.

## Supersession note

`R3_OQ1_DISPATCH002_ACCEPTANCE_RECORD.md` (Sprint R3-V era) reconstructed
the A1–A10 text from R2V-era artifacts because no canonical in-repo copy
existed at that time. This file IS the canonical in-repo copy going
forward. Any divergence between the two is resolved in favor of this file.
