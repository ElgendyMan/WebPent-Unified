# VIP Source and Integration Reports

## Decision rule

المصدر الخارجي يمكن أن يساهم في knowledge enrichment أو schema mapping فقط بعد مراجعة commit وlicense وdependency surface. لا يُسمح بإدخال exploit engine أو subprocess/network behavior إلى WebPent runtime من خلال import غير معزول.

## AutoPentestX

- Pinned source was reviewed in an isolated workspace.
- The selective adapter is observation-only and does not execute the external scanner, exploit engine, CVE lookup, database, or report generator.
- External claims are not treated as WebPent findings.
- License and dependency information are retained in the source audit artifacts.
- Live behavior was intentionally not invoked in this cycle.

## WebPent-owned sources

The authoritative implementation remains WebPent's ActionAuthority, validator registry, ProofBundle, ledger, report model, and release gates. These components are covered by local tests and are the only path allowed to produce Tool-Confirmed findings.

## Reference repositories and tools

Any third-party repository or tool listed in the plan is classified as one of: `reference-only`, `schema-only`, `offline-fixture`, or `not-integrated`. A repository is not considered integrated merely because its URL or name appears in documentation. Integration requires a source review, license record, deterministic contract test, and explicit runtime callgraph evidence.

## Evidence status

The local artifacts prove source review, contract coverage, and offline safety boundaries. They do not prove target-specific discovery, exploitation, OOB delivery, browser behavior, or live precision/recall. Those statuses remain `not_run` while WAPTLab is intentionally excluded from this cycle.
