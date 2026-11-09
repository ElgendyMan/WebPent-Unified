# Payload Library + OWASP WSTG Integration — Changelog

## Added

- Added `webpent.recon.payload_library.PayloadLibrary` with deterministic Markdown fenced-block parsing, family/subtype classification, bounded selection, search, immutable iteration, JSON export, provenance, and safety labels.
- Added `webpent.recon.wstg_catalog.WSTGCatalog` with WSTG identifier extraction, aliases, family mappings, methodology/expected-behavior/remediation fields, bounded queries, and JSON export.
- Added `webpent.memory.knowledge_ingest` for source-attributed, `global_advisory` payload/WSTG ingestion and bounded local knowledge search.
- Added `webpent knowledge update`, `webpent knowledge status`, and `webpent knowledge search` CLI commands.
- Added WSTG and payload metadata to advisory hypotheses. Metadata is informational and does not authorize network activity or promotion.
- Added bounded WSTG methodology and expected-behavior projections to the redaction-safe LLM payload-advisor prompt.
- Added external parsed-library filtering to LLM payload selection, so accepted IDs must come from the pinned parsed catalog.
- Added non-authoritative WSTG/payload metadata to governed decision evidence and structural validator context.
- Added focused tests covering parser safety, deterministic selection, WSTG aliases/mappings, RAG source attribution, bounded prompts, hypothesis metadata, and export determinism.

## Safety and compatibility

- No frozen trust-spine module was intentionally modified; the frozen-manifest check remained `OK` for all 13 files.
- ScopeLaw, ActionAuthority, M4 credential attachment, AVI, validators, ProofBundle sealing, replay verification, and PromotionPipeline remain authoritative.
- Payloads are test inputs only. The integration does not lower validator thresholds, skip negative controls, or create a second promotion path.
- Payloads marked `catalog_only` are retained as advisory knowledge and are not automatically executed.
- Upstream Markdown is parsed as data; no upstream code is executed.
- Target content remains behind the existing untrusted-content boundary. Raw target bodies, headers, cookies, and credentials were not placed in LLM prompts or packaged evidence.
- Local LLM key material remains environment/config-only and is excluded from exports and release packaging.

## Evidence

The canonical source-matched campaign is `recall-gap-llm-20261001t143038z`. It used 1,421 parsed payload entries and 116 WSTG tests, made six live `gpt-5-mini` calls, cost `$0.017244`, and produced three promoted findings across IDOR, BOLA, and SQLI plus nine validator-refuted candidates.

The final project validation recorded 2097/2097 full-suite tests passed, three passing acceptance rounds, five passing security gates, a matching frozen manifest, and a passing direct-I/O inventory check.
