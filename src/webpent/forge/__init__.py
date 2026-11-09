"""webpent.forge — THE FORGE (payload corpus system).

Wave 1-2 Tier-1 MVP: MultiSourceIngester (U-FORGE-1), QualityGate
(U-FORGE-2), Normalizer (U-FORGE-4), Indexer (U-FORGE-5) and
PayloadQueryEngine (U-FORGE-6).

Governing laws honored here: INGEST_DONT_INVENT (the ingester parses
caller-provided, pre-fetched content only — zero live network from the
core), QUALITY_OVER_QUANTITY, DETERMINISTIC_CORE (stable ids, stable
ordering), ATTRIBUTION_IS_SACRED (license + source on every payload),
CORPUS_IS_VERSIONED (SQLite, idempotent stores), ADVISORY_ONLY.
"""
