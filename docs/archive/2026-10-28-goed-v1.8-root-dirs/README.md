# goed_v1_8* — root freeze dirs (archived 2026-10-29)

Track 7.2: legacy model-eval/freeze directories that still sat in
the project root after their canonical provenance was already
archived under `docs/archive/goed-v1.8.*/`. Excluded from the
package build by construction (src/-scoped packaging) and now out
of the lint surface too. No source file imports them (verified by
the same reference scan that performed this move).
