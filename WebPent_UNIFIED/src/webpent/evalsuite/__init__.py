"""Ground-truth evaluation for the L6 blind-discovery benchmark.

This subpackage lives OUTSIDE webpent.egaie on purpose: no
discovery-path module imports it, so the investigation process cannot
reach the defect layout, the expected verdicts, or this evaluator. It
reads the instance spec (the authoritative defect record) and scores
completed investigation states.
"""
