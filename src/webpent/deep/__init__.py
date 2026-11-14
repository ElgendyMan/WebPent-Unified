"""webpent.deep — THE DEEP FAMILIES (Tier 1).

Advisory-only detection of deep vulnerability families. Every detector
receives its transport as an injected ``send`` function: the package
performs zero live network I/O, never exploits, and only reports.
Findings carry family/subfamily, evidence, and the wording a Prism
consumer or a campaign hypothesis needs.
"""
