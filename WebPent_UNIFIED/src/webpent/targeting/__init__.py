# src/webpent/targeting/__init__.py
"""Target selection (PROPOSALS_ULTIMATE_V2 §10, 2026-10-30).

Operator-supplied program briefs (scope / out-of-scope / bounty table)
and a deterministic UCB1 target selector over attack history. The
selector RECOMMENDS only: the final acceptance is the operator's
approval step, and the scope enforcer remains the FINAL judge over any
target — selection never widens scope and never issues requests.
"""
