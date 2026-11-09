"""DOM XSS package (PROPOSALS_ULTIMATE_V2 §2, 2026-10-29).

Static source→sink taint analysis over parsed JavaScript plus a
browser-confirmation bridge that reuses webpent.shared.browser_proof_runner.
Flag-gated: ``enable_dom_xss`` (default False), ``dom_xss_max_ast_nodes``
(default 50000, fail-closed above).
"""

from .agent import (
    DomXssAnalyzer,
    DomXssCandidate,
    DomXssReport,
    build_browser_probes,
    dom_xss_causal_predicate,
)
from .parser import AstBudgetExceeded, parse_script
from .taint import TaintFlow, find_taint_flows

__all__ = [
    "AstBudgetExceeded",
    "DomXssAnalyzer",
    "DomXssCandidate",
    "DomXssReport",
    "TaintFlow",
    "build_browser_probes",
    "dom_xss_causal_predicate",
    "find_taint_flows",
    "parse_script",
]
