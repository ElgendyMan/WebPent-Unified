"""The Judgment Council (v85): a deterministic, advisory-only meta-cognition layer.

Seven advocate modules argue over injected context, a skeptic challenges every
argument, an evidence weigher scores the evidence transparently, and a judge
synthesizes a verdict with dissent preserved (JC-L-1..JC-L-8):

    U-JC-1  CouncilChamber    convene/submit/close, deterministic session ids
    U-JC-2  advocates         7 default advocates (abstain without context)
    U-JC-3  Skeptic           7 documented bias flags, severity capped at 0.9
    U-JC-4  EvidenceWeigher   source x recency x specificity x corroboration
    U-JC-5  Judge             AdvocateScore, Confidence, tiers, escalation
    U-JC-6  DissentRegister   append-only minority opinions + outcomes
    U-JC-7  Calibrator        Brier score, buckets, drift, min-20 guard
    U-JC-8  BiasDetector      5 systemic patterns with recommendations
    U-JC-9  CouncilMemory     context-hash retrieval, patterns, retention
    U-JC-10 Explainer         3-level reasoning reports
    U-JC-11 OverrideProtocol  full/partial/advisory, operator accuracy
    U-JC-12 Dashboard/CLI     operator console (webpent jc ...)

No module here opens a socket, spawns a subprocess or fetches anything
(L-2/JC-L-2), and none of it executes anything: every output is advisory
and marked ``"advisory": True`` (JC-L-1).
"""

from webpent.jc.advocates import all_advocate_ids, build_default_advocates
from webpent.jc.calibration import ConfidenceCalibrator
from webpent.jc.chamber import CouncilChamber, load_council_config
from webpent.jc.contracts import (
    Argument,
    Challenge,
    CouncilSession,
    Evidence,
    Verdict,
    context_hash,
    deterministic_id,
)
from webpent.jc.dissent import DissentRegister
from webpent.jc.judge import Judge
from webpent.jc.verdict import VerdictRules
from webpent.jc.weigher import EvidenceWeigher

__version__ = "0.1.0"

__all__ = [
    "Argument",
    "Challenge",
    "ConfidenceCalibrator",
    "CouncilChamber",
    "CouncilSession",
    "DissentRegister",
    "Evidence",
    "EvidenceWeigher",
    "Judge",
    "Verdict",
    "VerdictRules",
    "all_advocate_ids",
    "build_default_advocates",
    "context_hash",
    "deterministic_id",
    "load_council_config",
]
