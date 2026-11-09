"""EGAIE — Evidence-Grounded Autonomous Investigation Engine.

Minimal orchestrator package that COMPOSES the existing validated stack
(cqa_v2.causal_guard, cqa_v2.proof_bundle_builder, cqa_v2.replay_verifier)
without modifying it. Every CONFIRMED verdict in this package requires a
sealed CompleteProofBundle whose replay verification passes; no component
here can promote an unverified hypothesis into a confirmed vulnerability.
"""
