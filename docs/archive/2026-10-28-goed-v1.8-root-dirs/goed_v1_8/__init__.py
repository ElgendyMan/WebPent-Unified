"""GOED v1.8 — External Runtime Validation + LLM-Augmented Autonomous Research

Tracks implemented:
- A: Release Candidate preparation
- D: LLM Researcher interface
- E: LLM Tool Boundary
- F: Research Loop
- G: LLM ON/OFF comparison harness
- L: Prompt injection resistance tests
- P: Truth Audit generation
- Q: Delivery preparation

Governance: vip_qualified=false, P10=CLOSED, P9=CLOSED, CONDITIONAL
"""
from .llm_comparison import (
    compare_modes,
    run_mode_deterministic_only,
    run_mode_llm_augmented,
)
from .prompt_injection_test import run_all_tests as run_prompt_injection_tests
from .report_generators import generate_executive_summary, generate_truth_audit

__all__ = [
    "run_mode_deterministic_only", "run_mode_llm_augmented", "compare_modes",
    "run_prompt_injection_tests",
    "generate_truth_audit", "generate_executive_summary",
]
