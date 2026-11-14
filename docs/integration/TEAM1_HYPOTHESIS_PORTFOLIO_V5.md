# TEAM1 Hypothesis Portfolio / Exploration vs Exploitation (V5)

Added: hypothesis_portfolio.py (generic branch state: confidence, exploration_pressure, exploitation_value, saturation_state — structural only).
Adapter: session-scoped portfolio; record_outcome updates portfolio; branch_portfolio_signal exposed to LLM (value-only advisory).
Anti-forcing: NO branch rotation, NO hard filter, NO reorder after ranking, NO LLM override. Exploration pressure modifies displayed candidate value only.
Tests: 11 added (A-I + long-horizon synthetic + signal-in-prompt), all pass.
CausalGuard/ProofBundle/Replay/governance/ToolBoundary unchanged. TEAM-2 MUST PERFORM INDEPENDENT VALIDATION.
