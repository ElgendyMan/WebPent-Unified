=== CQA v2 Regression Check ===

--- pytest (CQA + existing) ---
...................................                                      [100%]
35 passed in 1.90s

--- compileall ---
OK

--- git diff ---
 pyproject.toml                     |   0
 src/webpent/cqa_v2/causal_guard.py | 159 ++++++++++++++++++++++++++++---------
 2 files changed, 120 insertions(+), 39 deletions(-)

--- git status ---
 M pyproject.toml
 M src/webpent/cqa_v2/causal_guard.py
?? reports/cqa_v2/fn_challenge_report.md
?? reports/cqa_v2/learning_gate_report.md
?? reports/cqa_v2/negative_challenge_report.md
?? reports/cqa_v2/quality_gate_verification.md
?? reports/cqa_v2/regression_protection_log.md
?? scripts/cqa_v2_regression_check.sh
?? tests/cqa/test_cqa_v2_challenges.py
?? tests/cqa/test_cqa_v2_quality_gate.py

=== Regression Check Complete ===
If test count dropped without explanation: STOP + DIAGNOSE
Do NOT delete tests to reduce failure count.
