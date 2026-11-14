"""THE ORACLE (v88) — sees the whole target before touching it.

Passive intelligence first, attack graph second, kill-chain synthesis
third, operator interface fourth. Every module here is advisory-only
(ORACLE-L-10): the Oracle proposes, the operator decides, Apex executes.
The package imports no network primitive at all (ORACLE-L-2/L-10); all
external data enters through operator-injected fetchers.
"""

from __future__ import annotations

PREAMBLE_LINE = (
    "advisory: the oracle observes passively and predicts; it never sends "
    "a request to the target and never executes without the operator's "
    "explicit approval."
)

ORACLE_LAWS: dict[str, str] = {
    "ORACLE-L-1": "PASSIVE FIRST — no request to the target before Wave 1 completes",
    "ORACLE-L-2": "ZERO-TOUCH PROOF — every operation carries proof it did not touch the target",
    "ORACLE-L-3": "SECRETS SANITIZED — secrets stored as hashes + partial prefix only",
    "ORACLE-L-4": "PII FILTERED — personal data redacted before any storage",
    "ORACLE-L-5": "LEGAL BASIS — every OSINT source documents its legal basis",
    "ORACLE-L-6": "GRAPH FROM TRUTH — the graph is built from confirmed data only",
    "ORACLE-L-7": "6 PERSPECTIVES — every finding analyzed from six minds; high value = 3+",
    "ORACLE-L-8": "PREDICT-VALIDATE-LEARN — every prediction is checked and fed back",
    "ORACLE-L-9": "IMPACT OVER SEVERITY — real business impact outranks CVSS",
    "ORACLE-L-10": "ADVISORY-ONLY — the oracle proposes, the operator decides",
    "ORACLE-L-11": "PREAMBLE BEFORE — every unit ships preamble + evidence + DoD",
    "ORACLE-L-12": "SUITE MONOTONIC — at least 250 new tests, count never decreases",
}
