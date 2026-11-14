#!/usr/bin/env python3
"""UM-DR-35/36 — deterministic frozen-manifest re-pin (DR-009 protocol).

Re-pin EVERY manifest entry whose recorded hash no longer matches the
file on disk, but ONLY for files whose drift is attributable to the
UM-DR-35/36 mission change set (the declared prefixes below). Any drift
OUTSIDE the declared set aborts loudly (fail-closed).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "frozen_modules.sha256"

DECLARED_DRIFT_PREFIXES = (
    "src/webpent/production/discovery_funnel.py",
    "src/webpent/production/confirmation_adapter.py",
    "src/webpent/graph/appmodel_nodes.py",
    "src/webpent/agents/hypothesis_analyzer/agent.py",
    "src/webpent/production/autonomous_validation_v1.py",
    "src/webpent/agents/validator/agent.py",
    "src/webpent/agents/validator/postp0_checks.py",
    "src/webpent/agents/validator/active_checks.py",
    "src/webpent/agents/validator/structural_checks.py",
    "src/webpent/agents/api_testing/agent.py",
    "src/webpent/agents/cloud_security/agent.py",
    "src/webpent/agents/elasticsearch/agent.py",
    "src/webpent/agents/xslt_injection/agent.py",
    "src/webpent/cqa_v2/causal_guard.py",
    "src/webpent/shared/verifier.py",
    "src/webpent/shared/bac_identity_tester.py",
    "src/webpent/shared/kev.py",
    "src/webpent/state/state.py",
    "src/webpent/graph/builder.py",
    "src/webpent/models/findings.py",
    "src/webpent/production/advisory_registration.py",
)


def main() -> int:
    lines = MANIFEST.read_text(encoding="utf-8").splitlines()
    out: list[str] = []
    repinned: list[str] = []
    undeclared: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        digest, _, path = line.partition("  ")
        f = REPO / path
        if not f.exists():
            out.append(line)
            continue
        current = hashlib.sha256(f.read_bytes()).hexdigest()
        if current == digest:
            out.append(line)
            continue
        if path.startswith(DECLARED_DRIFT_PREFIXES):
            repinned.append(path)
            out.append(f"{current}  {path}")
        else:
            undeclared.append(path)
    if undeclared:
        print("ABORT: undeclared drift outside the declared change set:")
        for p in undeclared:
            print("  -", p)
        return 1
    MANIFEST.write_text("\n".join(out) + "\n", encoding="utf-8")
    print(f"Re-pinned {len(repinned)} drifted file(s); manifest entries: {len(out)}.")
    for p in repinned:
        print("  ~", p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
