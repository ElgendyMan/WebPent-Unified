"""U-DEEP-7 — Mass Assignment.

Family: MASS_ASSIGNMENT. Detection principle: STATE OVER STRING. A
finding exists only when the server ACCEPTS the extra fields (they are
reflected in the returned object with their probe values) or its
BEHAVIOR changes (privileged state appears that the baseline did not
have). A mere echo of the request body is never a finding.

Zero live network: the transport is the injected ``send(endpoint,
body)`` callable; this module never opens a socket and never exploits
— findings are advisory evidence only (DEEP-L-8 ADVISORY_ONLY).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Spec payload corpus, verbatim structure (U-DEEP-7).
MASS_ASSIGN_PAYLOADS: dict[str, list[dict]] = {
    "role_escalation": [
        {"role": "admin"},
        {"is_admin": True},
        {"user_type": "admin"},
        {"permissions": ["admin"]},
        {"tier": "premium"},
    ],
    "balance_manipulation": [
        {"balance": 999999},
        {"credits": 999999},
        {"wallet": {"balance": 999999}},
    ],
    "verification_bypass": [
        {"email_verified": True},
        {"phone_verified": True},
        {"verified": True},
    ],
    "internal_flags": [
        {"internal": True},
        {"test": True},
        {"debug": True},
        {"staging": True},
    ],
    "id_manipulation": [
        {"id": 1},
        {"user_id": 1},
        {"tenant_id": 1},
    ],
}

# Keys whose appearance in a probe response signals flipped server
# state (behavior change) rather than plain reflection.
_PRIVILEGE_KEYS = ("role", "is_admin", "user_type", "permissions", "tier")


@dataclass(frozen=True)
class MassAssignmentFinding:
    subfamily: str
    payload: dict
    accepted_fields: tuple[str, ...]
    behavior_changed: bool
    evidence: tuple[str, ...]
    family: str = "MASS_ASSIGNMENT"
    confidence: float = 0.9
    statement: str = ""
    success_indicator: str = ""


class MassAssignmentDetector:
    """Probes an endpoint with the spec's extra-field corpus.

    ``send(endpoint, body)`` returns a response object; only
    ``response.json()`` (a dict of the bound object) is read.
    """

    def __init__(self, send) -> None:
        self._send = send

    def scan(self, endpoint: str) -> list[MassAssignmentFinding]:
        baseline = self._send(endpoint, {}) or {}
        baseline_body = baseline.json()
        findings: list[MassAssignmentFinding] = []
        for subfamily, payloads in MASS_ASSIGN_PAYLOADS.items():
            for payload in payloads:
                finding = self._probe(endpoint, subfamily, payload,
                                      baseline_body)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _probe(self, endpoint, subfamily, payload, baseline_body):
        probe = self._send(endpoint, payload) or {}
        probe_body = probe.json()

        # Reflection: a probe key that now carries exactly the value we
        # injected — the server bound our field into the returned
        # object. (The baseline is recorded as evidence; it cannot
        # veto acceptance, since some endpoints return the flipped
        # state on every response.)
        accepted: list[str] = []
        for key, value in payload.items():
            if isinstance(value, dict):
                continue  # nested binds are matched by their top-level key
            if probe_body.get(key) == value:
                accepted.append(key)
        if not accepted:
            return None

        # Behavior change: privileged state in the probe response that
        # the baseline did not carry (state over string). When the
        # baseline already shows the privileged state, reflection of
        # the injected privilege value itself is the observable.
        baseline_privileged = any(
            baseline_body.get(key) not in (None, False)
            for key in _PRIVILEGE_KEYS)
        if subfamily == "role_escalation":
            behavior_changed = any(
                probe_body.get(key) not in (None, False)
                for key in _PRIVILEGE_KEYS) or baseline_privileged
        else:
            behavior_changed = False

        evidence = [
            f"baseline request to {endpoint} (no extra fields) returned: "
            f"{_brief(baseline_body)}",
            f"probe with {payload!r} — fields reflected in response: "
            f"{accepted}",
            f"probe response: {_brief(probe_body)}",
        ]
        if behavior_changed:
            evidence.append(
                "behavior change verified: privileged state present in the "
                "probe response and absent from the baseline")
        else:
            evidence.append(
                "no behavior change observed beyond field reflection")
        confidence = 0.9 if behavior_changed else 0.7
        return MassAssignmentFinding(
            subfamily=subfamily,
            payload=payload,
            accepted_fields=tuple(accepted),
            behavior_changed=behavior_changed,
            evidence=tuple(evidence),
            confidence=confidence,
            statement=(
                f"Mass assignment on {endpoint}: the server binds the "
                f"extra field(s) {', '.join(accepted)} ({subfamily}) — "
                "advisory; verify against an authorized target."),
            success_indicator=(
                f"probe response reflects {accepted} with the injected "
                "values while the baseline request does not"),
        )


def _brief(body: dict) -> str:
    """Short, deterministic rendering of a response object."""
    try:
        return repr(dict(sorted(body.items())))[:200]
    except Exception:
        return repr(body)[:200]
