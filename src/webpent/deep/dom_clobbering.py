"""U-DEEP-16 — DOM Clobbering.

Family: DOM_CLOBBERING. Where HTML injection exists (even without
XSS), named or id-ed elements clobber window properties: the page's
own script then reads the attacker's node instead of its config.

Payload corpus (spec verbatim, U-DEEP-16): global_vars, attributes,
nested. Detection principle: EFFECT OVER ECHO — a payload is only a
finding when the client-side behavior actually changed (the script
followed the clobbered property), never when the injected markup is
merely reflected.

Zero live network: the transport is the injected
``send(endpoint, body)`` callable; findings are advisory evidence
only (DEEP-L-8 ADVISORY_ONLY).
"""
from __future__ import annotations

from dataclasses import dataclass

INJECTION_MARKER = "<!--injection-point-->"

# Spec corpus, verbatim (U-DEEP-16).
DOM_CLOBBER_PAYLOADS: dict[str, list[str]] = {
    "global_vars": [
        '<a id="config">',
        '<img name="config">',
        '<form name="config">',
    ],
    "attributes": [
        '<a id="config" href="evil.com">',
        '<form id="config" action="evil.com">',
    ],
    "nested": [
        '<a id="config"><a id="config" name="url" '
        'href="evil.com"></a></a>',
    ],
}

SEVERITY_BY_SUBFAMILY = {
    "global_vars": "medium",
    "attributes": "high",
    "nested": "high",
}


@dataclass(frozen=True)
class ClobberingFinding:
    subfamily: str
    severity: str
    evidence: tuple[str, ...]
    payload: str
    family: str = "DOM_CLOBBERING"
    confidence: float = 0.8
    statement: str = ""
    success_indicator: str = ""


_DEFAULT_PAGE = (
    "<html><body><div>" + INJECTION_MARKER + "</div>"
    "<script>var config = window.config || {};</script></body>"
    "</html>")


class DomClobberingDetector:
    """Injects each corpus payload at the page's injection point and
    reports only payloads whose client behavior changed."""

    _ENDPOINT = "/page"

    def __init__(self, send, page: str | None = None) -> None:
        self._send = send
        self._page = page if page is not None else _DEFAULT_PAGE

    # ------------------------------------------------------------------

    @staticmethod
    def identify_injection_points(page: str) -> list[str]:
        """Where attacker HTML lands: the documented injection
        markers present in the page."""
        points = []
        start = page.find(INJECTION_MARKER)
        while start != -1:
            points.append(INJECTION_MARKER)
            start = page.find(INJECTION_MARKER,
                              start + len(INJECTION_MARKER))
        return points

    @staticmethod
    def inject(page: str, payload: str) -> str:
        """Place one payload at the first injection point."""
        return page.replace(INJECTION_MARKER, payload, 1)

    def build_plan(self) -> list[dict]:
        """Deterministic plan: every corpus payload with its
        sub-family."""
        return [{"subfamily": subfamily, "payload": payload}
                for subfamily in ("global_vars", "attributes",
                                  "nested")
                for payload in DOM_CLOBBER_PAYLOADS[subfamily]]

    def scan(self) -> list[ClobberingFinding]:
        findings: list[ClobberingFinding] = []
        for entry in self.build_plan():
            finding = self._probe(entry)
            if finding is not None:
                findings.append(finding)
        return findings

    # ------------------------------------------------------------------

    def _probe(self, entry: dict) -> ClobberingFinding | None:
        payload = entry["payload"]
        probe_page = self.inject(self._page, payload)
        response = self._send(self._ENDPOINT, {"html": probe_page})
        if response.status_code >= 400:
            return None
        try:
            body = response.json()
        except Exception:
            return None
        # EFFECT OVER ECHO: a reflection is not a behavior change
        if body.get("behavior") != "changed":
            return None
        subfamily = entry["subfamily"]
        sink = body.get("sink", "")
        evidence = [
            f"behavior: client script changed after the clobber "
            f"({subfamily})",
            f"sink: {sink}" if sink else "sink: config existence flip",
        ]
        if subfamily == "nested":
            evidence.append(
                "nested: the inner anchor's name=url property "
                "reached the script")
        statements = {
            "global_vars": (
                "A named/id-ed element clobbered the window.config "
                "global and the page's script changed behavior — "
                "DOM clobbering, global variable (advisory; verify "
                "against an authorized target)."),
            "attributes": (
                "The clobbered node's href/action attribute was "
                "followed by the page's script — DOM clobbering, "
                "attribute sink (advisory; verify against an "
                "authorized target)."),
            "nested": (
                "A nested clobbering chain reached a deeper property "
                "(config.url) and the script followed it — DOM "
                "clobbering, nested (advisory; verify against an "
                "authorized target)."),
        }
        indicators = {
            "global_vars": "window.config resolved to the injected "
                           "node",
            "attributes": "script followed the clobbered href/action",
            "nested": "script read config.url from the nested node",
        }
        return ClobberingFinding(
            subfamily=subfamily,
            severity=SEVERITY_BY_SUBFAMILY[subfamily],
            evidence=tuple(evidence),
            payload=payload,
            statement=statements[subfamily],
            success_indicator=indicators[subfamily],
        )
