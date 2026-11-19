"""webpent.deception.fixtures — M6 (Part 4 §8): the deception fixture
corpus.

Registry scope: "deception fixtures (generic 200s, reflected-but-
uninterpreted payloads, catch-alls, decoys, WAF pages, cached/stale,
randomized, delayed)".

Every fixture is a deterministic in-process responder with recorded
GROUND TRUTH: the target is NOT vulnerable — the deceptive behavior
exists to trick a verifier into a false confirmation. A verifier that
"confirms" anything on this corpus is broken, and the benchmark says
so with per-class counts.

The responders are pure functions over a request spec — no network,
no state, no randomness except where the class IS randomness (seeded,
so runs are reproducible).
"""

from __future__ import annotations

import hashlib
import random
from typing import Any, Mapping

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "DECEPTION_CLASSES",
    "DeceptionFixture",
    "build_fixture_corpus",
]


DECEPTION_CLASSES = (
    "generic_200",
    "reflected_uninterpreted",
    "catch_all",
    "decoy",
    "waf_page",
    "cached_stale",
    "randomized",
    "delayed",
)


class DeceptionFixture(BaseModel):
    """One deceptive responder with ground truth (never vulnerable)."""

    model_config = ConfigDict(extra="forbid")

    fixture_id: str = Field(min_length=3, max_length=120)
    deception_class: str = Field(min_length=3, max_length=40)
    description: str = Field(default="", max_length=400)
    ground_truth_vulnerable: bool = False
    expected_verdict: str = Field(default="refuted_deceptive", max_length=40)

    def respond(self, request: Mapping[str, Any]) -> dict[str, Any]:
        """The deceptive response for one request.

        ``request`` carries ``payload`` (str), ``path`` (str) and
        ``token`` (str — distinguishes baseline/candidate/control runs).
        """
        handler = _HANDLERS.get(self.deception_class)
        if handler is None:  # pragma: no cover — corpus is closed
            return {"status": 200, "headers": {}, "body": ""}
        return handler(self, request)


def _sha(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:16]


# -- handlers: one per deception class --------------------------------------


def _generic_200(fixture: DeceptionFixture, request: Mapping[str, Any]) -> dict[str, Any]:
    """Every request — payload or not — gets the same friendly 200."""
    return {
        "status": 200,
        "headers": {"content-type": "text/html"},
        "body": "<html><body>Welcome! Your request was processed successfully.</body></html>",
    }


def _reflected_uninterpreted(
    fixture: DeceptionFixture, request: Mapping[str, Any]
) -> dict[str, Any]:
    """Reflects the payload verbatim inside a <pre> block — looks like
    XSS to a naive reflection check, but the content-type is text/plain
    (never interpreted as HTML)."""
    payload = str(request.get("payload") or "")
    return {
        "status": 200,
        "headers": {"content-type": "text/plain"},
        "body": f"Search results for:\n<pre>{payload}</pre>\nNo vulnerabilities found.",
    }


def _catch_all(fixture: DeceptionFixture, request: Mapping[str, Any]) -> dict[str, Any]:
    """Any path, any payload: the SPA shell with 200."""
    return {
        "status": 200,
        "headers": {"content-type": "text/html"},
        "body": "<html><body><div id=root></div><script src=/app.js></script></body></html>",
    }


def _decoy(fixture: DeceptionFixture, request: Mapping[str, Any]) -> dict[str, Any]:
    """A convincing fake admin page with fake sensitive rows — data that
    exists to be 'found'."""
    return {
        "status": 200,
        "headers": {"content-type": "text/html"},
        "body": (
            "<html><body><h1>Admin Console</h1>"
            "<table><tr><td>admin</td><td>admin@example.com</td></tr>"
            "<tr><td>root</td><td>root@example.com</td></tr></table>"
            "</body></html>"
        ),
    }


def _waf_page(fixture: DeceptionFixture, request: Mapping[str, Any]) -> dict[str, Any]:
    """A 403 WAF block page whose body contains security vocabulary that
    naive keyword scanners read as evidence."""
    return {
        "status": 403,
        "headers": {"content-type": "text/html", "server": "cloudflare"},
        "body": (
            "<html><body><h1>Request blocked</h1>"
            "<p>The request was blocked by the Web Application Firewall "
            "because it matched injection and cross-site scripting rules. "
            "Reference ID: 8f5a2b91.</p></body></html>"
        ),
    }


def _cached_stale(fixture: DeceptionFixture, request: Mapping[str, Any]) -> dict[str, Any]:
    """The SAME cached response (same ETag, same body) for every payload —
    a cache that ignores the request entirely."""
    body = (
        "<html><body>Cached content served from edge. Version 1.</body></html>"
    )
    return {
        "status": 200,
        "headers": {"etag": '"stale-1"', "x-cache": "HIT", "content-type": "text/html"},
        "body": body,
    }


def _randomized(fixture: DeceptionFixture, request: Mapping[str, Any]) -> dict[str, Any]:
    """A different body per request — defeats naive diffing that reads
    ANY difference as a payload effect. Seeded by request token so runs
    are reproducible."""
    seed = int(hashlib.sha256(str(request.get("token") or "").encode()).hexdigest()[:8], 16)
    noise = random.Random(seed).randint(10**9, 10**10)
    return {
        "status": 200,
        "headers": {"content-type": "text/html"},
        "body": f"<html><body>Request id: {noise}</body></html>",
    }


def _delayed(fixture: DeceptionFixture, request: Mapping[str, Any]) -> dict[str, Any]:
    """Marks a constant artificial delay on EVERY request — time-based
    scanners read the delay as a time-based injection effect."""
    return {
        "status": 200,
        "headers": {"content-type": "text/html", "x-artificial-delay-ms": "1500"},
        "body": "<html><body>OK (processed)</body></html>",
    }


_HANDLERS = {
    "generic_200": _generic_200,
    "reflected_uninterpreted": _reflected_uninterpreted,
    "catch_all": _catch_all,
    "decoy": _decoy,
    "waf_page": _waf_page,
    "cached_stale": _cached_stale,
    "randomized": _randomized,
    "delayed": _delayed,
}

_DESCRIPTIONS = {
    "generic_200": "identical friendly 200 for every payload",
    "reflected_uninterpreted": "payload reflected in text/plain <pre> (never interpreted)",
    "catch_all": "SPA shell 200 for any path/payload",
    "decoy": "convincing fake admin data page",
    "waf_page": "403 WAF block page full of security vocabulary",
    "cached_stale": "same cached body+ETag for every payload",
    "randomized": "seeded per-token random body (diff-defeating)",
    "delayed": "constant artificial delay marker on every request",
}


def build_fixture_corpus() -> list[DeceptionFixture]:
    """The deterministic corpus: 3 fixtures per deception class (24)."""
    corpus: list[DeceptionFixture] = []
    for index, deception_class in enumerate(DECEPTION_CLASSES):
        for variant in range(3):
            corpus.append(
                DeceptionFixture(
                    fixture_id=f"deception-{deception_class}-{variant + 1:02d}",
                    deception_class=deception_class,
                    description=(
                        f"{_DESCRIPTIONS[deception_class]} "
                        f"(variant {variant + 1})"
                    )[:400],
                    ground_truth_vulnerable=False,
                    expected_verdict="refuted_deceptive",
                )
            )
    _ = index
    return corpus
