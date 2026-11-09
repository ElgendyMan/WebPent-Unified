"""The Dojo — U-DOJO-1: the Lab Generator.

Builds deterministic synthetic labs (DOJO-L-4) with fully documented
ground truth (DOJO-L-3), isolated resettable state (DOJO-L-2) and zero
network surface (DOJO-L-1): a synthetic lab lives at a ``dojo://``
pseudo-address and never opens a socket.

External labs (Juice Shop, DVWA, WebGoat) are declared but inert: they
require explicit operator enablement and even then this module performs
no I/O itself — wiring a real external application is an operator
action outside the dojo core, which is what keeps L-1 provable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from webpent.dojo.engine import (
    LabInstance,
    RouteSpec,
    SimulatedTarget,
    VulnPoint,
    stable_hash,
)

#: declared external labs: named, documented, and never started here (L-1)
EXTERNAL_LABS: dict[str, dict[str, Any]] = {
    "juice_shop": {
        "kind": "external",
        "family": "xss",
        "requires_operator_enablement": True,
        "bind": "127.0.0.1 only, when operator-enabled",
    },
    "dvwa": {
        "kind": "external",
        "family": "sqli",
        "requires_operator_enablement": True,
        "bind": "127.0.0.1 only, when operator-enabled",
    },
    "webgoat": {
        "kind": "external",
        "family": "idor",
        "requires_operator_enablement": True,
        "bind": "127.0.0.1 only, when operator-enabled",
    },
}

#: default retention: keep at most this many started labs per template
RETENTION_PER_TEMPLATE = 5


@dataclass
class LabTemplate:
    """One synthetic application blueprint."""

    template_id: str
    family: str
    stack: str
    difficulty: int
    description: str
    #: routes/points builders receive the seed-derived session token
    build: Any = None


def _tok(template_id: str, seed: int) -> str:
    return stable_hash(template_id, seed)[:8]


def _build_flask_api_with_idor(tok: str) -> tuple[tuple[RouteSpec, ...],
                                                  tuple[VulnPoint, ...],
                                                  frozenset[str]]:
    routes = (
        RouteSpec("/api/records", "GET", "none", "list own records"),
        RouteSpec("/api/record", "GET", "none", "fetch one record by id"),
        RouteSpec("/login", "POST", "none", "issue a session"),
    )
    points = (
        VulnPoint("idor", "/api/record", "id", "1002", "none", True,
                  note="record ids are sequential across owners"),
        VulnPoint("idor", "/api/record", "id", "9999", "none", False,
                  note="nonexistent record: a hit here is a false positive"),
    )
    return routes, points, frozenset({f"sess-{tok}"})


def _build_express_jwt_confusion(tok: str) -> tuple[tuple[RouteSpec, ...],
                                                    tuple[VulnPoint, ...],
                                                    frozenset[str]]:
    routes = (
        RouteSpec("/api/session", "POST", "none", "exchange token"),
        RouteSpec("/api/profile", "GET", "user", "read own profile"),
    )
    points = (
        VulnPoint("jwt_key_confusion", "/api/session", "token", "alg:none",
                  "none", True, note="unsigned tokens are accepted"),
        VulnPoint("jwt_weakness", "/api/session", "token", "expired", "none",
                  False, note="expired tokens are rejected before parsing"),
    )
    return routes, points, frozenset({f"user-{tok}"})


def _build_django_ssrf_endpoint(tok: str) -> tuple[tuple[RouteSpec, ...],
                                                   tuple[VulnPoint, ...],
                                                   frozenset[str]]:
    routes = (
        RouteSpec("/fetch", "GET", "user", "server-side URL fetch"),
        RouteSpec("/health", "GET", "none", "liveness"),
    )
    points = (
        VulnPoint("ssrf", "/fetch", "url", "169.254.169.254", "user", True,
                  note="metadata IP is reachable from the server"),
        VulnPoint("ssrf", "/fetch", "url", "localhost", "user", False,
                  note="loopback is denylisted: a hit here is a false positive"),
    )
    return routes, points, frozenset({f"sess-{tok}"})


def _build_spring_actuator_exposed(tok: str) -> tuple[tuple[RouteSpec, ...],
                                                      tuple[VulnPoint, ...],
                                                      frozenset[str]]:
    routes = (
        RouteSpec("/actuator", "GET", "none", "actuator index"),
        RouteSpec("/actuator/env", "GET", "none", "environment view"),
    )
    points = (
        VulnPoint("info_disclosure", "/actuator/env", "reveal", "env",
                  "none", True, note="full environment dumped unauthenticated"),
        VulnPoint("info_disclosure", "/actuator/env", "dump", "heapdump",
                  "none", False, note="heap dump endpoint is disabled"),
    )
    return routes, points, frozenset()


def _build_node_race_condition(tok: str) -> tuple[tuple[RouteSpec, ...],
                                                  tuple[VulnPoint, ...],
                                                  frozenset[str]]:
    routes = (
        RouteSpec("/api/coupon/apply", "POST", "user", "apply coupon code"),
    )
    points = (
        VulnPoint("race_condition", "/api/coupon/apply", "code", "DUPLICATE",
                  "user", True,
                  note="concurrent applications bypass the single-use check"),
        VulnPoint("race_condition", "/api/coupon/apply", "code", "SINGLE",
                  "user", False,
                  note="single request is correctly rejected"),
    )
    return routes, points, frozenset({f"sess-{tok}"})


def _build_flask_sqli_login(tok: str) -> tuple[tuple[RouteSpec, ...],
                                               tuple[VulnPoint, ...],
                                               frozenset[str]]:
    routes = (
        RouteSpec("/login", "POST", "none", "login form"),
        RouteSpec("/dashboard", "GET", "user", "post-login view"),
    )
    points = (
        VulnPoint("sqli", "/login", "username", "' OR 1=1", "none", True,
                  note="login query interpolates user input"),
        VulnPoint("sqli", "/login", "username", "union select", "none", False,
                  note="UNION is collapsed by the driver: false positive"),
    )
    return routes, points, frozenset({f"sess-{tok}"})


def _build_php_xss_comment_board(tok: str) -> tuple[tuple[RouteSpec, ...],
                                                    tuple[VulnPoint, ...],
                                                    frozenset[str]]:
    routes = (
        RouteSpec("/comment", "POST", "none", "post a comment"),
        RouteSpec("/board", "GET", "none", "render comments"),
    )
    points = (
        VulnPoint("xss", "/comment", "text", "<script>", "none", True,
                  note="comment body is rendered raw"),
        VulnPoint("xss", "/comment", "text", "<img>", "none", False,
                  note="img tags are sanitized: false positive"),
    )
    return routes, points, frozenset()


def _build_flask_business_logic_checkout(tok: str) -> tuple[
        tuple[RouteSpec, ...], tuple[VulnPoint, ...], frozenset[str]]:
    routes = (
        RouteSpec("/checkout", "POST", "user", "place an order"),
        RouteSpec("/orders", "GET", "user", "list orders"),
    )
    points = (
        VulnPoint("mass_assignment", "/checkout", "price", "-1", "user",
                  True, note="negative totals are accepted by the API"),
        VulnPoint("mass_assignment", "/checkout", "discount", "200%", "user",
                  False, note="discount is capped server-side"),
    )
    return routes, points, frozenset({f"sess-{tok}"})


def _build_express_auth_bypass_panel(tok: str) -> tuple[
        tuple[RouteSpec, ...], tuple[VulnPoint, ...], frozenset[str]]:
    routes = (
        RouteSpec("/admin", "GET", "none", "admin panel entry"),
        RouteSpec("/admin/users", "GET", "admin", "user management"),
    )
    points = (
        VulnPoint("auth_bypass", "/admin", "role", "administrator", "none",
                  True, note="client-side role check only"),
        VulnPoint("auth_bypass", "/admin", "debug", "true", "none", False,
                  note="debug flag reveals nothing sensitive"),
    )
    return routes, points, frozenset({f"admin-{tok}"})


_BUILDERS = {
    "flask_api_with_idor": _build_flask_api_with_idor,
    "express_jwt_confusion": _build_express_jwt_confusion,
    "django_ssrf_endpoint": _build_django_ssrf_endpoint,
    "spring_actuator_exposed": _build_spring_actuator_exposed,
    "node_race_condition": _build_node_race_condition,
    "flask_sqli_login": _build_flask_sqli_login,
    "php_xss_comment_board": _build_php_xss_comment_board,
    "flask_business_logic_checkout": _build_flask_business_logic_checkout,
    "express_auth_bypass_panel": _build_express_auth_bypass_panel,
}

_TEMPLATES: dict[str, LabTemplate] = {
    "flask_api_with_idor": LabTemplate(
        "flask_api_with_idor", "idor", "flask", 2,
        "records API with sequential ids across owners",
        _BUILDERS["flask_api_with_idor"],
    ),
    "express_jwt_confusion": LabTemplate(
        "express_jwt_confusion", "jwt", "express", 3,
        "token endpoint accepting unsigned JWTs",
        _BUILDERS["express_jwt_confusion"],
    ),
    "django_ssrf_endpoint": LabTemplate(
        "django_ssrf_endpoint", "ssrf", "django", 3,
        "server-side fetcher with metadata access",
        _BUILDERS["django_ssrf_endpoint"],
    ),
    "spring_actuator_exposed": LabTemplate(
        "spring_actuator_exposed", "info_disclosure", "spring", 1,
        "actuator endpoints left open to the internet",
        _BUILDERS["spring_actuator_exposed"],
    ),
    "node_race_condition": LabTemplate(
        "node_race_condition", "race_condition", "node", 4,
        "coupon endpoint with a single-use check that can be raced",
        _BUILDERS["node_race_condition"],
    ),
    "flask_sqli_login": LabTemplate(
        "flask_sqli_login", "sqli", "flask", 2,
        "login form built on string interpolation",
        _BUILDERS["flask_sqli_login"],
    ),
    "php_xss_comment_board": LabTemplate(
        "php_xss_comment_board", "xss", "php", 1,
        "comment board rendering input raw",
        _BUILDERS["php_xss_comment_board"],
    ),
    "flask_business_logic_checkout": LabTemplate(
        "flask_business_logic_checkout", "business_logic", "flask", 3,
        "checkout API trusting client-side totals",
        _BUILDERS["flask_business_logic_checkout"],
    ),
    "express_auth_bypass_panel": LabTemplate(
        "express_auth_bypass_panel", "auth_bypass", "express", 2,
        "admin panel gated by a client-side role check",
        _BUILDERS["express_auth_bypass_panel"],
    ),
}


class LabGenerator:
    """Starts, resets, stops and documents synthetic labs (L-2, L-3)."""

    def __init__(self, *, target: SimulatedTarget | None = None) -> None:
        self._target = target or SimulatedTarget()
        self._labs: dict[str, LabInstance] = {}

    # ------------------------------------------------------------ catalog
    def list_available(self) -> list[LabTemplate]:
        """All synthetic templates, sorted by id (deterministic)."""
        return [_TEMPLATES[k] for k in sorted(_TEMPLATES)]

    # ----------------------------------------------------------- lifecycle
    def start(self, template_id: str, *, seed: int) -> LabInstance:
        if template_id in EXTERNAL_LABS:
            raise ValueError(
                f"external lab {template_id!r} requires explicit operator "
                "enablement; the dojo core never starts it"
            )
        template = _TEMPLATES.get(template_id)
        if template is None:
            raise KeyError(f"unknown lab template: {template_id!r}")
        tok = _tok(template_id, seed)
        routes, points, tokens = template.build(tok)
        instance = LabInstance(
            instance_id=f"{template_id}-{seed}-{tok}",
            template_id=template_id,
            family=template.family,
            seed=seed,
            base_url=f"dojo://synthetic/{template_id}/{tok}",
            routes=routes,
            vuln_points=points,
            valid_tokens=tokens,
        )
        self._labs[instance.instance_id] = instance
        self._enforce_retention(template_id)
        return instance

    def stop(self, instance_id: str) -> None:
        self._labs.pop(instance_id, None)

    def reset(self, instance_id: str) -> LabInstance:
        lab = self._get(instance_id)
        lab.state = {}
        lab.request_budget = 24
        lab.normalize_input = False
        lab.strict_types = False
        return lab

    def get_vuln_map(self, instance_id: str) -> dict[str, Any]:
        """Full documented ground truth for the trainer (L-3)."""
        lab = self._get(instance_id)
        return {
            "instance_id": lab.instance_id,
            "template_id": lab.template_id,
            "family": lab.family,
            "vuln_points": [p for p in lab.vuln_points if p.exploitable],
            "decoys": [p for p in lab.vuln_points if not p.exploitable],
            "valid_tokens": sorted(lab.valid_tokens),
        }

    def get(self, instance_id: str) -> LabInstance:
        return self._get(instance_id)

    # ------------------------------------------------------------ helpers
    def _get(self, instance_id: str) -> LabInstance:
        if instance_id not in self._labs:
            raise KeyError(f"no running lab: {instance_id!r}")
        return self._labs[instance_id]

    def _enforce_retention(self, template_id: str) -> None:
        """Keep at most RETENTION_PER_TEMPLATE started labs per template.

        Retired in start order: dict insertion order is the true FIFO, so
        the FIRST-started lab is retired first (RT-03), never the
        lexicographically smallest instance id.
        """
        running = [
            iid for iid, lab in self._labs.items()
            if lab.template_id == template_id
        ]
        excess = len(running) - RETENTION_PER_TEMPLATE
        for iid in running[:max(0, excess)]:
            self._labs.pop(iid, None)


__all__ = [
    "EXTERNAL_LABS",
    "LabGenerator",
    "LabTemplate",
    "RETENTION_PER_TEMPLATE",
]
