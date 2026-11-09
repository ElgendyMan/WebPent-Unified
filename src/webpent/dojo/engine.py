"""The Dojo — shared engine (plan: docs/plans/2026-10-16-v85-dojo.md).

The dojo's core is a deterministic, in-memory simulator of a web
application. There is no HTTP and no socket anywhere (DOJO-L-1): a
``SimulatedTarget`` matches ``DojoRequest`` objects against a lab's
documented ``VulnPoint`` ground truth (DOJO-L-3) with pure string
logic, so the same seed and the same requests always produce the same
responses (DOJO-L-4).

Decoys are signed, filtered vulnerability points marked
``exploitable=False``: matching one and claiming success is a false
positive, which is what makes the ``(1 - fp)`` term of the score and
skill formulas honest rather than decorative.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

#: auth levels a route may require
AUTH_LEVELS = ("none", "user", "admin")

#: response flags emitted by SimulatedTarget
RESPONSE_FLAGS = (
    "ok",
    "not_found",
    "auth_blocked",
    "filtered",
    "vuln_hit",
    "decoy_hit",
    "rate_limited",
    "method_not_allowed",
)


def stable_hash(*parts: Any) -> str:
    """Order-stable sha256 hex digest over canonicalized parts (L-4)."""
    canonical = json.dumps(list(parts), sort_keys=True, default=repr)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class DojoRequest:
    """One synthetic request inside the dojo (no sockets involved)."""

    method: str = "GET"
    path: str = "/"
    params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "params": dict(self.params),
            "headers": dict(self.headers),
            "body": self.body,
        }


@dataclass
class DojoResponse:
    """Deterministic response of the simulated target."""

    status: int = 200
    body: str = ""
    flags: tuple[str, ...] = ("ok",)

    def has(self, flag: str) -> bool:
        return flag in self.flags

    def as_dict(self) -> dict[str, Any]:
        return {"status": self.status, "body": self.body,
                "flags": list(self.flags)}


@dataclass
class RouteSpec:
    """One route of a synthetic lab."""

    path: str
    method: str = "GET"
    requires_auth: str = "none"
    description: str = ""


@dataclass
class VulnPoint:
    """One documented point of ground truth (L-3).

    ``exploitable=False`` marks a decoy: the signature matches but the
    input is filtered, so claiming a finding there is a false positive.
    """

    vuln_class: str
    path: str
    param: str
    signature: str
    requires_auth: str = "none"
    exploitable: bool = True
    filter_token: str = ""
    note: str = ""


@dataclass
class LabInstance:
    """A started synthetic lab with isolated, resettable state (L-2)."""

    instance_id: str
    template_id: str
    family: str
    seed: int
    base_url: str
    routes: tuple[RouteSpec, ...]
    vuln_points: tuple[VulnPoint, ...]
    valid_tokens: frozenset[str] = frozenset()
    state: dict[str, Any] = field(default_factory=dict)
    request_budget: int = 24
    #: defense toggles (blue side patches these, see defender.py)
    normalize_input: bool = False
    strict_types: bool = False

    @property
    def state_hash(self) -> str:
        return stable_hash(
            self.template_id, self.seed,
            [r.__dict__ for r in self.routes],
            [p.__dict__ for p in self.vuln_points],
            sorted(self.valid_tokens),
            self.request_budget,
            self.normalize_input,
            self.strict_types,
        )

    def public_view(self) -> dict[str, Any]:
        """What an attacker is allowed to see: routes and auth shape,
        never the vuln map (L-3 keeps the truth on the trainer side)."""
        return {
            "instance_id": self.instance_id,
            "template_id": self.template_id,
            "family": self.family,
            "base_url": self.base_url,
            "routes": [
                {"path": r.path, "method": r.method,
                 "requires_auth": r.requires_auth,
                 "params": sorted({
                     p.param for p in self.vuln_points if p.path == r.path
                 })}
                for r in self.routes
            ],
            "request_budget": self.request_budget,
        }


class SimulatedTarget:
    """Pure deterministic matcher of requests against lab ground truth."""

    def respond(self, lab: LabInstance, request: DojoRequest) -> DojoResponse:
        if lab.request_budget <= 0:
            return DojoResponse(429, "rate limited", ("rate_limited",))
        lab.request_budget -= 1
        route = next(
            (
                r for r in lab.routes
                if r.path == request.path
                and r.method.upper() == request.method.upper()
            ),
            None,
        )
        if route is None:
            if any(r.path == request.path for r in lab.routes):
                return DojoResponse(
                    405, "method not allowed", ("method_not_allowed",)
                )
            return DojoResponse(404, "no such route", ("not_found",))
        if route.requires_auth != "none":
            token = request.headers.get("session", "")
            if token not in lab.valid_tokens:
                return DojoResponse(401, "forbidden", ("auth_blocked",))
        for point in lab.vuln_points:
            if point.path != request.path:
                continue
            # a vuln point can demand its own authentication, stricter
            # than the route it sits on; without a valid token the point
            # is simply not visible to the requester (L-3 ground truth)
            if point.requires_auth != "none":
                token = request.headers.get("session", "")
                if token not in lab.valid_tokens:
                    continue
            value = request.params.get(point.param, "")
            if not value:
                continue
            # R2-dojo-07: strict_types is the stronger gate, so it is checked
            # first; checking normalize_input first made strict_types a
            # silent no-op whenever both toggles were set
            if lab.strict_types:
                if value != point.signature:
                    continue
            elif lab.normalize_input:
                if point.signature not in value:
                    continue
            elif point.signature.lower() not in value.lower():
                continue
            if point.filter_token:
                # R2-dojo-06: the default matcher is case-insensitive, so its
                # denylist must be applied case-insensitively too, or case
                # variants of exactly the accepted payload evade the filter.
                # The strict/normalize matchers are exact and keep the
                # case-sensitive check.
                if lab.strict_types or lab.normalize_input:
                    filtered = point.filter_token in value
                else:
                    filtered = point.filter_token.lower() in value.lower()
                if filtered:
                    return DojoResponse(
                        200, "input filtered by validation", ("filtered",)
                    )
            if point.exploitable:
                return DojoResponse(
                    200,
                    f"behavior consistent with {point.vuln_class}",
                    ("vuln_hit", point.vuln_class),
                )
            return DojoResponse(
                200, "reflected but neutralized", ("decoy_hit",)
            )
        return DojoResponse(200, "normal response", ("ok",))

    def burn(self, lab: LabInstance, count: int = 1) -> int:
        """Consume request budget; excess trips rate limiting (L-2).

        Negative counts are clamped to zero: burn can only consume.
        """
        lab.request_budget = max(0, lab.request_budget - max(0, int(count)))
        return lab.request_budget


__all__ = [
    "AUTH_LEVELS",
    "RESPONSE_FLAGS",
    "DojoRequest",
    "DojoResponse",
    "LabInstance",
    "RouteSpec",
    "SimulatedTarget",
    "VulnPoint",
    "stable_hash",
]
