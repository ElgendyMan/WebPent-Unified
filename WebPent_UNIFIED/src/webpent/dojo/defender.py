"""U-DOJO-4 (blue side): defense patterns that patch a synthetic lab.

Laws honored here:
- L-4 DETERMINISTIC: every patch is a pure function of the lab and the
  pattern; no randomness, no environment.
- L-6 ADVERSARIAL HONESTY: a patch is judged by whether the red side still
  lands its ground-truth payload, never by how the patch describes itself.
- L-10: patterns touch only dojo lab instances, never real campaign state.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from webpent.dojo.engine import LabInstance, stable_hash


@dataclass(frozen=True)
class DefensePattern:
    """One named, deterministic blue-side patch of a lab instance."""

    name: str
    description: str

    def apply(self, lab: LabInstance) -> LabInstance:
        raise NotImplementedError


def _copy(lab: LabInstance) -> LabInstance:
    clone = replace(lab)
    clone.state = dict(lab.state)
    return clone


def _patch(
    name: str, description: str, mutate
) -> DefensePattern:
    """Wrap a mutation into a DefensePattern with a shared apply()."""

    class _Pattern(DefensePattern):
        def apply(self, lab: LabInstance) -> LabInstance:
            patched = _copy(lab)
            mutate(patched)
            return patched

    _Pattern.__name__ = f"Pattern_{name}"
    _Pattern.__qualname__ = _Pattern.__name__
    return _Pattern(name=name, description=description)


def _add_input_filter(lab: LabInstance) -> None:
    lab.vuln_points = tuple(
        replace(p, filter_token=p.signature) if p.exploitable else p
        for p in lab.vuln_points
    )


def _elevate_auth_requirement(lab: LabInstance) -> None:
    lab.routes = tuple(replace(r, requires_auth="admin") for r in lab.routes)


def _rotate_param_name(lab: LabInstance) -> None:
    lab.vuln_points = tuple(
        replace(p, param=f"{p.param}_rotated") for p in lab.vuln_points
    )


def _shrink_request_budget(lab: LabInstance) -> None:
    lab.request_budget = max(1, lab.request_budget // 4)


def _normalize_input_matching(lab: LabInstance) -> None:
    lab.normalize_input = True


def _remove_vulnerable_route(lab: LabInstance) -> None:
    exposed = {p.path for p in lab.vuln_points if p.exploitable}
    lab.routes = tuple(r for r in lab.routes if r.path not in exposed)
    lab.vuln_points = tuple(
        p for p in lab.vuln_points if not (p.exploitable and p.path in exposed)
    )


def _require_exploit_token(lab: LabInstance) -> None:
    lab.valid_tokens = frozenset()


def _rate_limit_lockout(lab: LabInstance) -> None:
    lab.request_budget = 1


def _session_bind_param(lab: LabInstance) -> None:
    exposed = {p.path for p in lab.vuln_points if p.exploitable}
    lab.routes = tuple(
        replace(r, requires_auth="user") if r.path in exposed else r
        for r in lab.routes
    )


def _strict_type_validation(lab: LabInstance) -> None:
    lab.strict_types = True


def _decoy_hardening(lab: LabInstance) -> None:
    """Make decoys mirror the real flaw and meet probes first, so sloppy
    reds land on neutralized ground instead of the truth."""
    points = list(lab.vuln_points)
    for index, point in enumerate(points):
        if point.exploitable:
            continue
        twin = next(
            (
                p for p in points
                if p.exploitable and p.path == point.path
            ),
            None,
        )
        if twin is not None:
            points[index] = replace(point, signature=twin.signature)
    exploitable = [p for p in points if p.exploitable]
    decoys = [p for p in points if not p.exploitable]
    lab.vuln_points = tuple(decoys + exploitable)


def _signature_rotation(lab: LabInstance) -> None:
    lab.vuln_points = tuple(
        replace(p, signature=stable_hash(p.signature)[:8])
        if p.exploitable else p
        for p in lab.vuln_points
    )


DEFENSE_PATTERNS: tuple[DefensePattern, ...] = (
    _patch(
        "add_input_filter",
        "denylist the known payload so probes containing it are filtered",
        _add_input_filter,
    ),
    _patch(
        "elevate_auth_requirement",
        "require an admin session on every route",
        _elevate_auth_requirement,
    ),
    _patch(
        "rotate_param_name",
        "rename the vulnerable parameter",
        _rotate_param_name,
    ),
    _patch(
        "shrink_request_budget",
        "cut the request budget to a quarter",
        _shrink_request_budget,
    ),
    _patch(
        "normalize_input_matching",
        "match signatures case-sensitively only",
        _normalize_input_matching,
    ),
    _patch(
        "remove_vulnerable_route",
        "take the vulnerable route offline entirely",
        _remove_vulnerable_route,
    ),
    _patch(
        "require_exploit_token",
        "revoke every valid session token",
        _require_exploit_token,
    ),
    _patch(
        "rate_limit_lockout",
        "allow a single request before lockout",
        _rate_limit_lockout,
    ),
    _patch(
        "session_bind_param",
        "require a user session only on the vulnerable route",
        _session_bind_param,
    ),
    _patch(
        "strict_type_validation",
        "require exact-type signature equality",
        _strict_type_validation,
    ),
    _patch(
        "decoy_hardening",
        "mirror the flaw on decoys and let probes meet them first",
        _decoy_hardening,
    ),
    _patch(
        "signature_rotation",
        "rotate the accepted payload to an unpredictable value",
        _signature_rotation,
    ),
)

_PATTERN_BY_NAME = {p.name: p for p in DEFENSE_PATTERNS}


def get_pattern(name: str) -> DefensePattern:
    return _PATTERN_BY_NAME[name]
