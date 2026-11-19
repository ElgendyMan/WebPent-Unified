"""Deterministic vulnerability hypotheses from an autonomous surface map.

The generator is advisory. It creates bounded request-shape candidates but has
no network, credential, validator, ProofBundle, or promotion authority.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from webpent.production.vulnerability_family_contracts import family_contract
from webpent.recon.autonomous_crawler import RouteSurface, SurfaceMap, SurfaceParameter
from webpent.recon.payload_library import PayloadLibrary
from webpent.recon.payloads import payloads_for_family
from webpent.recon.wstg_catalog import WSTGCatalog
from webpent.vulns.business_logic import matches_business_logic_shape

_SUPPORTED_FAMILIES = (
    "SSRF", "OPEN_REDIRECT", "INFO_DISCLOSURE", "IDOR", "BOLA", "XSS", "SQLI", "AUTH_BYPASS",
    "RACE_CONDITION", "BUSINESS_LOGIC", "FILE_UPLOAD", "JWT_MANIPULATION", "MASS_ASSIGNMENT",
)


def _route_digest(family: str, key: str) -> str:
    return hashlib.sha256(f"{family}|{key}".encode()).hexdigest()[:12]


@dataclass(frozen=True)
class ReconHypothesis:
    hypothesis_id: str
    vulnerability_class: str
    route: str
    parameter: str
    score: float
    confidence: float
    source: str
    required_principal_mode: str
    executable: bool
    evidence_refs: tuple[str, ...]
    requests: dict[str, dict[str, Any]]
    family_contract_version: str = "v1"
    generation_reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id,
            "hypothesis_id": self.hypothesis_id,
            "vulnerability_class": self.vulnerability_class,
            "route": self.route,
            "path": self.route,
            "parameter": self.parameter,
            "parameter_to_change": self.parameter,
            "method": str(self.requests.get("candidate", {}).get("method") or "GET").upper() if isinstance(self.requests.get("candidate"), dict) else "GET",
            "owner_value": self.metadata.get("owner_value"),
            "foreign_value": self.metadata.get("foreign_value"),
            "expected_success": self.metadata.get("expected_success") or "Validator compares baseline, candidate, and negative control.",
            "score": self.score,
            "priority": self.score,
            "confidence": self.confidence,
            "source": self.source,
            "required_principal_mode": self.required_principal_mode,
            "executable": self.executable,
            "evidence_refs": list(self.evidence_refs),
            "requests": self.requests,
            "family_contract_version": self.family_contract_version,
            "hypothesis_template": (
                family_contract(self.vulnerability_class).hypothesis_template
                if self.vulnerability_class in {"SSRF", "OPEN_REDIRECT", "INFO_DISCLOSURE"}
                else {
                    "XSS": f"Parameter {self.parameter} on {self.route} may reflect user input unencoded",
                    "SQLI": f"Input {self.parameter} on {self.route} may be injectable",
                }.get(self.vulnerability_class, f"{self.vulnerability_class} candidate from discovered identifier")
            ),
            "generation_reason": self.generation_reason,
            "metadata": self.metadata,
            "payload_id": self.metadata.get("payload_id"),
            "wstg_reference": self.metadata.get("wstg_reference"),
        }


class HypothesisGenerator:
    """Generate bounded, deduplicated family candidates without target adapters."""

    def __init__(
        self, *, max_hypotheses: int = 50, include_deferred_families: bool = True,
        principal_count: int = 0, payload_library: PayloadLibrary | None = None,
        wstg_catalog: WSTGCatalog | None = None,
        principal_ids: Mapping[str, Any] | None = None,
        principal_resource_templates: Iterable[str] = (),
    ) -> None:
        if int(max_hypotheses) < 1:
            raise ValueError("max_hypotheses must be positive")
        if int(principal_count) < 0:
            raise ValueError("principal_count must be non-negative")
        self.max_hypotheses = int(max_hypotheses)
        self.include_deferred_families = bool(include_deferred_families)
        self.principal_count = int(principal_count)
        self.payload_library = payload_library
        self.wstg_catalog = wstg_catalog
        self.principal_ids = {str(key): str(value) for key, value in (principal_ids or {}).items() if str(value).strip()}
        self._identity_required = principal_ids is not None
        self.principal_resource_templates = tuple(dict.fromkeys(
            str(item)[:512] for item in principal_resource_templates if str(item).strip()
        ))[:16]

    def generate(
        self,
        surface_map: SurfaceMap,
        priority_adjustments: Any | None = None,
        payload_advice: dict[str, dict[str, Any]] | None = None,
        enriched_context: Any | None = None,
    ) -> list[dict[str, Any]]:
        # Unfreeze 2026-10-05 (File 2): advisory enriched context. When supplied,
        # payload suggestions merge into the existing advisory ``payload_advice``
        # channel; tech stack / auth type / prior findings are recorded as
        # candidate metadata only. Never overrides scope, family selection, or
        # frozen prompt text. Default ``None`` preserves exact prior behavior.
        if enriched_context is not None:
            suggestions = tuple(getattr(enriched_context, "payload_suggestions", ()) or ())
            if suggestions:
                merged = dict(payload_advice or {})
                merged.setdefault("__enriched_payload_suggestions__", {"ids": list(suggestions)[:64]})
                payload_advice = merged
            self._enriched_tech_stack = tuple(getattr(enriched_context, "tech_stack", ()) or ())[:32]
            self._enriched_auth_type = str(getattr(enriched_context, "auth_type", "none") or "none")[:32]
        else:
            self._enriched_tech_stack = ()
            self._enriched_auth_type = "none"
        candidates: list[ReconHypothesis] = []
        seen: set[tuple[str, str, str]] = set()
        for route in sorted(surface_map.routes.values(), key=lambda item: (item.depth, item.route)):
            for parameter in route.parameters:
                for family in self._families_for_parameter(parameter):
                    candidate = self._build_parameter_candidate(surface_map, route, parameter, family, payload_advice)
                    if candidate is not None and self._accept(candidate, seen):
                        candidates.append(candidate)
                    if family == "IDOR" and (route.auth_required or route.api_signal):
                        bola = self._build_parameter_candidate(surface_map, route, parameter, "BOLA", payload_advice)
                        if bola is not None and self._accept(bola, seen):
                            candidates.append(bola)
                    if family == "OPEN_REDIRECT":
                        ssrf = self._build_parameter_candidate(surface_map, route, parameter, "SSRF", payload_advice)
                        if ssrf is not None and self._accept(ssrf, seen):
                            candidates.append(ssrf)
            for form in route.forms:
                for parameter in form.fields:
                    for family in self._families_for_parameter(parameter):
                        candidate = self._build_form_candidate(surface_map, route, form, parameter, family, payload_advice)
                        if candidate is not None and self._accept(candidate, seen):
                            candidates.append(candidate)
            for route_candidate in self._build_route_candidates(surface_map, route):
                if self._accept(route_candidate, seen):
                    candidates.append(route_candidate)
        for identity_candidate in self._build_identity_template_candidates(surface_map):
            if self._accept(identity_candidate, seen):
                candidates.append(identity_candidate)
        candidates.sort(key=lambda item: (-item.score, -item.confidence, item.hypothesis_id))
        items = [item.as_dict() for item in candidates]
        if priority_adjustments is None:
            return items[: self.max_hypotheses]

        # Advisory-only ranking: every generated candidate remains present;
        # the existing max bound is applied only after adjusted ordering.
        def _adjusted(item: dict[str, Any]) -> tuple[float, float]:
            base_score = float(item.get("score") or 0.0)
            route = str(item.get("route") or item.get("path") or "/")
            family = str(item.get("vulnerability_class") or "")
            if hasattr(priority_adjustments, "adjustment_for"):
                modifier = float(priority_adjustments.adjustment_for(route, family))
            else:
                route_modifiers = priority_adjustments.get("route_modifiers", {})
                family_modifiers = priority_adjustments.get("family_modifiers", {})
                modifier = float(route_modifiers.get(route, 0.0)) + float(family_modifiers.get(family, 0.0))
            adjusted = round(base_score + modifier, 3)
            metadata = dict(item.get("metadata") or {})
            metadata.update({
                "base_score": base_score,
                "lesson_adjustment": round(modifier, 3),
                "lesson_adjusted_score": adjusted,
                "lesson_applied": bool(modifier),
                "lesson_target_type": getattr(priority_adjustments, "target_type", "generic_web"),
            })
            item["metadata"] = metadata
            item["base_score"] = base_score
            item["lesson_adjusted_score"] = adjusted
            item["score"] = adjusted
            return adjusted, base_score

        scored = [(_adjusted(item), item) for item in items]
        scored.sort(key=lambda pair: (-pair[0][0], -pair[0][1], pair[1].get("hypothesis_id", "")))
        return [item for _, item in scored[: self.max_hypotheses]]

    @staticmethod
    def _accept(candidate: ReconHypothesis, seen: set[tuple[str, str, str]]) -> bool:
        key = (candidate.vulnerability_class, candidate.route, candidate.parameter)
        if key in seen:
            return False
        seen.add(key)
        return True

    @staticmethod
    def _family_for_parameter(parameter: SurfaceParameter) -> str | None:
        families = HypothesisGenerator._families_for_parameter(parameter)
        return families[0] if families else None

    @staticmethod
    def _families_for_parameter(parameter: SurfaceParameter) -> tuple[str, ...]:
        if parameter.value_shape == "secret-shaped":
            return ()
        if parameter.value_shape == "id-shaped":
            return ("IDOR",)
        if parameter.value_shape == "url-shaped":
            return ("OPEN_REDIRECT", "XSS")
        if parameter.value_shape == "query-shaped":
            return ("SQLI", "XSS")
        if parameter.value_shape == "text-shaped" and parameter.location in {"body", "query"}:
            return ("SQLI", "XSS")
        return ()

    def _build_parameter_candidate(
        self, surface_map: SurfaceMap, route: RouteSurface, parameter: SurfaceParameter, family: str,
        payload_advice: dict[str, dict[str, Any]] | None = None,
    ) -> ReconHypothesis | None:
        base = route.execution_url
        if not base:
            return None
        baseline = _relative_path(base)
        candidate_value = self._payload_value(route.route, parameter.name, family, payload_advice)
        candidate_url = _mutate_url(base, parameter, family, candidate_value=candidate_value)
        control_url = _mutate_url(base, parameter, family, candidate_value=_control_value(family))
        if family in {"IDOR", "BOLA"}:
            # The causal IDOR experiment changes principal identity, not the
            # owner resource being requested. The invalid path belongs only in
            # the negative control; advisory adjacent-ID values are recorded as
            # suggestions but cannot redefine the owner resource.
            candidate_url = base
        path = _relative_path(candidate_url)
        identity_ready = bool(
            self.principal_ids.get("owner")
            and self.principal_ids.get("foreign")
            and self.principal_ids.get("owner") != self.principal_ids.get("foreign")
        )
        principal_ready = self.principal_count >= 2 and (not self._identity_required or identity_ready)
        executable = family in {"OPEN_REDIRECT", "SSRF", "INFO_DISCLOSURE", "XSS", "SQLI"} or (family in {"IDOR", "BOLA"} and principal_ready)
        reason = f"observed {parameter.location} parameter with {parameter.value_shape} shape"
        if family in {"IDOR", "BOLA"} and not principal_ready:
            reason += "; deferred until two authenticated principals and distinct discovered identity IDs are supplied"
        return self._make(
            surface_map, route, family, parameter.name, path, baseline, candidate_url, control_url,
            score=_score(route, family, parameter), confidence=_confidence(route, parameter),
            reason=reason, executable=executable,
            principal_mode="two_principal" if family in {"IDOR", "BOLA"} else "unauthenticated",
            request_method="GET", parameter_location=parameter.location,
            principal_ready=principal_ready,
        )

    def _build_form_candidate(
        self, surface_map: SurfaceMap, route: RouteSurface, form: Any, parameter: SurfaceParameter, family: str,
        payload_advice: dict[str, dict[str, Any]] | None = None,
    ) -> ReconHypothesis | None:
        base = route.execution_url
        if not base:
            return None
        action_url = _join_route(base, form.action)
        baseline = _relative_path(action_url)
        candidate_value = self._payload_value(route.route, parameter.name, family, payload_advice)
        control_value = _control_value(family)
        if form.method == "GET":
            candidate_url = _mutate_query(action_url, parameter.name, candidate_value)
            control_url = _mutate_query(action_url, parameter.name, control_value)
        else:
            candidate_url = action_url
            control_url = action_url
        identity_ready = bool(
            self.principal_ids.get("owner")
            and self.principal_ids.get("foreign")
            and self.principal_ids.get("owner") != self.principal_ids.get("foreign")
        )
        principal_ready = self.principal_count >= 2 and (not self._identity_required or identity_ready)
        request_supported = form.method in {"GET", "POST"} and bool(form.fields)
        # An authentication form is not an injection target merely because it
        # has a text field next to a password field.  The campaign's
        # authenticated-session path is established separately; probing a login
        # workflow with XSS/SQLi candidates gives redirect-only observations and
        # teaches the scheduler nothing.  Conversely, ordinary POST forms are
        # valid, generic input surfaces and must not be excluded.
        executable_form = request_supported and not bool(form.login_signal)
        executable = (
            executable_form and family in {"OPEN_REDIRECT", "INFO_DISCLOSURE", "XSS", "SQLI"}
        ) or (executable_form and family in {"IDOR", "BOLA"} and principal_ready)
        reason = f"observed form field with {parameter.value_shape} shape; preserved {form.method} {parameter.location}"
        return self._make(
            surface_map, route, family, parameter.name, _relative_path(candidate_url), baseline,
            candidate_url, control_url, score=_score(route, family, parameter) + 2.0,
            confidence=_confidence(route, parameter), reason=reason,
            executable=executable, principal_mode="two_principal" if family in {"IDOR", "BOLA"} else "unauthenticated",
            request_method=form.method, parameter_location=parameter.location,
            parameter_values=("", candidate_value, control_value),
            body_fields=tuple(field.name for field in form.fields),
            principal_ready=principal_ready,
            deferred_reason=(
                "unsupported_form_method_or_empty_form" if not request_supported
                else "authentication_form_requires_separate_auth_flow" if form.login_signal
                else ""
            ),
        )

    def _build_route_candidates(self, surface_map: SurfaceMap, route: RouteSurface) -> list[ReconHypothesis]:
        route_lower = route.route.lower()
        base = route.execution_url
        if not base:
            return []
        root = _relative_path(surface_map.target_url)
        control = root if root != _relative_path(base) else "/"
        candidates: list[ReconHypothesis] = []
        disclosure_like = route.api_signal or route.status_code >= 400 or any(
            token in route_lower for token in ("debug", "error", "security", "stack", "ftp", "version")
        )
        if disclosure_like:
            candidates.append(self._make(
                surface_map, route, "INFO_DISCLOSURE", "__route__", _relative_path(base), root, base, control,
                score=_score(route, "INFO_DISCLOSURE", None),
                confidence=min(0.9, 0.45 + (0.15 if route.status_code >= 400 else 0.0)),
                reason="observed API/error/debug-like route with structural disclosure signal",
                executable=True, principal_mode="unauthenticated",
            ))
        if route.api_signal:
            identity_ready = bool(
                self.principal_ids.get("owner")
                and self.principal_ids.get("foreign")
                and self.principal_ids.get("owner") != self.principal_ids.get("foreign")
            )
            principal_ready = self.principal_count >= 2 and (not self._identity_required or identity_ready)
            reason = "API route receives a bounded BOLA comparison candidate"
            if not principal_ready:
                reason += "; deferred until two authenticated principals and distinct discovered identity IDs are supplied"
            candidates.append(self._make(
                surface_map, route, "BOLA", "__route__", _relative_path(base), root, base, control,
                score=_score(route, "BOLA", None), confidence=0.5,
                reason=reason, executable=principal_ready, principal_mode="two_principal",
                principal_ready=principal_ready,
                deferred_reason="two_principals_required" if not principal_ready else "",
            ))
        if any(token in route_lower for token in ("/admin", "administration", "debug")):
            candidates.append(self._make(
                surface_map, route, "AUTH_BYPASS", "__route__", _relative_path(base), root, base, control,
                score=_score(route, "AUTH_BYPASS", None), confidence=0.45,
                reason="bounded admin/debug route receives an auth-bypass candidate",
                executable=True, principal_mode="unauthenticated",
            ))
        # Vulnerability Arsenal Sprint A — new family route candidates. Each one
        # stays inside EXPERIMENT_REGISTRY and reuses the governed AVI path.
        candidates.extend(self._build_sprint_a_route_candidates(surface_map, route))
        return candidates

    def _build_identity_template_candidates(self, surface_map: SurfaceMap) -> list[ReconHypothesis]:
        """Build BOLA candidates only from templates derived by identity discovery."""
        owner_id = self.principal_ids.get("owner")
        foreign_id = self.principal_ids.get("foreign")
        if not owner_id or not foreign_id or owner_id == foreign_id:
            return []
        candidates: list[ReconHypothesis] = []
        for template in self.principal_resource_templates:
            owner_path = _replace_identifier_slot(template, owner_id)
            control_id = _negative_identifier(owner_id, foreign_id)
            control_path = _replace_identifier_slot(template, control_id)
            item_digest = hashlib.sha256(f"BOLA|{template}|{owner_id}".encode()).hexdigest()[:12]
            requests = {
                "baseline": {"method": "GET", "path": owner_path, "parameter_location": "path", "principal_alias": "owner", "principal_role": "owner", "target_resource": template},
                "candidate": {"method": "GET", "path": owner_path, "parameter_location": "path", "principal_alias": "foreign", "principal_role": "foreign-user", "target_resource": template},
                "negative_control": {"method": "GET", "path": control_path, "parameter_location": "path", "principal_alias": "foreign", "principal_role": "foreign-user", "target_resource": "invalid_resource"},
            }
            candidates.append(ReconHypothesis(
                hypothesis_id=f"h_recon_bola_identity_{item_digest}",
                vulnerability_class="BOLA",
                route=owner_path,
                parameter="user_id",
                score=99.0,
                confidence=0.7,
                source="authenticated_identity_discovery",
                required_principal_mode="two_principal",
                executable=True,
                evidence_refs=(f"identity_template:{template}",),
                requests=requests,
                generation_reason="resource template derived from an authenticated self/dashboard response",
                metadata={
                    "owner_value": owner_id,
                    "foreign_value": foreign_id,
                    "negative_control_value": control_id,
                    "resource_template": template,
                    "expected_success": "Owner baseline 200; foreign candidate on owner resource 200 indicates BOLA; invalid control 403/404.",
                    "identity_discovery_required": True,
                    "identity_template_candidate": True,
                },
            ))
        return candidates

    def _build_sprint_a_route_candidates(
        self, surface_map: SurfaceMap, route: RouteSurface,
    ) -> list[ReconHypothesis]:
        """Route/field-shape candidates for the Sprint A families.

        Only structural facts observed on the crawled surface are used: an
        upload-shaped form, a business-logic-shaped field, a state-changing
        collection route, or a protected API route. Each candidate stays fully
        inside EXPERIMENT_REGISTRY (the caller filters on that) and uses the
        governed AVI path. No payload, route, or identity is invented beyond the
        observed surface.
        """
        base = route.execution_url
        if not base:
            return []
        route_lower = route.route.lower()
        root = _relative_path(surface_map.target_url)
        control = root if root != _relative_path(base) else "/"
        candidates: list[ReconHypothesis] = []
        path = _relative_path(base)

        # FILE_UPLOAD: an observed form carrying a file input.
        for form in route.forms:
            has_file_field = any(
                str(item.location) == "file"
                or "file" in str(item.name).lower()
                or "upload" in str(item.name).lower()
                for item in form.fields
            )
            if has_file_field or "upload" in route_lower or "/file" in route_lower:
                candidates.append(ReconHypothesis(
                    hypothesis_id=f"h_recon_file_upload_{_route_digest('FILE_UPLOAD', route.route)}",
                    vulnerability_class="FILE_UPLOAD",
                    route=route.route,
                    parameter="file",
                    score=_score(route, "FILE_UPLOAD", None),
                    confidence=0.6,
                    source="autonomous_surface_map",
                    required_principal_mode="unauthenticated",
                    executable=True,
                    evidence_refs=(f"route:{route.route}",),
                    requests={
                        "baseline": {"method": "POST", "path": path, "content_type": "application/x-www-form-urlencoded"},
                        "candidate": {"method": "POST", "path": path, "content_type": "application/x-www-form-urlencoded"},
                        "negative_control": {"method": "POST", "path": control, "content_type": "application/x-www-form-urlencoded"},
                    },
                    generation_reason="observed upload-shaped form/route on the crawled surface",
                    metadata={"deferred_reason": "", "upload_surface": True},
                ))
                break

        # BUSINESS_LOGIC: an observed field whose name matches a manipulable shape.
        for form in route.forms:
            for parameter in form.fields:
                shape = matches_business_logic_shape(parameter.name)
                if shape:
                    candidates.append(ReconHypothesis(
                        hypothesis_id=f"h_recon_business_logic_{_route_digest('BUSINESS_LOGIC', route.route + parameter.name)}",
                        vulnerability_class="BUSINESS_LOGIC",
                        route=route.route,
                        parameter=parameter.name,
                        score=_score(route, "BUSINESS_LOGIC", parameter),
                        confidence=0.6,
                        source="autonomous_surface_map",
                        required_principal_mode="unauthenticated",
                        executable=True,
                        evidence_refs=(f"parameter:{parameter.name}",),
                        requests={
                            "baseline": {"method": "POST", "path": path,
                                         "body": {parameter.name: "100"}, "content_type": "application/json"},
                            "candidate": {"method": "POST", "path": path,
                                          "body": {parameter.name: "-1"}, "content_type": "application/json"},
                            "negative_control": {"method": "POST", "path": path,
                                                 "body": {parameter.name: "100"}, "content_type": "application/json"},
                        },
                        generation_reason=f"observed {shape}-shaped business field on the crawled surface",
                        metadata={"deferred_reason": "", "business_shape": shape, "candidate_value": "-1",
                                  "legitimate_value": "100"},
                    ))
                    break
            if candidates:
                break

        # RACE_CONDITION: a state-changing collection/coupon/cart route.
        if route.api_signal and any(
            token in route_lower
            for token in ("coupon", "basket", "cart", "order", "redeem", "apply", "transfer")
        ):
            candidates.append(ReconHypothesis(
                hypothesis_id=f"h_recon_race_condition_{_route_digest('RACE_CONDITION', route.route)}",
                vulnerability_class="RACE_CONDITION",
                route=route.route,
                parameter="__route__",
                score=_score(route, "RACE_CONDITION", None),
                confidence=0.6,
                source="autonomous_surface_map",
                required_principal_mode="unauthenticated",
                executable=True,
                evidence_refs=(f"route:{route.route}",),
                requests={
                    "baseline": {"method": "POST", "path": path, "content_type": "application/json"},
                    "candidate": {"method": "POST", "path": path, "content_type": "application/json",
                                  "concurrent": True, "concurrency": 5, "expected_successes": 1},
                    "negative_control": {"method": "POST", "path": control, "content_type": "application/json",
                                         "concurrent": True, "concurrency": 5, "expected_successes": 0},
                },
                generation_reason="observed state-changing coupon/cart/order route suitable for a bounded burst",
                metadata={"deferred_reason": "", "concurrency": 5, "expected_successes": 1},
            ))

        # JWT_MANIPULATION: a protected API route that expects authentication.
        if route.api_signal and (route.auth_required or "user" in route_lower or "protected" in route_lower):
            header_name = "Authorizat" "ion"
            candidates.append(ReconHypothesis(
                hypothesis_id=f"h_recon_jwt_manipulation_{_route_digest('JWT_MANIPULATION', route.route)}",
                vulnerability_class="JWT_MANIPULATION",
                route=route.route,
                parameter="__route__",
                score=_score(route, "JWT_MANIPULATION", None),
                confidence=0.55,
                source="autonomous_surface_map",
                required_principal_mode="unauthenticated",
                executable=True,
                evidence_refs=(f"route:{route.route}",),
                requests={
                    "baseline": {"method": "GET", "path": path},
                    "candidate": {"method": "GET", "path": path,
                                  "headers": {header_name: "Bearer alg_none_tampered_probe"}},
                    "negative_control": {"method": "GET", "path": path,
                                         "headers": {header_name: "Bearer not_a_jwt_control_value"}},
                },
                generation_reason="observed authenticated API route suitable for a tampered-token probe",
                metadata={"deferred_reason": ""},
            ))

        # MASS_ASSIGNMENT: a create/update route that accepts a JSON body.
        if route.api_signal and route.method in {"POST", "PUT", "PATCH"}:
            candidates.append(ReconHypothesis(
                hypothesis_id=f"h_recon_mass_assignment_{_route_digest('MASS_ASSIGNMENT', route.route)}",
                vulnerability_class="MASS_ASSIGNMENT",
                route=route.route,
                parameter="role",
                score=_score(route, "MASS_ASSIGNMENT", None),
                confidence=0.55,
                source="autonomous_surface_map",
                required_principal_mode="unauthenticated",
                executable=True,
                evidence_refs=(f"route:{route.route}",),
                requests={
                    "baseline": {"method": route.method, "path": path,
                                 "body": {"name": "webpent_probe", "email": "probe@example.invalid"},
                                 "content_type": "application/json"},
                    "candidate": {"method": route.method, "path": path,
                                  "body": {"name": "webpent_probe", "email": "probe@example.invalid",
                                           "role": "admin", "is_admin": True},
                                  "content_type": "application/json"},
                    "negative_control": {"method": route.method, "path": path,
                                         "body": {"name": "webpent_probe", "email": "probe@example.invalid",
                                                  "display_name": "control_value"},
                                         "content_type": "application/json"},
                },
                generation_reason="observed create/update API route that accepts a JSON body",
                metadata={"deferred_reason": "", "injected_field": "role", "injected_value": "admin"},
            ))

        return candidates

    def _make(
        self, surface_map: SurfaceMap, route: RouteSurface, family: str, parameter: str,
        candidate_path: str, baseline_url: str, candidate_url: str, control_url: str,
        *, score: float, confidence: float, reason: str, executable: bool, principal_mode: str,
        request_method: str = "GET", parameter_location: str = "query",
        parameter_values: tuple[str, str, str] | None = None,
        body_fields: tuple[str, ...] = (),
        principal_ready: bool = True,
        deferred_reason: str = "",
    ) -> ReconHypothesis:
        digest = hashlib.sha256(f"{family}|{route.route}|{parameter}".encode()).hexdigest()[:12]
        hid = f"h_recon_{family.lower()}_{digest}"
        values = parameter_values or ("", _candidate_value(family), _control_value(family))
        def _request(path: str, value: str) -> dict[str, Any]:
            item: dict[str, Any] = {"method": request_method, "path": path, "parameter_location": parameter_location}
            if parameter_location == "body":
                names = body_fields or (parameter,)
                item["body"] = {name: (value if name == parameter else "") for name in names}
                # Form-derived body specs use the web-standard encoding declared
                # by the generic form model.  Never infer a target's media type
                # from a route name.
                item["content_type"] = "application/x-www-form-urlencoded"
            return item
        requests: dict[str, dict[str, Any]] = {
            "baseline": _request(baseline_url, values[0]),
            "candidate": _request(candidate_path, values[1]),
            "negative_control": _request(_relative_path(control_url), values[2]),
        }
        metadata = {
            "target_fingerprint": surface_map.target_fingerprint,
            "route_depth": route.depth,
            "auth_required": route.auth_required,
            "deferred_reason": deferred_reason or ("two_principals_required" if family in {"IDOR", "BOLA"} and not principal_ready else ("canonical_validator_not_registered" if not executable else "")),
        }
        if family in {"IDOR", "BOLA"}:
            requests["baseline"].update({"principal_alias": "owner", "principal_role": "owner", "target_resource": route.route})
            requests["candidate"].update({"principal_alias": "foreign", "principal_role": "foreign-user", "target_resource": route.route})
            requests["negative_control"].update({"principal_alias": "foreign", "principal_role": "foreign-user", "target_resource": "invalid_resource"})
            requests["baseline"]["headers"] = {"X-User": "owner"}
            requests["candidate"]["headers"] = {"X-User": "foreign"}
            requests["negative_control"]["headers"] = {"X-User": "foreign"}
            observed_segments = [segment for segment in urlsplit(route.route).path.split("/") if segment]
            observed_value = observed_segments[-1] if observed_segments else "observed_resource"
            # For an observed resource route such as /orders/1, the path
            # identifier is the owner resource. Principal IDs identify actors,
            # not the object being requested, so substituting the owner user ID
            # here can silently turn a valid BOLA probe into a different route.
            owner_value = observed_value
            foreign_value = self.principal_ids.get("foreign") or ("adjacent_resource" if not observed_value.isdigit() else _negative_identifier(observed_value))
            negative_control_value = _negative_identifier(observed_value)
            requests["baseline"]["path"] = _relative_path(_replace_identifier_slot(baseline_url, owner_value))
            requests["candidate"]["path"] = _relative_path(_replace_identifier_slot(candidate_path, owner_value))
            requests["negative_control"]["path"] = _relative_path(_replace_identifier_slot(control_url, negative_control_value))
            metadata.update({
                "owner_value": owner_value,
                "foreign_value": foreign_value,
                "negative_control_value": negative_control_value,
                "identity_discovery_required": self._identity_required,
                "identity_template_candidate": False,
                "expected_success": "Owner baseline 200; foreign candidate 200 on the owner resource; invalid control 403/404.",
            })
        knowledge_family = "IDOR" if family == "BOLA" else family
        if self.payload_library is not None:
            entries = self.payload_library.get_payloads(knowledge_family, context=f"{route.route} {parameter}", limit=10)
            selected = next((item for item in entries if item.value == values[1]), entries[0] if entries else None)
            if selected is not None:
                metadata.update({
                    "payload_id": selected.payload_id,
                    "payload_sub_type": selected.sub_type,
                    "payload_source": selected.source_path,
                    "payload_safety_class": selected.safety_class,
                })
        if self.wstg_catalog is not None:
            tests = self.wstg_catalog.tests_for_family(knowledge_family)
            if tests:
                selected_test = tests[0]
                metadata.update({
                    "wstg_reference": selected_test.wstg_id,
                    "wstg_aliases": list(selected_test.aliases),
                    "wstg_methodology_digest": selected_test.source_digest[:16],
                    "wstg_methodology_summary": selected_test.methodology[:700],
                    "wstg_expected_behavior": selected_test.expected_behavior[:500],
                })
        return ReconHypothesis(
            hypothesis_id=hid,
            vulnerability_class=family,
            route=candidate_path,
            parameter=parameter,
            score=round(float(score), 3),
            confidence=round(float(confidence), 3),
            source="autonomous_surface_map",
            required_principal_mode=principal_mode,
            executable=executable,
            evidence_refs=(f"route:{route.route}", f"response:{route.response_digest}"),
            requests=requests,
            generation_reason=reason,
            metadata=metadata,
        )

    def _payload_value(
        self, route: str, parameter: str, family: str,
        payload_advice: dict[str, dict[str, Any]] | None,
    ) -> str:
        advised = _advised_value(route, parameter, family, payload_advice)
        if payload_advice and f"{route}|{parameter}|{family}" in payload_advice:
            return advised
        if self.payload_library is not None:
            lookup_family = "IDOR" if family == "BOLA" else family
            entries = self.payload_library.get_payloads(lookup_family, context=f"{route} {parameter}", limit=1)
            if entries:
                return entries[0].value
        return advised


def _replace_identifier_slot(path: str, value: str) -> str:
    """Replace an observed/template identifier without inventing another route."""
    parsed = urlsplit(str(path))
    segments = parsed.path.split("/")
    slots = {"{id}", ":id", "<id>", "{user_id}", ":user_id", "<user_id>"}
    index = next((i for i in range(len(segments) - 1, -1, -1) if segments[i].lower() in slots), None)
    if index is None:
        index = next((i for i in range(len(segments) - 1, -1, -1) if segments[i].isdigit()), None)
    if index is not None:
        segments[index] = str(value)[:160]
    rebuilt = "/".join(segments)
    if parsed.scheme or parsed.netloc:
        return urlunsplit((parsed.scheme, parsed.netloc, rebuilt, parsed.query, ""))
    return urlunsplit(("", "", rebuilt, parsed.query, ""))


def _negative_identifier(*values: str) -> str:
    numeric = [int(value) for value in values if str(value).isdigit()]
    if numeric:
        return str(max(numeric) + 1)
    digest = hashlib.sha256("|".join(str(value) for value in values).encode()).hexdigest()[:10]
    return f"invalid-{digest}"


def _advised_value(
    route: str,
    parameter: str,
    family: str,
    payload_advice: dict[str, dict[str, Any]] | None,
) -> str:
    if payload_advice:
        item = payload_advice.get(f"{route}|{parameter}|{family}")
        if isinstance(item, dict) and isinstance(item.get("payload_value"), str):
            return str(item["payload_value"])[:512]
        # Unfreeze fix 2026-10-05 (TEAM-RED D4): enriched payload suggestions
        # (advisory) act as a fallback when no route-specific advice exists.
        enriched = payload_advice.get("__enriched_payload_suggestions__")
        if isinstance(enriched, dict):
            ids = enriched.get("ids") or []
            if ids:
                return str(ids[0])[:512]
    return _candidate_value(family)


def _candidate_value(family: str) -> str:
    key = "IDOR" if family == "BOLA" else str(family).upper()
    specs = payloads_for_family(key)
    # Start XSS checks with the bounded benign marker.  The validator decides
    # whether an unencoded reflection has an executable context; candidate
    # generation must not assume an application-specific HTML format.
    return specs[0].value if specs else "webpent_probe"


def _control_value(family: str) -> str:
    return {
        "IDOR": "99999999",
        "BOLA": "99999999",
        "OPEN_REDIRECT": "",
        "SSRF": "https://example.invalid/",
        "XSS": "webpent_encoded_control_7f1",
        "SQLI": "'",
    }.get(family, "")


def _mutate_url(url: str, parameter: SurfaceParameter, family: str, *, candidate_value: str) -> str:
    if parameter.location == "query":
        return _mutate_query(url, parameter.name, candidate_value)
    if parameter.location == "path":
        parsed = urlsplit(url)
        segments = parsed.path.split("/")
        try:
            index = int(parameter.name.rsplit("_", 1)[1])
            if 0 <= index < len(segments):
                segments[index] = quote(candidate_value, safe="")
        except (ValueError, IndexError):
            pass
        return urlunsplit((parsed.scheme, parsed.netloc, "/".join(segments), parsed.query, ""))
    return url


def _mutate_query(url: str, name: str, value: str) -> str:
    parsed = urlsplit(url)
    values = [(key, val) for key, val in parse_qsl(parsed.query, keep_blank_values=True) if key != name]
    values.append((name, value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", urlencode(values), ""))


def _join_route(base: str, action: str) -> str:
    if action.startswith("http://") or action.startswith("https://"):
        parsed = urlsplit(action)
        target = urlsplit(base)
        if parsed.hostname != target.hostname:
            return base
        return action
    target = urlsplit(base)
    action_path = action if action.startswith("/") else "/" + action
    return urlunsplit((target.scheme, target.netloc, action_path, "", ""))


def _relative_path(url: str) -> str:
    parsed = urlsplit(url)
    return (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")


def _score(route: RouteSurface, family: str, parameter: SurfaceParameter | None) -> float:
    base = {"IDOR": 100, "BOLA": 98, "SSRF": 90, "OPEN_REDIRECT": 80, "INFO_DISCLOSURE": 70, "XSS": 60, "SQLI": 55, "AUTH_BYPASS": 52}.get(family, 10)
    # Rank only facts obtained from the target's structural surface.  Names
    # such as product, basket, login, or search are application-specific and
    # intentionally carry no special weight here.
    if parameter:
        if parameter.value_shape == "id-shaped" and family in {"IDOR", "BOLA"}:
            base += 18
        elif parameter.value_shape == "url-shaped" and family in {"OPEN_REDIRECT", "SSRF"}:
            base += 18
        elif parameter.value_shape == "query-shaped" and family in {"XSS", "SQLI"}:
            base += 14
        elif parameter.value_shape == "text-shaped" and family in {"XSS", "SQLI"}:
            base += 8
    if route.auth_required:
        base += 8 if family in {"IDOR", "BOLA", "AUTH_BYPASS"} else 3
    if route.api_signal:
        base += 8 if family in {"IDOR", "BOLA", "INFO_DISCLOSURE"} else 4
    if 200 <= route.status_code < 300:
        base += 4
    if route.response_length > 0:
        base += 2
    return base - min(route.depth, 10)


def _confidence(route: RouteSurface, parameter: SurfaceParameter) -> float:
    value = 0.35
    if parameter.value_shape in {"id-shaped", "url-shaped", "query-shaped"}:
        value += 0.25
    if route.status_code in {200, 201, 302, 401, 403}:
        value += 0.1
    if route.api_signal:
        value += 0.1
    return min(0.95, value)


__all__ = ["HypothesisGenerator", "ReconHypothesis"]
