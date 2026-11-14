"""Runtime-only generic principal provisioning for authorized lab campaigns."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit

from webpent.models.evidence import sha256_text
from webpent.production.context_authority import ContextAuthority, PrincipalRef, PrincipalRole
from webpent.recon.auth_detector import AuthDetection, AuthDetector
from webpent.recon.identity_discovery import IdentityDiscoverer, IdentityDiscoveryResult, decode_login_jwt_claims
from webpent.recon.login_executor import LoginExecutor, LoginResult, RegistrationResult
from webpent.shared.engagement_scope import clear_engagement_target_hosts, set_engagement_target_hosts
from webpent.shared.http import make_safe_httpx_client


@dataclass(frozen=True)
class ProvisionedPrincipal:
    alias: str
    role: str
    credential_alias: str
    login: LoginResult
    vault_bound: bool = False
    vault_key_digest: str = ""
    registration_attempted: bool = False
    registration_success: bool = False
    registration_status_code: int | None = None
    identity: IdentityDiscoveryResult | None = field(default=None, repr=False, compare=False)
    # r9 D3 (DR-017): the requested vs detected vs executed auth-type triple
    # is recorded, never silently relabelled.
    requested_auth_type: str = ""
    detected_auth_type: str = ""

    def as_dict(self) -> dict[str, Any]:
        value = self.login.as_dict()
        value.update({
            "alias": self.alias,
            "role": self.role,
            "credential_alias": self.credential_alias,
            "vault_bound": self.vault_bound,
            "vault_key_digest": self.vault_key_digest,
            "registration_attempted": self.registration_attempted,
            "registration_success": self.registration_success,
            "registration_status_code": self.registration_status_code,
            "identity_discovery": self.identity.as_dict() if self.identity else None,
            "requested_auth_type": self.requested_auth_type[:64] or None,
            "detected_auth_type": self.detected_auth_type[:64] or None,
            "executed_auth_type": str(self.login.auth_type or "")[:64] or None,
        })
        return value


@dataclass(frozen=True)
class ProvisioningResult:
    detection: AuthDetection
    principals: tuple[ProvisionedPrincipal, ...]
    target_fingerprint: str
    reason: str = ""

    @property
    def successful_count(self) -> int:
        return sum(1 for item in self.principals if item.login.success and item.vault_bound)

    @property
    def aliases(self) -> tuple[str, ...]:
        return tuple(item.alias for item in self.principals if item.login.success and item.vault_bound)

    @property
    def identity_ids(self) -> dict[str, str]:
        return {
            item.alias: str(item.identity.user_id)
            for item in self.principals
            if item.login.success and item.vault_bound and item.identity and item.identity.success and item.identity.user_id
        }

    @property
    def resource_templates(self) -> tuple[str, ...]:
        values: list[str] = []
        for item in self.principals:
            if item.identity is None:
                continue
            for template in item.identity.resource_templates:
                if template not in values:
                    values.append(template)
        return tuple(values[:16])

    @property
    def identity_resolution(self) -> dict[str, Any]:
        """r6c identity-resolution rollup (tests/test_identity_ladder_r6.py).

        ``attempted`` is a boolean (any principal carried an identity result),
        ``winner_strategies`` maps alias -> winner (None when unresolved), and
        ``s4_honest_exhaustion`` counts principals that halted honestly.
        """
        winner_map: dict[str, str | None] = {}
        exhausted_aliases: list[str] = []
        resolved_count = 0
        exhausted_count = 0
        attempted = False
        for item in self.principals:
            identity = item.identity
            if identity is None:
                continue
            attempted = True
            if identity.success:
                resolved_count += 1
                winner_map[item.alias[:128]] = str(identity.winner_strategy or "unknown")
            elif identity.reason == "identity_resolution_exhausted":
                exhausted_count += 1
                winner_map[item.alias[:128]] = None
                exhausted_aliases.append(item.alias[:128])
        return {
            "attempted": attempted,
            "resolved": resolved_count,
            "winner_strategies": winner_map,
            "s4_honest_exhaustion": exhausted_count,
            "exhausted_principals": exhausted_aliases,
            "reason": "identity_resolution_block",
        }

    def as_dict(self) -> dict[str, Any]:
        return {
            "detection": self.detection.as_dict(),
            "target_fingerprint": self.target_fingerprint,
            "principals": [item.as_dict() for item in self.principals],
            "successful_count": self.successful_count,
            "available_aliases": list(self.aliases),
            "identity_ids_discovered": sorted(self.identity_ids),
            "resource_template_count": len(self.resource_templates),
            "identity_resolution": self.identity_resolution,
            "reason": self.reason,
        }


def _target_fingerprint(target_url: str) -> str:
    # AVI and ContextAuthority bind on the canonical evidence fingerprint,
    # not the raw-string digest. Keeping this helper identical prevents a
    # successful seal from becoming an apparently unbound principal later.
    return sha256_text(target_url)[:16]


def _role_for(index: int, profile: Mapping[str, Any]) -> str:
    requested = str(profile.get("role") or "").strip().lower()
    if requested in {role.value for role in PrincipalRole}:
        return requested
    return PrincipalRole.OWNER.value if index == 0 else PrincipalRole.FOREIGN_USER.value


def _canonical_alias(index: int, profile_name: str, role: str) -> str:
    # The generic hypothesis contract uses these aliases for the comparative
    # owner/foreign triple. Operator names remain in redacted metadata only.
    if role == PrincipalRole.OWNER.value:
        return "owner"
    if index == 1:
        return "foreign"
    return f"foreign{index}"


_M4_RESERVED_HEADERS = {"accept", "x-user", "cookie", "authorization", "user-agent", "content-type"}


def _extract_m4_attached_credential(headers: Mapping[str, str]) -> tuple[str, str] | None:
    """Read the credential that M4 itself attached to the resolved headers.

    Only vault-attached material is considered: the Authorization bearer value,
    a single vault-added api-key style header, or the vault-added cookie.  The
    caller NEVER supplies credential material; this is read-back of what the
    governed boundary produced, so no second credential-attachment path exists.
    """
    authorization = headers.get("Authorization") or headers.get("authorization") or ""
    if authorization.startswith("Bearer ") and authorization[7:].strip():
        return "token", authorization[7:].strip()
    extra = [(key, value) for key, value in headers.items() if str(key).lower() not in _M4_RESERVED_HEADERS]
    if len(extra) == 1 and str(extra[0][1]).strip():
        return str(extra[0][0])[:128], str(extra[0][1]).strip()
    cookie = headers.get("Cookie") or headers.get("cookie") or ""
    cookie = cookie.split(";", 1)[0]
    name, separator, value = cookie.partition("=")
    if separator and name.strip() and value.strip():
        return name.strip()[:128], value.strip()
    return None


def _relocate_m4_credential(headers: dict[str, str], transport: str, request_url: str) -> tuple[str, dict[str, str]] | None:
    """Relocate the M4-attached credential INSIDE the governed boundary.

    Transport variants (``query:<param>`` / ``cookie:<name>``) are part of the
    extended request spec.  The credential source is exclusively the M4 attach
    output; relocation happens after authorize -> resolve -> attach and never
    bypasses M4.  Returns the (possibly query-augmented) url and headers, or
    None when the sealed material cannot legally ride the requested transport
    (e.g. Basic auth) — the caller records that honestly.
    """
    kind, _, target_name = str(transport).partition(":")
    if kind not in {"query", "cookie"}:
        return None
    credential = _extract_m4_attached_credential(headers)
    if credential is None:
        return None
    _credential_name, credential_value = credential
    target_name = (target_name.strip() or "token")[:128]
    kept: dict[str, str] = {}
    for key, value in headers.items():
        lowered = str(key).lower()
        if lowered in {"authorization", "cookie"}:
            continue
        if lowered not in _M4_RESERVED_HEADERS:
            continue  # drop the credential header being relocated
        kept[key] = value
    if kind == "query":
        from urllib.parse import quote
        separator = "&" if "?" in request_url else "?"
        relocated_url = f"{request_url}{separator}{quote(target_name, safe='')}={quote(credential_value, safe='')}"
        return relocated_url[:2048], kept
    kept["Cookie"] = f"{target_name}={credential_value}"
    return request_url, kept


class PrincipalProvisioner:
    """Login each supplied identity with a fresh client, then seal via M4."""

    def __init__(self, *, target_url: str, engagement_id: str, audit_chain: Any = None, timeout_seconds: float = 10.0) -> None:
        self.target_url = target_url.rstrip("/")
        self.engagement_id = str(engagement_id)
        self.audit_chain = audit_chain
        self.timeout_seconds = timeout_seconds

    def provision(
        self,
        profiles: Mapping[str, Mapping[str, Any]] | Sequence[Mapping[str, Any]],
        *,
        detection: AuthDetection | None = None,
        crawl_routes: Sequence[str] = (),
    ) -> ProvisioningResult:
        normalized: list[tuple[str, Mapping[str, Any]]] = []
        if isinstance(profiles, Mapping):
            for name, profile in list(profiles.items())[:32]:
                if isinstance(profile, Mapping):
                    normalized.append((str(name)[:128], profile))
        else:
            for index, profile in enumerate(list(profiles)[:32]):
                if isinstance(profile, Mapping):
                    normalized.append((str(profile.get("name") or f"principal_{index + 1}")[:128], profile))
        if detection is None:
            detection = AuthDetector(target_url=self.target_url).detect({}, credential_aliases=[name for name, _ in normalized])
        if not detection.signals and normalized:
            configured_type = str(normalized[0][1].get("auth_type") or "").strip()
            configured_url = str(normalized[0][1].get("login_url") or "").strip()
            if configured_type in {"form_session", "api_jwt", "basic", "oauth", "api_key"}:
                from webpent.recon.auth_detector import AuthSignal
                detection = AuthDetection((AuthSignal(auth_type=configured_type, login_url=configured_url or None, login_method="POST"),), detection.target_origin, detection.credential_aliases)
        if not detection.signals:
            return ProvisioningResult(detection, (), _target_fingerprint(self.target_url), "no_auth_signal_detected")
        signal = detection.primary
        if signal is None:
            return ProvisioningResult(detection, (), _target_fingerprint(self.target_url), "no_primary_auth_signal")
        api_signals = [item for item in detection.signals if item.auth_type == "api_jwt" and item.login_url]
        signal_candidates = tuple(api_signals) + tuple(item for item in detection.signals if item not in api_signals)
        executor = LoginExecutor(target_url=self.target_url, timeout_seconds=self.timeout_seconds)
        authority = ContextAuthority(
            engagement_id=self.engagement_id,
            target_fingerprint=_target_fingerprint(self.target_url),
            audit_chain=self.audit_chain,
        )
        results: list[ProvisionedPrincipal] = []
        for index, (profile_name, profile) in enumerate(normalized[:3]):
            role = _role_for(index, profile)
            alias = _canonical_alias(index, profile_name, role)
            configured_type = str(profile.get("auth_type") or "").strip()
            supported_types = {"form_session", "api_jwt", "basic", "oauth", "api_key"}
            configured_url = str(profile.get("login_url") or "").strip()
            if configured_type and configured_type not in supported_types:
                login = LoginResult(alias, False, configured_type, configured_url or None, None, "unsupported_auth_type")
                results.append(ProvisionedPrincipal(alias, role, profile_name, login, requested_auth_type=configured_type, detected_auth_type=detected_type))
                continue
            allowed_types = {configured_type} if configured_type else None
            configured_fields = profile.get("login_fields") if isinstance(profile.get("login_fields"), Mapping) else {}
            candidates_for_profile = tuple(item for item in signal_candidates if allowed_types is None or item.auth_type in allowed_types)
            if not candidates_for_profile:
                if configured_type and configured_url:
                    from webpent.recon.auth_detector import AuthSignal
                    candidates_for_profile = (AuthSignal(
                        auth_type=configured_type,
                        login_url=configured_url,
                        login_method="POST",
                        login_fields={str(k): str(v) for k, v in configured_fields.items()},
                        token_type="jwt" if configured_type == "api_jwt" else "none",
                    ),)
                elif configured_type:
                    # r9 D3: no DETECTED signal matches the requested type — the
                    # requested strategy is still attempted through the synthetic
                    # signal only when a URL exists; otherwise the DETECTED
                    # strategy stays reachable through the fallback loop below.
                    candidates_for_profile = ()
                else:
                    candidates_for_profile = (signal,)
            detected_type = str(getattr(detection, "auth_type", "") or "")
            requested_candidates_present = bool(candidates_for_profile)
            login: LoginResult | None = None
            registration: RegistrationResult | None = None
            for candidate_signal in candidates_for_profile[:8]:
                selected_signal = candidate_signal
                if configured_type and selected_signal.auth_type != configured_type:
                    continue
                if configured_url or configured_fields:
                    selected_signal = replace(
                        selected_signal,
                        login_url=configured_url or selected_signal.login_url,
                        login_fields={**selected_signal.login_fields, **{str(k): str(v) for k, v in configured_fields.items()}},
                    )
                login = executor.login(alias=alias, signal=selected_signal, credentials=profile)
                if login.success and login.material is not None:
                    break
            # r9 D3 (DR-017): the requested strategy failed or was not even
            # reachable — the DETECTED strategy remains reachable, and the
            # record says which type actually executed instead of silently
            # relabelling the detection.  The fallback fires ONLY when the
            # requested strategy was never ATTEMPTED (no matching signal and
            # no operator-supplied URL): an explicit configured URL that
            # fails is the honest result (the repair-recon contract — the
            # operator's own route is not second-guessed).
            if requested_candidates_present is False and (login is None or not login.success or login.material is None):
                for candidate_signal in signal_candidates[:8]:
                    if configured_type and candidate_signal.auth_type == configured_type:
                        continue
                    if configured_url or configured_fields:
                        candidate_signal = replace(
                            candidate_signal,
                            login_url=configured_url or candidate_signal.login_url,
                            login_fields={**candidate_signal.login_fields, **{str(k): str(v) for k, v in configured_fields.items()}},
                        )
                    fallback_login = executor.login(alias=alias, signal=candidate_signal, credentials=profile)
                    if fallback_login.success and fallback_login.material is not None:
                        login = fallback_login
                        break
            if login is None:
                login = LoginResult(alias, False, configured_type or detected_type or "none", configured_url or None, None, "configured_auth_type_not_detected")
            registration_url = str(profile.get("registration_url") or "").strip()
            registration_urls = tuple(url for url in (registration_url, *detection.registration_urls) if url)
            registration_allowed = bool(profile.get("register_if_unauthorized") or registration_url)
            if (
                registration_allowed
                and not login.success
                and int(login.status_code or 0) in {401, 403}
                and registration_urls
            ):
                registration = executor.register(
                    alias=alias,
                    registration_url=registration_urls[0],
                    credentials=profile,
                    field_map=profile.get("registration_fields") if isinstance(profile.get("registration_fields"), Mapping) else {},
                    extra_fields=profile.get("registration_extra") if isinstance(profile.get("registration_extra"), Mapping) else {},
                )
                if registration.success:
                    for candidate_signal in candidates_for_profile[:8]:
                        selected_signal = candidate_signal
                        if configured_type and selected_signal.auth_type != configured_type:
                            continue
                        if configured_url or configured_fields:
                            selected_signal = replace(
                                selected_signal,
                                login_url=configured_url or selected_signal.login_url,
                                login_fields={**selected_signal.login_fields, **{str(k): str(v) for k, v in configured_fields.items()}},
                            )
                        login = executor.login(alias=alias, signal=selected_signal, credentials=profile)
                        if login.success and login.material is not None:
                            login = replace(login, reason=f"registered_then_{login.reason}")
                            break
            if not login.success or login.material is None:
                results.append(ProvisionedPrincipal(
                    alias, role, profile_name, login, False, "",
                    registration is not None, bool(registration and registration.success),
                    registration.status_code if registration else None,
                    None,
                    configured_type,
                    detected_type,
                ))
                continue
            identity: IdentityDiscoveryResult | None = None
            try:
                vault_key = authority.seal_principal_credentials(
                    principal_alias=alias,
                    role=role,
                    password=login.material.m4_secret(),
                )
                # Seal alone is not evidence that the encrypted vault retained
                # material. Exercise the same M4 authorize/resolve boundary AVI
                # will use, fail-closed if the runtime key is absent, and never
                # report a principal as available on an unverified seal.
                principal_ref = PrincipalRef(
                    principal_alias=alias,
                    engagement_id=self.engagement_id,
                    target_fingerprint=_target_fingerprint(self.target_url),
                    role=PrincipalRole(role),
                )
                decision_token = authority.authorize_execution(
                    principal_ref=principal_ref,
                    tool_name="httpx_bounded",
                    target_url=f"{self.target_url}/",
                    arguments={"method": "GET", "path": "/", "role": "provisioning_check"},
                    execution_window_id=f"provision_{alias}",
                )
                verification_context = authority.resolve(principal_ref, decision_token)
                authority.destroy(verification_context)

                identity_paths = profile.get("identity_paths") if isinstance(profile.get("identity_paths"), (list, tuple)) else ()

                def _governed_identity_request(request_url: str, *, transport: str = "header", _alias=alias, _principal_ref=principal_ref) -> Any:
                    """Run one identity request after M4 has attached auth.

                    The transport variant (``header`` | ``query:<param>`` |
                    ``cookie:<name>``) is part of the extended request spec.
                    Relocation of the credential happens INSIDE this boundary
                    and uses only the material M4 attached; the caller never
                    supplies or observes credential material, so this remains
                    the single governed credential-attachment path.
                    """
                    parsed = urlsplit(str(request_url))
                    target = urlsplit(self.target_url)
                    if (
                        parsed.scheme not in {"http", "https"}
                        or parsed.hostname != target.hostname
                        or parsed.port != target.port
                    ):
                        raise ValueError("identity_request_out_of_scope")
                    normalized_transport = str(transport or "header").strip().lower()[:64] or "header"
                    path = parsed.path or "/"
                    if parsed.query:
                        path = f"{path}?{parsed.query}"
                    request_spec = {
                        "method": "GET",
                        "path": path,
                        "headers": {"Accept": "application/json"},
                    }
                    if normalized_transport != "header":
                        request_spec["identity_transport"] = normalized_transport
                    request_token = authority.authorize_execution(
                        principal_ref=_principal_ref,
                        tool_name="httpx_bounded",
                        target_url=str(request_url),
                        arguments={"method": "GET", "path": path, "transport": normalized_transport},
                        execution_window_id=f"identity_{_alias}_{sha256_text(path)[:12]}",
                    )
                    context = authority.resolve(_principal_ref, request_token)
                    marker = set_engagement_target_hosts(self.target_url)
                    try:
                        attached = authority.attach(context, request_spec)
                        headers = dict(attached.get("headers") or {})
                        final_url = str(request_url)
                        requested_transport = str(attached.get("identity_transport") or "header")
                        if requested_transport != "header":
                            relocated = _relocate_m4_credential(headers, requested_transport, final_url)
                            if relocated is None:
                                # Honest failure: the sealed material cannot
                                # ride this transport (fail-soft, recorded).
                                raise ValueError("identity_transport_not_applicable")
                            final_url, headers = relocated
                        with make_safe_httpx_client(
                            timeout=self.timeout_seconds,
                            follow_redirects=False,
                            headers={"Accept": "application/json"},
                        ) as client:
                            return client.request("GET", final_url, headers=headers)
                    finally:
                        authority.destroy(context)
                        clear_engagement_target_hosts(marker)

                # R2 wiring: the runner already holds the login artifacts.
                # Decode JWT claims from the sealed bearer material and hand
                # BOTH artifacts (claims + login response body) to the
                # discoverer for EVERY principal.  Only redacted claim data is
                # passed; the token itself never crosses this call boundary.
                login_claims: Mapping[str, Any] | None = None
                sealed_material = login.material
                if sealed_material is not None and sealed_material.kind == "bearer":
                    token_value = str(sealed_material.value or "")
                    if token_value.count(".") == 2:
                        login_claims = decode_login_jwt_claims(token_value)
                login_body = login.login_response_payload

                identity = IdentityDiscoverer(
                    target_url=self.target_url,
                    timeout_seconds=self.timeout_seconds,
                ).discover(
                    alias=alias,
                    request_callback=_governed_identity_request,
                    candidate_paths=identity_paths,
                    principal_identifier=str(profile.get("username") or profile.get("email") or ""),
                    identity_claims=login_claims,
                    login_response_body=login_body,
                    crawl_paths=crawl_routes,
                )
                key_digest = hashlib.sha256(vault_key.encode("utf-8", "replace")).hexdigest()[:16]
                results.append(ProvisionedPrincipal(
                    alias, role, profile_name, login, True, key_digest,
                    registration is not None, bool(registration and registration.success),
                    registration.status_code if registration else None,
                    identity,
                    configured_type,
                    detected_type,
                ))
            except (AttributeError, OSError, PermissionError, RuntimeError, TypeError, ValueError) as exc:
                failed = LoginResult(login.alias, False, login.auth_type, login.login_url, login.status_code, f"m4_seal_{type(exc).__name__}", material=login.material, validation_status_code=login.validation_status_code, validation_url=login.validation_url)
                results.append(ProvisionedPrincipal(
                    alias, role, profile_name, failed, False, "",
                    registration is not None, bool(registration and registration.success),
                    registration.status_code if registration else None,
                    identity,
                    configured_type,
                    detected_type,
                ))
        reason = "three_or_fewer_operator_principals_attempted"
        if len(normalized) < 2:
            reason = "fewer_than_two_operator_principals_supplied_no_identity_fabrication"
        return ProvisioningResult(detection, tuple(results), _target_fingerprint(self.target_url), reason)


__all__ = ["PrincipalProvisioner", "ProvisionedPrincipal", "ProvisioningResult"]
