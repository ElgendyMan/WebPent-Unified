# src/webpent/production/context_authority.py
"""Sprint I-2, Part 2 — M4 Context Authority (per Milestone 4 v2.1 ratified build list).

Minimal public API:
    resolve(principal_ref, decision_token) -> AuthContextRef
    attach(context_ref, request)            -> request (X-User overwritten)
    destroy(context_ref)

The vault import (webpent.auth.reauth_vault) is INTERNAL to this module and
is NEVER re-exported. Callers outside this module must go through the
ContextAuthority public API; they must not import the vault directly (enforced
by scripts/check_vault_import_authority.py, which allowlists this module).

Components:
  2.2 Decision token (M4 §3.3.5): HMAC-SHA256 over
      (tool_name, target_url_digest, arguments_digest, engagement_id,
       principal_alias, execution_window_id, timestamp, single_use_nonce);
      key from Settings.audit_secret_key; single-use nonce ledger (atomic
      insert-if-absent, engagement-scoped); DECISION_TOKEN_REPLAYED fail-closed.
  2.3 v2 vault keys (M4 §3.5.2):
      v2:<engagement>:<target_fingerprint>:<principal_alias>:<role>:<family>
      strict per-component charset [A-Za-z0-9_.-] — REJECTION never
      transformation. The legacy identity_vault_key fallback
      (reauth_vault.py:47-48) is NOT touched (deferred ruling).
  2.4 PrincipalRef / AuthContextRef minimal frozen dataclasses; lifecycle
      usable/revoked; role enum (owner/foreign-user/anonymous-control).
  2.5 Alias registry minimal: worker-side minting; intake-time collision
      validation fail-closed.
  2.6 Audit events: context.minted/resolved/attached/destroyed + denials
      write to the shared/engagement_audit.py chain with value-free payloads
      (M4 §3.3.4).
"""
from __future__ import annotations

import hashlib
import hmac
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from webpent.utils.crypto import _compute_hmac, _get_audit_key

# Vault import is INTERNAL — never re-exported. Imported lazily inside methods
# so that importing this module does not require the vault to be present, and
# so the symbol never appears in this module's public namespace.
# (Allowlisted in scripts/check_vault_import_authority.py.)


# ---------------------------------------------------------------------------
# 2.4 Role enum + PrincipalRef / AuthContextRef (frozen dataclasses)
# ---------------------------------------------------------------------------
class PrincipalRole(str, Enum):
    OWNER = "owner"
    FOREIGN_USER = "foreign-user"
    ANONYMOUS_CONTROL = "anonymous-control"


class ContextLifecycle(str, Enum):
    USABLE = "usable"
    REVOKED = "revoked"
    DESTROYED = "destroyed"


@dataclass(frozen=True)
class PrincipalRef:
    """M4 Table 3-1 core fields (minimal)."""
    principal_alias: str
    engagement_id: str
    target_fingerprint: str
    role: PrincipalRole
    lifecycle: ContextLifecycle = ContextLifecycle.USABLE

    def with_lifecycle(self, lifecycle: ContextLifecycle) -> "PrincipalRef":
        return PrincipalRef(
            principal_alias=self.principal_alias,
            engagement_id=self.engagement_id,
            target_fingerprint=self.target_fingerprint,
            role=self.role,
            lifecycle=lifecycle,
        )


@dataclass(frozen=True)
class AuthContextRef:
    """M4 Table 3-2 core fields (minimal)."""
    context_ref: str
    principal_ref: PrincipalRef
    decision_token_digest: str
    status: ContextLifecycle = ContextLifecycle.USABLE
    created_at: float = field(default_factory=time.time)
    vault_bound_alias: str | None = None

    def with_status(self, status: ContextLifecycle) -> "AuthContextRef":
        return AuthContextRef(
            context_ref=self.context_ref,
            principal_ref=self.principal_ref,
            decision_token_digest=self.decision_token_digest,
            status=status,
            created_at=self.created_at,
            vault_bound_alias=self.vault_bound_alias,
        )


# ---------------------------------------------------------------------------
# 2.3 v2 vault keys — strict charset, REJECTION never transformation
# ---------------------------------------------------------------------------
_V2_COMPONENT_CHARSET = set("abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "0123456789_.-")


class V2KeyComponentInvalid(ValueError):
    """A v2 key component contains a character outside [A-Za-z0-9_.-].
    M4 §3.5.2: REJECTION never transformation — we raise, we do not sanitize."""


def validate_v2_component(name: str, value: str) -> None:
    if not isinstance(value, str) or not value:
        raise V2KeyComponentInvalid(f"v2 key component {name!r} must be a non-empty string")
    bad = [c for c in value if c not in _V2_COMPONENT_CHARSET]
    if bad:
        raise V2KeyComponentInvalid(
            f"v2 key component {name!r}={value!r} contains forbidden character(s) "
            f"{sorted(set(bad))!r}; allowed charset is [A-Za-z0-9_.-]. "
            "Rejection, never transformation (M4 §3.5.2)."
        )


def build_v2_vault_key(*, engagement_id: str, target_fingerprint: str,
                       principal_alias: str, role: str, family: str) -> str:
    """v2:<engagement>:<target_fingerprint>:<principal_alias>:<role>:<family>

    Every component is validated against [A-Za-z0-9_.-]; any invalid component
    raises V2KeyComponentInvalid (rejection, never transformation). The literal
    "v2" prefix and the ":" separators are fixed and not subject to the
    component charset.
    """
    validate_v2_component("engagement_id", engagement_id)
    validate_v2_component("target_fingerprint", target_fingerprint)
    validate_v2_component("principal_alias", principal_alias)
    validate_v2_component("role", role)
    validate_v2_component("family", family)
    return f"v2:{engagement_id}:{target_fingerprint}:{principal_alias}:{role}:{family}"


# ---------------------------------------------------------------------------
# 2.2 Decision token + single-use nonce ledger
# ---------------------------------------------------------------------------
class DecisionTokenReplayed(RuntimeError):
    """DECISION_TOKEN_REPLAYED — a nonce was already consumed. Fail-closed."""
    error_class = "DECISION_TOKEN_REPLAYED"


class _NonceLedger:
    """Engagement-scoped single-use nonce ledger. Atomic insert-if-absent.

    In-memory (Phase-1 scope: the M4 perimeter is process-local in this
    sprint). A nonce is bound to (engagement_id, nonce); a second mint with
    the same pair raises DecisionTokenReplayed.
    """
    def __init__(self) -> None:
        self._consumed: set[tuple[str, str]] = set()
        self._lock = threading.Lock()

    def consume(self, engagement_id: str, nonce: str) -> None:
        with self._lock:
            key = (engagement_id, nonce)
            if key in self._consumed:
                raise DecisionTokenReplayed(
                    f"decision-token nonce {nonce!r} already consumed for "
                    f"engagement {engagement_id!r}"
                )
            self._consumed.add(key)

    def contains(self, engagement_id: str, nonce: str) -> bool:
        with self._lock:
            return (engagement_id, nonce) in self._consumed


_nonce_ledger = _NonceLedger()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def mint_decision_token(*, tool_name: str, target_url: str, arguments: dict[str, Any],
                        engagement_id: str, principal_alias: str,
                        execution_window_id: str) -> dict[str, Any]:
    """Mint a decision token (M4 §3.3.5).

    HMAC-SHA256 over (tool_name, target_url_digest, arguments_digest,
    engagement_id, principal_alias, execution_window_id, timestamp,
    single_use_nonce). Key from Settings.audit_secret_key (via _get_audit_key).
    The nonce is consumed atomically at mint time; re-minting with the same
    nonce is impossible because nonces are fresh uuids. Verification consumes
    the nonce a second time only if a caller replays an existing token.
    """
    timestamp = str(int(time.time()))
    nonce = uuid.uuid4().hex
    target_url_digest = _digest(target_url)
    arguments_digest = _digest(
        hashlib.sha256(
            __import__("json").dumps(arguments, sort_keys=True, default=str).encode()
        ).hexdigest()
    )
    message = "|".join([
        tool_name, target_url_digest, arguments_digest, engagement_id,
        principal_alias, execution_window_id, timestamp, nonce,
    ])
    key = _get_audit_key()
    if not key:
        # Fail-closed: no audit secret key -> no decision token.
        raise RuntimeError("audit_secret_key not configured — cannot mint decision token")
    tag = _compute_hmac(key, message.encode("utf-8"))
    token = {
        "tool_name": tool_name,
        "target_url_digest": target_url_digest,
        "arguments_digest": arguments_digest,
        "engagement_id": engagement_id,
        "principal_alias": principal_alias,
        "execution_window_id": execution_window_id,
        "timestamp": timestamp,
        "single_use_nonce": nonce,
        "hmac_tag": tag,
    }
    return token


def verify_decision_token(token: dict[str, Any]) -> bool:
    """Verify a decision token's HMAC and consume its nonce (single-use).

    Returns True only if the HMAC validates AND the nonce was not previously
    consumed. Any failure (bad HMAC, missing field, replayed nonce) raises or
    returns False — fail-closed.
    """
    required = ("tool_name", "target_url_digest", "arguments_digest",
                "engagement_id", "principal_alias", "execution_window_id",
                "timestamp", "single_use_nonce", "hmac_tag")
    if not isinstance(token, dict) or any(k not in token for k in required):
        return False
    message = "|".join([
        str(token["tool_name"]), str(token["target_url_digest"]),
        str(token["arguments_digest"]), str(token["engagement_id"]),
        str(token["principal_alias"]), str(token["execution_window_id"]),
        str(token["timestamp"]), str(token["single_use_nonce"]),
    ])
    key = _get_audit_key()
    if not key:
        return False
    expected = _compute_hmac(key, message.encode("utf-8"))
    if not hmac.compare_digest(expected, str(token["hmac_tag"])):
        return False
    # Single-use: consume the nonce. If already consumed, this raises.
    _nonce_ledger.consume(str(token["engagement_id"]), str(token["single_use_nonce"]))
    return True


# ---------------------------------------------------------------------------
# 2.5 Alias registry (minimal) — worker-side minting, collision fail-closed
# ---------------------------------------------------------------------------
class AliasCollisionError(RuntimeError):
    """Intake-time alias collision — fail-closed (M4 OQ-2)."""


class AliasRegistry:
    """Minimal alias registry. Worker-side minting for lab principals.

    An alias maps to a (engagement_id, target_fingerprint, role) triple.
    Registering the same alias twice with DIFFERENT attributes is a collision
    and raises AliasCollisionError (fail-closed). Re-registering with
    identical attributes is idempotent.
    """
    def __init__(self) -> None:
        self._aliases: dict[str, tuple[str, str, str]] = {}
        self._lock = threading.Lock()

    def mint(self, *, alias: str, engagement_id: str, target_fingerprint: str,
             role: str) -> None:
        validate_v2_component("principal_alias", alias)
        # D-RED-11 hotfix: keyed by (engagement_id, alias) — the same alias in
        # a different engagement is a DIFFERENT vault namespace (v2 key
        # includes engagement_id), so it is NOT a collision. Collision only
        # when the same alias in the SAME engagement carries different attrs.
        key = (engagement_id, alias)
        with self._lock:
            existing = self._aliases.get(key)
            new = (target_fingerprint, role)
            if existing is not None and existing != new:
                raise AliasCollisionError(
                    f"alias {alias!r} (engagement {engagement_id!r}) already "
                    f"registered with {existing!r}; cannot re-register with "
                    f"{new!r} (intake-time collision, fail-closed, M4 OQ-2)"
                )
            self._aliases[key] = new

    def resolve(self, alias: str, engagement_id: str | None = None) -> tuple[str, str, str] | None:
        with self._lock:
            if engagement_id is not None:
                val = self._aliases.get((engagement_id, alias))
                if val is not None:
                    return (engagement_id, val[0], val[1])
                return None
            # Legacy unscoped lookup: return the first matching alias (used
            # only by unit tests that mint with a single engagement).
            for (eng, al), val in self._aliases.items():
                if al == alias:
                    return (eng, val[0], val[1])
            return None


# D-RED-11 (hotfix): a process-wide shared AliasRegistry, so that aliases
# minted in one ContextAuthority instance (e.g. the lab-setup helper) are
# visible to resolve() in a different instance (e.g. the per-request
# authority constructed in _execute_real_triple). Collision validation is
# therefore process-wide, not per-instance.
_SHARED_ALIAS_REGISTRY = AliasRegistry()


def shared_alias_registry() -> AliasRegistry:
    """Return the process-wide shared alias registry."""
    return _SHARED_ALIAS_REGISTRY


# ---------------------------------------------------------------------------
# 2.6 Audit helper — value-free payloads to the shared engagement audit chain
# ---------------------------------------------------------------------------
def _audit(chain: Any, *, event_type: str, principal_alias: str | None,
           engagement_id: str, target_fingerprint: str | None,
           error_class: str | None = None,
           details: dict[str, Any] | None = None) -> None:
    """Append a value-free audit event. M4 §3.3.4: details must never contain
    secret material. We only record ids/digests/booleans/enums — never raw
    credentials, tokens, or payloads."""
    if chain is None:
        return
    safe_details = {}
    if details:
        for k, v in details.items():
            if isinstance(v, (str, int, float, bool)) or v is None:
                safe_details[k] = v
            else:
                safe_details[k] = _digest(repr(v))[:16]
    try:
        chain.append_event(
            event_type=event_type,
            principal_alias=principal_alias,
            target_fingerprint=target_fingerprint,
            error_class=error_class,
            details=safe_details,
        )
    except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
        # Audit failure must not break the fail-closed perimeter; the event
        # is simply lost (the chain's own finalization will reveal a gap).
        pass


# ---------------------------------------------------------------------------
# 2.1 Context Authority — public API
# ---------------------------------------------------------------------------
class ContextAuthority:
    """M4 Context Authority (OQ-3). The ONLY module that may import the vault.

    Public API:
        resolve(principal_ref, decision_token) -> AuthContextRef
        attach(context_ref, request)            -> request (X-User overwritten)
        destroy(context_ref)
    """

    def __init__(self, *, engagement_id: str, target_fingerprint: str,
                 audit_chain: Any = None, alias_registry: AliasRegistry | None = None) -> None:
        self.engagement_id = engagement_id
        self.target_fingerprint = target_fingerprint
        self.audit_chain = audit_chain
        # D-RED-11 (hotfix): default to the process-wide shared registry so
        # mint and resolve in different instances see the same alias set.
        self.alias_registry = alias_registry if alias_registry is not None else shared_alias_registry()
        self._contexts: dict[str, AuthContextRef] = {}
        self._lock = threading.Lock()

    # -- internal vault bridge (lazy import, never re-exported) -------------
    @staticmethod
    def _vault_seal(thread_id: str, secret: str) -> None:
        from webpent.auth.reauth_vault import seal_reauth_secret  # noqa: PLC0415
        seal_reauth_secret(thread_id, secret)

    @staticmethod
    def _vault_unseal(thread_id: str) -> str | None:
        from webpent.auth.reauth_vault import unseal_reauth_secret  # noqa: PLC0415
        return unseal_reauth_secret(thread_id)

    def seal_principal_credentials(self, *, principal_alias: str, role: str,
                                   password: str, family: str = "password") -> str:
        """Lab-setup helper: seal a principal's credentials under a v2 key.

        Uses the v2 vault key format (M4 §3.5.2). The legacy identity_vault_key
        fallback (reauth_vault.py:47-48) is NOT touched.
        """
        v2_key = build_v2_vault_key(
            engagement_id=self.engagement_id,
            target_fingerprint=self.target_fingerprint,
            principal_alias=principal_alias,
            role=role,
            family=family,
        )
        self._vault_seal(v2_key, password)
        self.alias_registry.mint(
            alias=principal_alias, engagement_id=self.engagement_id,
            target_fingerprint=self.target_fingerprint, role=role,
        )
        _audit(self.audit_chain, event_type="context.principal_sealed",
               principal_alias=principal_alias, engagement_id=self.engagement_id,
               target_fingerprint=self.target_fingerprint,
               details={"vault_key_digest": _digest(v2_key)[:16], "family": family})
        return v2_key

    # -- D-RED-5 (hotfix): authorize_execution — the SINGLE choke point ------
    # A decision token may ONLY be minted here, after the authority has
    # confirmed the principal is vault-bound and the request is in-scope.
    # _execute_real_triple must NOT call mint_decision_token directly.
    def authorize_execution(self, *, principal_ref: PrincipalRef,
                            tool_name: str, target_url: str,
                            arguments: dict[str, Any],
                            execution_window_id: str) -> dict[str, Any]:
        """Mint a decision token (the ONLY authorized minting path).

        Fail-closed: revoked principal, missing vault binding, or invalid
        v2-key component raises before any token is issued. The token is
        single-use (nonce consumed at verify time). Callers must pass the
        returned token to resolve(); a hand-rolled token (not minted here)
        is still HMAC-verifiable — but the convention enforced by
        _execute_real_triple is that only this method's output is used.
        """
        if principal_ref.lifecycle != ContextLifecycle.USABLE:
            raise RuntimeError(f"principal {principal_ref.principal_alias!r} not usable")
        # Confirm vault binding BEFORE issuing a token.
        v2_key = build_v2_vault_key(
            engagement_id=self.engagement_id,
            target_fingerprint=self.target_fingerprint,
            principal_alias=principal_ref.principal_alias,
            role=principal_ref.role.value,
            family="password",
        )
        if self._vault_unseal(v2_key) is None:
            raise RuntimeError(
                f"principal {principal_ref.principal_alias!r} not vault-bound "
                "(x_user_not_vault_bound) — no token issued"
            )
        token = mint_decision_token(
            tool_name=tool_name, target_url=target_url, arguments=arguments,
            engagement_id=self.engagement_id,
            principal_alias=principal_ref.principal_alias,
            execution_window_id=execution_window_id,
        )
        _audit(self.audit_chain, event_type="context.authorized",
               principal_alias=principal_ref.principal_alias,
               engagement_id=self.engagement_id,
               target_fingerprint=self.target_fingerprint,
               details={"execution_window_id": execution_window_id,
                        "tool_name": tool_name})
        return token

    def resolve(self, principal_ref: PrincipalRef, decision_token: dict[str, Any]) -> AuthContextRef:
        """Resolve a principal_ref + decision_token into an AuthContextRef.

        Fail-closed: revoked principal, invalid/replayed token, or missing
        vault-bound alias raises and the caller must BLOCK the row.
        """
        if principal_ref.lifecycle != ContextLifecycle.USABLE:
            _audit(self.audit_chain, event_type="context.resolve_denied",
                   principal_alias=principal_ref.principal_alias,
                   engagement_id=self.engagement_id,
                   target_fingerprint=principal_ref.target_fingerprint,
                   error_class="PRINCIPAL_NOT_USABLE",
                   details={"lifecycle": principal_ref.lifecycle.value})
            raise RuntimeError(f"principal {principal_ref.principal_alias!r} is "
                               f"{principal_ref.lifecycle.value}, not usable")
        # Verify decision token (HMAC + single-use nonce). Raises on replay.
        if not verify_decision_token(decision_token):
            _audit(self.audit_chain, event_type="context.resolve_denied",
                   principal_alias=principal_ref.principal_alias,
                   engagement_id=self.engagement_id,
                   target_fingerprint=principal_ref.target_fingerprint,
                   error_class="DECISION_TOKEN_INVALID")
            raise RuntimeError("decision token invalid — fail-closed")
        # Vault-bound alias: confirm credentials exist under the v2 key.
        v2_key = build_v2_vault_key(
            engagement_id=self.engagement_id,
            target_fingerprint=self.target_fingerprint,
            principal_alias=principal_ref.principal_alias,
            role=principal_ref.role.value,
            family="password",
        )
        vault_secret = self._vault_unseal(v2_key)
        if vault_secret is None:
            _audit(self.audit_chain, event_type="context.resolve_denied",
                   principal_alias=principal_ref.principal_alias,
                   engagement_id=self.engagement_id,
                   target_fingerprint=principal_ref.target_fingerprint,
                   error_class="VAULT_ALIAS_NOT_BOUND",
                   details={"vault_key_digest": _digest(v2_key)[:16]})
            raise RuntimeError(
                f"principal {principal_ref.principal_alias!r} has no vault-bound "
                "credentials under v2 key — x_user_not_vault_bound (B11)"
            )
        context_ref = f"ctx_{uuid.uuid4().hex[:12]}"
        ctx = AuthContextRef(
            context_ref=context_ref,
            principal_ref=principal_ref,
            decision_token_digest=_digest(repr(decision_token))[:16],
            status=ContextLifecycle.USABLE,
            vault_bound_alias=principal_ref.principal_alias,
        )
        with self._lock:
            self._contexts[context_ref] = ctx
        _audit(self.audit_chain, event_type="context.resolved",
               principal_alias=principal_ref.principal_alias,
               engagement_id=self.engagement_id,
               target_fingerprint=principal_ref.target_fingerprint,
               details={"context_ref": context_ref, "role": principal_ref.role.value})
        return ctx

    def attach(self, context_ref: AuthContextRef | str, request: dict[str, Any]) -> dict[str, Any]:
        """Attach a resolved context to a request spec.

        OVERWRITES the spec's X-User header with the vault-resolved alias.
        Caller-supplied X-User is advisory-only and is DISCARDED. The request
        dict is mutated in place (so the forged value never reaches
        _compute_identity_binding, which reads from hypothesis["requests"]).
        """
        if isinstance(context_ref, str):
            with self._lock:
                ctx = self._contexts.get(context_ref)
        else:
            ctx = context_ref
        if ctx is None or ctx.status != ContextLifecycle.USABLE:
            _audit(self.audit_chain, event_type="context.attach_denied",
                   principal_alias=None, engagement_id=self.engagement_id,
                   target_fingerprint=self.target_fingerprint,
                   error_class="CONTEXT_NOT_USABLE")
            raise RuntimeError("context not usable — cannot attach (fail-closed)")
        alias = ctx.vault_bound_alias
        if alias is None:
            raise RuntimeError("context has no vault-bound alias — fail-closed")
        headers = dict(request.get("headers") or {})
        # Discard any caller-supplied X-User (advisory-only). Overwrite with
        # the vault-resolved alias. Both casings are overwritten.
        headers.pop("X-User", None)
        headers.pop("x-user", None)
        headers["X-User"] = alias
        # Additive target-auth bridge: a lab adapter may seal a bearer token as
        # ``bearer:<token>`` or a session cookie as ``cookie:<name>=<value>``
        # under the same M4 password slot. Only M4 can unseal it; caller-
        # supplied Authorization/Cookie material is discarded before the
        # vault-bound credential is attached. Plain password secrets retain
        # the historical X-User-only behavior.
        try:
            v2_key = build_v2_vault_key(
                engagement_id=self.engagement_id,
                target_fingerprint=self.target_fingerprint,
                principal_alias=alias,
                role=ctx.principal_ref.role.value,
                family="password",
            )
            bound_secret = self._vault_unseal(v2_key)
            if isinstance(bound_secret, str) and bound_secret.startswith("bearer:"):
                bearer = bound_secret[7:].strip()
                headers.pop("Authorization", None)
                headers.pop("authorization", None)
                if bearer:
                    headers["Authorization"] = f"Bearer {bearer}"
            elif isinstance(bound_secret, str) and bound_secret.startswith("basic:"):
                basic = bound_secret[6:].strip()
                headers.pop("Authorization", None)
                headers.pop("authorization", None)
                if basic:
                    headers["Authorization"] = f"Basic {basic}"
            elif isinstance(bound_secret, str) and bound_secret.startswith("api-key:"):
                key = bound_secret[8:].strip()
                header_name, separator, header_value = key.partition("=")
                if separator and header_name.strip() and header_value.strip():
                    headers.pop(header_name.strip(), None)
                    headers.pop(header_name.strip().lower(), None)
                    headers[header_name.strip()] = header_value.strip()
            elif isinstance(bound_secret, str) and bound_secret.startswith("cookie:"):
                cookie = bound_secret[7:].strip().split(";", 1)[0]
                cookie_name, separator, cookie_value = cookie.partition("=")
                if separator and cookie_name.strip() and cookie_value.strip():
                    headers.pop("Authorization", None)
                    headers.pop("authorization", None)
                    headers.pop("Cookie", None)
                    headers.pop("cookie", None)
                    headers["Cookie"] = f"{cookie_name.strip()}={cookie_value.strip()}"
        except (AttributeError, KeyError, OSError, PermissionError, RuntimeError, TypeError, ValueError):
            # The ordinary X-User path remains valid for non-bearer lab
            # principals; failed optional enrichment never bypasses M4.
            pass
        request["headers"] = headers
        request["_m4_context_ref"] = ctx.context_ref
        request["_m4_vault_bound"] = True
        _audit(self.audit_chain, event_type="context.attached",
               principal_alias=alias, engagement_id=self.engagement_id,
               target_fingerprint=self.target_fingerprint,
               details={"context_ref": ctx.context_ref,
                        "caller_x_user_discarded": True})
        return request

    def destroy(self, context_ref: AuthContextRef | str) -> None:
        """Destroy a context (revoke lifecycle). Idempotent."""
        if isinstance(context_ref, AuthContextRef):
            ref = context_ref.context_ref
        else:
            ref = context_ref
        with self._lock:
            ctx = self._contexts.get(ref)
            if ctx is not None:
                self._contexts[ref] = ctx.with_status(ContextLifecycle.DESTROYED)
        _audit(self.audit_chain, event_type="context.destroyed",
               principal_alias=ctx.principal_ref.principal_alias if ctx else None,
               engagement_id=self.engagement_id,
               target_fingerprint=self.target_fingerprint,
               details={"context_ref": ref})


__all__ = [
    "PrincipalRole", "ContextLifecycle", "PrincipalRef", "AuthContextRef",
    "V2KeyComponentInvalid", "validate_v2_component", "build_v2_vault_key",
    "DecisionTokenReplayed", "mint_decision_token", "verify_decision_token",
    "AliasCollisionError", "AliasRegistry", "shared_alias_registry",
    "ContextAuthority",
]
