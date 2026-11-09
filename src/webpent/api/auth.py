# src/webpent/api/auth.py
"""webpent.api.auth

V6 — JWT-based authentication + Role-Based Access Control (RBAC).

V6.1 Changes:
  - bcrypt 72-byte limit: wrapped in try/except ValueError, log + skip.
  - Password parsing: split(":",1) + rsplit(":",1) handles colons in passwords.
  - Lazy-load _DEFAULT_ADMIN: no bcrypt hash at import time (~300ms saved).
  - auth_enabled toggle: when False, bypass JWT entirely.
"""

from __future__ import annotations

import logging
import os
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel

from webpent.config.settings import get_settings

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    auto_error=False,
)

_DEFAULT_TOKEN_EXPIRE_MINUTES = 60


@dataclass
class User:
    username: str
    hashed_password: str
    role: str
    token_version: int = 1
    tenant_id: str | None = None
    is_global_admin: bool = False


@dataclass
class TokenData:
    username: str
    role: str
    exp: datetime
    jti: str
    token_version: int


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = _DEFAULT_TOKEN_EXPIRE_MINUTES * 60
    role: str


# V6.1: Lazy-loaded default admin — no bcrypt hash at import time.
_DEFAULT_ADMIN: User | None = None
_USERS: dict[str, User] = {}

# V9 P1 RE-2/RE-3: thread-safe seeding with double-checked locking.
_SEED_LOCK = threading.Lock()
_SEED_ATTEMPTED = False
_TOKEN_VERSION_LOCK = threading.Lock()
_TOKEN_VERSIONS: dict[str, int] = {}


def _configured_global_admins() -> set[str]:
    """Return explicitly configured global administrators."""
    return {
        username.strip()
        for username in os.environ.get("WEBPENT_GLOBAL_ADMINS", "").split(",")
        if username.strip()
    }


def _configured_user_tenants() -> dict[str, str]:
    """Parse ``WEBPENT_USER_TENANTS=user=tenant,...`` safely."""
    mappings: dict[str, str] = {}
    for entry in os.environ.get("WEBPENT_USER_TENANTS", "").split(","):
        entry = entry.strip()
        if not entry or "=" not in entry:
            continue
        username, tenant_id = (part.strip() for part in entry.split("=", 1))
        if (
            username
            and tenant_id
            and "\r" not in username + tenant_id
            and "\n" not in username + tenant_id
        ):
            mappings[username] = tenant_id
    return mappings


def _user_scope(username: str, role: str) -> tuple[str | None, bool]:
    """Resolve tenant scope while preserving legacy admin behavior.

    An explicit tenant mapping always makes an admin tenant-scoped. A user
    listed in ``WEBPENT_GLOBAL_ADMINS`` or using the ``global_admin`` role is
    global. Legacy admins without either mapping remain global for backwards
    compatibility; new deployments should configure one of the explicit
    variables.
    """
    tenants = _configured_user_tenants()
    tenant_id = tenants.get(username)
    normalized_role = role.lower()
    is_global_admin = normalized_role == "global_admin" or username in _configured_global_admins()
    if normalized_role == "admin" and tenant_id is None and username not in tenants:
        is_global_admin = True
    return tenant_id, is_global_admin


def _safe_hash_password(password: str) -> str | None:
    """Hash a password with bcrypt, handling the 72-byte limit.

    V6.1 P0: bcrypt raises ValueError if the password exceeds 72 bytes.
    We catch it, log an error, and return None instead of crashing.
    """
    pw_bytes = password.encode("utf-8")
    try:
        return bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")
    except ValueError:
        logger.error(
            "Password for user exceeds 72-byte bcrypt limit (%d bytes). "
            "User will be skipped. Use a shorter password.",
            len(pw_bytes),
        )
        return None


def _safe_check_password(password: str, hashed: str) -> bool:
    """Verify a password against a hash, handling the 72-byte limit.

    V6.1 P0: Returns False if the password exceeds 72 bytes instead
    of crashing with ValueError.
    """
    pw_bytes = password.encode("utf-8")
    try:
        return bcrypt.checkpw(pw_bytes, hashed.encode("utf-8"))
    except ValueError:
        logger.error("Password exceeds 72-byte bcrypt limit during verification. Rejecting login.")
        return False


def _get_default_admin() -> User:
    """V6 Absolute-Flawless P0 FIX (CISO audit): No hardcoded fallback.

    Previously this function would, if the runtime bcrypt hash of
    ``"admin"`` failed for any reason, fall back to a hardcoded
    pre-computed bcrypt hash string. That hash was a constant in the
    source tree — anyone with read access to the repository (or to a
    Docker image layer) could authenticate as ``admin`` with the
    known password ``admin``, bypassing the entire auth layer. This
    is a textbook auth-bypass via hardcoded credential.

    The fallback is now removed. If the runtime bcrypt hash fails
    (e.g. bcrypt is broken, FIPS mode disallows the cost factor, etc.)
    we fail SECURELY by raising ``ValueError`` — the caller surfaces
    this as a 500 to the client and the operator must fix the
    environment. We never authenticate with a known hash.
    """
    global _DEFAULT_ADMIN
    if _DEFAULT_ADMIN is None:
        # V6 Absolute-Flawless: ADMIN_PASSWORD env var is REQUIRED.
        # There is no default password. The previous implementation
        # silently created an admin/admin user when WEBPENT_USERS was
        # unset — see _seed_users_from_env for the matching fix.
        admin_password = os.environ.get("ADMIN_PASSWORD")
        if not admin_password:
            raise RuntimeError(
                "Missing ADMIN_PASSWORD environment variable. The auth "
                "module refuses to provision a default admin user with a "
                "known password. Set ADMIN_PASSWORD to a strong secret "
                "before enabling auth_enabled=true."
            )
        hashed = _safe_hash_password(admin_password)
        if hashed is None:
            # bcrypt rejected the password (e.g. >72 bytes). Fail secure.
            raise ValueError(
                "ADMIN_PASSWORD could not be hashed with bcrypt (likely "
                "exceeds the 72-byte limit). Use a shorter password."
            )
        _DEFAULT_ADMIN = User(
            username="admin",
            hashed_password=hashed,
            role="admin",
        )
    return _DEFAULT_ADMIN


def _seed_users_from_env() -> None:
    """Populate the user store from WEBPENT_USERS env var.

    V6.1 P1: Fixed password parsing to handle colons within passwords.
    Uses split(":", 1) for username, then rsplit(":", 1) for password:role.
    Format: "username:password:role,username2:pass:with:colons:role2"

    V6 Absolute-Flawless P0 FIX (CISO audit): The previous code, when
    WEBPENT_USERS was unset, silently created an ``admin`` user with
    the password ``admin`` — a default credential that allowed
    unauthenticated attackers to log in as soon as ``auth_enabled``
    was flipped to True. This is a textbook default-credential
    vulnerability (CWE-798).

    The fallback is now removed. If WEBPENT_USERS is unset, the
    function falls back to ``_get_default_admin()``, which itself
    requires ``ADMIN_PASSWORD`` to be set in the environment —
    failure to provide it raises ``RuntimeError`` rather than
    provisioning an insecure default. There is no path through this
    code that produces a known-credential user.
    """
    if _USERS:
        return

    raw = os.environ.get("WEBPENT_USERS", "")
    if raw:
        for entry in raw.split(","):
            entry = entry.strip()
            if not entry or ":" not in entry:
                continue
            # V6.1 P1: split username first, then rsplit role from the rest.
            # This allows passwords to contain colons.
            try:
                username, rest = entry.split(":", 1)
                password, role = rest.rsplit(":", 1)
            except ValueError:
                logger.warning("Skipping malformed WEBPENT_USERS entry: %s", entry[:50])
                continue

            # M1-A (H-2): .env.example ships "CHANGE-ME:CHANGE-ME:admin".
            # An operator who copies it verbatim would seed an admin whose
            # credentials are repo-readable — a full compromise dressed as
            # a hardened deployment. Refuse placeholder-credential entries
            # (fail-closed: the user simply does not exist).
            if (
                username.strip().upper().startswith("CHANGE-ME")
                or password.strip().upper().startswith("CHANGE-ME")
            ):
                logger.error(
                    "REFUSED placeholder WEBPENT_USERS entry %r — username or "
                    "password is still the .env.example CHANGE-ME placeholder. "
                    "Generate real credentials (M1-A/H-2).",
                    username[:50],
                )
                continue

            # V6.1 P0: Safe hash with 72-byte limit handling.
            hashed = _safe_hash_password(password)
            if hashed is None:
                continue  # Skip users with passwords too long for bcrypt

            normalized_role = role.lower()
            tenant_id, is_global_admin = _user_scope(username, normalized_role)
            _USERS[username] = User(
                username=username,
                hashed_password=hashed,
                role="admin" if normalized_role == "global_admin" else normalized_role,
                tenant_id=tenant_id,
                is_global_admin=is_global_admin,
            )
        logger.info("Seeded %d user(s) from WEBPENT_USERS", len(_USERS))
    else:
        # V6 Absolute-Flawless: No default admin/admin. Delegate to
        # _get_default_admin(), which requires ADMIN_PASSWORD to be
        # set in the environment and raises RuntimeError otherwise.
        # We never log a "default password: admin" warning again.
        default_admin = _get_default_admin()
        tenant_id, is_global_admin = _user_scope(default_admin.username, default_admin.role)
        default_admin.tenant_id = tenant_id
        default_admin.is_global_admin = is_global_admin
        _USERS["admin"] = default_admin
        logger.info(
            "WEBPENT_USERS not set — provisioned admin user from "
            "ADMIN_PASSWORD env var (no default password)."
        )


# V6.1: Defer seeding to first access (not at import time).
# _seed_users_from_env() is called lazily by get_current_user / login.


def _ensure_seeded() -> None:
    """Ensure the user store is populated (lazy init).

    V9 P1 RE-2/RE-3: Thread-safe double-checked locking. Prevents
    concurrent requests from racing on _seed_users_from_env(). Also
    tracks _SEED_ATTEMPTED so a failed seed doesn't retry forever.
    """
    global _SEED_ATTEMPTED
    if _USERS:
        return
    if _SEED_ATTEMPTED:
        return
    with _SEED_LOCK:
        if _USERS:
            return
        if _SEED_ATTEMPTED:
            return
        _SEED_ATTEMPTED = True
        try:
            _seed_users_from_env()
        except Exception as exc:
            logger.error(
                "User store seeding FAILED: %s. All authenticated "
                "requests will return 401 until the configuration is "
                "fixed and the service is restarted.",
                exc,
            )


def _create_access_token(data: dict[str, Any], expires_delta: timedelta | None = None) -> str:
    settings = get_settings()
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.jwt_expire_minutes)
    )
    now = datetime.now(timezone.utc)
    to_encode.update(
        {
            "exp": expire,
            "iat": now,
            "nbf": now,
            "jti": to_encode.get("jti") or secrets.token_urlsafe(24),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
        }
    )

    try:
        from jose import jwt
    except ImportError:
        jwt = None
    if jwt is not None:
        return jwt.encode(
            to_encode,
            settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
            headers={"typ": "JWT"},
        )
    try:
        import jwt as pyjwt
    except ImportError as exc:  # pragma: no cover - pyjwt is a declared dependency
        raise RuntimeError(
            "JWT token issuance requires the 'pyjwt' package (or 'python-jose'). "
            "Both are missing from the environment; pyjwt is declared in pyproject."
        ) from exc
    return pyjwt.encode(
        to_encode,
        settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
        headers={"typ": "JWT"},
    )


def _get_shared_token_version(username: str) -> int:
    """Read the authoritative token version from the shared database."""
    from webpent.memory.db import get_db_manager

    shared_version = get_db_manager().get_token_version(username)
    with _TOKEN_VERSION_LOCK:
        cached_version = _TOKEN_VERSIONS.get(username, 1)
        current_version = max(cached_version, shared_version)
        _TOKEN_VERSIONS[username] = current_version
    return current_version


def _decode_access_token(token: str) -> TokenData:
    settings = get_settings()
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    # V9 P1 RE-4: Surface missing JWT library as 500, not 401.
    try:
        try:
            from jose import jwt as jose_jwt

            payload = jose_jwt.decode(
                token,
                settings.jwt_secret_key,
                algorithms=[settings.jwt_algorithm],
                issuer=settings.jwt_issuer,
                audience=settings.jwt_audience,
                options={"require_iat": True, "require_nbf": True, "require_jti": True},
            )
        except ImportError:
            try:
                import jwt as pyjwt

                payload = pyjwt.decode(
                    token,
                    settings.jwt_secret_key,
                    algorithms=[settings.jwt_algorithm],
                    issuer=settings.jwt_issuer,
                    audience=settings.jwt_audience,
                    options={"require": ["iat", "nbf", "jti"]},
                )
            except ImportError:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="No JWT library installed. Install 'python-jose' or 'PyJWT'.",
                ) from None
        username: str = payload.get("sub", "")
        role: str = payload.get("role", "")
        exp = payload.get("exp")
        jti = payload.get("jti", "")
        token_version = int(payload.get("ver", 0))
        if not username or not role or not jti or token_version < 1:
            raise credentials_exception
        exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc) if exp else datetime.now(timezone.utc)
        current_version = _get_shared_token_version(username)
        if token_version != current_version:
            raise credentials_exception
        return TokenData(
            username=username,
            role=role,
            exp=exp_dt,
            jti=jti,
            token_version=token_version,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise credentials_exception from exc


def revoke_user_tokens(username: str) -> None:
    """Atomically invalidate all tokens for ``username`` across workers."""
    from webpent.memory.db import get_db_manager

    next_version = get_db_manager().bump_token_version(username)
    with _TOKEN_VERSION_LOCK:
        _TOKEN_VERSIONS[username] = next_version


_DUMMY_BCRYPT_HASH: str | None = None


def _dummy_password_check(password: str) -> bool:
    """P2-04 (0.33.0): burn the same bcrypt cost for unknown usernames.

    ``authenticate_user`` used to return immediately for unknown users
    while existing users paid a ~100-300 ms bcrypt verify — a reliable
    username-enumeration oracle on POST /token. The dummy hash is
    generated lazily once; its plaintext is meaningless and is NOT a
    credential (nothing authenticates against it).
    """
    global _DUMMY_BCRYPT_HASH
    if _DUMMY_BCRYPT_HASH is None:
        _DUMMY_BCRYPT_HASH = bcrypt.hashpw(
            b"webpent-unknown-user-timing-equalizer",
            bcrypt.gensalt(),
        ).decode("utf-8")
    return _safe_check_password(password, _DUMMY_BCRYPT_HASH)


def authenticate_user(username: str, password: str) -> User | None:
    """Verify username + password using bcrypt directly.

    V6.1 P0: Wrapped in _safe_check_password to handle 72-byte limit.
    P2-04 (0.33.0): unknown usernames now pay the same bcrypt cost as
    existing ones (timing side-channel closed).
    """
    _ensure_seeded()
    user = _USERS.get(username)
    if user is None:
        _dummy_password_check(password)  # timing equalizer — result ignored
        return None
    if not _safe_check_password(password, user.hashed_password):
        return None
    return user


def get_current_user(token: str | None = Depends(oauth2_scheme)) -> User:
    """FastAPI dependency: validate JWT OR bypass if auth_enabled=False.

    V6 Titanium P1 FIX (CISO audit — Broken Dev Mode):
        The previous implementation called ``_get_default_admin()``
        even when ``auth_enabled=False``. The Absolute-Flawless fix
        made ``_get_default_admin`` raise ``RuntimeError`` when
        ``ADMIN_PASSWORD`` was unset — which is the correct secure
        behaviour for production (auth_enabled=True). But in dev
        mode (auth_enabled=False), the operator deliberately turned
        auth OFF, so requiring ``ADMIN_PASSWORD`` defeats the
        purpose of the dev toggle: every dev-mode startup without
        ``ADMIN_PASSWORD`` set would crash with ``RuntimeError:
        Missing ADMIN_PASSWORD``, breaking ``docker-compose.dev.yml``
        and the local-dev quick-start.

        The fix: when ``auth_enabled=False``, return a stub admin
        User immediately — without calling ``_get_default_admin()``
        and without seeding the user store. The stub has an empty
        ``hashed_password`` because no password is ever checked
        (auth is disabled). The role is ``"admin"`` so
        ``require_admin`` / ``require_role`` dependencies pass
        through. The stub is constructed inline (no global state,
        no env-var lookup) so dev mode starts up cleanly even with
        a minimal ``.env``.
    """
    settings = get_settings()

    if not settings.auth_enabled:
        # V6 Titanium P1: dev mode — bypass auth entirely. Return a
        # stub admin User with an empty password hash. No env-var
        # lookup, no seeding, no RuntimeError. The empty hash is
        # never checked because auth is disabled; if auth is later
        # re-enabled at runtime (rare), the next request will hit
        # the ``settings.auth_enabled`` check again and fall through
        # to the real auth path, which WILL require a valid token.
        return User(
            username="admin",
            hashed_password="",
            role="admin",
            is_global_admin=True,
        )

    _ensure_seeded()

    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_data = _decode_access_token(token)
    user = _USERS.get(token_data.username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_role(*allowed_roles: str):
    """FastAPI dependency factory: require one of ``allowed_roles``."""

    def _check(user: User = Depends(get_current_user)) -> User:  # noqa: B008
        settings = get_settings()
        if not settings.auth_enabled:
            return user
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"Insufficient permissions: requires one of "
                    f"{list(allowed_roles)}, user has role '{user.role}'"
                ),
            )
        return user

    return _check


def require_admin(user: User = Depends(get_current_user)) -> User:  # noqa: B008
    if not get_settings().auth_enabled:
        return user
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


def require_viewer(user: User = Depends(get_current_user)) -> User:  # noqa: B008
    if not get_settings().auth_enabled:
        return user
    if user.role not in ("admin", "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Viewer access required",
        )
    return user


def login_for_access_token(
    form_data: OAuth2PasswordRequestForm,
) -> TokenResponse:
    """POST /token handler — OAuth2 password flow."""
    settings = get_settings()

    if not settings.auth_enabled:
        # Auth-off is a loopback-only development mode. It must never mint a
        # reusable signed admin token that could escape that boundary.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token endpoint is disabled while authentication is disabled",
        )

    user = authenticate_user(form_data.username, form_data.password)
    if user is None:
        # POST-P0 Phase 9: durable login-failure audit (identifier only;
        # never the attempted password or any secret material).
        from webpent.memory.decision_log import log_operator_event

        log_operator_event(
            action="login",
            actor=form_data.username,
            outcome="failed",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # POST-P0 Phase 9: durable login-success audit.
    from webpent.memory.decision_log import log_operator_event

    log_operator_event(
        action="login",
        actor=user.username,
        outcome="success",
        metadata={"role": str(user.role)[:40]},
    )
    access_token = _create_access_token(
        data={
            "sub": user.username,
            "role": user.role,
            "ver": _get_shared_token_version(user.username),
        }
    )
    return TokenResponse(
        access_token=access_token,
        role=user.role,
        expires_in=settings.jwt_expire_minutes * 60,
    )
