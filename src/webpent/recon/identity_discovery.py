"""Generic authenticated identity and resource-ID discovery.

The discoverer runs only after an operator-authorized login. It uses the same
safe HTTP factory and same-origin scope as login execution. Runtime IDs remain
in memory for governed request construction; serialized evidence contains only
bounded IDs, sources, and structural resource templates.

Identity resolution strategy ladder (general, autonomous, target-agnostic):

  S1 LOGIN ARTIFACT MINING (zero network): decode the login token when it is a
     JWT and mine the login response body the runner already received at login,
     pairing id-like scalars with email-shaped scalars.  Email-matched pairs
     (owner-bound) are preferred over bare id-like values.
  S2 SELF-ENDPOINT PROBE: ordered candidates are the profile wiring hint (if
     any), then the convention list loaded from the config data file, then
     self-action-shaped paths already discovered by recon/crawler.  Same-origin
     enforcement is kept.
  S3 ANONYMOUS-SHAPE SELF-HEAL: a 2xx JSON body whose shape has no id-like or
     email-like scalar is classified ``anonymous_shape_or_transport_mismatch``
     and the same path is autonomously retried across transport variants
     (query-param token, cookie).  Variants run INSIDE the governed M4 request
     boundary: the callback only relocates credential material that M4 itself
     attached; this class never sees or transports credentials.
  S4 HONEST EXHAUSTION: halt only after S1-S3 are exhausted, with reason
     ``identity_resolution_exhausted`` plus per-strategy structured attempts.
     Unverified candidates are reported as inconclusive, never as discovered;
     no identity is ever fabricated.

The request callback remains the ONLY auth path.  This class is deliberately
not allowed to receive LoginMaterial or attach Authorization/Cookie/API-key
values.  The callback must already be backed by M4 authorize -> resolve ->
attach and may return only a safe HTTP response.  An OPTIONAL ``transport``
keyword may be accepted by the callback so the governed boundary can relocate
its own M4-attached material; supplying it is additive and never bypasses M4.
"""
from __future__ import annotations

import base64
import hashlib
import inspect
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import quote, urljoin, urlsplit

from webpent.config.identity_vocab import load_identity_vocab

_SELF_ACTIONS_FALLBACK = {"dashboard", "me", "current", "profile", "details", "self", "account", "whoami"}

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_ID_KEY_SUFFIX_RE = re.compile(r"(?:^|_)(?:id|uid|no|number|num)$", re.I)

ANONYMOUS_SHAPE_OUTCOME = "anonymous_shape_or_transport_mismatch"
EXHAUSTED_REASON = "identity_resolution_exhausted"

S1_STRATEGY = "s1_login_artifact_mining"
S2_STRATEGY = "s2_self_endpoint_probe"
S3_STRATEGY = "s3_transport_self_heal"

# r6c contract (tests/test_identity_ladder_r6.py): the S1 stage runs TWO
# branches and each branch owns its winner name in ``winner_strategy``.
S1_JWT_BRANCH = "jwt_claims"
S1_BODY_BRANCH = "login_body"
S1_JWT_WINNER = "s1_jwt_claims"
S1_BODY_MATCHED_WINNER = "s1_login_body_mining"
S1_BODY_BARE_WINNER = S1_STRATEGY

# Probe-window bounds (r6c): the hint source may consume at most 8 slots and
# the whole S2 ladder probes at most 16 paths; attempt records are capped so
# honest exhaustion can never serialize unbounded traffic.
_MAX_PROBE_WINDOW = 16
_MAX_HINT_PATHS = 8
_MAX_ATTEMPT_RECORDS = 48
_MAX_SERIALIZED_ATTEMPTS = 32


def _bounded(value: Any, limit: int = 160) -> str:
    return str(value)[:limit]


def _safe_json(response: Any) -> Any:
    try:
        value = response.json()
    except Exception:
        return None
    return value


def _is_email_value(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    return 3 <= len(text) <= 254 and bool(_EMAIL_RE.match(text))


def _is_id_like_value(value: Any) -> bool:
    """Value-shape test for identifiers: numeric, UUID, or digit-bearing slug."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return 0 < value < 10**19
    if isinstance(value, str):
        text = value.strip()
        if not text or len(text) > 128 or _is_email_value(text):
            return False
        if text.isdigit() and len(text) <= 19:
            return True
        if _UUID_RE.match(text):
            return True
        return bool(re.fullmatch(r"[A-Za-z0-9_.:-]{2,64}", text) and any(ch.isdigit() for ch in text))
    return False


def _is_id_like_key(lowered: str, vocab: Mapping[str, Any]) -> bool:
    """Key-shape test: exact user-identity keys, short forms, and suffixes."""
    if lowered in set(vocab.get("negative_id_keys", ())):
        return False
    if lowered in set(vocab.get("user_identity_keys", ())) or lowered == "id":
        return True
    if lowered in set(vocab.get("id_key_short_forms", ())):
        return True
    suffixes = tuple(str(item).lower() for item in vocab.get("id_key_suffixes", ()))
    return bool(suffixes) and lowered.endswith(suffixes)


def _is_user_identity_key(lowered: str, vocab: Mapping[str, Any]) -> bool:
    return lowered in set(vocab.get("user_identity_keys", ())) or lowered == "id"


def _shape(value: Any, depth: int = 0) -> Any:
    """Structural projection with all values replaced by type names."""
    if depth > 6:
        return "..."
    if isinstance(value, Mapping):
        return {str(key)[:64]: _shape(item, depth + 1) for key, item in list(value.items())[:32]}
    if isinstance(value, list):
        return [_shape(value[0], depth + 1)] if value else []
    return type(value).__name__


def _shape_hash(value: Any) -> str:
    try:
        canonical = json.dumps(_shape(value), sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        canonical = type(value).__name__
    return hashlib.sha256(canonical.encode("utf-8", "replace")).hexdigest()[:16]


def _walk_identity(
    value: Any,
    *,
    vocab: Mapping[str, Any] | None = None,
    path: str = "",
) -> tuple[str | None, str | None, dict[str, str]]:
    """Find a user identity and small scalar resource-ID projection.

    Key vocabularies are value-shape driven: exact user-identity keys (including
    camelCase folded via lower()), short forms such as ``bid``/``uid``, and
    keys ending in id/uid/no/number (snake or camel).  Email-shaped scalars are
    never returned as identifiers; they serve as owner-matching signals.
    """
    active_vocab = vocab if vocab is not None else load_identity_vocab()
    user_id: str | None = None
    source_key: str | None = None
    resources: dict[str, str] = {}
    if isinstance(value, Mapping):
        for raw_key, item in list(value.items())[:64]:
            key = str(raw_key)
            lowered = key.lower().replace("-", "_")
            if isinstance(item, (str, int)) and str(item).strip() and not _is_email_value(item):
                scalar = _bounded(item)
                if _is_user_identity_key(lowered, active_vocab) and user_id is None:
                    user_id, source_key = scalar, key
                elif _is_id_like_value(item) and _is_id_like_key(lowered, active_vocab) and len(resources) < 16:
                    resources[key[:96]] = scalar
                elif _is_user_identity_key(lowered, active_vocab) and len(resources) < 16:
                    resources[f"{path}.{key}"[-96:]] = scalar
            nested_id, nested_source, nested_resources = _walk_identity(item, vocab=active_vocab, path=f"{path}.{key}")
            if user_id is None and nested_id is not None:
                user_id, source_key = nested_id, nested_source
            for nested_key, nested_value in nested_resources.items():
                if len(resources) < 16:
                    resources[nested_key] = nested_value
    elif isinstance(value, list):
        for item in value[:16]:
            nested_id, nested_source, nested_resources = _walk_identity(item, vocab=active_vocab, path=path)
            if user_id is None and nested_id is not None:
                user_id, source_key = nested_id, nested_source
            for nested_key, nested_value in nested_resources.items():
                if len(resources) < 16:
                    resources[nested_key] = nested_value
    return user_id, source_key, resources


def _has_identity_scalars(value: Any, *, vocab: Mapping[str, Any] | None = None) -> bool:
    """True when any scalar looks like an identifier or an email address."""
    active_vocab = vocab if vocab is not None else load_identity_vocab()
    if isinstance(value, Mapping):
        for raw_key, item in list(value.items())[:64]:
            lowered = str(raw_key).lower().replace("-", "_")
            if isinstance(item, (str, int)) and str(item).strip():
                if _is_email_value(item):
                    return True
                if _is_id_like_value(item) and _is_id_like_key(lowered, active_vocab):
                    return True
            if _has_identity_scalars(item, vocab=active_vocab):
                return True
    elif isinstance(value, list):
        return any(_has_identity_scalars(item, vocab=active_vocab) for item in value[:16])
    return False


def _find_matching_identity(value: Any, identifier: str) -> tuple[str | None, str | None]:
    """Find an ID from a record whose email/username/email-shaped value matches."""
    wanted = str(identifier or "").strip().lower()
    if not wanted:
        return None, None
    if isinstance(value, Mapping):
        fields = {str(key).lower().replace("-", "_"): item for key, item in value.items()}
        matching = any(
            isinstance(item, (str, int)) and str(item).strip().lower() == wanted
            for key, item in fields.items()
            if key in {"email", "username", "user_name", "login", "mail", "useremail", "user_email", "emailaddress", "email_address"}
            or _is_email_value(item)
        )
        if matching:
            for key, item in value.items():
                lowered = str(key).lower().replace("-", "_")
                if _is_user_identity_key(lowered, load_identity_vocab()) and isinstance(item, (str, int)) and str(item).strip() and not _is_email_value(item):
                    return _bounded(item), str(key)
        for item in list(value.values())[:64]:
            found = _find_matching_identity(item, wanted)
            if found[0] is not None:
                return found
    elif isinstance(value, list):
        for item in value[:32]:
            found = _find_matching_identity(item, wanted)
            if found[0] is not None:
                return found
    return None, None


def _bounded_artifact(value: Any, *, depth: int, max_depth: int, budget: list[int]) -> Any:
    """Bound a login artifact for in-memory mining only (never serialized)."""
    if budget[0] <= 0 or depth > max_depth:
        return None
    budget[0] -= 1
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for raw_key, item in list(value.items())[:32]:
            key = str(raw_key)[:128]
            if isinstance(item, (str, int, bool)) or item is None:
                if isinstance(item, str) and len(item) > 512:
                    item = item[:512]
                output[key] = item
                budget[0] -= 1
            else:
                output[key] = _bounded_artifact(item, depth=depth + 1, max_depth=max_depth, budget=budget)
        return output
    if isinstance(value, list):
        return [_bounded_artifact(item, depth=depth + 1, max_depth=max_depth, budget=budget) for item in value[:16]]
    if isinstance(value, str) and len(value) > 512:
        return value[:512]
    return value if isinstance(value, (str, int, bool, float)) or value is None else None


@dataclass(frozen=True)
class _ArtifactCandidate:
    user_id: str
    source_field: str
    source_url: str
    reason: str
    confidence: str  # "high" | "medium"
    owner_matched: bool
    position: int
    branch: str = S1_BODY_BRANCH  # "jwt_claims" | "login_body"
    resources: tuple[tuple[str, str], ...] = ()


class _ArtifactMiningOutcome:
    """Ranked S1 candidates plus structured attempt entries (value-free)."""

    def __init__(self) -> None:
        self.candidates: list[_ArtifactCandidate] = []
        self.attempts: list[dict[str, Any]] = []
        self.body_seeds: dict[str, str] = {}
        self.body_email_matched_identity_key = False

    def best(self) -> _ArtifactCandidate | None:
        if not self.candidates:
            return None
        rank = {"high": 2, "medium": 1}
        # Branch precedence first (r6c test_attempt_records_never_carry_mined_values:
        # the jwt branch resolves before the body branch), then confidence,
        # then owner matching, then discovery position.
        self.candidates.sort(
            key=lambda item: (
                0 if item.branch == S1_JWT_BRANCH else 1,
                -(rank.get(item.confidence, 0)),
                -(1 if item.owner_matched else 0),
                item.position,
            )
        )
        return self.candidates[0]


def _decode_jwt_claims(token: str) -> Mapping[str, Any] | None:
    parts = str(token).split(".")
    if len(parts) != 3:
        return None
    try:
        raw = base64.urlsafe_b64decode(parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4))
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, Mapping) else None


def decode_login_jwt_claims(token: str) -> Mapping[str, Any] | None:
    """Public generic helper: decode JWT claims from a login token for mining.

    Returns only claim data (never the token itself) so callers can feed
    ``identity_claims`` without exposing credential material to the
    discoverer.  Signature is NOT verified: claims are mining hints, not auth.
    """
    return _decode_jwt_claims(token)


# UNIFIED MERGE (2026-11-02): public alias restored per the v15.2 R6
# contract (tests/test_identity_ladder_r6.py::
# test_decode_jwt_claims_public_alias_works). Same decoder, public name.
decode_jwt_claims = _decode_jwt_claims


def _payload_type_name(body: Any) -> str:
    """r6c branch record vocabulary for the login-body shape."""
    if body is None:
        return "absent"
    if isinstance(body, Mapping):
        return "mapping" if body else "absent"
    if isinstance(body, list):
        return "list" if body else "absent"
    return "scalar"


def _mine_login_artifacts(
    identity_claims: Mapping[str, Any] | None,
    login_response_body: Any,
    principal_identifier: str | None,
    vocab: Mapping[str, Any],
) -> _ArtifactMiningOutcome:
    """S1: pair id-like scalars with email-shaped scalars in login artifacts.

    r6c contract: the stage records ONE attempt entry per BRANCH in
    ``attempts`` (jwt_claims — attempted only when claims are supplied;
    login_body — always attempted, with payload_type and resource-seed
    names), while ``strategy_attempts`` keeps the historical per-strategy
    entries for the rollup surfaces.
    """
    outcome = _ArtifactMiningOutcome()
    position = 0
    wanted = str(principal_identifier or "").strip().lower()

    # ---- branch A: jwt claims ------------------------------------------
    claims_supplied = isinstance(identity_claims, Mapping) and bool(identity_claims)
    claim_id: str | None = None
    claim_field: str | None = None
    claim_email: str | None = None
    if claims_supplied:
        claim_keys = [str(key) for key in vocab.get("identity_claim_keys", ())]
        email_keys = {str(key).lower() for key in vocab.get("email_claim_keys", ())}
        for raw_key, item in list(identity_claims.items())[:64]:
            key = str(raw_key)
            lowered = key.lower()
            if claim_id is None and key in claim_keys and _is_id_like_value(item) and not _is_email_value(item):
                claim_id, claim_field = _bounded(item), key
            elif claim_email is None and (lowered in email_keys or _is_email_value(item)):
                if _is_email_value(item):
                    claim_email = str(item).strip()
        if claim_id is not None:
            owner_matched = bool(claim_email and wanted and claim_email.lower() == wanted)
            email_paired = claim_email is not None
            confidence = "high" if (email_paired or owner_matched) else "medium"
            outcome.candidates.append(_ArtifactCandidate(
                user_id=claim_id, source_field=claim_field or "", source_url="jwt://claims",
                reason="identity_discovered_from_redacted_claim_fallback",
                confidence=confidence, owner_matched=owner_matched, position=position,
                branch=S1_JWT_BRANCH,
            ))
            position += 1
            outcome.attempts.append({
                "strategy": S1_STRATEGY, "source": "jwt://claims",
                "outcome": "email_matched_pair" if email_paired else "bare_id_like_value",
                "confidence": confidence, "principal_identifier_match": owner_matched,
            })
        else:
            outcome.attempts.append({
                "strategy": S1_STRATEGY, "source": "jwt://claims",
                "outcome": "no_id_like_claim", "confidence": "inconclusive",
            })
    outcome.attempts.append({
        "stage": "s1", "branch": S1_JWT_BRANCH,
        "attempted": claims_supplied, "resolved": claim_id is not None,
        "resolved_key": claim_field,
    })

    # ---- branch B: login response body ----------------------------------
    body_mined: dict[str, Any] = {
        "candidates": [], "seeds": {}, "seed_names": [], "resolved_key": None,
        "pair_found": False, "bare_found": False,
    }
    if isinstance(login_response_body, (Mapping, list)) and login_response_body:
        max_depth = int(vocab.get("max_login_artifact_depth", 4))
        budget = [int(vocab.get("max_login_artifact_nodes", 256))]
        artifact = _bounded_artifact(login_response_body, depth=0, max_depth=max_depth, budget=budget)
        body_mined = _mine_body_records(artifact, principal_identifier=principal_identifier, vocab=vocab)
        outcome.candidates.extend(body_mined["candidates"])
        outcome.attempts.append({
            "strategy": S1_STRATEGY, "source": "login://response_body",
            "outcome": "email_matched_pair" if body_mined["pair_found"] else (
                "bare_id_like_value" if body_mined["bare_found"] else "no_id_like_scalar"
            ),
            "confidence": "high" if body_mined["pair_found"] else (
                "medium" if body_mined["bare_found"] else "inconclusive"
            ),
            "candidate_count": len(body_mined["candidates"]),
        })
    else:
        outcome.attempts.append({
            "strategy": S1_STRATEGY, "source": None,
            "outcome": "no_login_artifacts_available", "confidence": "inconclusive",
        })
    outcome.attempts.append({
        "stage": "s1", "branch": S1_BODY_BRANCH,
        "attempted": True, "resolved": body_mined["resolved_key"] is not None,
        "resolved_key": body_mined["resolved_key"],
        "payload_type": _payload_type_name(login_response_body),
        "resource_seed_count": len(body_mined["seeds"]),
        "resource_seed_names": sorted(body_mined["seeds"])[:16],
    })
    outcome.body_seeds = dict(body_mined["seeds"])
    outcome.body_email_matched_identity_key = any(
        candidate.owner_matched and _is_user_identity_key(
            str(candidate.source_field).lower().replace("-", "_"), vocab
        )
        for candidate in body_mined["candidates"]
    )
    return outcome


def _mine_body_records(value: Any, *, principal_identifier: str | None, vocab: Mapping[str, Any]) -> dict[str, Any]:
    """Recursive login-body scan under the r6c resource-seed semantics.

    - A record whose email-shaped scalar matches the principal identifier is
      owner-bound: its id-like key resolves the identity (winner
      ``s1_login_body_mining``) — including short-form keys such as ``bid``.
    - A bare USER-IDENTITY key (``user_id``/``id``/``uid``/...) with an
      id-like value resolves the identity at medium confidence.
    - Every other id-like key (``bid``/``cart_id``/``row_id``/...) is a
      RESOURCE SEED, never an identity.
    """
    candidates: list[_ArtifactCandidate] = []
    seeds: dict[str, str] = {}
    pair_found = False
    bare_found = False
    resolved_key: str | None = None
    wanted = str(principal_identifier or "").strip().lower()

    def visit(node: Any) -> None:
        nonlocal pair_found, bare_found, resolved_key
        if not isinstance(node, Mapping):
            if isinstance(node, list):
                for item in node[:16]:
                    visit(item)
            return
        emails: list[str] = []
        id_items: list[tuple[str, Any]] = []
        for raw_key, item in list(node.items())[:64]:
            key = str(raw_key)
            lowered = key.lower().replace("-", "_")
            if isinstance(item, (str, int)) and str(item).strip():
                if _is_email_value(item):
                    emails.append(str(item).strip())
                elif _is_id_like_value(item) and _is_id_like_key(lowered, vocab):
                    id_items.append((key, item))
        owner_bound = bool(wanted) and any(email.lower() == wanted for email in emails)
        matched_key: str | None = None
        if owner_bound and id_items:
            ordered = sorted(
                id_items,
                key=lambda pair: 0 if _is_user_identity_key(pair[0].lower().replace("-", "_"), vocab) else 1,
            )
            key, item = ordered[0]
            matched_key = key
            pair_found = True
            if resolved_key is None:
                resolved_key = key
            candidates.append(_ArtifactCandidate(
                user_id=_bounded(item), source_field=key, source_url="login://response_body",
                reason="identity_discovered_from_login_artifact_mining",
                confidence="high", owner_matched=True,
                position=len(candidates), branch=S1_BODY_BRANCH,
            ))
        for key, item in id_items:
            lowered = key.lower().replace("-", "_")
            if key == matched_key:
                continue
            if _is_user_identity_key(lowered, vocab):
                bare_found = True
                if resolved_key is None:
                    resolved_key = key
                candidates.append(_ArtifactCandidate(
                    user_id=_bounded(item), source_field=key, source_url="login://response_body",
                    reason="identity_discovered_from_login_artifact_mining",
                    confidence="medium", owner_matched=False,
                    position=len(candidates), branch=S1_BODY_BRANCH,
                ))
            elif key.lower() not in seeds and len(seeds) < 16:
                seeds[key.lower()[:96]] = _bounded(item)
        for item in list(node.values())[:64]:
            visit(item)

    visit(value)
    return {
        "candidates": candidates,
        "seeds": seeds,
        "seed_names": sorted(seeds),
        "resolved_key": resolved_key,
        "pair_found": pair_found,
        "bare_found": bare_found,
    }


def _non_json_result_name(response: Any) -> str:
    """r6c classification of a 2xx non-JSON body (SPA catch-alls recorded)."""
    try:
        content_type = str(getattr(response, "headers", {}).get("content-type", "") or "").lower()
    except Exception:
        content_type = ""
    if "html" in content_type:
        return "spa_catch_all_html"
    try:
        text = str(getattr(response, "text", "") or "").lstrip()
    except Exception:
        text = ""
    if text.startswith("<"):
        return "spa_catch_all_html"
    return "non_json_response"


def _same_origin_probe(callback: Callable[..., Any], url: str) -> Any:
    """Invoke the governed callback for a derived path variant (header transport)."""
    return callback(url)


def _same_origin(base: str, candidate: str) -> str | None:
    value = urljoin(base.rstrip("/") + "/", str(candidate))
    target, parsed = urlsplit(base), urlsplit(value)
    if parsed.scheme not in {"http", "https"} or parsed.hostname != target.hostname:
        return None
    if parsed.port != target.port and not (parsed.port is None and target.port in {None, 80, 443}):
        return None
    return value.split("#", 1)[0][:2048]


def _self_action_vocabulary() -> set[str]:
    vocab = load_identity_vocab()
    actions = {str(item).strip().lower() for item in vocab.get("self_actions", ()) if str(item).strip()}
    return actions or set(_SELF_ACTIONS_FALLBACK)


def _derive_resource_templates(path: str) -> tuple[str, ...]:
    """Derive sibling `{id}` templates only from an observed self endpoint."""
    parsed = urlsplit(path)
    clean_path = parsed.path or path
    segments = [item for item in clean_path.split("/") if item]
    if not segments or segments[-1].lower().replace("-", "_") not in _self_action_vocabulary():
        return ()
    parent = "/" + "/".join(segments[:-1])
    if not parent or parent == "/":
        return ()
    template = parent.rstrip("/") + "/{id}"
    return (template[:512],)


def _filter_self_action_paths(paths: Iterable[str], *, limit: int) -> list[str]:
    """Select crawler-discovered paths whose last segment is self-action-shaped."""
    actions = _self_action_vocabulary()
    selected: list[str] = []
    for item in paths:
        raw = str(item or "").strip()
        if not raw or len(raw) > 512:
            continue
        segments = [segment for segment in urlsplit(raw).path.split("/") if segment]
        if not segments:
            continue
        if segments[-1].lower().replace("-", "_") in actions and raw not in selected:
            selected.append(raw)
            if len(selected) >= limit:
                break
    return selected


def _callback_supports_transport(callback: Callable[..., Any]) -> bool:
    """Detect whether the governed callback accepts a transport variant hint."""
    try:
        parameters = inspect.signature(callback).parameters
    except (TypeError, ValueError):
        return False
    for parameter in parameters.values():
        if parameter.kind is inspect.Parameter.VAR_KEYWORD or parameter.name == "transport":
            return True
    positional = [
        parameter
        for parameter in parameters.values()
        if parameter.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    return len(positional) >= 2


def _invoke_callback(callback: Callable[..., Any], url: str, transport: str, transport_supported: bool) -> Any:
    if transport == "header" or not transport_supported:
        return callback(url)
    return callback(url, transport=transport)


@dataclass(frozen=True)
class IdentityDiscoveryResult:
    alias: str
    success: bool
    user_id: str | None = field(default=None, repr=False, compare=False)
    source_url: str | None = None
    source_field: str | None = None
    status_code: int | None = None
    attempts: tuple[dict[str, Any], ...] = ()
    resource_ids: dict[str, str] = field(default_factory=dict, repr=False, compare=False)
    resource_templates: tuple[str, ...] = ()
    reason: str = ""
    winner_strategy: str = ""
    strategy_attempts: tuple[dict[str, Any], ...] = ()
    verified_resource_seeds: tuple[str, ...] = ()

    @property
    def user_id_digest(self) -> str:
        return hashlib.sha256(str(self.user_id or "").encode("utf-8")).hexdigest()[:16]

    def _strategy_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.strategy_attempts:
            name = str(item.get("strategy") or "unknown")
            counts[name] = counts.get(name, 0) + 1
        return counts

    def as_dict(self) -> dict[str, Any]:
        return {
            "alias": self.alias[:128],
            "success": self.success,
            "user_id_present": bool(self.user_id),
            "user_id_digest": self.user_id_digest if self.user_id else None,
            "source_url": self.source_url,
            "source_field": self.source_field,
            "status_code": self.status_code,
            "attempts": [dict(item) for item in self.attempts[:_MAX_SERIALIZED_ATTEMPTS]],
            "resource_id_names": sorted(str(key)[:96] for key in self.resource_ids)[:16],
            "resource_templates": list(self.resource_templates[:8]),
            "reason": self.reason[:240],
            "winner_strategy": self.winner_strategy[:64],
            "strategy_attempts": [dict(item) for item in self.strategy_attempts[:16]],
            "identity_resolution": {
                "resolved": self.success,
                "winner_strategy": self.winner_strategy[:64] or None,
                "strategy_attempt_counts": self._strategy_counts(),
                "reason": self.reason[:240],
                "resource_template_count": len(self.resource_templates),
                "verified_resource_seed_count": len(self.verified_resource_seeds),
            },
        }


class IdentityDiscoverer:
    """Discover a principal's real ID through a caller-owned M4 request boundary.

    This class is deliberately not allowed to receive LoginMaterial or attach
    Authorization/Cookie/API-key values.  The request callback must already be
    backed by M4 authorize -> resolve -> attach and may return only a safe HTTP
    response.  This keeps identity discovery advisory and prevents it from
    becoming a second credential-attachment path.

    The callback may OPTIONALLY accept a ``transport`` keyword (e.g.
    ``"header"``, ``"query:token"``, ``"cookie:token"``).  When it does, the
    governed boundary relocates only material that M4 itself attached; this
    class never observes or transports credentials, so the M4 guarantee that
    the callback is the only auth path is preserved.
    """

    def __init__(self, *, target_url: str, timeout_seconds: float = 10.0, max_response_bytes: int = 512_000) -> None:
        self.target_url = target_url.rstrip("/")
        self.timeout_seconds = max(0.1, min(float(timeout_seconds), 60.0))
        self.max_response_bytes = max(1024, min(int(max_response_bytes), 2_000_000))

    def discover(
        self,
        *,
        alias: str,
        request_callback: Callable[..., Any] | None = None,
        candidate_paths: Iterable[str] = (),
        principal_identifier: str | None = None,
        identity_claims: Mapping[str, Any] | None = None,
        login_response_body: Any = None,
        crawl_paths: Iterable[str] = (),
    ) -> IdentityDiscoveryResult:
        if request_callback is None:
            return IdentityDiscoveryResult(alias[:128], False, reason="m4_request_callback_required")
        vocab = load_identity_vocab()
        transport_supported = _callback_supports_transport(request_callback)
        attempts: list[dict[str, Any]] = []
        strategy_attempts: list[dict[str, Any]] = []

        # ---- S1: login artifact mining (zero network) --------------------
        mining = _mine_login_artifacts(identity_claims, login_response_body, principal_identifier, vocab)
        # r6c: the two S1 branch records open the attempts tuple (trim-safe),
        # while the historical strategy entries feed the rollup surfaces.
        attempts.extend(item for item in mining.attempts if "stage" in item)
        strategy_attempts.extend(item for item in mining.attempts if "stage" not in item)

        # ---- r6c zero-network win path ---------------------------------
        # A login-body record whose email matches the principal AND whose
        # id key is a user-identity key resolves with ZERO probes.  The jwt
        # branch never short-circuits: its fallback win happens only after
        # the S2/S3 ladder is exhausted (the R9 contract).
        jwt_candidate_present = any(item.branch == S1_JWT_BRANCH for item in mining.candidates)
        if mining.body_email_matched_identity_key and not jwt_candidate_present:
            best = mining.best()
            if best is not None:
                return self._mined_success_result(
                    alias=alias, best=best, attempts=attempts, strategy_attempts=strategy_attempts,
                    request_callback=request_callback, transport_supported=transport_supported,
                    anonymous_shape_paths=[], vocab=vocab,
                )

        # ---- S2: self-endpoint probe --------------------------------------
        # Ordered candidates: profile wiring hint (prepend-only, optional),
        # then the convention list from the config data file, then
        # self-action-shaped paths already discovered by recon/crawler.
        # Each source is bounded separately so crawler EVIDENCE always keeps a
        # slot even when the convention list is long; the whole ladder probes
        # at most _MAX_PROBE_WINDOW paths.
        hint_paths = [str(item or "").strip() for item in candidate_paths if str(item or "").strip()][:_MAX_HINT_PATHS]
        crawl_self_paths = _filter_self_action_paths(crawl_paths, limit=int(vocab.get("max_crawl_self_paths", 8)))
        convention_budget = max(int(vocab.get("max_probe_paths", 10)), 4)
        paths: list[str] = []
        for item in (*hint_paths, *vocab.get("probe_paths", ())[:convention_budget]):
            path = str(item or "").strip()
            if path and path not in paths:
                paths.append(path[:512])
        for path in crawl_self_paths:
            if path not in paths:
                paths.append(path[:512])
        paths = paths[:_MAX_PROBE_WINDOW]
        if hint_paths:
            strategy_attempts.append({
                "strategy": S2_STRATEGY, "source": "profile_hint",
                "outcome": "hint_prepended", "confidence": "informational",
                "hint_path_count": len(hint_paths),
            })
        if crawl_self_paths:
            strategy_attempts.append({
                "strategy": S2_STRATEGY, "source": "recon_crawler",
                "outcome": "self_action_paths_selected", "confidence": "informational",
                "path_count": len(crawl_self_paths),
            })

        anonymous_shape_paths: list[tuple[str, str]] = []
        for path in paths:
            url = _same_origin(self.target_url, path)
            if not url:
                attempts.append({"path": path, "status_code": None, "result": "same_origin_rejected"})
                strategy_attempts.append({"strategy": S2_STRATEGY, "target": path[:256], "status_code": None, "outcome": "same_origin_rejected", "confidence": "inconclusive"})
                continue
            try:
                # The callback owns all authentication and must have already
                # completed M4 authorize -> resolve -> attach.  No material,
                # token, cookie, or caller-supplied auth header enters here.
                response = request_callback(url)
                status = int(getattr(response, "status_code", 0) or 0)
                payload = _safe_json(response)
                if not (200 <= status < 300):
                    attempts.append({"path": urlsplit(url).path, "status_code": status, "result": "http_status"})
                    strategy_attempts.append({"strategy": S2_STRATEGY, "target": urlsplit(url).path[:256], "status_code": status, "outcome": "http_error", "confidence": "inconclusive"})
                    continue
                if not isinstance(payload, (dict, list)):
                    attempts.append({"path": urlsplit(url).path, "status_code": status, "result": _non_json_result_name(response)})
                    strategy_attempts.append({"strategy": S2_STRATEGY, "target": urlsplit(url).path[:256], "status_code": status, "outcome": "not_json", "confidence": "inconclusive"})
                    continue
                user_id, source_field, resources = _walk_identity(payload, vocab=vocab)
                if principal_identifier:
                    matched_id, matched_field = _find_matching_identity(payload, principal_identifier)
                    if matched_id is not None:
                        user_id, source_field = matched_id, matched_field
                if user_id is None and not _has_identity_scalars(payload, vocab=vocab):
                    # Endpoint alive, identity absent via this transport:
                    # classify explicitly and self-heal across transports (S3).
                    attempts.append({"path": urlsplit(url).path, "status_code": status, "result": "anonymous_shape_observed"})
                    strategy_attempts.append({
                        "strategy": S2_STRATEGY, "target": urlsplit(url).path[:256], "status_code": status,
                        "outcome": ANONYMOUS_SHAPE_OUTCOME, "shape_hash": _shape_hash(payload),
                        "confidence": "inconclusive",
                    })
                    if len(anonymous_shape_paths) < int(vocab.get("max_anonymous_shape_retries", 3)):
                        anonymous_shape_paths.append((url, urlsplit(url).path))
                    continue
                if user_id is not None:
                    attempts.append({"path": urlsplit(url).path, "status_code": status, "result": "json_identity_resolved"})
                    return self._observed_success_result(
                        alias=alias, url=url, user_id=user_id, source_field=source_field,
                        resources=resources, status=status, attempts=attempts,
                        strategy_attempts=strategy_attempts, request_callback=request_callback,
                        transport_supported=transport_supported, transport="header",
                        vocab=vocab, mined_resources=(),
                    )
                attempts.append({"path": urlsplit(url).path, "status_code": status, "result": "anonymous_shape_observed"})
                strategy_attempts.append({"strategy": S2_STRATEGY, "target": urlsplit(url).path[:256], "status_code": status, "outcome": "identity_absent_after_walk", "shape_hash": _shape_hash(payload), "confidence": "inconclusive"})
            except Exception as exc:
                attempts.append({"path": urlsplit(url).path, "status_code": None, "result": type(exc).__name__})
                strategy_attempts.append({"strategy": S2_STRATEGY, "target": urlsplit(url).path[:256], "status_code": None, "outcome": f"exception_{type(exc).__name__}", "confidence": "inconclusive"})

        # ---- S3: anonymous-shape self-heal across path + transport variants ----
        # r6c: the self-heal runs even when the governed boundary does not
        # support transport relocation — a trailing-slash path variant is a
        # first-class retry.  Variant attempt records use ``path_template``
        # (never ``path``) so the probe-window accounting stays exact.
        transport_variants: list[str] = []
        for name in vocab.get("query_token_names", ()):
            transport_variants.append(f"query:{name}")
        for name in vocab.get("cookie_token_names", ()):
            transport_variants.append(f"cookie:{name}")
        retry_limit = int(vocab.get("max_transport_retries_per_path", 8))
        if not transport_supported and anonymous_shape_paths:
            strategy_attempts.append({"strategy": S3_STRATEGY, "target": anonymous_shape_paths[0][1][:256], "outcome": "transport_variants_unsupported_by_boundary", "confidence": "inconclusive"})
        for url, path in anonymous_shape_paths:
            variants: list[tuple[str, str]] = []
            if not path.endswith("/"):
                variants.append(("path", path + "/"))
            if transport_supported:
                variants.extend(("transport", name) for name in transport_variants[:retry_limit])
            for kind, variant in variants[: retry_limit + 2]:
                variant_path = variant if kind == "path" else path
                attempts.append({"path_template": variant_path[:512], "status_code": None, "result": "self_heal_variant"})
                try:
                    if kind == "path":
                        response = _same_origin_probe(request_callback, url + "/")
                    else:
                        response = _invoke_callback(request_callback, url, variant, transport_supported)
                    if response is None:
                        strategy_attempts.append({"strategy": S3_STRATEGY, "target": path[:256], "transport": variant, "status_code": None, "outcome": "same_origin_rejected", "confidence": "inconclusive"})
                        continue
                    status = int(getattr(response, "status_code", 0) or 0)
                    payload = _safe_json(response)
                    if not (200 <= status < 300) or not isinstance(payload, (dict, list)):
                        attempts[-1] = {"path_template": variant_path[:512], "status_code": status, "result": "http_status" if not (200 <= status < 300) else _non_json_result_name(response)}
                        strategy_attempts.append({"strategy": S3_STRATEGY, "target": path[:256], "transport": variant, "status_code": status, "outcome": "no_identity_response", "confidence": "inconclusive"})
                        continue
                    user_id, source_field, resources = _walk_identity(payload, vocab=vocab)
                    if principal_identifier and user_id is None:
                        matched_id, matched_field = _find_matching_identity(payload, principal_identifier)
                        if matched_id is not None:
                            user_id, source_field = matched_id, matched_field
                    if user_id is not None:
                        attempts[-1] = {"path_template": variant_path[:512], "status_code": status, "result": "json_identity_resolved"}
                        return self._observed_success_result(
                            alias=alias, url=url if kind == "transport" else url + "/", user_id=user_id, source_field=source_field,
                            resources=resources, status=status, attempts=attempts,
                            strategy_attempts=strategy_attempts, request_callback=request_callback,
                            transport_supported=transport_supported, transport="header" if kind == "path" else variant,
                            vocab=vocab, mined_resources=(), winner_strategy=S3_STRATEGY,
                        )
                    attempts[-1] = {"path_template": variant_path[:512], "status_code": status, "result": "anonymous_shape_observed"}
                    strategy_attempts.append({"strategy": S3_STRATEGY, "target": path[:256], "transport": variant, "status_code": status, "outcome": ANONYMOUS_SHAPE_OUTCOME, "shape_hash": _shape_hash(payload), "confidence": "inconclusive"})
                except Exception as exc:
                    attempts[-1] = {"path_template": variant_path[:512], "status_code": None, "result": type(exc).__name__}
                    strategy_attempts.append({"strategy": S3_STRATEGY, "target": path[:256], "transport": variant, "status_code": None, "outcome": f"exception_{type(exc).__name__}", "confidence": "inconclusive"})

        # ---- Resolution: observed identity absent -> S1 fallback ----------
        best = mining.best()
        if best is not None:
            return self._mined_success_result(
                alias=alias, best=best, attempts=attempts, strategy_attempts=strategy_attempts,
                request_callback=request_callback, transport_supported=transport_supported,
                anonymous_shape_paths=anonymous_shape_paths, vocab=vocab,
            )

        # ---- S4: honest exhaustion ----------------------------------------
        strategy_attempts.append({"strategy": "s4_honest_exhaustion", "outcome": EXHAUSTED_REASON, "confidence": "conclusive_negative"})
        return IdentityDiscoveryResult(
            alias[:128], False, None, None, None, None,
            tuple(attempts[:_MAX_ATTEMPT_RECORDS]), dict(mining.body_seeds), (),
            EXHAUSTED_REASON, "", tuple(strategy_attempts), (),
        )

    def _observed_success_result(
        self,
        *,
        alias: str,
        url: str,
        user_id: str,
        source_field: str | None,
        resources: dict[str, str],
        status: int,
        attempts: list[dict[str, Any]],
        strategy_attempts: list[dict[str, Any]],
        request_callback: Callable[..., Any],
        transport_supported: bool,
        transport: str,
        vocab: Mapping[str, Any],
        mined_resources: tuple[tuple[str, str], ...],
        winner_strategy: str | None = None,
    ) -> IdentityDiscoveryResult:
        """Build a success result from an observed M4-authenticated response."""
        winner = winner_strategy or (S2_STRATEGY if transport == "header" else S3_STRATEGY)
        templates: tuple[str, ...] = ()
        # A self endpoint such as /users/me can imply /users/{id}, but that
        # implication is only a hypothesis.  Confirm the owner baseline through
        # the same governed M4 callback before allowing the template to seed a
        # BOLA candidate.  Keep runtime identifiers out of serialized attempts.
        derived = _derive_resource_templates(urlsplit(url).path)
        verified, seed_entries, template_attempts = self._verify_templates(
            derived, request_callback, transport_supported, transport,
            {str(user_id)}, attempts, winner,
        )
        attempts.extend(template_attempts)
        strategy_attempts.append({
            "strategy": winner,
            "target": urlsplit(url).path[:256], "transport": transport if transport != "header" else None,
            "status_code": status, "outcome": "identity_found", "shape_hash": None,
            "confidence": "high",
        })
        strategy_attempts.append({
            "strategy": "resolution", "outcome": "winner_selected",
            "confidence": "high",
            "winner_strategy": winner,
            "owner_baseline_templates_verified": len(verified),
        })
        return IdentityDiscoveryResult(
            alias[:128], True, user_id, urlsplit(url).path, source_field, status,
            tuple(attempts[:_MAX_ATTEMPT_RECORDS]), resources, verified,
            "identity_discovered_from_m4_authenticated_response" if winner == S2_STRATEGY else "identity_discovered_after_transport_retry",
            winner,
            tuple(strategy_attempts), tuple(seed_entries),
        )

    def _mined_success_result(
        self,
        *,
        alias: str,
        best: _ArtifactCandidate,
        attempts: list[dict[str, Any]],
        strategy_attempts: list[dict[str, Any]],
        request_callback: Callable[..., Any],
        transport_supported: bool,
        anonymous_shape_paths: list[tuple[str, str]],
        vocab: Mapping[str, Any],
    ) -> IdentityDiscoveryResult:
        """Build a success result from S1 login-artifact mining.

        Mined resource ids may seed candidates only after the same governed
        owner-baseline verification used for templates: each derived template
        is probed through the M4 callback before it is reported.
        """
        identity_value = str(best.user_id)
        verified: list[str] = []
        seed_entries: list[str] = []
        candidate_templates: list[str] = []
        for url, _path in anonymous_shape_paths[: int(vocab.get("max_anonymous_shape_retries", 3))]:
            for template in _derive_resource_templates(urlsplit(url).path):
                if template not in candidate_templates:
                    candidate_templates.append(template)
        id_pool = [identity_value] + [value for _key, value in best.resources[:4]]
        for template in candidate_templates[:2]:
            for id_value in id_pool[:5]:
                candidate_url = _same_origin(self.target_url, template.replace("{id}", id_value, 1))
                if not candidate_url:
                    continue
                try:
                    response = request_callback(candidate_url)
                    status = int(getattr(response, "status_code", 0) or 0)
                    attempts.append({"path_template": template, "status_code": status, "result": "owner_baseline_check"})
                    if 200 <= status < 300 and template not in verified:
                        verified.append(template[:512])
                        if id_value != identity_value:
                            seed_entries.append(template[:512])
                        break
                except Exception as exc:
                    attempts.append({"path_template": template, "status_code": None, "result": type(exc).__name__})
        resources = {key: value for key, value in best.resources[:16]}
        if best.branch == S1_JWT_BRANCH:
            winner = S1_JWT_WINNER
        elif best.owner_matched:
            winner = S1_BODY_MATCHED_WINNER
        else:
            winner = S1_BODY_BARE_WINNER
        strategy_attempts.append({
            "strategy": S1_STRATEGY, "source": best.source_url,
            "outcome": "identity_found", "confidence": best.confidence,
            "owner_baseline_templates_verified": len(verified),
        })
        strategy_attempts.append({
            "strategy": "resolution", "outcome": "winner_selected",
            "confidence": best.confidence, "winner_strategy": winner,
            "principal_identifier_match": best.owner_matched,
        })
        return IdentityDiscoveryResult(
            alias[:128], True, best.user_id, best.source_url, best.source_field, None,
            tuple(attempts[:_MAX_ATTEMPT_RECORDS]), resources, tuple(verified),
            best.reason, winner, tuple(strategy_attempts), tuple(seed_entries),
        )

    def _verify_templates(
        self,
        templates: tuple[str, ...],
        request_callback: Callable[..., Any],
        transport_supported: bool,
        transport: str,
        identity_values: set[str],
        attempts: list[dict[str, Any]],
        strategy_name: str,
    ) -> tuple[tuple[str, ...], list[str], list[dict[str, Any]]]:
        """Governed owner-baseline verification of derived {id} templates."""
        verified: list[str] = []
        seed_entries: list[str] = []
        template_attempts: list[dict[str, Any]] = []
        for template in templates:
            confirmed = False
            for id_value in list(identity_values)[:5]:
                candidate_url = _same_origin(self.target_url, template.replace("{id}", id_value, 1))
                if not candidate_url:
                    template_attempts.append({"path_template": template, "status_code": None, "result": "same_origin_rejected"})
                    continue
                try:
                    template_response = _invoke_callback(request_callback, candidate_url, transport, transport_supported)
                    template_status = int(getattr(template_response, "status_code", 0) or 0)
                    template_attempts.append({"path_template": template, "status_code": template_status, "result": "owner_baseline_check"})
                    if 200 <= template_status < 300:
                        confirmed = True
                        break
                except Exception as exc:
                    template_attempts.append({"path_template": template, "status_code": None, "result": type(exc).__name__})
            if confirmed:
                verified.append(template[:512])
        return tuple(verified), seed_entries, template_attempts


__all__ = ["IdentityDiscoverer", "IdentityDiscoveryResult", "decode_login_jwt_claims"]
