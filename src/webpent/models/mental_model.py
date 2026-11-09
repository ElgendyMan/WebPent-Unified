# src/webpent/models/mental_model.py
"""webpent.models.mental_model

V7 Cognitive Upgrade — Phase 2: Mental Model / Knowledge Graph.

Gives the system a structured, queryable picture of the target,
instead of the scattered dicts and finding lists that ``crawled_data``
carries today. The Mental Model is **engagement-scoped** — it lives
in ``PentestState.mental_model`` (dict-shaped, ``merge_dicts`` reducer,
checkpointed by the existing SqliteSaver) and is NOT written to
ChromaDB. Cross-engagement learning stays where it already lives
(``reflection_node`` -> lessons store), which is a deliberately
separate concern from within-engagement situational awareness.

Design principles (per Phase 2 spec):

  * **Typed nodes** — ``host``, ``endpoint``, ``credential``,
    ``artifact`` (file/archive/config), ``service``, ``technology``.
    Each carries: stable ID, normalised identity key (used for Loop
    Prevention dedup), discovery source, in-scope status (NEVER
    inferred — always explicitly set by ``scope_enforcer`` or its
    rabbit-hole-path equivalent), criticality tag.
  * **Typed edges** — ``contains``, ``authenticates_to``,
    ``discovered_via``, ``references``, ``same_host_as``. Each links
    two node IDs with a source reference (which Decision Log entry
    created this edge).
  * **Deterministic extraction** — every node that currently
    *produces* discoveries (recon, crawler, hypothesis_analyzer, the
    four V7 Sprint-2 deep-probers, post_exploit) gets a small,
    additive responsibility: extract structured entities from its
    output and merge them into the Mental Model. The extraction is
    regex/heuristic pattern-matching — NO LLM. The LLM's role, if
    any, is limited to describing a *relationship* in natural
    language for the Decision Log, never to deciding *whether* an
    entity/edge exists. (Same discipline as hypothesis_analyzer's
    zero-LLM heuristic classification for structural facts.)
  * **Reducer discipline** — ``mental_model`` uses ``merge_dicts``
    exactly as ``crawled_data``/``session_cookies``/``credentials``
    do (per the V6 Absolute-Flawless CISO audit fix). Parallel
    branches can't clobber each other's discoveries; per-key updates
    are visible to checkpoints.

Persistence:
    The Mental Model is engagement-scoped and lives in
    ``PentestState.mental_model`` only. It is NOT persisted to a
    separate SQLite table — it checkpoint-survives via the existing
    SqliteSaver that already handles ``crawled_data`` etc. (Phase 2
    step 4 of the plan: "engagement-scoped, not cross-engagement ...
    does not get written into ChromaDB"). The Mental Model will
    contain sensitive material (credential strings, internal IPs,
    extracted secrets) by design — treat its persistence with the
    same care already given to ``evidence_bundle``/``evidence_hash``
    (Phase 6 / Section 6 risk note).

Query interface:
    :func:`query_unexplored_high_value_nodes` and
    :func:`is_asset_already_visited` provide the lightweight queries
    Dynamic Prioritization (Phase 3) and Rabbit Hole's Loop
    Prevention (Phase 6) need. The query interface is deliberately
    small — it can be extended later without touching the data model.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Enums — typed node kinds and edge kinds
# ---------------------------------------------------------------------------
class NodeKind(str, Enum):
    """Typed node kinds in the Mental Model.

    The closed set is deliberately small — each kind has a distinct
    criticality default that Dynamic Prioritization can use without
    asking the LLM. ``credential`` ranks above ``endpoint`` because
    a credential is a higher-leverage asset; ``host`` ranks above
    ``technology`` because a new host expands the attack surface
    more than a new framework fingerprint. These defaults are
    encoded in :data:`_DEFAULT_CRITICALITY_BY_KIND`.
    """

    HOST = "host"               # A network host (IP or hostname)
    ENDPOINT = "endpoint"       # A URL / route on a host
    CREDENTIAL = "credential"   # A credential pair / token / API key
    ARTIFACT = "artifact"       # A file / archive / config / compose file
    SERVICE = "service"         # A network service (port + protocol)
    TECHNOLOGY = "technology"   # A detected technology / framework / CMS
    IDENTITY = "identity"       # A redacted actor/profile reference
    OBJECT = "object"           # An observed business object reference
    WORKFLOW = "workflow"       # A bounded sequence/state machine


class EdgeKind(str, Enum):
    """Typed edge kinds in the Mental Model.

    Edges are intentionally a closed set — adding a new kind is a
    deliberate design decision, not a free-form LLM output. Each
    edge carries a ``source_ref`` pointing at the Decision Log entry
    that created it, so the chain of "why do we believe these two
    assets are related" is always traceable.
    """

    CONTAINS = "contains"                   # host contains endpoint / artifact
    AUTHENTICATES_TO = "authenticates_to"   # credential authenticates_to host/service
    DISCOVERED_VIA = "discovered_via"       # endpoint discovered_via finding/hypothesis
    REFERENCES = "references"               # artifact references host/endpoint
    SAME_HOST_AS = "same_host_as"           # two endpoints on the same host
    OWNS = "owns"                             # identity owns object
    REQUIRES_ROLE = "requires_role"           # endpoint/workflow requires role
    TRANSITIONS_TO = "transitions_to"         # workflow transition relation
    SAME_AUTH_PATTERN = "same_auth_pattern"   # assets share auth signal
    USES_IDENTITY = "uses_identity"           # endpoint observed with identity


class Criticality(str, Enum):
    """Criticality tier for a Mental Model node.

    Used by Dynamic Prioritization as one input to the ranking
    formula. Higher criticality = ranked higher when all else is
    equal. ``CRITICAL`` is reserved for credentials and apparent
    production data stores (the same categories that force an HITL
    pause in ``RabbitHolePolicy``, Phase 6).
    """

    LOW = "low"          # generic endpoint / technology fingerprint
    MEDIUM = "medium"    # service / artifact of unknown value
    HIGH = "high"        # host / admin-looking endpoint
    CRITICAL = "critical"  # credential / apparent production data store


# Default criticality by node kind. Used when a node is created
# without an explicit criticality tag. Mirrors the rationale in
# NodeKind's docstring — credentials and hosts rank above generic
# endpoints and technology fingerprints.
_DEFAULT_CRITICALITY_BY_KIND: dict[str, str] = {
    NodeKind.HOST.value: Criticality.HIGH.value,
    NodeKind.ENDPOINT.value: Criticality.LOW.value,
    NodeKind.CREDENTIAL.value: Criticality.CRITICAL.value,
    NodeKind.ARTIFACT.value: Criticality.MEDIUM.value,
    NodeKind.SERVICE.value: Criticality.MEDIUM.value,
    NodeKind.TECHNOLOGY.value: Criticality.LOW.value,
    NodeKind.IDENTITY.value: Criticality.HIGH.value,
    NodeKind.OBJECT.value: Criticality.MEDIUM.value,
    NodeKind.WORKFLOW.value: Criticality.MEDIUM.value,
}


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class MentalModelNode(BaseModel):
    """A single node in the Mental Model graph.

    Attributes:
        id: Stable UUID-style string. Generated by the extractor at
            creation time; used as the dict key in
            ``MentalModel.nodes`` and as the ``source_id``/``target_id``
            on edges.
        kind: The :class:`NodeKind` (host / endpoint / credential /
            artifact / service / technology).
        identity_key: Normalised identity key used for Loop Prevention
            dedup. For a host: the canonicalised hostname or IP string.
            For an endpoint: the canonicalised URL. For an artifact:
            a content hash (sha256:...) or canonicalised URL. For a
            credential: a fingerprint (sha256 of the credential string,
            NOT the credential itself — never store raw credentials
            in the identity_key).
        discovery_source: Which node/action found this entity
            (e.g. ``"recon_node"``, ``"crawler_node"``,
            ``"hypothesis_analyzer_node"``, ``"access_control_node"``,
            ``"api_testing_node"``, ``"business_logic_fuzzer_node"``,
            ``"request_smuggling_node"``, ``"post_exploitation_node"``,
            ``"rabbit_hole:branch_3"``).
        in_scope: Result of the scope check. NEVER inferred — always
            explicitly set by ``scope_enforcer`` (for the initial
            post-crawler sweep) or by the rabbit-hole-path equivalent
            (for any newly discovered host). ``None`` means "not yet
            checked" — Dynamic Prioritization must NOT treat None as
            in-scope; it must treat None as "needs scope check before
            investigation."
        criticality: :class:`Criticality` tier. Defaults to the
            per-kind default if not set at creation time.
        metadata: Free-form dict for kind-specific extras (e.g. HTTP
            status code for an endpoint, port number for a service,
            artifact type for an artifact). NEVER put raw credentials
            here — credentials are fingerprinted at extraction time
            and only the fingerprint is stored.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    id: str = Field(
        ...,
        min_length=1,
        description="Stable UUID-style string ID.",
    )
    kind: NodeKind = Field(
        ...,
        description="Typed node kind.",
    )
    identity_key: str = Field(
        ...,
        min_length=1,
        description=(
            "Normalised identity key for Loop Prevention dedup. "
            "NEVER store raw credentials here — fingerprint them."
        ),
    )
    discovery_source: str = Field(
        ...,
        min_length=1,
        description="Which node/action found this entity.",
    )
    in_scope: bool | None = Field(
        default=None,
        description=(
            "Result of the scope check. None = not yet checked "
            "(Dynamic Prioritization must treat None as 'needs scope "
            "check before investigation', never as in-scope)."
        ),
    )
    criticality: Criticality = Field(
        default=Criticality.LOW,
        description="Criticality tier for Dynamic Prioritization.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Free-form dict for kind-specific extras. NEVER put raw "
            "credentials here — fingerprint them."
        ),
    )

    @field_validator("kind", mode="before")
    @classmethod
    def _normalise_kind(cls, v: str | NodeKind | None) -> NodeKind:
        if v is None:
            raise ValueError("NodeKind cannot be None.")
        if isinstance(v, NodeKind):
            return v
        return NodeKind(str(v).lower())

    @field_validator("criticality", mode="before")
    @classmethod
    def _normalise_criticality(cls, v: str | Criticality | None) -> Criticality:
        if v is None:
            return Criticality.LOW
        if isinstance(v, Criticality):
            return v
        return Criticality(str(v).lower())


class MentalModelEdge(BaseModel):
    """A single typed edge in the Mental Model graph.

    Edges are intentionally a closed set (see :class:`EdgeKind`).
    Each edge carries a ``source_ref`` pointing at the Decision Log
    entry that created it, so the chain of "why do we believe these
    two assets are related" is always traceable.

    Attributes:
        kind: The :class:`EdgeKind`.
        source_id: The ID of the source :class:`MentalModelNode`.
        target_id: The ID of the target :class:`MentalModelNode`.
        source_ref: Reference to the Decision Log entry that created
            this edge. Empty string is allowed for edges created
            before the Decision Log exists (Phase 6) — those edges
            will be back-filled when the Decision Log lands.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    kind: EdgeKind = Field(
        ...,
        description="Typed edge kind.",
    )
    source_id: str = Field(
        ...,
        min_length=1,
        description="ID of the source node.",
    )
    target_id: str = Field(
        ...,
        min_length=1,
        description="ID of the target node.",
    )
    source_ref: str = Field(
        default="",
        description=(
            "Reference to the Decision Log entry that created this "
            "edge. Empty for edges created before the Decision Log "
            "exists (Phase 6)."
        ),
    )

    @field_validator("kind", mode="before")
    @classmethod
    def _normalise_kind(cls, v: str | EdgeKind | None) -> EdgeKind:
        if v is None:
            raise ValueError("EdgeKind cannot be None.")
        if isinstance(v, EdgeKind):
            return v
        return EdgeKind(str(v).lower())


class MentalModel(BaseModel):
    """Engagement-scoped Mental Model / knowledge graph.

    Stored in ``PentestState.mental_model`` as a dict (serialised
    via Pydantic's ``model_dump``), with the ``merge_dicts`` reducer
    handling parallel-branch writes. The dict shape is:

        {
            "nodes": {node_id: MentalModelNode_dict, ...},
            "edges": [MentalModelEdge_dict, ...],
        }

    Both ``nodes`` and ``edges`` are merged dict-wise / appended
    list-wise by ``merge_dicts`` (which deep-merges dicts and
    concatenates lists). This means two parallel branches that each
    discover a different host will both end up in the merged Mental
    Model without one clobbering the other — exactly the property
    the V6 CISO audit fix gave ``crawled_data``.

    The model is deliberately a thin container — all extraction
    logic lives in :mod:`webpent.shared.mental_model_extractor` and
    all query logic lives in :func:`query_unexplored_high_value_nodes`
    / :func:`is_asset_already_visited` below. This keeps the data
    model stable while the extraction and query surface can evolve.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    nodes: dict[str, MentalModelNode] = Field(
        default_factory=dict,
        description="Node ID -> MentalModelNode.",
    )
    edges: list[MentalModelEdge] = Field(
        default_factory=list,
        description="List of typed edges.",
    )

    def to_dict_for_state(self) -> dict[str, Any]:
        """Serialise to the dict shape stored in PentestState.

        ``PentestState.mental_model`` is ``Annotated[dict[str, Any],
        merge_dicts]`` — the reducer deep-merges dict values and
        concatenates list values, which is exactly what we want for
        parallel-branch node/edge merges.
        """
        return {
            "nodes": {
                nid: n.model_dump(mode="json") if isinstance(n, MentalModelNode) else dict(n)
                for nid, n in self.nodes.items()
            },
            "edges": [
                e.model_dump(mode="json") if isinstance(e, MentalModelEdge) else dict(e)
                for e in self.edges
            ],
        }


# ---------------------------------------------------------------------------
# Deterministic extractors — pure regex/heuristic, NO LLM
# ---------------------------------------------------------------------------
# IP-literal regex (v4 + v6-ish). ipaddress.ip_address is the authority
# for "is this a real IP" — this regex is just a cheap pre-filter to
# avoid calling ip_address on every token.
_IP_LITERAL_RE = re.compile(
    r"^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)$"
)

# Hostname regex — RFC 1123 (relaxed): labels separated by dots, each
# label alphanumeric + hyphen, not starting/ending with hyphen.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)

# URL regex — http(s):// + host + optional path/query. The crawler
# already produces clean URLs, so this is a tolerant matcher not a
# strict RFC 3986 parser.
_URL_RE = re.compile(
    r"^https?://[a-zA-Z0-9.\-_:]+(?:/[^\s\"'<>]*)?$",
    re.IGNORECASE,
)

# Credential-shaped patterns — same conservative patterns the crawler
# already uses for JS secret extraction (src/webpent/agents/crawler/
# agent.py:_SECRET_PATTERNS). Reusing the same shapes keeps the
# Mental Model's credential detection consistent with the existing
# JS-secret-extraction pipeline. The fingerprint is sha256 of the
# matched value — the raw credential is NEVER stored in the Mental
# Model. (Phase 6 / Section 6 risk note: the Mental Model will
# contain sensitive material by design — treat its persistence with
# the same care already given to evidence_bundle/evidence_hash.)
_CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Stripe Secret Key", re.compile(r"sk_live_[0-9a-zA-Z]{24}")),
    ("Stripe Publishable Key", re.compile(r"pk_live_[0-9a-zA-Z]{24}")),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9a-zA-Z-]{10,48}")),
    ("GitHub Token", re.compile(r"gh[ps]_[0-9a-zA-Z]{36}")),
    ("JWT Token", re.compile(
        r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"
    )),
]

# Artifact-type patterns — Phase 6 Rabbit Hole's deterministic
# artifact-pattern table will live in config/policies.py (Phase 7
# prerequisite). The patterns here are the *extraction* shapes only
# — they classify a discovered string as "this looks like an artifact
# of type X." The *decision* to follow an artifact is a separate
# Phase 6 concern, NOT made here.
_ARTIFACT_TYPE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Archive files
    ("archive", re.compile(r"\.(?:zip|tar(?:\.gz)?|tgz|rar|7z|gz|bz2)$", re.IGNORECASE)),
    # Config / compose files — V8 P0 A1 expanded: added Dockerfile,
    # .htaccess, .htpasswd, web.config, wp-config.php, id_rsa, id_dsa,
    # .npmrc, .git-credentials, .netrc, .pgpass, s3.cfg. These are the
    # canonical "files an attacker can read to win" set and were missing
    # from the V7 pattern table.
    ("config", re.compile(
        r"(?:^|/)(?:"
        r"docker-compose\.ya?ml|Dockerfile(?:\.[A-Za-z0-9_-]+)?|"
        r"\.env(?:\.[A-Za-z0-9_-]+)?|"
        r"config\.(?:ya?ml|json|ini|conf)|"
        r"settings\.(?:py|json|ya?ml)|"
        r"web\.config|wp-config\.php|"
        r"\.htaccess|\.htpasswd|"
        r"id_rsa|id_dsa|id_ecdsa|id_ed25519|"
        r"\.npmrc|\.git-credentials|\.netrc|\.pgpass|s3\.cfg|"
        r"\.aws/credentials|\.ssh/known_hosts"
        r")$",
        re.IGNORECASE,
    )),
    # .git markers — V8 P0 A1 expanded: also match /.git/HEAD, /.git/index,
    # /.git/config (already present), and the bare /.git$/ or /.git/$
    # directory disclosure (trailing-slash tolerant).
    ("git_marker", re.compile(
        r"(?:^|/)\.git(?:/(?:config|HEAD|index|packed-refs|refs|objects))?/?$",
        re.IGNORECASE,
    )),
    # .svn / .hg markers — V8 P0 A1 added (analogous to .git).
    ("vcs_marker", re.compile(r"(?:^|/)\.(?:svn|hg|bzr)(?:/|/?$)", re.IGNORECASE)),
    # SQL dumps
    ("sql_dump", re.compile(r"\.(?:sql|dump|db)$", re.IGNORECASE)),
    # Backup files
    ("backup", re.compile(r"\.(?:bak|backup|old|orig|swp)$", re.IGNORECASE)),
    # Source-code disclosure — V8 P0 A1 added. Common PHP/Java/Python
    # source files served raw by a misconfigured webroot are an
    # artifact disclosure, not a fingerprint.
    ("source_code", re.compile(
        r"\.(?:php|phtml|inc|java|py|rb|pl|cgi|jsp|asp|aspx)(?:~|\.bak|\.old)?$",
        re.IGNORECASE,
    )),
    # OS metadata files — V8 P0 A1 added. .DS_Store is famously
    # spiderable and exposes directory listings.
    ("os_metadata", re.compile(r"(?:^|/)\.DS_Store$", re.IGNORECASE)),
]


def _normalise_url(url: str) -> str:
    """Normalise a URL for dedup identity_key.

    Strips trailing slash, lowercases scheme + host, drops fragment.
    Query string is preserved (different query strings can be
    different endpoints). Path is preserved. Port is preserved if
    non-default.
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url.strip())
        scheme = (parsed.scheme or "http").lower()
        netloc = (parsed.netloc or "").lower()
        # Strip default ports.
        if scheme == "http" and netloc.endswith(":80"):
            netloc = netloc[:-3]
        elif scheme == "https" and netloc.endswith(":443"):
            netloc = netloc[:-4]
        path = (parsed.path or "/").rstrip("/") or "/"
        # Drop fragment, keep query.
        normalised = f"{scheme}://{netloc}{path}"
        if parsed.query:
            normalised += f"?{parsed.query}"
        return normalised
    except Exception:
        return url.strip().rstrip("/")


def _normalise_host(host: str) -> str:
    """Normalise a hostname or IP for dedup identity_key."""
    if not host:
        return ""
    h = host.strip().lower()
    # Strip brackets from IPv6 literals.
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h


def _fingerprint_credential(value: str) -> str:
    """Return a sha256 fingerprint of a credential string.

    The raw credential is NEVER stored in the Mental Model — only the
    fingerprint. This is the same posture the project already takes
    for evidence_hash (SHA-256 of evidence_bundle). The fingerprint
    is sufficient for Loop Prevention dedup ("have we already seen
    this exact credential?") without persisting the secret itself.
    """
    if not value:
        return ""
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def _is_ip_literal(host: str) -> bool:
    """Return True iff ``host`` is a bare IP literal (v4 or v6)."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _make_node_id(prefix: str, identity_key: str) -> str:
    """Derive a deterministic node ID from prefix + identity_key.

    Deterministic ID generation means the same asset extracted by two
    different nodes produces the SAME node ID, so the ``merge_dicts``
    reducer correctly merges them into a single node instead of
    creating duplicates. The ID is ``<prefix>-<sha256(identity_key)[:16]>``
    — the prefix is human-readable in logs, the hash suffix is unique.
    """
    if not identity_key:
        return prefix
    short_hash = hashlib.sha256(identity_key.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{short_hash}"


# ---------------------------------------------------------------------------
# Public extractor API — called additively by each discovery node
# ---------------------------------------------------------------------------
def extract_mental_model_updates(
    *,
    discovery_source: str,
    endpoints: list[str] | None = None,
    hosts: list[str] | None = None,
    credentials: list[dict[str, str]] | None = None,
    artifacts: list[dict[str, str]] | None = None,
    technologies: list[str] | None = None,
    services: list[dict[str, Any]] | None = None,
    endpoint_details: list[dict[str, Any]] | None = None,
    identities: list[dict[str, Any]] | None = None,
    objects: list[dict[str, Any]] | None = None,
    workflows: list[dict[str, Any]] | None = None,
    relations: list[dict[str, Any]] | None = None,
    target_url: str | None = None,
) -> dict[str, Any]:
    """Deterministically extract Mental Model node/edge updates.

    Pure regex/heuristic pattern-matching — NO LLM. Called
    additively at the end of each discovery node's return (recon,
    crawler, hypothesis_analyzer, the four V7 Sprint-2 deep-probers,
    post_exploit). The returned dict is merged into
    ``state["mental_model"]`` via the ``merge_dicts`` reducer.

    Args:
        discovery_source: Name of the calling node (e.g.
            ``"recon_node"``). Stored on every node/edge created
            here so the Decision Log can trace provenance.
        endpoints: List of URL strings discovered by the caller.
        hosts: List of hostnames/IPs discovered by the caller.
        credentials: List of ``{"type": str, "value": str, "source": str}``
            dicts (same shape as the crawler's JS secret extractor).
            The ``value`` is fingerprinted immediately — only the
            fingerprint is stored in the Mental Model.
        artifacts: List of ``{"type": str, "url": str}`` dicts.
            ``type`` is one of: archive / config / git_marker /
            sql_dump / backup.
        technologies: List of technology/framework names (e.g.
            ``"nginx"``, ``"PHP/7.4"``, ``"WordPress"``).
        services: List of ``{"port": int, "protocol": str, "name": str}``
            dicts.
        endpoint_details: Optional sanitized endpoint metadata. Only method
            names, parameter names, form flags, and evidence references are
            retained; parameter values are never persisted here.
        identities: Redacted actor/profile references with optional role and
            auth-signal metadata. Raw cookies/tokens are never persisted.
        objects: Observed business-object references. IDs are fingerprinted
            before storage and may be linked to an identity owner.
        workflows: Bounded workflow candidates with step/transition refs.
        relations: Explicit typed relations whose endpoints resolve to nodes;
            unknown or unsupported relation kinds are ignored.
        target_url: The engagement's primary target URL. Used to
            derive the root host node if no hosts were explicitly
            provided, so the Mental Model always has at least one
            host to anchor edges to.

    Returns:
        A dict shaped ``{"nodes": {node_id: MentalModelNode_dict, ...},
        "edges": [MentalModelEdge_dict, ...]}`` ready for
        ``merge_dicts`` into ``state["mental_model"]``. Empty
        ``nodes``/``edges`` keys are always present so the reducer
        merge is a no-op when nothing was extracted.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    # -- Derive root host from target_url if no hosts were provided --
    derived_hosts = list(hosts or [])
    if not derived_hosts and target_url:
        try:
            parsed = urlparse(target_url)
            if parsed.hostname:
                derived_hosts = [parsed.hostname]
        except Exception:
            pass
            # Intentionally suppressed — reviewed 2026-09-03

    # -- HOST nodes --
    host_node_ids: list[str] = []
    for host in derived_hosts:
        if not host:
            continue
        h = _normalise_host(host)
        if not h:
            continue
        node_id = _make_node_id("host", h)
        host_node_ids.append(node_id)
        if node_id not in nodes:
            criticality = (
                Criticality.HIGH.value
                if not _is_ip_literal(h)
                else Criticality.HIGH.value  # IP-literal hosts are also HIGH
            )
            nodes[node_id] = MentalModelNode(
                id=node_id,
                kind=NodeKind.HOST,
                identity_key=h,
                discovery_source=discovery_source,
                in_scope=None,  # Explicit "not yet checked" — scope_enforcer sets this
                criticality=criticality,
                metadata={"original": host},
            ).model_dump(mode="json")

    # -- ENDPOINT nodes (and same_host_as edges to their host) --
    endpoint_detail_by_url: dict[str, dict[str, Any]] = {}
    for detail in (endpoint_details or []):
        if not isinstance(detail, dict):
            continue
        detail_url = detail.get("url") or detail.get("endpoint") or detail.get("action")
        if not isinstance(detail_url, str):
            continue
        detail_normalised = _normalise_url(detail_url)
        if detail_normalised:
            endpoint_detail_by_url[detail_normalised] = detail

    for url in (endpoints or []):
        if not url or not _URL_RE.match(url.strip()):
            continue
        normalised = _normalise_url(url)
        if not normalised:
            continue
        node_id = _make_node_id("endpoint", normalised)
        if node_id not in nodes:
            detail = endpoint_detail_by_url.get(normalised, {})
            safe_methods = sorted({
                str(value).upper()
                for value in (detail.get("methods") or [detail.get("method")])
                if value
            })
            safe_parameters = sorted({
                str(value).strip()
                for value in (detail.get("parameters") or detail.get("parameter_names") or [])
                if str(value).strip()
            })
            metadata: dict[str, Any] = {"original_url": url}
            if safe_methods:
                metadata["methods"] = safe_methods
            if safe_parameters:
                metadata["parameter_names"] = safe_parameters[:100]
            if detail.get("form") or detail.get("is_form"):
                metadata["is_form"] = True
            if detail.get("auth_signals"):
                metadata["auth_signals"] = sorted({
                    str(value).strip()
                    for value in detail.get("auth_signals", [])
                    if str(value).strip()
                })[:50]
            if detail.get("evidence_refs"):
                metadata["evidence_refs"] = [
                    str(value) for value in detail.get("evidence_refs", [])[:50]
                ]
            nodes[node_id] = MentalModelNode(
                id=node_id,
                kind=NodeKind.ENDPOINT,
                identity_key=normalised,
                discovery_source=discovery_source,
                in_scope=None,
                criticality=Criticality.LOW.value,
                metadata=metadata,
            ).model_dump(mode="json")
        # Add a SAME_HOST_AS edge to the endpoint's host, if derivable.
        try:
            parsed = urlparse(normalised)
            if parsed.hostname:
                host_node_id = _make_node_id("host", _normalise_host(parsed.hostname))
                if host_node_id in nodes or host_node_id in host_node_ids:
                    edges.append(MentalModelEdge(
                        kind=EdgeKind.SAME_HOST_AS,
                        source_id=node_id,
                        target_id=host_node_id,
                        source_ref="",  # Back-filled when Decision Log exists (Phase 6)
                    ).model_dump(mode="json"))
        except Exception:
            pass
            # Intentionally suppressed — reviewed 2026-09-03

    # -- CREDENTIAL nodes (fingerprinted; raw value NEVER stored) --
    for cred in (credentials or []):
        if not isinstance(cred, dict):
            continue
        value = cred.get("value") or ""
        if not value:
            continue
        fingerprint = _fingerprint_credential(value)
        if not fingerprint:
            continue
        cred_type = cred.get("type") or "unknown"
        node_id = _make_node_id("credential", fingerprint)
        if node_id not in nodes:
            nodes[node_id] = MentalModelNode(
                id=node_id,
                kind=NodeKind.CREDENTIAL,
                identity_key=fingerprint,
                discovery_source=discovery_source,
                in_scope=None,
                criticality=Criticality.CRITICAL.value,
                metadata={
                    "type": cred_type,
                    "source_url": cred.get("source") or "",
                    # NOTE: raw credential value deliberately NOT stored.
                },
            ).model_dump(mode="json")
        # AUTHENTICATES_TO edge to the root host, if known.
        for host_id in host_node_ids:
            edges.append(MentalModelEdge(
                kind=EdgeKind.AUTHENTICATES_TO,
                source_id=node_id,
                target_id=host_id,
                source_ref="",
            ).model_dump(mode="json"))

    # -- ARTIFACT nodes --
    for art in (artifacts or []):
        if not isinstance(art, dict):
            continue
        url = art.get("url") or ""
        art_type = art.get("type") or "unknown"
        if not url:
            continue
        # The identity_key for an artifact is its normalised URL.
        # (Phase 6 will add content-hash identity_keys for downloaded
        # artifacts — that's a Rabbit Hole concern, not an extraction
        # concern.)
        normalised = _normalise_url(url)
        if not normalised:
            continue
        node_id = _make_node_id("artifact", normalised)
        if node_id not in nodes:
            nodes[node_id] = MentalModelNode(
                id=node_id,
                kind=NodeKind.ARTIFACT,
                identity_key=normalised,
                discovery_source=discovery_source,
                in_scope=None,
                criticality=Criticality.MEDIUM.value,
                metadata={"type": art_type, "url": url},
            ).model_dump(mode="json")
        # REFERENCES edge to the root host.
        for host_id in host_node_ids:
            edges.append(MentalModelEdge(
                kind=EdgeKind.REFERENCES,
                source_id=node_id,
                target_id=host_id,
                source_ref="",
            ).model_dump(mode="json"))

    # -- TECHNOLOGY nodes --
    for tech in (technologies or []):
        if not tech or not isinstance(tech, str):
            continue
        t = tech.strip()
        if not t:
            continue
        node_id = _make_node_id("technology", t.lower())
        if node_id not in nodes:
            nodes[node_id] = MentalModelNode(
                id=node_id,
                kind=NodeKind.TECHNOLOGY,
                identity_key=t.lower(),
                discovery_source=discovery_source,
                in_scope=None,  # Technologies aren't scope-checkable — set in_scope=None
                criticality=Criticality.LOW.value,
                metadata={"name": t},
            ).model_dump(mode="json")

    # -- SERVICE nodes --
    for svc in (services or []):
        if not isinstance(svc, dict):
            continue
        port = svc.get("port")
        protocol = (svc.get("protocol") or "").lower()
        name = (svc.get("name") or "").lower()
        if port is None:
            continue
        identity = f"{port}/{protocol or 'tcp'}"
        node_id = _make_node_id("service", identity)
        if node_id not in nodes:
            nodes[node_id] = MentalModelNode(
                id=node_id,
                kind=NodeKind.SERVICE,
                identity_key=identity,
                discovery_source=discovery_source,
                in_scope=None,
                criticality=Criticality.MEDIUM.value,
                metadata={"port": int(port), "protocol": protocol, "name": name},
            ).model_dump(mode="json")

    # -- IDENTITY nodes --
    identity_lookup: dict[str, str] = {}
    for identity_record in (identities or []):
        if not isinstance(identity_record, dict):
            continue
        identity_ref = (
            identity_record.get("ref")
            or identity_record.get("id")
            or identity_record.get("identity_ref")
        )
        if not identity_ref:
            continue
        identity_label = str(identity_ref)
        identity_key = _fingerprint_credential(identity_label)
        node_id = _make_node_id("identity", identity_key)
        identity_lookup[identity_label] = node_id
        metadata: dict[str, Any] = {
            "identity_ref": identity_key,
        }
        for field_name in ("role", "auth_pattern", "ownership_signal"):
            value = identity_record.get(field_name)
            if value:
                metadata[field_name] = str(value)[:200]
        if identity_record.get("evidence_refs"):
            metadata["evidence_refs"] = [
                str(value) for value in identity_record.get("evidence_refs", [])[:50]
            ]
        if node_id not in nodes:
            nodes[node_id] = MentalModelNode(
                id=node_id,
                kind=NodeKind.IDENTITY,
                identity_key=identity_key,
                discovery_source=discovery_source,
                in_scope=None,
                criticality=Criticality.HIGH.value,
                metadata=metadata,
            ).model_dump(mode="json")

    # -- OBJECT nodes --
    object_lookup: dict[str, str] = {}
    for object_record in (objects or []):
        if not isinstance(object_record, dict):
            continue
        object_type = str(
            object_record.get("type")
            or object_record.get("kind")
            or "object"
        ).strip()
        object_ref = (
            object_record.get("ref")
            or object_record.get("id")
            or object_record.get("object_id")
        )
        if not object_ref:
            continue
        object_label = f"{object_type}:{object_ref}"
        object_key = _fingerprint_credential(object_label)
        node_id = _make_node_id("object", object_key)
        object_lookup[str(object_ref)] = node_id
        object_lookup[object_label] = node_id
        metadata = {
            "object_type": object_type[:100],
            "object_ref": object_key,
        }
        object_url = object_record.get("url") or object_record.get("endpoint")
        if isinstance(object_url, str) and _URL_RE.match(object_url.strip()):
            metadata["url"] = _normalise_url(object_url)
        if object_record.get("evidence_refs"):
            metadata["evidence_refs"] = [
                str(value) for value in object_record.get("evidence_refs", [])[:50]
            ]
        if node_id not in nodes:
            nodes[node_id] = MentalModelNode(
                id=node_id,
                kind=NodeKind.OBJECT,
                identity_key=object_key,
                discovery_source=discovery_source,
                in_scope=None,
                criticality=Criticality.MEDIUM.value,
                metadata=metadata,
            ).model_dump(mode="json")
        owner_ref = object_record.get("owner_identity") or object_record.get("owner_ref")
        owner_node_id = identity_lookup.get(str(owner_ref))
        if owner_node_id:
            edges.append(MentalModelEdge(
                kind=EdgeKind.OWNS,
                source_id=owner_node_id,
                target_id=node_id,
                source_ref=str((object_record.get("evidence_refs") or [""])[0]),
            ).model_dump(mode="json"))

    # -- WORKFLOW nodes --
    workflow_lookup: dict[str, str] = {}
    for workflow_record in (workflows or []):
        if not isinstance(workflow_record, dict):
            continue
        workflow_ref = (
            workflow_record.get("ref")
            or workflow_record.get("id")
            or workflow_record.get("name")
        )
        if not workflow_ref:
            continue
        steps: list[dict[str, Any]] = []
        endpoint_ids: list[str] = []
        for step in workflow_record.get("steps") or []:
            if not isinstance(step, dict):
                continue
            step_url = step.get("url") or step.get("endpoint") or step.get("action_url")
            safe_step: dict[str, Any] = {}
            if isinstance(step_url, str) and _URL_RE.match(step_url.strip()):
                step_normalised = _normalise_url(step_url)
                safe_step["endpoint"] = step_normalised
                endpoint_id = _make_node_id("endpoint", step_normalised)
                if endpoint_id in nodes:
                    endpoint_ids.append(endpoint_id)
            for field_name in (
                "method",
                "action",
                "from_state",
                "to_state",
                "state_from",
                "state_to",
            ):
                if step.get(field_name) is not None:
                    safe_step[field_name] = str(step[field_name])[:100]
            if step.get("evidence_refs"):
                safe_step["evidence_refs"] = [
                    str(value) for value in step.get("evidence_refs", [])[:20]
                ]
            if safe_step:
                steps.append(safe_step)
        workflow_key = _fingerprint_credential(f"workflow:{workflow_ref}:{steps}")
        node_id = _make_node_id("workflow", workflow_key)
        workflow_lookup[str(workflow_ref)] = node_id
        metadata = {
            "workflow_ref": workflow_key,
            "steps": steps[:100],
        }
        for field_name in ("required_role", "auth_pattern"):
            if workflow_record.get(field_name):
                metadata[field_name] = str(workflow_record[field_name])[:200]
        if workflow_record.get("evidence_refs"):
            metadata["evidence_refs"] = [
                str(value) for value in workflow_record.get("evidence_refs", [])[:50]
            ]
        if node_id not in nodes:
            nodes[node_id] = MentalModelNode(
                id=node_id,
                kind=NodeKind.WORKFLOW,
                identity_key=workflow_key,
                discovery_source=discovery_source,
                in_scope=None,
                criticality=Criticality.MEDIUM.value,
                metadata=metadata,
            ).model_dump(mode="json")
        for endpoint_id in endpoint_ids:
            edges.append(MentalModelEdge(
                kind=EdgeKind.CONTAINS,
                source_id=node_id,
                target_id=endpoint_id,
                source_ref=str((workflow_record.get("evidence_refs") or [""])[0]),
            ).model_dump(mode="json"))

    # -- Explicit typed relations --
    relation_kinds = {kind.value for kind in EdgeKind}
    endpoint_lookup = {
        str(node.get("identity_key")): node_id
        for node_id, node in nodes.items()
        if node.get("kind") == NodeKind.ENDPOINT.value
    }

    def _resolve_relation_ref(value: Any) -> str | None:
        if value is None:
            return None
        candidate = str(value)
        if candidate in nodes:
            return candidate
        if candidate in identity_lookup:
            return identity_lookup[candidate]
        if candidate in object_lookup:
            return object_lookup[candidate]
        if candidate in workflow_lookup:
            return workflow_lookup[candidate]
        normalised_candidate = _normalise_url(candidate)
        if normalised_candidate in endpoint_lookup:
            return endpoint_lookup[normalised_candidate]
        return None

    for relation in (relations or []):
        if not isinstance(relation, dict):
            continue
        kind = str(relation.get("kind") or relation.get("relation") or "").lower()
        if kind not in relation_kinds:
            continue
        source_id = _resolve_relation_ref(relation.get("source") or relation.get("source_ref"))
        target_id = _resolve_relation_ref(relation.get("target") or relation.get("target_ref"))
        if not source_id or not target_id or source_id == target_id:
            continue
        evidence_refs = relation.get("evidence_refs") or []
        source_ref = (
            str(evidence_refs[0])
            if evidence_refs
            else str(relation.get("evidence_ref") or "")
        )
        edges.append(MentalModelEdge(
            kind=kind,
            source_id=source_id,
            target_id=target_id,
            source_ref=source_ref,
        ).model_dump(mode="json"))

    return {"nodes": nodes, "edges": edges}


# ---------------------------------------------------------------------------
# Query interface — used by Dynamic Prioritization (Phase 3) and
# Rabbit Hole's Loop Prevention (Phase 6)
# ---------------------------------------------------------------------------
def _coerce_to_mental_model(mental_model_state: Any) -> MentalModel:
    """Coerce a PentestState.mental_model value into a MentalModel.

    The state field is ``dict[str, Any]`` (merged by ``merge_dicts``),
    so callers pass a dict, not a MentalModel instance. This helper
    reconstructs the typed model for query convenience. Tolerates
    missing keys, malformed entries, and partial dicts — never raises.
    """
    if mental_model_state is None:
        return MentalModel()
    if isinstance(mental_model_state, MentalModel):
        return mental_model_state
    if not isinstance(mental_model_state, dict):
        return MentalModel()

    raw_nodes = mental_model_state.get("nodes") or {}
    raw_edges = mental_model_state.get("edges") or []

    nodes: dict[str, MentalModelNode] = {}
    for nid, nd in raw_nodes.items():
        try:
            if isinstance(nd, MentalModelNode):
                nodes[str(nid)] = nd
            elif isinstance(nd, dict):
                nodes[str(nid)] = MentalModelNode(**nd)
        except Exception:
            continue

    edges: list[MentalModelEdge] = []
    for ed in raw_edges:
        try:
            if isinstance(ed, MentalModelEdge):
                edges.append(ed)
            elif isinstance(ed, dict):
                edges.append(MentalModelEdge(**ed))
        except Exception:
            continue

    return MentalModel(nodes=nodes, edges=edges)


def query_unexplored_high_value_nodes(
    mental_model_state: Any,
    *,
    min_criticality: str = Criticality.MEDIUM.value,
) -> list[MentalModelNode]:
    """Return unexplored high-value nodes, sorted by criticality desc.

    Used by Dynamic Prioritization (Phase 3) to find the next
    promising investigation target. "Unexplored" means the node has
    no inbound ``DISCOVERED_VIA`` edge from a confirmed Finding —
    i.e., no finding has been produced that investigates this node.

    "High-value" is defined by ``min_criticality`` — only nodes with
    criticality >= this threshold are returned. Default is MEDIUM,
    which excludes only LOW-criticality nodes (generic endpoints and
    technology fingerprints). Pass CRITICAL to find only credentials
    and apparent production data stores.

    The result is sorted by criticality tier (CRITICAL > HIGH >
    MEDIUM > LOW) and then by discovery_source (deterministic
    tiebreak). The LLM is NEVER asked to pick from this list — the
    caller (Dynamic Prioritization) does deterministic arithmetic
    over the list using the Phase 3 scoring formula.
    """
    model = _coerce_to_mental_model(mental_model_state)

    # Collect IDs of nodes that have an inbound DISCOVERED_VIA edge
    # from a finding/hypothesis (i.e., already investigated).
    investigated_ids: set[str] = set()
    for edge in model.edges:
        if edge.kind == EdgeKind.DISCOVERED_VIA.value:
            investigated_ids.add(edge.target_id)

    rank = {
        Criticality.CRITICAL.value: 3,
        Criticality.HIGH.value: 2,
        Criticality.MEDIUM.value: 1,
        Criticality.LOW.value: 0,
    }
    min_rank = rank.get(min_criticality, 1)

    candidates = [
        node for node in model.nodes.values()
        if node.id not in investigated_ids
        and rank.get(node.criticality, 0) >= min_rank
    ]
    candidates.sort(
        key=lambda n: (
            -rank.get(n.criticality, 0),
            n.discovery_source,
            n.id,
        )
    )
    return candidates


def is_asset_already_visited(
    mental_model_state: Any,
    identity_key: str,
) -> bool:
    """Return True iff an asset with this identity_key is already in the Mental Model.

    Used by Rabbit Hole's Loop Prevention (Phase 6) — the direct
    generalization of ``exploit_chainer._already_proposed_pairs``.
    Before any Rabbit Hole action, the artifact's normalised identity
    (canonical URL / content hash / credential fingerprint) is
    checked against the Mental Model. Already visited -> stop, log
    it, done.

    Args:
        mental_model_state: The PentestState.mental_model value.
        identity_key: The normalised identity key to check (e.g.
            canonicalised URL for an endpoint, ``sha256:...`` for a
            credential fingerprint, ``sha256:...`` for an artifact
            content hash).

    Returns:
        True if any node in the Mental Model has this identity_key,
        False otherwise (including when the Mental Model is empty or
        malformed — fail-open for the query, the caller's
        Risk Manager check is the actual fail-closed gate).
    """
    if not identity_key:
        return False
    model = _coerce_to_mental_model(mental_model_state)
    return any(
        node.identity_key == identity_key for node in model.nodes.values()
    )


def classify_artifact_type(value: str) -> str | None:
    """Classify a string as a known artifact type, or None.

    Pure regex — NO LLM. Used by Rabbit Hole's deterministic
    classification gate (Phase 6 / Phase 7) to decide whether a
    discovered artifact is one the framework knows how to safely
    follow. Mirrors ``exploit_chainer._CHAIN_PATTERNS``: the "can we
    even consider this" question is answered by plain Python before
    any model call happens.

    V8 P0 A1: the pattern table was expanded to cover Dockerfile,
    .htaccess, web.config, wp-config.php, id_rsa, .htpasswd,
    .npmrc / .netrc / .pgpass / .aws/credentials / .ssh/known_hosts,
    .svn / .hg, .DS_Store, and source-code disclosures (.php/.java/.py
    served raw). Also feeds the recon agent's Mental Model extraction
    so Git/Dockerfile-style findings create ARTIFACT nodes in the same
    engagement run (Phase A1 DoD).

    Returns:
        One of: ``"archive"``, ``"config"``, ``"git_marker"``,
        ``"vcs_marker"``, ``"sql_dump"``, ``"backup"``,
        ``"source_code"``, ``"os_metadata"`` — or ``None`` if no
        pattern matches.
    """
    if not value or not isinstance(value, str):
        return None
    for art_type, pattern in _ARTIFACT_TYPE_PATTERNS:
        if pattern.search(value):
            return art_type
    return None


def classify_credential(value: str) -> str | None:
    """Classify a string as a known credential type, or None.

    Pure regex — NO LLM. Used by Rabbit Hole's deterministic
    classification gate (Phase 6 / Phase 7) and by the credential
    extractor above. Returns the credential type label
    (e.g. ``"AWS Access Key"``) or None.
    """
    if not value or not isinstance(value, str):
        return None
    for cred_type, pattern in _CREDENTIAL_PATTERNS:
        if pattern.search(value):
            return cred_type
    return None
