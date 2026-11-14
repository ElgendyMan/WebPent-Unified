# src/webpent/shared/cognitive_components.py
"""webpent.shared.cognitive_components

V7 Cognitive Upgrade — Phase 6 batch: the smaller composition
components that Dynamic Prioritization (Phase 3), Self-Critique
(Phase 5), and Rabbit Hole (Phase 7) consume.

This module groups the Phase 6 batch components that are pure functions
or small lookup tables (NOT nodes, NOT Pydantic models, NOT manager
classes — those have their own modules):

  * **Evidence Quality Assessment** — :func:`compute_evidence_quality_score`
  * **Cost vs Value Evaluation** — :data:`ACTION_COST_TABLE`,
    :func:`estimate_action_cost`
  * **Pattern Recognition (deterministic artifact-pattern table)** —
    :data:`ARTIFACT_FOLLOW_PATTERNS`, :func:`classify_followable_artifact`
  * **Online Learning** — :data:`ONLINE_LEARNING_DELTAS`,
    :func:`apply_online_learning_delta`
  * **Loop Prevention** — :func:`check_loop_prevention`,
    :func:`record_visited_asset`

All deterministic — no LLM. Per Phase 6 spec: "All new
prioritization/curiosity/confidence scoring stays deterministic
arithmetic over LLM-provided *signals*, never an LLM-provided
*decision*."
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ===========================================================================
# 1. Evidence Quality Assessment
# ===========================================================================
# Per Phase 6 spec: "the smallest lift in the whole plan. It's a
# scoring function composed almost entirely from fields and utilities
# that already exist: presence of ``evidence_bundle`` (mini-HAR),
# presence and validity of ``evidence_hash``, whether ``canary_token``
# was matched, and whether ``shared/grounding.py``'s existing
# ``verify_citation``/``baseline_differential_test`` primitives passed.
# No new evidence-capture mechanism is needed — this phase is purely
# 'write the scoring function over data that's already collected.'"

# Evidence quality component weights — deterministic, code-change-only.
_W_EVIDENCE_BUNDLE: float = 0.30   # mini-HAR present
_W_EVIDENCE_HASH: float = 0.25     # hash present + valid
_W_CANARY_MATCHED: float = 0.25    # canary token was matched
_W_GROUNDING_PASSED: float = 0.20  # verify_citation/baseline_differential passed


def compute_evidence_quality_score(
    *,
    has_evidence_bundle: bool = False,
    evidence_hash_valid: bool = False,
    canary_matched: bool = False,
    grounding_passed: bool = False,
) -> float:
    """Compute a deterministic evidence-quality score in [0, 1].

    Pure Python over boolean signals — no LLM. The score is the
    weighted sum of four components, each contributing its weight
    when the corresponding signal is True. The output is suitable
    for direct use as the ``evidence_quality`` input to
    :func:`webpent.shared.prioritization.score_hypothesis`.

    Args:
        has_evidence_bundle: True if the finding has a non-None
            ``evidence_bundle`` (mini-HAR dict).
        evidence_hash_valid: True if ``evidence_hash`` is present
            AND matches a re-computation over ``evidence_bundle``.
            (The caller does the re-computation; this function only
            consumes the boolean result.)
        canary_matched: True if the validator found the
            ``canary_token`` in the HTTP response.
        grounding_passed: True if ``shared/grounding.py``'s
            ``verify_citation`` AND ``baseline_differential_test``
            both passed for this finding.

    Returns:
        A float in [0, 1]. Each True signal adds its weight; the sum
        is clamped to [0, 1] defensively (should already be in range
        since the weights sum to 1.0, but a future contributor could
        add a component without re-normalising).
    """
    score = 0.0
    if has_evidence_bundle:
        score += _W_EVIDENCE_BUNDLE
    if evidence_hash_valid:
        score += _W_EVIDENCE_HASH
    if canary_matched:
        score += _W_CANARY_MATCHED
    if grounding_passed:
        score += _W_GROUNDING_PASSED
    return max(0.0, min(1.0, score))


# ===========================================================================
# 2. Cost vs Value Evaluation
# ===========================================================================
# Per Phase 6 spec: "Cost is estimated from a small deterministic
# lookup table keyed by action type (download+parse an archive = low
# cost; brute-force follow-up = high cost; new-host recon = medium
# cost), mirroring the lookup-table style already used for
# ``_CHAIN_PATTERNS``."

class ActionType(str, Enum):
    """Closed set of action types the framework can take.

    The cost lookup table is keyed by these types. Adding a new action
    type is a code change — keeps the cost vocabulary stable and
    auditable. Per Phase 6: "mirroring the lookup-table style already
    used for ``_CHAIN_PATTERNS``."
    """

    READ_ONLY_PARSE = "read_only_parse"               # grep a file for patterns
    DOWNLOAD_AND_PARSE_ARCHIVE = "download_and_parse_archive"  # .zip / .tar.gz
    READ_CONFIG_FILE = "read_config_file"             # docker-compose.yml, .env
    NEW_HOST_RECON = "new_host_recon"                 # httpx against a new host
    NEW_ENDPOINT_PROBE = "new_endpoint_probe"         # hypothesis on a new URL
    CREDENTIAL_TEST = "credential_test"               # test creds against a service
    BRUTE_FORCE_FOLLOWUP = "brute_force_followup"     # enumeration / fuzzing


# Deterministic cost lookup table — values in "action units" (0-10 scale).
# Per Phase 6: "download+parse an archive = low cost; brute-force
# follow-up = high cost; new-host recon = medium cost."
ACTION_COST_TABLE: dict[str, float] = {
    ActionType.READ_ONLY_PARSE.value: 1.0,
    ActionType.DOWNLOAD_AND_PARSE_ARCHIVE.value: 3.0,
    ActionType.READ_CONFIG_FILE.value: 2.0,
    ActionType.NEW_HOST_RECON.value: 5.0,
    ActionType.NEW_ENDPOINT_PROBE.value: 3.0,
    ActionType.CREDENTIAL_TEST.value: 7.0,
    ActionType.BRUTE_FORCE_FOLLOWUP.value: 9.0,
}


def estimate_action_cost(action_type: ActionType | str) -> float:
    """Return the deterministic cost estimate for an action type.

    Pure lookup — no LLM, no heuristic. Unknown action types default
    to the median cost (5.0) so a future contributor adding a new
    ActionType without updating the table doesn't get a silent zero.
    """
    at_str = (
        action_type.value
        if isinstance(action_type, ActionType)
        else str(action_type).lower()
    )
    return ACTION_COST_TABLE.get(at_str, 5.0)


# ===========================================================================
# 3. Pattern Recognition (deterministic artifact-pattern table)
# ===========================================================================
# Per Phase 6 spec: "A deterministic artifact-pattern table (new,
# small, same shape as ``_CHAIN_PATTERNS``) classifying which
# discovered artifact *types* are worth following at all (archives,
# config/compose files, ``.git`` markers, credential-shaped strings,
# IP-literal hosts). This is the actual decision mechanism for Rabbit
# Hole and must stay deterministic."
#
# This is the decision mechanism — the extraction-side classifiers
# (classify_artifact_type, classify_credential) already exist in
# webpent.models.mental_model. This table maps artifact types to
# (followable: bool, action_type: ActionType, forced_hitl_category: str|None).

class FollowableArtifactType(str, Enum):
    """Closed set of artifact types Rabbit Hole knows how to follow.

    Mirrors the artifact-type classification in
    :mod:`webpent.models.mental_model` but adds the follow-up metadata
    (action type + forced-HITL category) that the Phase 7 Rabbit Hole
    node needs. Adding a new followable type is a code change — keeps
    the recursion vocabulary closed and auditable.

    V8 P0 A1: added VCS_MARKER, SOURCE_CODE, OS_METADATA to mirror
    the expanded ``_ARTIFACT_TYPE_PATTERNS`` table in
    :mod:`webpent.models.mental_model`. These are all followable
    (read-only parse / config read).
    """

    ARCHIVE = "archive"
    CONFIG = "config"
    GIT_MARKER = "git_marker"
    VCS_MARKER = "vcs_marker"           # .svn / .hg / .bzr — read-only parse
    SQL_DUMP = "sql_dump"
    BACKUP = "backup"
    SOURCE_CODE = "source_code"         # .php/.java/.py served raw
    OS_METADATA = "os_metadata"         # .DS_Store
    CREDENTIAL_STRING = "credential_string"
    IP_LITERAL_HOST = "ip_literal_host"


# Deterministic follow-table: artifact_type -> (followable, action_type, forced_hitl_category)
# Per Phase 6: "the actual decision mechanism for Rabbit Hole and must
# stay deterministic." forced_hitl_category maps to
# RabbitHolePolicy.forced_hitl_categories — None means no forced HITL.
# The forced_hitl_category string literals MUST match
# webpent.config.policies.ForcedHITLCategory's enum values exactly.
ARTIFACT_FOLLOW_PATTERNS: dict[str, tuple[bool, str, str | None]] = {
    FollowableArtifactType.ARCHIVE.value: (
        True,
        ActionType.DOWNLOAD_AND_PARSE_ARCHIVE.value,
        None,
    ),
    FollowableArtifactType.CONFIG.value: (
        True,
        ActionType.READ_CONFIG_FILE.value,
        None,
    ),
    FollowableArtifactType.GIT_MARKER.value: (
        True,
        ActionType.READ_ONLY_PARSE.value,
        None,
    ),
    FollowableArtifactType.VCS_MARKER.value: (
        True,
        ActionType.READ_ONLY_PARSE.value,
        None,
    ),
    FollowableArtifactType.SQL_DUMP.value: (
        True,
        ActionType.READ_ONLY_PARSE.value,
        "apparent_production_datastore",  # ForcedHITLCategory.APPARENT_PRODUCTION_DATASTORE
    ),
    FollowableArtifactType.BACKUP.value: (
        True,
        ActionType.DOWNLOAD_AND_PARSE_ARCHIVE.value,
        None,
    ),
    FollowableArtifactType.SOURCE_CODE.value: (
        True,
        ActionType.READ_ONLY_PARSE.value,
        None,
    ),
    FollowableArtifactType.OS_METADATA.value: (
        True,
        ActionType.READ_ONLY_PARSE.value,
        None,
    ),
    FollowableArtifactType.CREDENTIAL_STRING.value: (
        True,
        ActionType.CREDENTIAL_TEST.value,
        "credential_material",  # ForcedHITLCategory.CREDENTIAL_MATERIAL
    ),
    FollowableArtifactType.IP_LITERAL_HOST.value: (
        True,
        ActionType.NEW_HOST_RECON.value,
        None,  # scope re-check handles out-of-scope hosts; not a forced HITL here
    ),
}


def classify_followable_artifact(
    artifact_type: str,
) -> tuple[bool, str, str | None] | None:
    """Return ``(followable, action_type, forced_hitl_category)`` or None.

    Pure lookup — no LLM. The Phase 7 Rabbit Hole node calls this
    after the extraction-side classifier
    (:func:`webpent.models.mental_model.classify_artifact_type` or
    :func:`classify_credential`) has determined the artifact's type.
    A return of None means "not a known followable type" — Rabbit
    Hole does nothing (per Phase 7: "If it doesn't match a known
    pattern, nothing happens — no LLM is asked to freely speculate").
    """
    if not artifact_type:
        return None
    return ARTIFACT_FOLLOW_PATTERNS.get(artifact_type.strip().lower())


# ===========================================================================
# 4. Online Learning — fixed deterministic deltas
# ===========================================================================
# Per Phase 6 spec: "not a separate node. It's the behavior where any
# node producing new evidence emits a small, fixed-size confidence
# delta applied to the related Hypothesis/Mental Model entry (e.g.
# 'tool-confirmed evidence found for a related hypothesis: +0.3';
# 'Devil's Advocate debunked a related finding: −0.4'). Deliberately
# implemented as fixed deterministic deltas, not a full Bayesian
# inference engine — auditable, debuggable, and consistent with
# 'no LLM deciding critical security-relevant values.'"
#
# These deltas are consumed by
# :func:`webpent.shared.confidence.compute_confidence_score` via its
# ``online_learning_deltas`` parameter. The caller collects the deltas
# that fired for a hypothesis and passes them as a list.

class OnlineLearningEvent(str, Enum):
    """Closed set of Online Learning events.

    Each event maps to a fixed deterministic delta in
    :data:`ONLINE_LEARNING_DELTAS`. Adding a new event is a code
    change — keeps the confidence-adjustment vocabulary stable and
    auditable.

    V8 P0 D3: Added VALIDATION_FAILED_* events for the failure-to-
    hypothesis learning loop. When the validator records a specific
    failure reason on a finding (see
    agents/validator/agent.py:_classify_validator_failure), the
    matching event here is fired against the finding's related
    hypothesis (linked via finding.hypothesis_id), deterministically
    adjusting its confidence_score. This turns validation failures
    into intelligence rather than dead ends — the system stops
    repeating the same weak approach and improves targeting inside
    one engagement.
    """

    TOOL_CONFIRMED_RELATED_EVIDENCE = "tool_confirmed_related_evidence"
    DEVILS_ADVOCATE_DEBUNKED_RELATED = "devils_advocate_debunked_related"
    RABBIT_HOLE_BRANCH_FOUND_ARTIFACT = "rabbit_hole_branch_found_artifact"
    RABBIT_HOLE_BRANCH_HIT_DEAD_END = "rabbit_hole_branch_hit_dead_end"
    SCOPE_CHECK_BLOCKED_RELATED = "scope_check_blocked_related"
    # V8 P0 D3: validation-failure learning events.
    # Map 1:1 to the failure reasons recorded by
    # _classify_validator_failure in agents/validator/agent.py.
    VALIDATION_FAILED_WAF_BLOCKED = "validation_failed_waf_blocked"
    VALIDATION_FAILED_AUTH_REQUIRED = "validation_failed_auth_required"
    VALIDATION_FAILED_LLM_REJECTED = "validation_failed_llm_rejected"
    VALIDATION_FAILED_TOOL_NO_MARKER = "validation_failed_tool_no_marker"


# Fixed deterministic deltas — per Phase 6: "fixed deterministic deltas,
# not a full Bayesian inference engine." Values are deliberately small
# so a single event can't flip a hypothesis from low to high confidence
# on its own. The cumulative cap is enforced by
# :func:`webpent.shared.confidence.compute_confidence_score`.
#
# V8 P0 D3: Added VALIDATION_FAILED_* deltas. All are NEGATIVE (a
# validation failure reduces the related hypothesis's confidence —
# the hypothesis was wrong about the endpoint being exploitable in
# this way). Magnitudes:
#   - WAF_BLOCKED: -0.05 (mild — the vuln may still exist, just needs
#     different obfuscation; the hypothesis is still plausible).
#   - TOOL_NO_MARKER: -0.05 (mild — same rationale as WAF_BLOCKED).
#   - AUTH_REQUIRED: -0.10 (moderate — the hypothesis was wrong about
#     the endpoint being exploitable without auth; bigger confidence hit).
#   - LLM_REJECTED: -0.10 (moderate — the LLM supervisor saw the marker
#     and rejected it as a false positive; significant confidence hit).
# All deltas are bounded by the cumulative cap in compute_confidence_score
# (which clamps the final score to [0, 1]) — no unbounded learning.
ONLINE_LEARNING_DELTAS: dict[str, float] = {
    OnlineLearningEvent.TOOL_CONFIRMED_RELATED_EVIDENCE.value: 0.10,
    OnlineLearningEvent.DEVILS_ADVOCATE_DEBUNKED_RELATED.value: -0.10,
    OnlineLearningEvent.RABBIT_HOLE_BRANCH_FOUND_ARTIFACT.value: 0.05,
    OnlineLearningEvent.RABBIT_HOLE_BRANCH_HIT_DEAD_END.value: -0.05,
    OnlineLearningEvent.SCOPE_CHECK_BLOCKED_RELATED.value: -0.10,
    # V8 P0 D3: validation-failure deltas.
    OnlineLearningEvent.VALIDATION_FAILED_WAF_BLOCKED.value: -0.05,
    OnlineLearningEvent.VALIDATION_FAILED_AUTH_REQUIRED.value: -0.10,
    OnlineLearningEvent.VALIDATION_FAILED_LLM_REJECTED.value: -0.10,
    OnlineLearningEvent.VALIDATION_FAILED_TOOL_NO_MARKER.value: -0.05,
}


def apply_online_learning_delta(
    event: OnlineLearningEvent | str,
) -> float:
    """Return the fixed deterministic delta for an Online Learning event.

    Pure lookup — no LLM. Unknown events return 0.0 (neutral) so a
    future contributor adding a new event without updating the table
    doesn't get a silent large delta.
    """
    e_str = (
        event.value
        if isinstance(event, OnlineLearningEvent)
        else str(event).lower()
    )
    return ONLINE_LEARNING_DELTAS.get(e_str, 0.0)


# ===========================================================================
# 5. Loop Prevention — visited-assets ledger
# ===========================================================================
# Per Phase 6 spec: "the direct generalization of ``exploit_chainer``'s
# existing ``_already_proposed_pairs``/``_MAX_PAIRS_EXAMINED``/
# ``_MAX_CHAINS_PROPOSED`` pattern, applied to the Mental Model
# instead of to finding-pairs: a 'visited assets' ledger (normalized
# URL / file content hash / credential fingerprint) checked before
# any Rabbit Hole action, plus hard caps on depth and total branches."
#
# The ledger lives in PentestState.rabbit_hole_ledger as a dict
# (merge_dicts reducer). Keyed by normalised identity; value is the
# discovery_source that first visited the asset.

def check_loop_prevention(
    rabbit_hole_ledger: Any,
    identity_key: str,
) -> bool:
    """Return True if ``identity_key`` is already in the visited-assets ledger.

    The direct generalization of ``exploit_chainer._already_proposed_pairs``.
    Pure dict lookup — no LLM. The Phase 7 Rabbit Hole node calls this
    BEFORE any branch action; already-visited -> stop, log it, done.

    Args:
        rabbit_hole_ledger: The ``PentestState.rabbit_hole_ledger``
            value (a dict, possibly empty or None).
        identity_key: The normalised identity key to check (canonical
            URL, ``sha256:...`` content hash, or ``sha256:...``
            credential fingerprint).

    Returns:
        True if the asset was already visited; False otherwise (including
        when the ledger is empty/None — fail-open for the query, the
        caller's Risk Manager check is the actual fail-closed gate).
    """
    if not identity_key:
        return False
    if not rabbit_hole_ledger or not isinstance(rabbit_hole_ledger, dict):
        return False
    return identity_key in rabbit_hole_ledger


def record_visited_asset(
    rabbit_hole_ledger: Any,
    identity_key: str,
    *,
    discovery_source: str,
    branch_id: str | None = None,
) -> dict[str, Any]:
    """Return a state update that records ``identity_key`` as visited.

    Pure function — returns a partial state update (shaped for
    ``merge_dicts``) that the caller applies by returning it from a
    LangGraph node. Does NOT mutate the input ledger.

    Args:
        rabbit_hole_ledger: The current ledger (used only to check
            for prior visits; not mutated).
        identity_key: The normalised identity key to record.
        discovery_source: Which node/action visited this asset.
        branch_id: Optional Rabbit Hole branch ID.

    Returns:
        A dict ``{identity_key: {discovery_source, branch_id, timestamp}}``
        ready for ``merge_dicts`` into ``state["rabbit_hole_ledger"]``.
        Empty dict if ``identity_key`` is empty or already visited.
    """
    if not identity_key:
        return {}
    if check_loop_prevention(rabbit_hole_ledger, identity_key):
        # Already visited — no-op (idempotent).
        return {}
    from datetime import datetime, timezone
    return {
        identity_key: {
            "discovery_source": discovery_source,
            "branch_id": branch_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    }


# ---------------------------------------------------------------------------
# Internal: ForcedHITLCategory string constants (avoid circular import
# with config.policies). The ARTIFACT_FOLLOW_PATTERNS table above uses
# these string literals directly so there's no import-time dependency
# on config.policies.
# ---------------------------------------------------------------------------
class ForcedHITLCategories:
    """String constants matching webpent.config.policies.ForcedHITLCategory.

    Kept as plain string constants here to avoid a circular import
    (config.policies imports nothing from this module, but this module
    is imported by shared.prioritization which is imported by agents
    that config.policies's neighbors import). The values MUST match
    ForcedHITLCategory's enum values exactly.
    """

    CREDENTIAL_MATERIAL = "credential_material"
    APPARENT_PRODUCTION_DATASTORE = "apparent_production_datastore"
    OUT_OF_SCOPE_HOST = "out_of_scope_host"
