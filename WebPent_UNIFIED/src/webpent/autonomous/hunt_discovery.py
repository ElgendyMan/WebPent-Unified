# src/webpent/autonomous/hunt_discovery.py
"""Adaptive discovery engine — the hunt loop that builds its own checklist.

Suggestion 3 of the autonomous-bug-hunter series, mapped onto this
codebase's governance (see docs/plans/2026-10-14-v74-critique.md):

  * ADVISORY-ONLY: every function here returns candidate records; nothing
    is executed, scheduled, or confirmed. Candidates enter the loop only
    through ``hunt_replanning``'s bounded merge, i.e. through the same
    planner/executor gates as every other seed.
  * EVIDENCE-BOUNDED: hybrid scenarios are built only from capability
    records that themselves carry evidence references; a scenario is a
    hypothesis with a test plan, never a finding. The ``/admin`` route
    sibling is minted only when observed evidence names an admin surface.
  * SAME-ORIGIN: minted route/parameter candidates never leave the
    target origin (scheme + host + effective port of the recorded URL).
    Endpoint mining is metadata-only and carries no origin claim: it
    extracts path-like strings from whatever the loop already recorded.
  * CONVERGENT: discovery candidates participate in the ordinary
    convergence accounting — a round whose only output is candidates that
    duplicate already-seen actions produces no new evidence and the loop
    still moves toward its typed stop reasons.
  * DETERMINISTIC: pure functions over the round's outcome records, no
    LLM, no wall-clock, no randomness; thresholds are constants paired
    with minimum-sample rules AND absolute floors so two outliers (or two
    tiny magnitudes) cannot become a signal.

  EXPLICIT NON-CLAIM: in the current loop only the strong-anomaly
  hypothesis seeds are consumed (through the re-hypothesis merge gate).
  Route, endpoint, parameter and hybrid candidates are advisory
  inventory for the operator report and future consumers; nothing
  executes, schedules, or confirms them.

Pipeline (all bounded, in call order):

    monitor_anomalies -> classify_anomalies -> anomalies_to_hypotheses
    infer_route_patterns / infer_parameters / mine_endpoints
    generate_hybrid_scenarios / allocate_uncertainty_budget
    build_discovery_agenda
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Final
from urllib.parse import urlsplit, urlunsplit

__all__ = [
    "allocate_uncertainty_budget",
    "anomalies_to_hypotheses",
    "build_discovery_agenda",
    "classify_anomalies",
    "discover_from_records",
    "generate_hybrid_scenarios",
    "infer_parameters",
    "infer_route_patterns",
    "mine_endpoints",
    "monitor_anomalies",
]

# ---------------------------------------------------------------------------
# constants — thresholds are paired with minimum-sample rules (critique B4)
# ---------------------------------------------------------------------------

_TIMING_DIVERGENCE: Final[float] = 0.30
_SIZE_DIVERGENCE: Final[float] = 0.20
# Each relative threshold is paired with an absolute minimum delta so
# small-magnitude noise (3 vs 4 bytes, 10 vs 20 ms) can never fire.
_SIZE_ABSOLUTE_FLOOR: Final[int] = 64  # bytes
_TIMING_ABSOLUTE_FLOOR_MS: Final[int] = 150  # milliseconds
_MIN_SAMPLES_PER_SIGNAL: Final[int] = 2
_MIN_STRONG_REPEATS: Final[int] = 2

_MAX_ANOMALIES: Final[int] = 24
_MAX_ROUTES: Final[int] = 16
_MAX_PARAMS: Final[int] = 12
_MAX_ENDPOINTS: Final[int] = 16
_MAX_HYBRIDS: Final[int] = 6
_MAX_HYPOTHESES: Final[int] = 8

_STATIC_EXTENSIONS: Final[frozenset[str]] = frozenset(
    {
        ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
        ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".mp4", ".mp3",
    }
)

# A generic probe identity: enough to group same-endpoint observations.
_PROBE_ID_KEYS: Final[tuple[str, ...]] = ("url", "path", "endpoint", "task_id", "probe")
_STATUS_KEYS: Final[tuple[str, ...]] = ("status_code", "status", "http_status")
_SIZE_KEYS: Final[tuple[str, ...]] = ("content_length", "body_size", "size", "body_bytes")
_TIMING_KEYS: Final[tuple[str, ...]] = ("elapsed_ms", "latency_ms", "duration_ms")
_ERROR_TEXT_KEYS: Final[tuple[str, ...]] = ("error", "error_message", "message", "reason")

_PATH_TOKEN: Final[re.Pattern[str]] = re.compile(r"(?:/[A-Za-z0-9_.\-*]+){1,8}")
_INTEGER_SEGMENT: Final[re.Pattern[str]] = re.compile(r"\b\d{3,}\b")
_HEX_SEGMENT: Final[re.Pattern[str]] = re.compile(r"\b[0-9a-fA-F]{16,}\b")
_UUID_SEGMENT: Final[re.Pattern[str]] = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

# Sibling parameter names worth trying when a parameter name is observed.
_PARAM_SIBLINGS: Final[dict[str, tuple[str, ...]]] = {
    "id": ("user_id", "uid", "account", "profile_id"),
    "user_id": ("uid", "account", "id"),
    "uid": ("user_id", "account"),
    "account": ("user_id", "uid", "account_id"),
    "profile": ("profile_id", "username"),
    "email": ("username", "login", "user"),
    "file": ("path", "filename", "filepath"),
    "path": ("file", "filename"),
    "url": ("callback", "redirect", "next", "return_to"),
    "redirect": ("next", "return_to", "callback"),
    "page": ("per_page", "limit", "offset"),
    "limit": ("offset", "per_page", "size"),
}

# Evidence-backed capability pairing rules (critique B5): a hybrid scenario
# is only proposed when BOTH capabilities were observed on records that
# carry evidence references. Rules are (capability_a, capability_b, plan).
_HYBRID_RULES: Final[tuple[tuple[str, str, str], ...]] = (
    (
        "accepts_svg_upload",
        "renders_svg_content",
        "svg-with-relative-reference: probe the render path with an SVG "
        "carrying a harmless relative reference and a canary, observe "
        "whether the reference is fetched",
    ),
    (
        "accepts_content_upload_no_type_check",
        "serves_user_content_directly",
        "extension-spoof-upload: upload a text file under an image "
        "extension, then fetch the served URL to see how it is processed",
    ),
    (
        "serves_public_user_media",
        "no_object_authorization_on_media_path",
        "media-object-swap: request another user's media object id "
        "through the same public path and compare the response",
    ),
)

_CAPABILITY_PATTERNS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("accepts_svg_upload", ("svg", "upload", "image/svg")),
    ("renders_svg_content", ("svg-render", "svg-preview", "rendered_svg")),
    (
        "accepts_content_upload_no_type_check",
        ("no-content-type-check", "upload-without-validation"),
    ),
    ("serves_user_content_directly", ("direct-file-link", "served-content")),
    ("serves_public_user_media", ("public-media", "media-url")),
    (
        "no_object_authorization_on_media_path",
        ("media-unauthorized", "media-no-authz"),
    ),
)

_BUDGET_TIERS: Final[dict[str, float]] = {
    "documented": 0.15,
    "incidental": 0.35,
    "anomalous_unexplained": 0.50,
}


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _first_value(record: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = record.get(key)
        if value is not None:
            return value
    return None


def _probe_identity(record: dict[str, Any]) -> str | None:
    for key in _PROBE_ID_KEYS:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _as_int(value: Any) -> int | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number != number or number in (float("inf"), float("-inf")):
        return None
    return int(number)


def _coerce_origin(url: str) -> tuple[str, str, str] | None:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if not scheme or not host:
        return None
    port = parts.port
    netloc = f"{host}:{port}" if port else host
    return scheme, host, netloc


def _same_origin(candidate: str, origin: tuple[str, str, str]) -> bool:
    parsed = _coerce_origin(candidate)
    if parsed is None:
        return False
    scheme, host, netloc = parsed
    return scheme == origin[0] and host == origin[1] and netloc == origin[2]


def _is_static(path: str) -> bool:
    lowered = path.lower()
    return any(lowered.endswith(ext) for ext in _STATIC_EXTENSIONS)


def _seen_signature(kind: str, value: str) -> str:
    digest = hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()
    return f"{kind}:{digest[:24]}"


_MAX_STRINGIFY_DEPTH: Final[int] = 8
_MAX_STRINGS_PER_RECORD: Final[int] = 200


def _stringify_strings(record: dict[str, Any]) -> list[str]:
    """All string values in a record, bounded — for path mining only.

    The walk is bounded two ways, each enforcing its own rule: nesting
    deeper than ``_MAX_STRINGIFY_DEPTH`` levels is not descended into,
    and no more than ``_MAX_STRINGS_PER_RECORD`` strings are collected.
    """
    found: list[str] = []
    stack: list[tuple[Any, int]] = [(record, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_STRINGIFY_DEPTH or len(found) >= _MAX_STRINGS_PER_RECORD:
            continue
        if isinstance(current, dict):
            stack.extend((value, depth + 1) for value in current.values())
        elif isinstance(current, list):
            stack.extend((item, depth + 1) for item in current)
        elif isinstance(current, str):
            found.append(current)
    return found


# ---------------------------------------------------------------------------
# 1) anomaly monitoring + 2) classification
# ---------------------------------------------------------------------------

def monitor_anomalies(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn response-metadata differentials into suspect observations.

    Each signal requires ``_MIN_SAMPLES_PER_SIGNAL`` same-endpoint
    records before it can fire; magnitude thresholds are relative and
    every observation carries its raw numbers for the classifier.
    """
    grouped: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        probe = _probe_identity(record)
        if not probe:
            continue
        grouped.setdefault(probe, []).append(record)

    anomalies: list[dict[str, Any]] = []
    for probe, group in grouped.items():
        if len(group) < _MIN_SAMPLES_PER_SIGNAL:
            continue

        sizes = [size for r in group if (size := _as_int(_first_value(r, _SIZE_KEYS))) is not None]
        if len(sizes) >= _MIN_SAMPLES_PER_SIGNAL:
            low, high = min(sizes), max(sizes)
            if low >= 0 and high > 0:
                divergence = (high - low) / max(high, 1)
                if (
                    divergence >= _SIZE_DIVERGENCE
                    and (high - low) >= _SIZE_ABSOLUTE_FLOOR
                ):
                    anomalies.append(
                        {
                            "probe": probe,
                            "kind": "size_divergence",
                            "confidence": round(min(0.9, 0.4 + divergence), 2),
                            "samples": len(sizes),
                            "detail": {"min": low, "max": high},
                        }
                    )

        timings = [
            ms for r in group if (ms := _as_int(_first_value(r, _TIMING_KEYS))) is not None
        ]
        if len(timings) >= _MIN_SAMPLES_PER_SIGNAL:
            low, high = min(timings), max(timings)
            if low >= 0 and high > 0:
                divergence = (high - low) / max(high, 1)
                if (
                    divergence >= _TIMING_DIVERGENCE
                    and (high - low) >= _TIMING_ABSOLUTE_FLOOR_MS
                ):
                    anomalies.append(
                        {
                            "probe": probe,
                            "kind": "timing_divergence",
                            "confidence": round(min(0.9, 0.35 + divergence), 2),
                            "samples": len(timings),
                            "detail": {"min_ms": low, "max_ms": high},
                        }
                    )

        statuses = {
            status
            for r in group
            if (status := _as_int(_first_value(r, _STATUS_KEYS))) is not None
        }
        if len(statuses) >= _MIN_SAMPLES_PER_SIGNAL:
            anomalies.append(
                {
                    "probe": probe,
                    "kind": "status_divergence",
                    # Evidence-derived: two distinct statuses sit exactly
                    # on the strong gate (0.75); each further distinct
                    # status adds 0.1, capped at 0.9.
                    "confidence": round(
                        min(0.9, 0.65 + 0.1 * (len(statuses) - 1)), 2
                    ),
                    "samples": len(group),
                    "detail": {"statuses": sorted(statuses)},
                }
            )

        error_texts = {
            str(_first_value(r, _ERROR_TEXT_KEYS)).strip()
            for r in group
            if _first_value(r, _ERROR_TEXT_KEYS) not in (None, "")
        }
        if len(error_texts) >= _MIN_SAMPLES_PER_SIGNAL:
            anomalies.append(
                {
                    "probe": probe,
                    "kind": "error_text_shift",
                    "confidence": 0.75,
                    "samples": len(group),
                    "detail": {"variants": min(len(error_texts), 4)},
                }
            )

    anomalies.sort(key=lambda a: (-a["confidence"], a["probe"], a["kind"]))
    return anomalies[:_MAX_ANOMALIES]


def classify_anomalies(
    anomalies: list[dict[str, Any]],
    *,
    history: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Tier each observation: noise / interesting / strong.

    Classification needs REPETITION (the same probe showing the same
    signal kind at least ``_MIN_STRONG_REPEATS`` times) before an
    observation can reach ``strong``; one-off magnitude never does.
    ``history`` carries the previous rounds' classified anomalies so
    repetition is judged across rounds: within one round a probe can
    produce each signal kind at most once, so repetition can only be
    real across rounds.

    Semantics (pinned by tests): repetition is judged across CONSECUTIVE
    rounds — the orchestrator passes only the previous round's anomalies
    as history, so a signal present in rounds 1 and 3 but absent in
    round 2 never reaches ``strong``. And a noise entry in history can
    never push a repeat to ``strong`` by itself: noise requires
    confidence < 0.5, below the strong gate, so the repetition counter
    including noise entries is harmless by construction.
    """
    repeats: dict[tuple[str, str], int] = {}
    for anomaly in list(history or []) + list(anomalies):
        key = (str(anomaly.get("probe")), str(anomaly.get("kind")))
        repeats[key] = repeats.get(key, 0) + 1

    classified: list[dict[str, Any]] = []
    for anomaly in anomalies:
        key = (str(anomaly.get("probe")), str(anomaly.get("kind")))
        repeat_count = repeats[key]
        confidence = float(anomaly.get("confidence", 0.0))
        if repeat_count >= _MIN_STRONG_REPEATS and confidence >= 0.75:
            tier = "strong"
        elif confidence >= 0.5:
            tier = "interesting"
        else:
            tier = "noise"
        out = dict(anomaly)
        out["tier"] = tier
        out["repeat_count"] = repeat_count
        classified.append(out)
    return classified


# ---------------------------------------------------------------------------
# 3) hypothesis generation from strong anomalies
# ---------------------------------------------------------------------------

_HYPOTHESIS_QUESTIONS: Final[dict[str, str]] = {
    "size_divergence": (
        "Same-endpoint responses differ in size by more than 20 percent — "
        "is variable data (other users' or configuration) being returned?"
    ),
    "timing_divergence": (
        "Same-endpoint response time diverges by more than 30 percent — is "
        "expensive validation or conditional logic executing?"
    ),
    "status_divergence": (
        "Same-endpoint requests receive different status codes — is there "
        "incomplete state validation between requests?"
    ),
    "error_text_shift": (
        "Error text changes between similar requests — is the backend "
        "leaking internal detail or validation internals?"
    ),
}


def anomalies_to_hypotheses(
    classified: list[dict[str, Any]], *, max_hypotheses: int = _MAX_HYPOTHESES
) -> list[dict[str, Any]]:
    """Convert ``strong`` anomalies into advisory hypothesis seeds.

    The shape matches what ``synthesize_gap_hypotheses``-style merges
    already consume, with ``origin="discovery-anomaly"`` so the report
    and the planner can attribute the seed to discovery, not to a
    validator contract.
    """
    seeds: list[dict[str, Any]] = []
    for anomaly in classified:
        if anomaly.get("tier") != "strong":
            continue
        kind = str(anomaly.get("kind"))
        question = _HYPOTHESIS_QUESTIONS.get(kind)
        if not question:
            continue
        probe = str(anomaly.get("probe"))
        seeds.append(
            {
                "gap_id": f"discovery:{_seen_signature(kind, probe)}",
                "description": question,
                "severity": 0.7 if kind in {"size_divergence", "status_divergence"} else 0.6,
                "required_evidence": [
                    "baseline_response",
                    "candidate_response",
                    "negative_control",
                ],
                "source": "discovery",
                "origin": "discovery-anomaly",
                "vulnerability_class": None,
                "priority": round(min(0.75, 0.35 + 0.4 * float(anomaly.get("confidence", 0.0))), 2),
                "anomaly": {
                    "kind": kind,
                    "probe": probe,
                    "samples": anomaly.get("samples"),
                    "detail": anomaly.get("detail"),
                },
            }
        )
    seeds.sort(key=lambda s: -s["priority"])
    return seeds[:max_hypotheses]


# ---------------------------------------------------------------------------
# 4) route-pattern inference, 5) parameter inference, 6) endpoint mining
# ---------------------------------------------------------------------------

def _generalize_path(path: str) -> str | None:
    parts = [p for p in path.strip("/").split("/") if p]
    if not parts:
        return None
    generalized: list[str] = []
    for part in parts:
        generalized_token = (
            _UUID_SEGMENT.fullmatch(part)
            or _HEX_SEGMENT.fullmatch(part)
            or _INTEGER_SEGMENT.fullmatch(part)
        )
        if generalized_token:
            generalized.append("{id}")
        else:
            generalized.append(part)
    return "/" + "/".join(generalized)


def infer_route_patterns(
    known_paths: list[str],
    *,
    origin: tuple[str, str, str] | None = None,
    seen_signatures: set[str] | None = None,
    max_routes: int = _MAX_ROUTES,
    admin_evidence: bool = False,
) -> list[dict[str, Any]]:
    """Same-origin candidate variants of recorded paths.

    Only scheme/host-preserving siblings are minted, deduplicated against
    ``seen_signatures`` (the loop's already-attempted actions) so repeated
    rounds do not re-probe the same 404s. Every minted candidate is a
    concrete path: no ``{id}`` placeholder is ever emitted. The ``/admin``
    sibling is minted only when ``admin_evidence`` is true — observed
    evidence that an admin surface exists, never pure speculation.
    """
    seen = seen_signatures or set()
    templates: dict[str, str] = {}
    for path in known_paths:
        if not isinstance(path, str) or not path.startswith("/") or _is_static(path):
            continue
        template = _generalize_path(path)
        if template and template not in templates:
            templates[template] = path

    candidates: list[dict[str, Any]] = []
    for template, source in templates.items():
        if "{id}" not in template:
            continue
        base = template.replace("{id}", "1")
        variants = [base]
        if template.startswith("/api/"):
            # Versioned sibling of the observed API surface, without
            # doubling the prefix (red-team R5).
            variants.append("/api/v2" + template[4:].replace("{id}", "1"))
        if admin_evidence:
            variants.append("/admin" + base)
        for variant in variants:
            if "{id}" in variant or variant == source or _is_static(variant):
                continue
            if (
                origin is not None
                and not _same_origin(urlunsplit((origin[0], origin[2], variant, "", "")), origin)
            ):
                continue
            signature = _seen_signature("route", variant)
            if signature in seen:
                continue
            seen.add(signature)
            candidates.append(
                {
                    "path": variant,
                    "origin": "discovery-route",
                    "source_template": template,
                    "source_path": source,
                    "signature": signature,
                    "rationale": "sibling of an observed path pattern",
                }
            )
            if len(candidates) >= max_routes:
                return candidates
    return candidates


def infer_parameters(
    observed_params: list[str],
    *,
    seen_signatures: set[str] | None = None,
    max_params: int = _MAX_PARAMS,
) -> list[dict[str, Any]]:
    """Sibling parameter names for recorded parameters (same position).

    Dedup keys are ``(source, sibling)`` pairs: parameter candidates are
    endpoint-scoped, so a sibling minted from one observed source name
    does not block minting it from a different observed name elsewhere.
    """
    seen = seen_signatures or set()
    candidates: list[dict[str, Any]] = []
    for name in observed_params:
        if not isinstance(name, str):
            continue
        key = name.strip().lower()
        for sibling in _PARAM_SIBLINGS.get(key, ()):
            if sibling == key:
                continue
            signature = _seen_signature("param", f"{key}->{sibling}")
            if signature in seen:
                continue
            seen.add(signature)
            candidates.append(
                {
                    "param": sibling,
                    "origin": "discovery-param",
                    "source_param": key,
                    "signature": signature,
                    "rationale": f"sibling name of observed parameter '{key}'",
                }
            )
            if len(candidates) >= max_params:
                return candidates
    return candidates


def mine_endpoints(
    records: list[dict[str, Any]],
    *,
    seen_signatures: set[str] | None = None,
    max_endpoints: int = _MAX_ENDPOINTS,
) -> list[dict[str, Any]]:
    """Path-like strings from recorded metadata, static-filtered, capped.

    Metadata only: this reads the string fields the loop already holds
    (urls, reasons, redirect notes) — response bodies are never retained
    by the hunt loop, so there is nothing to scan for them.
    """
    seen = seen_signatures or set()
    found: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        for text in _stringify_strings(record):
            for match in _PATH_TOKEN.finditer(text):
                token = match.group(0)
                # A token preceded by ":" or "/" is a URL scheme/host
                # fragment (e.g. the host inside "https://host/api/x"),
                # never an application path.
                start = match.start()
                if start > 0 and text[start - 1] in ":/":
                    continue
                if len(token) < 4 or _is_static(token):
                    continue
                if token.startswith("//") or ":" in token.split("/")[0]:
                    continue
                signature = _seen_signature("endpoint", token)
                if signature in seen:
                    continue
                seen.add(signature)
                found.append(
                    {
                        "path": token,
                        "origin": "discovery-endpoint",
                        "signature": signature,
                        "rationale": "path-like string in recorded metadata",
                    }
                )
                if len(found) >= max_endpoints:
                    return found
    return found


# ---------------------------------------------------------------------------
# 7) hybrid scenario generation, 8) uncertainty budget
# ---------------------------------------------------------------------------

def _capabilities_from_records(records: list[dict[str, Any]]) -> set[str]:
    """Capabilities named ONLY on records that carry evidence references."""
    capabilities: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        evidence = record.get("evidence_refs") or record.get("evidence")
        has_evidence = bool(evidence)
        if not has_evidence:
            continue
        text = " ".join(_stringify_strings(record)).lower()
        for capability, patterns in _CAPABILITY_PATTERNS:
            if any(pattern in text for pattern in patterns):
                capabilities.add(capability)
    return capabilities


def generate_hybrid_scenarios(
    records: list[dict[str, Any]],
    *,
    max_hybrids: int = _MAX_HYBRIDS,
    seen_signatures: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Pair evidence-backed capabilities into scenario hypotheses.

    Deterministic pairing rules only. A scenario is a hypothesis with a
    test plan — it is never a finding and never auto-executed. Scenarios
    whose scenario signature is already in ``seen_signatures`` are not
    re-minted, so a capability pair that stays present across rounds
    does not inflate the agenda (red-team R8b).
    """
    seen = seen_signatures or set()
    capabilities = _capabilities_from_records(records)
    scenarios: list[dict[str, Any]] = []
    for capability_a, capability_b, plan in _HYBRID_RULES:
        if capability_a not in capabilities or capability_b not in capabilities:
            continue
        signature = _seen_signature("hybrid", f"{capability_a}+{capability_b}")
        if signature in seen:
            continue
        seen.add(signature)
        scenarios.append(
            {
                "scenario_id": f"discovery:{signature}",
                "origin": "discovery-hybrid",
                "capabilities": [capability_a, capability_b],
                "test_plan": plan,
                "severity": 0.7,
                "required_evidence": [
                    "baseline_response",
                    "candidate_response",
                    "negative_control",
                ],
            }
        )
        if len(scenarios) >= max_hybrids:
            break
    return scenarios


def allocate_uncertainty_budget(
    regions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Weight exploration effort by how little is known about a region.

    Documented regions get the least share; regions that produced
    anomalies nobody has explained get the most. Weights are shares of a
    fixed exploration budget — this never mints requests.
    """
    weighted: list[dict[str, Any]] = []
    total = 0.0
    for region in regions:
        if not isinstance(region, dict):
            continue
        knowledge = str(region.get("knowledge_level", "documented"))
        share = _BUDGET_TIERS.get(knowledge, _BUDGET_TIERS["documented"])
        anomaly_boost = 0.1 * min(int(region.get("unexplained_anomalies", 0) or 0), 3)
        share = min(0.8, share + anomaly_boost)
        weighted.append({**region, "budget_share": share})
        total += share
    if total > 0:
        for entry in weighted:
            entry["budget_share"] = round(entry["budget_share"] / total, 3)
    return weighted


# ---------------------------------------------------------------------------
# 9) agenda + one-call round discovery
# ---------------------------------------------------------------------------

_CLASSES_KEYS = ("vuln_class", "class", "finding_class")


def _classes_seen_in(records: list[dict[str, Any]]) -> set[str]:
    """Classes actually observed in this round's records (bounded, redacted)."""
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        for key in _CLASSES_KEYS:
            value = record.get(key)
            if isinstance(value, str) and value.strip():
                seen.add(value.strip().lower()[:64])
    return seen


def build_discovery_agenda(
    hypotheses: list[dict[str, Any]],
    routes: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
    params: list[dict[str, Any]],
    hybrids: list[dict[str, Any]],
    seen_classes: set[str] | None = None,
) -> dict[str, Any]:
    """Priority-ordered agenda for the next round (advisory, bounded).

    ``coverage_packs`` rows (v80 Task 2) make the validator-uncovered
    classes visible in the agenda; the rows stay honest: a class only
    leaves ``missing-validator`` when a real proof bundle was recorded.
    """
    from webpent.autonomous.coverage_packs import pack_ledger_entries

    return {
        "origin": "discovery-agenda",
        "unvalidated_hypotheses": len(hypotheses),
        "new_routes": len(routes),
        "new_endpoints": len(endpoints),
        "new_parameters": len(params),
        "hybrid_scenarios": len(hybrids),
        "coverage_packs": pack_ledger_entries(seen_classes),
        "order": [
            "discovery-anomaly-hypotheses",
            "discovery-endpoint",
            "discovery-route",
            "discovery-param",
            "discovery-hybrid",
        ],
    }


def discover_from_records(
    records: list[dict[str, Any]],
    *,
    seen_signatures: set[str] | None = None,
    prior_anomalies: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run the full bounded pipeline over one round's records.

    ``prior_anomalies`` are the classified anomalies of earlier rounds;
    repetition (and therefore the ``strong`` tier) is judged across
    CONSECUTIVE rounds — the orchestrator passes only the previous
    round's anomalies as history, so a signal present in rounds 1 and 3
    but absent in round 2 never reaches ``strong``.

    Honesty note (red-team R7): only the strong-anomaly hypothesis seeds
    are consumed by the loop (through the re-hypothesis merge gate). The
    route/endpoint/param candidates and hybrid scenarios are ADVISORY
    INVENTORY with no consumer in the current loop; they exist for the
    operator report and for future consumers, and they dedup across
    rounds via ``seen_signatures`` so they never inflate.
    """
    seen = seen_signatures or set()
    anomalies = classify_anomalies(
        monitor_anomalies(records), history=prior_anomalies
    )
    hypotheses = anomalies_to_hypotheses(anomalies)

    paths: list[str] = []
    params: list[str] = []
    admin_seen = False
    for record in records:
        if not isinstance(record, dict):
            continue
        for text in _stringify_strings(record):
            if "admin" in text.lower():
                admin_seen = True
            for match in _PATH_TOKEN.findall(text):
                if match.startswith("/") and not _is_static(match):
                    paths.append(match)
        observed = record.get("params") or record.get("observed_params") or []
        if isinstance(observed, list):
            params.extend(str(p) for p in observed)

    origin: tuple[str, str, str] | None = None
    for record in records:
        if not isinstance(record, dict):
            continue
        url = record.get("url")
        if isinstance(url, str):
            parsed = _coerce_origin(url)
            if parsed:
                origin = parsed
                break

    routes = infer_route_patterns(
        paths, origin=origin, seen_signatures=seen, admin_evidence=admin_seen
    )
    endpoints = mine_endpoints(records, seen_signatures=seen)
    param_candidates = infer_parameters(params, seen_signatures=seen)
    hybrids = generate_hybrid_scenarios(records, seen_signatures=seen)
    strong_or_interesting = sum(
        1 for a in anomalies if a.get("tier") in {"interesting", "strong"}
    )
    budget = allocate_uncertainty_budget(
        [
            {"region": "observed-paths", "knowledge_level": "documented",
             "unexplained_anomalies": 0},
            {"region": "anomalous-probes",
             "knowledge_level": "anomalous_unexplained",
             "unexplained_anomalies": strong_or_interesting},
        ]
    )
    agenda = build_discovery_agenda(
        hypotheses,
        routes,
        endpoints,
        param_candidates,
        hybrids,
        seen_classes=_classes_seen_in(records),
    )
    return {
        "origin": "discovery",
        "anomalies": anomalies,
        "hypotheses": hypotheses,
        "routes": routes,
        "endpoints": endpoints,
        "params": param_candidates,
        "hybrids": hybrids,
        "uncertainty_budget": budget,
        "agenda": agenda,
    }


# End of hunt_discovery.py
