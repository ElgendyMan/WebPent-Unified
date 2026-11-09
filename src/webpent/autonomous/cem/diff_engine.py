"""CEM Watchtower — the diff engine (v83, U-CEM-2).

Compares two snapshots of the same target and classifies every change as
``NOISE`` (rotation, cache busting, ignore-listed paths), ``SIGNAL-LOW``
(uninteresting on its own), ``SIGNAL-HIGH`` (new attack surface worth a
focused look) or ``CRITICAL`` (the kind of change that justifies a full
wake-up). The classifier is advisory: it ranks and explains changes, it
never promotes or suppresses evidence, and it never touches anything.

Reappearance detection uses the endpoint history the caller passes in
(the snapshot store's ``history_endpoints``): an endpoint that returns
after disappearing is re-surfaced as SIGNAL-HIGH because the window that
opened and closed may now be open again.

Signal thresholds and ignore lists load from a small YAML config; a
missing or corrupt file degrades to the built-in defaults. All time is
injected; everything here is pure.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from webpent.autonomous.hunt_contracts import redact

_LOG = logging.getLogger(__name__)

NOISE = "noise"
SIGNAL_LOW = "signal-low"
SIGNAL_HIGH = "signal-high"
CRITICAL = "critical"

_RANK = {NOISE: 0, SIGNAL_LOW: 1, SIGNAL_HIGH: 2, CRITICAL: 3}

MAX_CHANGES_PER_DIFF = 200
MAX_ITEMS_PER_FIELD = 128

#: Header names whose disappearance is treated as high signal (defaults).
DEFAULT_CRITICAL_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
)

#: Path fragments that are pure rotation noise (defaults).
DEFAULT_NOISE_PATTERNS = (
    "/favicon",
    "/robots.txt",
    "/sitemap.xml",
    "etag",
    "csrf",
    "session",
    "date",
)

DEFAULTS: dict[str, Any] = {
    "noise_patterns": list(DEFAULT_NOISE_PATTERNS),
    "critical_headers": list(DEFAULT_CRITICAL_HEADERS),
    "ignore_headers": ("date", "etag", "x-request-id", "cf-ray"),
    "max_changes": MAX_CHANGES_PER_DIFF,
}


def _compact_list(values: Any, limit: int = MAX_ITEMS_PER_FIELD) -> list[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    return sorted({redact(str(v)).strip()[:200] for v in values if str(v or "").strip()})[:limit]


def load_signal_config(path: Any) -> dict[str, Any]:
    """Load the signal YAML; corrupt/missing -> built-in defaults.

    Only four whitelisted keys are read and only list-of-strings values
    are kept, so even a hostile file cannot smuggle in structure.
    """
    config: dict[str, Any] = {
        k: list(v) if isinstance(v, tuple) else v for k, v in DEFAULTS.items()
    }
    if path is None:
        return config
    try:
        import yaml

        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return config
    except Exception as exc:  # corrupt, wrong schema, missing yaml module
        _LOG.warning("signal config unreadable; using defaults: %s", exc)
        return config
    if not isinstance(raw, dict):
        return config
    for key in DEFAULTS:
        value = raw.get(key)
        if isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value):
            config[key] = [v[:200] for v in value][:200]
    if isinstance(raw.get("max_changes"), int) and 0 < raw["max_changes"] <= MAX_CHANGES_PER_DIFF:
        config["max_changes"] = raw["max_changes"]
    return config


def classify_change(change: dict[str, Any], config: dict[str, Any]) -> str:
    """Classify one change record; pure, bounded, explainable."""
    field = str(change.get("field", ""))
    kind = str(change.get("kind", ""))
    item = str(change.get("item", ""))
    lowered = (field + " " + item).lower()

    if noise_matcher(config).search(lowered):
        return NOISE
    if field == "headers":
        if kind == "removed" and item.lower() in [h.lower() for h in config["critical_headers"]]:
            return CRITICAL
        if any(item.lower().startswith(h.lower() + ":") for h in config["ignore_headers"]):
            return NOISE
        return SIGNAL_LOW
    if field == "endpoints":
        if kind == "added":
            # reappearance and fresh appearance rank the same today: both put
            # a surface back on the operator's desk. The flag rides the
            # change record so a stricter ranking can differentiate later.
            return SIGNAL_HIGH
        return SIGNAL_LOW
    if field == "subdomains":
        return CRITICAL if kind == "added" else SIGNAL_HIGH
    if field == "tech_stack":
        return SIGNAL_HIGH
    if field == "response_shapes":
        return SIGNAL_HIGH
    if field == "cert_expiry":
        return SIGNAL_LOW
    if field == "js_hashes":
        return SIGNAL_LOW
    return SIGNAL_LOW


def _emit(
    changes: list[dict[str, Any]],
    *,
    field: str,
    kind: str,
    item: str,
    detail: str = "",
    reappearance: bool = False,
    limit: int,
) -> None:
    if len(changes) >= limit:
        return
    changes.append(
        {
            "field": field[:60],
            "kind": kind[:20],
            "item": redact(item)[:200],
            "detail": redact(detail)[:200],
            "reappearance": bool(reappearance),
        }
    )


def diff_snapshots(
    old: dict[str, Any] | None,
    new: dict[str, Any] | None,
    *,
    config: dict[str, Any] | None = None,
    history_endpoints: Any = None,
) -> dict[str, Any]:
    """Compare two snapshots of one target and classify every change.

    Pure and advisory: the report explains what changed and how interesting
    it is, and never carries an instruction to act. ``history_endpoints``
    is the bounded union of previously observed endpoints, used to flag
    reappearance.
    """
    cfg = config or load_signal_config(None)
    limit = int(cfg.get("max_changes", MAX_CHANGES_PER_DIFF))
    old = old if isinstance(old, dict) else {}
    new = new if isinstance(new, dict) else {}
    history = {str(e) for e in history_endpoints or [] if str(e).strip()}

    changes: list[dict[str, Any]] = []

    old_eps = set(_compact_list(old.get("endpoints")))
    new_eps = set(_compact_list(new.get("endpoints")))
    for endpoint in sorted(new_eps - old_eps):
        _emit(
            changes,
            field="endpoints",
            kind="added",
            item=endpoint,
            reappearance=endpoint in history,
            detail="endpoint reappeared" if endpoint in history else "new endpoint",
            limit=limit,
        )
    for endpoint in sorted(old_eps - new_eps):
        _emit(changes, field="endpoints", kind="removed", item=endpoint, limit=limit)

    old_subs = set(_compact_list(old.get("subdomains")))
    new_subs = set(_compact_list(new.get("subdomains")))
    for sub in sorted(new_subs - old_subs):
        _emit(changes, field="subdomains", kind="added", item=sub,
              detail="new subdomain", limit=limit)
    for sub in sorted(old_subs - new_subs):
        _emit(changes, field="subdomains", kind="removed", item=sub, limit=limit)

    old_headers = old.get("headers") if isinstance(old.get("headers"), dict) else {}
    new_headers = new.get("headers") if isinstance(new.get("headers"), dict) else {}
    for header in sorted(set(new_headers) - set(old_headers)):
        _emit(
            changes,
            field="headers",
            kind="added",
            item=f"{header}: {new_headers[header]}",
            limit=limit,
        )
    for header in sorted(set(old_headers) - set(new_headers)):
        _emit(changes, field="headers", kind="removed", item=str(header), limit=limit)
    for header in sorted(set(old_headers) & set(new_headers)):
        if old_headers[header] != new_headers[header]:
            _emit(
                changes,
                field="headers",
                kind="changed",
                item=f"{header}: {old_headers[header]} -> {new_headers[header]}",
                limit=limit,
            )

    old_stack = set(_compact_list(old.get("tech_stack")))
    new_stack = set(_compact_list(new.get("tech_stack")))
    for tech in sorted(new_stack - old_stack):
        _emit(changes, field="tech_stack", kind="added", item=tech, limit=limit)
    for tech in sorted(old_stack - new_stack):
        _emit(changes, field="tech_stack", kind="removed", item=tech, limit=limit)

    old_js = old.get("js_hashes") if isinstance(old.get("js_hashes"), dict) else {}
    new_js = new.get("js_hashes") if isinstance(new.get("js_hashes"), dict) else {}
    for js in sorted(set(new_js) & set(old_js)):
        if new_js[js] != old_js[js]:
            _emit(changes, field="js_hashes", kind="changed", item=str(js), limit=limit)
    for js in sorted(set(new_js) - set(old_js)):
        _emit(changes, field="js_hashes", kind="added", item=str(js), limit=limit)

    old_shapes = old.get("response_shapes") if isinstance(old.get("response_shapes"), dict) else {}
    new_shapes = new.get("response_shapes") if isinstance(new.get("response_shapes"), dict) else {}
    for shape in sorted(set(new_shapes) & set(old_shapes)):
        if new_shapes[shape] != old_shapes[shape]:
            _emit(
                changes,
                field="response_shapes",
                kind="changed",
                item=str(shape),
                detail=f"{old_shapes[shape]} -> {new_shapes[shape]}",
                limit=limit,
            )

    old_cert = str(old.get("cert_expiry") or "")
    new_cert = str(new.get("cert_expiry") or "")
    if old_cert != new_cert and (old_cert or new_cert):
        _emit(changes, field="cert_expiry", kind="changed",
              item=f"{old_cert} -> {new_cert}", limit=limit)

    for change in changes:
        change["classification"] = classify_change(change, cfg)

    levels = [str(c.get("classification")) for c in changes]
    top = max((_RANK.get(name, 1) for name in levels), default=0)
    top_name = {v: k for k, v in _RANK.items()}[top]
    counts = {name: levels.count(name) for name in _RANK}
    return {
        "target_id": redact(str(new.get("target_id") or old.get("target_id") or ""))[:120],
        "from_ts": old.get("ts"),
        "to_ts": new.get("ts"),
        "from_hash": str(old.get("hash") or ""),
        "to_hash": str(new.get("hash") or ""),
        "changes": changes,
        "change_count": len(changes),
        "truncated": len(changes) >= limit,
        "counts": counts,
        "top_signal": top_name,
        "advisory": True,
    }


def is_actionable(report: dict[str, Any]) -> bool:
    """True when the diff justifies a focused mini-campaign (SIGNAL-HIGH+)."""
    return _RANK.get(str(report.get("top_signal")), 0) >= _RANK[SIGNAL_HIGH]


def is_wake_up(report: dict[str, Any]) -> bool:
    """True when the diff justifies the wake-up protocol (CRITICAL only)."""
    return report.get("top_signal") == CRITICAL


_PATTERN_CACHE: dict[str, re.Pattern[str]] = {}


def noise_matcher(config: dict[str, Any]) -> re.Pattern[str]:
    """Compiled alternation of the config's noise patterns (bounded)."""
    key = "|".join(config.get("noise_patterns", []))
    if key not in _PATTERN_CACHE:
        _PATTERN_CACHE[key] = re.compile(
            "|".join(re.escape(p) for p in config.get("noise_patterns", [])) or r"(?!)"
        )
    return _PATTERN_CACHE[key]


__all__ = [
    "CRITICAL",
    "NOISE",
    "SIGNAL_HIGH",
    "SIGNAL_LOW",
    "DEFAULTS",
    "MAX_CHANGES_PER_DIFF",
    "classify_change",
    "diff_snapshots",
    "is_actionable",
    "is_wake_up",
    "load_signal_config",
    "noise_matcher",
]
