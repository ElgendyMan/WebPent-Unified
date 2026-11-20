# src/webpent/agents/scope_enforcer/agent.py
"""webpent.agents.scope_enforcer.agent

LangGraph node that enforces target scope by filtering out-of-scope URLs.

V3.5 Phase 2 introduces strict scope enforcement. The ``Target`` model's
``is_in_scope(url)`` method is used to validate every URL in the
engagement state. Findings whose URLs are out of scope are discarded,
and crawled endpoints that fall outside the scope are filtered out.

This node runs immediately after the crawler and before the WAF detector
to ensure no out-of-scope data propagates downstream.

V4.5 Kill-Switch: The entire core logic is wrapped in a ``try/except``
block. On ANY unexpected exception, the node raises a critical error
(FAIL-CLOSED). It NEVER returns a default "in-scope" status or bypasses
the scope check.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from langchain_core.messages import AIMessage

from webpent.models.findings import Finding
from webpent.shared.scope_drift import detect_scope_drift
from webpent.state.state import PentestState

logger = logging.getLogger(__name__)


class ScopeEnforcementError(Exception):
    """Critical error raised when the scope enforcer fails-closed.

    V4.5 Kill-Switch: This exception halts the graph execution to
    prevent any out-of-scope data from propagating downstream when
    the enforcer encounters an unexpected error.
    """


def _extract_hostname(url: str) -> str | None:
    """Extract the hostname from a URL for logging purposes."""
    try:
        parsed = urlparse(url)
        return parsed.hostname
    except Exception:
        return None


def _scope_path_rules_from_state(state: dict[str, Any]) -> dict[str, tuple[str, ...]] | None:
    """Extract scope-file path rules from state (None when no rules exist).

    A *missing* declaration yields None (legacy host-level enforcement applies
    unchanged). A *malformed* declaration FAILS CLOSED: silently returning None
    here would drop the operator's ``exclude_paths`` deny-list and make
    explicitly excluded paths reachable, contradicting the V4.5 kill-switch
    contract of this module.
    """
    try:
        declaration = state.get("scope_declaration") or {}
        include_paths = tuple(str(p) for p in (declaration.get("include_paths") or ()))
        exclude_paths = tuple(str(p) for p in (declaration.get("exclude_paths") or ()))
    except Exception as exc:
        logger.critical(
            "Malformed scope_declaration — FAILING CLOSED rather than dropping "
            "path include/exclude rules: %s",
            exc,
        )
        raise ScopeEnforcementError(
            f"Malformed scope_declaration; refusing to enforce scope without "
            f"path rules: {exc}"
        ) from exc
    if include_paths or exclude_paths:
        return {"include_paths": include_paths, "exclude_paths": exclude_paths}
    return None


def _enforce_scope_core(
    target: Any,
    findings: list[Finding],
    crawled_data: dict[str, Any],
    path_rules: dict[str, tuple[str, ...]] | None = None,
) -> tuple[list[Finding], dict[str, Any], int, int]:
    """Core scope-enforcement logic.

    Returns a tuple of (filtered_findings, updated_crawled_data,
    findings_removed, endpoints_removed).

    Raises:
        ScopeEnforcementError: On any unexpected exception during
            scope validation.
    """
    endpoints: list[Any] = crawled_data.get("endpoints", [])

    # --- Filter findings ---
    filtered_findings: list[Finding] = []
    findings_removed = 0

    for finding in findings:
        try:
            in_scope = target.is_in_scope(finding.url)
        except Exception as exc:
            # V4.5 Kill-Switch: Any exception during scope check = FAIL.
            raise ScopeEnforcementError(
                f"Scope check failed for finding {finding.id} "
                f"(URL: {finding.url}): {exc}"
            ) from exc

        if in_scope:
            filtered_findings.append(finding)
        else:
            findings_removed += 1
            hostname = _extract_hostname(finding.url) or "unknown"
            logger.warning(
                "Discarding out-of-scope finding %s (URL: %s, host: %s)",
                finding.id, finding.url, hostname,
            )

    # --- Filter crawled endpoints ---
    filtered_endpoints: list[Any] = []
    endpoints_removed = 0

    for endpoint in endpoints:
        if isinstance(endpoint, str):
            url = endpoint
        elif isinstance(endpoint, dict):
            url = endpoint.get("url") or endpoint.get("endpoint") or ""
        else:
            logger.warning(
                "Dropping unrecognized endpoint type %s: %s",
                type(endpoint).__name__, endpoint,
            )
            endpoints_removed += 1
            continue

        # V4.5: Strict fail-closed — empty URLs are dropped.
        if not url:
            endpoints_removed += 1
            logger.info("Dropping empty crawled endpoint")
            continue

        try:
            in_scope = target.is_in_scope(url)
        except Exception as exc:
            raise ScopeEnforcementError(
                f"Scope check failed for endpoint (URL: {url}): {exc}"
            ) from exc

        if in_scope:
            # SCENARIO CONTRACT: with an explicit scope-file contract, path
            # rules are the operator's second enforcement layer. Exclude wins
            # over include; no path rules leaves the endpoint untouched
            # (legacy behaviour).
            if path_rules is not None:
                try:
                    from webpent.shared.scope_file import (
                        ScopeFileSpec,
                        evaluate_path_rules,
                    )

                    _path_spec = ScopeFileSpec(
                        allow_entries=(),
                        include_paths=path_rules.get("include_paths", ()),
                        exclude_paths=path_rules.get("exclude_paths", ()),
                    )
                except Exception as exc:
                    raise ScopeEnforcementError(
                        f"Scope-file path rule build failed for endpoint (URL: {url}): {exc}"
                    ) from exc
                if evaluate_path_rules(_path_spec, url) == "denied":
                    endpoints_removed += 1
                    logger.info(
                        "Discarding endpoint outside scope-file path rules (URL: %s)",
                        url,
                    )
                    continue
            filtered_endpoints.append(endpoint)
        else:
            endpoints_removed += 1
            hostname = _extract_hostname(url) or "unknown"
            logger.info(
                "Discarding out-of-scope crawled endpoint (URL: %s, host: %s)",
                url, hostname,
            )

    updated_crawled_data: dict[str, Any] = dict(crawled_data)
    updated_crawled_data["endpoints"] = filtered_endpoints

    return filtered_findings, updated_crawled_data, findings_removed, endpoints_removed


# NOTE: deterministic agent — no LLM reasoning by design (verified 2026-08-21).
def scope_enforcer_node(state: PentestState) -> dict:
    """LangGraph node that filters out-of-scope findings and crawled data.

    V4.5 Kill-Switch: The entire core logic is wrapped in a ``try/except``.
    On ANY unexpected exception, the node raises ``ScopeEnforcementError``
    to halt the graph execution. It NEVER returns a default "in-scope"
    status or bypasses the check.

    Args:
        state: Current graph state. Must contain ``target``, ``findings``,
            and ``crawled_data``.

    Returns:
        A partial state update with filtered ``findings`` and ``crawled_data``.

    Raises:
        ScopeEnforcementError: If scope enforcement fails-closed.
    """
    target = state["target"]
    findings: list[Finding] = list(state.get("findings") or [])
    crawled_data: dict[str, Any] = state.get("crawled_data") or {}

    try:
        filtered_findings, updated_crawled_data, findings_removed, endpoints_removed = (
            _enforce_scope_core(
                target,
                findings,
                crawled_data,
                path_rules=_scope_path_rules_from_state(state),
            )
        )
    except ScopeEnforcementError:
        # Re-raise — the graph MUST halt.
        raise
    except Exception as exc:
        # V4.5 Kill-Switch: ANY unexpected exception = FAIL-CLOSED.
        logger.critical(
            "Scope enforcer encountered unexpected error — FAILING CLOSED: %s",
            exc,
        )
        raise ScopeEnforcementError(
            f"Scope enforcement failed-closed due to unexpected error: {exc}"
        ) from exc

    discovered_urls = [
        str(endpoint.get("url") or endpoint.get("target_url") or "")
        for endpoint in (crawled_data.get("endpoints") or [])
        if isinstance(endpoint, dict)
    ]
    scope_drift = detect_scope_drift(discovered_urls, str(target.url))
    summary = (
        f"Scope enforcement completed. "
        f"Removed {findings_removed} out-of-scope finding(s) and "
        f"{endpoints_removed} out-of-scope endpoint(s). "
        f"Remaining: {len(filtered_findings)} finding(s), "
        f"{len(updated_crawled_data.get('endpoints', []))} endpoint(s)."
    )

    # V7 Cognitive Upgrade — Phase 2/7: annotate Mental Model nodes
    # with in_scope status. Per the plan: "in-scope status (result of
    # the scope check, never inferred, always explicitly set by
    # scope_enforcer or its rabbit-hole-path equivalent)." Without this,
    # all Mental Model nodes have in_scope=None forever, and the Rabbit
    # Hole node's _find_followable_artifacts can't distinguish in-scope
    # from out-of-scope artifacts.
    mental_model_update: dict[str, Any] = {"nodes": {}, "edges": []}
    try:
        from webpent.models.mental_model import NodeKind, _coerce_to_mental_model
        mental_model_state = state.get("mental_model") or {}
        model = _coerce_to_mental_model(mental_model_state)
        annotated_count = 0
        for node in model.nodes.values():
            # Only annotate host and endpoint nodes — these are the
            # ones with URLs that is_in_scope can check. Credential/
            # artifact/service/technology nodes don't have a meaningful
            # scope status (they're properties of a host, not hosts
            # themselves).
            if node.kind not in (NodeKind.HOST.value, NodeKind.ENDPOINT.value):
                continue
            # Skip if already annotated (idempotent).
            if node.in_scope is not None:
                continue
            # Derive a URL to check from the node's identity_key.
            check_url = node.identity_key
            if not check_url.startswith(("http://", "https://")):
                # For host nodes, construct a URL to check.
                check_url = f"http://{check_url}"
            try:
                in_scope = target.is_in_scope(check_url)
            except Exception as exc:
                # V4.5 Kill-Switch: any scope-check exception = FAIL.
                raise ScopeEnforcementError(
                    f"Scope check failed for Mental Model node {node.id} "
                    f"(identity_key={node.identity_key}): {exc}"
                ) from exc
            # Build an updated node dict with in_scope set.
            updated_node_dict = node.model_dump(mode="json")
            updated_node_dict["in_scope"] = in_scope
            mental_model_update["nodes"][node.id] = updated_node_dict
            annotated_count += 1
        if annotated_count:
            summary += (
                f" Annotated {annotated_count} Mental Model node(s) "
                f"with in_scope status."
            )
    except ScopeEnforcementError:
        raise
    except Exception as exc:
        # Non-fatal — Mental Model annotation is best-effort. The
        # scope_enforcer's PRIMARY job (filtering findings + endpoints)
        # already succeeded. Log and continue.
        logger.debug("Mental Model scope annotation failed: %s", exc)

    logger.info(summary)

    return {
        "findings": filtered_findings,
        "crawled_data": updated_crawled_data,
        "mental_model": mental_model_update,
        "scope_drift_detected": bool(scope_drift["detected"]),
        "scope_drift_events": [scope_drift] if scope_drift["detected"] else [],
        "messages": [AIMessage(content=summary)],
    }
