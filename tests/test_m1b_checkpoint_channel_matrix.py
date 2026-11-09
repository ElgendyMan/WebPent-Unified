# tests/test_m1b_checkpoint_channel_matrix.py
"""M1b residual closure — PentestState channel-level checkpoint compatibility
sweep across engine families.

UM-DR-13 recorded the M1b residual: "PentestState channel-level checkpoint
compatibility sweep across engine families — the hunter bridge covers the
budget keys; a full per-channel replay matrix is the next window."

This module IS that window. It pins, for EVERY declared state channel
(all of PentestState and the UnifiedState extras), that:

1. a realistic sample value survives a round trip through the PRODUCTION
   checkpoint stack (``webpent.graph.checkpoints.get_checkpointer`` — the
   redacting ``SqliteSaver`` used by real campaigns), loaded back from the
   sqlite file, not just through the in-memory reducer functions;
2. the documented secret-redaction contract holds per channel (the three
   designated secret channels persist empty, ``jwt_weak_secret_candidates``
   persists empty, ``auth_state`` secret keys are emptied while non-secret
   keys survive);
3. every reducer channel merges concurrent writes instead of overwriting
   (the exact class of defect the M1b state-consistency fix addressed for
   five shadowed channels — now swept across ALL reducer channels).

Engine families covered (per ``state/unified_state.py``):
* production  — ``PentestState`` (the 80+-node unified hunt graph schema);
* unified     — ``UnifiedState`` (superset: hunter-family budget fields +
  plan channels), the schema the unified engine actually runs;
* hunter      — a legacy ``HunterGraphState``-shaped dict mapped by
  ``adapters/legacy_state_bridge.hunter_state_to_unified`` and then run
  through the unified schema's checkpoint stack.

No LLM, no network, no frozen-node execution: a single passthrough node
writes every channel once; the assertions are about the checkpoint stack.
"""

from __future__ import annotations

import copy
import json
import os
import sqlite3
import uuid as uuid_module
from typing import (
    Annotated,
    Any,
    Literal,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)

import pytest
from langchain_core.messages import BaseMessage, HumanMessage
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel

from webpent.adapters.legacy_state_bridge import hunter_state_to_unified
from webpent.graph.checkpoints import (
    _SECRET_CHANNELS,
    _is_sensitive_key,
    get_checkpointer,
)
from webpent.state.state import PentestState
from webpent.state.unified_state import UnifiedState

# ---------------------------------------------------------------------------
# Fixtures — isolate any incidental file writes (vault open, sqlite sidecars)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _checkpoint_matrix_cwd(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """Run the matrix from a throwaway CWD.

    The production ``get_checkpointer`` path is passed explicitly, but the
    secret-restore step opens the reauth vault through the settings database
    URL, whose default is CWD-anchored. Keep the repo checkout untouched.
    """
    monkeypatch.chdir(tmp_path)
    yield


# ---------------------------------------------------------------------------
# Channel enumeration
# ---------------------------------------------------------------------------


def _channels(schema: type) -> dict[str, Any]:
    """Every declared channel of a state TypedDict with its annotation."""
    return dict(get_type_hints(schema, include_extras=True))


def _reducer_of(hint: Any) -> Any | None:
    """Return the channel's reducer function when the annotation carries one."""
    if get_origin(hint) is not Annotated:
        return None
    for meta in get_args(hint)[1:]:
        if callable(meta) and not isinstance(meta, type):
            return meta
    return None


# ---------------------------------------------------------------------------
# Deterministic per-channel sample values
# ---------------------------------------------------------------------------


def _probe_finding(variant: int):
    from datetime import datetime, timezone

    from webpent.models.findings import Confidence, Finding, Severity, VulnClass

    return Finding(
        id=uuid_module.UUID(f"00000000-0000-0000-0000-{variant:012d}"),
        created_at=datetime(2026, 1, 1, variant, 0, 0, tzinfo=timezone.utc),
        title=f"checkpoint matrix finding {variant}",
        severity=Severity.LOW,
        description="M1b channel-matrix fixture.",
        tool_name="matrix",
        url="https://probe-target.example/x",
        vuln_class=VulnClass.INFO_DISCLOSURE,
        confidence=Confidence.TENTATIVE,
        confidence_level="Pending",
        evidence={"validation_attempted": False, "variant": variant},
        thread_id=f"matrix-{variant}",
        oob_token=f"probe-oob-{variant}",
    )


def _probe_hypothesis(variant: int):
    from datetime import datetime, timezone

    from webpent.models.hypothesis import Hypothesis

    stamp = datetime(2026, 1, 1, variant, 0, 0, tzinfo=timezone.utc)
    return Hypothesis(
        id=uuid_module.UUID(f"00000000-0000-0000-0000-{variant:012d}"),
        target_url="https://probe-target.example",
        statement=f"checkpoint matrix hypothesis {variant}",
        created_at=stamp,
        updated_at=stamp,
    )


def _probe_target():
    from webpent.models.targets import Target

    return Target(url="https://probe-target.example")


def _sample_for(hint: Any, channel: str, variant: int = 1) -> Any:
    """Build a deterministic, serde-safe sample value for one annotation."""
    if get_origin(hint) is Annotated:
        return _sample_for(get_args(hint)[0], channel, variant)
    if hint is Any or hint is object:
        return f"probe-{channel}-{variant}"
    origin = get_origin(hint)
    import types as _types

    if origin is Union or origin is _types.UnionType:
        args = [a for a in get_args(hint) if a is not type(None)]
        return _sample_for(args[0], channel, variant)
    if origin is Literal:
        return get_args(hint)[0]
    if isinstance(hint, type):
        if issubclass(hint, BaseMessage):
            return HumanMessage(content=f"probe-{channel}-{variant}")
        if issubclass(hint, BaseModel):
            if hint.__name__ == "Finding":
                return _probe_finding(variant)
            if hint.__name__ == "Hypothesis":
                return _probe_hypothesis(variant)
            if hint.__name__ == "Target":
                return _probe_target()
            raise AssertionError(
                f"no sample factory for model {hint.__name__} on channel {channel!r}"
            )
        if issubclass(hint, bool):
            return variant % 2 == 1
        if issubclass(hint, int):
            return 7 * variant
        if issubclass(hint, float):
            return 1.25 * variant
        if issubclass(hint, str):
            return f"probe-{channel}-{variant}"
        if issubclass(hint, dict):
            return {f"probe_{variant}": f"v{variant}"}
        if issubclass(hint, list):
            return [f"probe-{channel}-{variant}"]
    import enum as _enum

    if isinstance(hint, type) and issubclass(hint, _enum.Enum):
        return list(hint)[0]
    if origin is dict:
        return {f"probe_{variant}": f"v{variant}"}
    if origin is list:
        args = get_args(hint)
        elem = args[0] if args else str
        return [_sample_for(elem, channel, variant)]
    if origin is tuple:
        args = get_args(hint)
        if args:
            return tuple(_sample_for(a, channel, variant) for a in args)
        return (f"probe-{channel}-{variant}",)
    return f"probe-{channel}-{variant}"


def _channel_sample(channel: str, variant: int = 1) -> Any:
    """Channel-specific sample: realistic shapes where reducers demand them."""
    if channel == "auth_state":
        return {
            "status": "ok",
            "cookies": [
                {
                    "name": "sid",
                    "value": f"v{variant}",
                    "domain": ".probe.example",
                }
            ],
            "headers": {"X-Probe": f"v{variant}"},
        }
    if channel == "payloads_to_test":
        return {f"param{variant}": [f"p{variant}"]}
    if channel == "optimization_retries":
        return {f"node{variant}": variant}
    if channel == "messages":
        return [HumanMessage(content=f"probe-messages-{variant}")]
    if channel == "findings":
        return [_probe_finding(variant)]
    if channel == "hypotheses":
        return [_probe_hypothesis(variant)]
    if channel == "target":
        return _probe_target()
    if channel == "hunter":
        return {"hunter_probe": variant}
    if channel == "runtime_context":
        # the redaction contract projects this channel through the runtime
        # descriptor path — only dict-shaped values are meaningful here
        return {"runtime_probe": f"v{variant}"}
    hints = _channels(PentestState)
    if channel not in hints:
        hints = _channels(UnifiedState)
    return _sample_for(hints[channel], channel, variant)


# ---------------------------------------------------------------------------
# Round-trip normalization (pydantic ↔ dict, BaseMessage ↔ dict, tuple ↔ list)
# ---------------------------------------------------------------------------


def _normalize(value: Any) -> Any:
    if isinstance(value, BaseMessage):
        return (
            "__message__",
            getattr(value, "type", ""),
            str(getattr(value, "content", "")),
        )
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="json"))
    if isinstance(value, dict):
        if {"content", "type"} <= {str(k) for k in value}:
            return ("__message__", str(value.get("type", "")), str(value.get("content", "")))
        return {str(k): _normalize(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    return value


def _leaves(value: Any):
    if isinstance(value, dict):
        for item in value.values():
            yield from _leaves(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _leaves(item)
    else:
        yield value


# ---------------------------------------------------------------------------
# Graph harness — one passthrough node over the production checkpoint stack
# ---------------------------------------------------------------------------


def _passthrough_node(state: dict[str, Any]) -> dict[str, Any]:
    # Production nodes write DELTAS, never the accumulated state back (the
    # append-only reducers would duplicate values). The matrix writes every
    # channel through the graph INPUT (the START task — the same path a
    # campaign resume takes), so the node itself is a deliberate no-op.
    return {}


def _compile_with(schema: type, saver: Any) -> Any:
    graph = StateGraph(schema)
    graph.add_node("passthrough", _passthrough_node)
    graph.add_edge(START, "passthrough")
    graph.add_edge("passthrough", END)
    return graph.compile(checkpointer=saver)


def _round_trip(schema: type, graph_input: dict[str, Any], thread_id: str, db_path) -> dict[str, Any]:
    """Write every channel through the production saver, read the sqlite
    checkpoint back, and return the persisted ``channel_values``."""
    config = {"configurable": {"thread_id": thread_id}}
    with get_checkpointer(db_path) as saver:
        app = _compile_with(schema, saver)
        app.invoke(copy.deepcopy(graph_input), config)
        checkpoint_tuple = saver.get_tuple(config)
    assert checkpoint_tuple is not None, "no checkpoint persisted"
    channels = checkpoint_tuple.checkpoint.get("channel_values")
    assert isinstance(channels, dict)
    return channels


# ---------------------------------------------------------------------------
# Family A — production PentestState, every channel
# ---------------------------------------------------------------------------


def test_production_family_all_pentest_state_channels_survive_checkpoint(tmp_path):
    pentest_channels = _channels(PentestState)
    assert len(pentest_channels) >= 250, "channel inventory unexpectedly small"

    graph_input = {name: _channel_sample(name, 1) for name in pentest_channels}
    persisted = _round_trip(
        PentestState, graph_input, "matrix-production", tmp_path / "prod.db"
    )

    missing = sorted(set(pentest_channels) - set(persisted))
    assert not missing, f"channels lost by the checkpoint stack: {missing}"

    for name, sample in graph_input.items():
        got = persisted.get(name)
        if name in _SECRET_CHANNELS:
            assert _normalize(got) == {}, f"secret channel {name!r} persisted non-empty"
            continue
        if name == "jwt_weak_secret_candidates":
            assert _normalize(got) == [], "jwt candidates must persist empty"
            continue
        if name == "auth_state":
            # documented auth_state contract: secret keys emptied, rest verbatim
            assert got.get("status") == "ok"
            assert got.get("cookies") == []
            assert got.get("headers") == {"X-Probe": "v1"}
            continue
        if name == "runtime_context":
            # restore step rebuilds the runtime: the loaded value is either
            # absent, the persisted descriptor dict, or a reconstructed
            # RuntimeContext — never an arbitrary corrupted shape
            from webpent.shared.runtime import RuntimeContext

            assert got is None or _normalize(got) == _normalize(sample) or isinstance(
                got, RuntimeContext
            ), "runtime_context corrupted"
            continue
        if _is_sensitive_key(name):
            # name-driven redaction is the documented contract for this channel
            assert _normalize(got) == _normalize(
                _redact_contract(name, sample)
            ), f"redaction contract mismatch on {name!r}"
            continue
        assert _normalize(got) == _normalize(sample), (
            f"channel {name!r} did not survive the checkpoint round trip verbatim"
        )


def _redact_contract(channel: str, value: Any) -> Any:
    """The documented redaction contract, expressed via the production code."""
    from webpent.graph.checkpoints import _redact_channel

    return _redact_channel(channel, copy.deepcopy(value))


# ---------------------------------------------------------------------------
# Family B — UnifiedState (superset: hunter budget fields + plan channels)
# ---------------------------------------------------------------------------


def test_unified_family_channels_survive_checkpoint(tmp_path):
    unified_channels = _channels(UnifiedState)
    pentest_channels = set(_channels(PentestState))
    unified_only = sorted(set(unified_channels) - pentest_channels)
    assert {"max_decisions", "max_cost_usd", "decisions"} <= set(unified_only), (
        "unified-only channel inventory changed; update this matrix"
    )

    graph_input = {name: _channel_sample(name, 1) for name in unified_channels}
    persisted = _round_trip(
        UnifiedState, graph_input, "matrix-unified", tmp_path / "unified.db"
    )

    missing = sorted(set(unified_channels) - set(persisted))
    assert not missing, f"unified channels lost: {missing}"
    for name in unified_only:
        sample = graph_input[name]
        got = persisted.get(name)
        if _is_sensitive_key(name) or name in _SECRET_CHANNELS:
            continue  # covered by the redaction contract test
        assert _normalize(got) == _normalize(sample), (
            f"unified-only channel {name!r} did not round-trip verbatim"
        )


# ---------------------------------------------------------------------------
# Family C — legacy hunter shape bridged into the unified checkpoint stack
# ---------------------------------------------------------------------------


def test_hunter_bridge_family_round_trips_through_unified_schema(tmp_path):
    hunter_state = {
        "max_llm_calls": 40,
        "max_cost_usd": 5.0,
        "persona": "matrix-hunter",
        "findings": [_probe_finding(1)],
        "hypotheses": [_probe_hypothesis(1)],
        "hunter_decisions": [{"decision": "probe"}],
        "hunter_memory": {"memory": "probe"},
        "hunt_artifact_root": "/tmp/probe-hunt",
    }
    lifted = hunter_state_to_unified(hunter_state)
    # provenance: hunter-only fields are preserved, never dropped (bridge contract)
    legacy_pairs = list(lifted.get("_hunter_legacy_fields") or [])
    assert {name for name, _ in legacy_pairs} == {
        "hunter_decisions",
        "hunter_memory",
        "hunt_artifact_root",
    }

    graph_input = {k: v for k, v in lifted.items() if k != "_hunter_legacy_fields"}
    persisted = _round_trip(
        UnifiedState, graph_input, "matrix-hunter", tmp_path / "hunter.db"
    )

    assert persisted.get("persona") == "matrix-hunter"
    assert persisted.get("max_llm_calls") == 40
    assert persisted.get("max_cost_usd") == 5.0
    assert _normalize(persisted.get("findings")) == _normalize([_probe_finding(1)])
    assert _normalize(persisted.get("hypotheses")) == _normalize([_probe_hypothesis(1)])


# ---------------------------------------------------------------------------
# Redaction contract — explicit, independent of the sweep above
# ---------------------------------------------------------------------------


def test_documented_secret_channels_are_redacted_on_persistence(tmp_path):
    channels = _channels(PentestState)
    assert _SECRET_CHANNELS == {"session_cookies", "session_headers", "identity_profiles"}

    graph_input = {name: _channel_sample(name, 1) for name in channels}
    graph_input["session_cookies"] = {"sid": "secret-cookie-value"}
    graph_input["session_headers"] = {"Authorization": "Bearer secret"}
    graph_input["identity_profiles"] = {"primary": {"user": "u", "password": "p"}}
    graph_input["jwt_weak_secret_candidates"] = ["weak-secret-one"]

    persisted = _round_trip(
        PentestState, graph_input, "matrix-secrets", tmp_path / "secrets.db"
    )

    assert persisted.get("session_cookies") == {}
    assert persisted.get("session_headers") == {}
    assert persisted.get("identity_profiles") == {}
    assert persisted.get("jwt_weak_secret_candidates") == []
    # the secret VALUES must never appear anywhere in the persisted channels
    blob = json.dumps(_normalize(persisted), default=str)
    assert "secret-cookie-value" not in blob
    assert "Bearer secret" not in blob
    assert "weak-secret-one" not in blob


# ---------------------------------------------------------------------------
# Reducer merge matrix — every reducer channel merges, none overwrite
# ---------------------------------------------------------------------------


def _assert_merge_preserved(name: str, existing: Any, new: Any, merged: Any) -> None:
    if name == "runtime_capability_gaps":
        # documented REPLACE semantics: capability gaps describe the CURRENT
        # runtime state, a later write fully supersedes the prior snapshot
        assert _normalize(merged) == _normalize(new), (
            "replace_runtime_capability_gaps must replace, not accumulate"
        )
        return
    if name == "auth_state":
        # upsert-by-cookie-name: the refreshed sid REPLACES, the new name appends
        cookies = merged.get("cookies")
        assert [c["name"] for c in cookies] == ["sid", "fresh"], (
            "merge_auth_state must upsert by cookie name (replace + append)"
        )
        assert cookies[0]["value"] == "v2"
        assert merged.get("status") == "ok"
        return
    if name == "optimization_retries":
        # documented overwrite-per-key: both keys survive, the shared one takes new
        assert merged.get("node1") == 1
        assert merged.get("node2") == 2
        return
    if name == "messages":
        contents = [str(m.content) if isinstance(m, BaseMessage) else str(m) for m in merged]
        assert any("1" in c for c in contents) and any("2" in c for c in contents)
        return
    if name == "findings":
        ids = {str(_model_or_dict_id(f)) for f in merged}
        assert len(ids) == 2, "merge_findings must keep both distinct findings"
        return
    if name == "hypotheses":
        ids = {str(_model_or_dict_id(h)) for h in merged}
        assert len(ids) == 2, "merge_hypotheses must keep both distinct hypotheses"
        return
    # generic contract: every leaf value from BOTH sides survives the merge
    merged_leaves = list(_leaves(_normalize(merged)))
    for side in (existing, new):
        for leaf in _leaves(_normalize(side)):
            if leaf is None:
                continue
            assert leaf in merged_leaves, (
                f"reducer for {name!r} dropped data from one side: {leaf!r}"
            )


def _model_or_dict_id(obj: Any) -> Any:
    if isinstance(obj, dict):
        return obj.get("id")
    return getattr(obj, "id", None)


def test_reducer_merge_matrix_all_reducer_channels_merge():
    channels = _channels(PentestState)
    checked: list[str] = []
    for name in sorted(channels):
        hint = channels[name]
        reducer = _reducer_of(hint)
        if reducer is None:
            continue
        existing = _channel_sample(name, 1)
        new = _channel_sample(name, 2)
        if name == "auth_state":
            # dedicated upsert scenario: refreshed sid + a brand-new cookie
            new = {
                "cookies": [
                    {"name": "sid", "value": "v2", "domain": ".probe.example"},
                    {"name": "fresh", "value": "n", "domain": ".probe.example"},
                ]
            }
        merged = reducer(copy.deepcopy(existing), copy.deepcopy(new))
        _assert_merge_preserved(name, existing, new, merged)
        checked.append(name)

    # the matrix must cover the documented reducer set — a channel silently
    # losing its reducer (the M1b shadowing defect) would drop out of `checked`
    assert {
        "findings",
        "hypotheses",
        "messages",
        "crawled_data",
        "auth_state",
        "payloads_to_test",
        "optimization_retries",
        "consulted_lessons",
        "lesson_priority_adjustments",
        "extracted_lessons",
        "surface_metrics",
        "detector_results",
    } <= set(checked), "a documented reducer channel vanished from the sweep"
    assert len(checked) >= 140, f"reducer coverage collapsed: {len(checked)}"


# ---------------------------------------------------------------------------
# Inventory guard — UnifiedState ⊇ PentestState at the annotation level
# (fast structural pin; the reducer-for-reducer equality lives in
# test_m1b_domain_contracts.py)
# ---------------------------------------------------------------------------


def test_unified_state_channel_inventory_is_a_superset():
    pentest = set(_channels(PentestState))
    unified = set(_channels(UnifiedState))
    assert pentest <= unified
