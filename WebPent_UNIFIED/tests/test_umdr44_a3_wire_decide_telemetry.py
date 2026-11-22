"""UM-DR-44 A3 — wire decide() and the identity telemetry into the
production merge path.

Findings on the current tree:

* ``hypothesis_identity.decide()`` — the §5.3 unknown-identity merge
  POLICY — had no production consumer: only tests called it.  The
  production merge (``state/reducers.merge_hypotheses``) implemented
  its own pair logic, so the policy and the implementation could
  drift apart silently.
* ``last_identity_telemetry`` — the §8 bounded counters — was written
  by the dedup pass but read by NOTHING in production (a dead global).

Wiring contract (this test):

1. ``merge_hypotheses`` consults the §5.3 policy (via the module-level
   ``_identity_decide`` seam) for every same-id re-emission — one
   policy, one implementation;
2. the dedup node's update carries the pass's counters under
   ``identity_telemetry`` (readable from state, not just the global);
3. the global stays importable (backward compatibility).
"""

from __future__ import annotations

from unittest.mock import patch

from uuid import uuid4

from webpent.models.hypothesis import Hypothesis
from webpent.production.hypothesis_dedup import (
    deduplicated_hypothesis_node,
    last_identity_telemetry,
)
from webpent.production.hypothesis_identity import decide
from webpent.state.reducers import merge_hypotheses

SHARED_ID = uuid4()


def _hyp(statement: str, *, same_id: bool = True) -> Hypothesis:
    return Hypothesis(
        id=SHARED_ID if same_id else uuid4(),
        target_url="https://t.example.com/orders",
        statement=statement,
        vuln_class="privilege_differential",
        status="unexplored",
    )


class TestMergeConsultsDecide:
    def test_merge_hypotheses_calls_policy(self) -> None:
        """The same-id re-emission path must consult the §5.3 policy."""
        a = _hyp("IDOR on orders")
        b = _hyp("IDOR on orders (re-emission)")  # same id -> collision
        with patch(
            "webpent.state.reducers._identity_decide",
            wraps=decide,
        ) as spy:
            merge_hypotheses([], [a])
            merge_hypotheses([a], [b])
        assert spy.called, (
            "merge_hypotheses must consult the §5.3 pair policy — "
            "one policy, one implementation"
        )

    def test_keep_separate_verdict_retains_distinct_entry(self) -> None:
        """When the policy says keep_separate (target/class differ),
        the re-emission is retained as a distinct entry, not merged."""
        a = _hyp("IDOR on orders")
        b = Hypothesis(
            id=a.id,  # same id arriving again (checkpoint round-trip shape)
            target_url="https://other.example.com/orders",
            statement="IDOR on orders (other target)",
            vuln_class="privilege_differential",
            status="unexplored",
        )
        pool = merge_hypotheses([a], [b])
        # policy: target differs -> keep_separate -> both retained
        assert len(pool) == 2

    def test_merge_verdict_still_merges(self) -> None:
        a = _hyp("IDOR on orders")
        b = _hyp("IDOR on orders (re-emission)")
        pool = merge_hypotheses([a], [b])
        assert len(pool) == 1


class TestTelemetryInNodeUpdate:
    def test_node_update_carries_counters(self) -> None:
        """The dedup node must expose the pass's §8 counters in the
        update under identity_telemetry."""
        from types import SimpleNamespace

        from webpent.models.targets import Target

        state = {
            "target": Target(url="http://127.0.0.1:9000/app/index.php"),
            "endpoints": [{"url": "http://127.0.0.1:9000/app/api/x",
                           "parameters": []}],
            "hypotheses": [],
            "findings": [],
            "coverage_map": {},
            "attack_surface": SimpleNamespace(
                endpoints=[], forms=[], parameters=[]),
        }
        update = deduplicated_hypothesis_node(state)
        assert isinstance(update, dict)
        assert "identity_telemetry" in update
        counters = update["identity_telemetry"]
        assert isinstance(counters, dict)
        assert "hypotheses_emitted" in counters
        assert counters.get("contract_version")


class TestGlobalStillCompatible:
    def test_global_telemetry_object_exists(self) -> None:
        assert last_identity_telemetry is not None
        assert hasattr(last_identity_telemetry, "to_dict")
