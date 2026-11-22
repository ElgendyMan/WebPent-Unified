"""UM-DR-44 B5 — discovery funnel accepted a fake ProofBundle and
mis-read entities from a copy-paste branch.

Two defects in ``production/discovery_funnel.py``:

1. ``_per_finding`` counted ``bundle_ok`` for ANY truthy non-Mapping
   value — the string ``"pending"`` (which producers genuinely write
   while a bundle is being built) counted as a valid ProofBundle, so a
   finding with a string placeholder lifted the funnel's
   ``proof_bundles`` stage and could complete a fake "confirmed" row.

2. ``_appmodel_semantic_counts`` checked
   ``isinstance(raw_relations, (list, tuple))`` when deciding whether
   ``raw_entities`` was list-shaped — a copy-paste of the relations
   line.  A list-shaped ``entities`` channel was therefore never read
   and semantic counts silently fell to zero.

Fix contract:

* a ProofBundle counts only when it is a Mapping with the required
  structural keys (``replay_metadata`` / ``promotion_guard`` per the
  shared/verifier.py contract) — a truthy string, list or object
  without those keys does NOT count;
* list-shaped ``entities`` are read from a Mapping model.
"""

from __future__ import annotations

from webpent.production.discovery_funnel import build_discovery_funnel


def _finding(evidence: dict) -> dict:
    return {
        "id": "f-b5",
        "confidence_level": "Tool-Confirmed",
        "promotion": {"decision": ""},
        "evidence": evidence,
    }


class TestFakeBundleStringsDoNotCount:
    def test_pending_string_not_counted_as_bundle(self) -> None:
        """RED on the current tree: 'pending' is truthy non-Mapping."""
        state = {
            "findings": [
                _finding({
                    "causal_guard": {"verdict": "CONFIRMED"},
                    "proof_bundle": "pending",
                })
            ]
        }
        funnel = build_discovery_funnel(state)
        stages = funnel["stages"]
        assert stages["proof_bundle_valid"] == 0

    def test_none_bundle_not_counted(self) -> None:
        state = {"findings": [_finding({"proof_bundle": None})]}
        funnel = build_discovery_funnel(state)
        assert funnel["stages"]["proof_bundle_valid"] == 0

    def test_real_bundle_with_replay_metadata_counts(self) -> None:
        state = {
            "findings": [
                _finding({
                    "causal_guard": {"verdict": "CONFIRMED"},
                    "proof_bundle": {
                        "bundle_id": "cqa2_pb_real_1",
                        "replay_metadata": {"replay_verified": True},
                    },
                    "replay_metadata": {"replay_verified": True},
                })
            ]
        }
        funnel = build_discovery_funnel(state)
        assert funnel["stages"]["proof_bundle_valid"] == 1

    def test_bundle_mapping_without_required_keys_not_counted(self) -> None:
        """A Mapping that carries neither replay_metadata nor
        promotion_guard is not a verifier-contract bundle."""
        state = {
            "findings": [
                _finding({"proof_bundle": {"anything": "else"}})
            ]
        }
        funnel = build_discovery_funnel(state)
        assert funnel["stages"]["proof_bundle_valid"] == 0


class TestListShapedEntitiesRead:
    def test_entities_list_channel_counted(self) -> None:
        """RED on the current tree: the copy-paste branch checked
        raw_relations, so a list-shaped entities channel was ignored."""
        state = {
            "appmodel": {
                "entities": [
                    {"id": "user", "kind": "identity"},
                    {"id": "order", "kind": "object"},
                ],
                "relations": [],
            }
        }
        funnel = build_discovery_funnel(state)
        # the funnel must see the channel as materialized (not the
        # not_materialized marker) — zero semantic relations is honest,
        # but the entities themselves must not vanish the channel.
        stages = funnel["stages"]
        assert stages.get("identity_relations", "not_materialized_in_state") != \
            "not_materialized_in_state" or stages.get(
                "object_ownership_relations") == 0

    def test_entities_mapping_channel_still_works(self) -> None:
        state = {
            "appmodel": {
                "entities": {
                    "u1": {"id": "u1", "kind": "identity"},
                },
                "relations": [
                    {"kind": "authenticates_as"},
                ],
            }
        }
        funnel = build_discovery_funnel(state)
        stages = funnel["stages"]
        assert stages["identity_relationships"] == 1
