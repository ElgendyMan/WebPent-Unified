"""L10 §Phase 1 — generation-3 dev-corpus semantics.

App-level tests for the two new L10 dev applications (consign,
permit). These run the apps DIRECTLY (no engine), asserting the
behavior contract the L10 phases must generalize to:

- the defect is demonstrable through the wire only after the
  prerequisite setup the app itself defines (multi-step, state-
  dependent evidence);
- the secured lookalike refuses the same cross-identity operation
  (a control surface always exists);
- the transition_no_vuln variant performs the same cross-identity
  transition but DOCUMENTS it (ground truth clean: a confirmation
  there is a false positive);
- the unavailable_prereq variant blocks the prerequisite
  transition for every probe identity: the prerequisite is
  unattainable in scope, so no finding can be demonstrated there;
- enforcement-order and refusal-shape contracts the engine must
  read correctly (nested refusal envelopes, stage-field presence).

The probe-credential protocol is the corpus's own (actor-a /
actor-b / actor-admin query credentials); nothing here imports the
engine or the ground truth.
"""

from __future__ import annotations

from typing import Any

import pytest

from webpent.appsuite.consign import ConsignApp, ConsignSpec
from webpent.appsuite.permit import PermitApp, PermitSpec

# suite instance ids, seeds, and the app's own probe credentials.
_CS_SEEDS = {"defective": 71, "secured": 72,
             "transition_no_vuln": 73, "unavailable_prereq": 74}
_PM_SEEDS = {"defective": 81, "secured": 82,
             "transition_no_vuln": 83, "unavailable_prereq": 84}


def _post(app: Any, path: str, params: dict[str, str]) -> tuple[
        int, dict[str, str], Any]:
    return app.handle_post(path, params)


# ----------------------------------------------------------- consign

def _cs_route(app: ConsignApp) -> str:
    return f"/{app.route}"


def _cs_ids(app: ConsignApp) -> list[str]:
    return sorted(app._consignments)


def _cs_defect_id(app: ConsignApp) -> str:
    """One consignment of the defect desk."""
    return sorted(
        cs_id for cs_id, cs in app._consignments.items()
        if cs[app.desk_field] == app.defect_desk)[0]


def _cs_healthy_id(app: ConsignApp) -> str:
    return sorted(
        cs_id for cs_id, cs in app._consignments.items()
        if cs[app.desk_field] != app.defect_desk)[0]


def test_consign_defect_requires_funding_then_cross_desk_release() -> (
        None):
    app = ConsignApp(ConsignSpec(_CS_SEEDS["defective"], "defective"))
    target = _cs_defect_id(app)
    actor = app.actor_param
    act = app.action_param
    route = _cs_route(app)

    # the healthy desk enforces its pairing: actor-b cannot release
    # there once funded (and funding there is the consignor's).
    healthy = _cs_healthy_id(app)
    code, _, _ = _post(
        app, f"{route}/{healthy}",
        {actor: "actor-a", act: app.actions["pledge"]})
    assert code == 200
    code, headers, body = _post(
        app, f"{route}/{healthy}",
        {actor: "actor-b", act: app.actions["release"]})
    assert code == 403
    assert headers[app.outcome_header] == "refused"

    # early release on the defect desk is refused by the TALLY
    # gate first (enforcement order: state before identity), even
    # for the identity the defect would let through.
    code, headers, body = _post(
        app, f"{route}/{target}",
        {actor: "actor-a", act: app.actions["release"]})
    assert code == 409
    assert body[app.state_field] == app.chain[0]
    assert body["refusal"]["reason"] == "stage-unmet"

    # prerequisite setup: a funding record exists, appended by the
    # consignment's own consignor...
    code, _, body = _post(
        app, f"{route}/{target}",
        {actor: "actor-a", act: app.actions["pledge"]})
    assert code == 200
    assert body[app.state_field] == app.chain[1]

    # ...and NOW the cross-desk miswire manifests: actor-a (the
    # OTHER desk's custodian of record) settles the defect-desk
    # consignment while the defect desk's own custodian of record
    # is refused (identity refusal, no stage field).
    code, headers, body = _post(
        app, f"{route}/{target}",
        {actor: "actor-b", act: app.actions["release"]})
    assert code == 403
    assert app.state_field not in body
    code, _, body = _post(
        app, f"{route}/{target}",
        {actor: "actor-a", act: app.actions["release"]})
    assert code == 200
    assert body[app.applied_field] is True
    assert body[app.state_field] == app.chain[2]
    # the settlement is already applied: the tally gate now refuses
    # further releases, including the defect desk's own custodian.
    code, _, body = _post(
        app, f"{route}/{target}",
        {actor: "actor-b", act: app.actions["release"]})
    assert code == 409
    assert body["refusal"]["reason"] == "stage-unmet"


def test_consign_pledge_is_reserved_to_the_consignor() -> None:
    """No benign open transition exists: funding is the consignor's
    on every variant, so a cross-identity transition that succeeds
    is the defect's miswire or the documented settlement openness
    and nothing else."""
    # defective: a non-consignor's funding is refused by identity
    # (no stage field) and the consignor's funding succeeds.
    app = ConsignApp(ConsignSpec(_CS_SEEDS["defective"], "defective"))
    target = _cs_defect_id(app)
    code, _, body = _post(
        app, f"{_cs_route(app)}/{target}",
        {app.actor_param: "actor-b",
         app.action_param: app.actions["pledge"]})
    assert code == 403
    assert app.state_field not in body
    code, _, _ = _post(
        app, f"{_cs_route(app)}/{target}",
        {app.actor_param: "actor-a",
         app.action_param: app.actions["pledge"]})
    assert code == 200
    # transition_no_vuln: the documented collective escrow covers
    # the SETTLEMENT record only; the pledge stays consignor-
    # reserved there too.
    app = ConsignApp(ConsignSpec(
        _CS_SEEDS["transition_no_vuln"], "transition_no_vuln"))
    target = _cs_defect_id(app)
    code, _, _ = _post(
        app, f"{_cs_route(app)}/{target}",
        {app.actor_param: "actor-b",
         app.action_param: app.actions["pledge"]})
    assert code == 403


def test_consign_secured_refuses_cross_desk_release() -> None:
    app = ConsignApp(ConsignSpec(_CS_SEEDS["secured"], "secured"))
    target = _cs_defect_id(app)
    route = _cs_route(app)
    # the consignor funds...
    code, _, _ = _post(
        app, f"{route}/{target}",
        {app.actor_param: "actor-a",
         app.action_param: app.actions["pledge"]})
    assert code == 200
    # ...the pairing is consulted correctly: the healthy desk's
    # custodian of record cannot release the defect-desk
    # consignment, and the desk's own custodian of record succeeds.
    code, _, body = _post(
        app, f"{route}/{target}",
        {app.actor_param: "actor-a",
         app.action_param: app.actions["release"]})
    assert code == 403
    assert app.state_field not in body  # identity refusal: no stage
    code, _, body = _post(
        app, f"{route}/{target}",
        {app.actor_param: "actor-b",
         app.action_param: app.actions["release"]})
    assert code == 200


def test_consign_transition_no_vuln_is_open_and_documented() -> None:
    app = ConsignApp(ConsignSpec(_CS_SEEDS["transition_no_vuln"], "transition_no_vuln"))
    target = _cs_defect_id(app)
    route = _cs_route(app)
    index = app._index()
    assert "desk_notes" in index["schema"]
    note = index["schema"]["desk_notes"]
    assert target in note
    code, _, _ = _post(
        app, f"{route}/{target}",
        {app.actor_param: "actor-a",
         app.action_param: app.actions["pledge"]})
    assert code == 200
    code, _, _ = _post(
        app, f"{route}/{_cs_healthy_id(app)}",
        {app.actor_param: "actor-b",
         app.action_param: app.actions["release"]})
    assert code == 409  # open policy, but the tally gate still binds
    code, _, _ = _post(
        app, f"{route}/{target}",
        {app.actor_param: "actor-a",
         app.action_param: app.actions["release"]})
    assert code == 200  # cross-identity, but documented: clean


def test_consign_unavailable_prereq_blocks_funding_in_scope() -> None:
    app = ConsignApp(ConsignSpec(_CS_SEEDS["unavailable_prereq"], "unavailable_prereq"))
    target = _cs_defect_id(app)
    route = _cs_route(app)
    for cred in ("actor-a", "actor-b", "actor-admin"):
        code, _, _ = _post(
            app, f"{route}/{target}",
            {app.actor_param: cred,
             app.action_param: app.actions["pledge"]})
        assert code == 403, cred
    # the healthy desk still funds and settles normally (control:
    # the consignor funds).
    code, _, _ = _post(
        app, f"{route}/{_cs_healthy_id(app)}",
        {app.actor_param: "actor-a",
         app.action_param: app.actions["pledge"]})
    assert code == 200


def test_consign_unauthenticated_is_refused() -> None:
    app = ConsignApp(ConsignSpec(_CS_SEEDS["defective"], "defective"))
    code, _, _ = app.handle_get(
        f"{_cs_route(app)}/{_cs_ids(app)[0]}", {})
    assert code == 401


def test_consign_index_publishes_tally_state_model() -> None:
    app = ConsignApp(ConsignSpec(_CS_SEEDS["defective"], "defective"))
    index = app._index()
    schema = index["schema"]
    assert schema["fields"]["custodian"] == app.custodian_field
    assert schema["fields"]["pool"] == app.desk_field
    for cs_id in _cs_ids(app):
        assert schema["state_chains"][cs_id] == list(app.chain)
        assert schema["action_targets"][cs_id][
            app.actions["release"]] == app.chain[2]


# ------------------------------------------------------------ permit

def _pm_route(app: PermitApp) -> str:
    return f"/{app.route}"


def _pm_target(app: PermitApp) -> str:
    return app._identity_target


def _pm_control(app: PermitApp) -> str:
    return sorted(
        pm_id for pm_id in app._permits
        if pm_id != app._identity_target)[0]


def test_permit_defect_requires_full_checklist_then_cross_approval(
) -> None:
    app = PermitApp(PermitSpec(_PM_SEEDS["defective"], "defective"))
    target = _pm_target(app)
    route = _pm_route(app)
    actor = app.actor_param
    act = app.action_param

    # before the checklist is complete the cross-identity approval
    # is refused by the IDENTITY gate (the flaw is state-
    # conditional; the gate order is identity first).
    code, _, body = _post(
        app, f"{route}/{target}",
        {actor: "actor-a", act: app.actions["approve"]})
    assert code == 403
    assert app.state_field not in body

    # prerequisite setup: the examiner performs all three satisfy
    # transitions.
    for _ in range(3):
        code, _, body = _post(
            app, f"{route}/{target}",
            {actor: "actor-b", act: app.actions["satisfy"]})
        assert code == 200
        assert body[app.applied_field] is True
    code, _, body = app.handle_get(f"{route}/{target}", {
        actor: "actor-b"})
    assert code == 200
    assert body[app.state_field] == app.chain[2]

    # NOW the state-conditional skip manifests: the NON-examiner
    # approves the completed file.
    code, _, body = _post(
        app, f"{route}/{target}",
        {actor: "actor-a", act: app.actions["approve"]})
    assert code == 200
    assert body[app.state_field] == app.chain[3]

    # control: the OTHER permits still enforce the examiner check
    # against a non-examiner (the target's examiner is actor-b, and
    # actor-b does not examine the control permit).
    control = _pm_control(app)
    code, _, _ = _post(
        app, f"{route}/{control}",
        {actor: "actor-b", act: app.actions["approve"]})
    assert code == 403


def test_permit_secured_enforces_and_checklist_gate_applies() -> None:
    app = PermitApp(PermitSpec(_PM_SEEDS["secured"], "secured"))
    target = _pm_target(app)
    route = _pm_route(app)
    # complete the checklist as the examiner...
    for _ in range(3):
        code, _, _ = _post(
            app, f"{route}/{target}",
            {app.actor_param: "actor-b",
             app.action_param: app.actions["satisfy"]})
        assert code == 200
    # ...the non-examiner is still refused (identity gate), and the
    # examiner with an INCOMPLETE checklist on another permit is
    # refused by the checklist gate (409, unmet items named).
    code, _, _ = _post(
        app, f"{route}/{target}",
        {app.actor_param: "actor-a",
         app.action_param: app.actions["approve"]})
    assert code == 403
    # the control permit's own examiner is actor-a: satisfy works
    # for them, and the checklist gate (not the identity gate)
    # refuses their approval until the requirements are met.
    control = _pm_control(app)
    code, _, body = _post(
        app, f"{route}/{control}",
        {app.actor_param: "actor-b",
         app.action_param: app.actions["approve"]})
    assert code == 403  # actor-b examines none of the other permits
    code, _, body = _post(
        app, f"{route}/{control}",
        {app.actor_param: "actor-a",
         app.action_param: app.actions["satisfy"]})
    assert code == 200
    code, _, body = _post(
        app, f"{route}/{control}",
        {app.actor_param: "actor-a",
         app.action_param: app.actions["approve"]})
    assert code == 409
    assert body["refusal"]["reason"] == "requirements-unmet"
    assert len(body[app.items_field]) == 2


def test_permit_examiner_incomplete_checklist_gets_unmet_items(
) -> None:
    app = PermitApp(PermitSpec(_PM_SEEDS["secured"], "secured"))
    target = _pm_target(app)
    route = _pm_route(app)
    code, _, body = _post(
        app, f"{route}/{target}",
        {app.actor_param: "actor-b",
         app.action_param: app.actions["approve"]})
    assert code == 409
    assert body["refusal"]["reason"] == "requirements-unmet"
    assert len(body[app.items_field]) == 3


def test_permit_transition_no_vuln_is_open_and_documented() -> None:
    app = PermitApp(PermitSpec(_PM_SEEDS["transition_no_vuln"], "transition_no_vuln"))
    target = _pm_target(app)
    route = _pm_route(app)
    index = app._index()
    note = index["schema"]["desk_notes"]
    assert target in note
    # cross-identity satisfy AND approve succeed...
    for _ in range(3):
        code, _, _ = _post(
            app, f"{route}/{target}",
            {app.actor_param: "actor-a",
             app.action_param: app.actions["satisfy"]})
        assert code == 200
    code, _, _ = _post(
        app, f"{route}/{target}",
        {app.actor_param: "actor-a",
         app.action_param: app.actions["approve"]})
    assert code == 200
    # ...but the checklist gate still binds: an approval with unmet
    # requirements is refused regardless of who asks.
    control = _pm_control(app)
    code, _, _ = _post(
        app, f"{route}/{control}",
        {app.actor_param: "actor-a",
         app.action_param: app.actions["approve"]})
    assert code == 409


def test_permit_unavailable_prereq_blocks_satisfy_in_scope() -> None:
    app = PermitApp(PermitSpec(_PM_SEEDS["unavailable_prereq"], "unavailable_prereq"))
    target = _pm_target(app)
    route = _pm_route(app)
    for cred in ("actor-a", "actor-b", "actor-admin"):
        code, _, _ = _post(
            app, f"{route}/{target}",
            {app.actor_param: cred,
             app.action_param: app.actions["satisfy"]})
        assert code == 403, cred
    # the approval skip is unobservable while the checklist cannot
    # be completed: a non-examiner approval is refused by the
    # identity gate (checklist incomplete).
    code, _, _ = _post(
        app, f"{route}/{target}",
        {app.actor_param: "actor-a",
         app.action_param: app.actions["approve"]})
    assert code == 403
    # other permits examine normally (control: actor-a examines the
    # first permit, so its satisfy succeeds).
    control = _pm_control(app)
    code, _, _ = _post(
        app, f"{route}/{control}",
        {app.actor_param: "actor-a",
         app.action_param: app.actions["satisfy"]})
    assert code == 200


def test_permit_unauthenticated_is_refused() -> None:
    app = PermitApp(PermitSpec(_PM_SEEDS["defective"], "defective"))
    code, _, _ = app.handle_get(
        f"{_pm_route(app)}/{_pm_target(app)}", {})
    assert code == 401


def test_permit_index_publishes_checklist_state_model() -> None:
    app = PermitApp(PermitSpec(_PM_SEEDS["defective"], "defective"))
    index = app._index()
    schema = index["schema"]
    for pm_id in app._permits:
        assert schema["checklist"][pm_id] == list(app.items)
        assert schema["state_chains"][pm_id] == list(app.chain)
        assert schema["action_targets"][pm_id][
            app.actions["approve"]] == app.chain[3]


@pytest.mark.parametrize("spec_cls,seeds", (
    (ConsignSpec, _CS_SEEDS), (PermitSpec, _PM_SEEDS)))
def test_l10_variants_are_deterministic_per_seed(
        spec_cls: Any, seeds: dict[str, int]) -> None:
    """Same seed+variant always builds the same instance."""
    for variant, seed in seeds.items():
        a = spec_cls(seed, variant)
        b = spec_cls(seed, variant)
        assert a.instance_id == b.instance_id
        app_a = (ConsignApp if spec_cls is ConsignSpec
                 else PermitApp)(a)
        app_b = (ConsignApp if spec_cls is ConsignSpec
                 else PermitApp)(b)
        assert app_a._index() == app_b._index()
