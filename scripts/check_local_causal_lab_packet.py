from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = Path(
    os.environ.get(
        'WEBPENT_LOCAL_CAUSAL_PACKET',
        ROOT / 'reports/evaluation/owner_decision/LOCAL-CAUSAL-LAB-OWNER-DECISION-PACKET-v1.json',
    )
)
INVENTORY = Path(
    os.environ.get(
        'WEBPENT_SOURCE_INVENTORY',
        ROOT / 'reports/evaluation/source_inventory/SOURCE-BACKED-CANDIDATE-INVENTORY-v1.json',
    )
)
HEX40 = re.compile(r'^[0-9a-f]{40}$')
HEX64 = re.compile(r'^[0-9a-f]{64}$')
APPROVAL_REQUIRED = 'candidate_for_narrow_owner_approval'


def fail(message: str) -> None:
    raise ValueError(message)


def load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f'cannot load {path}: {exc}')


def main() -> int:
    packet = load(PACKET)
    inventory = load(INVENTORY)
    if packet.get('schema') != 'webpent-owner-decision-local-causal-lab-v1':
        fail('unexpected packet schema')
    if packet.get('status') != 'PENDING_OWNER_APPROVAL':
        fail('packet must remain pending owner approval')
    decision = packet.get('owner_decision', {})
    if (
        decision.get('decision') is not None
        or decision.get('approved_targets')
        or decision.get('approved_case_ids')
    ):
        fail('packet contains an implicit or prefilled owner approval')
    state = packet.get('current_governance_state', {})
    if state.get('official_isolated_p10_runs_authorized') is not False:
        fail('official P10 gate is not closed')
    if state.get('bug_bounty') != 'BLOCKED':
        fail('Bug Bounty is not blocked')
    boundary = packet.get('proposed_lab_boundary', {})
    if boundary.get('host_allowlist') != ['127.0.0.1']:
        fail('host allowlist is not loopback-only')
    network = boundary.get('network_policy', {})
    blocked_network_flags = (
        'outbound_network',
        'oast_or_external_callbacks',
        'redirect_following',
        'dns_or_public_ip_resolution',
    )
    if any(network.get(key) is not False for key in blocked_network_flags):
        fail('network boundary is not closed')
    targets = packet.get('immutable_provenance', {}).get('targets', [])
    if {target.get('target_id') for target in targets} != {'owasp_webgoat', 'crapi'}:
        fail('packet must scope exactly WebGoat and crAPI')
    inventory_by_target = {target['target_id']: target for target in inventory['targets']}
    for target in targets:
        if not HEX40.fullmatch(target.get('source_revision', '')):
            fail(f"invalid source revision for {target.get('target_id')}")
        inv = inventory_by_target.get(target['target_id'])
        if inv is None or inv['source_revision'] != target['source_revision']:
            fail(f"source revision drift for {target.get('target_id')}")
        if target['target_id'] == 'crapi' and 'latest' not in target.get('version', '').lower():
            fail('crAPI reproducibility blocker was removed without a pinned digest')
    packet_inventory_sha = packet.get('immutable_provenance', {}).get('inventory_sha256')
    actual_inventory_sha = hashlib.sha256(INVENTORY.read_bytes()).hexdigest()
    if packet_inventory_sha != actual_inventory_sha:
        fail('inventory hash mismatch')
    seen: set[str] = set()
    for target_id, cases in packet.get('cases', {}).items():
        if target_id not in inventory_by_target:
            fail(f'unknown cases target {target_id}')
        inv_cases = {
            case['case_id']: case
            for case in inventory_by_target[target_id].get('source_candidate_surfaces', [])
        }
        for case in cases:
            case_id = case.get('case_id')
            if case_id in seen:
                fail(f'duplicate case {case_id}')
            seen.add(case_id)
            inv_case = inv_cases.get(case_id)
            if inv_case is None:
                fail(f'case {case_id} missing from source inventory')
            source = case.get('source_evidence', {})
            source_hash = source.get('source_sha256')
            if source_hash is None:
                if case.get('lab_disposition') == APPROVAL_REQUIRED:
                    fail(f'missing source hash for {case_id}')
            elif not HEX64.fullmatch(source_hash):
                fail(f'invalid source hash for {case_id}')
            if case.get('current_inventory_decision') != inv_case.get('decision'):
                fail(f'inventory decision drift for {case_id}')
            if case.get('lab_disposition') == APPROVAL_REQUIRED:
                required = (
                    'causal_oracle_proposal',
                    'independent_negative_control',
                    'central_verifier_mapping',
                    'proof_bundle_procedure',
                )
                if any(
                    not case.get(field) or 'not admitted' in case[field].lower()
                    for field in required
                ):
                    fail(f'incomplete causal lab proposal for {case_id}')
                if not case.get('requested_methods'):
                    fail(f'missing methods for {case_id}')
    if not seen:
        fail('packet contains no cases')
    promotion_gate = packet.get('execution_protocol_after_approval', {}).get(
        'promotion_gate', ''
    ).lower()
    if 'official p10' not in promotion_gate:
        fail('promotion gate does not explicitly preserve Official P10 separation')
    if not packet.get('stop_conditions') or not packet.get('cleanup_and_rollback'):
        fail('stop conditions or rollback are missing')
    print('LOCAL_CAUSAL_LAB_PACKET=PASS')
    print(f'CASES_REGISTERED={len(seen)}')
    print('OWNER_APPROVAL_PREFILLED=false')
    print('OFFICIAL_P10_GATE=false')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except ValueError as exc:
        print(f'FAIL: {exc}', file=sys.stderr)
        raise SystemExit(1) from exc
