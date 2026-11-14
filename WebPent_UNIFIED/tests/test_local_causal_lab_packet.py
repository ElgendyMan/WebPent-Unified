from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET_PATH = (
    ROOT / 'reports/evaluation/owner_decision/LOCAL-CAUSAL-LAB-OWNER-DECISION-PACKET-v1.json'
)
INVENTORY_PATH = (
    ROOT / 'reports/evaluation/source_inventory/SOURCE-BACKED-CANDIDATE-INVENTORY-v1.json'
)
CHECKER = ROOT / 'scripts/check_local_causal_lab_packet.py'


def run_checker(packet_path: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if packet_path is not None:
        env['WEBPENT_LOCAL_CAUSAL_PACKET'] = str(packet_path)
    env['WEBPENT_SOURCE_INVENTORY'] = str(INVENTORY_PATH)
    return subprocess.run(
        [sys.executable, str(CHECKER)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_local_causal_packet_is_pending_and_closed():
    result = run_checker()
    assert result.returncode == 0, result.stderr
    assert 'OWNER_APPROVAL_PREFILLED=false' in result.stdout
    assert 'OFFICIAL_P10_GATE=false' in result.stdout


def test_local_causal_packet_rejects_prefilled_approval(tmp_path):
    packet = json.loads(PACKET_PATH.read_text(encoding='utf-8'))
    packet['owner_decision']['approved_case_ids'] = ['webgoat.idor.view_other_profile.v1']
    altered = tmp_path / PACKET_PATH.name
    altered.write_text(json.dumps(packet), encoding='utf-8')
    result = run_checker(altered)
    assert result.returncode != 0
    assert 'implicit or prefilled owner approval' in result.stderr


def test_local_causal_packet_rejects_open_p10_gate(tmp_path):
    packet = json.loads(PACKET_PATH.read_text(encoding='utf-8'))
    packet['current_governance_state']['official_isolated_p10_runs_authorized'] = True
    altered = tmp_path / PACKET_PATH.name
    altered.write_text(json.dumps(packet), encoding='utf-8')
    result = run_checker(altered)
    assert result.returncode != 0
    assert 'official P10 gate is not closed' in result.stderr
