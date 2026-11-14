from __future__ import annotations

import pytest
from test_bounty_report import _finding


def test_fabricated_url_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from webpent.reporter.bounty_report import BountyReportError, build_bounty_report

    finding = _finding(monkeypatch)
    finding["evidence"]["request_sequence"][1]["url"] = "http://127.0.0.1:3000/api/fabricated"
    with pytest.raises(BountyReportError, match="digest_not_bound"):
        build_bounty_report(finding)


def test_fabricated_response_digest_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from webpent.reporter.bounty_report import BountyReportError, build_bounty_report

    finding = _finding(monkeypatch)
    finding["evidence"]["response_sequence"][1]["response_digest"] = "sha256:" + "0" * 64
    with pytest.raises(BountyReportError, match="response_digest_not_bound"):
        build_bounty_report(finding)


def test_fabricated_status_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from webpent.reporter.bounty_report import BountyReportError, build_bounty_report

    finding = _finding(monkeypatch)
    finding["evidence"]["response_sequence"][1]["status_code"] = 403
    finding["evidence"]["response_sequence"][1]["response_digest"] = finding["evidence"]["proof_bundle"]["response_digests"][1]
    with pytest.raises(BountyReportError, match="status_not_bound"):
        build_bounty_report(finding)


def test_reordered_request_sequence_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from webpent.reporter.bounty_report import BountyReportError, build_bounty_report

    finding = _finding(monkeypatch)
    finding["evidence"]["request_sequence"] = list(reversed(finding["evidence"]["request_sequence"]))
    with pytest.raises(BountyReportError, match="digest_not_bound"):
        build_bounty_report(finding)
