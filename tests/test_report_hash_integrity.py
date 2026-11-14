from webpent.utils.crypto import hash_report, verify_report


def test_report_hash_is_stable_after_master_hash_is_embedded():
    report = {
        "thread_id": "thread-1",
        "findings": [{"id": "F-1", "severity": "high"}],
        "audit_trail": {"algorithm": "HMAC-SHA256"},
    }
    expected = hash_report(report)
    report["audit_trail"]["master_report_hash"] = expected
    assert hash_report(report) == expected
    assert verify_report(report, expected)


def test_report_tampering_fails_verification():
    report = {
        "thread_id": "thread-1",
        "findings": [{"id": "F-1", "severity": "high"}],
    }
    expected = hash_report(report)
    report["findings"][0]["severity"] = "critical"
    assert not verify_report(report, expected)
