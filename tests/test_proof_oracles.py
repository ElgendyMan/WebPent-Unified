from webpent.shared.proof_oracles import OracleEngine, OracleFamily


def test_idor_requires_owner_foreign_access_and_denied_control() -> None:
    result = OracleEngine.evaluate(
        OracleFamily.IDOR,
        {
            "owner_accessible": True,
            "foreign_accessible": True,
            "foreign_denied": True,
        },
    )
    assert result.status == "reviewable"
    assert result.reviewable is True


def test_idor_without_negative_control_stays_inconclusive() -> None:
    result = OracleEngine.evaluate(
        OracleFamily.IDOR,
        {"owner_accessible": True, "foreign_accessible": True},
    )
    assert result.status == "inconclusive"
    assert "negative_control" in result.missing


def test_stored_xss_requires_execution_and_fresh_replay() -> None:
    result = OracleEngine.evaluate(
        OracleFamily.STORED_XSS,
        {
            "execution_marker": True,
            "fresh_session_replay": True,
            "encoded_control_safe": True,
            "literal_control_safe": True,
        },
    )
    assert result.reviewable is True


def test_ssrf_requires_correlated_callback_and_negative_absence() -> None:
    result = OracleEngine.evaluate(
        OracleFamily.SSRF,
        {
            "callback_received": True,
            "callback_correlated": True,
            "negative_callback_absent": True,
        },
    )
    assert result.reviewable is True


def test_csv_sqli_requires_causal_signal_and_negative_control() -> None:
    result = OracleEngine.evaluate(
        OracleFamily.CSV_SQLI,
        {
            "differential_observed": True,
            "sql_error_signature": True,
            "negative_control_rejected": True,
        },
    )
    assert result.reviewable is True
