from __future__ import annotations

from webpent.agents.hypothesis_analyzer.agent import hypothesis_node
from webpent.models.targets import Target


def test_post_form_generates_method_body_and_target_parameter() -> None:
    result = hypothesis_node(
        {
            "target": Target(url="https://lab.test"),
            "crawled_data": {
                "endpoints": ["https://lab.test/home"],
                "forms": [
                    {
                        "action": "/vulnerabilities/sqli/",
                        "method": "POST",
                        "data": {"id": "1", "Submit": "Submit"},
                        "source_url": "https://lab.test/home",
                    }
                ],
            },
        }
    )

    hypotheses = result["hypotheses"]
    sqli = [item for item in hypotheses if item.vuln_class == "sqli"]
    assert len(sqli) == 1
    hypothesis = sqli[0]
    assert hypothesis.target_url == "https://lab.test/vulnerabilities/sqli/"
    assert hypothesis.request_method == "POST"
    assert hypothesis.request_data == {"id": "1", "Submit": "Submit"}
    assert hypothesis.target_param == "id"
    assert hypothesis.deterministic_match is True


def test_post_form_does_not_duplicate_existing_endpoint_hypothesis() -> None:
    result = hypothesis_node(
        {
            "target": Target(url="https://lab.test"),
            "crawled_data": {
                "endpoints": ["https://lab.test/vulnerabilities/sqli/"],
                "forms": [
                    {
                        "action": "/vulnerabilities/sqli/",
                        "method": "POST",
                        "data": {"id": "1", "Submit": "Submit"},
                        "source_url": "https://lab.test",
                    }
                ],
            },
        }
    )

    sqli = [item for item in result["hypotheses"] if item.vuln_class == "sqli"]
    assert len(sqli) == 1
    assert sqli[0].request_method == "POST"
    assert sqli[0].target_param == "id"
