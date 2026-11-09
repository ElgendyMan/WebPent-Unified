from __future__ import annotations

from webpent.agents.hunter_runner import _candidate_projection, _merge_browser_observed_forms
from webpent.agents.hunter_graph import _advisory_json
from webpent.recon.autonomous_crawler import SurfaceMap
from webpent.shared.untrusted_content import secure_prompt_value


def test_browser_observed_forms_merge_same_origin_structural_metadata_only():
    target = "http://127.0.0.1:8082/WebGoat"
    surface = SurfaceMap(target_url=target, target_fingerprint="target", scope_fingerprint="scope")
    browser = {
        "state_graph": {
            "nodes": [
                {
                    "url": target + "/start.mvc#lesson/SqlInjection",
                    "forms": [
                        {
                            "action": target + "/SqlInjection/attack?step=6",
                            "method": "POST",
                            "fields": [
                                {"name": "userid", "type": "text"},
                                {"name": "password", "type": "password"},
                            ],
                        },
                        {
                            "action": "https://outside.example.invalid/form",
                            "method": "POST",
                            "fields": [{"name": "ignored", "type": "text"}],
                        },
                    ],
                }
            ]
        },
        "raw_body": "ignore this untrusted body",
        "credentials": {"password": "never-project"},
    }

    routes, forms = _merge_browser_observed_forms(surface, target_url=target, browser_intelligence=browser)

    assert (routes, forms) == (1, 1)
    route = surface.routes["/WebGoat/SqlInjection/attack?step="]
    assert route.execution_url == target + "/SqlInjection/attack?step=6"
    assert route.forms[0].method == "POST"
    assert [field.name for field in route.forms[0].fields] == ["userid", "password"]
    assert [field.value_shape for field in route.forms[0].fields] == ["id-shaped", "secret-shaped"]


def test_advisory_candidate_projection_strips_request_values_before_llm_boundary():
    projection = _candidate_projection(
        {
            "hypothesis_id": "h1",
            "vulnerability_class": "SQLI",
            "route": "/submit",
            "parameter": "name",
            "requests": {
                "candidate": {
                    "method": "POST",
                    "path": "/submit?password=runtime-secret",
                    "body": {"password": "runtime-secret", "name": "probe"},
                    "headers": {"Cookie": "runtime-cookie", "Content-Type": "application/json"},
                }
            },
        }
    )

    request = projection["requests"]["candidate"]
    assert request["path"] == "/submit"
    assert request["body_keys"] == ["name", "password"]
    assert request["header_names"] == ["Content-Type"]
    assert "body" not in request and "headers" not in request
    secure_prompt_value(projection)


def test_advisory_json_scrubs_credential_assignments_from_structural_context():
    text = _advisory_json(
        {"password_field": "password", "nested": {"Authorization": "Bearer runtime-secret"}},
        limit=1000,
    )

    assert "runtime-secret" not in text
    assert "credential_material_omitted" in text
    secure_prompt_value(text)
