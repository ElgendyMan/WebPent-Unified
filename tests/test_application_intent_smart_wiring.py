from webpent.shared.application_intent_graph import build_application_intent_model


def test_surface_records_feed_intent_objects_sinks_and_identity_contexts():
    model = build_application_intent_model(
        {
            "surface_records": [
                {
                    "url": "http://target.test/csv/upload",
                    "method": "POST",
                    "content_type": "multipart/form-data",
                    "fields": {"user_id": "1", "file": "<redacted>"},
                    "tenant": "tenant-a",
                    "authenticated": True,
                    "required_role": "owner",
                    "sink": "csv parser",
                }
            ]
        },
        target_url="http://target.test",
    )

    payload = model.as_dict()

    assert any(item["label"] == "authenticated_actor" for item in payload["actors"])
    assert any(item["label"] == "user" for item in payload["objects"])
    assert any(item["label"] == "parser" for item in payload["sinks"])
    assert any(
        item["role"] == "owner" and item["disposition"] == "observed"
        for item in payload["identities"]
    )
    assert any(item["label"] == "tenant_boundary" for item in payload["trust_boundaries"])
