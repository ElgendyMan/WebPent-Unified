from webpent.shared.workflow_understanding import extract_workflow_observations


def test_surface_records_feed_identity_aware_workflow_observations():
    observations = extract_workflow_observations(
        {
            "surface_records": [
                {
                    "url": "http://target.test/import",
                    "method": "POST",
                    "content_type": "multipart/form-data",
                    "fields": {"order_id": "1", "file": "<redacted>"},
                    "requires_auth": True,
                    "required_role": "owner",
                    "workflow": "import",
                    "state": "draft",
                    "next_state": "submitted",
                }
            ]
        },
        target_url="http://target.test",
    )

    assert len(observations) == 1
    observation = observations[0]
    assert observation.method == "POST"
    assert "authenticated_identity" in observation.prerequisites
    assert "object_parameter:order_id" in observation.prerequisites
    assert observation.authorization_boundary == "role_scoped"
    assert observation.from_state == "draft"
    assert observation.to_state == "submitted"
