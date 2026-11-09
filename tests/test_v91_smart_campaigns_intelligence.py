from webpent.agents.smart_campaigns.agent import smart_campaigns_node


def test_smart_campaigns_projects_research_intelligence_without_execution():
    state = {
        "smart_mode": True,
        "engagement_id": "engagement:test",
        "client_id": "client:test",
        "target": {"url": "https://target.test"},
        "crawled_data": {
            "surface_records": [
                {
                    "record_id": "surface:object:1",
                    "url": "https://target.test/object/1",
                    "method": "GET",
                }
            ]
        },
        "smart_governance": {"profile": "safe-smart"},
        "capability_manifest": {
            "capabilities": {"http_read": {"available": True, "status": "available"}}
        },
        "action_budget": {"used_actions": 0, "used_cost": 0.0},
        "campaign_ledger": {"entries": []},
        "campaign_plan": {"entries": []},
    }

    result = smart_campaigns_node(state)

    assert result["knowledge_gaps"]
    assert result["research_session"]["engagement_id"] == "engagement:test"
    assert result["research_session"]["client_id"] == "client:test"
    assert result["smart_information_actions"]
    assert result["research_decision_trace"]
    assert result["smart_replanning"]["execution_required"] is True
    assert all(item["status"] != "confirmed" for item in result["campaign_task_outcomes"])
