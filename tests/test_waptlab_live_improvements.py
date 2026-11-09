from webpent.agents.recon import agent as recon_agent
from webpent.config.settings import get_settings
from webpent.models.targets import Target
from webpent.tools.recon import nuclei as nuclei_module


def test_ip_literal_recon_preserves_target_url(monkeypatch):
    calls = []

    def fake_httpx(domains):
        calls.append(domains)
        return [{"url": domains[0]}]

    monkeypatch.setattr(recon_agent, "_get_run_httpx", lambda: fake_httpx)
    target = Target(url="http://127.0.0.1:8000")

    results, method = recon_agent._run_subdomain_recon(target)

    assert method == "httpx (ip-literal)"
    assert results == [{"url": "http://127.0.0.1:8000"}]
    assert calls == [["http://127.0.0.1:8000"]]


def test_nuclei_includes_configured_user_agent(monkeypatch):
    captured = {}

    def fake_run_command(cmd, timeout=None):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        return ""

    monkeypatch.setattr(nuclei_module, "run_command", fake_run_command)
    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda host: True,
    )
    monkeypatch.setenv("HTTP_USER_AGENT", "solverfileexpect_2222\r\nX-Injected: no")
    monkeypatch.setenv("NUCLEI_TIMEOUT", "45")
    get_settings.cache_clear()

    assert nuclei_module.run_nuclei(
        "http://127.0.0.1:8000",
        session_cookies={"laravel_session": "redacted"},
    ) == []

    assert captured["timeout"] == 45
    assert "User-Agent: solverfileexpect_2222  X-Injected: no" in captured["cmd"]
    assert "Cookie: laravel_session=redacted" in captured["cmd"]
    get_settings.cache_clear()


def test_nuclei_user_agent_header_is_not_added_when_empty(monkeypatch):
    captured = {}

    def fake_run_command(cmd, timeout=None):
        captured["cmd"] = cmd
        return ""

    monkeypatch.setattr(nuclei_module, "run_command", fake_run_command)
    monkeypatch.setattr(
        "webpent.shared.engagement_scope.is_engagement_target_host",
        lambda host: True,
    )
    monkeypatch.setenv("HTTP_USER_AGENT", "")
    get_settings.cache_clear()

    assert nuclei_module.run_nuclei("http://127.0.0.1:8000") == []
    assert not any(item.startswith("User-Agent: ") for item in captured["cmd"])
    get_settings.cache_clear()
