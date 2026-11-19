# WebPent VIP source-to-runtime capability inventory

Scope: local static inventory plus test references only; no WAPTLab or external target execution.

| Capability | Definition/source evidence | Runtime reference files | Test reference count | Evidence status |
|---|---|---:|---:|---|
| ActionAuthority | `src/webpent/agents/smart_campaigns/agent.py`,`src/webpent/shared/action_authority.py` `src/webpent/shared/autopentestx_adapter.py`,`src/webpent/shared/campaign_executor.py` `src/webpent/shared/nettacker_adapter.py` | 5 | 8 | multiple source references; runtime wiring requires manual review |
| ActionPolicy | — | 0 | 0 | not found under this exact symbol; inspect equivalent implementation |
| ActionExecutor | `src/webpent/agents/smart_campaigns/agent.py`,`src/webpent/shared/autonomous_controller.py` `src/webpent/shared/campaign_executor.py` | 3 | 3 | multiple source references; runtime wiring requires manual review |
| CapabilityManifest | — | 0 | 0 | not found under this exact symbol; inspect equivalent implementation |
| CoverageLedger | — | 0 | 0 | not found under this exact symbol; inspect equivalent implementation |
| SurfaceEvidenceGraph | `src/webpent/models/surface_graph.py`,`src/webpent/models/surface_security.py` `src/webpent/shared/surface_evidence_graph.py` | 3 | 0 | multiple source references; runtime wiring requires manual review |
| ApplicationIntent | `src/webpent/models/application_intent.py`,`src/webpent/models/surface_security.py` `src/webpent/shared/application_intent_graph.py` | 3 | 0 | multiple source references; runtime wiring requires manual review |
| IdentityTenantObjectGraph | — | 0 | 0 | not found under this exact symbol; inspect equivalent implementation |
| WorkflowReplay | `src/webpent/models/workflow_replay.py`,`src/webpent/shared/workflow_replay.py` | 2 | 0 | multiple source references; runtime wiring requires manual review |
| KnowledgeGap | `src/webpent/agents/smart_campaigns/agent.py`,`src/webpent/shared/research_intelligence.py` | 2 | 1 | multiple source references; runtime wiring requires manual review |
| NextBestAction | `src/webpent/agents/smart_campaigns/agent.py`,`src/webpent/shared/campaign_executor.py` `src/webpent/shared/research_intelligence.py` | 3 | 2 | multiple source references; runtime wiring requires manual review |
| SelfCritique | `src/webpent/agents/strategist/agent.py`,`src/webpent/agents/validator/agent.py` `src/webpent/shared/self_critique.py` | 3 | 2 | multiple source references; runtime wiring requires manual review |
| ProofEngine | — | 0 | 0 | not found under this exact symbol; inspect equivalent implementation |
| ProofBundle | `src/webpent/agents/validator/agent.py`,`src/webpent/models/proof_bundle.py` `src/webpent/validators/proof_validator.py`,`src/webpent/validators/replay_validator.py` | 4 | 0 | multiple source references; runtime wiring requires manual review |
| ValidatorRegistry | — | 0 | 0 | not found under this exact symbol; inspect equivalent implementation |
| Oracle | `src/webpent/shared/offline_validator_fixtures.py`,`src/webpent/shared/proof_oracles.py` | 2 | 1 | multiple source references; runtime wiring requires manual review |
| NegativeControl | `src/webpent/shared/proof_oracles.py` | 1 | 0 | source references found; runtime wiring requires manual review |
| Celery | `src/webpent/agents/execution_sandbox/agent.py`,`src/webpent/api/app.py` `src/webpent/api/scan_registry.py`,`src/webpent/config/settings.py` `src/webpent/memory/db.py`,`src/webpent/memory/lessons.py` `src/webpent/memory/vectorstore.py`,`src/webpent/models/findings.py` `src/webpent/shared/engagement_scope.py`,`src/webpent/shared/llm.py` `src/webpent/shared/preflight.py`,`src/webpent/shared/resume_capability.py` `src/webpent/shared/stealth.py`,`src/webpent/state/initial_state.py` `src/webpent/state/state.py`,`src/webpent/utils/task_crypto.py` `src/webpent/workers/observability.py`,`src/webpent/workers/pentest_worker.py` | 18 | 5 | multiple source references; runtime wiring requires manual review |
| idempotency | `src/webpent/agents/payload_generator/agent.py`,`src/webpent/agents/post_exploit/agent.py` `src/webpent/agents/smart_campaigns/agent.py`,`src/webpent/agents/validator/agent.py` `src/webpent/config/settings.py`,`src/webpent/models/research.py` `src/webpent/shared/action_authority.py`,`src/webpent/shared/action_ledger.py` `src/webpent/shared/autonomous_controller.py`,`src/webpent/shared/autopentestx_adapter.py` `src/webpent/shared/campaign_executor.py`,`src/webpent/shared/nettacker_adapter.py` `src/webpent/shared/research_contracts.py`,`src/webpent/shared/research_intelligence.py` `src/webpent/state/initial_state.py`,`src/webpent/utils/task_crypto.py` | 16 | 9 | multiple source references; runtime wiring requires manual review |
| resume | `src/webpent/agents/execution_sandbox/agent.py`,`src/webpent/agents/exploit_chainer/agent.py` `src/webpent/agents/reporter/agent.py`,`src/webpent/agents/validator/agent.py` `src/webpent/api/app.py`,`src/webpent/api/scan_registry.py` `src/webpent/auth/reauth_vault.py`,`src/webpent/config/settings.py` `src/webpent/models/goal_tree.py`,`src/webpent/shared/bac_identity_tester.py` `src/webpent/shared/engagement_scope.py`,`src/webpent/shared/prioritization.py` `src/webpent/shared/resume_capability.py`,`src/webpent/state/reducers.py` `src/webpent/state/state.py`,`src/webpent/utils/compliance.py` `src/webpent/workers/pentest_worker.py` | 17 | 6 | multiple source references; runtime wiring requires manual review |
| scope | `src/webpent/agents/api_testing/agent.py`,`src/webpent/agents/authentication/agent.py` `src/webpent/agents/business_logic_fuzzer/agent.py`,`src/webpent/agents/cloud_storage/agent.py` `src/webpent/agents/crawler/agent.py`,`src/webpent/agents/execution_sandbox/agent.py` `src/webpent/agents/exploit_chainer/agent.py`,`src/webpent/agents/hypothesis_analyzer/agent.py` `src/webpent/agents/javascript_intelligence/agent.py`,`src/webpent/agents/rabbit_hole/agent.py` `src/webpent/agents/recon/agent.py`,`src/webpent/agents/reporter/agent.py` `src/webpent/agents/request_smuggling/agent.py`,`src/webpent/agents/scope_enforcer/agent.py` `src/webpent/agents/smart_campaigns/agent.py`,`src/webpent/agents/strategist/agent.py` `src/webpent/agents/subdomain_takeover/agent.py`,`src/webpent/agents/target_understanding/agent.py` `src/webpent/agents/team.py`,`src/webpent/agents/validator/agent.py` `src/webpent/agents/validator/structural_checks.py`,`src/webpent/api/app.py` `src/webpent/api/auth.py`,`src/webpent/api/scan_registry.py` `src/webpent/cli/__init__.py`,`src/webpent/cli/manifest.py` `src/webpent/config/policies.py`,`src/webpent/config/settings.py` `src/webpent/experience/__init__.py`,`src/webpent/experience/store.py` `src/webpent/graph/builder.py`,`src/webpent/knowledge/builder.py` `src/webpent/knowledge/target_knowledge.py`,`src/webpent/knowledge/target_model.py` `src/webpent/memory/lessons.py`,`src/webpent/memory/vectorstore.py` `src/webpent/models/adaptive_hunt.py`,`src/webpent/models/decision_log.py` `src/webpent/models/evidence.py`,`src/webpent/models/hypothesis.py` `src/webpent/models/javascript_intelligence.py`,`src/webpent/models/memory.py` `src/webpent/models/mental_model.py`,`src/webpent/models/planner.py` `src/webpent/models/proof_engine.py`,`src/webpent/models/research.py` `src/webpent/models/targets.py`,`src/webpent/models/workflow_replay.py` `src/webpent/models/workflows.py`,`src/webpent/shared/action_authority.py` `src/webpent/shared/adaptive_hunt.py`,`src/webpent/shared/application_intent.py` `src/webpent/shared/application_intent_graph.py`,`src/webpent/shared/attack_graph.py` `src/webpent/shared/autopentestx_adapter.py`,`src/webpent/shared/campaign_planner.py` `src/webpent/shared/campaigns.py`,`src/webpent/shared/capability_manifest.py` `src/webpent/shared/cognitive_components.py`,`src/webpent/shared/coverage_ledger.py` `src/webpent/shared/engagement_scope.py`,`src/webpent/shared/evidence_contract.py` `src/webpent/shared/finding_aggregation.py`,`src/webpent/shared/http.py` `src/webpent/shared/javascript_intelligence.py`,`src/webpent/shared/llm_reliability.py` `src/webpent/shared/memory_boundary.py`,`src/webpent/shared/nettacker_adapter.py` `src/webpent/shared/persistent_finding_ledger.py`,`src/webpent/shared/planner_decisions.py` `src/webpent/shared/prioritization.py`,`src/webpent/shared/proof_engine.py` `src/webpent/shared/proof_oracles.py`,`src/webpent/shared/reference_lookup.py` `src/webpent/shared/report_quality.py`,`src/webpent/shared/research_contracts.py` `src/webpent/shared/research_intelligence.py`,`src/webpent/shared/surface_security.py` `src/webpent/shared/tool_adapters.py`,`src/webpent/shared/workflow_replay.py` `src/webpent/shared/workflow_understanding.py`,`src/webpent/state/state.py` `src/webpent/tools/exploitation/dalfox.py`,`src/webpent/tools/recon/ffuf.py` `src/webpent/tools/recon/httpx.py`,`src/webpent/tools/recon/katana.py` `src/webpent/tools/recon/nuclei.py`,`src/webpent/utils/task_crypto.py` `src/webpent/workers/pentest_worker.py` | 89 | 45 | multiple source references; runtime wiring requires manual review |
| authentication | `src/webpent/agents/access_control/agent.py`,`src/webpent/agents/api_testing/agent.py` `src/webpent/agents/authentication/agent.py`,`src/webpent/agents/business_logic_fuzzer/agent.py` `src/webpent/agents/cloud_storage/agent.py`,`src/webpent/agents/crawler/agent.py` `src/webpent/agents/devils_advocate/agent.py`,`src/webpent/agents/execution_sandbox/agent.py` `src/webpent/agents/executive_summary/agent.py`,`src/webpent/agents/request_smuggling/agent.py` `src/webpent/agents/target_understanding/agent.py`,`src/webpent/agents/validator/agent.py` `src/webpent/agents/validator/structural_checks.py`,`src/webpent/api/app.py` `src/webpent/api/auth.py`,`src/webpent/auth/__init__.py` `src/webpent/auth/reauth_vault.py`,`src/webpent/config/settings.py` `src/webpent/graph/builder.py`,`src/webpent/memory/db.py` `src/webpent/models/surface_security.py`,`src/webpent/shared/adaptive_hunt.py` `src/webpent/shared/http_discovery.py`,`src/webpent/shared/javascript_intelligence.py` `src/webpent/shared/preflight.py`,`src/webpent/shared/surface_evidence_graph.py` `src/webpent/shared/surface_security.py`,`src/webpent/state/initial_state.py` `src/webpent/workers/pentest_worker.py` | 29 | 9 | multiple source references; runtime wiring requires manual review |
| redaction | `src/webpent/agents/access_control/agent.py`,`src/webpent/agents/hypothesis_analyzer/agent.py` `src/webpent/agents/javascript_intelligence/agent.py`,`src/webpent/memory/lessons.py` `src/webpent/models/application_intent.py`,`src/webpent/models/authorization_matrix.py` `src/webpent/models/evidence.py`,`src/webpent/models/javascript_intelligence.py` `src/webpent/models/proof_bundle.py`,`src/webpent/reporter/export.py` `src/webpent/shared/autonomous_controller.py`,`src/webpent/shared/autopentestx_adapter.py` `src/webpent/shared/campaign_executor.py`,`src/webpent/shared/capability_manifest.py` `src/webpent/shared/exceptions.py`,`src/webpent/shared/grounding.py` `src/webpent/shared/llm.py`,`src/webpent/shared/llm_reliability.py` `src/webpent/shared/redaction.py`,`src/webpent/shared/stealth.py` `src/webpent/shared/tool_adapters.py`,`src/webpent/state/initial_state.py` `src/webpent/tools/registry.py` | 23 | 7 | multiple source references; runtime wiring requires manual review |
| autonomous_controller | `src/webpent/graph/builder.py`,`src/webpent/shared/autonomous_controller.py` `src/webpent/state/initial_state.py`,`src/webpent/state/state.py` | 4 | 3 | multiple source references; runtime wiring requires manual review |

## Direct-I/O enforcement evidence
```text
src/webpent/agents/api_testing/agent.py:118:    # No fallback to raw httpx.Client: every network request must pass
src/webpent/agents/api_testing/agent.py:219:    # No fallback to raw httpx.Client: every network request must pass
src/webpent/agents/api_testing/agent.py:404:    # No fallback to raw httpx.Client: every network request must pass
src/webpent/agents/api_testing/agent.py:451:                                    f"requests."
src/webpent/agents/authentication/agent.py:14:lightweight HTTP request and, if valid, skips Playwright login
src/webpent/agents/authentication/agent.py:16:via the API — Playwright login is fragile against DVWA's CSRF token
src/webpent/agents/authentication/agent.py:87:    """Launch Playwright, perform login, and return session cookies.
src/webpent/agents/authentication/agent.py:140:        # redirect Playwright to internal IPs (169.254.169.254 AWS
src/webpent/agents/authentication/agent.py:147:        # Playwright may execute route callbacks outside the caller's
src/webpent/agents/authentication/agent.py:303:        logger.warning("Playwright authentication failed: %s", exc)
src/webpent/agents/authentication/agent.py:341:        # to a raw ``httpx.Client``, which BYPASSES the SSRF pinning
src/webpent/agents/authentication/agent.py:480:    lightweight HTTP request and, if valid, skips Playwright login.
src/webpent/agents/authentication/agent.py:560:    # this base. A fresh cookie obtained via Playwright login is
src/webpent/agents/authentication/agent.py:578:                "Session cookies VALID — skipping Playwright login. "
src/webpent/agents/authentication/agent.py:607:                    f"Playwright login skipped."
src/webpent/agents/authentication/agent.py:619:    # --- Credentials (Playwright login) ---
src/webpent/agents/authentication/agent.py:665:    # V9 FIX-10 + V10 P0-2 Option A: After successful Playwright login,
src/webpent/agents/authentication/agent.py:743:        # with any freshly-extracted Playwright cookies layered on
src/webpent/agents/business_logic_fuzzer/agent.py:365:    # and the Playwright-login path build this same list shape). The
src/webpent/agents/execution_sandbox/agent.py:4:LangGraph node that actively exploits XSS payloads via Playwright by
src/webpent/agents/execution_sandbox/agent.py:10:  1. Launches a headless Chromium browser via Playwright.
src/webpent/agents/execution_sandbox/agent.py:136:    Playwright's ``set_input_files()``. The temp file is deleted in a
src/webpent/agents/execution_sandbox/agent.py:183:                        # is the recommended Playwright API.
src/webpent/agents/execution_sandbox/agent.py:227:    """Test a single payload against ``url`` via Playwright with a hard deadline.
src/webpent/agents/execution_sandbox/agent.py:261:        # context.new_page() / page.goto(). Without this, Playwright
src/webpent/agents/execution_sandbox/agent.py:354:        logger.warning("Playwright payload test failed for %s: %s", url, exc)
src/webpent/agents/execution_sandbox/agent.py:394:                    "Playwright XSS promotion blocked for %s: neutral control also triggered",
src/webpent/agents/execution_sandbox/agent.py:440:                "Playwright CONFIRMED XSS for finding %s (%s) — upgrading confidence",
src/webpent/agents/execution_sandbox/agent.py:463:            # worker crashes or times out after Playwright confirmation.
src/webpent/agents/execution_sandbox/agent.py:480:                    "Incrementally persisted Playwright-confirmed finding %s",
src/webpent/agents/execution_sandbox/agent.py:506:        "Playwright did not confirm XSS for finding %s — keeping original confidence",
src/webpent/agents/execution_sandbox/agent.py:515:    """V4.5 Sprint 2: Perform authenticated login via Playwright.
src/webpent/agents/execution_sandbox/agent.py:602:        logger.warning("Playwright login failed: %s", exc)
src/webpent/agents/execution_sandbox/agent.py:637:    V4.5 Sprint 2: Adds Playwright pre-flight health check and
src/webpent/agents/execution_sandbox/agent.py:687:        "Execution sandbox (Playwright) phase entered for target=%s "
src/webpent/agents/execution_sandbox/agent.py:722:        logger.info("Playwright disabled by pre-flight check — skipping sandbox")
src/webpent/agents/execution_sandbox/agent.py:725:            "messages": [AIMessage(content="Execution sandbox: Playwright disabled (pre-flight).")],
src/webpent/agents/execution_sandbox/agent.py:730:        logger.info("No payloads to test — skipping Playwright execution")
src/webpent/agents/execution_sandbox/agent.py:740:    # findings about to be tested, so Playwright's TCP connections go
src/webpent/agents/execution_sandbox/agent.py:750:        logger.error("Could not launch Playwright browser — skipping sandbox execution")
src/webpent/agents/execution_sandbox/agent.py:753:            "messages": [AIMessage(content="Execution sandbox: Playwright unavailable — skipped.")],
src/webpent/agents/execution_sandbox/agent.py:829:        f"Execution sandbox (Playwright) completed. Tested {tested_count} "
src/webpent/agents/executive_summary/agent.py:194:    # Playwright dialog detection — the authoritative signal is
src/webpent/agents/payload_generator/agent.py:164:# through the Playwright dialog-detection test — which can only ever
src/webpent/agents/post_exploit/agent.py:168:    ``subprocess.TimeoutExpired`` and other execution errors gracefully.
src/webpent/agents/recon/agent.py:468:            "directly with httpx. Nuclei will still run against %s.",
src/webpent/agents/request_smuggling/agent.py:72:    sock: socket.socket | None = None
src/webpent/agents/request_smuggling/agent.py:95:        sock = socket.create_connection(
src/webpent/agents/request_smuggling/agent.py:477:                        f"to smuggle requests."
src/webpent/agents/subdomain_takeover/agent.py:89:        _name, aliases, _addresses = socket.gethostbyname_ex(host)
src/webpent/agents/validator/agent.py:689:    """V5 Sprint 8: Fetch fully-rendered HTML via Playwright.
src/webpent/agents/validator/agent.py:693:    pre-hydration HTML and produces false positives. Playwright runs
src/webpent/agents/validator/agent.py:698:    Returns the rendered HTML string, or ``None`` if Playwright is
src/webpent/agents/validator/agent.py:736:                # the Playwright context BEFORE any page.goto() /
src/webpent/agents/validator/agent.py:737:                # context.new_page() calls. Without this, Playwright
src/webpent/agents/validator/agent.py:767:        logger.warning("Playwright CSRF fetch failed for %s: %s", url, exc)
src/webpent/agents/validator/agent.py:778:    requests. In such cases the CSRF finding should be flagged as
src/webpent/agents/validator/agent.py:785:            (e.g. ``httpx.Response.headers`` or a dict).
src/webpent/agents/validator/agent.py:823:    V5 Sprint 8: Uses Playwright to fetch the fully-rendered DOM when
src/webpent/agents/validator/agent.py:834:      1. Playwright is enabled and successfully rendered the page (so
src/webpent/agents/validator/agent.py:845:    # Extract auth cookies from auth_state (if present) for Playwright.
src/webpent/agents/validator/agent.py:855:    # ---- Try Playwright first when enabled ----
src/webpent/agents/validator/agent.py:862:                "CSRF validation: fetched rendered DOM via Playwright for %s",
src/webpent/agents/validator/agent.py:867:                "CSRF validation: Playwright enabled but fetch failed — "
src/webpent/agents/validator/agent.py:872:                "Playwright was enabled but could not render the page "
src/webpent/agents/validator/agent.py:933:        "Rendered via Playwright (JS-executed DOM)."
src/webpent/agents/validator/agent.py:941:    #   1. Playwright rendered the DOM (JS-injected tokens visible)
src/webpent/agents/validator/agent.py:952:            "Playwright-rendered DOM, no SameSite cookies",
src/webpent/agents/validator/agent.py:1058:#   3. Issue the crafted request via httpx.
src/webpent/agents/validator/agent.py:1833:    Playwright-rendered DOM (avoiding SPA false positives) with
src/webpent/agents/validator/agent.py:1838:    (via the same Playwright helper auth_node uses) when the operator
src/webpent/agents/validator/agent.py:2135:    # and rate-limiting before spawning the subprocess.
src/webpent/agents/validator/agent.py:2209:                    # attempt ONE re-login via the same Playwright helper
src/webpent/agents/validator/agent.py:2216:                    # a successful initial Playwright login (so it isn't
src/webpent/agents/validator/agent.py:2221:                    # Playwright login attempt that is doomed to fail,
src/webpent/agents/validator/agent.py:2305:                            # Playwright shape) written once by auth_node
src/webpent/agents/validator/agent.py:2900:    CSRF validator can use Playwright-rendered DOM with authenticated
src/webpent/agents/validator/structural_checks.py:41:    engagement-scope allowlist). No raw httpx.
src/webpent/api/app.py:113:# requests. FastAPI runs sync def endpoints in a threadpool, so two
src/webpent/api/app.py:152:    check-then-set race between concurrent status-poll requests.
src/webpent/api/app.py:416:    # auth_node skips Playwright login and uses these cookies directly
src/webpent/api/app.py:423:            "authenticated scanning without Playwright login. Shape: "
src/webpent/api/app.py:426:            "lightweight request and skips Playwright login. Takes "
src/webpent/api/app.py:1399:    measuring response latency across many requests.
src/webpent/cli/__init__.py:80:    Playwright login — same precedence as the API path.
src/webpent/cli/__init__.py:144:    """Launch Playwright Chromium once to verify availability.
src/webpent/cli/__init__.py:148:    console.print("[dim]Pre-flight: Checking Playwright Chromium...[/dim]")
src/webpent/cli/__init__.py:156:        console.print("[green]✓ Playwright Chromium available.[/green]")
src/webpent/cli/__init__.py:160:            f"[yellow]⚠ Playwright unavailable: {exc}[/yellow]\n"
src/webpent/cli/__init__.py:188:            "without Playwright login, e.g. 'PHPSESSID=abc123; security=low'. "
src/webpent/cli/__init__.py:192:            "Playwright login. Takes precedence over --creds if both are "
src/webpent/cli/__init__.py:252:            "before external tools and Playwright actions to evade "
src/webpent/cli/__init__.py:456:    header.add_row("Playwright", "Available" if playwright_enabled else "Disabled")
src/webpent/cli/__init__.py:492:            "Playwright actions will be paced with randomized jitter.[/dim yellow]"
src/webpent/cli/__init__.py:718:    """Run pre-flight health checks for all tools and Playwright."""
src/webpent/cli/__init__.py:721:    # Playwright
src/webpent/cli/__init__.py:768:        console.print("\n[yellow]⚠ Playwright is disabled — sandbox will skip gracefully.[/yellow]")
src/webpent/cli/git_source.py:71:        completed = subprocess.run(
src/webpent/cli/git_source.py:84:    except subprocess.TimeoutExpired as exc:
src/webpent/config/settings.py:348:            "state-changing surfaces without executing requests."
src/webpent/config/settings.py:597:        description="Retries for sqlmap POST form requests.",
src/webpent/config/settings.py:736:    # Playwright navigation/form-submit, and enforces a minimum spacing
src/webpent/config/settings.py:745:            "Minimum jitter (seconds) inserted before tool/Playwright "
src/webpent/config/settings.py:753:            "Maximum jitter (seconds) inserted before tool/Playwright "
src/webpent/graph/builder.py:514:        # offline mode, a browser-only validator without Playwright, or a
src/webpent/integrations/webhook.py:36:# a raw httpx.AsyncClient, bypassing the SSRF guard installed by
src/webpent/shared/adaptive_hunt.py:3:This module deliberately emits *tasks*, not HTTP requests.  An existing
src/webpent/shared/capability_manifest.py:59:        completed = subprocess.run(
src/webpent/shared/capability_manifest.py:64:    except (OSError, subprocess.SubprocessError):
src/webpent/shared/engagement_scope.py:8:``shared/http.py``'s SSRF guard (httpx transports + Playwright route
src/webpent/shared/engagement_scope.py:53:For the same reason, ``shared/http.py``'s Playwright guard does not
src/webpent/shared/engagement_scope.py:55:(Playwright's Python sync API may dispatch callbacks off the calling
src/webpent/shared/engagement_scope.py:60:of which thread/greenlet Playwright invokes the callback from.
src/webpent/shared/http.py:18:  * :func:`make_safe_httpx_client` — synchronous :class:`httpx.Client`
src/webpent/shared/http.py:19:  * :func:`make_safe_httpx_async_client` — async :class:`httpx.AsyncClient`
src/webpent/shared/http.py:28:    :class:`httpx.RequestError`) if the resolved IP falls in any of
src/webpent/shared/http.py:47:    :class:`httpx.BaseTransport` (sync) / :class:`httpx.AsyncBaseTransport`
src/webpent/shared/http.py:50:      1. Resolves the request host once (via :func:`socket.getaddrinfo`).
src/webpent/shared/http.py:68:    was using a raw ``httpx.AsyncClient`` and bypassing the guard
src/webpent/shared/http.py:91:verbatim to the underlying :class:`httpx.Client` /
```

## Graph/node inventory
```text
src/webpent/agents/__init__.py
src/webpent/agents/access_control/__init__.py
src/webpent/agents/access_control/agent.py
src/webpent/agents/api_testing/__init__.py
src/webpent/agents/api_testing/agent.py
src/webpent/agents/attack_graph/__init__.py
src/webpent/agents/attack_graph/agent.py
src/webpent/agents/authentication/__init__.py
src/webpent/agents/authentication/agent.py
src/webpent/agents/business_impact/__init__.py
src/webpent/agents/business_impact/agent.py
src/webpent/agents/business_logic_fuzzer/__init__.py
src/webpent/agents/business_logic_fuzzer/agent.py
src/webpent/agents/cloud_storage/__init__.py
src/webpent/agents/cloud_storage/agent.py
src/webpent/agents/crawler/__init__.py
src/webpent/agents/crawler/agent.py
src/webpent/agents/cross_reasoning/__init__.py
src/webpent/agents/cross_reasoning/agent.py
src/webpent/agents/cvss_engine/__init__.py
src/webpent/agents/cvss_engine/agent.py
src/webpent/agents/devils_advocate/__init__.py
src/webpent/agents/devils_advocate/agent.py
src/webpent/agents/disclosed_report_intel/agent.py
src/webpent/agents/execution_sandbox/__init__.py
src/webpent/agents/execution_sandbox/agent.py
src/webpent/agents/executive_summary/__init__.py
src/webpent/agents/executive_summary/agent.py
src/webpent/agents/exploit_chainer/__init__.py
src/webpent/agents/exploit_chainer/agent.py
src/webpent/agents/hypothesis_analyzer/__init__.py
src/webpent/agents/hypothesis_analyzer/agent.py
src/webpent/agents/javascript_intelligence/__init__.py
src/webpent/agents/javascript_intelligence/agent.py
src/webpent/agents/payload_generator/__init__.py
src/webpent/agents/payload_generator/agent.py
src/webpent/agents/payload_optimizer/__init__.py
src/webpent/agents/payload_optimizer/agent.py
src/webpent/agents/planner/__init__.py
src/webpent/agents/planner/agent.py
src/webpent/agents/post_exploit/__init__.py
src/webpent/agents/post_exploit/agent.py
src/webpent/agents/rabbit_hole/__init__.py
src/webpent/agents/rabbit_hole/agent.py
src/webpent/agents/recon/__init__.py
src/webpent/agents/recon/agent.py
src/webpent/agents/reflection/__init__.py
src/webpent/agents/reflection/agent.py
src/webpent/agents/reporter/__init__.py
src/webpent/agents/reporter/agent.py
src/webpent/agents/request_smuggling/__init__.py
src/webpent/agents/request_smuggling/agent.py
src/webpent/agents/scope_enforcer/__init__.py
src/webpent/agents/scope_enforcer/agent.py
src/webpent/agents/smart_campaigns/__init__.py
src/webpent/agents/smart_campaigns/agent.py
src/webpent/agents/strategist/__init__.py
src/webpent/agents/strategist/agent.py
src/webpent/agents/subdomain_takeover/__init__.py
src/webpent/agents/subdomain_takeover/agent.py
src/webpent/agents/target_understanding/__init__.py
src/webpent/agents/target_understanding/agent.py
src/webpent/agents/team.py
src/webpent/agents/validator/__init__.py
src/webpent/agents/validator/active_checks.py
src/webpent/agents/validator/agent.py
src/webpent/agents/validator/registry.py
src/webpent/agents/validator/structural_checks.py
src/webpent/agents/waf_detector/__init__.py
src/webpent/agents/waf_detector/agent.py
src/webpent/graph/__init__.py
src/webpent/graph/builder.py
src/webpent/graph/checkpoints.py
src/webpent/models/__init__.py
src/webpent/models/adaptive_hunt.py
src/webpent/models/application_intent.py
src/webpent/models/attack_graph.py
src/webpent/models/authorization_matrix.py
src/webpent/models/campaigns.py
src/webpent/models/decision_log.py
src/webpent/models/evidence.py
src/webpent/models/evidence_ledger.py
src/webpent/models/findings.py
src/webpent/models/goal_tree.py
src/webpent/models/hypothesis.py
src/webpent/models/javascript_intelligence.py
src/webpent/models/memory.py
src/webpent/models/mental_model.py
src/webpent/models/planner.py
src/webpent/models/proof_bundle.py
src/webpent/models/proof_engine.py
src/webpent/models/research.py
src/webpent/models/surface_graph.py
src/webpent/models/surface_security.py
src/webpent/models/targets.py
src/webpent/models/workflow_replay.py
src/webpent/models/workflows.py
src/webpent/shared/__init__.py
src/webpent/shared/action_authority.py
src/webpent/shared/action_ledger.py
src/webpent/shared/adaptive_hunt.py
src/webpent/shared/application_intent.py
src/webpent/shared/application_intent_graph.py
src/webpent/shared/attack_graph.py
src/webpent/shared/authorization_matrix.py
src/webpent/shared/autonomous_controller.py
src/webpent/shared/autopentestx_adapter.py
src/webpent/shared/bac_identity_tester.py
src/webpent/shared/campaign_executor.py
src/webpent/shared/campaign_planner.py
src/webpent/shared/campaigns.py
src/webpent/shared/capability_manifest.py
src/webpent/shared/cognitive_components.py
src/webpent/shared/confidence.py
src/webpent/shared/console.py
src/webpent/shared/copilot_boundary.py
src/webpent/shared/coverage_ledger.py
src/webpent/shared/deserialization.py
src/webpent/shared/disclosed_report_intel.py
src/webpent/shared/engagement_scope.py
src/webpent/shared/evidence_contract.py
src/webpent/shared/evidence_ledger.py
src/webpent/shared/exceptions.py
src/webpent/shared/finding_aggregation.py
src/webpent/shared/grounding.py
src/webpent/shared/http.py
src/webpent/shared/http_discovery.py
src/webpent/shared/javascript_intelligence.py
src/webpent/shared/jwt_deep_testing.py
src/webpent/shared/knowledge_retrieval.py
src/webpent/shared/llm.py
src/webpent/shared/llm_reliability.py
src/webpent/shared/memory_boundary.py
src/webpent/shared/nettacker_adapter.py
src/webpent/shared/novel_behavior.py
src/webpent/shared/offline_validator_fixtures.py
src/webpent/shared/persistent_finding_ledger.py
src/webpent/shared/planner_decisions.py
src/webpent/shared/poc_policy.py
src/webpent/shared/preflight.py
src/webpent/shared/prioritization.py
src/webpent/shared/proof_engine.py
src/webpent/shared/proof_oracles.py
src/webpent/shared/rate_governor.py
src/webpent/shared/recon_triage.py
src/webpent/shared/redaction.py
src/webpent/shared/reference_lookup.py
src/webpent/shared/report_quality.py
src/webpent/shared/research_contracts.py
src/webpent/shared/research_intelligence.py
src/webpent/shared/resume_capability.py
src/webpent/shared/self_critique.py
src/webpent/shared/skill_selector.py
src/webpent/shared/stealth.py
src/webpent/shared/surface_evidence_graph.py
src/webpent/shared/surface_security.py
src/webpent/shared/tool_adapters.py
src/webpent/shared/trust_matrix.py
src/webpent/shared/validator_plugins.py
src/webpent/shared/workflow_replay.py
src/webpent/shared/workflow_understanding.py
src/webpent/state/__init__.py
src/webpent/state/initial_state.py
src/webpent/state/reducers.py
src/webpent/state/state.py
src/webpent/tools/__init__.py
src/webpent/tools/exploitation/__init__.py
src/webpent/tools/exploitation/dalfox.py
src/webpent/tools/exploitation/phpggc.py
src/webpent/tools/exploitation/sqlmap.py
src/webpent/tools/exploitation/ysoserial.py
src/webpent/tools/recon/__init__.py
src/webpent/tools/recon/ffuf.py
src/webpent/tools/recon/httpx.py
src/webpent/tools/recon/katana.py
src/webpent/tools/recon/nuclei.py
src/webpent/tools/recon/subfinder.py
src/webpent/tools/registry.py
src/webpent/tools/utils/__init__.py
src/webpent/tools/utils/subprocess.py
src/webpent/workers/__init__.py
src/webpent/workers/observability.py
src/webpent/workers/pentest_worker.py
```
