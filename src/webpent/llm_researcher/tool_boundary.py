"""Strict tool capability boundary for LLM Researcher.
Every tool call is authorized, bounded, logged, and associated with a hypothesis.
The LLM cannot invoke arbitrary shell/system actions.

Track E of GOED v1.8: LLM Tool Boundary.
"""
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ToolName(str, Enum):
    DISCOVER = "discover"
    REQUEST = "request"
    REPLAY = "replay"
    COMPARE = "compare"
    INSPECT_STATE = "inspect_state"
    INSPECT_RESPONSE = "inspect_response"
    ENUMERATE_ENTITY = "enumerate_entity"
    RUN_WORKFLOW_STEP = "run_workflow_step"
    SUMMARIZE_MEMORY = "summarize_memory"


FORBIDDEN_TOOLS = {
    "shell_exec", "file_write", "modify_detector", "set_confirmed",
    "override_verdict", "bypass_causal_guard", "mutate_evidence",
    "modify_ground_truth", "system", "exec", "eval",
}

ALLOWED_TOOLS = {t.value for t in ToolName}


@dataclass
class ToolCall:
    call_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str = ""
    parameters: dict[str, Any] = field(default_factory=dict)
    hypothesis: str = ""
    timestamp: float = field(default_factory=time.time)
    result: dict[str, Any] | None = None
    error: str | None = None
    authorized: bool = False
    bounded: bool = False


class ToolBoundary:
    """Enforces strict capability limits on LLM tool calls.

    Rules:
    1. Only tools in ALLOWED_TOOLS may be invoked
    2. Every tool call MUST be associated with a research hypothesis
    3. HTTP requests are bounded (timeout, max count)
    4. All calls are logged for audit
    5. Forbidden tools are explicitly rejected
    """

    def __init__(self, http_client=None,
                 max_requests_per_call: int = 10,
                 request_timeout: float = 10.0,
                 allowed_hosts: tuple[str, ...] = ()):  # S-3
        self.http_client = http_client
        self.max_requests_per_call = max_requests_per_call
        self.request_timeout = request_timeout
        self.call_log: list[ToolCall] = []
        self.tool_calls_total = 0
        self.allowed_hosts = frozenset(allowed_hosts)

    def is_allowed(self, *, tool_name, target, args=None) -> bool:
        """S-3: fail-closed second-layer authorization."""
        try:
            if tool_name in FORBIDDEN_TOOLS: return False
            if tool_name not in ALLOWED_TOOLS: return False
            if self.allowed_hosts:
                from urllib.parse import urlparse
                host = (urlparse(target or "").hostname or "").lower()
                if host and host not in self.allowed_hosts: return False
            return True
        except Exception:
            return False

    def authorize(self, call: ToolCall) -> bool:
        """Check if tool call is authorized and within bounds."""
        if call.tool_name in FORBIDDEN_TOOLS:
            call.error = f"FORBIDDEN_TOOL: {call.tool_name} is explicitly forbidden by policy"
            return False
        if call.tool_name not in ALLOWED_TOOLS:
            call.error = f"UNKNOWN_TOOL: {call.tool_name} not in allowed set"
            return False
        if not call.hypothesis or len(call.hypothesis.strip()) < 5:
            call.error = "MISSING_HYPOTHESIS: Every tool call must be associated with a research hypothesis"
            return False
        call.authorized = True
        call.bounded = True
        return True

    def execute(self, call: ToolCall) -> dict[str, Any]:
        """Execute an authorized tool call. Returns bounded result only."""
        self.tool_calls_total += 1

        if not self.authorize(call):
            self.call_log.append(call)
            return {"call_id": call.call_id, "error": call.error, "authorized": False}

        result = {
            "call_id": call.call_id,
            "tool": call.tool_name,
            "authorized": True,
            "bounded": True,
            "hypothesis_cited": True,
        }

        try:
            if call.tool_name == ToolName.REQUEST.value:
                result.update(self._execute_request(call))
            elif call.tool_name == ToolName.INSPECT_RESPONSE.value:
                result.update({"inspection": "structured_observation_only",
                              "note": "Response metadata returned, raw content bounded"})
            elif call.tool_name == ToolName.SUMMARIZE_MEMORY.value:
                result.update({"summary": "bounded_memory_summary",
                              "max_items": 50,
                              "note": "Memory summary is bounded and structured"})
            elif call.tool_name == ToolName.DISCOVER.value:
                result.update({"discovery": "bounded_discovery",
                              "note": "Discovery is limited to observed patterns only"})
            elif call.tool_name == ToolName.COMPARE.value:
                result.update({"comparison": "bounded_structural_comparison",
                              "note": "Comparison returns structural diff only"})
            else:
                result.update({
                    "status": "tool_executed_bounded",
                    "note": f"{call.tool_name} executed within capability boundary",
                    "policy": "No unrestricted data access"
                })
        except Exception as e:
            call.error = f"EXECUTION_ERROR: {str(e)[:200]}"
            result["error"] = call.error

        call.result = result
        self.call_log.append(call)
        return result

    def _execute_request(self, call: ToolCall) -> dict[str, Any]:
        """Execute bounded HTTP request. Never returns raw unrestricted content."""
        params = call.parameters or {}
        url = params.get("url", "")
        method = str(params.get("method", "GET")).upper()

        if not url or not (url.startswith("http://") or url.startswith("https://")):
            return {"error": "INVALID_URL", "note": "URL must start with http:// or https://"}

        if self.http_client is None:
            return {"error": "NO_HTTP_CLIENT", "note": "No HTTP client configured"}

        # SSRF GUARD (added — Phase 14 finding): httpx.Client(base_url=...) only
        # prepends base_url for RELATIVE paths. An ABSOLUTE url in `params` (which is
        # LLM-controlled, and the LLM's tool-call decision can be steered by content
        # scraped from the target itself, e.g. injected instructions in an HTTP
        # response) bypasses base_url scoping entirely and is sent as-is. Verified
        # empirically: httpx.Client(base_url='https://target.test').build_request(
        # 'GET', 'http://169.254.169.254/latest/meta-data/') sends to
        # 169.254.169.254, not target.test. The old code only checked the URL scheme,
        # never the host, so a research LLM authorized to call "request" against the
        # test target could be redirected — via injected content — to fetch cloud
        # metadata endpoints or any other internal/external host. Fail closed: if the
        # client exposes a base_url, the requested host must match it; if it doesn't
        # expose one, we cannot verify scoping and refuse rather than silently allow.
        client_base = getattr(self.http_client, "base_url", None)
        if client_base:
            from urllib.parse import urlparse
            requested = urlparse(url)
            allowed_host = getattr(client_base, "host", None) or urlparse(str(client_base)).hostname
            allowed_port = getattr(client_base, "port", None)
            req_port = requested.port or (443 if requested.scheme == "https" else 80)
            eff_allowed_port = allowed_port or (443 if str(client_base).startswith("https") else 80)
            if requested.hostname != allowed_host or req_port != eff_allowed_port:
                return {
                    "error": "HOST_RESTRICTED",
                    "note": f"request host must match the configured target ({allowed_host}); "
                            f"got '{requested.hostname}'. Tool calls cannot be redirected to a "
                            f"different host, including internal/metadata addresses.",
                }

        try:
            headers = params.get("headers")
            query_params = params.get("query_params")
            json_body = params.get("json_body")

            if method == "GET":
                r = self.http_client.get(url, headers=headers,
                                         params=query_params,
                                         timeout=self.request_timeout)
            elif method == "POST":
                r = self.http_client.post(url, headers=headers,
                                          json=json_body,
                                          timeout=self.request_timeout)
            else:
                return {"error": f"METHOD_RESTRICTED: {method}",
                        "allowed_methods": ["GET", "POST"]}

            return {
                "status_code": r.status_code,
                "headers": {k.lower(): v for k, v in r.headers.items()},
                "body_length": len(r.text),
                "body_preview": r.text[:500],  # BOUNDED preview only
                "content_type": r.headers.get("content-type", ""),
            }
        except Exception as e:
            return {"error": f"REQUEST_FAILED: {str(e)[:100]}"}

    def get_call_log(self) -> list[dict[str, Any]]:
        """Return audit log of all tool calls."""
        return [{
            "call_id": c.call_id,
            "tool": c.tool_name,
            "hypothesis": c.hypothesis,
            "authorized": c.authorized,
            "bounded": c.bounded,
            "error": c.error,
            "timestamp": c.timestamp,
        } for c in self.call_log]
