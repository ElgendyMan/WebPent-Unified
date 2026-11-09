"""The Apex Predator — U-APEX-10, the MCP Server (v87).

The MCP surface AI agents talk to: five tools (apex_recon, apex_scan,
apex_chain, apex_status, apex_tools), a manifest with schemas, token auth
with a constant-time compare, and a declared local-only binding — the
networked MCP transport is the operator's deployment concern and stays
out of this codebase (advisory surfaces only, APEX-L-9). Dispatch returns
dicts that always carry the preamble.
"""

from __future__ import annotations

import hashlib
import hmac

from webpent.apex.orchestrator import (
    AdaptiveOrchestrator,
    BrainDecision,
    OrchestrationStatus,
    Target,
)
from webpent.apex.tool_chain_builder import ToolChainBuilder
from webpent.apex.tool_registry import ToolRegistry

PREAMBLE_LINE = (
    "advisory: MCP tools propose and execute only what the operator's "
    "configuration and scope allow; every response carries this line."
)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class ApexMcpServer:
    """Registration + manifest + dispatch. No network code lives here."""

    def __init__(
        self,
        builder: ToolChainBuilder,
        token: str,
        bind: str = "127.0.0.1:0",
        orchestrator: AdaptiveOrchestrator | None = None,
    ) -> None:
        self._builder = builder
        self._token_hash = _hash_token(token)
        self._bind = bind
        if not self._is_loopback_bind(bind):
            raise ValueError(
                f"refusing non-loopback bind {bind!r}: this server exposes "
                "dispatch only and must be bound to 127.0.0.1 or localhost"
            )
        self._orchestrator = orchestrator or AdaptiveOrchestrator(builder=builder)

    @staticmethod
    def _is_loopback_bind(bind: str) -> bool:
        """RT-06: parse the host, never startswith — a host like
        "127.0.0.1.evil.com" is not loopback. RT-19: bare ("::1") and
        bracketed ("[::1]:8080") IPv6 loopback forms parse correctly;
        anything malformed stays rejected (fail closed)."""
        import ipaddress

        host = bind.strip()
        if host.startswith("["):
            end = host.find("]")
            if end == -1:
                return False
            remainder = host[end + 1:]
            if remainder and not remainder.startswith(":"):
                return False
            host = host[1:end]
        elif ":" in host:
            # a bare IPv6 address parses as a whole ("::1" is loopback,
            # "::1:99" is a non-loopback IPv6 address and stays rejected)
            try:
                return ipaddress.ip_address(host).is_loopback
            except ValueError:
                pass
            candidate, _, port = host.rpartition(":")
            if not port.isdigit() or not candidate:
                return False
            host = candidate
        if host == "localhost":
            return True
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return False

    # -- manifest --------------------------------------------------------------

    def manifest(self) -> dict:
        return {
            "server": {
                "bind": self._bind,
                "local_only": self._is_loopback_bind(self._bind),
                "transport_note": (
                    "the networked MCP transport is the operator's "
                    "deployment concern; this server exposes dispatch only"
                ),
            },
            "tools": [
                {
                    "name": "apex_recon",
                    "description": "Run full recon on target.",
                    "schema": {
                        "type": "object",
                        "properties": {"target": {"type": "string"}},
                        "required": ["target"],
                    },
                },
                {
                    "name": "apex_scan",
                    "description": "Run specific capability scan.",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string"},
                            "capability": {"type": "string"},
                        },
                        "required": ["target", "capability"],
                    },
                },
                {
                    "name": "apex_chain",
                    "description": "Build and run a tool chain.",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "hypothesis": {"type": "string"},
                            "target": {"type": "string"},
                        },
                        "required": ["hypothesis", "target"],
                    },
                },
                {
                    "name": "apex_status",
                    "description": "Get current orchestration status.",
                    "schema": {
                        "type": "object",
                        "properties": {},
                        "required": [],
                    },
                },
                {
                    "name": "apex_tools",
                    "description": "List available tools.",
                    "schema": {
                        "type": "object",
                        "properties": {
                            "category": {"type": "string", "nullable": True}
                        },
                        "required": [],
                    },
                },
            ],
        }

    # -- auth -------------------------------------------------------------------

    def _authorize(self, token: str) -> None:
        candidate = _hash_token(token or "")
        if not hmac.compare_digest(candidate, self._token_hash):
            raise PermissionError("invalid or missing MCP token")

    # -- dispatch -----------------------------------------------------------------

    def dispatch(self, tool_name: str, args: dict, token: str) -> dict:
        # RT-14: the advisory contract says every response carries the
        # preamble — including error responses. Auth, unknown tools and
        # missing arguments come back as structured dicts, never raw
        # exceptions that break the JSON surface.
        try:
            self._authorize(token)
            handler = {
                "apex_recon": self._apex_recon,
                "apex_scan": self._apex_scan,
                "apex_chain": self._apex_chain,
                "apex_status": self._apex_status,
                "apex_tools": self._apex_tools,
            }.get(tool_name)
            if handler is None:
                raise ValueError(f"unknown MCP tool {tool_name!r}")
            result = handler(args)
        except (PermissionError, ValueError, KeyError) as exc:
            return {
                "ok": False,
                "error": str(exc),
                "advisory_note": PREAMBLE_LINE,
            }
        return {"ok": True, "result": result, "advisory_note": PREAMBLE_LINE}

    # -- tool implementations ----------------------------------------------------

    def _apex_recon(self, args: dict) -> dict:
        decision = BrainDecision(
            decision_id="mcp-recon",
            hypothesis_type="subdomain_takeover",
            target=args["target"],
        )
        result = self._orchestrator.orchestrate(
            decision, Target(host=args["target"],
                             allowed_scopes=[args["target"]])
        )
        return {"chain_id": result.chain.chain_id,
                "hypothesis_type": result.chain.hypothesis_type}

    def _apex_scan(self, args: dict) -> dict:
        selection = self._builder._registry
        candidates = [
            spec.id for spec in selection.list_tools()
            if args["capability"] in spec.capabilities
        ]
        return {
            "capability": args["capability"],
            "target": args["target"],
            "candidate_tools": candidates,
            "advisory": "candidates listed for operator approval",
        }

    def _apex_chain(self, args: dict) -> dict:
        chain = self._builder.build(args["hypothesis"], args["target"])
        return {"chain": chain.to_dict()}

    def _apex_status(self, args: dict) -> dict:
        status: OrchestrationStatus = self._orchestrator.get_status()
        return status.to_dict()

    def _apex_tools(self, args: dict) -> list:
        registry: ToolRegistry = self._builder._registry
        specs = registry.list_tools(category=args.get("category"))
        return [
            {
                "id": spec.id,
                "name": spec.name,
                "category": spec.category,
                "speed": spec.speed,
                "stealth": spec.stealth,
            }
            for spec in specs
        ]
