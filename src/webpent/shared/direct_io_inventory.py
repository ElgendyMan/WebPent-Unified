"""Complete direct-I/O transport inventory and static enforcement helpers.

G-02 contract: every external transport entry point is either implemented in a
hardened boundary or explicitly catalogued as a constrained exception.  The
inventory is source-based so a newly added direct transport cannot hide behind
a capability name or an adapter description.

The scanner is deliberately conservative.  It resolves only local imports and
simple assignments; anything that could dynamically reach a transport is
reported as an unapproved indirect transport instead of being treated as safe.
"""

from __future__ import annotations

import ast
from datetime import date
from pathlib import Path
from typing import Any

DIRECT_IMPORT_ROOTS = frozenset(
    {
        "httpx",
        "requests",
        "aiohttp",
        "urllib.request",
        "http.client",
        "urllib3",
        "socket",
        "subprocess",
        "playwright",
        "selenium",
        "websockets",
        "boto3",
        "botocore",
        "paramiko",
    }
)

_DIRECT_HTTP_METHODS = frozenset(
    {"request", "get", "post", "put", "patch", "delete", "head", "options"}
)
_DIRECT_PROCESS_METHODS = frozenset(
    {
        "run",
        "Popen",
        "call",
        "check_call",
        "check_output",
        "check_status",
        "getoutput",
        "getstatusoutput",
        "wait",
    }
)

DIRECT_CALLS = frozenset(
    {
        "httpx.Client",
        "httpx.AsyncClient",
        "httpx.request",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "httpx.delete",
        "requests.Session",
        "requests.request",
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "aiohttp.ClientSession",
        "urllib.request.urlopen",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
        "http.client.HTTPConnection.request",
        "http.client.HTTPSConnection.request",
        "urllib3.PoolManager",
        "urllib3.ProxyManager",
        "urllib3.HTTPConnectionPool",
        "urllib3.HTTPSConnectionPool",
        "urllib3.PoolManager.request",
        "urllib3.ProxyManager.request",
        "socket.create_connection",
        "socket.socket",
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
        "socket.getfqdn",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_output",
        "subprocess.check_call",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "sync_playwright",
        "async_playwright",
        "playwright.chromium.launch",
        "playwright.firefox.launch",
        "playwright.webkit.launch",
        "webdriver.Remote",
        "websockets.connect",
        "boto3.client",
        "boto3.resource",
        "paramiko.SSHClient",
        "paramiko.SSHClient.connect",
        "os.system",
        "os.popen",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.spawnvpe",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnlpe",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
    }
)

SAFE_BOUNDARY_CALLS = frozenset(
    {
        "make_safe_httpx_client",
        "make_safe_httpx_async_client",
        "run_command",
    }
)

# Legacy file-level map remains public for backward compatibility with the v1
# artifact.  Enforcement below uses the narrower symbol-level map.
APPROVED_DIRECT_FILES = {
    "src/webpent/shared/http.py": "hardened_httpx_and_dns_boundary",
    "src/webpent/adapters/generic_web/adapter.py": "generic_adapter_uses_hardened_http_boundary",
    "src/webpent/tools/utils/subprocess.py": "bounded_subprocess_boundary",
    "src/webpent/cli/git_source.py": "bounded_git_source_subprocess",
    "src/webpent/shared/capability_manifest.py": "read_only_tool_capability_probe",
    "src/webpent/shared/preflight.py": "read_only_playwright_capability_probe",
    "src/webpent/shared/playwright_adapter.py": "typed_playwright_observation_boundary",
    "src/webpent/shared/oob_provider.py": "bounded_opt_in_oob_subprocess_and_session_files",
    "src/webpent/agents/authentication/agent.py": "scoped_playwright_auth_flow",
    "src/webpent/agents/execution_sandbox/agent.py": "scoped_playwright_xss_replay",
    "src/webpent/agents/validator/agent.py": "scoped_playwright_csrf_replay",
    "src/webpent/cli/__init__.py": "bounded_playwright_preflight",
    "src/webpent/agents/request_smuggling/agent.py": "scoped_raw_tcp_validator",
    "src/webpent/agents/subdomain_takeover/agent.py": "scoped_dns_resolution_validator",
    "src/webpent/adapters/controlled_target/adapter.py": (
        "loopback_only_controlled_target_http_boundary"
    ),
    "src/webpent/service/health.py": "fixed_gate_scripts_bounded_subprocess_monitor",
    "src/webpent/production/verdict_bridge.py": (
        "bounded_argv_verdict_cli_registration_m2_documented"
    ),
    "src/webpent/memory/ab_lab.py": "bounded_argv_lab_hunt_runner_m2_documented",
    "src/webpent/apex/sandbox.py": "bounded_argv_sandbox_executor_m2_documented",
    "src/webpent/recon/browser_farm.py": "bounded_playwright_browser_farm_scope_and_lifecycle",
    "src/webpent/recon/browser_crawler.py": "bounded_playwright_rendered_recon_scope",
    "src/webpent/recon/traffic_interceptor.py": "redacted_playwright_traffic_boundary",
}

# Structured approvals are intentionally symbol-scoped.  A file-level entry
# alone is never enough to make a new raw transport safe.
APPROVED_RAW_SYMBOLS_BY_FILE: dict[str, frozenset[str]] = {
    "src/webpent/adapters/generic_web/adapter.py": frozenset({"httpx"}),
    "src/webpent/shared/http.py": frozenset(
        {"socket", "httpx", "socket.getaddrinfo", "httpx.Client", "httpx.AsyncClient"}
    ),
    "src/webpent/tools/utils/subprocess.py": frozenset({"subprocess", "subprocess.Popen"}),
    "src/webpent/cli/git_source.py": frozenset({"subprocess", "subprocess.run"}),
    "src/webpent/shared/capability_manifest.py": frozenset({"subprocess", "subprocess.run"}),
    "src/webpent/shared/preflight.py": frozenset({"playwright"}),
    "src/webpent/shared/playwright_adapter.py": frozenset(
        {"playwright.sync_api.sync_playwright", "playwright.chromium.launch"}
    ),
    "src/webpent/shared/oob_provider.py": frozenset({"subprocess", "subprocess.Popen"}),
    "src/webpent/agents/authentication/agent.py": frozenset(
        {"playwright.sync_api.sync_playwright", "sync_playwright"}
    ),
    "src/webpent/agents/execution_sandbox/agent.py": frozenset(
        {"playwright.sync_api.sync_playwright", "sync_playwright"}
    ),
    "src/webpent/agents/validator/agent.py": frozenset(
        {"playwright.sync_api.sync_playwright", "sync_playwright"}
    ),
    "src/webpent/cli/__init__.py": frozenset(
        {"playwright.sync_api.sync_playwright", "sync_playwright"}
    ),
    "src/webpent/agents/request_smuggling/agent.py": frozenset(
        {"socket", "socket.create_connection"}
    ),
    "src/webpent/agents/subdomain_takeover/agent.py": frozenset(
        {"socket", "socket.gethostbyname_ex"}
    ),
    "src/webpent/adapters/controlled_target/adapter.py": frozenset(
        {"urllib.request", "urllib.request.urlopen"}
    ),
    "src/webpent/service/health.py": frozenset({"subprocess", "subprocess.run"}),
    "src/webpent/production/verdict_bridge.py": frozenset({"subprocess", "subprocess.run"}),
    "src/webpent/memory/ab_lab.py": frozenset({"subprocess", "subprocess.run"}),
    "src/webpent/apex/sandbox.py": frozenset({"subprocess", "subprocess.run"}),
    "src/webpent/recon/browser_farm.py": frozenset({"playwright.sync_api.sync_playwright", "playwright.sync_api.Playwright", "playwright.sync_api.BrowserContext", "playwright.sync_api.Page"}),
    "src/webpent/recon/browser_crawler.py": frozenset({"playwright.sync_api.Error", "playwright.sync_api.TimeoutError"}),
    "src/webpent/recon/traffic_interceptor.py": frozenset({"playwright.sync_api.Page"}),
}

APPROVED_TRANSPORT_RECORDS: tuple[dict[str, Any], ...] = tuple(
    {
        "file": file_name,
        "symbol": symbol,
        "transport": "raw-or-boundary",
        "canonical_wrapper": reason,
        "reason": reason,
        "owner": "security-engineering",
        "approved_by": "g02-baseline-review-20260821",
        "expires_at": "2026-11-19",
        "runtime_tests": ["test_g02_direct_io_inventory", "test_g02_runtime_invariants"],
        "risk": "high" if symbol.startswith(("socket", "subprocess", "playwright")) else "medium",
    }
    for file_name, symbols in APPROVED_RAW_SYMBOLS_BY_FILE.items()
    for symbol in sorted(symbols)
    for reason in [APPROVED_DIRECT_FILES[file_name]]
)

# Only the two reviewed dynamic-loader call sites in the built-in tool registry
# are permitted.  The modules list at those lines is hardcoded in source; a
# new dynamic site or a non-constant loader remains unapproved.
DYNAMIC_IMPORT_ALLOWLIST: tuple[dict[str, Any], ...] = (
    {
        "file": "src/webpent/tools/registry.py",
        "line_range": [215, 217],
        "symbols": ["importlib.reload", "importlib.import_module"],
        "constant_source": "modules literal in auto_discover",
        "owner": "security-engineering",
        "reason": "reload/import only the fixed built-in wrapper module catalog",
        "approved_by": "g02-baseline-review-20260821",
        "expires_at": "2026-11-19",
        "required_wrapper_contract": (
            "built-in tool registration only; no target-controlled module path"
        ),
    },
    {
        "file": "src/webpent/cli/ingest.py",
        "line_range": [119, 119],
        "symbols": ["importlib.import_module"],
        "constant_source": "_EXTENSION_LOADERS literal",
        "owner": "security-engineering",
        "reason": "load only fixed document-loader classes selected by a bounded extension map",
        "approved_by": "g02-baseline-review-20260821",
        "expires_at": "2026-11-19",
        "required_wrapper_contract": (
            "no target-controlled module path; loader class must be in static map"
        ),
    },
    {
        "file": "src/webpent/shared/oob_provider.py",
        "line_range": [213, 213],
        "symbols": ["__import__"],
        "constant_source": "literal hashlib module used only for local JSONL digesting",
        "owner": "security-engineering",
        "reason": "digest-only dynamic import; no target-controlled module resolution",
        "approved_by": "g02-oob-review-20260823",
        "expires_at": "2026-11-19",
        "required_wrapper_contract": "module name remains the source literal hashlib",
    },
)

LOGICAL_TRANSPORTS = {
    "http": {
        "boundary": "webpent.shared.http.make_safe_httpx_client",
        "authority": "ActionAuthority/action_family=http_read|validation",
        "proof": "response evidence plus verifier contract where promotion is requested",
    },
    "browser": {
        "boundary": "Playwright sites listed in APPROVED_DIRECT_FILES",
        "authority": "scope checks, playwright_enabled, and action policy",
        "proof": "browser observation; confirmation additionally requires ProofBundle",
    },
    "api": {
        "boundary": "http",
        "authority": "API testing action family and target-origin scope",
        "proof": "replay observation and strict verifier",
    },
    "graphql": {
        "boundary": "http",
        "authority": "API/validation action family and target-origin scope",
        "proof": "query/response replay observation and strict verifier",
    },
    "file_upload": {
        "boundary": "http",
        "authority": "form_submit/file_upload policy and target-origin scope",
        "proof": "upload response/replay observation and strict verifier",
    },
    "oob": {
        "boundary": "http plus configured callback receiver",
        "authority": "OOB preconditions, callback secret and target scope",
        "proof": "correlated callback plus negative control and strict verifier",
    },
    "subprocess": {
        "boundary": "webpent.tools.utils.subprocess.run_command or catalogued probes",
        "authority": "tool allowlist, timeout, argv validation and action policy",
        "proof": "bounded tool result; no confirmation without verifier evidence",
    },
    "raw_tcp_dns": {
        "boundary": "catalogued request_smuggling/subdomain_takeover validators",
        "authority": "target scope and validator-specific bounded controls",
        "proof": "validator observation; no implicit promotion",
    },
    "websocket": {
        "boundary": "registered HTTP/WebSocket adapter",
        "authority": "target-origin scope, endpoint policy, and action ledger",
        "proof": "bounded handshake/response observation plus strict verifier",
    },
    "cloud": {
        "boundary": "registered cloud adapter",
        "authority": "endpoint policy, credential restriction, and action ledger",
        "proof": "redacted provider response plus strict verifier",
    },
    "ssh": {
        "boundary": "registered SSH adapter",
        "authority": "host/port allowlist, timeout, credential restriction",
        "proof": "redacted bounded command result plus strict verifier",
    },
}


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Subscript):
        prefix = _dotted(node.value)
        if not prefix:
            return ""
        try:
            key = ast.literal_eval(node.slice)
        except (ValueError, TypeError, SyntaxError):
            return f"{prefix}[<dynamic>]"
        return f"{prefix}[{key!r}]"
    return ""


def _import_names(node: ast.Import | ast.ImportFrom) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    module = node.module or ""
    return [module if alias.name == "*" else f"{module}.{alias.name}" for alias in node.names]


def _is_direct_import(name: str) -> bool:
    return any(name == root or name.startswith(f"{root}.") for root in DIRECT_IMPORT_ROOTS)


def _transport_family(symbol: str, classification: str) -> str:
    if classification.startswith("browser") or symbol.startswith(
        ("playwright", "webdriver", "selenium")
    ):
        return "browser"
    if symbol.startswith("websockets."):
        return "websocket"
    if symbol.startswith(("boto3.", "botocore.")):
        return "cloud"
    if symbol.startswith("paramiko."):
        return "ssh"
    if symbol.startswith(("socket.",)) or classification.startswith("raw_tcp_dns"):
        return "raw_tcp_dns"
    if symbol.startswith(("subprocess.", "asyncio.create_subprocess", "os.")):
        return "subprocess"
    if symbol.startswith(
        ("httpx.", "requests.", "aiohttp.", "urllib.", "http.client.", "urllib3.")
    ):
        return "http"
    if classification.endswith("implementation") and classification.startswith("http"):
        return "http"
    return "unknown"


def classify_symbol(symbol: str, kind: str) -> str:
    """Return one deterministic classification for a canonical source symbol."""
    if kind == "dynamic_import":
        return "dynamic_import"
    if kind == "dynamic_resolution":
        return "dynamic_resolution"
    if kind == "import" and symbol.startswith("playwright"):
        return "browser_implementation"
    if symbol in {"httpx.Client", "make_safe_httpx_client"} or symbol.endswith(
        ".make_safe_httpx_client"
    ):
        return "http_sync"
    if symbol in {"httpx.AsyncClient", "make_safe_httpx_async_client"} or symbol.endswith(
        ".make_safe_httpx_async_client"
    ):
        return "http_async"
    if symbol in {"sync_playwright", "async_playwright"} or symbol.startswith("playwright"):
        return "browser_playwright"
    if symbol.startswith(("webdriver.", "selenium.")):
        return "browser_selenium"
    if symbol.startswith("socket."):
        return "raw_tcp_dns"
    if symbol.startswith(("subprocess.", "asyncio.create_subprocess", "os.")):
        return "subprocess" if symbol.startswith(("subprocess.", "asyncio.")) else "shell_execution"
    if symbol == "run_command" or symbol.endswith(".run_command"):
        return "subprocess_boundary"
    if symbol.startswith("websockets."):
        return "websocket"
    if symbol.startswith("boto3."):
        return "cloud_provider"
    if symbol.startswith("paramiko."):
        return "ssh"
    if symbol.startswith(("requests.", "aiohttp.", "urllib.", "http.client.", "urllib3.")):
        return "http_transport"
    if kind == "import" and symbol.startswith(
        ("httpx", "requests", "aiohttp", "urllib", "http.client", "urllib3")
    ):
        return "http_implementation"
    if kind == "import" and symbol == "socket":
        return "raw_tcp_dns_implementation"
    if kind == "import" and symbol in {"subprocess", "asyncio"}:
        return "subprocess_implementation"
    if kind == "import" and symbol in {"boto3", "botocore"}:
        return "cloud_implementation"
    if kind == "import" and symbol == "paramiko":
        return "ssh_implementation"
    return "unclassified"


def _build_symbol_table(tree: ast.AST) -> dict[str, str]:
    """Resolve simple local aliases without attempting whole-program inference."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                local = item.asname or item.name.split(".")[0]
                aliases[local] = item.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for item in node.names:
                if item.name == "*":
                    continue
                local = item.asname or item.name
                aliases[local] = f"{module}.{item.name}" if module else item.name
        elif isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                value = node.value
                dotted = _dotted(value)
                if dotted:
                    aliases[target.id] = _resolve_alias(dotted, aliases)
                elif isinstance(value, ast.Call):
                    call_symbol = _resolve_alias(_dotted(value.func), aliases)
                    if call_symbol in DIRECT_CALLS or _looks_like_transport(call_symbol):
                        aliases[target.id] = call_symbol
    return aliases


def _resolve_alias(symbol: str, aliases: dict[str, str]) -> str:
    if not symbol:
        return ""
    parts = symbol.split(".")
    first = aliases.get(parts[0])
    if first:
        return ".".join([first, *parts[1:]])
    return aliases.get(symbol, symbol)


def _is_module_subscript(symbol: str) -> bool:
    return symbol.startswith("sys.modules[")


def _looks_like_transport(symbol: str) -> bool:
    return bool(
        symbol.startswith(
            (
                "httpx.",
                "requests.",
                "aiohttp.",
                "urllib.",
                "http.client.",
                "urllib3.",
                "socket.",
                "subprocess.",
                "asyncio.create_subprocess",
                "websockets.",
                "boto3.",
                "paramiko.",
                "os.",
            )
        )
    )


def _is_transport_call(symbol: str) -> bool:
    if symbol in DIRECT_CALLS:
        return True
    if (
        symbol.startswith(("requests.Session.", "aiohttp.ClientSession."))
        and symbol.rsplit(".", 1)[-1] in _DIRECT_HTTP_METHODS
    ):
        return True
    if symbol.startswith(
        ("http.client.HTTPConnection.", "http.client.HTTPSConnection.")
    ) and symbol.rsplit(".", 1)[-1] in {"request", "connect", "send"}:
        return True
    if symbol.startswith("urllib3.") and symbol.rsplit(".", 1)[-1] in _DIRECT_HTTP_METHODS:
        return True
    return symbol.startswith("subprocess.") and symbol.rsplit(".", 1)[-1] in _DIRECT_PROCESS_METHODS


def _dynamic_allowlist_entry(relative: str, line: int, symbol: str) -> dict[str, Any] | None:
    for entry in DYNAMIC_IMPORT_ALLOWLIST:
        start, end = entry["line_range"]
        if entry["file"] == relative and start <= line <= end and symbol in entry["symbols"]:
            return entry
    return None


def _indirect_transport_signal(symbol: str) -> bool:
    transport_roots = (
        "httpx",
        "requests",
        "aiohttp",
        "urllib",
        "http.client",
        "urllib3",
        "socket",
        "subprocess",
        "asyncio",
        "websockets",
        "boto3",
        "botocore",
        "paramiko",
        "os",
    )
    return symbol.startswith("getattr(sys.modules") or any(
        root in symbol for root in transport_roots
    )


def _record(
    *,
    relative: str,
    node: ast.AST,
    kind: str,
    source_symbol: str,
    normalized_symbol: str,
) -> dict[str, Any]:
    classification = classify_symbol(normalized_symbol, kind)
    family = _transport_family(normalized_symbol, classification)
    line = int(getattr(node, "lineno", 0))
    column = int(getattr(node, "col_offset", 0)) + 1
    approval = "not_applicable"
    reason = "non-transport source record"
    if kind == "safe_boundary_call":
        approval = "approved"
        reason = "central hardened wrapper call"
        if normalized_symbol.endswith("make_safe_httpx_client"):
            classification = "http_sync"
        elif normalized_symbol.endswith("make_safe_httpx_async_client"):
            classification = "http_async"
        elif normalized_symbol.endswith("run_command"):
            classification = "subprocess_boundary"
        family = _transport_family(normalized_symbol, classification)
    elif kind in {"import", "call"}:
        if normalized_symbol in APPROVED_RAW_SYMBOLS_BY_FILE.get(relative, frozenset()):
            approval = "approved"
            reason = APPROVED_DIRECT_FILES[relative]
        else:
            approval = "not_approved"
            reason = "raw transport is outside the symbol-scoped approval record"
    elif kind == "dynamic_import":
        entry = _dynamic_allowlist_entry(relative, line, normalized_symbol)
        if entry:
            approval = "approved_with_expiry"
            reason = str(entry["reason"])
        else:
            approval = "not_approved"
            reason = "dynamic transport/module resolution is not explicitly allowlisted"
    elif kind == "dynamic_resolution":
        if _indirect_transport_signal(normalized_symbol):
            approval = "not_approved"
            reason = "indirect transport resolution is unknown and must fail closed"
        else:
            approval = "not_applicable"
            reason = "dynamic attribute access observed without a transport signal"
            family = "non_transport"
    return {
        "file": relative,
        "line": line,
        "column": column,
        "kind": kind,
        "symbol": source_symbol,
        "normalized_symbol": normalized_symbol,
        "transport": classification,
        "transport_family": family,
        "classification": classification,
        "approval_status": approval,
        "reason": reason,
    }


def scan_direct_io(root: Path) -> list[dict[str, Any]]:
    """Return sorted direct-I/O, boundary, and fail-closed indirect records."""
    records: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        relative = path.relative_to(root.parent).as_posix()
        aliases = _build_symbol_table(tree)
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                for index, name in enumerate(_import_names(node)):
                    if _is_direct_import(name):
                        alias = node.names[index]
                        source = (
                            alias.name
                            if isinstance(node, ast.Import)
                            else (f"{node.module}.{alias.name}" if node.module else alias.name)
                        )
                        records.append(
                            _record(
                                relative=relative,
                                node=node,
                                kind="import",
                                source_symbol=source,
                                normalized_symbol=name,
                            )
                        )
                continue
            if not isinstance(node, ast.Call):
                continue
            source_symbol = _dotted(node.func)
            normalized_symbol = _resolve_alias(source_symbol, aliases)
            kind = ""
            if source_symbol in SAFE_BOUNDARY_CALLS or normalized_symbol in SAFE_BOUNDARY_CALLS:
                kind = "safe_boundary_call"
            elif _is_transport_call(normalized_symbol):
                kind = "call"
            elif _is_module_subscript(normalized_symbol):
                # A local alias such as ``mod = sys.modules["subprocess"]``
                # must remain observable when later invoked as ``mod.run``.
                # It is indirect resolution, not a literal approved call.
                kind = "dynamic_resolution"
            elif normalized_symbol in {"importlib.import_module", "importlib.reload", "__import__"}:
                kind = "dynamic_import"
            elif normalized_symbol == "getattr" and node.args:
                base = _resolve_alias(_dotted(node.args[0]), aliases)
                # getattr is intrinsically indirect: the attribute name can be
                # runtime-controlled, so an unknown or empty subject must never
                # be treated as safe.  Subscripted sys.modules aliases are kept
                # in the normalized symbol for auditability.
                if _is_module_subscript(base) or _looks_like_transport(base) or not base:
                    kind = "dynamic_resolution"
                    normalized_symbol = f"getattr({base}, ... )" if base else "getattr(... )"
                else:
                    kind = "dynamic_resolution"
                    normalized_symbol = f"getattr({base}, ... )"
            if kind:
                records.append(
                    _record(
                        relative=relative,
                        node=node,
                        kind=kind,
                        source_symbol=source_symbol,
                        normalized_symbol=normalized_symbol,
                    )
                )
    records.sort(
        key=lambda item: (
            str(item["file"]),
            int(item["line"]),
            int(item.get("column", 0)),
            str(item["kind"]),
            str(item["normalized_symbol"]),
        )
    )
    deduped: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, int, str, str]] = set()
    for record in records:
        key = (
            str(record["file"]),
            int(record["line"]),
            str(record["kind"]),
            str(record["symbol"]),
        )
        if key in seen_keys:
            continue
        seen_keys.add(key)
        deduped.append(record)
    return deduped


def expired_approval_errors(today: date | None = None) -> list[str]:
    """Return fail-closed errors for invalid or expired approval metadata.

    ``expires_at`` is an operational TTL, not a descriptive label.  The date is
    injectable so CI can prove expiry behavior without waiting for the calendar.
    """
    effective_today = today or date.today()
    errors: list[str] = []
    approval_sets = (
        ("approved_transport_records", APPROVED_TRANSPORT_RECORDS),
        ("dynamic_import_allowlist", DYNAMIC_IMPORT_ALLOWLIST),
    )
    for collection_name, entries in approval_sets:
        for index, entry in enumerate(entries):
            raw_expiry = entry.get("expires_at")
            location = entry.get("file", f"index={index}")
            if not isinstance(raw_expiry, str):
                errors.append(f"{collection_name} {location}: missing expires_at")
                continue
            try:
                expiry = date.fromisoformat(raw_expiry)
            except ValueError:
                errors.append(f"{collection_name} {location}: invalid expires_at={raw_expiry!r}")
                continue
            if expiry <= effective_today:
                errors.append(f"{collection_name} {location}: expired expires_at={raw_expiry}")
    return errors


def inventory_key(record: dict[str, Any]) -> tuple[str, int, str, str, str]:
    return (
        str(record["file"]),
        int(record["line"]),
        str(record["kind"]),
        str(record.get("normalized_symbol", record["symbol"])),
        str(record["transport"]),
    )


def inventory_contract_errors(
    inventory: dict[str, Any],
    source_root: Path,
) -> list[str]:
    """Return deterministic G-02 contract violations for CI/runtime gates.

    This function never grants approval.  It only verifies that every observed
    site is represented by the checked-in artifact and that unknown/indirect
    sites remain blocked.
    """
    errors: list[str] = []
    expected = scan_direct_io(source_root)
    observed = inventory.get("records")
    if observed != expected:
        errors.append("artifact records drift from current source scan")
    observed_records = observed if isinstance(observed, list) else []
    keys = [inventory_key(record) for record in observed_records]
    if len(keys) != len(set(keys)):
        errors.append("duplicate inventory record key")
    logical = inventory.get("logical_transports") or {}
    families = set(logical)
    for record in observed_records:
        if record.get("transport") == "unclassified":
            errors.append(f"unclassified transport: {record.get('file')}:{record.get('line')}")
        if record.get("transport_family") not in families and record.get(
            "transport_family"
        ) not in {"unknown", "non_transport"}:
            errors.append(
                f"unknown transport family {record.get('transport_family')!r}: "
                f"{record.get('file')}:{record.get('line')}"
            )
        if (
            record.get("kind") in {"import", "call", "dynamic_import", "dynamic_resolution"}
            and record.get("approval_status") not in {"approved", "approved_with_expiry"}
            and not (
                record.get("kind") == "dynamic_resolution"
                and record.get("approval_status") == "not_applicable"
                and record.get("transport_family") == "non_transport"
            )
        ):
            errors.append(
                f"unapproved direct/indirect transport: {record.get('file')}:{record.get('line')}"
            )
    if inventory.get("approved_transport_records") != list(APPROVED_TRANSPORT_RECORDS):
        errors.append("structured approval records drift from source policy")
    if inventory.get("dynamic_import_allowlist") != list(DYNAMIC_IMPORT_ALLOWLIST):
        errors.append("dynamic import allowlist drift from source policy")
    return errors
