"""Independent token-based cross-check for the G-02 AST inventory.

This scanner intentionally uses Python's tokenizer and small lexical patterns,
not the primary AST walker.  It is a disagreement detector, not an approval
engine: a disagreement makes the gate fail closed.
"""

from __future__ import annotations

import io
import re
import tokenize
from pathlib import Path
from typing import Any

_STRING_TOKEN_TYPES = {tokenize.STRING}
for _token_name in ("FSTRING_START", "FSTRING_MIDDLE", "FSTRING_END"):
    _token_type = getattr(tokenize, _token_name, None)
    if _token_type is not None:
        _STRING_TOKEN_TYPES.add(_token_type)

_SECONDARY_IMPORT_ROOTS = frozenset(
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
_SECONDARY_SAFE_BOUNDARIES = frozenset(
    {"make_safe_httpx_client", "make_safe_httpx_async_client", "run_command"}
)
_SECONDARY_DIRECT_CALLS = frozenset(
    {
        "httpx.Client",
        "httpx.AsyncClient",
        "httpx.request",
        "requests.Session",
        "requests.request",
        "aiohttp.ClientSession",
        "urllib.request.urlopen",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
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
    }
)


def _secondary_is_import_root(name: str) -> bool:
    return any(
        name == root or name.startswith(f"{root}.")
        for root in _SECONDARY_IMPORT_ROOTS
    )


def _secondary_is_transport_call(symbol: str) -> bool:
    if symbol in _SECONDARY_DIRECT_CALLS:
        return True
    if symbol.startswith(("requests.Session.", "aiohttp.ClientSession.")):
        return symbol.rsplit(".", 1)[-1] in {
            "request",
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "head",
            "options",
        }
    if symbol.startswith(("http.client.HTTPConnection.", "http.client.HTTPSConnection.")):
        return symbol.rsplit(".", 1)[-1] in {"request", "connect", "send"}
    return symbol.startswith("subprocess.") and symbol.rsplit(".", 1)[-1] in {
        "run",
        "Popen",
        "call",
        "check_output",
        "check_call",
        "getoutput",
        "getstatusoutput",
        "wait",
    }


_DOTTED = r"[A-Za-z_]\w*(?:\s*\.\s*[A-Za-z_]\w*)*"
_CALL_RE = re.compile(rf"(?P<symbol>{_DOTTED})\s*\(")
_FROM_IMPORT_RE = re.compile(
    rf"\bfrom\s+(?P<module>{_DOTTED})\s+import\s+(?P<name>[A-Za-z_]\w*)"
)
_IMPORT_RE = re.compile(rf"\bimport\s+(?P<module>{_DOTTED})")


def _normalize_dotted(value: str) -> str:
    return re.sub(r"\s*\.\s*", ".", value.strip())


def _aliases_from_lines(cleaned: dict[int, str]) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for text in cleaned.values():
        from_match = _FROM_IMPORT_RE.search(text)
        if from_match:
            module = _normalize_dotted(from_match.group("module"))
            name = from_match.group("name")
            aliases[name] = f"{module}.{name}"
            continue
        import_match = _IMPORT_RE.search(text)
        if import_match:
            module = _normalize_dotted(import_match.group("module"))
            aliases[module.rsplit(".", 1)[-1]] = module
    return aliases


def _clean_lines(source: str) -> dict[int, str]:
    lines: dict[int, list[str]] = {}
    try:
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        for token in tokens:
            if token.type in _STRING_TOKEN_TYPES:
                # Drop only the literal token; retain other calls on the same
                # physical line so `getattr(obj, "name")` and transport calls
                # cannot hide beside harmless string arguments.
                continue
            if token.type in {tokenize.COMMENT, tokenize.ENCODING}:
                continue
            if token.type in {tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT}:
                continue
            lines.setdefault(token.start[0], []).append(token.string)
    except (IndentationError, tokenize.TokenError):
        return {}
    return {
        line: " ".join(parts)
        for line, parts in lines.items()
        if (parts[0] if parts else "") != "def"
    }


def scan_secondary(root: Path) -> list[dict[str, Any]]:
    """Return lexical transport observations with stable file/line/symbol keys."""
    observations: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root.parent).as_posix()
        cleaned = _clean_lines(path.read_text(encoding="utf-8"))
        aliases = _aliases_from_lines(cleaned)
        for line, text in cleaned.items():
            from_match = _FROM_IMPORT_RE.search(text)
            if from_match:
                module = _normalize_dotted(from_match.group("module"))
                imported = from_match.group("name")
                symbol = f"{module}.{imported}"
                if _secondary_is_import_root(symbol) or _secondary_is_import_root(module):
                    observations.append(
                        {"file": relative, "line": line, "kind": "import", "symbol": symbol}
                    )
            else:
                import_match = _IMPORT_RE.search(text)
                if import_match:
                    module = _normalize_dotted(import_match.group("module"))
                    if _secondary_is_import_root(module):
                        observations.append(
                            {"file": relative, "line": line, "kind": "import", "symbol": module}
                        )
            for match in _CALL_RE.finditer(text):
                source_symbol = _normalize_dotted(match.group("symbol"))
                resolved_symbol = aliases.get(source_symbol, source_symbol)
                kind = ""
                if (
                    source_symbol in _SECONDARY_SAFE_BOUNDARIES
                    or resolved_symbol in _SECONDARY_SAFE_BOUNDARIES
                ):
                    kind = "safe_boundary_call"
                elif _secondary_is_transport_call(resolved_symbol):
                    kind = "call"
                elif source_symbol == "getattr":
                    # The lexical scanner cannot safely infer the subject or
                    # attribute name after token filtering; every getattr is
                    # therefore an unresolved dynamic-resolution observation.
                    kind = "dynamic_resolution"
                elif resolved_symbol in {
                    "importlib.import_module",
                    "importlib.reload",
                    "__import__",
                }:
                    kind = "dynamic_import"
                if kind:
                    observations.append(
                        {"file": relative, "line": line, "kind": kind, "symbol": source_symbol}
                    )
    observations.sort(key=lambda item: (item["file"], item["line"], item["kind"], item["symbol"]))
    return observations


def cross_check_primary(
    primary_records: list[dict[str, Any]],
    root: Path,
) -> list[str]:
    """Return disagreements; never suppress or downgrade a primary finding."""
    secondary = scan_secondary(root)
    primary_keys = {
        (record["file"], int(record["line"]), record["kind"], record["symbol"])
        for record in primary_records
        if record["kind"] in {
            "import",
            "call",
            "safe_boundary_call",
            "dynamic_import",
            "dynamic_resolution",
        }
    }
    secondary_keys = {
        (record["file"], int(record["line"]), record["kind"], record["symbol"])
        for record in secondary
    }
    errors: list[str] = []
    for item in sorted(primary_keys - secondary_keys):
        errors.append(f"secondary scanner missed {item}")
    for item in sorted(secondary_keys - primary_keys):
        errors.append(f"primary scanner missed {item}")
    return errors
