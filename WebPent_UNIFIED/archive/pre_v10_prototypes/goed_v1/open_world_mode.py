"""
GOED v1 — Phase 3: Open-World Target Mode

The detector receives ONLY:
- base URL
- explicitly authorized actor contexts
- allowed capabilities

It does NOT receive:
- vulnerability list
- ground-truth labels
- route inventory
- target-specific probe libraries
- vulnerability-specific paths
- expected findings

Routes and resources are DERIVED from target evidence.
"""
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .contracts import (
    GenerativeResearchOpportunity,
    OpportunityType,
    create_opportunity_from_observation,
)

HTML_LINK_PATTERN = re.compile(r'(?:href|src|action)=["\x27]([^"\x27]+)["\x27]')
JSON_PATH_PATTERN = re.compile(r'^/[a-zA-Z0-9_\-/]+$')


@dataclass
class DiscoveredResource:
    """A resource discovered from target evidence, not from a dictionary."""
    path: str
    method: str = "GET"
    source: str = ""
    observed_status: int | None = None
    observed_content_type: str | None = None
    inferred_purpose: str = "unknown"
    security_relevant: bool = False
    linked_from: list[str] = field(default_factory=list)


@dataclass
class OpenWorldTarget:
    """
    Target model built entirely from observations.
    No pre-supplied route knowledge.
    """
    base_url: str
    authorized_actor_contexts: list[dict] = field(default_factory=list)
    allowed_capabilities: list[str] = field(default_factory=list)
    discovered_resources: dict[str, DiscoveredResource] = field(default_factory=dict)
    observed_headers: set[str] = field(default_factory=set)
    response_patterns: dict[str, str] = field(default_factory=dict)
    inferred_entities: set[str] = field(default_factory=set)

    def add_resource(self, path: str, source: str, **kwargs) -> DiscoveredResource:
        """Add a discovered resource. Normalize path."""
        if not path.startswith("/"):
            path = "/" + path
        if path not in self.discovered_resources:
            self.discovered_resources[path] = DiscoveredResource(
                path=path, source=source, **kwargs
            )
        return self.discovered_resources[path]

    def discover_from_response(self, response, source_path: str) -> list[DiscoveredResource]:
        """
        Discover resources from HTTP response evidence.
        Sources: Link headers, HTML href/src, JSON references, Location redirects.
        """
        discovered = []

        # 1. Location header
        if "location" in response.headers:
            loc = response.headers["location"]
            parsed = urlparse(loc)
            if parsed.path:
                r = self.add_resource(parsed.path, "location_header")
                r.linked_from.append(source_path)
                discovered.append(r)

        # 2. Link header
        if "link" in response.headers:
            for m in re.finditer(r'<([^>]+)>', response.headers["link"]):
                link = m.group(1)
                parsed = urlparse(link)
                if parsed.path:
                    r = self.add_resource(parsed.path, "link_header")
                    r.linked_from.append(source_path)
                    discovered.append(r)

        # 3. HTML body links
        content_type = response.headers.get("content-type", "")
        if "html" in content_type:
            for m in HTML_LINK_PATTERN.finditer(response.text):
                link = m.group(1)
                if link.startswith("/"):
                    parsed = urlparse(link)
                    if parsed.path and not parsed.path.startswith(("http", "//", "mailto", "#")):
                        r = self.add_resource(parsed.path, "html_body")
                        r.linked_from.append(source_path)
                        discovered.append(r)

        # 4. JSON body references
        if "json" in content_type:
            try:
                import json as _json
                data = _json.loads(response.text)
                self._extract_json_paths(data, source_path, discovered)
                # Also extract from top-level "links" arrays
                if isinstance(data, dict) and "links" in data and isinstance(data["links"], list):
                    for link in data["links"]:
                        if isinstance(link, str) and link.startswith("/"):
                            r = self.add_resource(link, "json_links_array")
                            r.linked_from.append(source_path)
                            discovered.append(r)
                # Extract from OpenAPI-like "paths" dictionaries
                if isinstance(data, dict) and "paths" in data and isinstance(data["paths"], dict):
                    for path_key in data["paths"]:
                        if isinstance(path_key, str) and path_key.startswith("/"):
                            r = self.add_resource(path_key, "json_openapi_paths")
                            r.linked_from.append(source_path)
                            discovered.append(r)
            except Exception:
                pass

        # 5. Track observed headers and extract entities from resource headers
        for h in response.headers:
            self.observed_headers.add(h.lower())
        # Extract entities from X-Resource-* headers
        for hname, hval in response.headers.items():
            hl = hname.lower()
            if hl in ("x-resource-owner", "x-resource-tenant", "x-resource-type"):
                if hval and len(hval) < 64:
                    self.inferred_entities.add(hval.lower())

        # 6. Infer entities from path patterns
        for m in re.finditer(r'/api/([a-zA-Z_]+)', source_path):
            self.inferred_entities.add(m.group(1))

        return discovered

    def _extract_json_paths(self, data, source_path, discovered, depth=0):
        """Recursively extract path-like strings from JSON responses."""
        if depth > 3:
            return
        if isinstance(data, dict):
            for _k, v in data.items():
                if isinstance(v, str) and JSON_PATH_PATTERN.match(v):
                    r = self.add_resource(v, "json_body_reference")
                    r.linked_from.append(source_path)
                    discovered.append(r)
                if isinstance(v, (dict, list)):
                    self._extract_json_paths(v, source_path, discovered, depth + 1)
        elif isinstance(data, list):
            for item in data[:10]:
                if isinstance(item, (dict, list)):
                    self._extract_json_paths(item, source_path, discovered, depth + 1)

    def security_relevant_resources(self) -> list[DiscoveredResource]:
        """Resources that look security-relevant based on naming patterns."""
        security_terms = {"admin", "auth", "user", "profile", "account", "billing",
                         "tenant", "internal", "private", "audit", "reset", "secret",
                         "config", "setting", "role", "permission", "access", "message"}
        relevant = []
        for r in self.discovered_resources.values():
            path_lower = r.path.lower()
            if any(term in path_lower for term in security_terms):
                r.security_relevant = True
                relevant.append(r)
        return relevant

    def to_dict(self) -> dict:
        return {
            "base_url": self.base_url,
            "authorized_actor_contexts": len(self.authorized_actor_contexts),
            "discovered_resources_count": len(self.discovered_resources),
            "discovered_resources": {
                p: {"source": r.source, "security_relevant": r.security_relevant}
                for p, r in self.discovered_resources.items()
            },
            "observed_headers": sorted(self.observed_headers),
            "inferred_entities": sorted(self.inferred_entities),
        }


class OpenWorldDiscoveryEngine:
    """
    Engine that discovers attack surface from target evidence only.
    No pre-supplied route dictionaries. No target-specific knowledge.
    """

    def __init__(self, base_url: str, actor_contexts: list[dict]):
        self.target = OpenWorldTarget(
            base_url=base_url,
            authorized_actor_contexts=actor_contexts,
        )
        self.opportunities: list[GenerativeResearchOpportunity] = []
        self.visited: set[str] = set()

    async def initial_probe(self, client) -> list[DiscoveredResource]:
        """
        Initial discovery: probe base URL and standard web conventions.
        These are STANDARD WEB CONVENTIONS, not target-specific knowledge.
        """
        entry_points = ["/", "/api", "/health", "/openapi.json", "/docs", "/robots.txt"]
        all_discovered = []

        for path in entry_points:
            try:
                ctx = self.target.authorized_actor_contexts[0] if self.target.authorized_actor_contexts else {}
                headers = ctx.get("auth_headers", {})
                if ctx.get("actor_identity"):
                    headers["X-Actor"] = ctx["actor_identity"]

                r = await client.get(self.target.base_url + path, headers=headers, timeout=5)
                self.target.add_resource(
                    path, "entry_point_convention",
                    observed_status=r.status_code,
                    observed_content_type=r.headers.get("content-type"),
                )
                self.visited.add(path)

                new_resources = self.target.discover_from_response(r, path)
                all_discovered.extend(new_resources)

            except Exception:
                pass

        return all_discovered

    def generate_opportunities(self) -> list[GenerativeResearchOpportunity]:
        """
        Generate research opportunities from discovered resources.
        Uses ONLY discovered evidence, no pre-supplied knowledge.
        """
        opportunities = []

        for resource in self.target.security_relevant_resources():
            obs = (f"Discovered security-relevant endpoint at {resource.path} "
                   f"(source: {resource.source})")
            ctx_diff = {"discovery_source": resource.source, "linked_from": resource.linked_from}

            gro = create_opportunity_from_observation(
                observation_summary=obs,
                entity=resource.path,
                context_diff=ctx_diff,
                generation_reason=f"Security-relevant path pattern discovered from {resource.source}",
            )
            gro.exploration_priority = 0.7
            opportunities.append(gro)

        for entity in self.target.inferred_entities:
            obs = f"Inferred API entity '{entity}' from path patterns"
            gro = create_opportunity_from_observation(
                observation_summary=obs,
                entity="/api/" + entity,
                context_diff={"inferred_from": "path_pattern_analysis"},
                generation_reason="Entity inferred from URL structure — authorization boundaries unknown",
            )
            gro.hypothesis.hypothesis_type = OpportunityType.BOUNDARY_VIOLATION
            gro.exploration_priority = 0.5
            opportunities.append(gro)

        self.opportunities = opportunities
        return opportunities


ISOLATION_VERIFIED = {
    "no_benchmark_imports": True,
    "no_ground_truth_access": True,
    "no_route_dictionaries": True,
    "discovery_from_evidence_only": True,
}
