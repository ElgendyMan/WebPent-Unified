"""Pure contracts for distributed storage readiness.

The module describes configuration and verification state only.  It never opens
network connections, migrates schemas, or treats configured services as
production-qualified.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlparse


class EvidenceObjectStore(Protocol):
    """Minimal interface for an implementation that stores sealed evidence."""

    def put(self, key: str, payload: bytes, *, content_type: str) -> str:
        ...

    def get(self, key: str) -> bytes | None:
        ...


class VectorStore(Protocol):
    """Minimal interface for scope-isolated vector retrieval."""

    def upsert(self, records: Sequence[Mapping[str, Any]]) -> None:
        ...

    def search(self, query: str, *, limit: int = 10) -> Sequence[Mapping[str, Any]]:
        ...


@dataclass(frozen=True)
class StorageReadiness:
    """Non-invasive readiness result for one named storage component."""

    component: str
    configured: bool
    protocol: str
    explicitly_verified: bool
    ready: bool
    production_qualified: bool
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "configured": self.configured,
            "protocol": self.protocol,
            "explicitly_verified": self.explicitly_verified,
            "ready": self.ready,
            "production_qualified": self.production_qualified,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class DistributedStorageContract:
    """Configuration contract for the optional distributed runtime seams."""

    database_url: str = ""
    redis_url: str = ""
    object_store_url: str = ""
    vector_store_url: str = ""
    verified_components: tuple[str, ...] = ()

    def _verified(self, component: str) -> bool:
        return component in set(self.verified_components)

    @staticmethod
    def _protocol(value: str) -> str:
        parsed = urlparse(str(value or ""))
        return parsed.scheme.lower()

    def readiness(self) -> tuple[StorageReadiness, ...]:
        specs = (
            ("database", self.database_url, {"sqlite", "postgres", "postgresql"}),
            ("redis", self.redis_url, {"redis", "rediss"}),
            ("evidence_object_store", self.object_store_url, {"file", "s3", "minio"}),
            ("vector_store", self.vector_store_url, {"chroma", "pgvector", "weaviate"}),
        )
        results: list[StorageReadiness] = []
        for component, value, supported_protocols in specs:
            protocol = self._protocol(value)
            configured = bool(protocol)
            explicitly_verified = self._verified(component)
            if not configured:
                results.append(
                    StorageReadiness(
                        component,
                        False,
                        "",
                        explicitly_verified,
                        False,
                        False,
                        "not_configured",
                    )
                )
                continue
            if protocol not in supported_protocols:
                reason = "unsupported_protocol"
            elif not explicitly_verified:
                reason = "requires_explicit_readiness_verification"
            else:
                reason = "readiness_explicitly_verified"
            results.append(
                StorageReadiness(
                    component,
                    True,
                    protocol,
                    explicitly_verified,
                    protocol in supported_protocols and explicitly_verified,
                    False,
                    reason,
                )
            )
        return tuple(results)

    def as_dict(self) -> dict[str, Any]:
        readiness = self.readiness()
        return {
            "components": [item.as_dict() for item in readiness],
            "all_ready": bool(readiness) and all(item.ready for item in readiness),
            "production_qualified": False,
            "live_qualification_proven": False,
            "network_probe_performed": False,
            "migration_performed": False,
        }


__all__ = [
    "DistributedStorageContract",
    "EvidenceObjectStore",
    "StorageReadiness",
    "VectorStore",
]
