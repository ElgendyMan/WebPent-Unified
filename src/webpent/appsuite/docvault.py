"""DocVault: an independently implemented document-vault application.

DEV-block app for L8 §2 (object-level authorization / ownership).
Implementation notes that establish independence from the L6 fixture
target and the L7 labsuite deployments:

- authorization is a per-document GRANT MATRIX (principal -> doc ->
  read/write bits), not an owner-field comparison and not the labsuite
  ACL list;
- documents live in collections; the defective variant skips the
  write-bit check, the multi-observation variant skips it in ONE
  collection only, so evidence requires comparing across resources;
- vocabulary, route shape, header names and id formats are generated
  from this module's own wordlist and per-instance seed;
- the ambiguous variant is DOCUMENTED guest access to a lobby notice:
  ground truth clean, so a confirmation there is a false positive;
- state is a plain dict mutated in place; there is no history chain,
  no session ledger and no workflow machinery anywhere in this module.
"""
from __future__ import annotations

import json
import random
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

# This module's own vocabulary. The isolation tests assert it is
# disjoint from the L6 fixture wordlist and the L7 labsuite wordlist.
WORDS = (
    "basalt", "alcove", "cactus", "bracken", "coppice", "prism",
    "delta", "dune", "estuary", "fen", "gulf", "grove", "orbit",
    "heath", "inlet", "knoll", "marsh", "fjord", "cascade",
    "nook", "osier", "meadow", "sumac", "polder",
)

VARIANTS = ("defective", "secured", "ambiguous", "multi_observation")


@dataclass(frozen=True)
class DocVaultSpec:
    seed: int
    variant: str = "defective"

    def __post_init__(self) -> None:
        if self.variant not in VARIANTS:
            raise ValueError(self.variant)

    @property
    def instance_id(self) -> str:
        return f"dv-{100 + self.seed % 100}"


@dataclass
class _Doc:
    doc_id: str
    title: str
    owner: str
    collection: str
    notes: list[str] = field(default_factory=list)
    revision: int = 1


class DocVaultApp:
    """The application. Each instance is its own deployment."""

    def __init__(self, spec: DocVaultSpec) -> None:
        if spec.variant not in VARIANTS:
            raise ValueError(spec.variant)
        self.spec = spec
        self.requests = 0
        rnd = random.Random(f"docvault/{spec.seed}/{spec.variant}")
        self._lock = threading.Lock()
        pick = rnd.sample(WORDS, 17)

        self.route = pick[0]                      # vault route segment
        self.annotate_seg = pick[1]               # mutate sub-segment
        self.actor_param = pick[2][:4]            # credential param
        self.note_param = pick[3][:4]             # note payload param
        self.resource_param = pick[12][:4]        # document selector
        self.owner_header = f"X-{pick[4].capitalize()}-Holder"
        self.outcome_header = f"X-{pick[5].capitalize()}-Result"
        self.collections = (pick[6], pick[7])
        self.guest_seg = pick[8]                  # lobby route segment
        self.owner_field = pick[14][:6]           # body owner role
        self.kind_field = pick[15][:6]            # body kind role
        self.applied_by_field = pick[16][:6]      # applied-by role

        # principals: the app's own identity representation, one per
        # probe credential (the credential literals are the wire
        # protocol; the principal strings are this app's own).
        self._keys: dict[str, str] = {}
        self._matrix: dict[str, dict[str, dict[str, bool]]] = {}
        self._docs: dict[str, _Doc] = {}

        for idx, cred in enumerate(("actor-a", "actor-b", "actor-admin")):
            principal = f"member:{pick[9 + idx]}"
            self._keys[cred] = principal

        for c_idx, coll in enumerate(self.collections):
            for d_idx in range(3):
                owner = (
                    f"member:{pick[9 + (c_idx + d_idx) % 3]}")
                doc_id = f"{pick[12]}-{coll[:3]}{d_idx + 1}"
                self._docs[doc_id] = _Doc(
                    doc_id=doc_id, title=f"{coll.title()} {d_idx + 1}",
                    owner=owner, collection=coll)
                # owner holds both bits on the doc; the other two
                # members hold none (the matrix is the only source).
                self._matrix.setdefault(owner, {})[doc_id] = {
                    "read": True, "write": True}
        self._lobby_id = f"{pick[13]}-notice"
        self._docs[self._lobby_id] = _Doc(
            doc_id=self._lobby_id, title="Lobby notice",
            owner=f"member:{pick[9]}", collection=self.guest_seg,
            notes=["welcome"])
        self._known_principals = frozenset(self._keys.values())

    # -- identity resolution (probe-credential protocol) -----------

    def _principal_of(self, value: str) -> str | None:
        """Map a wire credential onto this app's identity space.

        The literal probe credentials map to their principals; a
        value that already IS a principal passes through unchanged;
        anything else is unknown (denied on every gated route).
        """
        principal = self._keys.get(value)
        if principal is not None:
            return principal
        return value if value in self._known_principals else None

    # -- authorization decisions ----------------------------------

    def _read_allowed(self, principal: str, doc: _Doc) -> bool:
        if spec_allows_guest(self.spec) and doc.collection == (
                self.guest_seg):
            return True
        bits = self._matrix.get(principal, {}).get(doc.doc_id)
        return bool(bits and bits["read"])

    def _write_allowed(self, principal: str, doc: _Doc) -> bool:
        # THE defect surface. defective: the write bit is trusted to
        # the caller's session everywhere (never checked).
        if self.spec.variant in ("defective",):
            return True
        if self.spec.variant == "multi_observation" and (
                doc.collection == self.collections[1]):
            return True
        bits = self._matrix.get(principal, {}).get(doc.doc_id)
        return bool(bits and bits["write"])

    # -- wire ------------------------------------------------------

    def _index(self) -> dict[str, Any]:
        read_paths = {
            f"/{self.route}/{d.doc_id}": "read" for d in
            self._docs.values()}
        # The annotate operation binds its document by parameter (the
        # operation's own selector), not by path position: one
        # operation, many documents.
        mutate_path = f"/{self.route}/{self.annotate_seg}"
        schema = {
            "params": {"actor": self.actor_param,
                       "resource": self.resource_param,
                       "payload": {self.note_param: "string"}},
            "fields": {"owner": self.owner_field,
                       "kind": self.kind_field,
                       "discount_applied_by": (
                           self.applied_by_field)},
            "owner_header": self.owner_header,
            "outcome_header": self.outcome_header,
            "outcome_denied": "refused",
            "granting": (
                "documents are shared per grant; a holder sees only "
                "granted documents"),
        }
        if self.spec.variant == "ambiguous":
            schema["guest_access"] = (
                f"{self.guest_seg} notices are readable by any guest "
                "key without a grant; this is documented behavior")
        return {
            "api": {
                "shelves": [
                    {"path": path, "role": "read",
                     self.actor_param: "member"}
                    for path in sorted(read_paths)],
                "annotations": [
                    # role "pay" is the wire contract's semantic tag
                    # for a bare resource-bound mutation (apply an
                    # annotation to a document); renaming it would be
                    # a protocol mismatch, not independence.
                    {"path": mutate_path, "role": "pay",
                     self.actor_param: "member",
                     self.resource_param: "doc-id",
                     self.note_param: "note"}],
            },
            "kinds": {**read_paths, mutate_path: "mutate"},
            "schema": schema,
        }

    def _denied(self, code: int) -> tuple[int, dict[str, str], Any]:
        return code, {self.outcome_header: "refused"}, {
            "error": "refused"}

    def handle_get(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        key = params.get(self.actor_param, "")
        principal = self._principal_of(key)
        if key and principal is None:
            return self._denied(401)
        for doc in self._docs.values():
            if path == f"/{self.route}/{doc.doc_id}":
                if principal is None:
                    return self._denied(401)
                if not self._read_allowed(principal, doc):
                    return self._denied(403)
                headers = {
                    self.owner_header: doc.owner,
                    self.outcome_header: "processed"}
                return 200, headers, {
                    "document": doc.doc_id, "title": doc.title,
                    self.owner_field: doc.owner,
                    self.kind_field: doc.collection,
                    "revision": doc.revision,
                    "notes": list(doc.notes)}
        if path == f"/{self.route}/{self.guest_seg}" and (
                self.spec.variant == "ambiguous"):
            return 200, {}, {"lobby": self._lobby_id}
        return 404, {}, {"error": "no-such-document"}

    def handle_post(self, path: str, params: dict[str, str]) -> (
            tuple[int, dict[str, str], Any]):
        with self._lock:
            self.requests += 1
        key = params.get(self.actor_param, "")
        principal = self._principal_of(key)
        note = params.get(self.note_param, "")
        if path == f"/{self.route}/{self.annotate_seg}":
            doc = self._docs.get(
                params.get(self.resource_param, ""))
            if doc is None:
                return 404, {}, {"error": "no-such-document"}
            if principal is None:
                return self._denied(401)
            if not self._write_allowed(principal, doc):
                return self._denied(403)
            with self._lock:
                doc.notes.append(note)
                doc.revision += 1
            return 200, {self.outcome_header: "processed"}, {
                "document": doc.doc_id, "revision": doc.revision,
                self.owner_field: doc.owner,
                self.applied_by_field: principal,
                "annotated": True}
        return 404, {}, {"error": "no-such-document"}


def spec_allows_guest(spec: DocVaultSpec) -> bool:
    return spec.variant == "ambiguous"


class _Handler(BaseHTTPRequestHandler):
    app: DocVaultApp

    def _dispatch(self, post: bool) -> None:
        parsed = urlparse(self.path)
        params = {k: v[-1] for k, v in
                  parse_qs(parsed.query).items()}
        try:
            if parsed.path in ("", "/") and not post:
                status, headers, body = 200, {}, self.app._index()
            elif post:
                status, headers, body = self.app.handle_post(
                    parsed.path, params)
            else:
                status, headers, body = self.app.handle_get(
                    parsed.path, params)
        except Exception:                              # noqa: BLE001
            status, headers, body = 500, {}, {"error": "internal"}
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:                          # noqa: N802
        self._dispatch(False)

    def do_POST(self) -> None:                         # noqa: N802
        self._dispatch(True)

    def log_message(self, fmt: str, *args: Any) -> None:
        pass


class DocVaultServer:
    """Own serving loop (duplicated per app by design, not shared)."""

    def __init__(self, spec: DocVaultSpec) -> None:
        self.app = DocVaultApp(spec)
        self.requests = 0
        self._http = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._http.daemon_threads = True
        handler = type("_Bound", (_Handler,), {"app": self.app})
        self._http.RequestHandlerClass = handler
        self.origin = f"http://127.0.0.1:{self._http.server_port}"

    def __enter__(self) -> "DocVaultServer":
        self._thread = threading.Thread(
            target=self._http.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._http.shutdown()
        self._http.server_close()

    def request_count(self) -> int:
        return self.requests
