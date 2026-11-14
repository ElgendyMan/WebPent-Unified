"""Self-hosted OAST collector (PROPOSALS_ULTIMATE_V2 §1, 2026-10-29).

The correlation ENGINE already lives in ``webpent.shared.oob``
(OOBCollaborator, per-probe token minting, fail-closed identity,
deterministic evidence windows) — this package ships the piece that was
explicitly left to the operator: the NETWORK listener that receives the
callbacks and the glue that feeds them back into the collaborator.

Components:

  * :mod:`webpent.oast.server`   — the collector itself: an HTTP listener
    that records callbacks keyed by probe token and serves them on
    ``GET /poll?token=...`` in exactly the record shape
    :func:`webpent.shared.oob.poll_remote_collector` already consumes,
    plus an optional minimal DNS A-responder so DNS-based OOB
    (blind XXE, blind SQLi exfil, targetless SSRF) works even when the
    target can never make an HTTP call back out.
  * :mod:`webpent.oast.correlate` — the poll/record bridge and a bounded
    ``wait_for_callback`` loop that connects a live collaborator binding
    to a collector URL.

Design rules (same campaign discipline as shared/oob):

  * FLAG-GATED — every consumer checks ``enable_oast`` (default False)
    before touching this package; with the flag off it is inert library
    code and nothing binds a socket.
  * FAIL-CLOSED ON IDENTITY — a callback without a recognisable probe
    token is dropped by the collector and re-checked by the
    collaborator's own registered-token gate on ingestion; a sprayed
    guess can never become evidence.
  * NO THIRD PARTY — no interactsh.fun, no external DNS service. The
    zone is the operator's own; ``docs/oast-deployment.md`` documents
    the wildcard setup and warns never to point it at campaign targets.
  * BOUNDED — per-token callback ring (default 64), 4 KiB body cap,
    bounded detail strings, every socket read/write bounded.
  * STDLIB ONLY — ``http.server`` + one UDP socket; no new dependencies.
"""

from webpent.oast.correlate import sync_remote_callbacks, wait_for_callback
from webpent.oast.server import OastCollectorServer, OastDnsResponder

__all__ = [
    "OastCollectorServer",
    "OastDnsResponder",
    "sync_remote_callbacks",
    "wait_for_callback",
]
