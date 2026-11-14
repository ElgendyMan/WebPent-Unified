"""appsuite: generation-2 applications for L8 §2.

This package is a SECOND generation of independently implemented
loopback applications, distinct from both the L6 fixture target and
the L7 labsuite deployments: every app here is its own module with its
own request handler, state model, vocabulary generator and defect
embedding. No app imports labsuite or egaie, and the apps share no
handler or state code with each other. What the apps share is only
the engine's documented observation protocol (an index document at
/, query-string parameters, JSON bodies, the probe-credential
literals actor-a/actor-b/actor-admin and their actor-param role), the
same way any real client would share a wire protocol.

L8 blocks:

- DEV (tuning-permitted): docvault (object-level ownership),
  market (server-authoritative pricing), requisitions (L9 §4
  development case: pool-level workflow identity over an enforced
  transition machine).
- HELD-OUT (never touched during tuning): ticketflow (workflow
  state-transition), slots (idempotent mutation: duplicate submission
  must not double-apply — an invariant family NO engine generator was
  tuned on, unlike L7's grant-replay which entered the engine through
  the L7 DEV failure analysis).

Case types per block: defective, secured lookalike, ambiguous (a
documented behavior that mimics a violation; ground truth CLEAN, so a
confirmation there is a false positive), and multi-observation (a
defect whose evidence requires correlating several observations). The
L10 generation-3 apps (consign, permit) carry a four-variant rotation
instead: defective, secured, transition_no_vuln (a documented open
transition implying nothing about authorization) and
unavailable_prereq (a defect whose prerequisite is unreachable in
scope).

Ground truth lives only in appsuite.groundtruth and is applied after
investigation, never published on the wire.
"""

from webpent.appsuite.consign import ConsignApp, ConsignSpec
from webpent.appsuite.docvault import DocVaultApp, DocVaultSpec
from webpent.appsuite.market import MarketApp, MarketSpec
from webpent.appsuite.permit import PermitApp, PermitSpec
from webpent.appsuite.requisitions import (
    RequisitionsApp,
    RequisitionsSpec,
)
from webpent.appsuite.slots import SlotDeskApp, SlotDeskSpec
from webpent.appsuite.ticketflow import TicketFlowApp, TicketFlowSpec

__all__ = [
    "ConsignApp",
    "ConsignSpec",
    "DocVaultApp",
    "DocVaultSpec",
    "MarketApp",
    "MarketSpec",
    "PermitApp",
    "PermitSpec",
    "RequisitionsApp",
    "RequisitionsSpec",
    "SlotDeskApp",
    "SlotDeskSpec",
    "TicketFlowApp",
    "TicketFlowSpec",
]
