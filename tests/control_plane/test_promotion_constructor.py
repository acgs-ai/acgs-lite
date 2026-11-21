"""PromotionGate constructor refusals: a misconfigured gate is never built."""

from __future__ import annotations

from typing import Any

import pytest

from acgs_lite.control_plane import (
    InMemoryReceiptStore,
    PolicyDecisionPoint,
    Principal,
    PrincipalKind,
    PromotionGate,
    ReceiptLedger,
    TrustedRunRegistry,
)
from acgs_lite.control_plane.roles import RoleAssignments

pytest.importorskip("cryptography")
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("make_kwargs", "exc_type", "message"),
    [
        (lambda: {"roles": object()}, TypeError, "roles must be a RoleAssignments"),
        (
            lambda: {"roles": RoleAssignments(Principal("root-admin", PrincipalKind.HUMAN))},
            ValueError,
            "role-checked promotion needs a PDP with an ApprovalGate",
        ),
        (
            lambda: {"incident_lock": object()},
            TypeError,
            "incident_lock must be an IncidentMutationLock",
        ),
    ],
)
def test_constructor_refuses_misconfiguration(
    pdp: PolicyDecisionPoint,
    make_kwargs: Any,
    exc_type: type[Exception],
    message: str,
) -> None:
    ledger = ReceiptLedger(
        Ed25519ReceiptSigner.from_seed(b"ledger".ljust(32, b"0"), key_id="l"),
        store=InMemoryReceiptStore(),
    )

    with pytest.raises(exc_type, match=message):
        PromotionGate(ledger, TrustedRunRegistry(), pdp=pdp, **make_kwargs())

    assert ledger.receipts() == ()
