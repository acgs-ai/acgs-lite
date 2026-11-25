"""HTTP transport for basic federation discovery and audit exchange.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import os
from typing import Annotated

from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel

from acgs_lite._compat import constant_time_compare
from acgs_lite._meta import CONSTITUTIONAL_HASH

_SUPPORTED_RULES = ["ACGS-001", "ACGS-002", "ACGS-003"]

federation_router = APIRouter(tags=["federation"])


class AuditPushRequest(BaseModel):
    entry_id: str
    agent_id: str
    action: str
    valid: bool
    constitutional_hash: str
    timestamp: str


class PolicyProposalRequest(BaseModel):
    policy_id: str
    rule_text: str
    submitter: str


def _require_federation_auth(
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> None:
    expected_token = os.getenv("ACGS_FEDERATION_TOKEN")
    if not expected_token:
        return

    expected_value = f"Bearer {expected_token}"
    if authorization is None or not constant_time_compare(authorization, expected_value):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized federation request",
        )


@federation_router.post("/audit/push")
def push_audit_entry(
    payload: AuditPushRequest,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> dict[str, str]:
    _require_federation_auth(authorization)
    if payload.constitutional_hash != CONSTITUTIONAL_HASH:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="constitutional_hash mismatch",
        )
    return {"status": "accepted"}


@federation_router.get("/capabilities")
def get_capabilities(
    _authorized: Annotated[str | None, Header(alias="Authorization")] = None,
) -> dict[str, str | list[str]]:
    _require_federation_auth(_authorized)
    return {
        "version": "1.0",
        "supported_rules": _SUPPORTED_RULES,
        "constitutional_hash": CONSTITUTIONAL_HASH,
    }


@federation_router.post("/policy/propose")
def propose_policy(
    payload: PolicyProposalRequest,
    _authorized: Annotated[str | None, Header(alias="Authorization")] = None,
) -> dict[str, str]:
    _require_federation_auth(_authorized)
    return {"status": "queued", "policy_id": payload.policy_id}
