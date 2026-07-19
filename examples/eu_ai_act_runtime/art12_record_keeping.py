"""EU AI Act Article 12 — automatic record-keeping with signed attestation receipts.

This example wraps a simulated high-risk agent action in an ``Article12Logger``
record chain, then issues a signed ``AttestationRegistry`` receipt for the
same decision. It shows both integrity mechanisms working together, then
tampers with the attestation to demonstrate that verification fails closed.

Run:
    python examples/eu_ai_act_runtime/art12_record_keeping.py

No external services required — all record-keeping runs in-process.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

from acgs_lite.constitution.attestation import AttestationRegistry
from acgs_lite.eu_ai_act import Article12Logger

CONSTITUTIONAL_HASH = "608508a9bd224290"

SYSTEM_ID = "credit-risk-scorer-v1"


def _simulate_agent_action(prompt: str) -> str:
    """Stand-in for a real LLM/agent call — deterministic for the demo."""
    return f"decision for: {prompt}"


def run_demo() -> dict[str, object]:
    logger = Article12Logger(system_id=SYSTEM_ID, risk_level="high_risk")

    actions = [
        "score applicant 001",
        "score applicant 002",
        "score applicant 003",
    ]
    for action in actions:
        logger.log_call(
            operation="credit_score",
            call=lambda action=action: _simulate_agent_action(action),
            input_text=action,
            human_oversight_applied=False,
        )

    chain_valid_before = logger.verify_chain()

    # demo key — production keys come from a KMS/secret manager
    registry = AttestationRegistry(signing_key="demo-attestation-key")
    receipt = registry.attest(
        action=actions[-1],
        decision="allow",
        constitution_hash=CONSTITUTIONAL_HASH,
        rule_ids_evaluated=["credit-risk-policy"],
        violations_found=[],
        metadata={"system_id": SYSTEM_ID},
    )
    receipt_verified_before = registry.verify(receipt)

    # Tamper with the receipt after issuance — e.g. an attacker or a corrupted store.
    receipt.decision = "deny"
    receipt_verified_after_tamper = registry.verify(receipt)

    return {
        "records_logged": logger.record_count,
        "chain_valid_before": chain_valid_before,
        "receipt_id": receipt.attestation_id,
        "receipt_verified_before": receipt_verified_before,
        "receipt_verified_after_tamper": receipt_verified_after_tamper,
        "tamper_detected": receipt_verified_before and not receipt_verified_after_tamper,
        "constitutional_hash": CONSTITUTIONAL_HASH,
    }


def main() -> int:
    result = run_demo()
    print("EU AI Act Article 12 — record-keeping + signed attestation")
    print(f"Records logged: {result['records_logged']}")
    print(f"Chain valid before tamper: {result['chain_valid_before']}")
    print(
        f"Receipt {result['receipt_id']} verified before tamper: "
        f"{result['receipt_verified_before']}"
    )
    print(f"Receipt verified after tamper: {result['receipt_verified_after_tamper']}")
    print(f"Tamper detected: {result['tamper_detected']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
