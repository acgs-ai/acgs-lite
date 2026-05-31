"""Executable red-team cases for governance fail-closed regression evidence."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from acgs_lite.audit import AuditEntry
from acgs_lite.cdp.assembler import assemble_cdp_record
from acgs_lite.governed import GovernedAgent, GovernedCallable
from acgs_lite.legitimacy import DecisionReceipt, ExecutionBoundary
from acgs_lite.maci import MACIRole

EXPECTED_DECISION = "FAIL_CLOSED"
EXPECTED_TRIGGER_CLASSES = frozenset(
    {
        "authorization_failure",
        "constitution_hash_mismatch",
        "stale_policy",
        "receipt_integrity_failure",
        "audit_evidence_unverifiability",
    }
)
CANONICAL_CONSTITUTION_HASH = "608508a9bd224290"


@dataclass(slots=True)
class SideEffectSpy:
    """Minimal side-effect counter used by every adversarial case."""

    count: int = 0

    def execute(self) -> str:
        self.count += 1
        return "side-effect-executed"


@dataclass(frozen=True, slots=True)
class GovernanceBypassCaseResult:
    """Machine-readable outcome for one fail-closed bypass attempt."""

    trigger_class: str
    attack_name: str
    expected_decision: str
    observed_decision: str
    side_effect_count: int
    audit_evidence_ok: bool
    passed: bool
    exception_type: str | None = None
    exception_message: str | None = None
    ood_provenance: str | None = None

    @property
    def bypassed(self) -> bool:
        return self.observed_decision != self.expected_decision or self.side_effect_count != 0

    def to_artifact(self) -> dict[str, Any]:
        return {
            "trigger_class": self.trigger_class,
            "attack_name": self.attack_name,
            "expected_decision": self.expected_decision,
            "observed_decision": self.observed_decision,
            "side_effect_count": self.side_effect_count,
            "audit_evidence_ok": self.audit_evidence_ok,
            "pass": self.passed,
            "bypass": self.bypassed,
            "exception_type": self.exception_type,
            "exception_message": self.exception_message,
            "ood_provenance": self.ood_provenance,
        }


class _SpyAgent:
    def __init__(self, spy: SideEffectSpy) -> None:
        self._spy = spy

    def run(self, _input: str, **_kwargs: Any) -> str:
        return self._spy.execute()


def _boundary(
    *,
    method: str = "execute_transfer",
    scope: str = "tenant-a",
    subjects: tuple[str, ...] = ("account-123",),
    expires_at: str | None = None,
) -> ExecutionBoundary:
    return ExecutionBoundary(
        allowed_method=method,
        allowed_scope=scope,
        allowed_subjects=subjects,
        expires_at=expires_at,
        single_use=True,
    )


def _receipt(
    *,
    request_id: str = "req-red-team",
    method: str = "execute_transfer",
    subjects: tuple[str, ...] = ("account-123",),
    expires_at: str | None = None,
) -> DecisionReceipt:
    return DecisionReceipt.create(
        request_id=request_id,
        goal="Execute an approved side-effectful governance action",
        proposed_method=method,
        decision_type="ALLOW",
        authority_basis="role:executor",
        matched_constraints=("governance-regression-policy",),
        policy_version=f"constitution:{CANONICAL_CONSTITUTION_HASH}",
        execution_boundary=_boundary(method=method, subjects=subjects, expires_at=expires_at),
    )


def _observe_fail_closed_case(
    *,
    trigger_class: str,
    attack_name: str,
    spy: SideEffectSpy,
    attack: Callable[[], None],
    audit_evidence_ok: Callable[[], bool] | bool = True,
    ood_provenance: str | None = None,
) -> GovernanceBypassCaseResult:
    observed_decision = "ALLOW"
    exception_type: str | None = None
    exception_message: str | None = None

    try:
        attack()
    except Exception as exc:  # noqa: BLE001 - red-team harness records any fail-closed guard.
        observed_decision = EXPECTED_DECISION
        exception_type = type(exc).__name__
        exception_message = str(exc)

    evidence_ok = audit_evidence_ok() if callable(audit_evidence_ok) else audit_evidence_ok
    passed = observed_decision == EXPECTED_DECISION and spy.count == 0
    return GovernanceBypassCaseResult(
        trigger_class=trigger_class,
        attack_name=attack_name,
        expected_decision=EXPECTED_DECISION,
        observed_decision=observed_decision,
        side_effect_count=spy.count,
        audit_evidence_ok=evidence_ok,
        passed=passed,
        exception_type=exception_type,
        exception_message=exception_message,
        ood_provenance=ood_provenance,
    )


def authorization_failure_case() -> GovernanceBypassCaseResult:
    """A proposer attempts to execute through GovernedAgent MACI enforcement."""
    spy = SideEffectSpy()
    governed = GovernedAgent(
        _SpyAgent(spy),
        agent_id="red-team-proposer",
        maci_role=MACIRole.PROPOSER,
        validate_output=False,
    )

    def attack() -> None:
        governed.run("attempt side effect with proposer role", governance_action="execute")

    return _observe_fail_closed_case(
        trigger_class="authorization_failure",
        attack_name="proposer_role_execute_action",
        spy=spy,
        attack=attack,
        audit_evidence_ok=governed.audit_log.verify_chain,
    )


def constitution_hash_mismatch_case() -> GovernanceBypassCaseResult:
    """A provenance record with the wrong constitution hash cannot unlock execution."""
    spy = SideEffectSpy()
    guard = GovernedCallable()

    @guard
    def execute_transfer(input: str, *, scope: str, subjects: tuple[str, ...]) -> str:
        return spy.execute()

    receipt = _receipt()

    def attack() -> None:
        assemble_cdp_record(
            raw_input="approved transfer request",
            agent_id="red-team-executor",
            constitutional_hash="attacker-supplied-constitution",
            verdict="allow",
            action="execute_transfer",
        )
        execute_transfer(
            "approved transfer request",
            scope="tenant-a",
            subjects=("account-123",),
            decision_receipt=receipt,
        )

    return _observe_fail_closed_case(
        trigger_class="constitution_hash_mismatch",
        attack_name="wrong_constitution_hash_provenance",
        spy=spy,
        attack=attack,
        audit_evidence_ok=guard.audit_log.verify_chain,
    )


def stale_policy_expired_receipt_case() -> GovernanceBypassCaseResult:
    """An expired execution boundary must not authorize a side effect."""
    spy = SideEffectSpy()
    guard = GovernedCallable()
    expired_at = (datetime.now(timezone.utc) - timedelta(seconds=5)).isoformat()
    receipt = _receipt(expires_at=expired_at)

    @guard
    def execute_transfer(input: str, *, scope: str, subjects: tuple[str, ...]) -> str:
        return spy.execute()

    def attack() -> None:
        execute_transfer(
            "approved transfer request",
            scope="tenant-a",
            subjects=("account-123",),
            decision_receipt=receipt,
        )

    return _observe_fail_closed_case(
        trigger_class="stale_policy",
        attack_name="expired_receipt_replay",
        spy=spy,
        attack=attack,
        audit_evidence_ok=guard.audit_log.verify_chain,
    )


def receipt_integrity_tampered_hash_case() -> GovernanceBypassCaseResult:
    """A forged receipt hash must fail before the wrapped callable runs."""
    spy = SideEffectSpy()
    guard = GovernedCallable()
    receipt = _receipt()
    object.__setattr__(receipt, "receipt_hash", "0" * 64)

    @guard
    def execute_transfer(input: str, *, scope: str, subjects: tuple[str, ...]) -> str:
        return spy.execute()

    def attack() -> None:
        execute_transfer(
            "approved transfer request",
            scope="tenant-a",
            subjects=("account-123",),
            decision_receipt=receipt,
        )

    return _observe_fail_closed_case(
        trigger_class="receipt_integrity_failure",
        attack_name="tampered_receipt_hash",
        spy=spy,
        attack=attack,
        audit_evidence_ok=guard.audit_log.verify_chain,
    )


def audit_evidence_unverifiable_case() -> GovernanceBypassCaseResult:
    """A broken audit chain blocks otherwise well-formed receipt execution."""
    spy = SideEffectSpy()
    guard = GovernedCallable()

    @guard
    def execute_transfer(input: str, *, scope: str, subjects: tuple[str, ...]) -> str:
        return spy.execute()

    guard.audit_log.record(
        AuditEntry(id="audit-1", type="validation", action="approved", valid=True)
    )
    guard.audit_log.record(
        AuditEntry(id="audit-2", type="validation", action="approved", valid=True)
    )
    guard.audit_log._entries[0].action = "tampered-after-the-fact"

    def attack() -> None:
        execute_transfer(
            "approved transfer request",
            scope="tenant-a",
            subjects=("account-123",),
            decision_receipt=_receipt(),
        )

    return _observe_fail_closed_case(
        trigger_class="audit_evidence_unverifiability",
        attack_name="tampered_audit_chain_replay",
        spy=spy,
        attack=attack,
        audit_evidence_ok=guard.audit_log.verify_chain,
    )


def ood_confused_deputy_boundary_substitution_case() -> GovernanceBypassCaseResult:
    """An allowed receipt for one subject cannot be replayed for another subject."""
    spy = SideEffectSpy()
    guard = GovernedCallable()
    receipt = _receipt(
        request_id="req-confused-deputy",
        method="send_customer_email",
        subjects=("customer-123",),
    )

    @guard
    def send_customer_email(customer_id: str, *, scope: str) -> str:
        return spy.execute()

    def attack() -> None:
        send_customer_email(
            "customer-999",
            scope="tenant-a",
            decision_receipt=receipt,
        )

    # OOD provenance: this is an original, license-safe implementation of the
    # confused-deputy / argument-substitution attack class described broadly in
    # capability-security literature; no proprietary attack text was copied.
    provenance = (
        "Externally inspired by the confused-deputy / argument-substitution "
        "attack class from capability-security literature; original scenario."
    )
    return _observe_fail_closed_case(
        trigger_class="receipt_integrity_failure",
        attack_name="ood_confused_deputy_subject_substitution",
        spy=spy,
        attack=attack,
        audit_evidence_ok=guard.audit_log.verify_chain,
        ood_provenance=provenance,
    )


CASE_RUNNERS: tuple[Callable[[], GovernanceBypassCaseResult], ...] = (
    authorization_failure_case,
    constitution_hash_mismatch_case,
    stale_policy_expired_receipt_case,
    receipt_integrity_tampered_hash_case,
    audit_evidence_unverifiable_case,
    ood_confused_deputy_boundary_substitution_case,
)


def run_governance_fail_closed_cases() -> list[GovernanceBypassCaseResult]:
    """Run every adversarial bypass case and return machine-readable outcomes."""
    return [case_runner() for case_runner in CASE_RUNNERS]
