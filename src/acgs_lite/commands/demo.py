# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""acgs demo — zero-config interactive tour of Receipted Effects and MACI."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.engine.core import GovernanceEngine
from acgs_lite.errors import MACIViolationError
from acgs_lite.legitimacy import (
    ActualCall,
    ContractedEffectStore,
    DecisionReceipt,
    Ed25519ReceiptSigner,
    EffectOutcome,
    EffectRequest,
    EffectState,
    EffectStore,
    ExecutionAuthority,
    ExecutionGrant,
    LegitimacyInvariantError,
    ProviderContract,
    ProviderContractClass,
    ProviderContractRegistry,
    ProviderResult,
    ReceiptSigningUnavailable,
    SignedOutcomeReceipt,
    SignedReceipt,
    bind_invocation,
    bind_policy,
    local_grant_identity,
    outcome_from_record,
    receipt_identity,
    sign_execution_authorization,
    sign_outcome,
    validate_receipt_for_execution,
)
from acgs_lite.legitimacy.authorization import (
    authorization_envelope_json,
    build_issue_receipt,
    engine_decision_from_results,
)
from acgs_lite.maci import MACIEnforcer, MACIRole

_DEMO_SIGNING_SEED = b"acgs-demo-ed25519-seed-2026-11-!"[:32]
assert len(_DEMO_SIGNING_SEED) == 32


@dataclass
class _DemoProvider:
    """In-memory FENCEABLE provider supporting dedup and atomic query-and-fence."""

    provider_id: str = "demo-payments"
    sends: list[EffectRequest] = field(default_factory=list)
    queries: list[EffectRequest] = field(default_factory=list)
    done_keys: set[str] = field(default_factory=set)
    fenced_keys: set[str] = field(default_factory=set)
    timeout_once_keys: set[str] = field(default_factory=set)
    timeout_lands: dict[str, bool] = field(default_factory=dict)

    def send(self, request: EffectRequest) -> ProviderResult:
        if request.key in self.done_keys:
            return ProviderResult(request.key, self.provider_id, EffectOutcome.DONE, fenced=True)
        if request.key in self.fenced_keys:
            return ProviderResult(
                request.key, self.provider_id, EffectOutcome.NOT_DONE, fenced=True
            )
        self.sends.append(request)
        if request.key in self.timeout_once_keys:
            self.timeout_once_keys.remove(request.key)
            if self.timeout_lands.get(request.key, True):
                self.done_keys.add(request.key)
            raise TimeoutError("simulated provider gateway timeout")
        self.done_keys.add(request.key)
        return ProviderResult(request.key, self.provider_id, EffectOutcome.DONE, fenced=True)

    def query_and_fence(self, request: EffectRequest) -> ProviderResult:
        self.queries.append(request)
        if request.key in self.done_keys:
            return ProviderResult(request.key, self.provider_id, EffectOutcome.DONE)
        self.fenced_keys.add(request.key)
        return ProviderResult(request.key, self.provider_id, EffectOutcome.NOT_DONE, fenced=True)


def _demo_target(action: str, *, scope: str, subject: str) -> dict[str, str]:
    return {"action": action, "scope": scope, "subject": subject}


def _build_demo_constitution() -> Constitution:
    return Constitution(
        name="acgs-demo-membrane",
        version="2026.11",
        rules=[
            Rule(
                id="no-wire-transfer",
                text="Unapproved wire transfers are blocked before execution",
                severity=Severity.CRITICAL,
                keywords=["wire transfer"],
            ),
            Rule(
                id="no-raw-ssn",
                text="Raw SSNs are blocked before execution",
                severity=Severity.HIGH,
                patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
            ),
        ],
    )


def _init_signer() -> tuple[Ed25519ReceiptSigner | None, str | None]:
    try:
        signer = Ed25519ReceiptSigner.from_seed(_DEMO_SIGNING_SEED, key_id="acgs-demo-key-1")
        return signer, signer.public_key_hex()
    except ReceiptSigningUnavailable:
        return None, None


def _authorize_and_mint(
    *,
    engine: GovernanceEngine,
    constitution: Constitution,
    authority: ExecutionAuthority,
    signer: Ed25519ReceiptSigner | None,
    action: str,
    scope: str,
    subject: str,
) -> tuple[ExecutionGrant, SignedReceipt | None]:
    val_result = engine.validate(action, agent_id="demo-agent")
    if not val_result.valid:
        raise LegitimacyInvariantError(
            f"Constitutional violation blocked action: {[v.rule_id for v in val_result.violations]}"
        )
    invocation = bind_invocation(_demo_target, (action,), {"scope": scope, "subject": subject})
    policy = bind_policy(constitution)
    decision = engine_decision_from_results([val_result])
    grant_id = authority.allocate_grant_id()
    try:
        receipt = build_issue_receipt(
            func=_demo_target,
            invocation=invocation,
            policy=policy,
            decision=decision,
            grant_id=grant_id,
        )
        signed_decision: SignedReceipt | None = None
        if signer is not None:
            auth_json = authorization_envelope_json(invocation, policy, grant_id=grant_id)
            signed_decision = sign_execution_authorization(
                receipt, signer, authorization_json=auth_json
            )
        grant = authority.issue(
            receipt=receipt,
            invocation=invocation,
            policy=policy,
            grant_id=grant_id,
            signed_receipt=signed_decision,
        )
    finally:
        authority.release_grant_id(grant_id)

    validate_receipt_for_execution(
        grant.receipt,
        actual_call=ActualCall(method="_demo_target", scope=scope, subjects=(subject,)),
    )
    return grant, signed_decision


def _run_allow_scenario(
    *,
    engine: GovernanceEngine,
    constitution: Constitution,
    authority: ExecutionAuthority,
    contracted: ContractedEffectStore,
    provider: _DemoProvider,
    signer: Ed25519ReceiptSigner | None,
    public_key: str | None,
) -> tuple[dict[str, Any], ExecutionGrant, str]:
    grant, signed_decision = _authorize_and_mint(
        engine=engine,
        constitution=constitution,
        authority=authority,
        signer=signer,
        action="refund invoice inv-1042",
        scope="tenant-demo",
        subject="customer-1042",
    )
    effect = contracted.store.reserve(
        provider_id=provider.provider_id,
        grant_identity=local_grant_identity(grant),
        action={"operation": "refund", "invoice": "inv-1042", "amount_cents": 2500},
        budget_id="demo-payments-budget",
        amount=2500,
    )
    record = contracted.send(effect.key, provider, grant=grant)
    outcome = outcome_from_record(
        record,
        store=contracted,
        provider=provider,
        grant=grant,
        provider_reference="ch_demo_1042",
    )

    signed_outcome: SignedOutcomeReceipt | None = None
    decision_verified: bool | None = None
    outcome_verified: bool | None = None
    if signer is not None and public_key is not None:
        signed_outcome = sign_outcome(outcome, signer)
        decision_verified = signed_decision is not None and signed_decision.verify(public_key)
        outcome_verified = signed_outcome.verify(public_key)

    return (
        {
            "passed": (
                record.state is EffectState.DONE
                and len(provider.sends) == 1
                and (decision_verified in (True, None))
                and (outcome_verified in (True, None))
            ),
            "decision": grant.receipt.decision_type,
            "decision_receipt_identity": receipt_identity(grant.receipt),
            "effect_key": record.key,
            "outcome": outcome.outcome.value,
            "outcome_receipt_identity": outcome.identity,
            "provider_calls": len(provider.sends),
            "decision_signature_verified": decision_verified,
            "outcome_signature_verified": outcome_verified,
        },
        grant,
        effect.key,
    )


def _run_retry_and_unknown_scenario(
    *,
    engine: GovernanceEngine,
    constitution: Constitution,
    authority: ExecutionAuthority,
    contracted: ContractedEffectStore,
    provider: _DemoProvider,
    signer: Ed25519ReceiptSigner | None,
    public_key: str | None,
    first_grant: ExecutionGrant,
    first_effect_key: str,
) -> dict[str, Any]:
    sends_before_retry = len(provider.sends)
    retried_record = contracted.send(first_effect_key, provider, grant=first_grant)
    calls_after_retry = len(provider.sends) - sends_before_retry

    timeout_grant, _ = _authorize_and_mint(
        engine=engine,
        constitution=constitution,
        authority=authority,
        signer=signer,
        action="refund invoice inv-2099",
        scope="tenant-demo",
        subject="customer-2099",
    )
    timeout_effect = contracted.store.reserve(
        provider_id=provider.provider_id,
        grant_identity=local_grant_identity(timeout_grant),
        action={"operation": "refund", "invoice": "inv-2099", "amount_cents": 1500},
        budget_id="demo-payments-budget",
        amount=1500,
    )
    provider.timeout_once_keys.add(timeout_effect.key)
    provider.timeout_lands[timeout_effect.key] = True

    timed_out = False
    try:
        contracted.send(timeout_effect.key, provider, grant=timeout_grant)
    except TimeoutError:
        timed_out = True

    held_state = contracted.store.get(timeout_effect.key).state
    unknown_refused_receipt = False
    try:
        outcome_from_record(
            contracted.store.get(timeout_effect.key),
            store=contracted,
            provider=provider,
            grant=timeout_grant,
        )
    except ValueError:
        unknown_refused_receipt = True

    # Per-key UNKNOWN isolation: another key still dispatches normally.
    sibling_grant, _ = _authorize_and_mint(
        engine=engine,
        constitution=constitution,
        authority=authority,
        signer=signer,
        action="refund invoice inv-3001",
        scope="tenant-demo",
        subject="customer-3001",
    )
    sibling_effect = contracted.store.reserve(
        provider_id=provider.provider_id,
        grant_identity=local_grant_identity(sibling_grant),
        action={"operation": "refund", "invoice": "inv-3001", "amount_cents": 500},
        budget_id="demo-payments-budget",
        amount=500,
    )
    sibling_record = contracted.send(sibling_effect.key, provider, grant=sibling_grant)

    reconciled_record = contracted.reconcile(timeout_effect.key, provider)
    reconciled_outcome = outcome_from_record(
        reconciled_record,
        store=contracted,
        provider=provider,
        grant=timeout_grant,
        provider_reference="ch_demo_2099",
    )
    reconciled_verified: bool | None = None
    if signer is not None and public_key is not None:
        reconciled_verified = sign_outcome(reconciled_outcome, signer).verify(public_key)

    return {
        "passed": (
            retried_record.state is EffectState.DONE
            and calls_after_retry == 0
            and timed_out
            and held_state is EffectState.UNKNOWN
            and unknown_refused_receipt
            and sibling_record.state is EffectState.DONE
            and reconciled_record.state is EffectState.DONE
            and (reconciled_verified in (True, None))
        ),
        "retry_provider_calls_added": calls_after_retry,
        "timeout_held_state": held_state.value,
        "unknown_blocked_receipt": unknown_refused_receipt,
        "other_key_unblocked": sibling_record.state is EffectState.DONE,
        "reconciled_state": reconciled_record.state.value,
        "reconciled_outcome_identity": reconciled_outcome.identity,
        "reconciled_signature_verified": reconciled_verified,
    }


def _run_deny_scenario(engine: GovernanceEngine, provider: _DemoProvider) -> dict[str, Any]:
    sends_before = len(provider.sends)
    result = engine.validate("wire transfer $100000", agent_id="demo-agent")
    rule_ids = [v.rule_id for v in result.violations]
    sends_after = len(provider.sends)
    return {
        "passed": (not result.valid)
        and ("no-wire-transfer" in rule_ids)
        and sends_after == sends_before,
        "valid": result.valid,
        "matched_rules": rule_ids,
        "provider_calls_added": sends_after - sends_before,
    }


def _run_missing_receipt_scenario(constitution: Constitution) -> dict[str, Any]:
    missing_refused = False
    missing_error = ""
    try:
        validate_receipt_for_execution(
            None,
            actual_call=ActualCall(
                method="_demo_target", scope="tenant-demo", subjects=("acct-1",)
            ),
        )
    except LegitimacyInvariantError as exc:
        missing_refused = True
        missing_error = str(exc)

    from acgs_lite.legitimacy import ExecutionBoundary

    denied_receipt = DecisionReceipt.create(
        request_id="demo-deny-1",
        goal="block denied receipt at executor gate",
        proposed_method="_demo_target",
        decision_type="DENY_GOAL",
        authority_basis="acgs-demo",
        matched_constraints=("no-wire-transfer",),
        policy_version=constitution.hash_versioned,
        denial_or_review_rationale="denied by constitutional rule",
        execution_boundary=ExecutionBoundary(
            allowed_method="_demo_target",
            allowed_scope="tenant-demo",
            allowed_subjects=("acct-1",),
            expires_at=None,
            single_use=True,
        ),
    )
    denied_refused = False
    denied_error = ""
    try:
        validate_receipt_for_execution(
            denied_receipt,
            actual_call=ActualCall(
                method="_demo_target", scope="tenant-demo", subjects=("acct-1",)
            ),
        )
    except LegitimacyInvariantError as exc:
        denied_refused = True
        denied_error = str(exc)

    return {
        "passed": missing_refused and denied_refused,
        "missing_receipt_refused": missing_refused,
        "missing_receipt_error": missing_error,
        "denied_receipt_refused": denied_refused,
        "denied_receipt_error": denied_error,
    }


def _run_maci_scenario() -> dict[str, Any]:
    maci = MACIEnforcer()
    maci.assign_role("agent-proposer", MACIRole.PROPOSER)
    maci.assign_role("agent-validator", MACIRole.VALIDATOR)
    maci.assign_role("agent-executor", MACIRole.EXECUTOR)

    independent_ok = maci.check_no_self_validation("agent-proposer", "agent-validator")
    executor_ok = maci.check("agent-executor", "execute")

    self_validation_blocked = False
    try:
        maci.check_no_self_validation("agent-proposer", "agent-proposer")
    except MACIViolationError:
        self_validation_blocked = True

    proposer_execute_blocked = False
    try:
        maci.check("agent-proposer", "execute")
    except MACIViolationError:
        proposer_execute_blocked = True

    return {
        "passed": (
            independent_ok and executor_ok and self_validation_blocked and proposer_execute_blocked
        ),
        "independent_validation_allowed": independent_ok,
        "executor_allowed": executor_ok,
        "self_validation_blocked": self_validation_blocked,
        "proposer_execute_blocked": proposer_execute_blocked,
    }


def run_demo_suite() -> dict[str, Any]:
    """Run all five zero-config ACGS demo scenarios and return structured results."""
    constitution = _build_demo_constitution()
    engine = GovernanceEngine(constitution, strict=False)
    authority = ExecutionAuthority()
    signer, public_key = _init_signer()
    provider = _DemoProvider()
    registry = ProviderContractRegistry()
    contract = registry.register(
        ProviderContract(
            provider_id=provider.provider_id,
            contract_class=ProviderContractClass.FENCEABLE,
            version="2026-11",
            dedup_by_key=True,
            atomic_query_fence=True,
        )
    )

    with tempfile.TemporaryDirectory(prefix="acgs-demo-") as tmp_dir:
        store = EffectStore(Path(tmp_dir) / "demo_effects.sqlite")
        store.create_budget("demo-payments-budget", 10_000)
        contracted = ContractedEffectStore(store, registry)

        allow_res, first_grant, first_key = _run_allow_scenario(
            engine=engine,
            constitution=constitution,
            authority=authority,
            contracted=contracted,
            provider=provider,
            signer=signer,
            public_key=public_key,
        )
        retry_res = _run_retry_and_unknown_scenario(
            engine=engine,
            constitution=constitution,
            authority=authority,
            contracted=contracted,
            provider=provider,
            signer=signer,
            public_key=public_key,
            first_grant=first_grant,
            first_effect_key=first_key,
        )
        deny_res = _run_deny_scenario(engine, provider)
        missing_res = _run_missing_receipt_scenario(constitution)
        maci_res = _run_maci_scenario()

    scenarios = {
        "allow_and_signed_receipts": allow_res,
        "at_most_once_and_unknown_reconcile": retry_res,
        "deny_before_side_effect": deny_res,
        "missing_or_denied_receipt_refusal": missing_res,
        "maci_separation_of_duties": maci_res,
    }
    all_passed = all(bool(item["passed"]) for item in scenarios.values())
    return {
        "all_passed": all_passed,
        "crypto_signing_available": signer is not None,
        "public_key_hex": public_key,
        "contract_identity": contract.identity,
        "scenarios": scenarios,
    }


def add_parser(sub: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the demo subcommand."""
    p = sub.add_parser(
        "demo",
        help="Run a zero-config tour of signed receipts, at-most-once effects, and MACI",
    )
    p.add_argument("--json", dest="json_out", action="store_true", help="Emit JSON output")


def handler(args: argparse.Namespace) -> int:
    """Execute the zero-config ACGS Receipted Effects & MACI demonstration."""
    summary = run_demo_suite()
    if getattr(args, "json_out", False):
        print(json.dumps(summary, indent=2))
        return 0 if summary["all_passed"] else 1

    s = summary["scenarios"]
    print()
    print("  ACGS 4.0 — Receipted Effects & MACI Demo")
    print("  " + "=" * 56)
    print(f"  Contract: {summary['contract_identity']}")
    if not summary["crypto_signing_available"]:
        print(
            "  Warning: 'cryptography' extra not installed — Ed25519 signing skipped "
            "(install acgs-lite[crypto] to verify signatures).",
            file=sys.stderr,
        )
    else:
        print(f"  Public Key (Ed25519): {summary['public_key_hex'][:24]}...")
    print()

    a = s["allow_and_signed_receipts"]
    print(f"  [1/5] ALLOW + Signed Receipts ....... {'PASS' if a['passed'] else 'FAIL'}")
    print(f"        Decision: {a['decision']} -> {a['decision_receipt_identity'][:40]}...")
    print(f"        Outcome:  {a['outcome']} -> {a['outcome_receipt_identity'][:40]}...")
    print(
        f"        Offline public-key verify: decision={a['decision_signature_verified']}, "
        f"outcome={a['outcome_signature_verified']}"
    )

    r = s["at_most_once_and_unknown_reconcile"]
    print(f"  [2/5] At-Most-Once + UNKNOWN ........ {'PASS' if r['passed'] else 'FAIL'}")
    print(f"        Same-key retry extra sends: {r['retry_provider_calls_added']} (deduplicated)")
    print(
        f"        Timeout state: {r['timeout_held_state']} -> other key unblocked="
        f"{r['other_key_unblocked']} -> reconciled={r['reconciled_state']}"
    )

    d = s["deny_before_side_effect"]
    print(f"  [3/5] DENY Before Side Effect ....... {'PASS' if d['passed'] else 'FAIL'}")
    print(
        f"        Rules: {d['matched_rules']} | Provider calls added: {d['provider_calls_added']}"
    )

    m = s["missing_or_denied_receipt_refusal"]
    print(f"  [4/5] Missing/Denied Receipt Gate ... {'PASS' if m['passed'] else 'FAIL'}")
    print(f"        Missing receipt refused: {m['missing_receipt_error']}")

    maci = s["maci_separation_of_duties"]
    print(f"  [5/5] MACI Separation of Duties ..... {'PASS' if maci['passed'] else 'FAIL'}")
    print(
        f"        Self-validation blocked={maci['self_validation_blocked']} | "
        f"Proposer-execute blocked={maci['proposer_execute_blocked']}"
    )
    print()
    print("  Result: ALL 5 SCENARIOS PASSED" if summary["all_passed"] else "  Result: FAILED")
    print("  Next:   acgs init  |  https://acgs.ai")
    print()
    return 0 if summary["all_passed"] else 1
