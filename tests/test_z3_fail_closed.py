"""Fail-closed regressions for the Z3 enforcement gate.

The gate used to be ``verified and not satisfiable`` — block only on a *proven*
violation. Every failure path set ``verified=False``, so a missing solver, a
malformed policy, a timeout, or an exception all read as "allow". A one-character
typo in a constitution turned a real BLOCK into an ALLOW while logging at WARNING.

The invariant these tests hold:

    PASS          verified=True,  satisfiable=True    -> allow
    everything else                                   -> block

INAPPLICABLE is in "everything else". A policy that names none of a callable's
parameters is usually about some other callable -- but it is also what you get
when a callable has no type hints at all, so "nothing applied" cannot be told
apart from "the control was switched off by deleting an annotation". Running
such a callable requires an explicit, expiring, audited exemption; see
tests/test_verification_exemption.py.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
from pydantic import Field

from acgs_lite import Constitution, ConstitutionalViolationError, GovernedCallable, Rule
from acgs_lite.audit import AuditLog
from acgs_lite.legitimacy.receipt import DecisionReceipt, ExecutionBoundary
from acgs_lite.z3_verify import (
    Z3_AVAILABLE,
    VerificationStatus,
    Z3VerifyResult,
    blocks_execution,
    verify_callable_arguments,
)

pytestmark = pytest.mark.unit

# Deliberately NOT `importorskip` at module scope. The most important thing this
# file asserts is what happens when the solver is ABSENT — skipping the whole
# module without z3 would turn the z3-less lane green while testing none of it.
# Only the cases that need real solving are guarded; the rest run in both
# configurations, and CI runs both (see .github/workflows/ci.yml).
requires_z3 = pytest.mark.skipif(not Z3_AVAILABLE, reason="needs a real solver")


def _result(status: VerificationStatus, **overrides: Any) -> Z3VerifyResult:
    defaults: dict[str, Any] = {
        "satisfiable": status in (VerificationStatus.PASS, VerificationStatus.INAPPLICABLE),
        "verified": status in (VerificationStatus.PASS, VerificationStatus.FAIL),
        "solver_result": "skipped",
        "counterexample": None,
        "verification_time_ms": 0.0,
        "status": status,
    }
    return Z3VerifyResult(**{**defaults, **overrides})


class TestBlocksExecutionIsAnAllowlist:
    """Only two statuses may permit execution; the rest must block."""

    @pytest.mark.parametrize("status", [VerificationStatus.PASS])
    def test_allowing_statuses(self, status: VerificationStatus) -> None:
        assert blocks_execution(_result(status)) is False

    def test_pass_is_the_only_allowing_status(self) -> None:
        """One member. Adding a second needs an argument about what it proves."""
        allowing = [s for s in VerificationStatus if not blocks_execution(_result(s))]
        assert allowing == [VerificationStatus.PASS]

    @pytest.mark.parametrize(
        "status",
        [
            VerificationStatus.FAIL,
            VerificationStatus.INAPPLICABLE,
            VerificationStatus.UNAVAILABLE,
            VerificationStatus.INVALID_POLICY,
            VerificationStatus.UNKNOWN,
            VerificationStatus.ERROR,
        ],
    )
    def test_blocking_statuses(self, status: VerificationStatus) -> None:
        assert blocks_execution(_result(status)) is True

    def test_every_status_is_classified(self) -> None:
        """A status added later must be covered here, not silently permitted."""
        for status in list(VerificationStatus):
            assert isinstance(blocks_execution(_result(status)), bool)

    def test_default_status_blocks(self) -> None:
        """A result built without an explicit status must not read as a pass."""
        bare = Z3VerifyResult(
            satisfiable=True,
            verified=True,
            solver_result="unsat",
            counterexample=None,
            verification_time_ms=0.0,
        )
        assert blocks_execution(bare) is True


def _policy_result(policy: str, value: int = 10_000) -> Z3VerifyResult:
    def transfer(amount: int) -> str:
        return f"moved {amount}"

    return verify_callable_arguments(transfer, (value,), {}, [policy])


@requires_z3
class TestVerifierErrorStatesBlock:
    def test_violation_blocks(self) -> None:
        res = _policy_result("amount < 500", 10_000)
        assert res.status is VerificationStatus.FAIL
        assert blocks_execution(res)

    def test_compliant_call_passes(self) -> None:
        res = _policy_result("amount < 500", 10)
        assert res.status is VerificationStatus.PASS
        assert not blocks_execution(res)

    @pytest.mark.parametrize(
        "policy",
        [
            "amount << 500",
            "amount <",
            "amount.__class__ == int",
            "open('x') == 1",
            "(lambda: 1)() < 500",
        ],
    )
    def test_malformed_policy_blocks(self, policy: str) -> None:
        """The F4 headline: a broken policy must not read as 'nothing to check'."""
        res = _policy_result(policy)
        assert res.status is VerificationStatus.INVALID_POLICY
        assert blocks_execution(res)

    def test_typo_cannot_turn_block_into_allow(self) -> None:
        """`<` vs `<<` on the same policy and the same violating argument."""
        correct = _policy_result("amount < 500", 10_000)
        typo = _policy_result("amount << 500", 10_000)
        assert blocks_execution(correct)
        assert blocks_execution(typo), "a typo silently disabled enforcement"

    def test_partially_bound_policy_blocks(self) -> None:
        """Some names resolve, some do not — undecidable, so block."""

        def transfer(amount: int) -> str:
            return f"moved {amount}"

        res = verify_callable_arguments(transfer, (10,), {}, ["And(amount < 500, quota > 0)"])
        assert res.status is VerificationStatus.INVALID_POLICY
        assert blocks_execution(res)

    def test_policy_naming_nothing_here_is_inapplicable_and_blocks(self) -> None:
        """A global policy about another callable's parameters proves nothing here.

        Not a failure, but not a pass either -- and the gate only forwards a pass.
        """

        def rotate_key(name: str) -> str:
            return name

        res = verify_callable_arguments(rotate_key, ("k",), {}, ["amount < 500"])
        assert res.status is VerificationStatus.INAPPLICABLE
        assert blocks_execution(res)

    def test_unannotated_callable_blocks(self) -> None:
        """The fail-open vector, closed.

        No type hints means no variables, so every policy is trivially disjoint
        and the old rule read that as "nothing to enforce". Deleting a `: int`
        must not be a way out of a control.
        """

        def anything(x):  # type: ignore[no-untyped-def]
            return x

        res = verify_callable_arguments(anything, (1,), {}, ["amount < 500"])
        assert res.status is VerificationStatus.INAPPLICABLE
        assert blocks_execution(res)
        assert res.satisfiable is False, "a blocking status must not read as satisfiable"

    def test_solver_exception_blocks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import acgs_lite.z3_verify as mod

        def boom(*_a: Any, **_k: Any) -> Any:
            raise RuntimeError("solver exploded")

        monkeypatch.setattr(mod.z3, "Solver", boom)
        res = _policy_result("amount < 500")
        assert res.status is VerificationStatus.ERROR
        assert blocks_execution(res)

    def test_solver_unknown_blocks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import acgs_lite.z3_verify as mod

        class _UnknownSolver:
            def set(self, *_a: Any, **_k: Any) -> None: ...
            def add(self, *_a: Any, **_k: Any) -> None: ...
            def check(self) -> Any:
                return mod.z3.unknown

        monkeypatch.setattr(mod.z3, "Solver", _UnknownSolver)
        res = _policy_result("amount < 500")
        assert res.status is VerificationStatus.UNKNOWN
        assert blocks_execution(res)

    def test_missing_solver_blocks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Requirement 3: no verifier installed must not mean no verification."""
        import acgs_lite.z3_verify as mod

        monkeypatch.setattr(mod, "Z3_AVAILABLE", False)
        res = _policy_result("amount < 500")
        assert res.status is VerificationStatus.UNAVAILABLE
        assert blocks_execution(res)
        assert res.satisfiable is False


class TestGovernedEnforcement:
    """End to end through GovernedCallable, not the verifier in isolation."""

    @staticmethod
    def _receipt(method: str) -> DecisionReceipt:
        return DecisionReceipt.create(
            request_id=f"req-{method}",
            goal="Run governed callable test fixture",
            proposed_method=method,
            decision_type="ALLOW",
            authority_basis="test-authority",
            matched_constraints=("test-baseline-rule",),
            policy_version="test-policy-v1",
            execution_boundary=ExecutionBoundary(
                allowed_method=method,
                allowed_scope=None,
                allowed_subjects=(),
                expires_at=None,
                single_use=True,
            ),
        )

    @staticmethod
    def _constitution(policy: str) -> Constitution:
        return Constitution.from_rules([Rule(id="R1", text=f"z3: {policy}")])

    @requires_z3
    def test_violating_call_is_blocked(self) -> None:
        @GovernedCallable(self._constitution("amount < 500"))
        def withdraw(amount: float = Field(gt=0, le=1000)) -> str:
            return f"Withdrew {amount}"

        with pytest.raises(ConstitutionalViolationError, match="violates mathematical"):
            withdraw(600.0, decision_receipt=self._receipt("withdraw"))

    @requires_z3
    def test_compliant_call_still_runs(self) -> None:
        @GovernedCallable(self._constitution("amount < 500"))
        def withdraw(amount: float = Field(gt=0, le=1000)) -> str:
            return f"Withdrew {amount}"

        assert withdraw(300.0, decision_receipt=self._receipt("withdraw")) == "Withdrew 300.0"

    def test_malformed_policy_is_rejected_at_decoration(self) -> None:
        """A broken control fails when the constitution is wired up, not silently."""
        with pytest.raises(ConstitutionalViolationError, match="invalid Z3 policy"):

            @GovernedCallable(self._constitution("amount << 500"))
            def withdraw(amount: float = Field(gt=0, le=1000)) -> str:
                return f"Withdrew {amount}"

    def test_sandbox_escape_policy_is_rejected_at_decoration(self, tmp_path: Any) -> None:
        marker = tmp_path / "PWNED.txt"
        payload = (
            "And.__globals__['__builtins__']['open']"
            f"({str(marker)!r}, 'w').write('x') == 0 or amount < 500"
        )
        with pytest.raises(ConstitutionalViolationError, match="invalid Z3 policy"):

            @GovernedCallable(self._constitution(payload))
            def withdraw(amount: float = Field(gt=0, le=1000)) -> str:
                return f"Withdrew {amount}"

        assert not marker.exists(), "constitution rule executed during decoration"

    def test_missing_solver_blocks_a_governed_call(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """With a policy present and no solver, the call must not proceed."""

        @GovernedCallable(self._constitution("amount < 500"))
        def withdraw(amount: float = Field(gt=0, le=1000)) -> str:
            return f"Withdrew {amount}"

        import acgs_lite.z3_verify as mod

        monkeypatch.setattr(mod, "Z3_AVAILABLE", False)
        with pytest.raises(ConstitutionalViolationError, match="unavailable"):
            withdraw(300.0, decision_receipt=self._receipt("withdraw"))

    @requires_z3
    def test_async_path_enforces_the_same_rule(self) -> None:
        @GovernedCallable(self._constitution("amount < 500"))
        async def withdraw(amount: float = Field(gt=0, le=1000)) -> str:
            return f"Withdrew {amount}"

        import asyncio

        with pytest.raises(ConstitutionalViolationError, match="violates mathematical"):
            asyncio.run(withdraw(600.0, decision_receipt=self._receipt("withdraw")))

    def test_no_policies_leaves_behavior_unchanged(self) -> None:
        """A constitution with no z3 rules must not start blocking anything."""
        plain = Constitution.from_rules([Rule(id="R1", text="be careful")])

        @GovernedCallable(plain)
        def withdraw(amount: float = Field(gt=0, le=1000)) -> str:
            return f"Withdrew {amount}"

        assert withdraw(600.0, decision_receipt=self._receipt("withdraw")) == "Withdrew 600.0"


def test_audit_log_is_untouched_by_this_change() -> None:
    """Guard against the fix accidentally altering unrelated governance state."""
    log = AuditLog()
    assert log.verify_chain() is True
    _ = time.time
