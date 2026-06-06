"""Tests for Z3 Pydantic-to-Z3 parsing and type-hint boundary checks."""

from __future__ import annotations

import logging
from typing import Annotated

import pytest
from pydantic import BaseModel, Field

from acgs_lite import Constitution, ConstitutionalViolationError, GovernedCallable, Rule
from acgs_lite.legitimacy.receipt import DecisionReceipt, ExecutionBoundary
from acgs_lite.z3_verify import (
    Z3_AVAILABLE,
    _extract_z3_policies,
    parse_callable_to_z3,
    parse_pydantic_to_z3,
    verify_callable_arguments,
    verify_callable_safety,
)

_log = logging.getLogger(__name__)


class SampleModel(BaseModel):
    amount: float = Field(gt=0, le=1000)
    count: int = Field(ge=1, lt=10)
    label: str = Field(min_length=3, max_length=20)
    flag: bool


@pytest.mark.skipif(not Z3_AVAILABLE, reason="z3-solver not installed")
class TestZ3BoundaryParsers:
    def test_parse_pydantic_model(self) -> None:
        """Verify parsing of Pydantic models into Z3 variables and constraints."""
        variables, constraints = parse_pydantic_to_z3(SampleModel)

        assert "amount" in variables
        assert "count" in variables
        assert "label" in variables
        assert "flag" in variables

        # There should be constraints for gt, le, ge, lt, min_length, max_length
        # 2 constraints for amount, 2 for count, 2 for label = 6 constraints
        assert len(constraints) == 6

    def test_parse_callable_parameters(self) -> None:
        """Verify parsing of function parameters and Annotated types."""

        def my_function(
            amount: Annotated[float, Field(gt=0, le=1000)],
            count: int = Field(ge=1, lt=10),
            flag: bool = True,
        ) -> None:
            pass

        variables, constraints = parse_callable_to_z3(my_function)

        assert "amount" in variables
        assert "count" in variables
        assert "flag" in variables
        assert len(constraints) == 4

    def test_parse_callable_with_pydantic_model(self) -> None:
        """Verify parsing of function parameters that are Pydantic models."""

        def process_request(data: SampleModel) -> None:
            pass

        variables, constraints = parse_callable_to_z3(process_request)

        assert "amount" in variables
        assert "count" in variables
        assert "label" in variables
        assert "flag" in variables
        assert len(constraints) == 6


@pytest.mark.skipif(not Z3_AVAILABLE, reason="z3-solver not installed")
class TestZ3SafetyVerification:
    def test_verify_callable_safety_unsafe(self) -> None:
        """Verify safety check fails (sat) when input space can violate policy."""

        def withdraw(amount: float = Field(gt=0, le=1000)) -> None:
            pass

        # Policy: amount must be less than 500.
        # Since amount can be up to 1000, this is unsafe.
        res = verify_callable_safety(withdraw, ["amount < 500"])
        assert res.satisfiable is False
        assert res.solver_result == "sat"
        assert res.counterexample is not None
        assert res.counterexample["amount"] >= 500

    def test_verify_callable_safety_safe(self) -> None:
        """Verify safety check passes (unsat) when input space is guaranteed safe."""

        def withdraw(amount: float = Field(gt=0, le=400)) -> None:
            pass

        # Since amount max is 400, it is guaranteed to be < 500.
        res = verify_callable_safety(withdraw, ["amount < 500"])
        assert res.satisfiable is True
        assert res.solver_result == "unsat"
        assert res.counterexample is None

    def test_verify_callable_arguments_unsafe(self) -> None:
        """Verify argument validation detects a runtime violation."""

        def withdraw(amount: float = Field(gt=0, le=1000)) -> None:
            pass

        # Runtime value amount = 600 violates policy amount < 500
        res = verify_callable_arguments(withdraw, (600.0,), {}, ["amount < 500"])
        assert res.satisfiable is False
        assert res.solver_result == "sat"

    def test_verify_callable_arguments_safe(self) -> None:
        """Verify argument validation passes for safe runtime values."""

        def withdraw(amount: float = Field(gt=0, le=1000)) -> None:
            pass

        res = verify_callable_arguments(withdraw, (300.0,), {}, ["amount < 500"])
        assert res.satisfiable is True
        assert res.solver_result == "unsat"


@pytest.mark.skipif(not Z3_AVAILABLE, reason="z3-solver not installed")
class TestGovernedCallableZ3Integration:
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

    def test_governed_callable_runtime_enforcement(self) -> None:
        """Test GovernedCallable dynamically enforces mathematical rules at runtime."""
        rules = Constitution.from_rules(
            [
                Rule(
                    id="R1",
                    text="z3: amount < 500",
                )
            ]
        )

        @GovernedCallable(rules)
        def withdraw(amount: float = Field(gt=0, le=1000)) -> str:
            return f"Withdrew {amount}"

        # Safe call
        assert withdraw(300.0, decision_receipt=self._receipt("withdraw")) == "Withdrew 300.0"

        # Unsafe call should raise ConstitutionalViolationError
        with pytest.raises(ConstitutionalViolationError) as exc_info:
            withdraw(600.0, decision_receipt=self._receipt("withdraw"))
        assert "violates mathematical constraints" in str(exc_info.value)

    def test_governed_callable_static_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test GovernedCallable logs a static warning if input space allows violations."""
        rules = Constitution.from_rules(
            [
                Rule(
                    id="R1",
                    text="amount < 500",
                    metadata={"z3_expression": "amount < 500"},
                )
            ]
        )

        import logging

        with caplog.at_level(logging.WARNING, logger="acgs_lite.governed"):

            @GovernedCallable(rules)
            def withdraw(amount: float = Field(gt=0, le=1000)) -> None:
                pass

        # Check if warning was logged
        warnings = [
            rec.message for rec in caplog.records if "Static verification warning" in rec.message
        ]
        assert len(warnings) > 0
        assert "withdraw" in warnings[0]
        assert "boundaries" in warnings[0]


def test_extract_z3_policies() -> None:
    """Verify policies are correctly extracted from rule metadata and text prefixes."""
    rules = Constitution.from_rules(
        [
            Rule(
                id="R1",
                text="Some rule",
                metadata={"z3_expression": "x < 10"},
            ),
            Rule(
                id="R2",
                text="z3: y > 5",
            ),
            Rule(
                id="R3",
                text="smt: z == 1",
            ),
            Rule(
                id="R4",
                text="Ignored rule",
            ),
        ]
    )

    policies = _extract_z3_policies(rules)
    assert "x < 10" in policies
    assert "y > 5" in policies
    assert "z == 1" in policies
    assert len(policies) == 3
