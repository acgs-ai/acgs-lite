"""Boundary and failure-direction tests for the SMT verification gate.

Failure direction: anything the gate could not decide must be reported as a
non-``PASS`` status, because only ``PASS`` counts as verified. The z3-absent tests
run without z3 on purpose (the python-fallback CI lane installs none); every test
that needs the solver calls ``pytest.importorskip("z3")`` itself.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.formal import smt_gate
from acgs_lite.formal.policy_ast import parse_policy_source
from acgs_lite.formal.smt_gate import Z3VerificationGate
from acgs_lite.z3_verify import VerificationStatus

pytestmark = pytest.mark.unit


def _constitution(*rules: Rule) -> Constitution:
    return Constitution.from_rules(list(rules), name="boundary")


def _rule(rule_id: str, policy: str, **kwargs: Any) -> Rule:
    return Rule(id=rule_id, text=f"z3: {policy}", severity=Severity.CRITICAL, **kwargs)


class _SolverProxy:
    """The real z3 module, except that ``Solver()`` misbehaves after *good_calls* calls.

    Everything else is delegated through ``__getattr__`` so expressions, sorts and
    the sat/unsat constants are real z3 objects.
    """

    def __init__(self, z3: Any, good_calls: int, *, unknown_after: bool = False) -> None:
        self._z3 = z3
        self._good_calls = good_calls
        self._unknown_after = unknown_after
        self._calls = 0

    def __getattr__(self, name: str) -> Any:
        return getattr(self._z3, name)

    def Solver(self) -> Any:  # noqa: N802 - mirrors the z3 API
        self._calls += 1
        if self._calls <= self._good_calls:
            return self._z3.Solver()
        if self._unknown_after:
            return _UnknownSolver(self._z3.unknown)
        raise RuntimeError("solver crashed")


class _UnknownSolver:
    def __init__(self, answer: Any) -> None:
        self._answer = answer

    def set(self, *args: Any) -> None:
        return None

    def add(self, expression: Any) -> None:
        return None

    def check(self) -> Any:
        return self._answer


# --------------------------------------------------------------------------- #
# z3 absent: nothing verified, never PASS.
# --------------------------------------------------------------------------- #


def test_missing_z3_reports_unavailable_for_constitution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "z3", None)

    gate = Z3VerificationGate()
    report = gate.verify_constitution(_constitution(_rule("R-1", "x > 0")))

    assert gate.available is False
    assert report.status is VerificationStatus.UNAVAILABLE
    assert report.exit_code == 2
    assert report.verified is False


def test_missing_z3_reports_unavailable_for_single_rule() -> None:
    rule = _rule("R-1", "(p and not q) or -x > 0")

    result = Z3VerificationGate(z3_module=None).check(rule, _constitution(rule))

    assert result.status is VerificationStatus.UNAVAILABLE
    assert result.detail == "z3-solver is not installed"
    assert result.verified is False


# --------------------------------------------------------------------------- #
# Sort inference and worst-verdict selection (real z3).
# --------------------------------------------------------------------------- #


def test_infer_sorts_covers_python_connectives() -> None:
    sorts = smt_gate._infer_sorts(parse_policy_source("(p and not q) or -x > y"))

    assert sorts == {"p": "Bool", "q": "Bool", "x": "Real", "y": "Real"}


def test_python_connectives_policy_is_satisfiable_and_passes() -> None:
    pytest.importorskip("z3")
    rule = _rule("R-1", "(p and not q) or -x > 0")

    result = Z3VerificationGate().check(rule, _constitution(rule))

    assert result.status is VerificationStatus.PASS
    assert result.detail == "satisfiable"


def test_worst_verdict_wins_when_a_rule_carries_several_policies() -> None:
    pytest.importorskip("z3")
    contradictory = _rule("R-2", "x > 0", metadata={"z3_expression": "x > 1 and x < 0"})

    result = Z3VerificationGate().check(contradictory, _constitution(contradictory))

    assert result.status is VerificationStatus.FAIL
    assert result.policy == "x > 1 and x < 0"
    assert result.detail.startswith("policy is unsatisfiable")


def test_invalid_policy_outranks_a_passing_policy_on_the_same_rule() -> None:
    pytest.importorskip("z3")
    malformed = _rule("R-3", "x > 0", metadata={"z3_expression": "x >"})

    result = Z3VerificationGate().check(malformed, _constitution(malformed))

    assert result.status is VerificationStatus.INVALID_POLICY
    assert result.policy == "x >"
    assert result.verified is False


# --------------------------------------------------------------------------- #
# Broken solvers fail closed.
# --------------------------------------------------------------------------- #

# Each policy uses exactly two Solver() instances in _check_policy (satisfiability,
# then _is_tautology), so with two policies the 5th Solver() call is the cluster's.
_POLICY_SOLVERS_FOR_TWO_POLICIES = 4


def _cluster_constitution() -> Constitution:
    # Both rules bind x, so they form a single cluster.
    return _constitution(_rule("C-1", "x > 0"), _rule("C-2", "x < 10"))


def test_crashing_cluster_solver_is_error_not_pass() -> None:
    z3 = pytest.importorskip("z3")
    gate = Z3VerificationGate(z3_module=_SolverProxy(z3, _POLICY_SOLVERS_FOR_TWO_POLICIES))

    report = gate.verify_constitution(_cluster_constitution())

    assert report.status is VerificationStatus.ERROR
    assert report.exit_code == 2
    assert len(report.clusters) == 1
    cluster = report.clusters[0]
    assert cluster.status is VerificationStatus.ERROR
    assert cluster.detail == "RuntimeError: solver crashed"
    assert cluster.rule_ids == ("C-1", "C-2")


def test_unknown_cluster_solver_answer_is_not_verified() -> None:
    z3 = pytest.importorskip("z3")
    proxy = _SolverProxy(z3, _POLICY_SOLVERS_FOR_TWO_POLICIES, unknown_after=True)

    report = Z3VerificationGate(z3_module=proxy).verify_constitution(_cluster_constitution())

    assert report.status is VerificationStatus.UNKNOWN
    assert report.exit_code == 2
    assert report.clusters[0].status is VerificationStatus.UNKNOWN
    assert (
        report.clusters[0].detail == "solver returned unknown; joint consistency was not verified"
    )


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "smt_gate._is_tautology swallows a solver exception and returns False, so a "
        "tautology is reported PASS when the tautology solver crashes; the module "
        "docstring (Failure direction) says a raising solver must never yield PASS"
    ),
)
def test_crashing_tautology_solver_must_not_verify() -> None:
    z3 = pytest.importorskip("z3")
    # Solver #1 (satisfiability) works; solver #2 (tautology check) raises.
    gate = Z3VerificationGate(z3_module=_SolverProxy(z3, 1))
    rule = _rule("T-1", "x > 0 or x <= 0")

    result = gate.check(rule, _constitution(rule))

    assert not result.verified
