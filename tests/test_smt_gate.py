"""Adversarial tests for constitution SMT verification.

The gate this file covers replaced one whose verdict was constant by construction:
``satisfiable`` asserted a disjunction of fresh unconstrained booleans, and
``contradiction`` required two rules sharing an ``id`` with different severities, which
``Constitution`` rejects at construction. ``acgs eval verify-constitution`` could not
fail. So the load-bearing tests here are the ones that prove it now *can*: a
constitution with a real defect must produce a non-zero exit code through the actual
command, not merely a False attribute on an object.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pytest

from acgs_lite.commands import eval_cmd
from acgs_lite.constitution import Constitution, Rule, Severity
from acgs_lite.formal import smt_gate
from acgs_lite.formal.smt_gate import (
    ConstitutionVerificationReport,
    NullVerificationGate,
    Z3VerificationGate,
)
from acgs_lite.z3_verify import VerificationStatus

try:  # pragma: no cover - availability is the thing under test elsewhere
    import z3 as _z3

    Z3_INSTALLED = True
except ImportError:  # pragma: no cover
    _z3 = None
    Z3_INSTALLED = False

requires_z3 = pytest.mark.skipif(not Z3_INSTALLED, reason="z3-solver is not installed")


def _constitution(*policies: tuple[str, str]) -> Constitution:
    return Constitution.from_rules(
        [
            Rule(id=rule_id, text=f"z3: {policy}", severity=Severity.CRITICAL)
            for rule_id, policy in policies
        ],
        name="test-constitution",
    )


def _run_cli(*argv: str) -> int:
    """Drive argparse -> handler exactly as ``acgs`` does, and return the exit code.

    A unit test against the gate proves nothing about the command: the defect being
    fixed lived in the wiring between them, where a report was reduced to
    ``any(result.contradiction ...)``.
    """
    parser = argparse.ArgumentParser()
    eval_cmd.add_parser(parser.add_subparsers(dest="command", required=True))
    return eval_cmd.handler(parser.parse_args(["eval", *argv]))


def _write(tmp_path: Path, name: str, *policies: tuple[str, str]) -> str:
    # json.dumps produces a YAML-safe double-quoted scalar, so a policy may itself
    # contain quotes (`role == "admin"`) without breaking the fixture.
    lines = ["name: fixture", 'version: "1.0"', "rules:"]
    for rule_id, policy in policies:
        lines += [
            f"  - id: {json.dumps(rule_id)}",
            f"    text: {json.dumps('z3: ' + policy)}",
            "    severity: critical",
        ]
    path = tmp_path / name
    path.write_text("\n".join(lines) + "\n")
    return str(path)


# --------------------------------------------------------------------------- #
# The four cases the release brief requires, driven end to end where it matters.
# --------------------------------------------------------------------------- #


@requires_z3
def test_valid_constitution_verifies(tmp_path: Path) -> None:
    """A satisfiable, mutually consistent constitution passes and exits 0."""
    path = _write(tmp_path, "valid.yaml", ("T-001", "amount > 0"), ("T-002", "amount < 1000"))

    assert _run_cli("verify-constitution", "--constitution", path) == 0


@requires_z3
def test_conflicting_constitution_fails_through_the_cli(tmp_path: Path) -> None:
    """Two rules that cannot hold together exit 1. The old command exited 0 here."""
    path = _write(tmp_path, "conflict.yaml", ("T-001", "amount > 100"), ("T-002", "amount < 10"))

    assert _run_cli("verify-constitution", "--constitution", path) == 1


@requires_z3
def test_self_contradictory_policy_fails(tmp_path: Path) -> None:
    """A single unsatisfiable policy blocks every call it applies to, so it is a defect."""
    path = _write(tmp_path, "unsat.yaml", ("T-001", "And(amount > 100, amount < 10)"))

    assert _run_cli("verify-constitution", "--constitution", path) == 1


def test_solver_unavailable_blocks_and_never_passes() -> None:
    """No solver is ``UNAVAILABLE`` and exit 2 — never a pass, never a silent 0."""
    report = Z3VerificationGate(z3_module=None).verify_constitution(_constitution(("T-1", "a > 0")))

    assert report.status is VerificationStatus.UNAVAILABLE
    assert report.exit_code == 2
    assert report.verified is False
    assert all(r.status is VerificationStatus.UNAVAILABLE for r in report.results)


# --------------------------------------------------------------------------- #
# No-false-PASS paths.
# --------------------------------------------------------------------------- #


def test_constitution_without_policies_is_not_a_pass() -> None:
    """Nothing to verify must not read as verified — the shipped default's case."""
    report = Z3VerificationGate().verify_constitution(Constitution.default())

    assert report.status is VerificationStatus.INAPPLICABLE
    assert report.exit_code == 2
    assert report.verified is False
    assert "nothing was verified" in report.detail


def test_default_constitution_exits_two_through_the_cli() -> None:
    """The no-argument invocation reports NOT VERIFIED rather than success."""
    assert _run_cli("verify-constitution") == 2


def test_unreadable_constitution_file_is_not_verified_not_a_defect(tmp_path: Path) -> None:
    """A mistyped path verified nothing. Reporting exit 1 would read as "contradictory"."""
    assert _run_cli("verify-constitution", "--constitution", str(tmp_path / "absent.yaml")) == 2


def test_constitution_that_does_not_load_is_a_defect(tmp_path: Path) -> None:
    """It read but did not validate. Broken in the same way a malformed policy is."""
    path = tmp_path / "broken.yaml"
    path.write_text("name: broken\nrules: [[[\n")

    assert _run_cli("verify-constitution", "--constitution", str(path)) == 1


@requires_z3
def test_malformed_policy_is_invalid_not_absent(tmp_path: Path) -> None:
    """A policy that does not parse is a broken control, not a missing one."""
    path = _write(tmp_path, "malformed.yaml", ("T-001", "And.__globals__"))

    assert _run_cli("verify-constitution", "--constitution", path) == 1


@requires_z3
def test_broken_solver_module_is_error_not_pass() -> None:
    """A rule carrying a policy plus a solver module that raises must block."""

    class _BrokenSolver:
        def __getattr__(self, name: str) -> Any:
            raise RuntimeError(f"solver is broken: {name}")

    report = Z3VerificationGate(z3_module=_BrokenSolver()).verify_constitution(
        _constitution(("T-1", "amount > 0"))
    )

    assert report.status is VerificationStatus.ERROR
    assert report.exit_code == 2


@requires_z3
def test_unknown_verdict_does_not_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """A solver that will not answer is not a pass."""

    class _UnknownSolver:
        def set(self, *_a: Any, **_k: Any) -> None: ...
        def add(self, *_a: Any, **_k: Any) -> None: ...
        def check(self) -> Any:
            return _z3.unknown

    gate = Z3VerificationGate()
    monkeypatch.setattr(_z3, "Solver", _UnknownSolver)
    report = gate.verify_constitution(_constitution(("T-1", "amount > 0")))

    assert report.status is VerificationStatus.UNKNOWN
    assert report.exit_code == 2


def test_every_non_pass_status_maps_to_a_non_zero_exit_code() -> None:
    """PASS is the only status that may exit 0. A new status blocks by default."""
    for status in VerificationStatus:
        report = ConstitutionVerificationReport(status=status)
        assert (report.exit_code == 0) is (status is VerificationStatus.PASS), status


def test_every_status_has_a_precedence_entry() -> None:
    """A status missing from precedence would be dropped and could collapse to PASS."""
    assert set(smt_gate._STATUS_PRECEDENCE) == set(VerificationStatus)


def test_worst_of_nothing_blocks() -> None:
    """The unreachable default must still be a blocking status, not PASS."""
    assert smt_gate._worst([]) is not VerificationStatus.PASS


# --------------------------------------------------------------------------- #
# No-false-FAIL paths. A verifier that cries wolf gets switched off.
# --------------------------------------------------------------------------- #


@requires_z3
def test_policies_sharing_no_variable_are_not_a_contradiction(tmp_path: Path) -> None:
    """``amount`` in one rule and ``quantity`` in another bind to different callables.

    Joint-checking every policy in one namespace would report a contradiction between
    rules that can never apply to the same call.
    """
    path = _write(tmp_path, "disjoint.yaml", ("T-001", "amount > 100"), ("T-002", "quantity < 10"))

    assert _run_cli("verify-constitution", "--constitution", path) == 0


@requires_z3
def test_fractional_range_is_satisfiable_over_the_reals() -> None:
    """Variables are Reals, so ``0 < x < 1`` is SAT. Declaring Int would false-FAIL it."""
    report = Z3VerificationGate().verify_constitution(
        _constitution(("T-1", "And(ratio > 0, ratio < 1)"))
    )

    assert report.status is VerificationStatus.PASS


@requires_z3
def test_boolean_and_numeric_variables_coexist() -> None:
    """Sorts are inferred from syntax: propositions are Bools, operands are Reals."""
    report = Z3VerificationGate().verify_constitution(
        _constitution(("T-1", "Implies(is_admin, amount < 100)"))
    )

    assert report.status is VerificationStatus.PASS


@requires_z3
def test_one_variable_used_as_both_sorts_is_rejected_not_guessed() -> None:
    report = Z3VerificationGate().verify_constitution(_constitution(("T-1", "And(x, x > 1)")))

    assert report.status is VerificationStatus.INVALID_POLICY
    assert "one sort" in report.results[0].detail


# --------------------------------------------------------------------------- #
# The defect class the old gate was an instance of.
# --------------------------------------------------------------------------- #


@requires_z3
def test_tautology_is_a_defect_not_a_pass(tmp_path: Path) -> None:
    """``Or(flag, Not(flag))`` is satisfiable and enforces nothing.

    Reported as FAIL, not as a pass with a note: a control that is true for every input
    is the same defect class this module replaced, and a warning on an exit-0 run is not
    a machine-readable signal.
    """
    report = Z3VerificationGate().verify_constitution(_constitution(("T-1", "Or(flag, Not(flag))")))

    assert report.status is VerificationStatus.FAIL
    assert [r.rule_id for r in report.tautologies] == ["T-1"]

    path = _write(tmp_path, "taut.yaml", ("T-001", "Or(flag, Not(flag))"))
    assert _run_cli("verify-constitution", "--constitution", path) == 1


@requires_z3
def test_a_constant_true_policy_is_also_a_tautology() -> None:
    """``1 < 2`` names no variable and still constrains nothing."""
    report = Z3VerificationGate().verify_constitution(_constitution(("T-1", "1 < 2")))

    assert report.status is VerificationStatus.FAIL


# --------------------------------------------------------------------------- #
# Sorts the runtime can bind must be sorts this module can check.
# --------------------------------------------------------------------------- #


@requires_z3
def test_string_policy_verifies(tmp_path: Path) -> None:
    """`z3_verify` binds a ``str`` parameter as ``z3.String``, so a string policy is real."""
    path = _write(tmp_path, "str_ok.yaml", ("T-001", 'role == "admin"'))

    assert _run_cli("verify-constitution", "--constitution", path) == 0


@requires_z3
def test_contradictory_string_policies_fail(tmp_path: Path) -> None:
    """Declaring `role` a Real would make this ERROR (exit 2) instead of a defect."""
    path = _write(
        tmp_path, "str_bad.yaml", ("T-001", 'role == "admin"'), ("T-002", 'role == "user"')
    )

    assert _run_cli("verify-constitution", "--constitution", path) == 1


@requires_z3
def test_modulo_policy_verifies(tmp_path: Path) -> None:
    """``%`` is in the policy language and is meaningless over the reals — infer Int."""
    path = _write(tmp_path, "mod_ok.yaml", ("T-001", "x % 2 == 0"))

    assert _run_cli("verify-constitution", "--constitution", path) == 0


@requires_z3
def test_contradictory_modulo_policies_fail(tmp_path: Path) -> None:
    path = _write(tmp_path, "mod_bad.yaml", ("T-001", "x % 2 == 0"), ("T-002", "x % 2 == 1"))

    assert _run_cli("verify-constitution", "--constitution", path) == 1


@requires_z3
def test_modulo_narrows_the_variable_for_the_whole_cluster() -> None:
    """``x % 2`` makes x an integer, so ``0 < x < 1`` becomes a genuine contradiction."""
    report = Z3VerificationGate().verify_constitution(
        _constitution(("T-1", "x % 2 == 0"), ("T-2", "And(x > 0, x < 1)"))
    )

    assert report.status is VerificationStatus.FAIL


@requires_z3
def test_a_variable_used_as_string_and_number_is_rejected() -> None:
    report = Z3VerificationGate().verify_constitution(
        _constitution(("T-1", 'role == "a"'), ("T-2", "role > 1"))
    )

    assert report.status is VerificationStatus.INVALID_POLICY


@requires_z3
def test_a_real_constraint_is_not_reported_as_a_tautology() -> None:
    report = Z3VerificationGate().verify_constitution(_constitution(("T-1", "amount > 0")))

    assert report.tautologies == ()


@requires_z3
def test_the_old_keyword_disjunction_can_no_longer_produce_a_verdict() -> None:
    """Keywords are not a constraint. A rule with keywords and no policy verifies nothing."""
    rule = Rule(
        id="RULE-001",
        text="block secrets",
        severity=Severity.CRITICAL,
        keywords=["secret", "token", "key"],
    )
    constitution = Constitution.from_rules([rule], name="keywords-only")

    report = Z3VerificationGate().verify_constitution(constitution)

    assert report.status is VerificationStatus.INAPPLICABLE
    assert report.exit_code == 2


# --------------------------------------------------------------------------- #
# Per-rule surface and the null gate.
# --------------------------------------------------------------------------- #


@requires_z3
def test_check_reports_inapplicable_for_a_rule_without_a_policy() -> None:
    rule = Rule(id="RULE-001", text="block secrets", severity=Severity.CRITICAL, keywords=["x"])

    result = Z3VerificationGate().check(rule, Constitution.from_rules([rule], name="c"))

    assert result.status is VerificationStatus.INAPPLICABLE
    assert result.verified is False


@requires_z3
def test_check_reads_a_policy_from_rule_metadata() -> None:
    rule = Rule(
        id="RULE-001",
        text="spend cap",
        severity=Severity.CRITICAL,
        metadata={"z3_expression": "And(amount > 10, amount < 1)"},
    )

    result = Z3VerificationGate().check(rule, Constitution.from_rules([rule], name="c"))

    assert result.status is VerificationStatus.FAIL


def test_null_gate_reports_unavailable_never_pass() -> None:
    """A gate that verifies nothing must not be a drop-in that says everything is fine."""
    rule = Rule(id="RULE-001", text="block secrets", severity=Severity.CRITICAL, keywords=["s"])

    result = NullVerificationGate().check(rule, Constitution.from_rules([rule], name="c"))
    report = NullVerificationGate().verify_constitution(Constitution.default())

    assert result.status is VerificationStatus.UNAVAILABLE
    assert result.verified is False
    assert report.status is VerificationStatus.UNAVAILABLE
    assert report.exit_code == 2
