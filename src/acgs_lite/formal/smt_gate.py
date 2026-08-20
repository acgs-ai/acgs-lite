"""SMT verification of the machine-checkable content of a constitution.

What this module can and cannot prove
-------------------------------------
A constitutional rule is mostly prose. Prose is not checkable by a solver, and the
previous version of this gate pretended otherwise: it asserted ``Or(kw_0, ..., kw_n)``
over *fresh unconstrained booleans* — a formula whose satisfiability is independent of
the rule it claims to be about — and reported a contradiction only when two rules
shared an ``id`` with different severities, which ``Constitution`` rejects at
construction. Both columns were constants, so ``acgs eval verify-constitution`` could
not fail. A verification command that is structurally incapable of detecting failure
is worse than no command, because it produces an assurance record.

The only machine-checkable content a rule carries is a **Z3 policy**: the
``z3:``/``smt:`` prefix on ``rule.text``, or the ``z3_expression`` / ``smt_constraint``
metadata keys. Those are the strings the runtime gate in :mod:`acgs_lite.z3_verify`
actually enforces, so they are exactly the strings worth verifying ahead of time. This
module checks three things about them, and claims nothing else:

1. **Well-formedness.** Each policy parses under the restricted policy language
   (:mod:`acgs_lite.formal.policy_ast`). A policy that does not parse is a broken
   control — at runtime it raises at decoration time and the callable never exists.
2. **Individual satisfiability.** A policy that is UNSAT can never be satisfied by any
   input, so the rule blocks every call it applies to. That is a defect, not a strict
   policy.
3. **Joint satisfiability within a variable-sharing cluster.** Two policies can only
   contradict each other if they name a common variable: a conjunction of
   variable-disjoint formulas is satisfiable exactly when each conjunct is. Policies are
   therefore grouped into connected components over the variable-sharing graph and each
   component is checked as a conjunction. Clustering is not an optimisation — it is what
   keeps the joint verdict from asserting a contradiction between rules whose variables
   never interact. A component that is UNSAT means *any callable binding those variables
   can never execute*, which is the honest claim, narrower than "the constitution is
   contradictory".

Sorts
-----
At constitution level there are no type hints to derive sorts from, so a free variable
takes the sort its surrounding syntax requires: ``Bool`` in a proposition position,
``String`` when compared against a string literal, ``Int`` when it takes part in a
``%``, and ``Real`` otherwise. Those mirror what :mod:`acgs_lite.z3_verify` derives at
runtime from ``bool``/``str``/``int``/``float`` annotations, so a policy the runtime can
enforce is a policy this module can check.

``Real`` is the numeric default because it is the weakest: the integers are a subset of
the reals, so UNSAT over the reals implies UNSAT under any integer refinement, and a
FAIL on a ``Real`` variable is never a sort artifact. The converse does not hold — an
integer-only contradiction such as ``0 < x < 1`` is satisfiable over the reals and is
*not* reported unless the policy text forces ``Int``. This module under-reports; it does
not over-report.

Failure direction
-----------------
Anything that goes wrong — an unparseable policy, a solver that raises, a solver that
returns ``unknown``, a missing solver, a constitution with no machine-checkable content
at all — resolves to a non-``PASS`` :class:`~acgs_lite.z3_verify.VerificationStatus`
and a non-zero exit code. ``PASS`` is reachable only when at least one policy was
verified and every check answered.
"""

from __future__ import annotations

import ast
import importlib
from dataclasses import dataclass
from typing import Any

from acgs_lite.constitution import Constitution, Rule
from acgs_lite.formal.policy_ast import (
    ALLOWED_CALLS,
    PolicyParseError,
    build_policy_expression,
    parse_policy_source,
    policy_variable_names,
)
from acgs_lite.z3_verify import VerificationStatus, _iter_rule_policies

__all__ = [
    "ClusterFinding",
    "ConstitutionVerificationReport",
    "NullVerificationGate",
    "VerificationResult",
    "Z3VerificationGate",
]

_NO_WARNINGS: tuple[str, ...] = ()
_UNSET = object()

# A human-authored constitution is small. A policy that has not resolved in five
# seconds is reported as UNKNOWN, which blocks, rather than hanging a CI job.
_SOLVER_TIMEOUT_MS = 5_000

# Worst first: the overall verdict is the worst per-policy verdict. PASS is last, so a
# report is PASS only when nothing else was observed.
_STATUS_PRECEDENCE: tuple[VerificationStatus, ...] = (
    VerificationStatus.INVALID_POLICY,
    VerificationStatus.FAIL,
    VerificationStatus.ERROR,
    VerificationStatus.UNKNOWN,
    VerificationStatus.UNAVAILABLE,
    VerificationStatus.INAPPLICABLE,
    VerificationStatus.PASS,
)

# Exit codes are a public contract for CI: 0 verified, 1 defect found, 2 not verified.
# "Not verified" is never 0 — a command that verified nothing must not look like a
# command that verified everything.
_EXIT_CODES: dict[VerificationStatus, int] = {
    VerificationStatus.PASS: 0,
    VerificationStatus.FAIL: 1,
    VerificationStatus.INVALID_POLICY: 1,
    VerificationStatus.ERROR: 2,
    VerificationStatus.UNKNOWN: 2,
    VerificationStatus.UNAVAILABLE: 2,
    VerificationStatus.INAPPLICABLE: 2,
}

_TAUTOLOGY_DETAIL = "policy is a tautology: it is true for every input and constrains nothing"


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Verification outcome for one policy carried by one constitutional rule.

    ``status`` is the same vocabulary the runtime gate uses, so a reader does not have
    to learn two. Only :attr:`VerificationStatus.PASS` means "verified".
    """

    rule_id: str
    status: VerificationStatus
    detail: str = ""
    policy: str | None = None
    warnings: tuple[str, ...] = _NO_WARNINGS

    @property
    def verified(self) -> bool:
        """True only for ``PASS``. Mirrors the runtime gate's allowlist of one."""
        return self.status is VerificationStatus.PASS


@dataclass(frozen=True, slots=True)
class ClusterFinding:
    """Joint result for the policies that share at least one free variable."""

    variables: tuple[str, ...]
    rule_ids: tuple[str, ...]
    status: VerificationStatus
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ConstitutionVerificationReport:
    """Everything ``acgs eval verify-constitution`` learned, and its exit code."""

    status: VerificationStatus
    results: tuple[VerificationResult, ...] = ()
    clusters: tuple[ClusterFinding, ...] = ()
    detail: str = ""

    @property
    def exit_code(self) -> int:
        """0 verified, 1 defect found, 2 not verified."""
        return _EXIT_CODES[self.status]

    @property
    def verified(self) -> bool:
        return self.status is VerificationStatus.PASS

    @property
    def tautologies(self) -> tuple[VerificationResult, ...]:
        """Policies that are true for every input, and so enforce nothing."""
        return tuple(r for r in self.results if _TAUTOLOGY_DETAIL in r.warnings)


def _worst(statuses: list[VerificationStatus]) -> VerificationStatus:
    for candidate in _STATUS_PRECEDENCE:
        if candidate in statuses:
            return candidate
    # Reached only if a VerificationStatus is added without a precedence entry. Block.
    return VerificationStatus.ERROR


_NUMERIC_SORTS = frozenset({"Int", "Real"})


def _merge_sorts(name: str, first: str, second: str) -> str:
    """Combine two observed sorts for one variable, or refuse to guess.

    ``Int`` and ``Real`` are both numeric and reconcile to ``Int``: the only thing that
    makes a variable ``Int`` here is syntax that is meaningless over the reals (``%``),
    so the narrower sort is the one the author actually meant and the one the runtime
    will derive from an ``int`` annotation. Any other disagreement — a name used as both
    a proposition and a number, or as both a string and a number — has no reconciliation
    and is a malformed policy.
    """
    if first == second:
        return first
    if {first, second} == _NUMERIC_SORTS:
        return "Int"
    kinds = " and ".join(sorted({first, second}))
    raise PolicyParseError(
        f"variable {name!r} is used as both {kinds}; a policy variable must have one sort"
    )


def _infer_sorts(tree: ast.Expression) -> dict[str, str]:
    """Map each free variable to the z3 sort the syntax around it requires.

    ``Bool`` in a proposition position — the whole policy, an operand of ``and``/``or``/
    ``not``, or an argument of ``And``/``Or``/``Not``/``Implies``. ``String`` when the
    comparison it appears in has a string literal on the other side. ``Int`` when it
    takes part in a ``%``, which has no meaning over the reals. ``Real`` otherwise.

    These follow what :mod:`acgs_lite.z3_verify` derives at runtime from type hints
    (``bool``/``int``/``float``/``str`` → ``Bool``/``Int``/``Real``/``String``), so a
    policy the runtime can enforce is a policy this module can check. ``Real`` remains
    the numeric default because it is the weakest: a variable is only narrowed to ``Int``
    when the policy text forces it.
    """
    sorts: dict[str, str] = {}

    def assign(name: str, sort: str) -> None:
        sorts[name] = _merge_sorts(name, sorts[name], sort) if name in sorts else sort

    def comparison_sort(node: ast.Compare) -> str:
        operands = [node.left, *node.comparators]
        if any(isinstance(o, ast.Constant) and isinstance(o.value, str) for o in operands):
            return "String"
        if any(isinstance(n, ast.Mod) for o in operands for n in ast.walk(o)):
            return "Int"
        return "Real"

    def walk(node: ast.AST, sort: str) -> None:
        if isinstance(node, ast.Name):
            assign(node.id, sort)
            return
        if isinstance(node, ast.BoolOp):
            for value in node.values:
                walk(value, "Bool")
            return
        if isinstance(node, ast.UnaryOp):
            walk(node.operand, "Bool" if isinstance(node.op, ast.Not) else sort)
            return
        if isinstance(node, ast.Call):
            # _validate_call has already restricted this to bare And/Or/Not/Implies.
            for arg in node.args:
                walk(arg, "Bool")
            return
        if isinstance(node, ast.Compare):
            operand_sort = comparison_sort(node)
            walk(node.left, operand_sort)
            for comparator in node.comparators:
                walk(comparator, operand_sort)
            return
        if isinstance(node, ast.BinOp):
            operand_sort = "Int" if isinstance(node.op, ast.Mod) else sort
            walk(node.left, operand_sort)
            walk(node.right, operand_sort)
            return
        for child in ast.iter_child_nodes(node):
            walk(child, sort)

    walk(tree.body, "Bool")
    return sorts


class Z3VerificationGate:
    """Verifies the Z3 policies a constitution carries, or reports why it could not."""

    def __init__(self, *, z3_module: Any = _UNSET) -> None:
        # Deliberately typed Any rather than `Any | None`: every use is guarded by an
        # explicit None check or by `available`, and the alternative is a `# type: ignore`
        # on each solver call.
        self._z3: Any = self._load_z3() if z3_module is _UNSET else z3_module

    @staticmethod
    def _load_z3() -> Any | None:
        try:
            return importlib.import_module("z3")
        except ImportError:
            return None

    @property
    def available(self) -> bool:
        return self._z3 is not None

    def _helpers(self) -> dict[str, Any]:
        return {name: getattr(self._z3, name) for name in sorted(ALLOWED_CALLS)}

    def _declare(self, sorts: dict[str, str]) -> dict[str, Any]:
        return {name: getattr(self._z3, sort)(name) for name, sort in sorts.items()}

    def _solver(self) -> Any:
        solver = self._z3.Solver()
        solver.set("timeout", _SOLVER_TIMEOUT_MS)
        return solver

    def check(self, rule: Rule, constitution: Constitution) -> VerificationResult:
        """Verify the policies carried by one rule.

        Returns ``INAPPLICABLE`` when the rule carries no machine-checkable policy —
        the common case, and never ``PASS``, because nothing was verified. When a rule
        carries several policies the worst verdict wins.
        """
        del constitution  # a single rule is checked in isolation; see verify_constitution
        policies = [policy for rule_id, policy in _iter_rule_policies(_SingleRule(rule))]
        if not policies:
            return VerificationResult(
                rule_id=rule.id,
                status=VerificationStatus.INAPPLICABLE,
                detail="rule carries no z3:/smt: policy; nothing to verify",
            )
        results = [self._check_policy(rule.id, policy) for policy in policies]
        if len(results) == 1:
            return results[0]
        worst = _worst([result.status for result in results])
        for result in results:
            if result.status is worst:
                return result
        return results[0]  # pragma: no cover - _worst always matches one result

    def verify_constitution(self, constitution: Constitution) -> ConstitutionVerificationReport:
        """Verify every policy in *constitution*, plus each variable-sharing cluster."""
        pairs = _iter_rule_policies(constitution)

        if not pairs:
            return ConstitutionVerificationReport(
                status=VerificationStatus.INAPPLICABLE,
                detail=(
                    "constitution carries no z3:/smt: policies; there is no "
                    "machine-checkable content and nothing was verified"
                ),
            )

        if self._z3 is None:
            return ConstitutionVerificationReport(
                status=VerificationStatus.UNAVAILABLE,
                results=tuple(
                    VerificationResult(
                        rule_id=rule_id,
                        status=VerificationStatus.UNAVAILABLE,
                        detail="z3-solver is not installed",
                        policy=policy,
                    )
                    for rule_id, policy in pairs
                ),
                detail="z3-solver is not installed; install the 'z3' extra to verify",
            )

        results = [self._check_policy(rule_id, policy) for rule_id, policy in pairs]
        clusters = self._check_clusters(pairs)
        status = _worst(
            [result.status for result in results] + [cluster.status for cluster in clusters]
        )
        return ConstitutionVerificationReport(
            status=status,
            results=tuple(results),
            clusters=tuple(clusters),
        )

    def _check_policy(self, rule_id: str, policy: str) -> VerificationResult:
        if self._z3 is None:
            return VerificationResult(
                rule_id=rule_id,
                status=VerificationStatus.UNAVAILABLE,
                detail="z3-solver is not installed",
                policy=policy,
            )
        try:
            tree = parse_policy_source(policy)
            sorts = _infer_sorts(tree)
        except PolicyParseError as exc:
            return VerificationResult(
                rule_id=rule_id,
                status=VerificationStatus.INVALID_POLICY,
                detail=str(exc),
                policy=policy,
            )

        try:
            expression = build_policy_expression(tree, self._declare(sorts), self._helpers())
            solver = self._solver()
            solver.add(expression)
            outcome = solver.check()
        except Exception as exc:  # noqa: BLE001 - a broken solver must block, not pass
            return VerificationResult(
                rule_id=rule_id,
                status=VerificationStatus.ERROR,
                detail=f"{type(exc).__name__}: {exc}",
                policy=policy,
            )

        if outcome == self._z3.unsat:
            return VerificationResult(
                rule_id=rule_id,
                status=VerificationStatus.FAIL,
                detail=(
                    "policy is unsatisfiable: no input satisfies it, so this rule "
                    "blocks every call it applies to"
                ),
                policy=policy,
            )
        if outcome != self._z3.sat:
            return VerificationResult(
                rule_id=rule_id,
                status=VerificationStatus.UNKNOWN,
                detail="solver returned unknown; the policy was not verified",
                policy=policy,
            )

        if self._is_tautology(expression):
            # Satisfiable but valid: no input can violate it. That is the same defect
            # class this module replaced — a control that reports clean by construction —
            # so it is a finding, not a footnote on a pass.
            return VerificationResult(
                rule_id=rule_id,
                status=VerificationStatus.FAIL,
                detail=_TAUTOLOGY_DETAIL,
                policy=policy,
                warnings=(_TAUTOLOGY_DETAIL,),
            )
        return VerificationResult(
            rule_id=rule_id,
            status=VerificationStatus.PASS,
            detail="satisfiable",
            policy=policy,
        )

    def _is_tautology(self, expression: Any) -> bool:
        """True when no input can violate the policy. Same defect class as old F1."""
        try:
            solver = self._solver()
            solver.add(self._z3.Not(expression))
            return bool(solver.check() == self._z3.unsat)
        except Exception:  # noqa: BLE001 - undecided is not a finding; the SAT verdict stands
            return False

    def _check_clusters(self, pairs: list[tuple[str, str]]) -> list[ClusterFinding]:
        """Joint-check each connected component of the variable-sharing graph.

        Policies that share no variable cannot contradict each other — a conjunction of
        variable-disjoint formulas is satisfiable iff each conjunct is — and at runtime
        they generally apply to different callables. Clustering keeps the joint verdict
        from asserting a contradiction between rules that can never meet.
        """
        parsed: list[tuple[str, str, ast.Expression, dict[str, str]]] = []
        for rule_id, policy in pairs:
            try:
                tree = parse_policy_source(policy)
                parsed.append((rule_id, policy, tree, _infer_sorts(tree)))
            except PolicyParseError:
                continue  # already reported per-policy as INVALID_POLICY

        parent: dict[str, str] = {}

        def find(item: str) -> str:
            parent.setdefault(item, item)
            while parent[item] != item:
                parent[item] = parent[parent[item]]
                item = parent[item]
            return item

        def union(left: str, right: str) -> None:
            parent[find(left)] = find(right)

        keys = [f"policy:{index}" for index, _ in enumerate(parsed)]
        for key, (_rule_id, _policy, tree, _sorts) in zip(keys, parsed, strict=True):
            find(key)
            for name in policy_variable_names(tree):
                union(key, f"var:{name}")

        groups: dict[str, list[int]] = {}
        for index, key in enumerate(keys):
            groups.setdefault(find(key), []).append(index)

        findings: list[ClusterFinding] = []
        for members in groups.values():
            if len(members) < 2:
                continue  # a lone policy was already checked individually
            findings.append(self._check_cluster([parsed[index] for index in members]))
        return findings

    def _check_cluster(
        self, members: list[tuple[str, str, ast.Expression, dict[str, str]]]
    ) -> ClusterFinding:
        sorts: dict[str, str] = {}
        rule_ids = tuple(dict.fromkeys(rule_id for rule_id, _p, _t, _s in members))
        for _rule_id, _policy, _tree, member_sorts in members:
            for name, sort in member_sorts.items():
                try:
                    sorts[name] = _merge_sorts(name, sorts[name], sort) if name in sorts else sort
                except PolicyParseError as exc:
                    return ClusterFinding(
                        variables=tuple(sorted(sorts)),
                        rule_ids=rule_ids,
                        status=VerificationStatus.INVALID_POLICY,
                        detail=f"rules disagree on a variable's sort: {exc}",
                    )
        variables = tuple(sorted(sorts))
        try:
            declared = self._declare(sorts)
            helpers = self._helpers()
            solver = self._solver()
            for _rule_id, _policy, tree, _member_sorts in members:
                solver.add(build_policy_expression(tree, declared, helpers))
            outcome = solver.check()
        except Exception as exc:  # noqa: BLE001 - a broken solver must block, not pass
            return ClusterFinding(
                variables=variables,
                rule_ids=rule_ids,
                status=VerificationStatus.ERROR,
                detail=f"{type(exc).__name__}: {exc}",
            )

        if outcome == self._z3.unsat:
            return ClusterFinding(
                variables=variables,
                rule_ids=rule_ids,
                status=VerificationStatus.FAIL,
                detail=(
                    f"policies of {', '.join(rule_ids)} cannot hold together: any callable "
                    f"binding {', '.join(variables)} can never execute"
                ),
            )
        if outcome != self._z3.sat:
            return ClusterFinding(
                variables=variables,
                rule_ids=rule_ids,
                status=VerificationStatus.UNKNOWN,
                detail="solver returned unknown; joint consistency was not verified",
            )
        return ClusterFinding(
            variables=variables,
            rule_ids=rule_ids,
            status=VerificationStatus.PASS,
            detail="jointly satisfiable",
        )


class _SingleRule:
    """Adapter so :func:`_iter_rule_policies` can be pointed at one rule."""

    __slots__ = ("rules",)

    def __init__(self, rule: Rule) -> None:
        self.rules = [rule]


class NullVerificationGate:
    """A gate that performs no verification, and says so.

    It exists for callers that want the gate interface without the solver dependency.
    It reports ``UNAVAILABLE``, never ``PASS``: "no verification was performed" and
    "verification succeeded" must not be the same answer.
    """

    def check(self, rule: Rule, constitution: Constitution) -> VerificationResult:
        del constitution
        return VerificationResult(
            rule_id=rule.id,
            status=VerificationStatus.UNAVAILABLE,
            detail="NullVerificationGate performs no verification",
        )

    def verify_constitution(self, constitution: Constitution) -> ConstitutionVerificationReport:
        del constitution
        return ConstitutionVerificationReport(
            status=VerificationStatus.UNAVAILABLE,
            detail="NullVerificationGate performs no verification",
        )
