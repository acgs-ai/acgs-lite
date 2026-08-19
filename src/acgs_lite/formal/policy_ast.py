"""Restricted parser for Z3 policy expressions carried in constitution rules.

Policy strings reach this module from ``rule.text`` (``z3:`` / ``smt:`` prefix) and
from the ``z3_expression`` / ``smt_constraint`` rule metadata keys. They used to be
handed to :func:`eval` with ``{"__builtins__": {}}`` as globals, on the stated
assumption that emptying builtins stopped a rule from reaching ``__import__`` or
``open``.

That assumption is false. Emptying ``__builtins__`` blocks *name* lookup; it does
not block *attribute* lookup, and the eval locals necessarily contain live z3
helper functions. Every Python function carries ``__globals__``, so
``And.__globals__["__builtins__"]`` is a fully populated builtins mapping and the
rule author has arbitrary code execution inside the governed process.

A denylist over ``eval`` globals cannot be made safe, because the attack surface is
every attribute of every object the expression can name. This module inverts that:
the policy is parsed to an AST and every node is checked against an explicit
allowlist before anything is evaluated. Nodes that are not on the list are rejected
by type, so a construct nobody anticipated fails closed rather than passing through.

The accepted language is deliberately small — the four z3 helpers the previous eval
context exposed, comparisons, boolean connectives, arithmetic, and literals:

    amount < 500
    And(amount > 0, amount < 500)
    Implies(is_admin, Not(destructive))
    quantity * price <= 10000

Notably absent, and rejected by construction: attribute access, subscripting,
lambdas, comprehensions, f-strings, walrus assignments, ``await``, starred
arguments, keyword arguments, and calls to anything but the four helpers.
"""

from __future__ import annotations

import ast
from collections.abc import Mapping
from typing import Any

__all__ = [
    "ALLOWED_CALLS",
    "PolicyNameError",
    "PolicyParseError",
    "build_policy_expression",
    "parse_policy_source",
    "policy_variable_names",
]

# The four helpers the previous eval context exposed. Kept identical so that
# policies which were valid before remain valid, minus the escape.
ALLOWED_CALLS: frozenset[str] = frozenset({"And", "Or", "Not", "Implies"})

# Cheap structural bounds. A constitution rule is human-authored; these are far
# above any legitimate policy and stop a pathological string from costing real
# parse/solve time.
_MAX_SOURCE_CHARS = 4_096
_MAX_NODES = 512
_MAX_DEPTH = 32

_ALLOWED_NODES: tuple[type[ast.AST], ...] = (
    ast.Expression,
    ast.BoolOp,
    ast.And,
    ast.Or,
    ast.UnaryOp,
    ast.Not,
    ast.USub,
    ast.UAdd,
    ast.BinOp,
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.Div,
    ast.Mod,
    ast.Compare,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
    ast.Call,
    ast.Name,
    ast.Load,
    ast.Constant,
)

_ALLOWED_CONSTANTS = (bool, int, float, str)


class PolicyParseError(ValueError):
    """A policy string is not valid in the restricted policy language.

    Raised for syntax errors and for any construct outside the allowlist. This is
    a broken control, not a policy violation: the caller must fail closed rather
    than treating the policy as absent.
    """


class PolicyNameError(PolicyParseError):
    """A policy is well-formed but names something the caller did not supply.

    Separated from :class:`PolicyParseError` because the two need different
    handling. A malformed policy is broken everywhere. A policy naming variables
    this particular callable does not have may simply be inapplicable to it — see
    ``z3_verify`` for the resolution rule.
    """


def parse_policy_source(source: str) -> ast.Expression:
    """Parse *source* into an AST containing only allowlisted node types.

    Performs no name resolution and builds no z3 objects, so this is the check to
    run when a policy should be validated for well-formedness before it is used —
    e.g. at decoration time, so a typo in a constitution fails immediately instead
    of silently disabling enforcement at the first call.

    :raises PolicyParseError: on invalid syntax or any disallowed construct.
    """
    if not isinstance(source, str):
        raise PolicyParseError(f"policy must be a string, got {type(source).__name__}")
    stripped = source.strip()
    if not stripped:
        raise PolicyParseError("policy is empty")
    if len(stripped) > _MAX_SOURCE_CHARS:
        raise PolicyParseError(
            f"policy is {len(stripped)} characters, limit is {_MAX_SOURCE_CHARS}"
        )

    try:
        tree = ast.parse(stripped, mode="eval")
    except SyntaxError as exc:
        raise PolicyParseError(f"policy is not a valid expression: {exc.msg}") from exc

    _validate(tree)
    return tree


def policy_variable_names(tree: ast.Expression) -> set[str]:
    """Every free variable named by an already-validated policy AST.

    Call names (``And`` and friends) are excluded — only operands are returned.
    """
    called: set[str] = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    return {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} - called


def build_policy_expression(
    tree: ast.Expression,
    variables: Mapping[str, Any],
    helpers: Mapping[str, Any],
) -> Any:
    """Evaluate a validated policy AST into a z3 expression.

    Names resolve against *variables* only; call targets against *helpers* only.
    Neither mapping is consulted for anything else, and no Python object reachable
    from either is ever traversed by attribute, so there is no path from a policy
    string back into the interpreter.

    :raises PolicyNameError: if the policy names a variable that is not supplied.
    """
    return _Builder(variables, helpers).visit(tree.body)


def _validate(tree: ast.Expression) -> None:
    """Reject any node type outside the allowlist, plus call/constant specifics."""
    for node_count, node in enumerate(ast.walk(tree), start=1):
        if node_count > _MAX_NODES:
            raise PolicyParseError(f"policy has more than {_MAX_NODES} nodes")
        if not isinstance(node, _ALLOWED_NODES):
            raise PolicyParseError(f"{type(node).__name__} is not allowed in a policy expression")
        if isinstance(node, ast.Name) and node.id.startswith("__"):
            # A bare dunder name would fail resolution anyway, since names only
            # resolve against the caller's variable mapping. Refused here as well
            # so the guarantee does not depend on that mapping never containing a
            # dunder key.
            raise PolicyParseError(f"name {node.id!r} is not allowed in a policy expression")
        if isinstance(node, ast.Constant) and not isinstance(node.value, _ALLOWED_CONSTANTS):
            # `None`, `...`, and bytes are all ast.Constant but are not values the
            # policy language has any use for.
            raise PolicyParseError(f"constant of type {type(node.value).__name__} is not allowed")
        if isinstance(node, ast.Call):
            _validate_call(node)
    _check_depth(tree)


def _validate_call(node: ast.Call) -> None:
    """Only bare calls to the four allowlisted helpers, positional args only."""
    if not isinstance(node.func, ast.Name):
        # Blocks `obj.method(...)` before the Attribute check would even fire,
        # and gives a message that names the actual problem.
        raise PolicyParseError("only direct calls to And/Or/Not/Implies are allowed")
    if node.func.id not in ALLOWED_CALLS:
        raise PolicyParseError(
            f"call to {node.func.id!r} is not allowed; "
            f"permitted: {', '.join(sorted(ALLOWED_CALLS))}"
        )
    if node.keywords:
        raise PolicyParseError(f"{node.func.id} does not accept keyword arguments")
    for arg in node.args:
        if isinstance(arg, ast.Starred):
            raise PolicyParseError(f"{node.func.id} does not accept starred arguments")


def _check_depth(tree: ast.Expression) -> None:
    """Bound nesting so a deeply nested policy cannot exhaust the stack."""

    def depth(node: ast.AST, level: int) -> int:
        if level > _MAX_DEPTH:
            raise PolicyParseError(f"policy nests deeper than {_MAX_DEPTH} levels")
        children = list(ast.iter_child_nodes(node))
        return level if not children else max(depth(child, level + 1) for child in children)

    depth(tree, 0)


class _Builder:
    """Turns a validated AST into z3 objects.

    Written as an explicit dispatch rather than ``ast.NodeVisitor`` so that an
    unhandled node type raises instead of falling back to ``generic_visit``.
    """

    def __init__(self, variables: Mapping[str, Any], helpers: Mapping[str, Any]) -> None:
        self._variables = variables
        self._helpers = helpers

    def visit(self, node: ast.AST) -> Any:
        handler = getattr(self, f"_on_{type(node).__name__}", None)
        if handler is None:
            raise PolicyParseError(f"{type(node).__name__} cannot be evaluated")
        return handler(node)

    def _on_Name(self, node: ast.Name) -> Any:
        try:
            return self._variables[node.id]
        except KeyError:
            raise PolicyNameError(f"policy names unknown variable {node.id!r}") from None

    def _on_Constant(self, node: ast.Constant) -> Any:
        return node.value

    def _on_UnaryOp(self, node: ast.UnaryOp) -> Any:
        operand = self.visit(node.operand)
        if isinstance(node.op, ast.Not):
            return self._helpers["Not"](operand)
        if isinstance(node.op, ast.USub):
            return -operand
        return +operand

    def _on_BoolOp(self, node: ast.BoolOp) -> Any:
        values = [self.visit(v) for v in node.values]
        combine = self._helpers["And" if isinstance(node.op, ast.And) else "Or"]
        return combine(*values)

    def _on_BinOp(self, node: ast.BinOp) -> Any:
        left, right = self.visit(node.left), self.visit(node.right)
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Div):
            return left / right
        return left % right

    def _on_Compare(self, node: ast.Compare) -> Any:
        # `0 < x < 10` is a chained comparison; Python's semantics conjoin the
        # links, and z3 has no chained form, so build the conjunction explicitly.
        left = self.visit(node.left)
        terms = []
        for op, comparator in zip(node.ops, node.comparators, strict=True):
            right = self.visit(comparator)
            terms.append(self._compare(op, left, right))
            left = right
        return terms[0] if len(terms) == 1 else self._helpers["And"](*terms)

    @staticmethod
    def _compare(op: ast.cmpop, left: Any, right: Any) -> Any:
        if isinstance(op, ast.Lt):
            return left < right
        if isinstance(op, ast.LtE):
            return left <= right
        if isinstance(op, ast.Gt):
            return left > right
        if isinstance(op, ast.GtE):
            return left >= right
        if isinstance(op, ast.Eq):
            return left == right
        return left != right

    def _on_Call(self, node: ast.Call) -> Any:
        # _validate_call has already established func is a Name in ALLOWED_CALLS.
        func = self._helpers[node.func.id]  # type: ignore[attr-defined]
        return func(*[self.visit(arg) for arg in node.args])
