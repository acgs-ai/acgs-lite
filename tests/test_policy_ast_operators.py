"""Operator and limit coverage for the z3 policy AST builder.

``policy_ast`` is the only door between a policy string and the solver, so its
boundaries are security-relevant: an expression that is too large must be refused,
and a node the builder cannot evaluate must raise ``PolicyParseError`` rather than
fall back to a generic visitor. These tests use plain-Python helpers in place of z3,
so the evaluated value is exact and no solver is needed.
"""

from __future__ import annotations

import ast
from typing import Any

import pytest

from acgs_lite.formal.policy_ast import (
    PolicyNameError,
    PolicyParseError,
    build_policy_expression,
    parse_policy_source,
)

pytestmark = pytest.mark.unit

HELPERS: dict[str, Any] = {
    "And": lambda *a: all(a),
    "Or": lambda *a: any(a),
    "Not": lambda a: not a,
    "Implies": lambda a, b: (not a) or b,
}
VARS: dict[str, Any] = {"x": 6, "y": 3, "p": True, "q": False}


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("not q", True),
        ("-x", -6),
        ("+x", 6),
        ("p and q", False),
        ("p or q", True),
        ("x + y", 9),
        ("x - y", 3),
        ("x * y", 18),
        ("x / y", 2.0),
        ("x <= 6", True),
        ("x >= 7", False),
        ("x != y", True),
        ("not (y <= x) or -x != +y", True),
    ],
)
def test_operator_evaluates_to_exact_value(source: str, expected: Any) -> None:
    result = build_policy_expression(parse_policy_source(source), VARS, HELPERS)

    assert result == expected
    assert type(result) is type(expected)


def test_node_count_limit_refuses_oversized_policy() -> None:
    oversized = "And(" + ",".join(["a"] * 600) + ")"
    assert len(oversized) < 4096  # the node limit, not the character limit, must fire

    with pytest.raises(PolicyParseError, match="more than 512 nodes"):
        parse_policy_source(oversized)


def test_policy_below_node_limit_still_parses() -> None:
    tree = parse_policy_source("And(" + ",".join(["a"] * 100) + ")")

    assert isinstance(tree, ast.Expression)


def test_builder_refuses_unhandled_node_without_generic_fallback() -> None:
    """An unhandled node raises even when ``_validate`` never ran on the tree.

    The builder is an explicit dispatch so that it cannot silently fall back to
    ``generic_visit``; a hand-built tree reaches it without the allowlist.
    """
    tree = ast.Expression(body=ast.List(elts=[], ctx=ast.Load()))

    with pytest.raises(PolicyParseError, match="List cannot be evaluated") as excinfo:
        build_policy_expression(tree, {}, {})

    assert type(excinfo.value) is PolicyParseError
    assert not isinstance(excinfo.value, PolicyNameError)
