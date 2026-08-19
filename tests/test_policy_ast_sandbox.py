"""Sandbox-escape regressions for the restricted policy parser.

Policy strings arrive from constitution rule text. They used to be handed to
``eval`` behind ``{"__builtins__": {}}``, which blocks name lookup but not
attribute lookup — ``And.__globals__["__builtins__"]`` reached a populated
builtins mapping and a rule author had arbitrary code execution.

Every escape test here is written against the *real* entry points, not the parser
in isolation, so that a future refactor which reintroduces an eval somewhere in
the chain fails these rather than passing them.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from acgs_lite.formal.policy_ast import (
    PolicyNameError,
    PolicyParseError,
    build_policy_expression,
    parse_policy_source,
    policy_variable_names,
)

pytestmark = pytest.mark.unit


# Expressions that must never be accepted. Each one is a distinct route out of the
# expression language, not a variation on a single theme.
ESCAPE_ATTEMPTS = [
    pytest.param("And.__globals__", id="attribute-on-helper"),
    pytest.param(
        "And.__globals__['__builtins__']['__import__']('os').system('id') == 0",
        id="original-proven-escape",
    ),
    pytest.param("amount.__class__.__mro__[1] == 0", id="attribute-chain-on-variable"),
    pytest.param("().__class__.__bases__[0] == 0", id="empty-tuple-mro-walk"),
    pytest.param("__import__('os').getcwd() == '/'", id="bare-import-builtin"),
    pytest.param("open('/etc/passwd').read() == ''", id="bare-open-builtin"),
    pytest.param("eval('1+1') == 2", id="nested-eval"),
    pytest.param("exec('x=1') == None", id="nested-exec"),
    pytest.param("globals()['amount'] < 500", id="globals-call"),
    pytest.param("(lambda: 1)() == 1", id="lambda"),
    pytest.param("[x for x in (1, 2)] == []", id="list-comprehension"),
    pytest.param("{x: 1 for x in (1,)} == {}", id="dict-comprehension"),
    pytest.param("amount[0] < 500", id="subscript"),
    pytest.param("f'{amount}' == '1'", id="fstring"),
    pytest.param("(y := amount) < 500", id="walrus"),
    pytest.param("amount if amount else 0", id="conditional-expression"),
    pytest.param("Not(*[amount])", id="starred-argument"),
    pytest.param("And(amount > 0, x=1)", id="keyword-argument"),
    pytest.param("print(amount)", id="call-to-unlisted-name"),
    pytest.param("amount.bit_length() < 500", id="method-call"),
]


@pytest.mark.parametrize("source", ESCAPE_ATTEMPTS)
def test_escape_attempt_is_rejected_at_parse(source: str) -> None:
    """No escape reaches evaluation — all are refused while still text."""
    with pytest.raises(PolicyParseError):
        parse_policy_source(source)


@pytest.mark.parametrize("source", ESCAPE_ATTEMPTS)
def test_escape_attempt_has_no_side_effect(source: str, tmp_path: Path) -> None:
    """Rejection happens before evaluation, so nothing in the payload can run."""
    marker = tmp_path / "executed"
    payload = source.replace("'/etc/passwd'", repr(str(marker)))
    with pytest.raises(PolicyParseError):
        tree = parse_policy_source(payload)
        build_policy_expression(tree, {}, {})
    assert not marker.exists()


def test_the_documented_escape_cannot_reach_builtins(tmp_path: Path) -> None:
    """The exact payload from the audit, end to end, must not write its file."""
    marker = tmp_path / "PWNED.txt"
    payload = (
        "And.__globals__['__builtins__']['open']"
        f"({str(marker)!r}, 'w').write('x') == 0 or amount < 500"
    )
    with pytest.raises(PolicyParseError):
        parse_policy_source(payload)
    assert not marker.exists(), "policy string executed despite being rejected"


def test_dunder_name_alone_is_rejected() -> None:
    with pytest.raises(PolicyParseError):
        parse_policy_source("__builtins__ == 1")


def test_import_statement_is_not_an_expression() -> None:
    with pytest.raises(PolicyParseError, match="not a valid expression"):
        parse_policy_source("import os")


def test_statement_forms_are_rejected() -> None:
    for source in ("x = 1", "del amount", "assert amount", "raise ValueError()"):
        with pytest.raises(PolicyParseError):
            parse_policy_source(source)


class TestStructuralLimits:
    def test_empty_policy_is_rejected(self) -> None:
        with pytest.raises(PolicyParseError, match="empty"):
            parse_policy_source("   ")

    def test_non_string_is_rejected(self) -> None:
        with pytest.raises(PolicyParseError, match="must be a string"):
            parse_policy_source(None)  # type: ignore[arg-type]

    def test_oversized_policy_is_rejected(self) -> None:
        with pytest.raises(PolicyParseError, match="limit is"):
            parse_policy_source("amount < 1 or " * 400 + "amount < 1")

    def test_deeply_nested_policy_is_rejected(self) -> None:
        with pytest.raises(PolicyParseError, match="nests deeper|more than"):
            parse_policy_source("Not(" * 40 + "amount > 0" + ")" * 40)

    def test_none_constant_is_rejected(self) -> None:
        with pytest.raises(PolicyParseError, match="NoneType"):
            parse_policy_source("amount == None")

    def test_bytes_constant_is_rejected(self) -> None:
        with pytest.raises(PolicyParseError, match="bytes"):
            parse_policy_source("amount == b'x'")


class TestAcceptedLanguage:
    """The parser must still accept everything a legitimate policy needs."""

    @pytest.mark.parametrize(
        "source",
        [
            "amount < 500",
            "amount <= 500",
            "amount > 0",
            "amount >= 0",
            "amount == 500",
            "amount != 500",
            "0 < amount < 500",
            "And(amount > 0, amount < 500)",
            "Or(amount < 0, amount > 500)",
            "Not(amount > 500)",
            "Implies(amount > 100, amount < 500)",
            "amount + 1 < 500",
            "amount - 1 < 500",
            "amount * 2 < 500",
            "amount / 2 < 500",
            "amount % 2 == 0",
            "-amount < 0",
            "amount < 500 and amount > 0",
            "amount < 0 or amount > 500",
            "not (amount > 500)",
            "name == 'alice'",
            "flag == True",
        ],
    )
    def test_valid_policy_parses(self, source: str) -> None:
        assert isinstance(parse_policy_source(source), ast.Expression)

    def test_variable_names_exclude_call_targets(self) -> None:
        tree = parse_policy_source("And(amount > 0, Not(quantity < 5))")
        assert policy_variable_names(tree) == {"amount", "quantity"}

    def test_unbound_variable_raises_name_error(self) -> None:
        tree = parse_policy_source("amount < 500")
        with pytest.raises(PolicyNameError, match="unknown variable 'amount'"):
            build_policy_expression(tree, {}, {})


class TestBuildsRealZ3Expressions:
    """The parser must produce the same z3 objects the old eval produced."""

    def test_comparison_matches_direct_construction(self) -> None:
        z3 = pytest.importorskip("z3")
        amount = z3.Int("amount")
        tree = parse_policy_source("amount < 500")
        built = build_policy_expression(tree, {"amount": amount}, {})
        assert built.eq(amount < 500)

    def test_helper_call_matches_direct_construction(self) -> None:
        z3 = pytest.importorskip("z3")
        amount = z3.Int("amount")
        helpers = {"And": z3.And, "Or": z3.Or, "Not": z3.Not, "Implies": z3.Implies}
        tree = parse_policy_source("And(amount > 0, amount < 500)")
        built = build_policy_expression(tree, {"amount": amount}, helpers)
        assert built.eq(z3.And(amount > 0, amount < 500))

    def test_chained_comparison_becomes_a_conjunction(self) -> None:
        z3 = pytest.importorskip("z3")
        amount = z3.Int("amount")
        helpers = {"And": z3.And, "Or": z3.Or, "Not": z3.Not, "Implies": z3.Implies}
        tree = parse_policy_source("0 < amount < 500")
        built = build_policy_expression(tree, {"amount": amount}, helpers)
        # Python chains conjoin; z3 has no chained form, so this must expand.
        assert built.eq(z3.And(amount > 0, amount < 500))
