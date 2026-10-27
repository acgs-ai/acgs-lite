"""Dispatcher-level fail-closed payload enforcement for ``GovernedCallable``.

Every test calls the decorated function (or ``issue_grant``) and asserts the
wrapped side effect never ran on deny. Covers oversize payloads, scalars and
opaque arguments, and discarded engine results under ``strict=False``.
"""

from __future__ import annotations

import asyncio
import enum
from decimal import Decimal
from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.constitution.rule import Rule, ViolationAction
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import (
    AuthorizationProfile,
    DecisionReceipt,
    ExecutionBoundary,
    LegitimacyInvariantError,
)
from acgs_lite.legitimacy.invocation import ArgumentNotDigestible
from acgs_lite.legitimacy.ledger import AttemptStatus
from acgs_lite.serialization import (
    GovernancePayloadError,
    governance_payloads_for_enforcement,
    serialize_for_governance,
)

LIMIT = 10_000


def _constitution() -> Constitution:
    return Constitution.from_rules(
        [
            Rule(id="BAD-WORD", text="no forbiddenword", keywords=["forbiddenword"]),
            Rule(id="NUM-666", text="no 666", keywords=["666"]),
            Rule(id="BOOL-TRUE", text="no true flag", keywords=["true"]),
            Rule(id="FLOAT-PI", text="no 3.25", keywords=["3.25"]),
            Rule(
                id="WARN-PING",
                text="warn on pingword",
                keywords=["pingword"],
                workflow_action=ViolationAction.WARN,
            ),
        ]
    )


def _receipt(method: str) -> DecisionReceipt:
    return DecisionReceipt.create(
        request_id="req-compat",
        goal="compat call",
        proposed_method=method,
        decision_type="ALLOW",
        authority_basis="role:test",
        matched_constraints=("test-constraint",),
        policy_version="policy-v1",
        execution_boundary=ExecutionBoundary(
            allowed_method=method,
            allowed_scope=None,
            allowed_subjects=(),
            expires_at=None,
            single_use=False,
        ),
    )


def _compat(**options: Any) -> GovernedCallable:
    return GovernedCallable(_constitution(), **options)


def _production(**options: Any) -> GovernedCallable:
    return GovernedCallable(
        _constitution(), authorization_profile=AuthorizationProfile.PRODUCTION, **options
    )


class Opaque:
    __slots__ = ()


# --- 1a: oversize payloads deny, never truncate ---------------------------------


def test_oversize_input_denied_in_compatibility_profile() -> None:
    calls: list[str] = []

    @_compat()
    def f(text: str) -> str:
        calls.append(text)
        return "ok"

    long_text = "a" * LIMIT + " forbiddenword"
    with pytest.raises(GovernancePayloadError) as excinfo:
        f(long_text, decision_receipt=_receipt("f"))
    assert excinfo.value.rule_id == "GOVERNANCE-PAYLOAD-OVERSIZE"
    assert str(LIMIT) in str(excinfo.value)
    assert calls == []


def test_oversize_benign_input_still_denied() -> None:
    calls: list[str] = []

    @_compat()
    def f(text: str) -> str:
        calls.append(text)
        return "ok"

    with pytest.raises(GovernancePayloadError):
        f("a" * (LIMIT + 1), decision_receipt=_receipt("f"))
    assert calls == []


def test_oversize_input_denied_at_issue_in_production() -> None:
    calls: list[str] = []

    @_production()
    def f(text: str) -> str:
        calls.append(text)
        return "ok"

    with pytest.raises(GovernancePayloadError):
        f.issue_grant("a" * LIMIT + " forbiddenword")
    assert calls == []


def test_oversize_keyword_payload_denied() -> None:
    calls: list[str] = []

    @_compat()
    def f(*, text: str) -> str:
        calls.append(text)
        return "ok"

    with pytest.raises(GovernancePayloadError):
        f(text="a" * LIMIT, decision_receipt=_receipt("f"))
    assert calls == []


def test_payload_at_exact_limit_is_evaluated_by_rule() -> None:
    calls: list[str] = []

    @_compat()
    def f(text: str) -> str:
        calls.append(text)
        return "ok"

    marker = "forbiddenword"
    exact = "a" * (LIMIT - len(marker)) + marker
    assert len(exact) == LIMIT
    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f(exact, decision_receipt=_receipt("f"))
    assert not isinstance(excinfo.value, GovernancePayloadError)
    assert excinfo.value.rule_id == "BAD-WORD"
    assert calls == []


def test_oversize_output_denied_after_call_in_production() -> None:
    calls: list[str] = []
    guard = _production()

    @guard
    def f(text: str) -> str:
        calls.append(text)
        return "b" * (LIMIT + 1)

    grant = f.issue_grant("hello")
    with pytest.raises(GovernancePayloadError):
        f("hello", execution_grant=grant, execution_attempt_id="big-out")
    assert calls == ["hello"]
    assert guard._ledger._attempts["big-out"].status is AttemptStatus.PARTIAL


def test_oversize_output_denied_in_compatibility_profile() -> None:
    calls: list[str] = []

    @_compat()
    def f(text: str) -> str:
        calls.append(text)
        return "b" * (LIMIT + 1)

    with pytest.raises(GovernancePayloadError):
        f("hello", decision_receipt=_receipt("f"))
    assert calls == ["hello"]


def test_async_oversize_input_and_output_denied() -> None:
    calls: list[str] = []

    @_compat()
    async def f(text: str) -> str:
        calls.append(text)
        return "b" * (LIMIT + 1) if text == "big" else "ok"

    with pytest.raises(GovernancePayloadError):
        asyncio.run(f("a" * (LIMIT + 1), decision_receipt=_receipt("f")))
    assert calls == []
    with pytest.raises(GovernancePayloadError):
        asyncio.run(f("big", decision_receipt=_receipt("f")))
    assert calls == ["big"]


def test_preview_serializer_still_truncates() -> None:
    preview = serialize_for_governance("x" * 100, max_chars=40)
    assert len(preview) == 40
    assert preview.endswith("… [truncated]")


# --- 1b: scalars evaluated, opaque values denied --------------------------------


@pytest.mark.parametrize(
    ("value", "rule_id"),
    [(666, "NUM-666"), (True, "BOOL-TRUE"), (3.25, "FLOAT-PI"), (b"666", "NUM-666")],
)
def test_scalar_positional_arguments_are_evaluated(value: object, rule_id: str) -> None:
    calls: list[object] = []

    @_compat()
    def f(x: object) -> str:
        calls.append(x)
        return "ok"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f(value, decision_receipt=_receipt("f"))
    assert excinfo.value.rule_id == rule_id
    assert calls == []


def test_decimal_and_enum_positional_arguments_are_evaluated() -> None:
    class Code(enum.Enum):
        BAD = "forbiddenword"

    calls: list[object] = []

    @_compat()
    def f(x: object) -> str:
        calls.append(x)
        return "ok"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f(Decimal("666"), decision_receipt=_receipt("f"))
    assert excinfo.value.rule_id == "NUM-666"
    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f(Code.BAD, decision_receipt=_receipt("f"))
    assert excinfo.value.rule_id == "BAD-WORD"
    assert calls == []


def test_opaque_positional_argument_denied_in_compatibility_profile() -> None:
    calls: list[object] = []

    @_compat()
    def f(x: object) -> str:
        calls.append(x)
        return "ok"

    with pytest.raises(GovernancePayloadError) as excinfo:
        f.issue_grant(Opaque())
    assert excinfo.value.rule_id == "GOVERNANCE-PAYLOAD-UNEVALUABLE"
    assert "Opaque" in str(excinfo.value)
    # Execute path: the invocation binder already refuses the opaque value.
    with pytest.raises((GovernancePayloadError, ArgumentNotDigestible)):
        f(Opaque(), decision_receipt=_receipt("f"))
    assert calls == []


def test_opaque_keyword_argument_denied() -> None:
    calls: list[object] = []

    @_compat()
    def f(*, x: object) -> str:
        calls.append(x)
        return "ok"

    with pytest.raises(GovernancePayloadError) as excinfo:
        f.issue_grant(x=Opaque())
    assert excinfo.value.rule_id == "GOVERNANCE-PAYLOAD-UNEVALUABLE"
    with pytest.raises((GovernancePayloadError, ArgumentNotDigestible)):
        f(x=Opaque(), decision_receipt=_receipt("f"))
    assert calls == []


def test_opaque_argument_denied_at_issue_in_production() -> None:
    calls: list[object] = []

    @_production()
    def f(x: object) -> str:
        calls.append(x)
        return "ok"

    with pytest.raises(GovernancePayloadError) as excinfo:
        f.issue_grant(Opaque())
    assert excinfo.value.rule_id == "GOVERNANCE-PAYLOAD-UNEVALUABLE"
    assert calls == []


def test_undecodable_bytes_denied() -> None:
    calls: list[object] = []

    @_compat()
    def f(x: object) -> str:
        calls.append(x)
        return "ok"

    with pytest.raises(GovernancePayloadError) as excinfo:
        f(b"\xff\xfe", decision_receipt=_receipt("f"))
    assert excinfo.value.rule_id == "GOVERNANCE-PAYLOAD-UNEVALUABLE"
    assert calls == []


def test_benign_scalar_is_evaluated_before_grant_is_minted() -> None:
    guard = _production()
    seen: list[str] = []
    original = guard.engine.validate

    def spy(payload: str, **kwargs: Any) -> Any:
        seen.append(payload)
        return original(payload, **kwargs)

    guard.engine.validate = spy  # type: ignore[method-assign]
    calls: list[int] = []

    @guard
    def f(n: int) -> str:
        calls.append(n)
        return "ok"

    grant = f.issue_grant(5)
    assert "5" in seen
    assert calls == []
    assert f(5, execution_grant=grant) == "ok"
    assert calls == [5]


def test_none_and_empty_arguments_are_skipped() -> None:
    calls: list[object] = []

    @_compat()
    def f(a: object, b: object) -> str:
        calls.append((a, b))
        return "ok"

    assert f(None, "", decision_receipt=_receipt("f")) == "ok"
    assert calls == [(None, "")]


def test_opaque_output_keeps_existing_compatibility_behaviour() -> None:
    """Owner decision covers opaque *arguments* only; opaque output is unchanged."""
    sentinel = Opaque()

    @_compat()
    def f(text: str) -> object:
        return sentinel

    assert f("hello", decision_receipt=_receipt("f")) is sentinel


def test_undecodable_bytes_output_keeps_existing_compatibility_behaviour() -> None:
    @_compat()
    def f(text: str) -> bytes:
        return b"\xff\xfe"

    assert f("hello", decision_receipt=_receipt("f")) == b"\xff\xfe"


def test_scalar_output_is_evaluated() -> None:
    calls: list[str] = []

    @_compat()
    def f(text: str) -> int:
        calls.append(text)
        return 666

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f("hello", decision_receipt=_receipt("f"))
    assert excinfo.value.rule_id == "NUM-666"
    assert calls == ["hello"]


def test_enforcement_payload_helper_counts_every_value() -> None:
    assert governance_payloads_for_enforcement("x", None, 7, {"k": 1}) == [
        "x",
        "7",
        '{"k": 1}',
    ]
    with pytest.raises(GovernancePayloadError):
        governance_payloads_for_enforcement("x" * 11, max_chars=10)
    # Unsortable mixed keys fall back to the container repr, which is still evaluated.
    assert governance_payloads_for_enforcement({1: "forbiddenword", "k": 2}) == [
        "{1: 'forbiddenword', 'k': 2}"
    ]


# --- 1c: a discarded engine result can no longer allow --------------------------


def test_non_strict_compat_callable_denies_violating_input() -> None:
    calls: list[str] = []

    @_compat(strict=False)
    def f(text: str) -> str:
        calls.append(text)
        return "ok"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f("contains forbiddenword", decision_receipt=_receipt("f"))
    assert excinfo.value.rule_id == "BAD-WORD"
    assert calls == []


def test_non_strict_compat_callable_denies_violating_output() -> None:
    calls: list[str] = []

    @_compat(strict=False)
    def f(text: str) -> str:
        calls.append(text)
        return "leaks forbiddenword"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f("hello", decision_receipt=_receipt("f"))
    assert excinfo.value.rule_id == "BAD-WORD"
    assert calls == ["hello"]


def test_non_strict_async_callable_denies_input_and_output() -> None:
    calls: list[str] = []

    @_compat(strict=False)
    async def f(text: str) -> str:
        calls.append(text)
        return "leaks forbiddenword"

    with pytest.raises(ConstitutionalViolationError):
        asyncio.run(f("forbiddenword", decision_receipt=_receipt("f")))
    assert calls == []
    with pytest.raises(ConstitutionalViolationError):
        asyncio.run(f("hello", decision_receipt=_receipt("f")))
    assert calls == ["hello"]


def test_non_strict_issue_grant_denies_violation() -> None:
    calls: list[str] = []

    @_compat(strict=False)
    def f(text: str) -> str:
        calls.append(text)
        return "ok"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f.issue_grant("forbiddenword")
    assert excinfo.value.rule_id == "BAD-WORD"
    assert calls == []


def test_production_profile_rejects_non_strict_engine() -> None:
    with pytest.raises(LegitimacyInvariantError, match="strict"):
        _production(strict=False)


class _NoValid:
    violations: list[Any] = []


def test_result_without_valid_attribute_denies_issue_and_execute() -> None:
    guard = _compat()
    guard.engine.validate = lambda *_a, **_k: _NoValid()  # type: ignore[method-assign]
    calls: list[str] = []

    @guard
    def f(text: str) -> str:
        calls.append(text)
        return "ok"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f.issue_grant("hello")
    assert excinfo.value.rule_id == "EXECUTION-GRANT-DENIED"
    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f("hello", decision_receipt=_receipt("f"))
    assert excinfo.value.rule_id == "EXECUTION-GRANT-DENIED"
    assert calls == []


def test_warn_only_rules_still_pass() -> None:
    calls: list[str] = []

    @_compat(strict=False)
    def f(text: str) -> str:
        calls.append(text)
        return "pingword back"

    assert f("pingword", decision_receipt=_receipt("f")) == "pingword back"
    assert calls == ["pingword"]
