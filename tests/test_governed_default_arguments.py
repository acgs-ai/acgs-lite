"""Parameter defaults are evaluated, not only digested, by ``GovernedCallable``.

The argument digest binds defaults (``apply_defaults``), so a default the call
relies on must reach the engine too. Every test goes through the decorated
function or ``issue_grant`` and asserts the side effect never ran on deny.
"""

from __future__ import annotations

from typing import Any

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.constitution.rule import Rule
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import AuthorizationProfile, DecisionReceipt, ExecutionBoundary
from acgs_lite.legitimacy.invocation import ArgumentNotDigestible, defaulted_argument_values
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner
from acgs_lite.serialization import GovernancePayloadError


def _constitution() -> Constitution:
    return Constitution.from_rules(
        [Rule(id="BAD-WORD", text="no forbiddenword", keywords=["forbiddenword"])]
    )


def _compat() -> GovernedCallable:
    return GovernedCallable(_constitution())


def _production() -> GovernedCallable:
    signer = Ed25519ReceiptSigner.from_seed(bytes(range(32)))
    return GovernedCallable(
        _constitution(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        receipt_signer=signer,
        trusted_execution_keys={signer.key_id: signer.public_key_hex()},
    )


def _receipt(method: str) -> DecisionReceipt:
    return DecisionReceipt.create(
        request_id="req-defaults",
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


class Opaque:
    __slots__ = ()


def test_forbidden_default_denied_on_compat_execute() -> None:
    calls: list[str] = []

    @_compat()
    def f(text: str, note: str = "forbiddenword") -> str:
        calls.append(text)
        return "ok"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f("hello", decision_receipt=_receipt("f"))
    assert excinfo.value.rule_id == "BAD-WORD"
    assert calls == []
    assert f("hello", note="safe", decision_receipt=_receipt("f")) == "ok"
    assert calls == ["hello"]


@pytest.mark.asyncio
async def test_forbidden_default_denied_on_async_compat_execute() -> None:
    calls: list[str] = []

    @_compat()
    async def f(text: str, *, note: str = "forbiddenword") -> str:
        calls.append(text)
        return "ok"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        await f("hello", decision_receipt=_receipt("f"))
    assert excinfo.value.rule_id == "BAD-WORD"
    assert calls == []
    assert await f("hello", note="safe", decision_receipt=_receipt("f")) == "ok"
    assert calls == ["hello"]


def test_forbidden_default_denied_at_compat_issue() -> None:
    calls: list[str] = []

    @_compat()
    def f(text: str, note: str = "forbiddenword") -> str:
        calls.append(text)
        return "ok"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f.issue_grant("hello")
    assert excinfo.value.rule_id == "BAD-WORD"
    grant = f.issue_grant("hello", note="safe")
    assert f("hello", note="safe", execution_grant=grant) == "ok"
    assert calls == ["hello"]


def test_forbidden_default_denied_at_production_issue() -> None:
    calls: list[str] = []

    @_production()
    def f(text: str, note: str = "forbiddenword") -> str:
        calls.append(text)
        return "ok"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f.issue_grant("hello")
    assert excinfo.value.rule_id == "BAD-WORD"
    grant = f.issue_grant("hello", note="safe")
    assert f("hello", note="safe", execution_grant=grant) == "ok"
    assert calls == ["hello"]


@pytest.mark.asyncio
async def test_benign_default_runs_in_async_production() -> None:
    calls: list[str] = []

    @_production()
    async def f(text: str, note: str = "fine") -> str:
        calls.append(f"{text}:{note}")
        return "ok"

    grant = f.issue_grant("hello")
    assert await f("hello", execution_grant=grant) == "ok"
    assert calls == ["hello:fine"]


def test_default_free_callable_is_unchanged() -> None:
    calls: list[str] = []

    @_compat()
    def f(text: str) -> str:
        calls.append(text)
        return "ok"

    assert f("hello", decision_receipt=_receipt("f")) == "ok"
    with pytest.raises(ConstitutionalViolationError):
        f("forbiddenword", decision_receipt=_receipt("f"))
    assert calls == ["hello"]


@pytest.mark.parametrize("guard", [_compat, _production])
def test_opaque_default_denies_in_both_profiles(guard: Any) -> None:
    # Execute: pre-existing behaviour, the binder digests defaults and refuses the
    # value before any profile-specific check. Issue: the defaults evaluation now
    # refuses it first, as unevaluable.
    calls: list[str] = []

    @guard()
    def f(text: str, handle: object = Opaque()) -> str:  # noqa: B008
        calls.append(text)
        return "ok"

    with pytest.raises(GovernancePayloadError) as excinfo:
        f.issue_grant("hello")
    assert excinfo.value.rule_id == "GOVERNANCE-PAYLOAD-UNEVALUABLE"
    with pytest.raises(ArgumentNotDigestible):
        f("hello", decision_receipt=_receipt("f"))
    assert calls == []


def test_defaulted_values_skip_supplied_variadic_and_receiver() -> None:
    def f(self: object, a: int, b: str = "b", *rest: int, c: str = "c", **extra: int) -> None:
        return None

    assert defaulted_argument_values(f, (object(), 1), {}) == ("b", "c")
    assert defaulted_argument_values(f, (object(), 1, "x", 2), {"c": "y", "z": 3}) == ()
    assert defaulted_argument_values(f, (object(), 1), {"execution_grant": object()}) == (
        "b",
        "c",
    )


def test_defaulted_values_include_parameters_named_like_receivers() -> None:
    # Only a defaulted self/cls is reported; a real receiver is always supplied.
    def f(self: str = "s", cls: str = "c") -> None:
        return None

    assert defaulted_argument_values(f, (), {}) == ("s", "c")
    assert defaulted_argument_values(f, ("x",), {}) == ("c",)


@pytest.mark.parametrize("name", ["self", "cls"])
@pytest.mark.parametrize("guard", [_compat, _production])
def test_forbidden_default_on_receiver_named_parameter_denied_at_issue(
    guard: Any, name: str
) -> None:
    calls: list[str] = []
    namespace: dict[str, Any] = {"calls": calls}
    exec(  # noqa: S102 - builds a parameter literally named self/cls
        f"def f(text: str, {name}: str = 'forbiddenword') -> str:\n"
        "    calls.append(text)\n"
        "    return 'ok'\n",
        namespace,
    )
    governed = guard()(namespace["f"])

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        governed.issue_grant("hello")
    assert excinfo.value.rule_id == "BAD-WORD"
    grant = governed.issue_grant("hello", **{name: "safe"})
    assert governed("hello", **{name: "safe"}, execution_grant=grant) == "ok"
    assert calls == ["hello"]


def test_forbidden_cls_default_denied_on_compat_execute() -> None:
    calls: list[str] = []

    @_compat()
    def f(text: str, cls: str = "forbiddenword") -> str:
        calls.append(text)
        return "ok"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f("hello", decision_receipt=_receipt("f"))
    assert excinfo.value.rule_id == "BAD-WORD"
    assert calls == []


def test_defaulted_values_fail_closed_on_bad_binding() -> None:
    def f(a: int) -> None:
        return None

    with pytest.raises(ArgumentNotDigestible):
        defaulted_argument_values(f, (), {"b": 1})

    def g() -> None:
        return None

    g.__signature__ = "not a signature"  # type: ignore[attr-defined]
    with pytest.raises(ArgumentNotDigestible):
        defaulted_argument_values(g, (), {})
