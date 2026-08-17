"""Canonical invocation and policy binding tests."""

from __future__ import annotations

import math

import pytest

from acgs_lite.constitution import Constitution
from acgs_lite.legitimacy.invocation import (
    CONTROL_KWARGS,
    ArgumentNotDigestible,
    bind_invocation,
    bind_policy,
    canonical_argument_digest,
    trusted_method_id,
)


def _add(amount: int, currency: str = "USD") -> int:
    return amount


def test_trusted_method_id_is_module_qualname() -> None:
    assert trusted_method_id(_add) == f"{_add.__module__}:{_add.__qualname__}"


def test_trusted_method_id_override_is_explicit() -> None:
    assert trusted_method_id(_add, override="payments.transfer") == "payments.transfer"


def test_control_kwargs_are_stripped_from_digest() -> None:
    left = canonical_argument_digest(_add, (10,), {"currency": "USD"})
    right = canonical_argument_digest(
        _add,
        (10,),
        {
            "currency": "USD",
            "decision_receipt": object(),
            "execution_grant": object(),
            "human_approval": {"approved_by": "x"},
        },
    )
    assert left == right
    assert "decision_receipt" in CONTROL_KWARGS


def test_positional_and_keyword_defaults_match() -> None:
    a = canonical_argument_digest(_add, (10,), {})
    b = canonical_argument_digest(_add, (), {"amount": 10, "currency": "USD"})
    c = canonical_argument_digest(_add, (10,), {"currency": "USD"})
    assert a == b == c


def test_tuple_and_list_have_distinct_digests() -> None:
    def take(items: object) -> None:
        return None

    tuple_digest = canonical_argument_digest(take, ((1,),), {})
    list_digest = canonical_argument_digest(take, ([1],), {})
    assert tuple_digest != list_digest


def test_nan_argument_fails_closed() -> None:
    def take(value: float) -> None:
        return None

    with pytest.raises(ArgumentNotDigestible):
        canonical_argument_digest(take, (math.nan,), {})


def test_unsupported_object_fails_closed() -> None:
    def take(value: object) -> None:
        return None

    with pytest.raises(ArgumentNotDigestible):
        canonical_argument_digest(take, (object(),), {})


def test_bind_invocation_includes_method_and_digest() -> None:
    binding = bind_invocation(_add, (25,), {"currency": "EUR"})
    assert binding.method_id == trusted_method_id(_add)
    assert binding.argument_digest == canonical_argument_digest(_add, (25,), {"currency": "EUR"})
    assert binding.scope is None
    assert binding.subjects == ()


def test_policy_digest_changes_when_constitution_content_changes() -> None:
    first = bind_policy(Constitution.default())
    other = Constitution.default()
    object.__setattr__(other, "name", f"{other.name}-variant")
    second = bind_policy(other)
    assert first.algorithm == "sha256"
    assert len(first.digest) == 64
    assert first.digest != second.digest
