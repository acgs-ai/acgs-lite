"""Dispatcher-level recursive projection of nested governed payloads.

Nested values (dict values, list/tuple/set elements, dataclass fields including
``repr=False``, pydantic models) are projected field by field and evaluated;
nothing reaches the engine as ``repr()``/``__str__`` text. Values outside the
closed allowlist (plain objects, non-dict mappings, ``dict()``/``model_dump()``
duck types, opaque keys, undecodable bytes) deny with
``GOVERNANCE-PAYLOAD-UNEVALUABLE`` wherever they are nested, on input and output. Every test calls the decorated function or ``issue_grant`` and asserts
the wrapped side effect never ran on deny.
"""

from __future__ import annotations

import datetime as dt
import enum
import io
import uuid
from collections import ChainMap
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

import pytest
from pydantic import BaseModel, ConfigDict, Field, field_serializer, model_serializer

from acgs_lite.constitution import Constitution
from acgs_lite.constitution.rule import Rule
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import DecisionReceipt, ExecutionBoundary
from acgs_lite.legitimacy.invocation import ArgumentNotDigestible
from acgs_lite.serialization import GovernancePayloadError, governance_payloads_for_enforcement

UNEVALUABLE = "GOVERNANCE-PAYLOAD-UNEVALUABLE"


def _constitution() -> Constitution:
    return Constitution.from_rules(
        [
            Rule(id="BAD-WORD", text="no forbiddenword", keywords=["forbiddenword"]),
            Rule(id="NUM-666", text="no 666", keywords=["666"]),
        ]
    )


def _receipt(method: str) -> DecisionReceipt:
    return DecisionReceipt.create(
        request_id="req-nested",
        goal="nested call",
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


def _guard() -> GovernedCallable:
    return GovernedCallable(_constitution())


class Email:
    def __init__(self, body: str) -> None:
        self.body = body


@dataclass
class Disguised:
    """Custom ``__str__``/``__repr__`` must never stand in for field content."""

    body: str

    def __str__(self) -> str:
        return "hello"

    __repr__ = __str__


@dataclass
class Hidden:
    body: str = field(repr=False)


class Model(BaseModel):
    body: str


class Opaque:
    __slots__ = ()


class Color(enum.Enum):
    BAD = "forbiddenword"


def _assert_rule_denies(call: Any, rule_id: str) -> None:
    with pytest.raises(ConstitutionalViolationError) as excinfo:
        call()
    assert not isinstance(excinfo.value, GovernancePayloadError)
    assert excinfo.value.rule_id == rule_id


# --- [0] nested content is evaluated, never repr/__str__ ------------------------


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda: Disguised("rm forbiddenword"), id="custom-str"),
        pytest.param(lambda: Hidden("rm forbiddenword"), id="dataclass-repr-false"),
        pytest.param(lambda: Model(body="rm forbiddenword"), id="pydantic"),
    ],
)
def test_keyword_object_fields_are_evaluated_at_issue_and_execute(make: Any) -> None:
    calls: list[object] = []

    @_guard()
    def send(*, email: object) -> str:
        calls.append(email)
        return "sent"

    _assert_rule_denies(lambda: send.issue_grant(email=make()), "BAD-WORD")
    # Execute path: the invocation binder refuses objects it cannot digest, else the
    # projected fields are evaluated; either way the side effect never runs.
    with pytest.raises(ConstitutionalViolationError) as excinfo:
        send(email=make(), decision_receipt=_receipt("send"))
    if not isinstance(excinfo.value, ArgumentNotDigestible):
        assert not isinstance(excinfo.value, GovernancePayloadError)
        assert excinfo.value.rule_id == "BAD-WORD"
    assert calls == []


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda: [Hidden("forbiddenword")], id="list"),
        pytest.param(lambda: (Disguised("forbiddenword"),), id="tuple"),
        pytest.param(lambda: {"a": {"b": [Hidden("forbiddenword")]}}, id="nested-dict"),
        pytest.param(lambda: {Color.BAD}, id="set-of-enum"),
        pytest.param(lambda: frozenset({"forbiddenword"}), id="frozenset"),
    ],
)
def test_container_elements_are_evaluated(make: Any) -> None:
    calls: list[object] = []

    @_guard()
    def f(items: object) -> str:
        calls.append(items)
        return "ok"

    _assert_rule_denies(lambda: f.issue_grant(make()), "BAD-WORD")
    _assert_rule_denies(lambda: f.issue_grant(items=make()), "BAD-WORD")
    with pytest.raises(ConstitutionalViolationError):
        f(make(), decision_receipt=_receipt("f"))
    assert calls == []


def test_keyword_and_positional_object_yield_the_same_evaluated_content() -> None:
    positional = governance_payloads_for_enforcement(Hidden("rm forbiddenword"))
    keyword = governance_payloads_for_enforcement({"email": Hidden("rm forbiddenword")})
    assert positional == ['{"body": "rm forbiddenword"}']
    assert keyword == ['{"email": {"body": "rm forbiddenword"}}']
    assert "object at 0x" not in keyword[0]


def test_disguised_and_repr_false_fields_reach_the_engine() -> None:
    [payload] = governance_payloads_for_enforcement({"x": Disguised("secret-body")})
    assert "secret-body" in payload and "hello" not in payload
    [payload] = governance_payloads_for_enforcement({"x": Hidden("secret-body")})
    assert payload == '{"x": {"body": "secret-body"}}'


def test_benign_nested_payload_still_mints_a_grant() -> None:
    calls: list[object] = []

    @_guard()
    def send(*, email: object) -> str:
        calls.append(email)
        return "sent"

    # Evaluation passes; the invocation binder then refuses the undigestible object.
    with pytest.raises(ArgumentNotDigestible):
        send.issue_grant(email=Hidden("hello"))
    # A plain object is not projectable at all, so it denies before binding.
    with pytest.raises(GovernancePayloadError):
        send.issue_grant(email=Email("hello"))
    assert send.issue_grant(email={"body": "hello", "to": ["a", "b"]}) is not None
    assert calls == []


# --- [1] opaque values deny wherever they are nested -----------------------------


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda: [io.StringIO("forbiddenword")], id="list-of-stringio"),
        pytest.param(lambda: [Opaque()], id="top-level-list-of-opaque"),
        pytest.param(lambda: (1, Opaque()), id="tuple"),
        pytest.param(lambda: {"a": {"b": (x for x in ["forbiddenword"])}}, id="nested-gen"),
        pytest.param(lambda: Email("forbiddenword"), id="plain-object"),
        pytest.param(lambda: Hidden(Opaque()), id="object-field"),  # type: ignore[arg-type]
        pytest.param(lambda: {"a": [b"\xff\xfe"]}, id="nested-undecodable-bytes"),
        pytest.param(lambda: {Opaque(): "x"}, id="opaque-key"),
    ],
)
def test_nested_opaque_values_are_denied(make: Any) -> None:
    calls: list[object] = []

    @_guard()
    def f(items: object) -> str:
        calls.append(items)
        return "ok"

    for call in (lambda: f.issue_grant(make()), lambda: f.issue_grant(items=make())):
        with pytest.raises(GovernancePayloadError) as excinfo:
            call()
        assert excinfo.value.rule_id == UNEVALUABLE
    with pytest.raises((GovernancePayloadError, ArgumentNotDigestible)):
        f(make(), decision_receipt=_receipt("f"))
    assert calls == []


def test_cyclic_payload_is_denied() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(GovernancePayloadError) as excinfo:
        governance_payloads_for_enforcement(cyclic)
    assert excinfo.value.rule_id == UNEVALUABLE


def test_shared_reference_is_not_a_cycle() -> None:
    shared = {"k": "v"}
    assert governance_payloads_for_enforcement([shared, shared]) == ['[{"k": "v"}, {"k": "v"}]']


def test_excessive_nesting_is_denied() -> None:
    deep: object = "x"
    for _ in range(100):
        deep = [deep]
    with pytest.raises(GovernancePayloadError) as excinfo:
        governance_payloads_for_enforcement(deep)
    assert excinfo.value.rule_id == UNEVALUABLE


def test_shared_reference_blowup_is_denied_as_oversize() -> None:
    node: object = "a" * 100
    for _ in range(20):
        node = [node, node]
    with pytest.raises(GovernancePayloadError) as excinfo:
        governance_payloads_for_enforcement(node)
    assert excinfo.value.rule_id == "GOVERNANCE-PAYLOAD-OVERSIZE"


def test_colliding_projected_keys_are_denied() -> None:
    with pytest.raises(GovernancePayloadError) as excinfo:
        governance_payloads_for_enforcement({1: "a", "1": "forbiddenword"})
    assert excinfo.value.rule_id == UNEVALUABLE


def test_failing_model_dump_is_denied() -> None:
    class Broken:
        def model_dump(self, **_kwargs: Any) -> Any:
            raise RuntimeError("boom")

    with pytest.raises(GovernancePayloadError) as excinfo:
        governance_payloads_for_enforcement({"m": Broken()})
    assert excinfo.value.rule_id == UNEVALUABLE


def test_nested_opaque_output_is_denied_not_stringified() -> None:
    sentinel = Opaque()
    calls: list[str] = []

    @_guard()
    def f(text: str) -> object:
        calls.append(text)
        return {"handle": sentinel, "note": "fine"}

    with pytest.raises(GovernancePayloadError) as excinfo:
        f("hello", decision_receipt=_receipt("f"))
    assert excinfo.value.rule_id == UNEVALUABLE
    assert calls == ["hello"]
    with pytest.raises(GovernancePayloadError):
        governance_payloads_for_enforcement({"h": Disguised("x"), "o": sentinel})


def test_nested_output_content_is_evaluated() -> None:
    calls: list[str] = []

    @_guard()
    def f(text: str) -> object:
        calls.append(text)
        return [Disguised("leaks forbiddenword")]

    _assert_rule_denies(lambda: f("hello", decision_receipt=_receipt("f")), "BAD-WORD")
    assert calls == ["hello"]


# --- [10] well-known value types are projected deterministically ------------------


def test_well_known_value_types_are_projected() -> None:
    value = {
        "ts": dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc),
        "day": dt.date(2026, 1, 2),
        "at": dt.time(3, 4, 5),
        "id": uuid.UUID(int=1),
        "path": PurePosixPath("/srv/data"),
        "amount": Decimal("1.50"),
        "color": Color.BAD,
        "raw": b"utf8",
    }
    assert governance_payloads_for_enforcement(value) == [
        '{"amount": "1.50", "at": "03:04:05", "color": "forbiddenword", '
        '"day": "2026-01-02", "id": "00000000-0000-0000-0000-000000000001", '
        '"path": "/srv/data", "raw": "utf8", "ts": "2026-01-02T03:04:05+00:00"}'
    ]
    assert governance_payloads_for_enforcement(dt.date(2026, 1, 2)) == ["2026-01-02"]


@pytest.mark.parametrize(
    ("value", "rule_id"),
    [
        (dt.datetime(2666, 1, 1), "NUM-666"),
        (Path("/x/forbiddenword"), "BAD-WORD"),
        (uuid.UUID("00000000-0000-0000-0000-000000000666"), "NUM-666"),
        (Decimal("666"), "NUM-666"),
    ],
)
def test_well_known_nested_values_are_evaluated_not_denied(value: object, rule_id: str) -> None:
    calls: list[object] = []

    @_guard()
    def f(meta: object) -> str:
        calls.append(meta)
        return "ok"

    _assert_rule_denies(lambda: f.issue_grant({"v": value}), rule_id)
    _assert_rule_denies(lambda: f.issue_grant(meta={"v": [value]}), rule_id)
    assert calls == []


def test_benign_well_known_nested_values_mint() -> None:
    @_guard()
    def f(meta: object) -> str:
        return "ok"

    assert f.issue_grant({"ts": dt.datetime(2026, 1, 1), "n": Decimal("1.5")}) is not None
    with pytest.raises(ArgumentNotDigestible):
        f.issue_grant({"id": uuid.uuid4(), "path": Path("/srv")})


def test_enum_keys_project_while_legacy_dict_cycles_and_opaque_keys_deny() -> None:
    class Legacy:
        def dict(self) -> dict[str, Any]:
            return {"body": "forbiddenword"}

    assert governance_payloads_for_enforcement({Color.BAD: Hidden("forbiddenword")}) == [
        '{"forbiddenword": {"body": "forbiddenword"}}'
    ]
    cyclic: list[object] = ["x"]
    cyclic.append(cyclic)
    # There is no output-only skip mode: every one of these denies on both sides.
    for value in ({Color.BAD: Legacy()}, cyclic, {Opaque(): "kept", "k": "v"}):
        with pytest.raises(GovernancePayloadError) as excinfo:
            governance_payloads_for_enforcement(value)
        assert excinfo.value.rule_id == UNEVALUABLE


# --- [11] output with opaque keys or binary denies, it is never partially read ----


@pytest.mark.parametrize(
    "result",
    [
        pytest.param(lambda: {Opaque(): "leaks forbiddenword"}, id="value-under-opaque-key"),
        pytest.param(lambda: {("forbiddenword",): "x"}, id="tuple-key-content"),
        pytest.param(lambda: b"\xffleaks forbiddenword", id="undecodable-bytes"),
        pytest.param(lambda: {"blob": b"\xfe forbiddenword \xff"}, id="nested-undecodable-bytes"),
    ],
)
def test_output_with_opaque_keys_or_binary_is_denied(result: Any) -> None:
    calls: list[str] = []

    @_guard()
    def f(text: str) -> object:
        calls.append(text)
        return result()

    with pytest.raises(GovernancePayloadError) as excinfo:
        f("hello", decision_receipt=_receipt("f"))
    assert excinfo.value.rule_id == UNEVALUABLE
    assert calls == ["hello"]


def test_benign_output_with_opaque_keys_or_binary_is_denied() -> None:
    sentinel = Opaque()

    @_guard()
    def f(text: str) -> object:
        return {sentinel: "fine", "blob": b"\xff\xfe"}

    with pytest.raises(GovernancePayloadError):
        f("hello", decision_receipt=_receipt("f"))


def test_opaque_keys_still_deny_on_the_input_side() -> None:
    with pytest.raises(GovernancePayloadError) as excinfo:
        governance_payloads_for_enforcement({Opaque(): "x"})
    assert excinfo.value.rule_id == UNEVALUABLE
    with pytest.raises(GovernancePayloadError):
        governance_payloads_for_enforcement({"b": b"\xff"})


# --- [12] non-dict mappings deny: their items() is the type's own claim ----------


class Bag(Mapping[str, Any]):
    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data
        self.label = "internal"

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)


def test_non_dict_mappings_are_denied() -> None:
    for value in (
        MappingProxyType({"k": "v"}),
        {"m": Bag({"body": "x"})},
        {"m": ChainMap({"a": 1}, {"b": 2})},
        Bag({"k": Opaque()}),
    ):
        with pytest.raises(GovernancePayloadError) as excinfo:
            governance_payloads_for_enforcement(value)
        assert excinfo.value.rule_id == UNEVALUABLE

    @_guard()
    def f(meta: object) -> str:
        return "ok"

    with pytest.raises(GovernancePayloadError):
        f.issue_grant(MappingProxyType({"body": "forbiddenword"}))


# --- [13] pydantic models project field values, not their serialized form --------


class ExcludedModel(BaseModel):
    body: str = Field(exclude=True)


class FieldRedactedModel(BaseModel):
    body: str

    @field_serializer("body")
    def _redact(self, value: str) -> str:
        return "redacted"


class ModelRedactedModel(BaseModel):
    body: str

    @model_serializer
    def _redact(self) -> dict[str, str]:
        return {"body": "redacted"}


class ExtraModel(BaseModel):
    model_config = ConfigDict(extra="allow")


_REDACTING_MODELS = [
    pytest.param(lambda: ExcludedModel(body="forbiddenword"), id="field-exclude"),
    pytest.param(lambda: FieldRedactedModel(body="forbiddenword"), id="field-serializer"),
    pytest.param(lambda: ModelRedactedModel(body="forbiddenword"), id="model-serializer"),
    pytest.param(lambda: ExtraModel(body="forbiddenword"), id="extra-field"),
]


@pytest.mark.parametrize("make", _REDACTING_MODELS)
def test_redacted_model_output_content_is_evaluated(make: Any) -> None:
    calls: list[str] = []

    @_guard()
    def f(text: str) -> object:
        calls.append(text)
        return {"message": make()}

    _assert_rule_denies(lambda: f("hello", decision_receipt=_receipt("f")), "BAD-WORD")
    assert calls == ["hello"]


@pytest.mark.parametrize("make", _REDACTING_MODELS)
def test_redacted_model_input_content_is_evaluated(make: Any) -> None:
    calls: list[object] = []

    @_guard()
    def f(meta: object) -> str:
        calls.append(meta)
        return "ok"

    _assert_rule_denies(lambda: f.issue_grant(make()), "BAD-WORD")
    _assert_rule_denies(lambda: f.issue_grant(meta={"m": make()}), "BAD-WORD")
    assert calls == []


def test_model_field_values_are_projected_recursively() -> None:
    assert governance_payloads_for_enforcement(FieldRedactedModel(body="x")) == ['{"body": "x"}']
    with pytest.raises(GovernancePayloadError):
        governance_payloads_for_enforcement(ExtraModel(handle=Opaque()))
