"""JSON-only governance payloads, enforced on input and output.

The projector never asks a value's own type what it contains (``items()``,
``model_dump()``, ``dict()``, ``__dict__``, ``__getattr__``). Only exact built-in
JSON-native values are projected: ``str``/``int``/finite ``float``/``bool``/``None``,
strict-UTF-8 ``bytes``, ``list``/``tuple`` and ``dict`` with ``str`` keys. Everything
else, dataclasses and pydantic models included, denies with
``GOVERNANCE-PAYLOAD-UNEVALUABLE`` before execution (input) and after it (output,
attempt left ``PARTIAL``). Each attack row hides ``forbiddenword`` from an earlier
projector; the control rows prove the harness denies a plain payload by rule.
"""

from __future__ import annotations

import array
import asyncio
import collections
import enum
import inspect
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, NamedTuple

import pydantic.v1 as pydantic_v1
import pytest
from pydantic import BaseModel, ConfigDict, PrivateAttr, RootModel, computed_field

from acgs_lite.constitution import Constitution
from acgs_lite.constitution.rule import Rule
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import AuthorizationProfile, DecisionReceipt, ExecutionBoundary
from acgs_lite.legitimacy.ledger import AttemptStatus
from acgs_lite.legitimacy.signing import Ed25519ReceiptSigner
from acgs_lite.serialization import GovernancePayloadError, governance_payloads_for_enforcement

W = "forbiddenword"
UNEVALUABLE = "GOVERNANCE-PAYLOAD-UNEVALUABLE"
BAD_WORD = "BAD-WORD"


def _constitution() -> Constitution:
    return Constitution.from_rules([Rule(id=BAD_WORD, text="no forbiddenword", keywords=[W])])


def _receipt(method: str) -> DecisionReceipt:
    return DecisionReceipt.create(
        request_id="req-allowlist",
        goal="allowlist call",
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


def _production() -> GovernedCallable:
    signer = Ed25519ReceiptSigner.from_seed(bytes(range(32)))
    return GovernedCallable(
        _constitution(),
        authorization_profile=AuthorizationProfile.PRODUCTION,
        receipt_signer=signer,
        trusted_execution_keys={signer.key_id: signer.public_key_hex()},
    )


# --- attack fixtures (the p1/p3/p4 security-review matrix) -----------------------


class Slotted:
    __slots__ = ("body",)

    def __init__(self) -> None:
        self.body = W


class MixedSlots:
    __slots__ = ("__dict__", "body")

    def __init__(self) -> None:
        self.body = W
        self.tag = "ok"


class SlottedBase:
    __slots__ = ("body",)


class SlottedBaseChild(SlottedBase):
    def __init__(self) -> None:
        self.body = W
        self.tag = "ok"


class PlainObject:
    def __init__(self) -> None:
        self.body = W


class DictSub(dict):  # type: ignore[type-arg]
    pass


class ListSub(list):  # type: ignore[type-arg]
    pass


class StrSub(str):
    pass


@dataclass
class DC:
    x: str


@dataclass
class SlottedFieldDC(SlottedBase):
    x: str = "ok"


@dataclass
class ShadowedDictDC:
    """A dataclass whose ``__dict__`` attribute lies about the instance state."""

    x: str

    @property  # type: ignore[misc]
    def __dict__(self) -> dict[str, Any]:  # type: ignore[override]
        return {"x": "ok"}


class LyingMap(Mapping[str, str]):
    def __getitem__(self, key: str) -> str:
        return W

    def __iter__(self) -> Iterator[str]:
        return iter(["k"])

    def __len__(self) -> int:
        return 1

    def items(self) -> Any:
        return [("k", "ok")]


class Pair(NamedTuple):
    a: str
    b: str


class PydV1(pydantic_v1.BaseModel):
    a: str = "ok"

    class Config:
        fields = {"a": {"exclude": True}}  # noqa: RUF012


class PlainModel(BaseModel):
    note: str = "ok"


class LegacyDict:
    def dict(self) -> dict[str, str]:
        return {"body": "ok"}

    body = W


class ModelDumpOnly:
    def model_dump(self, **_kwargs: Any) -> dict[str, str]:
        return {"body": "ok"}

    body = W


def _dataclass_extra_attr() -> DC:
    value = DC("ok")
    value.body = W  # type: ignore[attr-defined]
    return value


def _shadowed_dict_dc() -> ShadowedDictDC:
    value = ShadowedDictDC("ok")
    object.__setattr__(value, "hidden", W)
    return value


def _property_shadow_dc() -> object:
    """Instance dict says ``ok``; attribute access returns the class property's value."""

    @dataclass
    class PropertyShadowDC:
        x: str

    value = PropertyShadowDC("ok")
    type.__setattr__(PropertyShadowDC, "x", property(lambda self: W))
    assert value.x == W
    return value


def _property_shadow_model() -> object:
    class PropertyShadowModel(BaseModel):
        x: str = "ok"

    value = PropertyShadowModel()
    type.__setattr__(PropertyShadowModel, "x", property(lambda self: W))
    assert value.x == W
    return value


def _dict_sub_attr() -> DictSub:
    value = DictSub(a="ok")
    value.body = W  # type: ignore[attr-defined]
    return value


def _list_sub_attr() -> ListSub:
    value = ListSub(["ok"])
    value.body = W  # type: ignore[attr-defined]
    return value


def _str_sub_attr() -> StrSub:
    value = StrSub("ok")
    value.body = W  # type: ignore[attr-defined]
    return value


def _model_hidden_attr() -> PlainModel:
    value = PlainModel()
    object.__setattr__(value, "hidden", W)
    return value


def _ordered_dict_attr() -> collections.OrderedDict[str, str]:
    value: collections.OrderedDict[str, str] = collections.OrderedDict(a="ok")
    value.body = W  # type: ignore[attr-defined]
    return value


_UNEVALUABLE_ROWS = [
    pytest.param(lambda: collections.deque([W]), id="deque"),
    pytest.param(lambda: (x for x in [W]), id="generator"),
    pytest.param(lambda: memoryview(W.encode()), id="memoryview"),
    pytest.param(lambda: array.array("u", W), id="array"),
    pytest.param(Slotted, id="slots"),
    pytest.param(MixedSlots, id="mixed-slots"),
    pytest.param(SlottedBaseChild, id="slotted-base-child"),
    pytest.param(PlainObject, id="plain-object-dict"),
    pytest.param(lambda: collections.defaultdict(lambda: W), id="defaultdict"),
    pytest.param(lambda: collections.Counter({W: 1}), id="counter"),
    pytest.param(_ordered_dict_attr, id="ordered-dict-attr"),
    pytest.param(_dict_sub_attr, id="dict-subclass-attr"),
    pytest.param(_list_sub_attr, id="list-subclass-attr"),
    pytest.param(_str_sub_attr, id="str-subclass-attr"),
    pytest.param(_dataclass_extra_attr, id="dataclass-extra-attr"),
    pytest.param(_shadowed_dict_dc, id="dataclass-shadowed-dict"),
    pytest.param(lambda: SlottedFieldDC(), id="dataclass-slotted-base"),
    pytest.param(_property_shadow_dc, id="dataclass-field-shadowed-by-property"),
    pytest.param(_property_shadow_model, id="pydantic-field-shadowed-by-property"),
    pytest.param(lambda: ValueError(W), id="exception-object"),
    pytest.param(LyingMap, id="lying-mapping"),
    pytest.param(lambda: MappingProxyType(LyingMap()), id="proxy-of-lying-mapping"),  # type: ignore[arg-type]
    pytest.param(lambda: collections.ChainMap({"a": "ok"}, {"b": W}), id="chainmap"),
    pytest.param(lambda: Pair("ok", W), id="namedtuple"),
    pytest.param(lambda: PydV1(a=W), id="pydantic-v1-exclude"),
    pytest.param(_model_hidden_attr, id="pydantic-hidden-instance-attr"),
    pytest.param(LegacyDict, id="legacy-dict-method"),
    pytest.param(ModelDumpOnly, id="model-dump-duck"),
    pytest.param(lambda: W.encode("utf-16-le"), id="utf16le-bytes"),
    pytest.param(lambda: b"forbidden\xffword", id="undecodable-bytes"),
    pytest.param(lambda: {"blob": bytearray(W.encode("utf-16-be"))}, id="nested-utf16be"),
    pytest.param(lambda: {PlainObject(): "x"}, id="opaque-key"),
    pytest.param(lambda: {("a", W): "x"}, id="tuple-key"),
    # Dataclasses and pydantic models deny outright under the JSON-only contract.
    pytest.param(lambda: Priv(), id="pydantic-private-attr"),
    pytest.param(lambda: Comp(), id="pydantic-computed-field"),
    pytest.param(lambda: Extra(body=W), id="pydantic-extra"),
    pytest.param(lambda: Root([W]), id="pydantic-root-model"),
    pytest.param(lambda: DC(W), id="dataclass-field"),
]


class Priv(BaseModel):
    note: str = "ok"
    _secret: str = PrivateAttr(default=W)


class Comp(BaseModel):
    note: str = "ok"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def c(self) -> str:
        return W


class Extra(BaseModel):
    model_config = ConfigDict(extra="allow")


class Root(RootModel[list[str]]):
    pass


# Plain JSON payloads carrying the keyword must deny by rule, not as unevaluable.
_EVALUATED_ROWS = [
    pytest.param(lambda: {"x": W}, id="control-plain-dict"),
    pytest.param(lambda: [{"x": (W,)}], id="control-nested-list"),
]


def _assert_denied(excinfo: pytest.ExceptionInfo[ConstitutionalViolationError], rule: str) -> None:
    if rule == UNEVALUABLE:
        assert isinstance(excinfo.value, GovernancePayloadError)
    else:
        assert not isinstance(excinfo.value, GovernancePayloadError)
    assert excinfo.value.rule_id == rule


def _check_input_and_output(make: Any, rule: str) -> None:
    calls: list[object] = []

    @GovernedCallable(_constitution())
    def take(value: object) -> str:
        calls.append(value)
        return "ok"

    if rule == UNEVALUABLE:
        with pytest.raises(GovernancePayloadError):
            governance_payloads_for_enforcement(make())
    else:
        assert any(W in payload for payload in governance_payloads_for_enforcement(make()))
    for call in (lambda: take.issue_grant(make()), lambda: take.issue_grant(value=make())):
        with pytest.raises(ConstitutionalViolationError) as excinfo:
            call()
        _assert_denied(excinfo, rule)
    assert calls == []

    produced: list[str] = []
    guard = _production()

    @guard
    def produce(text: str) -> object:
        produced.append(text)
        return make()

    grant = produce.issue_grant("hello")
    with pytest.raises(ConstitutionalViolationError) as excinfo:
        produce("hello", execution_grant=grant, execution_attempt_id="out")
    _assert_denied(excinfo, rule)
    assert produced == ["hello"]
    assert guard._ledger._attempts["out"].status is AttemptStatus.PARTIAL

    @GovernedCallable(_constitution())
    def produce_compat(text: str) -> object:
        return {"wrapped": [make()]}

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        produce_compat("hello", decision_receipt=_receipt("produce_compat"))
    _assert_denied(excinfo, rule)


@pytest.mark.parametrize("make", _UNEVALUABLE_ROWS)
def test_unlisted_type_is_denied_on_input_and_output(make: Any) -> None:
    _check_input_and_output(make, UNEVALUABLE)


@pytest.mark.parametrize("make", _EVALUATED_ROWS)
def test_plain_keyword_content_is_denied_by_rule_on_input_and_output(make: Any) -> None:
    _check_input_and_output(make, BAD_WORD)


def test_async_output_of_unlisted_type_is_denied_and_partial() -> None:
    produced: list[str] = []
    guard = _production()

    @guard
    async def produce(text: str) -> object:
        produced.append(text)
        return collections.deque([W])

    grant = produce.issue_grant("hello")
    with pytest.raises(GovernancePayloadError) as excinfo:
        asyncio.run(produce("hello", execution_grant=grant, execution_attempt_id="async-out"))
    assert excinfo.value.rule_id == UNEVALUABLE
    assert produced == ["hello"]
    assert guard._ledger._attempts["async-out"].status is AttemptStatus.PARTIAL


def test_output_cycle_is_denied() -> None:
    @GovernedCallable(_constitution())
    def produce(text: str) -> object:
        cyclic: list[object] = ["x"]
        cyclic.append(cyclic)
        return cyclic

    with pytest.raises(GovernancePayloadError) as excinfo:
        produce("hello", decision_receipt=_receipt("produce"))
    assert excinfo.value.rule_id == UNEVALUABLE


class RaisingComputed(BaseModel):
    @computed_field  # type: ignore[prop-decorator]
    @property
    def boom(self) -> str:
        raise RuntimeError("computed field failed")


def _bad_private() -> PlainModel:
    value = PlainModel()
    object.__setattr__(value, "__pydantic_private__", [("_k", W)])
    return value


def _colliding_extra() -> PlainModel:
    value = PlainModel()
    object.__setattr__(value, "__pydantic_extra__", {"note": W})
    return value


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(RaisingComputed, id="computed-field-raises"),
        pytest.param(_bad_private, id="non-dict-private-state"),
        pytest.param(_colliding_extra, id="extra-collides-with-field"),
    ],
)
def test_unreadable_model_state_is_denied(make: Any) -> None:
    with pytest.raises(GovernancePayloadError) as excinfo:
        governance_payloads_for_enforcement({"m": make()})
    assert excinfo.value.rule_id == UNEVALUABLE


def test_enum_with_none_value_is_denied_not_skipped() -> None:
    class Maybe(enum.Enum):
        NOTHING = None

    with pytest.raises(GovernancePayloadError) as excinfo:
        governance_payloads_for_enforcement(Maybe.NOTHING, "x")
    assert excinfo.value.rule_id == UNEVALUABLE


def test_skip_opaque_is_no_longer_accepted() -> None:
    # Introspect rather than call with the removed keyword: the static call
    # tripped CodeQL py/call/wrong-named-argument. Absence from the signature
    # plus no **kwargs catch-all means any skip_opaque= call raises TypeError.
    params = inspect.signature(governance_payloads_for_enforcement).parameters
    assert "skip_opaque" not in params
    assert not any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
    removed = {"skip_opaque": True}
    with pytest.raises(TypeError, match="skip_opaque"):
        governance_payloads_for_enforcement({"k": "v"}, **removed)


# --- benign JSON-native payloads still pass ---------------------------------------


def _benign() -> dict[str, Any]:
    return {
        "items": [1, 2.5, True, None, "s", (3, 4), [5], ["f"]],
        "nested": {"dc": {"label": "hi", "tags": ["a"]}, "frozen": {"n": 1}},
        "raw": b"utf8",
        "buf": bytearray(b"ba"),
        "ts": "2026-01-02T00:00:00+00:00",
        "id": "00000000-0000-0000-0000-000000000001",
        "amount": "1.5",
    }


def test_benign_allowlisted_payload_projects_every_field() -> None:
    [payload] = governance_payloads_for_enforcement(_benign())
    assert payload == (
        '{"amount": "1.5", "buf": "ba", '
        '"id": "00000000-0000-0000-0000-000000000001", '
        '"items": [1, 2.5, true, null, "s", [3, 4], [5], ["f"]], '
        '"nested": {"dc": {"label": "hi", "tags": ["a"]}, "frozen": {"n": 1}}, '
        '"raw": "utf8", "ts": "2026-01-02T00:00:00+00:00"}'
    )


def test_benign_allowlisted_output_is_returned() -> None:
    @GovernedCallable(_constitution())
    def produce_rich(text: str) -> object:
        return _benign()

    result = produce_rich("hello", decision_receipt=_receipt("produce_rich"))
    assert isinstance(result, dict) and result["raw"] == b"utf8"

    # Production also digests the result for the ledger, which needs plain JSON data.
    guard = _production()

    @guard
    def produce(text: str) -> object:
        return {"items": [1, "two", None], "nested": {"ok": True}}

    grant = produce.issue_grant("hello")
    assert produce("hello", execution_grant=grant, execution_attempt_id="benign") == {
        "items": [1, "two", None],
        "nested": {"ok": True},
    }
    assert guard._ledger._attempts["benign"].status is AttemptStatus.COMPLETED


def test_benign_plain_payload_still_mints_a_grant() -> None:
    @GovernedCallable(_constitution())
    def take(value: object) -> str:
        return "ok"

    assert take.issue_grant({"body": "hello", "to": ["a", "b"], "n": 1}) is not None
