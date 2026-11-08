"""JSON-only governance payloads: the projector, the binder and the output digest agree.

Governed arguments and return values may only be exact built-in JSON-native values:
``dict`` (exact ``str`` keys), ``list``, ``tuple`` (projected as a list), ``str``,
``int``, finite ``float``, ``bool``, ``None`` and strict-UTF-8 ``bytes``/``bytearray``
without NUL. Every rich object (Enum, dataclass, pydantic model, datetime, UUID, Path,
Decimal, set, subclasses of the accepted types, ...) denies on input and on output,
because its runtime behaviour can differ from any projection of its state.

Each row of the deny matrix reproduces a bypass found against an earlier projector.
Control rows (a plain payload carrying the forbidden keyword) must deny by rule, and
positive rows must pass and be returned, so the harness cannot go green vacuously.
"""

from __future__ import annotations

import array
import asyncio
import collections
import dataclasses
import datetime as dt
import decimal
import enum
import uuid
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any, NamedTuple

import pytest
from pydantic import BaseModel, ConfigDict, PrivateAttr, computed_field

from acgs_lite.constitution import Constitution
from acgs_lite.constitution.rule import Rule
from acgs_lite.errors import ConstitutionalViolationError
from acgs_lite.governed import GovernedCallable
from acgs_lite.legitimacy import (
    AuthorizationProfile,
    DecisionReceipt,
    ExecutionBoundary,
    LegitimacyInvariantError,
)
from acgs_lite.legitimacy.invocation import (
    ArgumentNotDigestible,
    bind_invocation,
    canonical_argument_digest,
)
from acgs_lite.legitimacy.ledger import AttemptStatus, digest_output
from acgs_lite.serialization import GovernancePayloadError, governance_payloads_for_enforcement

W = "forbiddenword"
UNEVALUABLE = "GOVERNANCE-PAYLOAD-UNEVALUABLE"


def _constitution() -> Constitution:
    return Constitution.from_rules(
        [Rule(id="BAD-WORD", text="no forbiddenword", keywords=["forbiddenword"])]
    )


def _receipt(method: str) -> DecisionReceipt:
    return DecisionReceipt.create(
        request_id="req-json-only",
        goal="json-only call",
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


def _compat_guard() -> GovernedCallable:
    return GovernedCallable(_constitution())


@pytest.fixture
def production_guard() -> Callable[[], GovernedCallable]:
    signing = pytest.importorskip("acgs_lite.legitimacy.signing")
    pytest.importorskip("cryptography")
    signer = signing.Ed25519ReceiptSigner.from_seed(bytes(range(32)), key_id="pinned")
    pins = {"pinned": signer.public_key_hex()}

    def make() -> GovernedCallable:
        return GovernedCallable(
            _constitution(),
            authorization_profile=AuthorizationProfile.PRODUCTION,
            receipt_signer=signer,
            trusted_execution_keys=pins,
        )

    return make


# --- rich objects whose runtime behaviour differs from their projected state ---------


@dataclasses.dataclass
class GetattributeDataclass:
    body: str

    def __getattribute__(self, name: str) -> Any:
        return W if name == "body" else object.__getattribute__(self, name)


class GetattributeModel(BaseModel):
    body: str

    def __getattribute__(self, name: str) -> Any:
        return W if name == "body" else super().__getattribute__(name)


class StrMixinEnum(str, enum.Enum):
    """The ``str`` data is the forbidden word; ``_value_`` is benign."""

    def __new__(cls, value: str) -> StrMixinEnum:
        member = str.__new__(cls, W)
        member._value_ = value
        return member

    A = "ok"


class AttrEnum(enum.Enum):
    A = "ok"


AttrEnum.A.payload = W  # type: ignore[attr-defined]


class MutatingComputed(BaseModel):
    body: str = "ok"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def c(self) -> str:
        self.__dict__["body"] = W
        return "ok"


class FlippingComputed(BaseModel):
    n: int = 0
    _k: int = 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def c(self) -> str:
        object.__setattr__(self, "__pydantic_private__", {"_k": self._k + 1})
        return "ok" if self._k == 1 else W


class ShadowedExtra(BaseModel):
    model_config = ConfigDict(extra="allow")

    @property
    def foo(self) -> str:
        return W


class PrivateModel(BaseModel):
    note: str = "ok"
    _secret: str = PrivateAttr(default=W)


class ComputedModel(BaseModel):
    note: str = "ok"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def c(self) -> str:
        return W


class PlainModel(BaseModel):
    note: str = "ok"


@dataclasses.dataclass
class PlainDataclass:
    note: str = "ok"


class Slotted:
    __slots__ = ("body",)

    def __init__(self) -> None:
        self.body = W


class MixedSlots:
    __slots__ = ("body", "__dict__")

    def __init__(self) -> None:
        self.body = W
        self.tag = "ok"


class SlottedBase:
    __slots__ = ("body",)


class SlottedChild(SlottedBase):
    def __init__(self) -> None:
        self.body = W
        self.tag = "ok"


class DictSub(dict):  # type: ignore[type-arg]
    pass


class ListSub(list):  # type: ignore[type-arg]
    pass


class StrSub(str):
    pass


class IntSub(int):
    pass


class FloatSub(float):
    pass


class BytesSub(bytes):
    pass


class Pair(NamedTuple):
    a: str
    b: str


def _lying_meta(base: type) -> type:
    """A metaclass whose instances compare and hash equal to ``base``."""

    def eq(cls: type, other: object) -> bool:
        return True

    def hash_(cls: type) -> int:
        return hash(base)

    return type(f"Lying{base.__name__.title()}Meta", (type,), {"__eq__": eq, "__hash__": hash_})


class MetaStr(str, metaclass=_lying_meta(str)):  # type: ignore[misc]
    pass


class MetaInt(int, metaclass=_lying_meta(int)):  # type: ignore[misc]
    pass


class MetaList(list, metaclass=_lying_meta(list)):  # type: ignore[misc, type-arg]
    def __iter__(self) -> Any:
        return iter(["ok"])


class MetaTuple(tuple, metaclass=_lying_meta(tuple)):  # type: ignore[misc, type-arg]
    def __iter__(self) -> Any:
        return iter(["ok"])


def _meta_str() -> Any:
    value = MetaStr("ok")
    value.body = W  # type: ignore[attr-defined]
    return value


class LyingMapping(Mapping[str, str]):
    def __getitem__(self, key: str) -> str:
        return W

    def __iter__(self) -> Iterator[str]:
        return iter(["k"])

    def __len__(self) -> int:
        return 1

    def items(self) -> Any:
        return [("k", "ok")]


class Color(enum.Enum):
    RED = "red"


class Level(enum.IntEnum):
    LOW = 1


def _attrs_value() -> Any:
    attrs = pytest.importorskip("attrs")

    @attrs.define
    class AttrsBody:
        body: str

    return AttrsBody(W)


def _dict_sub() -> Any:
    value = DictSub(a="ok")
    value.body = W  # type: ignore[attr-defined]
    return value


def _list_sub() -> Any:
    value = ListSub(["ok"])
    value.body = W  # type: ignore[attr-defined]
    return value


def _dataclass_extra() -> Any:
    value = PlainDataclass()
    value.body = W  # type: ignore[attr-defined]
    return value


def _cycle() -> Any:
    value: list[Any] = []
    value.append(value)
    return value


def _deep() -> Any:
    value: list[Any] = []
    for _ in range(40):
        value = [value]
    return value


DENY_CASES: list[Any] = [
    # q1 (b76b72d): runtime behaviour differs from the projected state
    pytest.param(lambda: GetattributeDataclass("ok"), id="dataclass-getattribute"),
    pytest.param(lambda: GetattributeModel(body="ok"), id="model-getattribute"),
    pytest.param(lambda: StrMixinEnum.A, id="enum-str-mixin-data"),
    pytest.param(lambda: AttrEnum.A, id="enum-extra-attribute"),
    pytest.param(MutatingComputed, id="computed-field-mutates-self"),
    pytest.param(FlippingComputed, id="computed-field-flips"),
    pytest.param(lambda: ShadowedExtra(foo="ok"), id="property-shadows-extra"),
    # p1 (385632f): opaque or partially projected objects
    pytest.param(lambda: collections.deque([W]), id="deque"),
    pytest.param(lambda: (x for x in [W]), id="generator"),
    pytest.param(lambda: memoryview(W.encode()), id="memoryview"),
    pytest.param(lambda: array.array("u", W), id="array"),
    pytest.param(Slotted, id="slots"),
    pytest.param(MixedSlots, id="mixed-slots"),
    pytest.param(SlottedChild, id="slotted-base-child"),
    pytest.param(_attrs_value, id="attrs-define"),
    pytest.param(PrivateModel, id="pydantic-private"),
    pytest.param(ComputedModel, id="pydantic-computed-field"),
    pytest.param(lambda: collections.defaultdict(lambda: W), id="defaultdict"),
    pytest.param(_dict_sub, id="dict-subclass-attr"),
    pytest.param(_list_sub, id="list-subclass-attr"),
    pytest.param(_dataclass_extra, id="dataclass-extra-attr"),
    pytest.param(lambda: ValueError(W), id="exception"),
    pytest.param(LyingMapping, id="lying-mapping"),
    pytest.param(lambda: W.encode("utf-16-le"), id="utf16-bytes"),
    pytest.param(lambda: b"forbidden\xffword", id="undecodable-bytes"),
    # now-denied rich types
    pytest.param(PlainModel, id="pydantic-model"),
    pytest.param(PlainDataclass, id="dataclass"),
    pytest.param(lambda: Color.RED, id="enum"),
    pytest.param(lambda: Level.LOW, id="int-enum"),
    pytest.param(lambda: dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc), id="datetime"),
    pytest.param(lambda: dt.date(2026, 1, 1), id="date"),
    pytest.param(lambda: dt.time(12, 0), id="time"),
    pytest.param(lambda: uuid.UUID(int=1), id="uuid"),
    pytest.param(lambda: Path("/tmp/x"), id="path"),
    pytest.param(lambda: decimal.Decimal("1.5"), id="decimal"),
    pytest.param(lambda: {"ok"}, id="set"),
    pytest.param(lambda: frozenset({"ok"}), id="frozenset"),
    pytest.param(lambda: StrSub("ok"), id="str-subclass"),
    pytest.param(lambda: IntSub(1), id="int-subclass"),
    pytest.param(lambda: FloatSub(1.5), id="float-subclass"),
    pytest.param(lambda: BytesSub(b"ok"), id="bytes-subclass"),
    pytest.param(lambda: Pair("a", "b"), id="namedtuple"),
    # subclasses whose metaclass claims equality with the base type
    pytest.param(_meta_str, id="metaclass-eq-str"),
    pytest.param(lambda: MetaInt(1), id="metaclass-eq-int"),
    pytest.param(lambda: MetaList([W]), id="metaclass-eq-list"),
    pytest.param(lambda: MetaTuple((W,)), id="metaclass-eq-tuple"),
    # edge values
    pytest.param(lambda: float("nan"), id="nan"),
    pytest.param(lambda: float("inf"), id="inf"),
    pytest.param(lambda: float("-inf"), id="negative-inf"),
    pytest.param(lambda: {1: "a"}, id="int-key"),
    pytest.param(lambda: {None: 1}, id="none-key"),
    pytest.param(lambda: {True: 1}, id="bool-key"),
    pytest.param(lambda: {Color.RED: 1}, id="enum-key"),
    pytest.param(lambda: {("a", "b"): 1}, id="tuple-key"),
    pytest.param(lambda: {StrSub("k"): 1}, id="str-subclass-key"),
    pytest.param(lambda: 10**5000, id="huge-int"),
    pytest.param(_deep, id="deep-nesting"),
    pytest.param(_cycle, id="cycle"),
    pytest.param(lambda: "forbidden\x00word", id="nul-spliced-string"),
    pytest.param(lambda: {"memo": "forbidden\x01word"}, id="control-spliced-value"),
    pytest.param(lambda: {"forbidden\x08word": "ok"}, id="control-spliced-key"),
    pytest.param(lambda: [b"forbidden\x0bword"], id="control-spliced-bytes"),
    pytest.param(lambda: (bytearray(b"forbidden\x1fword"),), id="control-spliced-bytearray"),
]


def _nested(make: Callable[[], Any]) -> Callable[[], Any]:
    return lambda: {"outer": [{"inner": make()}]}


# --- unit level: projector, binder and output digest deny alike ----------------------


@pytest.mark.parametrize("make", DENY_CASES)
@pytest.mark.parametrize("wrap", [False, True], ids=["top", "nested"])
def test_projector_denies(make: Callable[[], Any], wrap: bool) -> None:
    value = _nested(make)() if wrap else make()
    with pytest.raises(GovernancePayloadError) as excinfo:
        governance_payloads_for_enforcement(value)
    assert excinfo.value.rule_id in {UNEVALUABLE, "GOVERNANCE-PAYLOAD-OVERSIZE"}


@pytest.mark.parametrize("codepoint", [i for i in range(32) if i not in (9, 10, 13)])
def test_json_escaping_cannot_hide_control_splices(codepoint: int) -> None:
    text = "forbidden" + chr(codepoint) + "word"
    for value in (text, {"memo": text}, {text: "ok"}, [text], (text,), text.encode()):
        with pytest.raises(GovernancePayloadError):
            governance_payloads_for_enforcement(value)


def _one_arg(value: object) -> None:
    pass


@pytest.mark.parametrize("make", DENY_CASES)
@pytest.mark.parametrize("wrap", [False, True], ids=["top", "nested"])
def test_binder_denies(make: Callable[[], Any], wrap: bool) -> None:
    value = _nested(make)() if wrap else make()
    with pytest.raises(ArgumentNotDigestible):
        canonical_argument_digest(_one_arg, (value,), {})


@pytest.mark.parametrize("make", DENY_CASES)
@pytest.mark.parametrize("wrap", [False, True], ids=["top", "nested"])
def test_output_digest_denies(make: Callable[[], Any], wrap: bool) -> None:
    value = _nested(make)() if wrap else make()
    assert digest_output(value) is None


# --- dispatcher level, compatibility profile ------------------------------------------


@pytest.mark.parametrize("make", DENY_CASES)
def test_compat_input_denies_before_side_effect(make: Callable[[], Any]) -> None:
    calls: list[object] = []

    @_compat_guard()
    def f(x: object) -> str:
        calls.append(x)
        return "done"

    with pytest.raises(ConstitutionalViolationError):
        f.issue_grant(make())  # type: ignore[attr-defined]
    with pytest.raises(ConstitutionalViolationError):
        f(make(), decision_receipt=_receipt("f"))
    assert calls == []


@pytest.mark.parametrize("make", DENY_CASES)
def test_compat_output_is_withheld(make: Callable[[], Any]) -> None:
    calls: list[object] = []

    @_compat_guard()
    def f() -> object:
        calls.append(1)
        return make()

    returned: list[object] = []
    with pytest.raises(ConstitutionalViolationError):
        returned.append(f(decision_receipt=_receipt("f")))
    assert returned == []
    assert calls == [1]


# --- dispatcher level, signed production path (q2/q3) ---------------------------------


@pytest.mark.parametrize("make", DENY_CASES)
def test_production_issue_grant_denies(
    make: Callable[[], Any], production_guard: Callable[[], GovernedCallable]
) -> None:
    calls: list[object] = []

    def transfer(memo: object) -> str:
        calls.append(memo)
        return "sent"

    wrapped = production_guard()(transfer)
    with pytest.raises(ConstitutionalViolationError):
        wrapped.issue_grant(make())  # type: ignore[attr-defined]
    assert calls == []


@pytest.mark.parametrize("make", DENY_CASES)
def test_production_output_denies_records_partial_and_replay_withholds(
    make: Callable[[], Any], production_guard: Callable[[], GovernedCallable]
) -> None:
    guard = production_guard()
    calls: list[object] = []

    def act(a: str) -> object:
        calls.append(a)
        return [make()]

    wrapped = guard(act)
    grant = wrapped.issue_grant("x")  # type: ignore[attr-defined]
    returned: list[object] = []
    with pytest.raises(ConstitutionalViolationError):
        returned.append(wrapped("x", execution_grant=grant, execution_attempt_id="a1"))
    assert guard._ledger.attempt_status_for_grant(grant.grant_id) is AttemptStatus.PARTIAL
    with pytest.raises(LegitimacyInvariantError, match="attempt already partial"):
        returned.append(wrapped("x", execution_grant=grant, execution_attempt_id="a1"))
    assert returned == []
    assert calls == ["x"]


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda: StrMixinEnum.A, id="enum-str-mixin-data"),
        pytest.param(MutatingComputed, id="computed-field-mutates-self"),
        pytest.param(PlainDataclass, id="dataclass"),
    ],
)
def test_production_async_output_denies(
    make: Callable[[], Any], production_guard: Callable[[], GovernedCallable]
) -> None:
    guard = production_guard()

    async def act(a: str) -> object:
        return make()

    wrapped = guard(act)
    grant = wrapped.issue_grant("x")  # type: ignore[attr-defined]
    with pytest.raises(ConstitutionalViolationError):
        asyncio.run(wrapped("x", execution_grant=grant))
    assert guard._ledger.attempt_status_for_grant(grant.grant_id) is AttemptStatus.PARTIAL


# --- control rows: plain JSON payloads carrying the keyword deny by rule --------------

CONTROL_CASES: list[Any] = [
    pytest.param(lambda: W, id="str"),
    pytest.param(lambda: {"note": W}, id="dict"),
    pytest.param(lambda: [{"a": (1, W)}], id="nested-tuple"),
    pytest.param(lambda: W.encode(), id="bytes"),
]


def _assert_rule(excinfo: pytest.ExceptionInfo[ConstitutionalViolationError]) -> None:
    assert not isinstance(excinfo.value, GovernancePayloadError)
    assert excinfo.value.rule_id == "BAD-WORD"


@pytest.mark.parametrize("make", CONTROL_CASES)
def test_control_keyword_payload_denies_by_rule(
    make: Callable[[], Any], production_guard: Callable[[], GovernedCallable]
) -> None:
    calls: list[object] = []

    @_compat_guard()
    def f(x: object) -> str:
        calls.append(x)
        return "done"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        f(make(), decision_receipt=_receipt("f"))
    _assert_rule(excinfo)

    @_compat_guard()
    def out() -> object:
        return make()

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        out(decision_receipt=_receipt("out"))
    _assert_rule(excinfo)

    def transfer(memo: object) -> str:
        calls.append(memo)
        return "sent"

    with pytest.raises(ConstitutionalViolationError) as excinfo:
        production_guard()(transfer).issue_grant(make())  # type: ignore[attr-defined]
    _assert_rule(excinfo)
    assert calls == []


# --- positive rows: benign JSON-native payloads pass and are returned -----------------


def _benign() -> dict[str, Any]:
    return {
        "note": "hello",
        "whitespace": "ordinary\ttext\nwith\rline endings",
        "items": [1, -2, 2.5, True, False, None, "x"],
        "nested": {"deep": [{"k": "v"}]},
        "raw": b"plain bytes",
        "buf": bytearray(b"more"),
        "pair": ("a", 1),
        "big": 10**30,
        "empty": {},
    }


def test_benign_payload_projects_tuple_and_bytes_as_json() -> None:
    [payload] = governance_payloads_for_enforcement(_benign())
    assert '"pair": ["a", 1]' in payload
    assert '"raw": "plain bytes"' in payload
    assert '"buf": "more"' in payload


def test_benign_payload_and_output_pass_compat() -> None:
    calls: list[object] = []

    @_compat_guard()
    def f(x: object, *rest: object, **extra: object) -> object:
        calls.append(x)
        return (x, rest, extra)

    result = f(_benign(), "a", ("b",), k=[1], decision_receipt=_receipt("f"))
    assert result == (_benign(), ("a", ("b",)), {"k": [1]})
    assert len(calls) == 1


def test_benign_payload_and_output_pass_production_with_recovery(
    production_guard: Callable[[], GovernedCallable],
) -> None:
    guard = production_guard()
    calls: list[object] = []

    def act(payload: dict[str, Any]) -> object:
        calls.append(1)
        return [payload, (1, 2.0, None)]

    wrapped = guard(act)
    grant = wrapped.issue_grant(_benign())  # type: ignore[attr-defined]
    first = wrapped(_benign(), execution_grant=grant, execution_attempt_id="a1")
    assert first == [_benign(), (1, 2.0, None)]
    assert guard._ledger.attempt_status_for_grant(grant.grant_id) is AttemptStatus.COMPLETED
    replay = wrapped(_benign(), execution_grant=grant, execution_attempt_id="a1")
    assert replay == first
    assert calls == [1]


# --- parity: the three enforcement points share one acceptance set -------------------

ACCEPT_CASES: list[Any] = [
    pytest.param(lambda: "text", id="str"),
    pytest.param(lambda: 7, id="int"),
    pytest.param(lambda: 10**30, id="big-int"),
    pytest.param(lambda: -0.5, id="float"),
    pytest.param(lambda: True, id="bool"),
    pytest.param(lambda: None, id="none"),
    pytest.param(lambda: b"utf8", id="bytes"),
    pytest.param(lambda: bytearray(b"utf8"), id="bytearray"),
    pytest.param(lambda: ("a", [1]), id="tuple"),
    pytest.param(_benign, id="benign-nested"),
]


@pytest.mark.parametrize("make", ACCEPT_CASES)
def test_parity_accepts(make: Callable[[], Any]) -> None:
    governance_payloads_for_enforcement(make())
    canonical_argument_digest(_one_arg, (make(),), {})
    assert digest_output(make()) is not None


@pytest.mark.parametrize("make", DENY_CASES)
def test_parity_denies(make: Callable[[], Any]) -> None:
    verdicts = []
    for check in (
        lambda: governance_payloads_for_enforcement(make()),
        lambda: canonical_argument_digest(_one_arg, (make(),), {}),
    ):
        try:
            check()
        except ConstitutionalViolationError:
            verdicts.append("deny")
        else:
            verdicts.append("allow")
    verdicts.append("deny" if digest_output(make()) is None else "allow")
    assert verdicts == ["deny", "deny", "deny"]


def test_binder_does_not_stringify_scope_before_validation() -> None:
    seen: list[str] = []

    class Loud:
        def __str__(self) -> str:
            seen.append("str")
            return "scope"

    def g(scope: object) -> None:
        pass

    with pytest.raises(ArgumentNotDigestible):
        bind_invocation(g, (Loud(),), {}, strict_context=True)
    assert seen == []
