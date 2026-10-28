# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Shared serialization helpers for governance validation payloads.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import datetime
import json
import types
import typing
import uuid
from dataclasses import asdict, fields, is_dataclass
from decimal import Decimal
from enum import Enum
from pathlib import Path, PosixPath, PurePath, PurePosixPath, PureWindowsPath, WindowsPath
from typing import Any

from pydantic import BaseModel

from acgs_lite.errors import ConstitutionalViolationError

_MAX_GOVERNANCE_PAYLOAD_CHARS = 10_000

_OVERSIZE_RULE_ID = "GOVERNANCE-PAYLOAD-OVERSIZE"
_UNEVALUABLE_RULE_ID = "GOVERNANCE-PAYLOAD-UNEVALUABLE"


class GovernancePayloadError(ConstitutionalViolationError):
    """A governed payload could not be evaluated in full, so the call is denied."""

    __slots__ = ()


def _truncate_payload(payload: str, *, max_chars: int) -> str:
    if len(payload) <= max_chars:
        return payload
    suffix = "… [truncated]"
    return payload[: max_chars - len(suffix)] + suffix


def _to_jsonable(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return asdict(value)
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return model_dump(mode="json")
    dict_method = getattr(value, "dict", None)
    if callable(dict_method):
        return dict_method()
    if isinstance(value, set):
        return sorted(value, key=str)
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, (dict, list)):
        return value
    raw_dict = getattr(value, "__dict__", None)
    if isinstance(raw_dict, dict) and raw_dict:
        return raw_dict
    return value


def serialize_for_governance(value: Any, *, max_chars: int = _MAX_GOVERNANCE_PAYLOAD_CHARS) -> str:
    """Convert a value into a stable string payload for previews and logging.

    Preview only, not an enforcement input: it truncates oversize payloads and
    returns ``""`` for scalars and opaque objects. Enforcement paths use
    :func:`governance_payloads_for_enforcement`.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return _truncate_payload(value, max_chars=max_chars)

    jsonable = _to_jsonable(value)
    if jsonable is value and not isinstance(value, (dict, list, tuple, set)):
        return ""

    try:
        payload = json.dumps(jsonable, default=str, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        payload = str(jsonable)
    return _truncate_payload(payload, max_chars=max_chars)


def iter_governance_payloads(
    *values: Any, max_chars: int = _MAX_GOVERNANCE_PAYLOAD_CHARS
) -> list[str]:
    """Collect non-empty preview payloads (truncating; not an enforcement input)."""
    payloads: list[str] = []
    for value in values:
        payload = serialize_for_governance(value, max_chars=max_chars)
        if payload:
            payloads.append(payload)
    return payloads


def _unevaluable(value: Any, index: int) -> GovernancePayloadError:
    return GovernancePayloadError(
        f"governed value #{index} of type {type(value).__name__} is not a projectable "
        "type; governed values may only contain str/int/float/bool/None, exact "
        "dict/list/tuple/set/frozenset, dataclasses, pydantic v2 models and well-known "
        "value types. Pass handles via closure or functools.partial, not as governed values",
        rule_id=_UNEVALUABLE_RULE_ID,
    )


_MAX_PROJECTION_DEPTH = 32


class _Budget:
    """Lower bound on the serialized length, so shared-reference blowups stop early."""

    __slots__ = ("max_chars", "used")

    def __init__(self, max_chars: int) -> None:
        self.max_chars = max_chars
        self.used = 0

    def spend(self, chars: int, index: int) -> None:
        self.used += max(chars, 1)
        if self.used > self.max_chars:
            raise _oversize(index, self.used, self.max_chars)


def _oversize(index: int, size: int, max_chars: int) -> GovernancePayloadError:
    return GovernancePayloadError(
        f"governed value #{index} is at least {size} characters; the governance "
        f"payload limit is {max_chars} and oversize payloads are denied, not truncated",
        rule_id=_OVERSIZE_RULE_ID,
    )


# --- closed type allowlist --------------------------------------------------------
#
# The projector never asks a value what it contains through methods its own type can
# override (``items()``, ``model_dump()``, ``dict()``, ``__dict__``, ``__getattr__``).
# Types are matched exactly (``type(v) is ...``), never with ``isinstance``, so a
# subclass that adds hidden state is not mistaken for its base. Anything outside the
# allowlist denies, on input and on output alike.

_PRIMITIVE_TYPES: frozenset[type] = frozenset({str, int, float, bool})
_TEXT_TYPES: frozenset[type] = frozenset(
    {Decimal, uuid.UUID, PurePath, PurePosixPath, PureWindowsPath, Path, PosixPath, WindowsPath}
)
_ISOFORMAT_TYPES: frozenset[type] = frozenset({datetime.datetime, datetime.date, datetime.time})
_SEQUENCE_TYPES: frozenset[type] = frozenset({list, tuple})
_SET_TYPES: frozenset[type] = frozenset({set, frozenset})

# Interpreter-level accessors: a class (or its metaclass) cannot override these.
_TYPE_NAMESPACE: Any = type.__dict__["__dict__"]
_TYPE_MRO: Any = type.__dict__["__mro__"]
_TYPE_FLAGS: Any = type.__dict__["__flags__"]
_TYPE_LAYOUT: tuple[Any, ...] = tuple(
    type.__dict__[name]
    for name in ("__basicsize__", "__itemsize__", "__dictoffset__", "__weakrefoffset__")
)
_HEAPTYPE = 1 << 9
# Bases that add no instance state; ``typing.Generic`` is a C type on 3.12+.
_STATELESS_BASES: frozenset[type] = frozenset({object, typing.Generic})  # type: ignore[arg-type]


def _layout(kind: type) -> tuple[int, ...]:
    return tuple(descriptor.__get__(kind) for descriptor in _TYPE_LAYOUT)


class _PlainReference:
    """Layout of a Python class whose only instance state is its ``__dict__``."""


class _ModelReference(BaseModel):
    """Layout of a pydantic model subclass that adds no instance storage."""


_PLAIN_LAYOUT = _layout(_PlainReference)
_MODEL_LAYOUT = _layout(_ModelReference)
_MODEL_NAMESPACE = _TYPE_NAMESPACE.__get__(BaseModel)
_MODEL_SLOTS = frozenset(BaseModel.__slots__)
_MODEL_SIDE_STATE = ("__pydantic_extra__", "__pydantic_private__")


def _instance_state(value: Any, layout: tuple[int, ...], slots: frozenset[str]) -> Any:
    """The instance ``__dict__`` when it is provably all of ``value``'s state, else ``None``.

    The layout must match a reference class (no extra slots, no C-level storage), every
    class in the MRO must be Python-defined with no slot descriptors beyond ``slots``,
    and ``__dict__`` must resolve to the interpreter's own descriptor, which is then
    called directly so a ``__dict__`` property cannot substitute a different mapping.
    """
    kind = type(value)
    if _layout(kind) != layout:
        return None
    descriptor: Any = None
    namespaces: list[Any] = []
    for klass in _TYPE_MRO.__get__(kind):
        if klass in _STATELESS_BASES:
            continue
        if not _TYPE_FLAGS.__get__(klass) & _HEAPTYPE:
            return None
        namespace = _TYPE_NAMESPACE.__get__(klass)
        namespaces.append(namespace)
        for name, member in namespace.items():
            if type(member) is types.MemberDescriptorType and name not in slots:
                return None
        if descriptor is None and "__dict__" in namespace:
            descriptor = namespace["__dict__"]
    if type(descriptor) is not types.GetSetDescriptorType:
        return None
    state = descriptor.__get__(value, kind)
    if type(state) is not dict:
        return None
    # A class-level descriptor (e.g. a property) under a state key decides what
    # attribute access returns, so the stored value would not be what the callee reads.
    for namespace in namespaces:
        for name in state:
            if name in namespace and hasattr(type(namespace[name]), "__get__"):
                return None
    return state


class _Projector:
    """Recursively project a governed value to JSON-safe content, failing closed.

    Only allowlisted types project; every other value, an undecodable or NUL-bearing
    byte string, a reference cycle, nesting deeper than 32 levels and budget
    exhaustion raise :class:`GovernancePayloadError`. There is no skip mode.
    """

    __slots__ = ("budget", "index", "path")

    def __init__(self, *, index: int, budget: _Budget) -> None:
        self.index = index
        self.budget = budget
        self.path: set[int] = set()

    def scalar(self, value: Any) -> tuple[bool, Any]:
        """Project allowlisted leaf types; ``(False, None)`` when ``value`` is not one."""
        kind = type(value)
        if value is None or kind in _PRIMITIVE_TYPES:
            return True, value
        if kind in _TEXT_TYPES:
            return True, str(value)
        if kind in _ISOFORMAT_TYPES:
            return True, value.isoformat()
        if kind is bytes or kind is bytearray:
            return True, self._text(value)
        return False, None

    def _text(self, value: bytes | bytearray) -> str:
        try:
            text = bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            raise _unevaluable(value, self.index) from None
        if "\x00" in text:
            # NUL bytes are how UTF-16/UTF-32 text hides ASCII words from keyword rules.
            raise _unevaluable(value, self.index)
        return text

    def project(self, value: Any, depth: int = 0) -> Any:
        if depth > _MAX_PROJECTION_DEPTH:
            raise GovernancePayloadError(
                f"governed value #{self.index} nests deeper than {_MAX_PROJECTION_DEPTH} "
                "levels and cannot be evaluated in full",
                rule_id=_UNEVALUABLE_RULE_ID,
            )
        if issubclass(type(value), Enum):
            return self.project(object.__getattribute__(value, "_value_"), depth + 1)
        known, projected = self.scalar(value)
        if known:
            self.budget.spend(len(projected) if isinstance(projected, str) else 1, self.index)
            return projected
        marker = id(value)
        if marker in self.path:
            raise GovernancePayloadError(
                f"governed value #{self.index} contains a reference cycle",
                rule_id=_UNEVALUABLE_RULE_ID,
            )
        self.path.add(marker)
        try:
            return self._project_compound(value, depth)
        finally:
            self.path.discard(marker)

    def _project_compound(self, value: Any, depth: int) -> Any:
        kind = type(value)
        self.budget.spend(2, self.index)
        if kind is dict:
            return self._mapping(value, depth)
        if kind in _SEQUENCE_TYPES:
            return [self.project(item, depth + 1) for item in value]
        if kind in _SET_TYPES:
            return sorted((self.project(item, depth + 1) for item in value), key=repr)
        if issubclass(kind, BaseModel):
            return self._mapping(self._model_state(value), depth)
        if is_dataclass(kind):
            return self._mapping(self._dataclass_state(value), depth)
        raise _unevaluable(value, self.index)

    def _dataclass_state(self, value: Any) -> dict[str, Any]:
        state = _instance_state(value, _PLAIN_LAYOUT, frozenset())
        names = {f.name for f in fields(type(value))}
        if state is None or set(state) != names:
            raise _unevaluable(value, self.index)
        return dict(state)

    def _model_state(self, value: Any) -> dict[str, Any]:
        """Field, extra, private and computed values, read without any serializer."""
        kind = type(value)
        state = _instance_state(value, _MODEL_LAYOUT, _MODEL_SLOTS)
        if state is None or set(state) != set(kind.model_fields):
            raise _unevaluable(value, self.index)
        values = dict(state)
        for slot in _MODEL_SIDE_STATE:
            try:
                side = _MODEL_NAMESPACE[slot].__get__(value, kind)
            except AttributeError:  # an unset slot (e.g. RootModel) holds nothing
                continue
            if side is None:
                continue
            if type(side) is not dict:
                raise _unevaluable(value, self.index)
            for key, item in side.items():
                self._merge(values, key, item)
        for name in list(kind.model_computed_fields):
            self._merge(values, name, object.__getattribute__(value, name))
        return values

    def _merge(self, values: dict[Any, Any], key: Any, item: Any) -> None:
        if key in values:
            raise self._collision()
        values[key] = item

    def _collision(self) -> GovernancePayloadError:
        return GovernancePayloadError(
            f"governed value #{self.index} has keys that collide after projection",
            rule_id=_UNEVALUABLE_RULE_ID,
        )

    def _key(self, key: Any) -> str:
        if issubclass(type(key), Enum):
            key = object.__getattribute__(key, "_value_")
        known, key_value = self.scalar(key)
        if not known:
            raise _unevaluable(key, self.index)
        return key_value if type(key_value) is str else json.dumps(key_value)

    def _mapping(self, mapping: dict[Any, Any], depth: int) -> dict[str, Any]:
        projected: dict[str, Any] = {}
        for key, item in mapping.items():
            name = self._key(key)
            if name in projected:
                raise self._collision()
            self.budget.spend(len(name), self.index)
            projected[name] = self.project(item, depth + 1)
        return projected


def _enforcement_payload(value: Any, index: int, *, max_chars: int) -> str | None:
    """Project one value for enforcement; ``None`` means nothing to evaluate."""
    if value is None:
        return None
    if type(value) is str:
        return value
    projector = _Projector(index=index, budget=_Budget(max_chars))
    try:
        projected = projector.project(value)
    except GovernancePayloadError:
        raise
    except Exception:
        # A computed field that raises, a dict mutated during projection, ...: the
        # value could not be read in full, so it denies like any other opaque value.
        raise _unevaluable(value, index) from None
    if projected is None:
        return None
    if type(projected) is str:
        return projected
    try:
        return json.dumps(projected, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        raise _unevaluable(value, index) from None


def governance_payloads_for_enforcement(
    *values: Any,
    max_chars: int = _MAX_GOVERNANCE_PAYLOAD_CHARS,
) -> list[str]:
    """Project every governed value for enforcement, failing closed.

    Used identically for call arguments and return values. Never truncates: a
    payload longer than ``max_chars`` raises :class:`GovernancePayloadError`.
    ``None`` and ``""`` are skipped; other scalars are evaluated.

    Projectable (closed allowlist, exact types only): ``str``/``int``/``float``/
    ``bool``/``None``; ``datetime``/``date``/``time`` (``isoformat()``), ``UUID``,
    paths and ``Decimal`` (``str``), ``Enum`` (its value); ``bytes``/``bytearray``
    that decode as strict UTF-8 with no NUL; ``dict`` with scalar keys;
    ``list``/``tuple``/``set``/``frozenset``; dataclass instances whose ``__dict__``
    holds exactly their fields (no slots); pydantic v2 models (fields, extras,
    private attributes and computed fields, read without serializers).

    Everything else denies with ``GOVERNANCE-PAYLOAD-UNEVALUABLE`` at any depth,
    including subclasses of the container types, other ``Mapping``s, plain objects,
    ``NamedTuple``, pydantic v1 models, generators, buffers and exceptions. A
    reference cycle or nesting deeper than 32 levels also denies.
    """
    payloads: list[str] = []
    skipped = 0
    for index, value in enumerate(values):
        payload = _enforcement_payload(value, index, max_chars=max_chars)
        if not payload:
            skipped += 1
            continue
        if len(payload) > max_chars:
            raise GovernancePayloadError(
                f"governed value #{index} is {len(payload)} characters; the governance "
                f"payload limit is {max_chars} and oversize payloads are denied, not truncated",
                rule_id=_OVERSIZE_RULE_ID,
            )
        payloads.append(payload)
    if len(payloads) + skipped != len(values):
        raise GovernancePayloadError(
            "governed values were not all accounted for", rule_id=_UNEVALUABLE_RULE_ID
        )
    return payloads


__all__ = [
    "GovernancePayloadError",
    "governance_payloads_for_enforcement",
    "iter_governance_payloads",
    "serialize_for_governance",
]
