# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Shared serialization helpers for governance validation payloads.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import asdict, is_dataclass
from typing import Any

from acgs_lite.errors import ConstitutionalViolationError

_MAX_GOVERNANCE_PAYLOAD_CHARS = 10_000

_OVERSIZE_RULE_ID = "GOVERNANCE-PAYLOAD-OVERSIZE"
_UNEVALUABLE_RULE_ID = "GOVERNANCE-PAYLOAD-UNEVALUABLE"

# JSON escapes these invisible controls, hiding keyword splices from the matcher.
# Keep ordinary text whitespace; the engine intentionally preserves it too.
_HIDDEN_JSON_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _has_hidden_json_control(text: str) -> bool:
    return _HIDDEN_JSON_CONTROL.search(text) is not None


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
        f"governed value #{index} of type {type(value).__name__} is not JSON-native; "
        "governed values may only contain exact str/int/finite float/bool/None, UTF-8 "
        "bytes, list/tuple and dict with str keys. Convert rich objects first (e.g. "
        'model_dump(mode="json"), isoformat(), str(uuid)); pass handles via closure or '
        "functools.partial, not as governed values",
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


# --- JSON-only contract ----------------------------------------------------------
#
# Governed values may only be exact built-in JSON-native values. Types are matched
# exactly (``type(v) is ...``), never with ``isinstance``, so no subclass, Enum,
# dataclass or model can supply behaviour that differs from its projected state, and
# the projector never calls a method that the value's type could override. Anything
# outside the contract denies, on input and on output alike. Use chained ``is``
# checks only: ``kind in {str, ...}`` would consult a metaclass ``__eq__``/``__hash__``.


class _Projector:
    """Recursively project a governed value to JSON text content, failing closed.

    Accepts ``None``, ``bool``, ``int``, finite ``float``, ``str``, strict-UTF-8
    ``bytes``/``bytearray`` without NUL (projected as text), ``list``, ``tuple``
    (projected as a list) and ``dict`` with ``str`` keys, all matched exactly. Every
    other value, a reference cycle, nesting deeper than 32 levels and budget
    exhaustion raise :class:`GovernancePayloadError`. Hidden C0 controls in any
    text or key also deny; ordinary tab/newline/carriage-return remain valid.
    There is no skip mode.

    Every text leaf (``str`` value, decoded bytes, dict key) is recorded in
    ``texts`` so the caller can validate it raw as well as inside the JSON blob.
    """

    __slots__ = ("budget", "index", "path", "texts")

    def __init__(self, *, index: int, budget: _Budget) -> None:
        self.index = index
        self.budget = budget
        self.path: set[int] = set()
        self.texts: list[str] = []

    def _text(self, value: bytes | bytearray) -> str:
        try:
            text = bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            raise _unevaluable(value, self.index) from None
        if _has_hidden_json_control(text):
            # Includes NUL padding used to disguise UTF-16/UTF-32 text.
            raise _unevaluable(value, self.index)
        self.texts.append(text)
        return text

    def project(self, value: Any, depth: int = 0) -> Any:
        if depth > _MAX_PROJECTION_DEPTH:
            raise GovernancePayloadError(
                f"governed value #{self.index} nests deeper than {_MAX_PROJECTION_DEPTH} "
                "levels and cannot be evaluated in full",
                rule_id=_UNEVALUABLE_RULE_ID,
            )
        kind = type(value)
        if value is None or kind is str or kind is int or kind is bool:
            if kind is str:
                if _has_hidden_json_control(value):
                    raise _unevaluable(value, self.index)
                self.texts.append(value)
            self.budget.spend(len(value) if kind is str else 1, self.index)
            return value
        if kind is float:
            if not math.isfinite(value):
                raise _unevaluable(value, self.index)
            self.budget.spend(1, self.index)
            return value
        if kind is bytes or kind is bytearray:
            text = self._text(value)
            self.budget.spend(len(text), self.index)
            return text
        if kind is not dict and kind is not list and kind is not tuple:
            raise _unevaluable(value, self.index)
        marker = id(value)
        if marker in self.path:
            raise GovernancePayloadError(
                f"governed value #{self.index} contains a reference cycle",
                rule_id=_UNEVALUABLE_RULE_ID,
            )
        self.path.add(marker)
        try:
            self.budget.spend(2, self.index)
            if kind is dict:
                return self._mapping(value, depth)
            return [self.project(item, depth + 1) for item in value]
        finally:
            self.path.discard(marker)

    def _mapping(self, mapping: dict[Any, Any], depth: int) -> dict[str, Any]:
        projected: dict[str, Any] = {}
        for key in dict.keys(mapping):
            if type(key) is not str:
                raise _unevaluable(key, self.index)
            if _has_hidden_json_control(key):
                raise _unevaluable(key, self.index)
            self.texts.append(key)
            self.budget.spend(len(key), self.index)
            projected[key] = self.project(dict.__getitem__(mapping, key), depth + 1)
        return projected


def _enforcement_payloads(value: Any, index: int, *, max_chars: int) -> list[str]:
    """Project one value for enforcement; an empty list means nothing to evaluate.

    The first payload is the whole value (raw text, or its JSON blob). It is
    followed by every distinct non-empty text leaf and key as raw text. Inside the
    blob a tab or newline is the two characters ``\\t``/``\\n`` and every leaf sits
    after a quote, so ``\\s+``/``\\b`` rules and ``^``/``$`` anchors only see the
    text as written when it is evaluated on its own.
    """
    if value is None:
        return []
    if type(value) is str:
        if _has_hidden_json_control(value):
            raise _unevaluable(value, index)
        return [value] if value else []
    projector = _Projector(index=index, budget=_Budget(max_chars))
    try:
        projected = projector.project(value)
    except GovernancePayloadError:
        raise
    except Exception:
        # A dict mutated during projection, ...: the value could not be read in
        # full, so it denies like any other unevaluable value.
        raise _unevaluable(value, index) from None
    if type(projected) is str:
        return [projected] if projected else []
    try:
        blob = json.dumps(projected, ensure_ascii=False, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        # ValueError includes Python's int-to-str digit limit for huge integers.
        raise _unevaluable(value, index) from None
    leaves = dict.fromkeys(text for text in projector.texts if text)
    return [blob, *leaves]


def governance_payloads_for_enforcement(
    *values: Any,
    max_chars: int = _MAX_GOVERNANCE_PAYLOAD_CHARS,
) -> list[str]:
    """Project every governed value for enforcement, failing closed.

    Used identically for call arguments and return values. Never truncates: a
    payload longer than ``max_chars`` raises :class:`GovernancePayloadError`.
    ``None`` and ``""`` are skipped; other scalars are evaluated.

    JSON-only contract (exact types, ``type(v) is T``; never ``isinstance``):
    ``str``, ``int``, ``bool``, finite ``float``, ``None``; ``bytes``/``bytearray``
    that decode as strict UTF-8 with no NUL (evaluated as text); ``list``;
    ``tuple`` (evaluated as a list); ``dict`` whose keys are all exact ``str``.
    Text and keys containing C0 controls other than tab, newline and carriage
    return deny: JSON escaping would conceal them from rule matching. Tab,
    newline and carriage return stay valid. Every distinct non-empty nested text
    and key is also returned raw, after its value's JSON payload.

    Everything else denies with ``GOVERNANCE-PAYLOAD-UNEVALUABLE`` at any depth:
    ``Enum`` members, dataclasses, pydantic models, ``datetime``/``date``/``time``,
    ``UUID``, paths, ``Decimal``, ``set``/``frozenset``, ``NamedTuple``, other
    mappings and sequences, subclasses of any accepted type, non-``str`` dict keys,
    NaN and infinities. A reference cycle or nesting deeper than 32 levels also
    denies. Convert rich objects to JSON-native values before the governed call,
    e.g. ``model.model_dump(mode="json")``, ``value.isoformat()``, ``str(uuid)``.
    """
    payloads: list[str] = []
    accounted = 0
    for index, value in enumerate(values):
        for payload in _enforcement_payloads(value, index, max_chars=max_chars):
            if len(payload) > max_chars:
                raise GovernancePayloadError(
                    f"governed value #{index} is {len(payload)} characters; the governance "
                    f"payload limit is {max_chars} and oversize payloads are denied, "
                    "not truncated",
                    rule_id=_OVERSIZE_RULE_ID,
                )
            payloads.append(payload)
        accounted += 1
    if accounted != len(values):
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
