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
import uuid
from dataclasses import asdict, fields, is_dataclass
from decimal import Decimal
from enum import Enum
from pathlib import PurePath
from typing import Any

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
        f"governed value #{index} of type {type(value).__name__} has no evaluable "
        "projection; pass handles via closure or functools.partial, not as governed arguments",
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


class _Projector:
    """Recursively project a governed value to JSON-safe content, failing closed.

    Every nested value is projected field by field; ``repr()``/``__str__`` never
    stands in for content. A value with no evaluable projection raises, unless
    ``skip_opaque`` is set (output check only), in which case it projects to ``None``.
    """

    __slots__ = ("budget", "index", "path", "skip_opaque")

    def __init__(self, *, index: int, skip_opaque: bool, budget: _Budget) -> None:
        self.index = index
        self.skip_opaque = skip_opaque
        self.budget = budget
        self.path: set[int] = set()

    def _opaque(self, value: Any) -> None:
        if self.skip_opaque:
            return None
        raise _unevaluable(value, self.index)

    def scalar(self, value: Any) -> tuple[bool, Any]:
        """Project well-known value types; ``(False, None)`` when ``value`` is not one."""
        if value is None or isinstance(value, (str, bool, int, float)):
            return True, value
        if isinstance(value, Decimal):
            return True, str(value)
        if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
            return True, value.isoformat()
        if isinstance(value, (uuid.UUID, PurePath)):
            return True, str(value)
        if isinstance(value, (bytes, bytearray)):
            try:
                return True, bytes(value).decode("utf-8")
            except UnicodeDecodeError:
                self._opaque(value)
                return True, None
        return False, None

    def project(self, value: Any, depth: int = 0) -> Any:
        if depth > _MAX_PROJECTION_DEPTH:
            raise GovernancePayloadError(
                f"governed value #{self.index} nests deeper than {_MAX_PROJECTION_DEPTH} "
                "levels and cannot be evaluated in full",
                rule_id=_UNEVALUABLE_RULE_ID,
            )
        if isinstance(value, Enum):
            return self.project(value.value, depth + 1)
        known, projected = self.scalar(value)
        if known:
            self.budget.spend(len(projected) if isinstance(projected, str) else 1, self.index)
            return projected
        marker = id(value)
        if marker in self.path:
            if self.skip_opaque:
                return None
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
        if is_dataclass(value) and not isinstance(value, type):
            self.budget.spend(2, self.index)
            return self._mapping({f.name: getattr(value, f.name) for f in fields(value)}, depth)
        model_dump = getattr(value, "model_dump", None)
        if callable(model_dump):
            return self.project(self._call(model_dump, value, mode="json"), depth + 1)
        dict_method = getattr(value, "dict", None)
        if callable(dict_method) and not isinstance(value, dict):
            return self.project(self._call(dict_method, value), depth + 1)
        # Model and dict() results spend their own budget when projected above.
        self.budget.spend(2, self.index)
        if isinstance(value, dict):
            return self._mapping(value, depth)
        if isinstance(value, (list, tuple)):
            return [self.project(item, depth + 1) for item in value]
        if isinstance(value, (set, frozenset)):
            items = [self.project(item, depth + 1) for item in value]
            return sorted(items, key=repr)
        raw_dict = getattr(value, "__dict__", None)
        if isinstance(raw_dict, dict) and raw_dict:
            return self._mapping(raw_dict, depth)
        self._opaque(value)
        return None

    def _call(self, method: Any, value: Any, **kwargs: Any) -> Any:
        try:
            return method(**kwargs)
        except Exception:
            raise _unevaluable(value, self.index) from None

    def _mapping(self, mapping: dict[Any, Any], depth: int) -> dict[str, Any]:
        projected: dict[str, Any] = {}
        for key, item in mapping.items():
            if isinstance(key, Enum):
                key = key.value
            known, key_value = self.scalar(key)
            if not known or (key_value is None and key is not None):
                self._opaque(key)
                continue
            name = key_value if isinstance(key_value, str) else json.dumps(key_value)
            if name in projected:
                raise GovernancePayloadError(
                    f"governed value #{self.index} has keys that collide after projection",
                    rule_id=_UNEVALUABLE_RULE_ID,
                )
            self.budget.spend(len(name), self.index)
            projected[name] = self.project(item, depth + 1)
        return projected


def _enforcement_payload(
    value: Any, index: int, *, skip_opaque: bool, max_chars: int
) -> str | None:
    """Project one value for enforcement; ``None`` means nothing to evaluate."""
    projector = _Projector(index=index, skip_opaque=skip_opaque, budget=_Budget(max_chars))
    if value is None:
        return None
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, str):
        return value
    known, scalar = projector.scalar(value)
    if known:
        if scalar is None:
            return None
        return scalar if isinstance(scalar, str) else json.dumps(scalar)
    projected = projector.project(value)
    if projected is None:
        return None
    # No ``default=``: anything the projector could not turn into JSON is a bug, not
    # something to stringify, so it denies.
    try:
        return json.dumps(projected, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        raise _unevaluable(value, index) from None


def governance_payloads_for_enforcement(
    *values: Any,
    max_chars: int = _MAX_GOVERNANCE_PAYLOAD_CHARS,
    skip_opaque: bool = False,
) -> list[str]:
    """Project every governed value for enforcement, failing closed.

    Never truncates: a payload longer than ``max_chars`` raises
    :class:`GovernancePayloadError`. Scalars are evaluated; ``None`` and ``""``
    are skipped. Containers, dataclasses (every field), pydantic models and plain
    objects are projected recursively; ``datetime``/``date``/``time``, ``UUID``,
    paths, ``Decimal``, ``Enum`` and UTF-8 bytes project to strings. A value with
    no evaluable projection at any depth, a reference cycle, or nesting deeper
    than 32 levels raises unless ``skip_opaque`` is set, which only the
    post-execution output check uses (opaque leaves then project to ``null``).
    """
    payloads: list[str] = []
    skipped = 0
    for index, value in enumerate(values):
        payload = _enforcement_payload(value, index, skip_opaque=skip_opaque, max_chars=max_chars)
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
