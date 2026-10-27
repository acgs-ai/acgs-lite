# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.
# Commercial license: https://acgs.ai

"""Shared serialization helpers for governance validation payloads.

Constitutional Hash: 608508a9bd224290
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from decimal import Decimal
from enum import Enum
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


def _enforcement_payload(value: Any, index: int, *, skip_opaque: bool) -> str | None:
    """Project one value for enforcement; ``None`` means nothing to evaluate."""
    if value is None:
        return None
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, str):
        return value
    if isinstance(value, (bool, int, float)):
        return json.dumps(value)
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (bytes, bytearray)):
        try:
            return bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            if skip_opaque:
                return None
            raise _unevaluable(value, index) from None
    jsonable = _to_jsonable(value)
    if jsonable is value and not isinstance(value, (dict, list, tuple, set)):
        if skip_opaque:
            return None
        raise _unevaluable(value, index)
    if isinstance(jsonable, dict) and not skip_opaque:
        for item in jsonable.values():
            if item is not None and _is_opaque(item):
                raise _unevaluable(item, index)
    try:
        return json.dumps(jsonable, default=str, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(jsonable)


def _is_opaque(value: Any) -> bool:
    if isinstance(value, (str, bool, int, float, Decimal, Enum, bytes, bytearray)):
        return False
    jsonable = _to_jsonable(value)
    return jsonable is value and not isinstance(value, (dict, list, tuple, set))


def governance_payloads_for_enforcement(
    *values: Any,
    max_chars: int = _MAX_GOVERNANCE_PAYLOAD_CHARS,
    skip_opaque: bool = False,
) -> list[str]:
    """Project every governed value for enforcement, failing closed.

    Never truncates: a payload longer than ``max_chars`` raises
    :class:`GovernancePayloadError`. Scalars are evaluated; ``None`` and ``""``
    are skipped. A value with no evaluable projection (and a top-level mapping
    value of that kind) raises unless ``skip_opaque`` is set, which only the
    post-execution output check uses.
    """
    payloads: list[str] = []
    skipped = 0
    for index, value in enumerate(values):
        payload = _enforcement_payload(value, index, skip_opaque=skip_opaque)
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
