"""Canonical invocation and policy bindings for execution authorization."""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Any

from acgs_lite.legitimacy.invariants import LegitimacyInvariantError

INVOCATION_DIGEST_DOMAIN = b"acgs-invocation-v1\x00"
POLICY_DIGEST_DOMAIN = b"acgs-policy-v1\x00"

CONTROL_KWARGS = frozenset(
    {
        "decision_receipt",
        "acgs_receipt",
        "execution_grant",
        "acgs_grant",
        "signed_receipt",
        "grant_id",
        "human_approval",
    }
)

METHOD_SPOOF_KWARGS = frozenset({"governance_method", "method", "action"})


class ArgumentNotDigestible(LegitimacyInvariantError):
    """Raised when an argument cannot be canonically digested."""

    def __init__(self, message: str, *, action: str = "") -> None:
        super().__init__(message, action=action)


@dataclass(slots=True, frozen=True)
class InvocationBinding:
    """Trusted callable identity plus the digest of bound arguments."""

    method_id: str
    argument_digest: str
    scope: str | None
    subjects: tuple[str, ...]


@dataclass(slots=True, frozen=True)
class PolicyBinding:
    """Full-strength digest of constitution content, plus the label used on receipts."""

    version: str
    algorithm: str
    digest: str


def trusted_method_id(func: Callable[..., Any], *, override: str | None = None) -> str:
    """Return a decorator-owned identity. Never derived from call-time kwargs."""
    if override:
        if not isinstance(override, str) or not override.strip():
            raise LegitimacyInvariantError("method override must be a non-empty string")
        return override
    return f"{func.__module__}:{func.__qualname__}"


def bind_invocation(
    func: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
    *,
    method_override: str | None = None,
) -> InvocationBinding:
    """Bind trusted method identity, argument digest, and signature-derived scope/subjects."""
    bound = _bound_arguments(func, args, kwargs)
    scope = bound.get("scope")
    if scope is None:
        scope = bound.get("governance_scope")
    subjects = bound.get("subjects", ())
    if not subjects:
        subjects = bound.get("governance_subjects", ())
    return InvocationBinding(
        method_id=trusted_method_id(func, override=method_override),
        argument_digest=canonical_argument_digest(func, args, kwargs),
        scope=None if scope is None else str(scope),
        subjects=_coerce_subjects(subjects),
    )


def bind_policy(constitution: Any) -> PolicyBinding:
    """Digest the full constitution projection. Do not reuse truncated Constitution.hash."""
    if hasattr(constitution, "model_dump"):
        dumped = constitution.model_dump(mode="json")
    elif hasattr(constitution, "to_dict"):
        dumped = constitution.to_dict()
    else:
        raise ArgumentNotDigestible("constitution cannot be canonically digested")
    canonical = _dumps(_canonical_json(dumped))
    digest = hashlib.sha256(POLICY_DIGEST_DOMAIN + canonical.encode("utf-8")).hexdigest()
    version = str(getattr(constitution, "hash", "") or getattr(constitution, "version", "") or "")
    if not version:
        raise ArgumentNotDigestible("constitution has no version or hash label")
    return PolicyBinding(version=version, algorithm="sha256", digest=digest)


def canonical_argument_digest(
    func: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
) -> str:
    """Return the domain-separated SHA-256 digest of bound, control-stripped arguments."""
    bound = _bound_arguments(func, args, kwargs)
    payload = {
        "parameters": [[name, _canonical_json(value)] for name, value in bound.items()],
    }
    canonical = _dumps(payload)
    return hashlib.sha256(INVOCATION_DIGEST_DOMAIN + canonical.encode("utf-8")).hexdigest()


def reject_method_spoof_kwargs(func: Callable[..., Any], kwargs: Mapping[str, Any]) -> None:
    """Fail closed if the caller tries to override method identity via undeclared kwargs."""
    try:
        names = set(inspect.signature(func).parameters)
    except (TypeError, ValueError):
        names = set()
    for name in METHOD_SPOOF_KWARGS:
        if name in kwargs and name not in names:
            raise LegitimacyInvariantError("Caller cannot override method identity")


def _bound_arguments(
    func: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError) as exc:
        raise ArgumentNotDigestible("callable has no inspectable signature") from exc
    filtered = {key: value for key, value in kwargs.items() if key not in CONTROL_KWARGS}
    try:
        bound = signature.bind_partial(*args, **filtered)
        bound.apply_defaults()
    except TypeError as exc:
        raise ArgumentNotDigestible(f"arguments do not match callable signature: {exc}") from exc
    arguments = dict(bound.arguments)
    arguments.pop("self", None)
    arguments.pop("cls", None)
    return arguments


def _canonical_json(value: Any, *, _seen: set[int] | None = None) -> Any:
    seen = _seen if _seen is not None else set()
    identity = id(value)
    if isinstance(value, (list, tuple, dict, set, frozenset)):
        if identity in seen:
            raise ArgumentNotDigestible("cyclic argument cannot be digested")
        seen = set(seen)
        seen.add(identity)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return {"__int__": str(value)}
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ArgumentNotDigestible("non-finite float cannot be digested")
        return {"__float__": value.hex()}
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray)):
        return {"__bytes__": base64.urlsafe_b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, Decimal):
        return {"__decimal__": str(value)}
    if isinstance(value, datetime):
        return {"__datetime__": value.isoformat()}
    if isinstance(value, Enum):
        return {"__enum__": [type(value).__name__, _canonical_json(value.value, _seen=seen)]}
    if isinstance(value, tuple):
        return {"__tuple__": [_canonical_json(item, _seen=seen) for item in value]}
    if isinstance(value, list):
        return {"__list__": [_canonical_json(item, _seen=seen) for item in value]}
    if isinstance(value, (set, frozenset)):
        encoded = sorted(
            (_dumps(_canonical_json(item, _seen=seen)) for item in value),
        )
        return {"__set__": encoded}
    if isinstance(value, Mapping):
        items = []
        for key, item in value.items():
            items.append([str(key), _canonical_json(item, _seen=seen)])
        items.sort(key=lambda pair: pair[0])
        return {"__map__": items}
    raise ArgumentNotDigestible(f"unsupported argument type: {type(value).__name__}")


def _dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _coerce_subjects(raw: Any) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        return (raw,)
    if isinstance(raw, Mapping):
        return tuple(str(item) for item in raw.values())
    try:
        return tuple(str(item) for item in raw)
    except TypeError:
        return (str(raw),)


__all__ = [
    "CONTROL_KWARGS",
    "INVOCATION_DIGEST_DOMAIN",
    "METHOD_SPOOF_KWARGS",
    "POLICY_DIGEST_DOMAIN",
    "ArgumentNotDigestible",
    "InvocationBinding",
    "PolicyBinding",
    "bind_invocation",
    "bind_policy",
    "canonical_argument_digest",
    "reject_method_spoof_kwargs",
    "trusted_method_id",
]
