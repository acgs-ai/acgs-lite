"""Canonical invocation and policy bindings for execution authorization."""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from acgs_lite.legitimacy.invariants import LegitimacyInvariantError, strict_bound_context

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
        "execution_attempt_id",
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
    if override is not None:
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
    include_receiver: bool = False,
    strict_context: bool = False,
) -> InvocationBinding:
    """Bind trusted method identity, argument digest, and signature-derived scope/subjects."""
    # Digest first: it admits only JSON-native values, so the scope and subject
    # coercion below never calls a method of a caller-supplied object.
    argument_digest = canonical_argument_digest(
        func, args, kwargs, include_receiver=include_receiver
    )
    bound = _bound_arguments(func, args, kwargs, include_receiver=include_receiver)
    scope = bound.get("scope")
    if scope is None:
        scope = bound.get("governance_scope")
    subjects = bound.get("subjects", ())
    if not subjects:
        subjects = bound.get("governance_subjects", ())
    if strict_context:
        scope, subjects = strict_bound_context(bound, func=func)
    return InvocationBinding(
        method_id=trusted_method_id(func, override=method_override),
        argument_digest=argument_digest,
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
    *,
    include_receiver: bool = False,
) -> str:
    """Return the domain-separated SHA-256 digest of bound, control-stripped arguments."""
    bound = _bound_arguments(func, args, kwargs, include_receiver=include_receiver)
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
    *,
    include_receiver: bool = False,
) -> dict[str, Any]:
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError) as exc:
        raise ArgumentNotDigestible("callable has no inspectable signature") from exc
    filtered = {key: value for key, value in kwargs.items() if key not in CONTROL_KWARGS}
    try:
        bound = signature.bind(*args, **filtered)
        bound.apply_defaults()
    except TypeError as exc:
        raise ArgumentNotDigestible(f"arguments do not match callable signature: {exc}") from exc
    arguments = dict(bound.arguments)
    if not include_receiver:
        # Historical compatibility bindings omitted these names. Production
        # binds every ordinary argument regardless of its spelling.
        arguments.pop("self", None)
        arguments.pop("cls", None)
    return arguments


def defaulted_argument_values(
    func: Callable[..., Any],
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
) -> tuple[Any, ...]:
    """Values the call takes from parameter defaults, in signature order.

    These are digested by :func:`canonical_argument_digest` (it applies defaults)
    but are not among the raw call arguments, so they must be evaluated
    separately. ``*args``/``**kwargs`` parameters have no default and are never
    included; neither are ``self``/``cls``.
    """
    try:
        signature = inspect.signature(func)
    except (TypeError, ValueError) as exc:
        raise ArgumentNotDigestible("callable has no inspectable signature") from exc
    filtered = {key: value for key, value in kwargs.items() if key not in CONTROL_KWARGS}
    try:
        bound = signature.bind(*args, **filtered)
    except TypeError as exc:
        raise ArgumentNotDigestible(f"arguments do not match callable signature: {exc}") from exc
    return tuple(
        parameter.default
        for name, parameter in signature.parameters.items()
        if name not in bound.arguments
        and name not in ("self", "cls")
        and parameter.default is not inspect.Parameter.empty
    )


_MAX_CANONICAL_DEPTH = 32


def _canonical_json(value: Any, *, _seen: set[int] | None = None, _depth: int = 0) -> Any:
    """Tagged canonical encoding of a JSON-native value; everything else is refused.

    Admits exactly the governance payload contract of
    :func:`acgs_lite.serialization.governance_payloads_for_enforcement`: exact
    ``None``/``bool``/``int``/finite ``float``/``str``, strict-UTF-8 ``bytes`` and
    ``bytearray`` without NUL, ``list``, ``tuple`` and ``dict`` with ``str`` keys,
    matched with ``type(v) is T`` so no method of the value's type is ever called.
    The tags keep ``int``/``float``, ``str``/``bytes`` and ``list``/``tuple`` distinct
    in the digest.
    """
    if _depth > _MAX_CANONICAL_DEPTH:
        raise ArgumentNotDigestible(f"argument nests deeper than {_MAX_CANONICAL_DEPTH} levels")
    kind = type(value)
    if value is None or kind is bool or kind is str:
        return value
    if kind is int:
        try:
            return {"__int__": str(value)}
        except ValueError:  # Python's int-to-str digit limit
            raise ArgumentNotDigestible("integer too large to digest") from None
    if kind is float:
        if not math.isfinite(value):
            raise ArgumentNotDigestible("non-finite float cannot be digested")
        return {"__float__": value.hex()}
    if kind is bytes or kind is bytearray:
        try:
            text = bytes(value).decode("utf-8")
        except UnicodeDecodeError:
            raise ArgumentNotDigestible("bytes argument is not strict UTF-8") from None
        if "\x00" in text:
            raise ArgumentNotDigestible("bytes argument contains NUL")
        return {"__bytes__": base64.urlsafe_b64encode(bytes(value)).decode("ascii")}
    if kind is not list and kind is not tuple and kind is not dict:
        raise ArgumentNotDigestible(f"unsupported argument type: {kind.__name__}")
    seen = _seen if _seen is not None else set()
    identity = id(value)
    if identity in seen:
        raise ArgumentNotDigestible("cyclic argument cannot be digested")
    seen = set(seen)
    seen.add(identity)
    depth = _depth + 1
    if kind is tuple:
        return {"__tuple__": [_canonical_json(item, _seen=seen, _depth=depth) for item in value]}
    if kind is list:
        return {"__list__": [_canonical_json(item, _seen=seen, _depth=depth) for item in value]}
    items = []
    for key in dict.keys(value):
        if type(key) is not str:
            raise ArgumentNotDigestible(f"unsupported mapping key type: {type(key).__name__}")
        encoded = _canonical_json(dict.__getitem__(value, key), _seen=seen, _depth=depth)
        items.append([_dumps(key), key, encoded])
    items.sort(key=lambda pair: pair[0])
    return {"__map__": [[key, item] for _sort, key, item in items]}


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
    "defaulted_argument_values",
    "reject_method_spoof_kwargs",
    "trusted_method_id",
]
