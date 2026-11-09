"""Cedar-style policy statements and policy sets.

Lives apart from :mod:`acgs_lite.control_plane.pdp` so that the
non-overridable invariants can be built from the same statement type without
an import cycle; ``pdp`` re-exports every public name here.
"""

from __future__ import annotations

import fnmatch
import functools
import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from acgs_lite._compat import StrEnum
from acgs_lite.control_plane.immutable_core import compile_glob
from acgs_lite.control_plane.principal import PrincipalKind
from acgs_lite.control_plane.tiers import ActionTier

if TYPE_CHECKING:
    from acgs_lite.control_plane.context import DecisionContext

__all__ = [
    "INVARIANT_ID_PREFIX",
    "PolicyEffect",
    "PolicyParseError",
    "PolicySet",
    "PolicyStatement",
]

INVARIANT_ID_PREFIX = "INV-"
POLICY_SET_VERSION = 1
POLICY_SET_DIGEST_DOMAIN = b"acgs-lite/control-plane/policy-set/v1\n"

_STATEMENT_KEYS = frozenset(
    {"id", "effect", "principal_kinds", "actions", "resources", "max_tier", "description"}
)
_REQUIRED_STATEMENT_KEYS = frozenset({"id", "effect", "actions", "resources"})
_TIER_NAME = re.compile(r"^T[0-3]$")


class PolicyParseError(ValueError):
    """Raised when a declarative policy set fails strict schema validation."""


class PolicyEffect(StrEnum):
    PERMIT = "permit"
    FORBID = "forbid"


_compiled_glob = functools.lru_cache(maxsize=2048)(compile_glob)


def _string_tuple(value: Iterable[str], label: str) -> tuple[str, ...]:
    if isinstance(value, str):
        raise ValueError(f"{label} must be a sequence of strings, not a string")
    items = tuple(value)
    if not items or not all(isinstance(item, str) and item for item in items):
        raise ValueError(f"{label} must be a non-empty sequence of non-empty strings")
    return items


@dataclass(frozen=True)
class PolicyStatement:
    """One permit/forbid rule.

    A statement matches when every populated constraint holds: principal kind,
    action glob (``fnmatch`` over dotted verbs), resource glob (repo-glob
    semantics over the normalised resource), ``tier <= max_tier`` and the
    optional Python ``condition``. A resource that cannot be normalised never
    satisfies a permit but always satisfies a forbid (deny side).
    """

    id: str
    effect: PolicyEffect
    principal_kinds: frozenset[PrincipalKind] | None
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    max_tier: ActionTier | None = None
    condition: Callable[[DecisionContext], bool] | None = None
    description: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip():
            raise ValueError("statement id must be a non-empty string")
        object.__setattr__(self, "effect", PolicyEffect(self.effect))
        if self.principal_kinds is not None:
            kinds = frozenset(PrincipalKind(kind) for kind in self.principal_kinds)
            if not kinds:
                raise ValueError("principal_kinds must be None or non-empty")
            object.__setattr__(self, "principal_kinds", kinds)
        object.__setattr__(self, "actions", _string_tuple(self.actions, "actions"))
        object.__setattr__(self, "resources", _string_tuple(self.resources, "resources"))
        if self.max_tier is not None:
            object.__setattr__(self, "max_tier", ActionTier(self.max_tier))
        if self.condition is not None and not callable(self.condition):
            raise ValueError("condition must be callable")

    def matches(self, ctx: DecisionContext) -> bool:
        """Return whether this statement applies. Errors propagate (PDP denies)."""
        request = ctx.request
        if self.principal_kinds is not None and request.principal.kind not in self.principal_kinds:
            return False
        action = request.action.lower()
        if not any(fnmatch.fnmatchcase(action, glob.lower()) for glob in self.actions):
            return False
        if self.max_tier is not None and request.tier > self.max_tier:
            return False
        normalized = ctx.registry.normalize(request.resource)
        if normalized is None:
            if self.effect is not PolicyEffect.FORBID:
                return False
        elif not any(
            _compiled_glob(glob, case_sensitive=self.effect is PolicyEffect.PERMIT).fullmatch(
                normalized
            )
            for glob in self.resources
        ):
            return False
        if self.condition is None:
            return True
        result = self.condition(ctx)
        if not isinstance(result, bool):
            raise TypeError(f"condition of {self.id} returned {type(result).__name__}, not bool")
        return result

    def declarative_projection(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "effect": self.effect.value,
            "principal_kinds": (
                None
                if self.principal_kinds is None
                else sorted(kind.value for kind in self.principal_kinds)
            ),
            "actions": list(self.actions),
            "resources": list(self.resources),
            "max_tier": None if self.max_tier is None else int(self.max_tier),
            "condition": (
                None
                if self.condition is None
                else f"{getattr(self.condition, '__module__', '?')}:"
                f"{getattr(self.condition, '__qualname__', repr(self.condition))}"
            ),
        }


def _digest(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(POLICY_SET_DIGEST_DOMAIN + canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PolicySet:
    """An ordered, immutable collection of loaded (overridable) statements."""

    statements: tuple[PolicyStatement, ...]
    source_digest: str

    def __post_init__(self) -> None:
        statements = tuple(self.statements)
        if not all(isinstance(statement, PolicyStatement) for statement in statements):
            raise ValueError("policy set statements must be PolicyStatement instances")
        ids = [statement.id for statement in statements]
        if len(ids) != len(set(ids)):
            raise ValueError("policy statement ids must be unique")
        reserved = [sid for sid in ids if sid.upper().startswith(INVARIANT_ID_PREFIX)]
        if reserved:
            raise ValueError(f"ids with prefix {INVARIANT_ID_PREFIX!r} are reserved: {reserved}")
        if not isinstance(self.source_digest, str) or not self.source_digest.strip():
            raise ValueError("policy set source_digest must be a non-empty string")
        object.__setattr__(self, "statements", statements)

    @classmethod
    def from_statements(cls, statements: Iterable[PolicyStatement]) -> PolicySet:
        """Build from Python statements; the digest covers declarative fields
        and each condition's qualified name (not its code)."""
        items = tuple(statements)
        return cls(items, _digest([statement.declarative_projection() for statement in items]))

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> PolicySet:
        """Strictly parse ``{"version": 1, "statements": [...]}``."""
        if not isinstance(data, Mapping):
            raise PolicyParseError("policy set must be a mapping")
        unknown = set(data) - {"version", "statements"}
        if unknown:
            raise PolicyParseError(f"unknown policy set keys: {sorted(unknown)}")
        if data.get("version") != POLICY_SET_VERSION:
            raise PolicyParseError(f"policy set version must be {POLICY_SET_VERSION}")
        raw_statements = data.get("statements")
        if not isinstance(raw_statements, list):
            raise PolicyParseError("policy set statements must be a list")
        statements = tuple(_parse_statement(raw, index) for index, raw in enumerate(raw_statements))
        try:
            return cls(statements, _digest(_json_safe(data)))
        except ValueError as exc:
            raise PolicyParseError(str(exc)) from exc

    @classmethod
    def from_yaml_str(cls, text: str) -> PolicySet:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise PolicyParseError(f"policy set is not valid YAML: {exc}") from exc
        return cls.from_mapping(data)

    @classmethod
    def from_yaml(cls, path: str | Path) -> PolicySet:
        return cls.from_yaml_str(Path(path).read_text(encoding="utf-8"))


def _json_safe(data: Mapping[str, Any]) -> Any:
    try:
        return json.loads(json.dumps(data, sort_keys=True, allow_nan=False))
    except (TypeError, ValueError) as exc:
        raise PolicyParseError(f"policy set is not JSON-representable: {exc}") from exc


def _parse_tier(value: object, where: str) -> ActionTier:
    if isinstance(value, bool):
        raise PolicyParseError(f"{where}: max_tier must be T0..T3 or 0..3")
    if isinstance(value, str) and _TIER_NAME.match(value):
        return ActionTier[value]
    if isinstance(value, int) and 0 <= value <= 3:
        return ActionTier(value)
    raise PolicyParseError(f"{where}: max_tier must be T0..T3 or 0..3, got {value!r}")


def _parse_string_list(raw: Mapping[str, Any], key: str, where: str) -> tuple[str, ...]:
    value = raw.get(key)
    if not isinstance(value, list) or not value:
        raise PolicyParseError(f"{where}: {key} must be a non-empty list")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise PolicyParseError(f"{where}: {key} entries must be non-empty strings")
    return tuple(value)


def _parse_statement(raw: object, index: int) -> PolicyStatement:
    where = f"statements[{index}]"
    if not isinstance(raw, Mapping):
        raise PolicyParseError(f"{where} must be a mapping")
    unknown = set(raw) - _STATEMENT_KEYS
    if unknown:
        raise PolicyParseError(f"{where}: unknown keys {sorted(unknown)}")
    missing = _REQUIRED_STATEMENT_KEYS - set(raw)
    if missing:
        raise PolicyParseError(f"{where}: missing keys {sorted(missing)}")
    statement_id = raw["id"]
    if not isinstance(statement_id, str) or not statement_id.strip():
        raise PolicyParseError(f"{where}: id must be a non-empty string")
    effect = raw["effect"]
    if effect not in {member.value for member in PolicyEffect}:
        raise PolicyParseError(f"{where}: effect must be 'permit' or 'forbid', got {effect!r}")
    kinds: frozenset[PrincipalKind] | None = None
    if raw.get("principal_kinds") is not None:
        raw_kinds = _parse_string_list(raw, "principal_kinds", where)
        try:
            kinds = frozenset(PrincipalKind(kind) for kind in raw_kinds)
        except ValueError as exc:
            raise PolicyParseError(f"{where}: unknown principal kind") from exc
    max_tier = None if raw.get("max_tier") is None else _parse_tier(raw["max_tier"], where)
    description = raw.get("description", "")
    if not isinstance(description, str):
        raise PolicyParseError(f"{where}: description must be a string")
    return PolicyStatement(
        id=statement_id,
        effect=PolicyEffect(effect),
        principal_kinds=kinds,
        actions=_parse_string_list(raw, "actions", where),
        resources=_parse_string_list(raw, "resources", where),
        max_tier=max_tier,
        description=description,
    )
