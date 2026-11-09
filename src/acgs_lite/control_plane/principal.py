"""Principals: the identities that request control-plane decisions.

``system_id`` groups sibling agents that belong to one system. Phase 3 uses it
to exclude siblings from approval quorums, so it is modelled from the start.

Trust boundary: a ``Principal`` is an *assertion by the host*, not by the
caller. Hosts MUST mint principals from an authenticated session (for MCP:
inside the ``principal_resolver``), and ``kind`` must never be taken from
agent-controlled input -- an agent that can construct
``Principal(..., PrincipalKind.HUMAN)`` bypasses every human-only invariant.
The same holds for approvers.

Ids must be canonical ASCII matching ``[A-Za-z0-9._@:-]+``. Identity comparisons (two-person rule, IAM grants) use
:attr:`Principal.canonical_id`, the casefolded id, so ``"Alice"`` and
``"alice"`` are the same person.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from acgs_lite._compat import StrEnum

__all__ = ["Principal", "PrincipalKind", "canonical_principal_id"]

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
# ASCII only: Unicode confusables (Cyrillic "а" vs Latin "a") would otherwise
# let one person appear as two distinct approvers.
_ID_CHARS = re.compile(r"[A-Za-z0-9._@:-]+")

# TODO(control-plane-gap): approvers are unattested Principal objects; the
# host vouches for them. Phase 3 adds signed approvals bound to inputs_digest.


def canonical_principal_id(principal_id: str) -> str:
    """Identity used for comparisons (casefolded)."""
    return principal_id.casefold()


def _validate_id(value: object, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    if (
        value != value.strip()
        or _CONTROL_CHARS.search(value)
        or unicodedata.normalize("NFKC", value) != value
    ):
        raise ValueError(f"{label} must be canonical (no padding/control chars, NFKC): {value!r}")
    if not _ID_CHARS.fullmatch(value):
        raise ValueError(f"{label} must be canonical ASCII [A-Za-z0-9._@:-]+: {value!r}")


class PrincipalKind(StrEnum):
    """Who is acting. Only ``HUMAN`` may ever change the immutable core."""

    HUMAN = "human"
    AGENT = "agent"
    SERVICE = "service"


@dataclass(frozen=True)
class Principal:
    """An authenticated actor. Construction validates every field."""

    id: str
    kind: PrincipalKind
    system_id: str | None = None
    roles: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        _validate_id(self.id, "principal id")
        object.__setattr__(self, "kind", PrincipalKind(self.kind))
        if self.system_id is not None and (
            not isinstance(self.system_id, str) or not self.system_id.strip()
        ):
            raise ValueError("principal system_id must be None or a non-empty string")
        roles = frozenset(self.roles)
        if not all(isinstance(role, str) and role for role in roles):
            raise ValueError("principal roles must be non-empty strings")
        object.__setattr__(self, "roles", roles)

    @property
    def canonical_id(self) -> str:
        return canonical_principal_id(self.id)

    def to_canonical(self) -> dict[str, object]:
        """Return a JSON-ready, order-independent projection."""
        return {
            "id": self.id,
            "kind": self.kind.value,
            "system_id": self.system_id,
            "roles": sorted(self.roles),
        }
