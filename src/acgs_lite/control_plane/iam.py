"""Repository permission layer, independent of the PDP.

This module must not import the PDP: it is a second, separately implemented
gate (defense in depth). A bug that makes the PDP permissive must not also
make repository permissions permissive, and vice versa.

* :class:`RepositoryPermissions` refuses, at construction, any write grant to
  a non-human principal whose glob could reach a root-anchored core pattern
  (including ``**`` and ``*``-prefixed globs), and :meth:`~RepositoryPermissions.can_write`
  re-checks every path against the registry regardless of grants.
* :func:`render_codeowners` turns the registry into a CODEOWNERS file so the
  forge requires human code-owner review on every core path.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from acgs_lite.control_plane.immutable_core import (
    CoreCategory,
    ImmutableCoreRegistry,
    compile_glob,
    literal_prefix,
)
from acgs_lite.control_plane.principal import (
    Principal,
    PrincipalKind,
    canonical_principal_id,
)

__all__ = [
    "CODEOWNERS_HEADER",
    "IAMGrantRejected",
    "RepositoryPermissions",
    "WriteGrant",
    "render_codeowners",
]

CODEOWNERS_HEADER = (
    "# GENERATED — do not hand edit; regenerate with scripts/render_codeowners.py\n"
    "# Source: acgs_lite.control_plane.immutable_core.DEFAULT_IMMUTABLE_CORE\n"
    "# Every immutable-core path requires review by a human code owner.\n"
)


class IAMGrantRejected(ValueError):
    """Raised when a grant would let a non-human principal write the core."""


@dataclass(frozen=True)
class WriteGrant:
    """Permission for one principal (id + kind) to write paths matching globs."""

    principal_id: str
    principal_kind: PrincipalKind
    path_globs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.principal_id, str) or not self.principal_id.strip():
            raise IAMGrantRejected("grant principal_id must be a non-empty string")
        object.__setattr__(self, "principal_kind", PrincipalKind(self.principal_kind))
        globs = (self.path_globs,) if isinstance(self.path_globs, str) else tuple(self.path_globs)
        if not globs:
            raise IAMGrantRejected("grant must name at least one path glob")
        cleaned: list[str] = []
        for glob in globs:
            if not isinstance(glob, str) or not glob.strip() or glob != glob.strip():
                raise IAMGrantRejected(f"invalid grant glob: {glob!r}")
            glob = glob[2:] if glob.startswith("./") else glob
            if glob.startswith("/") or "\\" in glob or ".." in glob.split("/"):
                raise IAMGrantRejected(f"grant glob must be relative and inside root: {glob!r}")
            cleaned.append(glob)
        object.__setattr__(self, "path_globs", tuple(cleaned))


def _overlapping_core_pattern(glob: str, registry: ImmutableCoreRegistry) -> str | None:
    """Return a root-anchored core pattern *glob* could reach, if any.

    Conservative: two globs may overlap when one literal prefix is a prefix of
    the other (``""`` -- i.e. ``**`` or ``*.py`` -- overlaps everything).
    Suffix patterns such as ``**/.env*`` have no anchor and would reject every
    grant, so they are enforced per path by :meth:`RepositoryPermissions.can_write`.
    """
    # TODO(control-plane-gap): glob-overlap is approximated by literal
    # prefixes; exact glob intersection is not implemented.
    grant_prefix = literal_prefix(glob)
    for patterns in (*registry.patterns().values(), *registry.shadow_patterns().values()):
        for pattern in patterns:
            core_prefix = literal_prefix(pattern)
            if not core_prefix:
                continue
            if grant_prefix.startswith(core_prefix) or core_prefix.startswith(grant_prefix):
                return pattern
    return None


class RepositoryPermissions:
    """Write-grant table checked against the immutable core on every call."""

    def __init__(self, registry: ImmutableCoreRegistry, grants: Iterable[WriteGrant] = ()) -> None:
        if not isinstance(registry, ImmutableCoreRegistry):
            raise IAMGrantRejected("registry must be an ImmutableCoreRegistry")
        checked: list[WriteGrant] = []
        for grant in grants:
            if not isinstance(grant, WriteGrant):
                raise IAMGrantRejected("grants must be WriteGrant instances")
            if grant.principal_kind is not PrincipalKind.HUMAN:
                for glob in grant.path_globs:
                    overlap = _overlapping_core_pattern(glob, registry)
                    if overlap is not None:
                        raise IAMGrantRejected(
                            f"grant {glob!r} for {grant.principal_kind.value} "
                            f"{grant.principal_id!r} overlaps immutable core {overlap!r}"
                        )
            checked.append(grant)
        self._registry = registry
        self._grants = tuple(checked)

    @property
    def grants(self) -> tuple[WriteGrant, ...]:
        return self._grants

    @property
    def registry(self) -> ImmutableCoreRegistry:
        return self._registry

    def has_unrestricted_write(self, principal: Principal) -> bool:
        """True only if *principal* (id + kind) holds a grant for ``**``.

        Used where write targets cannot be enumerated (shell commands): a
        path-scoped grant cannot be enforced there, so it is not enough.
        """
        if not isinstance(principal, Principal):
            return False
        return any(
            canonical_principal_id(grant.principal_id) == principal.canonical_id
            and grant.principal_kind is principal.kind
            and "**" in grant.path_globs
            for grant in self._grants
        )

    def can_write(self, principal: Principal, path: str) -> bool:
        """True only if a grant matches and, for non-humans, *path* is not core."""
        if not isinstance(principal, Principal):
            return False
        normalized = self._registry.normalize(path)
        if normalized is None:
            return False
        if principal.kind is not PrincipalKind.HUMAN and self._registry.is_core(normalized):
            return False
        for grant in self._grants:
            if (
                canonical_principal_id(grant.principal_id) != principal.canonical_id
                or grant.principal_kind is not principal.kind
            ):
                continue
            if any(compile_glob(glob).fullmatch(normalized) for glob in grant.path_globs):
                return True
        return False


def _codeowners_pattern(pattern: str) -> str:
    # Registry globs are root-anchored; CODEOWNERS anchors with a leading "/".
    return pattern if pattern.startswith("**/") else "/" + pattern


def render_codeowners(registry: ImmutableCoreRegistry, owners: Sequence[str]) -> str:
    """Render a CODEOWNERS file assigning every core pattern to *owners*."""
    owner_list = [owners] if isinstance(owners, str) else list(owners)
    if not owner_list:
        raise ValueError("at least one owner is required")
    for owner in owner_list:
        if not isinstance(owner, str) or not owner or any(ch.isspace() for ch in owner):
            raise ValueError(f"invalid owner: {owner!r}")
        if not owner.startswith("@") and "@" not in owner:
            raise ValueError(f"owner must be @user, @org/team or an email: {owner!r}")
    owner_text = " ".join(owner_list)
    lines = [CODEOWNERS_HEADER]
    patterns = registry.patterns()
    shadows = registry.shadow_patterns()
    for category in CoreCategory:
        if not patterns[category]:
            continue
        lines.append(f"\n# {category.value}\n")
        for pattern in patterns[category]:
            lines.append(f"{_codeowners_pattern(pattern)} {owner_text}\n")
        if shadows[category]:
            lines.append(f"# {category.value}: module shadows (package dirs, extensions, pyc)\n")
            for pattern in shadows[category]:
                lines.append(f"{_codeowners_pattern(pattern)} {owner_text}\n")
    return "".join(lines)
