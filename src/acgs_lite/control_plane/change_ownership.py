"""Single writer per change: one principal, one worktree, one branch.

Each ``change_id`` is assigned (by a HUMAN admin) to exactly one writer
principal, one worktree root (a repo-relative directory) and the branch
``agent/<canonical-id>/<change_id>``. :meth:`ChangeOwnershipRegistry.assert_writer`
denies a write by anyone but the owner, to any path outside the owner's
worktree (after normalisation; ``..`` escapes and symlinked components under
``repo_root`` are refused) or to any branch but the owner's.

The worktree root may not be, contain or lie inside the immutable core, so an
agent's own worktree never covers a core path.

Evidence: Replit -- concurrent, unscoped writes to shared state destroyed
production data; METR / DGM -- the proposer must not be able to reach the
grader, so its writes are confined to its own branch.
"""

from __future__ import annotations

import os
import posixpath
import re
import threading
from dataclasses import dataclass

from acgs_lite.control_plane.immutable_core import ImmutableCoreRegistry
from acgs_lite.control_plane.principal import Principal, PrincipalKind

__all__ = [
    "AGENT_NO_MERGE_ACTIONS",
    "ChangeOwnership",
    "ChangeOwnershipRegistry",
    "OwnershipDenied",
    "branch_for",
]

# Merge/approve operations no AGENT or SERVICE may perform
# (INV-AGENT-NO-MERGE matches these as actions and as tool names).
# TODO(control-plane-gap): matching by name; a host that registers a merge
# tool under another name must add it here.
AGENT_NO_MERGE_ACTIONS = frozenset(
    {"git.merge", "pr.merge", "pr.approve", "change.approve", "change.merge"}
)

_CHANGE_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")


class OwnershipDenied(PermissionError):
    """A write violates single-writer-per-change."""


def branch_for(principal: Principal, change_id: str) -> str:
    return f"agent/{principal.canonical_id}/{change_id}"


@dataclass(frozen=True)
class ChangeOwnership:
    change_id: str
    writer: Principal
    worktree_root: str
    """Normalised repo-relative directory (no trailing slash)."""
    branch: str


class ChangeOwnershipRegistry:
    """Harness-side change -> (writer, worktree, branch) table."""

    def __init__(self, registry: ImmutableCoreRegistry, *, admin: Principal) -> None:
        if not isinstance(registry, ImmutableCoreRegistry):
            raise TypeError("registry must be an ImmutableCoreRegistry")
        if not isinstance(admin, Principal) or admin.kind is not PrincipalKind.HUMAN:
            raise TypeError("admin must be the configured HUMAN admin Principal")
        # Bound like RoleAssignments: "a HUMAN" is not "the admin"; any other
        # human could otherwise release a change and re-assign (or widen) it.
        self._admin = admin
        self._registry = registry
        self._lock = threading.Lock()
        self._changes: dict[str, ChangeOwnership] = {}

    @property
    def registry(self) -> ImmutableCoreRegistry:
        return self._registry

    @property
    def admin(self) -> Principal:
        return self._admin

    def _require_admin(self, admin: object, verb: str) -> None:
        if (
            not isinstance(admin, Principal)
            or admin.kind is not PrincipalKind.HUMAN
            or admin.canonical_id != self._admin.canonical_id
        ):
            raise OwnershipDenied(f"only the configured HUMAN admin {verb} change ownership")

    def assign(
        self, admin: Principal, change_id: str, writer: Principal, worktree_root: str
    ) -> ChangeOwnership:
        self._require_admin(admin, "assigns")
        if not isinstance(writer, Principal):
            raise OwnershipDenied("writer must be a Principal")
        if not isinstance(change_id, str) or not _CHANGE_ID.fullmatch(change_id):
            raise OwnershipDenied("change_id must match [A-Za-z0-9._-]{1,128}")
        root = self._registry.normalize(worktree_root)
        if root is None or root == ".":
            raise OwnershipDenied(f"invalid worktree root {worktree_root!r}")
        if self._registry.is_core(root):
            raise OwnershipDenied(f"worktree root {worktree_root!r} is (or contains) the core")
        ownership = ChangeOwnership(change_id, writer, root, branch_for(writer, change_id))
        with self._lock:
            existing = self._changes.get(change_id)
            if existing is not None:
                raise OwnershipDenied(
                    f"change {change_id!r} already has writer {existing.writer.id!r}"
                )
            for other in self._changes.values():
                if _overlaps(other.worktree_root, root):
                    raise OwnershipDenied(f"worktree {root!r} overlaps change {other.change_id!r}")
            self._changes[change_id] = ownership
        return ownership

    def release(self, admin: Principal, change_id: str) -> bool:
        self._require_admin(admin, "releases")
        with self._lock:
            return self._changes.pop(change_id, None) is not None

    def get(self, change_id: str) -> ChangeOwnership | None:
        with self._lock:
            return self._changes.get(change_id)

    def assert_writer(
        self,
        principal: Principal,
        change_id: object,
        path: str | None = None,
        *,
        branch: object = None,
    ) -> ChangeOwnership:
        """Raise :class:`OwnershipDenied` unless *principal* owns *change_id*
        and *path* / *branch* (when given) are inside its worktree / its branch."""
        if not isinstance(change_id, str):
            raise OwnershipDenied("a change_id is required for governed writes")
        ownership = self.get(change_id)
        if ownership is None:
            raise OwnershipDenied(f"change {change_id!r} has no assigned writer")
        if (
            not isinstance(principal, Principal)
            or principal.canonical_id != ownership.writer.canonical_id
            or principal.kind is not ownership.writer.kind
        ):
            raise OwnershipDenied(
                f"{getattr(principal, 'id', principal)!r} is not the writer of change {change_id!r}"
            )
        if branch is not None and branch != ownership.branch:
            raise OwnershipDenied(
                f"branch {branch!r} is not the change branch {ownership.branch!r}"
            )
        if path is not None:
            self._check_path(ownership, path)
        return ownership

    def _check_path(self, ownership: ChangeOwnership, path: str) -> None:
        normalized = self._registry.normalize(path)
        if normalized is None or not _inside(ownership.worktree_root, normalized):
            raise OwnershipDenied(f"path {path!r} is outside worktree {ownership.worktree_root!r}")
        root = self._registry.repo_root
        if root is None:
            # TODO(control-plane-gap): without repo_root, symlinks cannot be
            # checked; the sandbox filesystem must refuse them.
            return
        # Every existing component from the *repository* root down (the
        # worktree's ancestors included) must be a real directory/file, not a
        # symlink that could point into the core.
        current = root
        for segment in [s for s in normalized.split("/") if s]:
            current = posixpath.join(current, segment)
            if os.path.islink(current):
                raise OwnershipDenied(f"path {path!r} traverses a symlink")
        # Containment is checked against the lexical worktree under the real
        # repository root, never against a resolved (possibly redirected) one.
        real_root = posixpath.join(os.path.realpath(root), ownership.worktree_root)
        real_target = os.path.realpath(posixpath.join(root, normalized))
        if real_target != real_root and not real_target.startswith(real_root.rstrip("/") + "/"):
            raise OwnershipDenied(f"path {path!r} resolves outside the worktree")


def _inside(root: str, path: str) -> bool:
    return path.lower() == root.lower() or path.lower().startswith(root.lower() + "/")


def _overlaps(a: str, b: str) -> bool:
    return _inside(a, b) or _inside(b, a)
