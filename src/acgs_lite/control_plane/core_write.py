"""The only path for CORE_HUMAN_ONLY file changes.

A ``content_digest`` the caller merely *claims* binds nothing: the PDP never
sees the bytes, so a writer could put anything on disk under an approved
digest. :class:`CoreChangeWriter` closes that gap. It computes
``sha256(content)`` itself, places it in the decision request (the caller
cannot supply it), decides through the PDP (which consumes the approvals),
and only on allow writes *exactly* that buffer, atomically, inside the
repository root.

Every CORE_HUMAN_ONLY change (see :mod:`.change_class`) must go through it:
INV-HUMAN-ONLY-CHANGE-CLASS denies any such request whose
``content_digest_source == "harness"`` attribute was not stamped by the
writer bound to that PDP (a module-private binding plus a per-PDP token held
in this writer's closure, the same pattern as the receipt ledger). A direct
``decide()`` with a caller-supplied digest is therefore always denied.

Evidence: DGM fabricated success logs and STOP disabled its sandbox flag --
claims made outside the harness are not evidence, so the harness hashes the
bytes it writes.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import secrets
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from acgs_lite.control_plane.approvals import SignedApproval
from acgs_lite.control_plane.context import DecisionRequest
from acgs_lite.control_plane.immutable_core import CoreCategory
from acgs_lite.control_plane.pdp import Decision, PolicyDecisionPoint
from acgs_lite.control_plane.principal import Principal
from acgs_lite.control_plane.tiers import ActionTier

if TYPE_CHECKING:
    from acgs_lite.control_plane.incident import IncidentMutationLock

__all__ = ["CONTENT_DIGEST_SOURCE", "CoreChangeWriter", "CoreWriteRejected"]

CONTENT_DIGEST_SOURCE = "harness"
_CORE_WRITER_BINDING = object()


class CoreWriteRejected(PermissionError):
    """The change was denied (or could not be written); nothing was written."""

    def __init__(self, reason: str, decision: Decision | None = None) -> None:
        super().__init__(reason)
        self.decision = decision


def content_digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


class CoreChangeWriter:
    """Harness-owned writer for immutable-core files (one per PDP)."""

    def __init__(
        self,
        pdp: PolicyDecisionPoint,
        *,
        tier: ActionTier = ActionTier.T2,
        incident_lock: IncidentMutationLock | None = None,
    ) -> None:
        if not isinstance(pdp, PolicyDecisionPoint):
            raise TypeError("pdp must be a PolicyDecisionPoint")
        if incident_lock is not None:
            from acgs_lite.control_plane.incident import IncidentMutationLock

            if type(incident_lock) is not IncidentMutationLock:
                raise TypeError("incident_lock must be an IncidentMutationLock")
        # Phase 5: during an incident only the lock holder may change the core.
        self._incident_lock = incident_lock
        root = pdp.registry.repo_root
        if root is None:
            raise ValueError("CoreChangeWriter needs a registry with repo_root")
        token = pdp._bind_core_writer(_CORE_WRITER_BINDING)
        bound = pdp

        # The PDP token is held only by this closure, never as an attribute.
        def decide(request: DecisionRequest) -> Decision:
            return bound._decide_attested(request, core_write_token=token)[0]

        self._decide = decide
        self._pdp = pdp
        self._root = Path(root)
        self._tier = ActionTier(tier)

    def __repr__(self) -> str:
        return f"CoreChangeWriter(root={str(self._root)!r})"

    def __copy__(self) -> CoreChangeWriter:
        raise TypeError("CoreChangeWriter cannot be copied")

    def __deepcopy__(self, memo: object) -> CoreChangeWriter:
        raise TypeError("CoreChangeWriter cannot be copied")

    def _request(
        self,
        principal: Principal,
        path: str,
        content: bytes,
        approvals: Sequence[SignedApproval],
        requested_by: str | None,
    ) -> tuple[DecisionRequest, str]:
        if not isinstance(content, bytes):
            raise CoreWriteRejected("content must be bytes")
        normalized = self._pdp.registry.normalize(path)
        if normalized is None or normalized == ".":
            raise CoreWriteRejected(f"path {path!r} does not resolve inside the repository")
        if not self._pdp.registry.is_core(normalized):
            # Routine paths go through the dispatcher (grants, budgets); this
            # writer must not become a second, grant-free route to them.
            raise CoreWriteRejected(f"path {path!r} is not immutable core; use the dispatcher")
        attributes: dict[str, str] = {
            "content_digest": content_digest(content),
            "content_digest_source": CONTENT_DIGEST_SOURCE,
        }
        if requested_by is not None:
            attributes["requested_by"] = requested_by
        request = DecisionRequest(
            principal=principal,
            action="file.write",
            resource=normalized,
            tier=self._tier,
            attributes=attributes,
            approvals=tuple(approvals),
        )
        return request, normalized

    def action_hash_for(
        self,
        principal: Principal,
        path: str,
        content: bytes,
        *,
        requested_by: str | None = None,
    ) -> str:
        """What an approver signs to approve writing exactly *content* at *path*."""
        from acgs_lite.control_plane.action_hash import action_hash

        return action_hash(self._request(principal, path, content, (), requested_by)[0])

    def write_core(
        self,
        principal: Principal,
        path: str,
        content: bytes,
        *,
        approvals: Sequence[SignedApproval],
        requested_by: str | None = None,
    ) -> Decision:
        """Decide, then atomically write *content*; raise :class:`CoreWriteRejected`."""
        request, normalized = self._request(principal, path, content, approvals, requested_by)
        *parents, name = normalized.split("/")
        # Fail fast on an existing symlink; the descriptor walk below is what
        # actually enforces it (the pathname may change during the decision).
        probe = os.path.realpath(self._root / normalized)
        root = os.path.realpath(self._root)
        if not probe.startswith(root + os.sep) or (self._root / normalized).is_symlink():
            raise CoreWriteRejected(f"path {path!r} escapes the root or is a symlink")
        if self._incident_lock is not None:
            denial = self._incident_lock.write_denial(principal)
            if denial is not None:
                raise CoreWriteRejected(f"incident: {denial}")
        decision = self._decide(request)
        if not decision.allowed:
            raise CoreWriteRejected(f"core change denied: {decision.reason}", decision)
        self._require_not_halted(decision)
        # Hold the incident lock from the re-check through os.replace, so a
        # declare/transfer cannot land between the check and the commit.
        guard = (
            self._incident_lock._locked()
            if self._incident_lock is not None
            else contextlib.nullcontext()
        )
        from acgs_lite.control_plane.incident import IncidentLockError

        try:
            with guard:
                if self._incident_lock is not None:
                    # Re-check: the decision's listeners may have declared an
                    # incident or moved the holder.
                    denial = self._incident_lock.write_denial(principal)
                    if denial is not None:
                        raise CoreWriteRejected(f"incident: {denial}", decision)
                try:
                    dir_fd = _open_parent(root, parents)
                except OSError as exc:
                    raise CoreWriteRejected(
                        f"core write failed: parent of {path!r} is not a plain directory "
                        f"({type(exc).__name__})",
                        decision,
                    ) from exc
                try:
                    mode = _target_mode(dir_fd, name, self._pdp.registry.categories(normalized))
                    tmp = f".core-write-{secrets.token_hex(8)}"
                    fd = os.open(
                        tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW, 0o600, dir_fd=dir_fd
                    )
                    try:
                        with os.fdopen(fd, "wb") as handle:
                            handle.write(content)
                            handle.flush()
                            os.fchmod(handle.fileno(), mode)
                            os.fsync(handle.fileno())
                        # Last moment before the change becomes visible.
                        self._require_not_halted(decision)
                        os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
                    except BaseException:
                        with contextlib.suppress(FileNotFoundError):
                            os.unlink(tmp, dir_fd=dir_fd)
                        raise
                    os.fsync(dir_fd)
                except OSError as exc:
                    # TODO(control-plane-gap): the allow is already receipted and the
                    # approvals consumed; a failed write leaves no partial file but is
                    # not itself receipted.
                    raise CoreWriteRejected(
                        f"core write failed: {type(exc).__name__}", decision
                    ) from exc
                finally:
                    os.close(dir_fd)
        except IncidentLockError as exc:
            raise CoreWriteRejected(f"incident lock unavailable: {exc}", decision) from exc
        return decision

    def _require_not_halted(self, decision: Decision) -> None:
        switch = self._pdp.kill_switch
        if switch is None:
            return
        try:
            engaged = bool(switch.is_engaged())
        except Exception:
            engaged = True  # unreadable state: fail closed
        if engaged:
            raise CoreWriteRejected("kill switch engaged; core write not performed", decision)


_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
# New core files: readable by other service accounts, credentials owner-only.
NEW_FILE_MODE = 0o644
NEW_CREDENTIAL_FILE_MODE = 0o600


def _open_parent(root: str, parts: Sequence[str]) -> int:
    """Open (creating as needed) ``root/parts...`` one component at a time
    relative to the previous descriptor, refusing symlinked components, so a
    directory swapped for a symlink after the check cannot redirect the write."""
    fd = os.open(root, os.O_RDONLY | _DIRECTORY)
    try:
        for part in parts:
            try:
                child = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                os.mkdir(part, 0o755, dir_fd=fd)
                child = os.open(part, os.O_RDONLY | _DIRECTORY | _NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
    except BaseException:
        os.close(fd)
        raise
    return fd


def _target_mode(dir_fd: int, name: str, categories: frozenset[CoreCategory]) -> int:
    """Keep an existing file's permission bits; pick a default for new files."""
    try:
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        if CoreCategory.CREDENTIALS in categories:
            return NEW_CREDENTIAL_FILE_MODE
        return NEW_FILE_MODE
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        raise IsADirectoryError(f"{name!r} is not a regular file")
    return stat.S_IMODE(st.st_mode)
