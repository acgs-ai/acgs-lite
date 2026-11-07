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

import hashlib
import os
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

from acgs_lite.control_plane.approvals import SignedApproval
from acgs_lite.control_plane.context import DecisionRequest
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
        target = self._root / normalized
        root = os.path.realpath(self._root)
        parent = os.path.realpath(target.parent)
        if parent != root and not parent.startswith(root + os.sep):
            raise CoreWriteRejected(f"path {path!r} escapes the repository root")
        if target.is_symlink():
            raise CoreWriteRejected(f"refusing to write through symlink {path!r}")
        if self._incident_lock is not None:
            denial = self._incident_lock.write_denial(principal)
            if denial is not None:
                raise CoreWriteRejected(f"incident: {denial}")
        decision = self._decide(request)
        if not decision.allowed:
            raise CoreWriteRejected(f"core change denied: {decision.reason}", decision)
        try:
            os.makedirs(parent, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=parent, prefix=".core-write-")
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, os.path.join(parent, target.name))
            except BaseException:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise
            dir_fd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError as exc:
            # TODO(control-plane-gap): the allow is already receipted and the
            # approvals consumed; a failed write leaves no partial file but is
            # not itself receipted.
            raise CoreWriteRejected(f"core write failed: {type(exc).__name__}", decision) from exc
        return decision
