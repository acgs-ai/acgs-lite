"""An independent kill switch the agent cannot operate.

Evidence: in the Replit incident an agent deleted a live production database
during a natural-language code freeze -- the freeze was an instruction to the
model, not a control outside it. This switch lives in the harness: the
dispatcher and the PDP check it *first* on every call, engaged means every
tool call is denied (including T0 reads), and any error reading its state
counts as engaged.

It reuses :class:`acgs_lite.circuit_breaker.GovernanceCircuitBreaker` (an
in-process ``threading.Event`` plus an atomically renamed cross-process
signal file ``acgs-halt-<system_id>``), but reads the signal file itself
with fail-closed error handling: the breaker's ``Path.exists`` probe would
report "not tripped" for some I/O errors.

The default signal directory, ``control-plane/halt/``, lies under the
``control-plane/**`` CONTROL_PLANE core pattern, so no agent tool may write
or delete the halt file through the dispatcher (INV-CORE-WRITE,
INV-TOOL-ARG-CORE). Only HUMAN or SERVICE operators may engage; only a HUMAN
may release.
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from acgs_lite.circuit_breaker import GovernanceCircuitBreaker
from acgs_lite.control_plane.immutable_core import ImmutableCoreRegistry
from acgs_lite.control_plane.principal import Principal, PrincipalKind

if TYPE_CHECKING:
    from acgs_lite.control_plane.identity import AdminAttestor

__all__ = [
    "DEFAULT_HALT_DIR",
    "KillSwitch",
    "KillSwitchOperationRejected",
]

logger = logging.getLogger(__name__)

DEFAULT_HALT_DIR = Path("control-plane") / "halt"


class KillSwitchOperationRejected(PermissionError):
    """Raised when a principal may not engage or release the switch."""


def _stat_probe(path: Path) -> bool:
    """True if the signal file exists; raises on anything but ENOENT."""
    try:
        os.stat(path)
    except FileNotFoundError:
        return False
    return True


class KillSwitch:
    """Harness-owned halt for one ``system_id``.

    ``probe`` (tests) replaces the signal-file existence check; it must raise
    rather than guess when it cannot tell.
    """

    def __init__(
        self,
        system_id: str,
        *,
        signal_dir: Path | str = DEFAULT_HALT_DIR,
        probe: Callable[[Path], bool] = _stat_probe,
        registry: ImmutableCoreRegistry | None = None,
        admin_attestor: AdminAttestor | None = None,
    ) -> None:
        """With *admin_attestor* (the facade wires one) engage and release
        need ``admin_credential=``: for engage a HUMAN operator's verified
        single-use credential (or a SERVICE credential with scope
        ``halt:engage``), for release the directory admin's."""
        from acgs_lite.control_plane.identity import checked_attestor

        self._attestor = checked_attestor(admin_attestor)
        if not isinstance(system_id, str) or not system_id.strip():
            raise ValueError("system_id must be a non-empty string")
        directory = Path(signal_dir)
        if not directory.is_absolute() and registry is not None and registry.repo_root:
            # Resolve against the repository root, not the process cwd, so the
            # halt file lands under the core-protected control-plane/ tree.
            directory = Path(registry.repo_root) / directory
        # TODO(control-plane-gap): without a registry repo_root a relative
        # signal_dir resolves against the cwd, which may lie outside the
        # protected tree.
        directory.mkdir(parents=True, exist_ok=True)
        self._dir = directory
        self._breaker = GovernanceCircuitBreaker(system_id, signal_dir=directory, check_file=True)
        self._probe = probe
        self._lock = threading.Lock()
        self._engaged = False
        self._reason = ""

    @property
    def system_id(self) -> str:
        return self._breaker.system_id

    @property
    def signal_path(self) -> Path:
        return self._dir / f"acgs-halt-{self.system_id}"

    @property
    def reason(self) -> str:
        with self._lock:
            if self._reason:
                return self._reason
        try:
            return self.signal_path.read_text(encoding="utf-8").strip() or "halted"
        except OSError:
            return "halted (reason unavailable)"

    def engage(
        self, operator: Principal, reason: str, *, admin_credential: str | None = None
    ) -> None:
        """Halt every governed call. HUMAN or SERVICE operators only."""
        if not isinstance(operator, Principal) or operator.kind is PrincipalKind.AGENT:
            raise KillSwitchOperationRejected("only a HUMAN or SERVICE operator may engage")
        if self._attestor is not None:
            from acgs_lite.control_plane.identity import KILL_SWITCH_ENGAGE_SCOPE

            if operator.kind is PrincipalKind.HUMAN:
                self._attestor.require(
                    operator,
                    admin_credential,
                    admin_only=False,
                    error=KillSwitchOperationRejected,
                )
            else:
                self._attestor.require(
                    operator,
                    admin_credential,
                    admin_only=False,
                    error=KillSwitchOperationRejected,
                    scope=KILL_SWITCH_ENGAGE_SCOPE,
                    kinds=frozenset({PrincipalKind.SERVICE}),
                )
        text = reason if isinstance(reason, str) and reason.strip() else "halted"
        with self._lock:
            self._engaged = True
            self._reason = f"{text} (by {operator.id})"
        self._breaker.trip(reason=self._reason)
        try:
            written = self._probe(self.signal_path)
        except OSError:
            written = False
        if not written:
            # The in-process flag still halts this process (fail closed).
            logger.error("kill switch signal file was not written: %s", self.signal_path)

    def release(self, operator: Principal, *, admin_credential: str | None = None) -> None:
        """Resume. HUMAN only; stays engaged if the signal file survives."""
        if not isinstance(operator, Principal) or operator.kind is not PrincipalKind.HUMAN:
            raise KillSwitchOperationRejected("only a HUMAN operator may release")
        if self._attestor is not None:
            # Releasing a halt is riskier than engaging one: the admin only.
            self._attestor.require(operator, admin_credential, error=KillSwitchOperationRejected)
        self._breaker.reset()
        try:
            still_there = self._probe(self.signal_path)
        except OSError:
            still_there = True
        with self._lock:
            if still_there:
                raise KillSwitchOperationRejected(
                    "signal file could not be removed; the switch stays engaged"
                )
            self._engaged = False
            self._reason = ""

    def is_engaged(self) -> bool:
        """Checked on every call: in-memory flag, then the signal file.

        A missing signal *directory* or any I/O error counts as engaged.
        """
        with self._lock:
            if self._engaged:
                return True
        try:
            if not self._dir.is_dir():
                return True
            return bool(self._probe(self.signal_path))
        except Exception:
            return True
