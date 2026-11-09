"""Promotion gate: no candidate is promoted on agent-written evidence.

Darwin Goedel Machine: the agent fabricated "tests passed" logs. So every
evidence ref is validated by an independent :class:`ExternalRunVerifier`
*before* anything is emitted, agent-only evidence is refused, the PDP must
permit ``promotion.promote`` and a PROMOTION receipt is appended to the
harness-owned ledger. Because ``promotion.*`` is the PROMOTION_GATE core
namespace, INV-CORE-WRITE already denies any non-human proposer.

Binding: every evidence ref must carry ``artifact_digest == candidate_digest``
(one green run cannot certify a different candidate), and the PROMOTION
receipt records the hashed ``candidate_digest``. With ``roles=`` at least one
gate-attested approver must hold the ``promotion.approve`` capability in the
:class:`~.roles.RoleAssignments`; with ``incident_lock=`` a declared incident
refuses promotion by anyone but the lock holder. The gate binds its ledger
once (private capability) and requires the PDP to be bound to the *same*
ledger, so a permissive PDP cannot be paired with the harness ledger.
"""

from __future__ import annotations

import re
import threading
import warnings
from collections.abc import Sequence
from typing import TYPE_CHECKING

from acgs_lite.control_plane import receipt_ledger as _ledger_module
from acgs_lite.control_plane.approvals import SignedApproval
from acgs_lite.control_plane.context import DecisionRequest
from acgs_lite.control_plane.evidence import (
    DEFAULT_EVIDENCE_POLICY,
    EvidencePolicy,
    EvidenceSource,
    ExternalRunRef,
    ExternalRunVerifier,
    evaluate_evidence,
)
from acgs_lite.control_plane.pdp import Decision, PolicyDecisionPoint
from acgs_lite.control_plane.principal import Principal
from acgs_lite.control_plane.receipt_ledger import ReceiptEmissionError, ReceiptLedger
from acgs_lite.control_plane.receipts import SignedControlPlaneReceipt, promotion_evidence_keys
from acgs_lite.control_plane.tiers import ActionTier

if TYPE_CHECKING:
    from acgs_lite.control_plane.identity import AdminAttestor
    from acgs_lite.control_plane.incident import IncidentMutationLock
    from acgs_lite.control_plane.roles import RoleAssignments

__all__ = ["PROMOTION_ACTION", "PromotionGate", "PromotionRejected"]

PROMOTION_ACTION = "promotion.promote"
# TODO(control-plane-gap): champion/challenger promotion rules (tier, required
# evidence count, accepted sources) are design inference; T2 and the
# EvidencePolicy defaults are configurable per gate. Non-human principals can
# never promote (INV-CORE-WRITE); a service-driven pipeline needs a distinct
# change class in a later phase.
DEFAULT_PROMOTION_TIER = ActionTier.T2
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class PromotionRejected(Exception):
    """Promotion refused; ``decision`` is set when the PDP denied it."""

    def __init__(self, reason: str, decision: Decision | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.decision = decision


class PromotionGate:
    def __init__(
        self,
        ledger: ReceiptLedger,
        run_verifier: ExternalRunVerifier,
        *,
        pdp: PolicyDecisionPoint,
        evidence_policy: EvidencePolicy = DEFAULT_EVIDENCE_POLICY,
        tier: ActionTier = DEFAULT_PROMOTION_TIER,
        roles: RoleAssignments | None = None,
        incident_lock: IncidentMutationLock | None = None,
        admin_attestor: AdminAttestor | None = None,
    ) -> None:
        """With *admin_attestor* :meth:`promote` needs the requester's
        verified single-use HUMAN ``admin_credential=``."""
        from acgs_lite.control_plane.identity import checked_attestor

        self._attestor = checked_attestor(admin_attestor)
        if roles is not None:
            from acgs_lite.control_plane.roles import RoleAssignments

            if type(roles) is not RoleAssignments:
                raise TypeError("roles must be a RoleAssignments")
            if pdp.approval_gate is None:
                raise ValueError("role-checked promotion needs a PDP with an ApprovalGate")
        if incident_lock is not None:
            from acgs_lite.control_plane.incident import IncidentMutationLock

            if type(incident_lock) is not IncidentMutationLock:
                raise TypeError("incident_lock must be an IncidentMutationLock")
        self._roles = roles
        self._incident_lock = incident_lock
        if type(ledger) is not ReceiptLedger:
            raise TypeError("ledger must be a ReceiptLedger")
        if not isinstance(run_verifier, ExternalRunVerifier):
            raise TypeError("run_verifier must be an ExternalRunVerifier")
        if not isinstance(pdp, PolicyDecisionPoint):
            raise TypeError("pdp must be a PolicyDecisionPoint")
        if pdp.receipt_ledger is not ledger:
            raise ValueError("pdp must be bound to the same receipt ledger")
        registry_key = getattr(run_verifier, "signing_public_key_hex", None)
        if registry_key is not None and registry_key == ledger.public_key_hex:
            # TODO(control-plane-gap): key separation between the run registry
            # and the receipt ledger is advised, not enforced.
            warnings.warn(
                "run registry and receipt ledger share a signing key; a leak of one key "
                "forges both runs and receipts",
                UserWarning,
                stacklevel=2,
            )
        token = ledger.bind_promotion_gate(_ledger_module._GATE_BINDING)
        bound = ledger

        # The ledger token is held only by this closure, never as an attribute.
        def append_promotion(
            decision: Decision, request: DecisionRequest
        ) -> SignedControlPlaneReceipt:
            return bound.append_promotion(decision, request, capability=token)

        self._append_promotion = append_promotion
        self._lock = threading.Lock()
        self._ledger = ledger
        self._verifier = run_verifier
        self._pdp = pdp
        self._policy = evidence_policy
        self._tier = ActionTier(tier)

    def promote(
        self,
        principal: Principal,
        candidate_id: str,
        *,
        candidate_digest: str,
        evidence: Sequence[ExternalRunRef],
        approvers: Sequence[Principal] = (),
        approvals: Sequence[SignedApproval] = (),
        admin_credential: str | None = None,
    ) -> SignedControlPlaneReceipt:
        """Promote *candidate_id*.

        With an ApprovalGate on the PDP, approvers come only from signed
        ``approvals`` (bound to the promotion's action hash and consumed by
        the PDP); host-asserted ``approvers=`` are refused.
        """
        if not isinstance(principal, Principal):
            raise PromotionRejected("principal must be a Principal")
        if self._attestor is not None:
            self._attestor.require(
                principal, admin_credential, admin_only=False, error=PromotionRejected
            )
        if not isinstance(candidate_id, str) or not candidate_id.strip():
            raise PromotionRejected("candidate_id must be a non-empty string")
        if not isinstance(candidate_digest, str) or not _DIGEST.fullmatch(candidate_digest):
            raise PromotionRejected("candidate_digest must be 'sha256:<64 hex>'")
        refs = tuple(evidence)
        if not all(isinstance(ref, ExternalRunRef) for ref in refs):
            raise PromotionRejected("evidence must be ExternalRunRef objects")
        approver_tuple = tuple(approvers)
        approval_tuple = tuple(approvals)
        if approver_tuple and self._pdp.approval_gate is not None:
            raise PromotionRejected(
                "host-asserted approvers are not accepted with an ApprovalGate; pass approvals="
            )
        if not all(isinstance(a, Principal) for a in approver_tuple):
            raise PromotionRejected("approvers must be Principal objects")
        if any(a.canonical_id == principal.canonical_id for a in approver_tuple):
            raise PromotionRejected("the proposer cannot approve its own promotion")
        # Evidence first: an agent-only or unverifiable claim emits nothing.
        problems = evaluate_evidence(
            refs, self._verifier, self._policy, required=True, bind_digest=candidate_digest
        )
        if problems:
            raise PromotionRejected("; ".join(problems))
        with self._lock:
            return self._decide_and_record(
                principal, candidate_id, candidate_digest, refs, approver_tuple, approval_tuple
            )

    def __repr__(self) -> str:
        return f"PromotionGate(ledger={self._ledger!r})"

    def __copy__(self) -> PromotionGate:
        raise TypeError("PromotionGate cannot be copied")

    def __deepcopy__(self, memo: object) -> PromotionGate:
        raise TypeError("PromotionGate cannot be copied")

    def _reused_evidence(self, candidate_id: str, refs: Sequence[ExternalRunRef]) -> list[str]:
        # TODO(control-plane-gap): "one (run, artifact) certifies at most one
        # candidate per ledger" is design inference for champion/challenger
        # promotion; re-promoting the same candidate id is allowed.
        certified: dict[tuple[str, str, str], str] = {}
        for signed in self._ledger.receipts():
            for key in promotion_evidence_keys(signed.receipt):
                certified.setdefault(key, signed.receipt.resource)
        problems = []
        for ref in refs:
            if ref.source is EvidenceSource.AGENT_LOG:
                continue
            prior = certified.get((ref.provider, ref.run_id, ref.artifact_digest or ""))
            if prior is not None and prior != candidate_id:
                problems.append(f"run {ref.label} already certified candidate {prior!r}")
        return problems

    def _decide_and_record(
        self,
        principal: Principal,
        candidate_id: str,
        candidate_digest: str,
        refs: tuple[ExternalRunRef, ...],
        approver_tuple: tuple[Principal, ...],
        approval_tuple: tuple[SignedApproval, ...] = (),
    ) -> SignedControlPlaneReceipt:
        reused = self._reused_evidence(candidate_id, refs)
        if reused:
            raise PromotionRejected("; ".join(reused))
        if self._incident_lock is not None:
            denial = self._incident_lock.write_denial(principal)
            if denial is not None:
                raise PromotionRejected(f"incident: {denial}")
        request = DecisionRequest(
            principal=principal,
            action=PROMOTION_ACTION,
            resource=candidate_id,
            tier=self._tier,
            approvers=approver_tuple,
            attributes={
                "candidate_digest": candidate_digest,
                "external_runs": [ref.to_dict() for ref in refs],
            },
            approvals=approval_tuple,
        )
        gate = self._pdp.approval_gate
        if self._roles is not None and gate is not None:
            from acgs_lite.control_plane.roles import CAP_PROMOTION_APPROVE

            quorum = gate.evaluate(request, approval_tuple, record_request=False)
            if not any(
                self._roles.has_capability(a, CAP_PROMOTION_APPROVE) for a in quorum.approvers
            ):
                raise PromotionRejected(
                    "no attested approver holds the promotion.approve capability"
                )
        decision, decided = self._pdp._decide_attested(request)
        if not decision.allowed or decided is None:
            raise PromotionRejected(f"PDP denied promotion: {decision.reason}", decision)
        if self._roles is not None and gate is not None:
            if not any(
                a.canonical_id != principal.canonical_id
                and self._roles.has_capability(a, CAP_PROMOTION_APPROVE)
                for a in decided.approvers
            ):
                raise PromotionRejected(
                    "final approval lacks an independent promotion.approve approver", decision
                )
        if self._incident_lock is None:
            try:
                # The receipt cites the gate-attested approvers, not host input.
                self._require_not_halted(decision)
                return self._append_promotion(decision, decided)
            except ReceiptEmissionError as exc:
                raise PromotionRejected(f"promotion receipt could not be emitted: {exc}") from exc
        from acgs_lite.control_plane.incident import IncidentLockError

        try:
            # Held from the re-check through the receipt append, so an
            # incident cannot be declared between the check and the commit.
            with self._incident_lock._locked():
                # A PDP listener may have declared an incident (or moved the
                # holder) during the decision: re-check before the receipt.
                denial = self._incident_lock.write_denial(principal)
                if denial is not None:
                    raise PromotionRejected(f"incident: {denial}", decision)
                try:
                    self._require_not_halted(decision)
                    return self._append_promotion(decision, decided)
                except ReceiptEmissionError as exc:
                    raise PromotionRejected(
                        f"promotion receipt could not be emitted: {exc}"
                    ) from exc
        except IncidentLockError as exc:
            raise PromotionRejected(f"incident lock unavailable: {exc}", decision) from exc

    def _require_not_halted(self, decision: Decision) -> None:
        switch = self._pdp.kill_switch
        if switch is None:
            return
        try:
            engaged = bool(switch.is_engaged())
        except Exception:
            engaged = True
        if engaged:
            raise PromotionRejected("kill switch engaged; promotion not performed", decision)
