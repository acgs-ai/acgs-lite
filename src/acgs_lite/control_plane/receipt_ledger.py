"""Harness-owned, append-only receipt ledger.

The ledger is the lineage archive that caught the Darwin Goedel Machine's
fabricated "tests passed" logs: it is written by the harness (never by the
agent), signed, hash-chained, and kept in the immutable-core ``AUDIT_LOG``
area, which the PDP (INV-CORE-WRITE) and repository permissions both keep
out of every agent write path. :class:`JSONLReceiptStore` refuses any path
that does not classify as ``AUDIT_LOG``.

No public API mints a receipt for a caller-supplied decision:

* A ledger is bound to exactly one :class:`PolicyDecisionPoint` (which passes
  ``receipt_ledger=``) and at most one :class:`PromotionGate`. Binding needs a
  module-private capability; each binding returns a private per-ledger token
  that :meth:`ReceiptLedger.append_decision` / ``append_promotion`` require.
  A second PDP or gate cannot bind the same ledger.
* In-process Python offers no hard isolation: code running in the same interpreter
  can reach private names. The PDP and ledger must therefore run outside the
  agent's process (already a Phase 1 requirement); the capabilities only
  ensure that no *public* path forges receipts.

Invariants (mirroring :mod:`acgs_lite.audit`): hash, sign and store write
happen under one lock and the head only advances after the write; the JSONL
store additionally takes an exclusive ``flock`` and refuses to append unless
the file tail is the ledger's head (a second writer forks nothing, it fails
closed). Reopening re-verifies hashes, linkage, ``ledger_id`` and every
signature against the signer's key.
"""

from __future__ import annotations

import importlib
import json
import logging
import os
import threading
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from acgs_lite.control_plane.context import DecisionRequest
from acgs_lite.control_plane.evidence import (
    DEFAULT_EVIDENCE_POLICY,
    EvidencePolicy,
    ExternalRunRef,
    _check_digest,
    parse_external_runs,
    require_audit_store_path,
)
from acgs_lite.control_plane.immutable_core import DEFAULT_IMMUTABLE_CORE, ImmutableCoreRegistry
from acgs_lite.control_plane.pdp import Decision
from acgs_lite.control_plane.principal import Principal, PrincipalKind
from acgs_lite.control_plane.receipts import (
    GENESIS_RECEIPT_HASH,
    MAX_APPROVERS,
    MAX_EXTERNAL_RUNS,
    MAX_FIELD_CHARS,
    ORIGIN_DISPATCHER_PRE_DENIAL,
    ORIGIN_PDP,
    ORIGIN_PROMOTION_GATE,
    ApproverRef,
    ControlPlaneReceipt,
    ReceiptKind,
    SignedControlPlaneReceipt,
    sign_control_plane_receipt,
    truncate_reason,
)
from acgs_lite.legitimacy.signing import ReceiptSigner, ReceiptSigningUnavailable, verify_signature

__all__ = [
    "DEFAULT_RECEIPT_STORE_PATH",
    "InMemoryReceiptStore",
    "JSONLReceiptStore",
    "ReceiptCapabilityError",
    "ReceiptConflict",
    "ReceiptEmissionError",
    "ReceiptLedger",
    "ReceiptStore",
    "ReceiptStoreCorrupted",
]

logger = logging.getLogger(__name__)

DEFAULT_RECEIPT_STORE_PATH = "audit/receipts.jsonl"

# Module-private binding capabilities (see module docstring).
_PDP_BINDING = object()
_GATE_BINDING = object()


def _token_pair() -> tuple[object, Callable[[object], bool]]:
    token = object()

    def is_token(candidate: object) -> bool:
        return candidate is token

    return token, is_token


class ReceiptEmissionError(RuntimeError):
    """A receipt could not be built, signed or stored (the chain did not advance)."""


class ReceiptConflict(ReceiptEmissionError):
    """The store's tail is not this ledger's head (another writer appended)."""


class ReceiptCapabilityError(PermissionError):
    """A receipt was requested without the ledger's private capability."""


class ReceiptStoreCorrupted(ValueError):
    """A stored receipt chain is malformed, broken or not signed by this ledger."""


@runtime_checkable
class ReceiptStore(Protocol):
    def append(self, signed: SignedControlPlaneReceipt) -> None:
        """Append iff the stored tail hash equals ``signed.receipt.prev_receipt_hash``."""
        ...

    def read_all(self) -> tuple[SignedControlPlaneReceipt, ...]: ...


class InMemoryReceiptStore:
    def __init__(self) -> None:
        self._items: list[SignedControlPlaneReceipt] = []
        self._lock = threading.Lock()

    def append(self, signed: SignedControlPlaneReceipt) -> None:
        with self._lock:
            tail = self._items[-1].receipt.receipt_hash if self._items else GENESIS_RECEIPT_HASH
            if tail != signed.receipt.prev_receipt_hash:
                raise ReceiptConflict("store tail is not the ledger head")
            self._items.append(signed)

    def read_all(self) -> tuple[SignedControlPlaneReceipt, ...]:
        with self._lock:
            return tuple(self._items)


def _flock_module() -> Any:
    try:
        return importlib.import_module("fcntl")
    except ImportError as exc:  # pragma: no cover - non-POSIX only
        raise ReceiptEmissionError("JSONL receipt store needs POSIX flock") from exc


def _parse_line(line: str, number: int) -> SignedControlPlaneReceipt:
    try:
        return SignedControlPlaneReceipt.from_dict(json.loads(line))
    except (ValueError, TypeError) as exc:
        raise ReceiptStoreCorrupted(f"line {number}: {exc}") from exc


class JSONLReceiptStore:
    """One signed receipt per line in the core AUDIT_LOG area.

    The tail (byte offset + last receipt hash) is scanned once on open and
    cached; an unterminated final record is refused. Each append takes
    ``flock(LOCK_EX)`` and stats the file: a file that shrank *or grew*
    since this store's last write fails closed (bytes from another writer
    are never trusted). It then requires the tail to be the new receipt's
    predecessor, writes, fsyncs and rolls back a partial write.
    """

    def __init__(
        self,
        path: str | Path = DEFAULT_RECEIPT_STORE_PATH,
        *,
        registry: ImmutableCoreRegistry = DEFAULT_IMMUTABLE_CORE,
    ) -> None:
        self._path = require_audit_store_path(path, registry)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._end = 0
        self._tail = GENESIS_RECEIPT_HASH
        if self._path.exists():
            data = self._path.read_bytes()
            self._require_terminated(data)
            self._end = len(data)
            self._tail = self._last_hash(data, GENESIS_RECEIPT_HASH)

    @property
    def path(self) -> Path:
        return self._path

    @staticmethod
    def _require_terminated(data: bytes) -> None:
        # A final record without "\n" would be glued to the next append and
        # make the whole store unreadable, so refuse it up front.
        if data and not data.endswith(b"\n"):
            raise ReceiptStoreCorrupted("store tail is not newline-terminated")

    @staticmethod
    def _last_hash(chunk: bytes, default: str) -> str:
        lines = [line for line in chunk.split(b"\n") if line.strip()]
        if not lines:
            return default
        try:
            text = lines[-1].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReceiptStoreCorrupted("store tail is not UTF-8") from exc
        return _parse_line(text, 0).receipt.receipt_hash

    def append(self, signed: SignedControlPlaneReceipt) -> None:
        fcntl = _flock_module()
        line = (json.dumps(signed.to_dict(), sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
        with self._lock, open(self._path, "a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                size = os.fstat(handle.fileno()).st_size
                if size < self._end:
                    raise ReceiptConflict("receipt store shrank since it was opened")
                if size > self._end:
                    # This store's ledger is its only writer; bytes it did not
                    # write are unverified (a copy of the head would pass the
                    # tail check and duplicate a sequence), so refuse them.
                    raise ReceiptConflict(
                        "receipt store grew since the last append (concurrent writer?)"
                    )
                if self._tail != signed.receipt.prev_receipt_hash:
                    raise ReceiptConflict("store tail is not the ledger head (concurrent writer?)")
                try:
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())
                except BaseException:
                    handle.truncate(size)
                    raise
                self._end = size + len(line)
                self._tail = signed.receipt.receipt_hash
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def read_all(self) -> tuple[SignedControlPlaneReceipt, ...]:
        if not self._path.exists():
            return ()
        with open(self._path, encoding="utf-8") as handle:
            return tuple(
                _parse_line(line, number)
                for number, line in enumerate(handle, start=1)
                if line.strip()
            )


def _check_existing(
    receipts: Sequence[SignedControlPlaneReceipt], signer: ReceiptSigner
) -> str | None:
    """Verify a reopened chain; return its ledger_id (None if empty)."""
    prev = GENESIS_RECEIPT_HASH
    ledger_id: str | None = None
    public_key = signer.public_key_hex()
    for index, signed in enumerate(receipts):
        receipt = signed.receipt
        if receipt.sequence != index or receipt.prev_receipt_hash != prev:
            raise ReceiptStoreCorrupted(f"chain broken at sequence {index}")
        if not receipt.verify_hash():
            raise ReceiptStoreCorrupted(f"receipt_hash mismatch at sequence {index}")
        if ledger_id is not None and receipt.ledger_id != ledger_id:
            raise ReceiptStoreCorrupted(f"mixed ledger_id at sequence {index}")
        ledger_id = receipt.ledger_id
        if signed.key_id != signer.key_id or signed.public_key_hex != public_key:
            raise ReceiptStoreCorrupted(f"receipt {index} is not signed by this ledger's key")
        try:
            good = verify_signature(
                signed.algorithm, public_key, signed.signing_message(), signed.signature
            )
        except (ValueError, ReceiptSigningUnavailable) as exc:
            raise ReceiptStoreCorrupted(f"cannot verify receipt {index}: {exc}") from exc
        if not good:
            raise ReceiptStoreCorrupted(f"bad signature at sequence {index}")
        prev = receipt.receipt_hash
    return ledger_id


class ReceiptLedger:
    """Append-only signed receipt chain. Owned by the harness, not the agent."""

    def __init__(
        self,
        signer: ReceiptSigner,
        *,
        store: ReceiptStore,
        ledger_id: str | None = None,
        evidence_policy: EvidencePolicy = DEFAULT_EVIDENCE_POLICY,
    ) -> None:
        if not isinstance(signer, ReceiptSigner):
            raise TypeError("signer must implement ReceiptSigner")
        if not isinstance(store, ReceiptStore):
            raise TypeError("store must implement ReceiptStore")
        existing = store.read_all()
        stored_id = _check_existing(existing, signer)
        if stored_id is not None and ledger_id is not None and stored_id != ledger_id:
            raise ReceiptStoreCorrupted("store belongs to a different ledger_id")
        self._ledger_id = stored_id or ledger_id or uuid.uuid4().hex
        self._signer = signer
        self._store = store
        self._policy = evidence_policy
        self._lock = threading.Lock()
        self._receipts: list[SignedControlPlaneReceipt] = list(existing)
        # Tokens live only inside these closures (and the binder's own
        # closure); no attribute holds a token.
        self._is_pdp: Callable[[object], bool] | None = None
        self._is_gate: Callable[[object], bool] | None = None

    def __repr__(self) -> str:
        return f"ReceiptLedger(ledger_id={self._ledger_id!r}, receipts={len(self)})"

    def __copy__(self) -> ReceiptLedger:
        raise TypeError("ReceiptLedger cannot be copied")

    def __deepcopy__(self, memo: object) -> ReceiptLedger:
        raise TypeError("ReceiptLedger cannot be copied")

    @property
    def ledger_id(self) -> str:
        return self._ledger_id

    @property
    def key_id(self) -> str:
        return self._signer.key_id

    @property
    def public_key_hex(self) -> str:
        return self._signer.public_key_hex()

    @property
    def head_hash(self) -> str:
        with self._lock:
            return (
                self._receipts[-1].receipt.receipt_hash if self._receipts else GENESIS_RECEIPT_HASH
            )

    def receipts(self) -> tuple[SignedControlPlaneReceipt, ...]:
        with self._lock:
            return tuple(self._receipts)

    def __len__(self) -> int:
        with self._lock:
            return len(self._receipts)

    # -- binding (capability-gated) -------------------------------------

    def bind_decision_source(self, capability: object) -> object:
        """Bind the one PDP allowed to emit decision receipts; returns its token."""
        with self._lock:
            if capability is not _PDP_BINDING:
                raise ReceiptCapabilityError("decision receipts can only be bound by the PDP")
            if self._is_pdp is not None:
                raise ReceiptCapabilityError("ledger is already bound to a PDP")
            token, self._is_pdp = _token_pair()
            return token

    def bind_promotion_gate(self, capability: object) -> object:
        """Bind the one PromotionGate allowed to emit promotion receipts."""
        with self._lock:
            if capability is not _GATE_BINDING:
                raise ReceiptCapabilityError("promotion receipts can only be bound by the gate")
            if self._is_gate is not None:
                raise ReceiptCapabilityError("ledger is already bound to a promotion gate")
            token, self._is_gate = _token_pair()
            return token

    # -- append ---------------------------------------------------------

    def append_decision(
        self,
        decision: Decision,
        request: DecisionRequest | None = None,
        *,
        capability: object,
        origin: str = ORIGIN_PDP,
    ) -> SignedControlPlaneReceipt:
        """PDP-only. External runs come from ``request.attributes["external_runs"]``
        (also bound by ``inputs_digest``); malformed refs fail an allow and are
        dropped from a deny so the deny is still recorded. An allow must come
        with the request it answers."""
        if self._is_pdp is None or not self._is_pdp(capability):
            raise ReceiptCapabilityError("append_decision requires the bound PDP's capability")
        if origin not in (ORIGIN_PDP, ORIGIN_DISPATCHER_PRE_DENIAL):
            raise ReceiptEmissionError(f"invalid decision receipt origin {origin!r}")
        if not isinstance(decision, Decision):
            raise ReceiptEmissionError("decision must be a Decision")
        if decision.allowed and (not isinstance(request, DecisionRequest) or origin != ORIGIN_PDP):
            raise ReceiptEmissionError("an allowed decision needs its request (origin pdp)")
        runs: tuple[ExternalRunRef, ...] = ()
        attributes = getattr(request, "attributes", None)
        if attributes is not None:
            try:
                runs = parse_external_runs(attributes.get("external_runs"))
            except (ValueError, TypeError) as exc:
                if decision.allowed:
                    raise ReceiptEmissionError("malformed external_runs on an allow") from exc
                logger.warning("dropping malformed external_runs on a deny receipt")
        return self._append(ReceiptKind.POLICY_DECISION, decision, request, runs, None, origin)

    def append_promotion(
        self,
        decision: Decision,
        request: DecisionRequest,
        *,
        capability: object,
    ) -> SignedControlPlaneReceipt:
        """Gate-only. Re-asserts the promotion invariants before signing."""
        if self._is_gate is None or not self._is_gate(capability):
            raise ReceiptCapabilityError("append_promotion requires the bound gate's capability")
        if not isinstance(decision, Decision) or decision.allowed is not True:
            raise ReceiptEmissionError("a promotion receipt requires an allowed decision")
        if not isinstance(request, DecisionRequest) or request.principal.kind is not (
            PrincipalKind.HUMAN
        ):
            raise ReceiptEmissionError("promotion requires a HUMAN requester")
        ids = [a.canonical_id for a in request.approvers]
        if len(set(ids)) != len(ids) or request.principal.canonical_id in ids:
            raise ReceiptEmissionError("promotion approvers must be distinct and not the requester")
        try:
            runs = parse_external_runs(request.attributes.get("external_runs"))
            candidate = request.attributes.get("candidate_digest")
        except (ValueError, TypeError) as exc:
            raise ReceiptEmissionError("malformed promotion evidence") from exc
        if not isinstance(candidate, str):
            raise ReceiptEmissionError("promotion requires candidate_digest")
        return self._append(
            ReceiptKind.PROMOTION, decision, request, runs, candidate, ORIGIN_PROMOTION_GATE
        )

    def _append(
        self,
        kind: ReceiptKind,
        decision: Decision,
        request: DecisionRequest | None,
        external_runs: Sequence[ExternalRunRef],
        candidate_digest: str | None,
        origin: str,
    ) -> SignedControlPlaneReceipt:
        if not isinstance(decision, Decision):
            raise ReceiptEmissionError("decision must be a Decision")
        principal = getattr(request, "principal", None)
        if not isinstance(principal, Principal):
            principal = None
        if request is not None and decision.inputs_digest:
            try:
                bound = request.inputs_digest() == decision.inputs_digest
            except (TypeError, ValueError):
                bound = False
            if not bound:
                raise ReceiptEmissionError("decision inputs_digest does not match the request")
        raw_approvers = getattr(request, "approvers", ())
        approvers: tuple[ApproverRef, ...] = ()
        oversized = len(tuple(external_runs)) > MAX_EXTERNAL_RUNS
        if isinstance(raw_approvers, tuple) and all(
            isinstance(a, Principal) for a in raw_approvers
        ):
            if len(raw_approvers) > MAX_APPROVERS or any(
                len(a.id) > MAX_FIELD_CHARS for a in raw_approvers
            ):
                oversized = True
            else:
                approvers = tuple(ApproverRef(a.id, a.kind.value) for a in raw_approvers)
        if principal is not None and len(principal.system_id or "") > MAX_FIELD_CHARS:
            oversized = True
        if oversized:
            if decision.allowed:
                raise ReceiptEmissionError("receipt evidence exceeds the size limits")
            # A deny grants nothing: record it without the oversized evidence.
            logger.warning("dropping oversized evidence from a deny receipt")
            approvers, external_runs = (), ()
            if principal is not None and len(principal.system_id or "") > MAX_FIELD_CHARS:
                principal = None
        attributes = getattr(request, "attributes", None)
        claims_success = (
            kind is ReceiptKind.PROMOTION
            or self._policy.is_success_claim(decision.action)
            or (attributes is not None and attributes.get("claims_success") is True)
        )
        if claims_success and candidate_digest is None and attributes is not None:
            candidate = attributes.get("candidate_digest")
            if candidate is not None:
                try:
                    # Use the same strict digest validation as external run refs.
                    candidate_digest = _check_digest(candidate, "candidate_digest")
                except (ValueError, TypeError) as exc:
                    if decision.allowed:
                        raise ReceiptEmissionError(
                            "malformed candidate_digest on success claim"
                        ) from exc
                    logger.warning("dropping malformed candidate_digest from deny receipt")
        with self._lock:
            try:
                head = (
                    self._receipts[-1].receipt.receipt_hash
                    if self._receipts
                    else GENESIS_RECEIPT_HASH
                )
                receipt = ControlPlaneReceipt.create(
                    ledger_id=self._ledger_id,
                    origin=origin,
                    kind=kind,
                    sequence=len(self._receipts),
                    prev_receipt_hash=head,
                    principal_id=principal.id if principal else decision.principal_id,
                    principal_kind=principal.kind.value if principal else None,
                    system_id=principal.system_id if principal else None,
                    action=decision.action,
                    resource=decision.resource,
                    tier=None if decision.tier is None else int(decision.tier),
                    constitution_hash=decision.constitution_hash,
                    policy_digest=decision.policy_digest,
                    policy_set_digest=decision.policy_set_digest,
                    inputs_digest=decision.inputs_digest,
                    decision_id=decision.decision_id,
                    allowed=decision.allowed,
                    determining_policies=decision.determining_policies,
                    reason=truncate_reason(decision.reason),
                    error=decision.error,
                    claims_success=claims_success,
                    candidate_digest=candidate_digest,
                    approvers=approvers,
                    external_runs=tuple(external_runs),
                )
                signed = sign_control_plane_receipt(receipt, self._signer)
                self._store.append(signed)
            except ReceiptEmissionError:
                raise
            except Exception as exc:
                raise ReceiptEmissionError(
                    f"receipt emission failed: {type(exc).__name__}"
                ) from exc
            self._receipts.append(signed)
            return signed
