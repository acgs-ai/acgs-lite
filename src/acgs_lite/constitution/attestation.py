"""exp177: Governance attestation receipts with cryptographic verification.

Attestations are independently verifiable certificates proving that a
specific action was evaluated against a specific constitution at a
specific time. Unlike audit logs (internal records), attestations can be
shared with regulators, insurers, and downstream systems as tamper-evident
proof of governance.

Each attestation is HMAC-SHA256 signed over its canonical content, so any
modification invalidates the signature. Attestations can be chained for
batch provenance (e.g. "these 50 actions were all governed by constitution
hash X in pipeline run Y").

Usage::

    from acgs_lite.constitution.attestation import AttestationRegistry

    registry = AttestationRegistry(signing_key="my-secret-key")

    att = registry.attest(
        action="deploy to production",
        decision="allow",
        constitution_hash="608508a9bd224290",
        rule_ids_evaluated=["SAFE-001", "SAFE-002"],
    )

    assert registry.verify(att)  # True
    att.decision = "deny"
    assert not registry.verify(att)  # Tampered!

    # Export chain for auditors
    chain = registry.export_chain(format="json")
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

from acgs_lite._compat import constant_time_compare


class GovernanceAttestation:
    """A signed attestation receipt for a governance decision.

    Attributes:
        attestation_id: Unique identifier (e.g. ``"ATT-00001"``).
        action_hash: SHA-256 of the evaluated action text.
        action_preview: First 80 chars of the action (for human reference).
        constitution_hash: Hash of the constitution used for evaluation.
        decision: Governance outcome (``"allow"``/``"deny"``/``"escalate"``).
        rule_ids_evaluated: List of rule IDs that were checked.
        violations_found: List of violation rule IDs (empty for allow).
        timestamp: ISO-8601 creation timestamp.
        metadata: Extension data (pipeline_id, agent_id, etc.).
        signature: HMAC-SHA256 hex digest of canonical content.
        chain_index: Position in an attestation chain (0-based).
        previous_attestation_id: Link to prior attestation (chain).
    """

    __slots__ = (
        "attestation_id",
        "action_hash",
        "action_preview",
        "constitution_hash",
        "decision",
        "domain",
        "rule_ids_evaluated",
        "violations_found",
        "timestamp",
        "metadata",
        "signature",
        "chain_index",
        "previous_attestation_id",
    )

    def __init__(
        self,
        *,
        attestation_id: str,
        action_hash: str,
        action_preview: str,
        constitution_hash: str,
        decision: str,
        rule_ids_evaluated: list[str],
        violations_found: list[str],
        timestamp: str,
        signature: str = "",
        chain_index: int = 0,
        previous_attestation_id: str = "",
        metadata: dict[str, Any] | None = None,
        domain: str | None = None,
    ) -> None:
        self.attestation_id = attestation_id
        self.action_hash = action_hash
        self.action_preview = action_preview
        self.constitution_hash = constitution_hash
        self.decision = decision
        self.domain = domain  # CapabilityDomain value if domain-scoped governance
        self.rule_ids_evaluated = list(rule_ids_evaluated)
        self.violations_found = list(violations_found)
        self.timestamp = timestamp
        self.signature = signature
        self.chain_index = chain_index
        self.previous_attestation_id = previous_attestation_id
        self.metadata = metadata or {}

    def canonical_content(self) -> str:
        """Return the canonical string representation for signing.

        The canonical form is a deterministic JSON string of the
        attestation's core fields (excluding signature itself).
        """
        payload = {
            "attestation_id": self.attestation_id,
            "action_hash": self.action_hash,
            "constitution_hash": self.constitution_hash,
            "decision": self.decision,
            "rule_ids_evaluated": sorted(self.rule_ids_evaluated),
            "violations_found": sorted(self.violations_found),
            "timestamp": self.timestamp,
            "chain_index": self.chain_index,
            "previous_attestation_id": self.previous_attestation_id,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for JSON export."""
        return {
            "attestation_id": self.attestation_id,
            "action_hash": self.action_hash,
            "action_preview": self.action_preview,
            "constitution_hash": self.constitution_hash,
            "decision": self.decision,
            "domain": self.domain,
            "rule_ids_evaluated": self.rule_ids_evaluated,
            "violations_found": self.violations_found,
            "timestamp": self.timestamp,
            "signature": self.signature,
            "chain_index": self.chain_index,
            "previous_attestation_id": self.previous_attestation_id,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GovernanceAttestation:
        """Reconstruct from dict (e.g. JSON import)."""
        return cls(
            attestation_id=data["attestation_id"],
            action_hash=data["action_hash"],
            action_preview=data.get("action_preview", ""),
            constitution_hash=data["constitution_hash"],
            decision=data["decision"],
            rule_ids_evaluated=data.get("rule_ids_evaluated", []),
            violations_found=data.get("violations_found", []),
            timestamp=data["timestamp"],
            signature=data.get("signature", ""),
            chain_index=data.get("chain_index", 0),
            previous_attestation_id=data.get("previous_attestation_id", ""),
            metadata=data.get("metadata"),
            domain=data.get("domain"),
        )

    def __repr__(self) -> str:
        return (
            f"GovernanceAttestation({self.attestation_id!r}, "
            f"decision={self.decision!r}, "
            f"constitution={self.constitution_hash[:8]}...)"
        )


class AttestationRegistry:
    """Registry for creating, verifying, and exporting governance attestations.

    Provides HMAC-SHA256 signing of attestation receipts and maintains an
    ordered chain for batch provenance. Attestations are independently
    verifiable without access to the governance engine.

    Args:
        signing_key: Secret key for HMAC-SHA256 signing. If empty,
            attestations are created unsigned (verification always fails).

    Usage::

        registry = AttestationRegistry(signing_key="secret")

        a1 = registry.attest(
            action="deploy service",
            decision="allow",
            constitution_hash="608508a9bd224290",
        )

        a2 = registry.attest(
            action="delete database",
            decision="deny",
            constitution_hash="608508a9bd224290",
            violations_found=["SAFE-003"],
        )

        assert registry.verify(a1)
        chain = registry.export_chain(format="json")

    """

    __slots__ = ("_key", "_attestations", "_counter")

    def __init__(self, signing_key: str = "") -> None:
        self._key = signing_key.encode("utf-8") if signing_key else b""
        self._attestations: list[GovernanceAttestation] = []
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"ATT-{self._counter:05d}"

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _hash_action(action: str) -> str:
        return hashlib.sha256(action.encode("utf-8")).hexdigest()

    def _sign(self, content: str) -> str:
        if not self._key:
            return ""
        return hmac.new(self._key, content.encode("utf-8"), hashlib.sha256).hexdigest()

    def attest(
        self,
        *,
        action: str,
        decision: str,
        constitution_hash: str,
        rule_ids_evaluated: list[str] | None = None,
        violations_found: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> GovernanceAttestation:
        """Create a signed attestation for a governance decision.

        Args:
            action: The action text that was evaluated.
            decision: Governance outcome (allow/deny/escalate).
            constitution_hash: Hash of the constitution used.
            rule_ids_evaluated: Rule IDs that were checked.
            violations_found: Rule IDs that triggered violations.
            metadata: Optional extension data.

        Returns:
            A signed GovernanceAttestation linked to the chain.
        """
        prev_id = self._attestations[-1].attestation_id if self._attestations else ""
        chain_idx = len(self._attestations)

        att = GovernanceAttestation(
            attestation_id=self._next_id(),
            action_hash=self._hash_action(action),
            action_preview=action[:80],
            constitution_hash=constitution_hash,
            decision=decision,
            rule_ids_evaluated=rule_ids_evaluated or [],
            violations_found=violations_found or [],
            timestamp=self._now(),
            chain_index=chain_idx,
            previous_attestation_id=prev_id,
            metadata=metadata,
        )
        att.signature = self._sign(att.canonical_content())
        self._attestations.append(att)
        return att

    def verify(self, attestation: GovernanceAttestation) -> bool:
        """Verify an attestation's HMAC signature.

        Returns:
            True if signature is valid and matches canonical content.
            False if unsigned, tampered, or key mismatch.
        """
        if not self._key or not attestation.signature:
            return False
        expected = self._sign(attestation.canonical_content())
        return constant_time_compare(attestation.signature, expected)

    def verify_chain_integrity(self) -> dict[str, Any]:
        """Verify the entire attestation chain for gaps and tampering.

        Returns:
            dict with ``valid`` (bool), ``total``, ``verified``,
            ``failed_ids``, and ``gap_indices``.
        """
        failed: list[str] = []
        gaps: list[int] = []

        for i, att in enumerate(self._attestations):
            if not self.verify(att):
                failed.append(att.attestation_id)

            if att.chain_index != i:
                gaps.append(i)

            expected_prev = self._attestations[i - 1].attestation_id if i > 0 else ""
            if att.previous_attestation_id != expected_prev:
                gaps.append(i)

        return {
            "valid": len(failed) == 0 and len(gaps) == 0,
            "total": len(self._attestations),
            "verified": len(self._attestations) - len(failed),
            "failed_ids": failed,
            "gap_indices": sorted(set(gaps)),
        }

    def query(
        self,
        *,
        decision: str | None = None,
        since: str | None = None,
        until: str | None = None,
        constitution_hash: str | None = None,
    ) -> list[GovernanceAttestation]:
        """Query attestations by decision, time range, or constitution.

        Args:
            decision: Filter by decision (allow/deny/escalate).
            since: ISO-8601 start timestamp (inclusive).
            until: ISO-8601 end timestamp (inclusive).
            constitution_hash: Filter by constitution hash.

        Returns:
            List of matching attestations.
        """
        results: list[GovernanceAttestation] = []
        for att in self._attestations:
            if decision and att.decision != decision:
                continue
            if since and att.timestamp < since:
                continue
            if until and att.timestamp > until:
                continue
            if constitution_hash and att.constitution_hash != constitution_hash:
                continue
            results.append(att)
        return results

    def export_chain(self, *, format: str = "json") -> str | list[dict[str, Any]]:
        """Export the attestation chain.

        Args:
            format: ``"json"`` for JSON string, ``"dict"`` for list of dicts.

        Returns:
            Serialized attestation chain with integrity metadata.
        """
        chain_data = {
            "schema_version": "1.0",
            "chain_length": len(self._attestations),
            "integrity": self.verify_chain_integrity(),
            "attestations": [a.to_dict() for a in self._attestations],
        }
        if format == "json":
            return json.dumps(chain_data, indent=2)
        return chain_data  # type: ignore[return-value]

    def summary(self) -> dict[str, Any]:
        """Summary statistics for the attestation registry."""
        by_decision: dict[str, int] = {}
        by_constitution: dict[str, int] = {}
        for att in self._attestations:
            by_decision[att.decision] = by_decision.get(att.decision, 0) + 1
            h = att.constitution_hash[:16]
            by_constitution[h] = by_constitution.get(h, 0) + 1

        return {
            "total": len(self._attestations),
            "by_decision": by_decision,
            "by_constitution": by_constitution,
            "chain_intact": self.verify_chain_integrity()["valid"] if self._attestations else True,
        }

    def __len__(self) -> int:
        return len(self._attestations)

    def __repr__(self) -> str:
        return f"AttestationRegistry({len(self._attestations)} attestations)"
