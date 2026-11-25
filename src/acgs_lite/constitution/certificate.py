"""exp188: ComplianceCertificate — signed compliance attestation.

Generates tamper-evident certificates proving governance compliance at a
point in time. Each certificate includes a validation summary, rule coverage,
HMAC signature, and chain link to the previous certificate for continuity.
"""

from __future__ import annotations

import hashlib
import hmac
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from acgs_lite._compat import constant_time_compare


class CertificateStatus(Enum):
    VALID = "valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"


@dataclass(frozen=True)
class ComplianceCertificate:
    certificate_id: str
    issued_at: datetime
    expires_at: datetime
    issuer: str
    subject: str
    framework: str
    compliance_score: float
    rules_evaluated: int
    rules_passed: int
    rules_failed: int
    findings: tuple[str, ...]
    constitution_hash: str
    previous_certificate_id: str | None
    signature: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at

    @property
    def pass_rate(self) -> float:
        if self.rules_evaluated == 0:
            return 1.0
        return self.rules_passed / self.rules_evaluated

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "issuer": self.issuer,
            "subject": self.subject,
            "framework": self.framework,
            "compliance_score": round(self.compliance_score, 4),
            "rules_evaluated": self.rules_evaluated,
            "rules_passed": self.rules_passed,
            "rules_failed": self.rules_failed,
            "findings": list(self.findings),
            "constitution_hash": self.constitution_hash,
            "previous_certificate_id": self.previous_certificate_id,
            "signature": self.signature,
            "pass_rate": round(self.pass_rate, 4),
            "metadata": self.metadata,
        }


def _compute_certificate_digest(
    certificate_id: str,
    issued_at: str,
    subject: str,
    framework: str,
    compliance_score: float,
    rules_evaluated: int,
    rules_passed: int,
    constitution_hash: str,
    previous_id: str | None,
) -> str:
    content = (
        f"{certificate_id}|{issued_at}|{subject}|{framework}|"
        f"{compliance_score:.4f}|{rules_evaluated}|{rules_passed}|"
        f"{constitution_hash}|{previous_id or 'none'}"
    )
    return hashlib.sha256(content.encode()).hexdigest()


class CertificateAuthority:
    """Issues and manages compliance certificates with HMAC chain integrity.

    Each certificate is signed with a shared secret and linked to the previous
    certificate, creating a tamper-evident chain of compliance attestations.
    """

    __slots__ = ("_issuer", "_secret", "_certificates", "_chain_head", "_revoked")

    def __init__(self, issuer: str, secret: str = "") -> None:
        if not secret:
            raise ValueError(
                "CertificateAuthority requires an explicit 'secret' parameter. "
                "A hardcoded default is not safe for certificate signing."
            )
        self._issuer = issuer
        self._secret = secret.encode()
        self._certificates: dict[str, ComplianceCertificate] = {}
        self._chain_head: str | None = None
        self._revoked: set[str] = set()

    def issue_certificate(
        self,
        subject: str,
        framework: str,
        compliance_score: float,
        rules_evaluated: int,
        rules_passed: int,
        findings: list[str] | None = None,
        constitution_hash: str = "",
        validity_days: int = 90,
        metadata: dict[str, Any] | None = None,
    ) -> ComplianceCertificate:
        cert_id = uuid.uuid4().hex[:16]
        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=validity_days)

        digest = _compute_certificate_digest(
            cert_id,
            now.isoformat(),
            subject,
            framework,
            compliance_score,
            rules_evaluated,
            rules_passed,
            constitution_hash,
            self._chain_head,
        )
        signature = hmac.new(self._secret, digest.encode(), hashlib.sha256).hexdigest()[:32]

        cert = ComplianceCertificate(
            certificate_id=cert_id,
            issued_at=now,
            expires_at=expires,
            issuer=self._issuer,
            subject=subject,
            framework=framework,
            compliance_score=compliance_score,
            rules_evaluated=rules_evaluated,
            rules_passed=rules_passed,
            rules_failed=rules_evaluated - rules_passed,
            findings=tuple(findings or []),
            constitution_hash=constitution_hash,
            previous_certificate_id=self._chain_head,
            signature=signature,
            metadata=metadata or {},
        )

        self._certificates[cert_id] = cert
        self._chain_head = cert_id
        return cert

    def verify_signature(self, cert: ComplianceCertificate) -> bool:
        digest = _compute_certificate_digest(
            cert.certificate_id,
            cert.issued_at.isoformat(),
            cert.subject,
            cert.framework,
            cert.compliance_score,
            cert.rules_evaluated,
            cert.rules_passed,
            cert.constitution_hash,
            cert.previous_certificate_id,
        )
        expected = hmac.new(self._secret, digest.encode(), hashlib.sha256).hexdigest()[:32]
        return constant_time_compare(cert.signature, expected)

    def get_status(self, certificate_id: str) -> CertificateStatus:
        if certificate_id in self._revoked:
            return CertificateStatus.REVOKED
        cert = self._certificates.get(certificate_id)
        if cert is None:
            msg = f"Unknown certificate: {certificate_id}"
            raise ValueError(msg)
        if cert.is_expired:
            return CertificateStatus.EXPIRED
        newer = [
            c
            for c in self._certificates.values()
            if c.subject == cert.subject
            and c.framework == cert.framework
            and c.issued_at > cert.issued_at
            and c.certificate_id not in self._revoked
        ]
        if newer:
            return CertificateStatus.SUPERSEDED
        return CertificateStatus.VALID

    def revoke(self, certificate_id: str, reason: str = "") -> None:
        if certificate_id not in self._certificates:
            msg = f"Unknown certificate: {certificate_id}"
            raise ValueError(msg)
        self._revoked.add(certificate_id)

    def get_certificate(self, certificate_id: str) -> ComplianceCertificate | None:
        return self._certificates.get(certificate_id)

    def certificates_for_subject(
        self, subject: str, framework: str | None = None
    ) -> list[ComplianceCertificate]:
        certs = [c for c in self._certificates.values() if c.subject == subject]
        if framework:
            certs = [c for c in certs if c.framework == framework]
        return sorted(certs, key=lambda c: c.issued_at, reverse=True)

    def verify_chain(self, certificate_id: str | None = None) -> bool:
        current_id = certificate_id or self._chain_head
        while current_id is not None:
            cert = self._certificates.get(current_id)
            if cert is None:
                return False
            if not self.verify_signature(cert):
                return False
            current_id = cert.previous_certificate_id
        return True

    def chain_length(self) -> int:
        length = 0
        current_id = self._chain_head
        while current_id is not None:
            cert = self._certificates.get(current_id)
            if cert is None:
                break
            length += 1
            current_id = cert.previous_certificate_id
        return length

    def stats(self) -> dict[str, Any]:
        valid = sum(
            1 for cid in self._certificates if self.get_status(cid) == CertificateStatus.VALID
        )
        return {
            "total_issued": len(self._certificates),
            "valid": valid,
            "revoked": len(self._revoked),
            "chain_length": self.chain_length(),
            "chain_intact": self.verify_chain(),
        }

    def __len__(self) -> int:
        return len(self._certificates)
