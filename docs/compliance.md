# Compliance

ACGS maps controls across 20 regulatory frameworks globally. Coverage ratios
are SELF-ASSESSED mapping coverage only; they are not certification, regulatory
approval, adoption proof, or a substitute for legal review.

## Coverage Summary

| Framework | Mapping Coverage | What It Covers |
|---|---|---|
| **EU AI Act** | SELF-ASSESSED mapping coverage: 5/9 | Risk classification, transparency, human oversight, documentation, post-market monitoring |
| **NIST AI RMF** | SELF-ASSESSED mapping coverage: 7/16 | Governance, risk mapping, measurement, management functions |
| **ISO/IEC 42001** | SELF-ASSESSED mapping coverage: 9/18 | AI management system, risk assessment, performance evaluation |
| **SOC 2 + AI** | SELF-ASSESSED mapping coverage: 10/16 | Security, availability, processing integrity, confidentiality, privacy |
| **HIPAA + AI** | SELF-ASSESSED mapping coverage: 9/15 | Administrative safeguards, technical safeguards, audit controls |
| **GDPR Art. 22** | SELF-ASSESSED mapping coverage: 10/12 | Automated decision-making, right to explanation, data protection |
| **ECOA/FCRA** | SELF-ASSESSED mapping coverage: 6/12 | Fair lending, adverse action notices, model documentation |
| **NYC LL 144** | SELF-ASSESSED mapping coverage: 6/12 | Bias audits, candidate notification, public reporting |
| **OECD AI** | SELF-ASSESSED mapping coverage: 10/15 | Transparency, accountability, robustness, human oversight |

## Running an Assessment

```python
from acgs_lite.compliance import MultiFrameworkAssessor

assessor = MultiFrameworkAssessor()
report = assessor.assess({"jurisdiction": "EU", "domain": "healthcare"})

print(report.overall_score)        # 0.62
print(report.cross_framework_gaps) # Items needing manual evidence
```

## CLI Assessment

```bash
acgs assess --jurisdiction european_union --domain healthcare
acgs report --markdown
acgs report --pdf
```

## EU AI Act One-Shot

```bash
acgs eu-ai-act --domain healthcare
```

!!! warning "Mapping coverage is not full compliance"
    The remaining items require manual evidence, organizational policies, or
    domain-specific documentation. Use `report.cross_framework_gaps` to identify
    what still needs human input. These ratios are self-assessed mapping
    coverage, not certification, adoption proof, or regulatory approval.

## Targeted Framework Assessment

```python
report = assessor.assess({
    "jurisdiction": "US",
    "domain": "finance",
    "frameworks": ["SOC2", "ECOA_FCRA"],
})

for gap in report.cross_framework_gaps:
    print(f"{gap.framework}: {gap.item} -- {gap.remediation}")
```

## Verifiable Receipt Bundles & SCITT `COSE_Sign1`

For auditors and offline evidence interchange, `acgs_lite.compliance` provides
deterministic SHA-256-manifested bundles and RFC 9052 SCITT `COSE_Sign1`
EdDSA (`alg = -8`) envelopes from signed 4.x receipts:

```bash
# Zero-config bundle generation, offline verification, and tamper-detection demo
acgs bundle demo --profile ca-admt-2027 --json
```

```python
from acgs_lite.compliance import (
    export_receipt_bundle,
    export_scitt_cose_sign1,
    verify_receipt_bundle,
    verify_scitt_cose_sign1,
)

# Bundle profiles: "ca-admt-2027" or "eu-ai-act-art12-26"
# export_scitt_cose_sign1(signed_receipt, signer, issuer="did:web:acgs.example")
# verify_scitt_cose_sign1(envelope.cose_bytes, {signer.key_id: signer.public_key_hex()})
```

!!! warning "Evidence format, not legal certification"
    Receipt bundles and SCITT `COSE_Sign1` envelopes provide cryptographically
    verifiable runtime decision and outcome evidence; they are not legal advice
    or third-party regulatory certification.
