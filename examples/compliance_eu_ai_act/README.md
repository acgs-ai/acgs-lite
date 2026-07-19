# Example: EU AI Act Compliance Assessment

Assess any AI system against EU AI Act (Regulation 2024/1689) articles. Risk tier
is inferred automatically from the `domain` field — no manual classification needed.

## What it shows

| Concept | Description |
|---------|-------------|
| `infer_risk_tier()` | Domain → risk tier mapping (high / limited / minimal) |
| `EUAIActFramework.assess()` | Per-article compliance score + gap list |
| `EUAIActFramework.get_checklist()` | Raw checklist filtered by tier |
| `MultiFrameworkAssessor` | Combined EU AI Act + GDPR + NIST AI RMF score |

## Run

```bash
python examples/compliance_eu_ai_act/main.py
```

## Expected output

```
=======================================================
  EU AI Act Compliance Assessment Demo
=======================================================

── 1. Automatic Risk-Tier Inference ──────────────────────────
  medical_device       → tier: high
  hr_recruitment       → tier: high
  chatbot              → tier: limited
  spam_filter          → tier: high

── 2. Single-Framework Assessment ────────────────────────────
  Framework   : EU Artificial Intelligence Act (Regulation (EU) 2024/1689)
  Score       : 58%
  ACGS coverage: 58%
  Gaps (6):
    • EU-AIA Art.9(4): Implement risk management measures including testing procedures
    • EU-AIA Art.10(2): Apply data governance practices covering the design choices of
    • EU-AIA Art.10(3): Ensure training, validation, and testing data sets are relevan
  Item counts : {'compliant': 14, 'pending': 10}

── 3. Checklist Size by Risk Tier ────────────────────────────
  unacceptable  :  2 applicable items
  limited       :  5 applicable items
  high          : 24 applicable items

── 4. Multi-Framework Assessment ─────────────────────────────
  Overall score: 62%
  eu_ai_act       ███████████          58%
  gdpr            ████████████████     83%
  nist_ai_rmf     ████████             44%
```

> `spam_filter` is not in the high-risk or limited-risk domain lists, so `infer_risk_tier()`
> falls through to its conservative default of `"high"` rather than `"minimal"`. There is no
> domain that infers `"minimal"` automatically in the current tier map — `"minimal"` is only
> reachable via an explicit `risk_tier="minimal"` override.

## Key API

```python
from acgs_lite.compliance import EUAIActFramework, MultiFrameworkAssessor, infer_risk_tier

# Tier inference
tier = infer_risk_tier({"domain": "medical_device"})  # → "high"

# Single framework
fw = EUAIActFramework()
result = fw.assess({"domain": "hr_recruitment", "has_audit_log": True})
print(result.compliance_score)   # 0.0–1.0
print(result.gaps)               # tuple of gap strings

# Multi-framework
assessor = MultiFrameworkAssessor(frameworks=["eu_ai_act", "gdpr", "nist_ai_rmf"])
results = assessor.assess({"system_id": "my-ai", "domain": "medical_device"})
print(results.overall_score)
```

## Supported frameworks

`australia_ai_ethics` · `brazil_lgpd` · `canada_aida` · `ccpa_cpra` · `china_ai` ·
`dora` · `eu_ai_act` · `gdpr` · `hipaa_ai` · `igaming` · `india_dpdp` · `iso_42001` ·
`japan_ai_guidelines` · `nist_ai_rmf` · `nyc_ll144` · `oecd_ai` · `singapore_maigf` ·
`soc2_ai` · `uk_ai_framework` · `us_fair_lending`

## Next steps

- [`../audit_trail/`](../audit_trail/) — persist assessment results to an audit log
- [`../mock_stub_testing/`](../mock_stub_testing/) — test compliance pipelines without external services
