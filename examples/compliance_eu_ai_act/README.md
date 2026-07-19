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
python packages/acgs-lite/examples/compliance_eu_ai_act/main.py
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
  spam_filter          → tier: minimal

── 2. Single-Framework Assessment ────────────────────────────
  Framework   : EU Artificial Intelligence Act (Regulation (EU) 2024/1689)
  Score       : 50%
  ACGS coverage: 87%
  Gaps (2):
    • EU-AIA Art.9(1): Establish, implement, document...
    • EU-AIA Art.10(2): Implement data governance practices...
  Item counts : {'compliant': 10, 'pending': 11, 'not_applicable': 2}

── 3. Checklist Size by Risk Tier ────────────────────────────
  unacceptable  :  2 applicable items
  limited       :  5 applicable items
  high          : 24 applicable items

── 4. Multi-Framework Assessment ─────────────────────────────
  Overall score: 72%
  eu_ai_act       ████████████████     82%
  gdpr            ████████████         60%
  nist_ai_rmf     ████████████████████ 100%
```

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

## Supported frameworks (2.5.0)

`eu_ai_act` · `gdpr` · `nist_ai_rmf` · `iso_42001` · `ccpa_cpra` · `dora` ·
`brazil_lgpd` · `india_dpdp` · `china_ai` · `singapore_maigf` · `australia_ai_ethics` ·
`canada_aida` · `uk_ai_framework` · `japan_ai_guidelines` · `korea_ai_act` ·
`uae_ai_strategy` · `oecd_ai_principles` · `g7_hiroshima`

## Next steps

- [`../audit_trail/`](../audit_trail/) — persist assessment results to an audit log
- [`../mock_stub_testing/`](../mock_stub_testing/) — test compliance pipelines without external services
