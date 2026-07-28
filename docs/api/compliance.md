# Compliance Frameworks

> **Stability: not classified in `acgs_lite.API_STABILITY`.** Framework
> classes live in `acgs_lite.compliance.<vendor>` submodules and are not
> re-exported from the top-level `acgs_lite` package. Treat the
> `ComplianceFramework` protocol and its `assess(system_description: dict)`
> contract as the load-bearing surface; individual framework class names may
> still be renamed before they are added to `__all__`.

ACGS covers 20 regulatory frameworks through a unified `ComplianceFramework`
protocol. Each framework maps rules to ACGS governance features and produces
structured assessment reports. Frameworks are dispatched via the
`MultiFrameworkAssessor` registry and addressed by string ID.

## Supported Frameworks

| Framework | Class | Registry ID | Domain |
|-----------|-------|-------------|--------|
| EU AI Act | `EUAIActFramework` | `eu_ai_act` | High-risk AI |
| NIST AI RMF | `NISTAIRMFFramework` | `nist_ai_rmf` | Risk management |
| ISO 42001 | `ISO42001Framework` | `iso_42001` | AI management systems |
| SOC 2 (AI) | `SOC2AIFramework` | `soc2_ai` | Security/availability |
| HIPAA AI | `HIPAAAIFramework` | `hipaa_ai` | Healthcare |
| GDPR | `GDPRFramework` | `gdpr` | Data protection |
| US Fair Lending (ECOA/FCRA) | `USFairLendingFramework` | `us_fair_lending` | Fair lending |
| NYC LL 144 | `NYCLL144Framework` | `nyc_ll144` | Automated employment |
| OECD AI | `OECDAIFramework` | `oecd_ai` | AI principles |
| DORA | `DORAFramework` | `dora` | Digital operational resilience |
| UK AI | `UKAIFramework` | `uk_ai_framework` | UK AI governance |
| Canada AIDA | `CanadaAIDAFramework` | `canada_aida` | Canadian AI |
| Brazil LGPD | `BrazilLGPDFramework` | `brazil_lgpd` | Brazilian data protection |
| India DPDP | `IndiaDPDPFramework` | `india_dpdp` | Indian data protection |
| China AI | `ChinaAIFramework` | `china_ai` | Chinese AI regulations |
| Australia AI Ethics | `AustraliaAIEthicsFramework` | `australia_ai_ethics` | AU AI principles |
| Singapore MAIGF | `SingaporeMAIGFFramework` | `singapore_maigf` | SG AI governance |
| CCPA/CPRA | `CCPACPRAFramework` | `ccpa_cpra` | California privacy |
| iGaming | `IGamingFramework` | `igaming` | Online gaming/gambling |

## Multi-Framework Assessor

::: acgs_lite.compliance.multi_framework.MultiFrameworkAssessor
    options:
      members:
        - assess
        - applicable_frameworks
        - available_frameworks

`MultiFrameworkAssessor.assess` takes a `system_description` dict (not an
`EvidenceCollector`) and returns a `MultiFrameworkReport`. When constructed
without explicit `frameworks=...`, the assessor auto-selects frameworks from
the `jurisdiction` and `domain` keys in the system description.

## ComplianceFramework Protocol

::: acgs_lite.compliance.base.ComplianceFramework

Each framework's `assess(system_description: dict) -> FrameworkAssessment`
runs against a serializable system description, not against a collector.

## EvidenceCollector Protocol

::: acgs_lite.compliance.evidence.EvidenceCollector

`EvidenceCollector` is a `runtime_checkable` `Protocol` with a single
`collect(system_description) -> list[EvidenceItem]` method. Use it to
plug in custom evidence sources; ACGS does not provide a `from_agent`
factory.

## Examples

### Assess against a single framework

```python
from acgs_lite.compliance.eu_ai_act import EUAIActFramework

framework = EUAIActFramework()
assessment = framework.assess({
    "system_id": "my-system",
    "domain": "healthcare",
    "jurisdiction": "european_union",
})

print(f"Score: {assessment.score:.0%}")
print(f"Gaps: {len(assessment.gaps)}")
```

### Multi-framework assessment

```python
from acgs_lite.compliance.multi_framework import MultiFrameworkAssessor

assessor = MultiFrameworkAssessor(frameworks=["eu_ai_act", "nist_ai_rmf", "iso_42001"])
report = assessor.assess({"system_id": "my-system", "domain": "healthcare"})

print(report.overall_score)
print(report.frameworks_assessed)
```

### Auto-select frameworks by jurisdiction

```python
assessor = MultiFrameworkAssessor()  # registry-driven selection
report = assessor.assess({
    "system_id": "my-system",
    "jurisdiction": "european_union",
    "domain": "healthcare",
})
```

### CLI shortcut

```bash
acgs eu-ai-act --system-id "my-system" --domain healthcare
```

The same command is also available as `acgs-lite eu-ai-act` (both console
scripts dispatch to the same entry point).
