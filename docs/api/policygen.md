# Adaptive Policy Generation

**Stability: beta.**

Turn a *pre-context* — a research brief about a governance domain — into a valid
acgs-lite constitution YAML, adapting the output to the domain's risk level and
deployment environment. The pipeline:

```text
PreContextBuilder → PreContext → PolicyResearcher → AdaptivePolicyGenerator → YAML
```

Everything is deterministic and offline by default. Free-text custom requirements
are synthesized through `Rule.from_description`; pass an optional
`RuleSynthesisProvider` for LLM-backed enrichment — it is injected by the caller,
never imported at module load.

## How it adapts

| Signal | Effect |
|--------|--------|
| Domain risk level `HIGH` | HIGH-severity rules promote to CRITICAL |
| Domain risk level `UNACCEPTABLE` | every rule escalates one severity step |
| `environment = production` | blocking CRITICAL rules become `block_and_notify` |
| Requirement is production-only | gets an `env=production` activation condition |
| Risk level | permission ceiling: `permissive` → `standard` → `strict` |

The generated constitution is verified to round-trip through
`Constitution.from_yaml_str` before it is returned — a policy that cannot be
parsed back is a generation failure, not a silent artifact.

## Pre-context Reference

::: acgs_lite.policygen.context.PreContextBuilder
    options:
      members:
        - with_objectives
        - add_risk_area
        - add_framework
        - add_custom_requirement
        - infer
        - build

::: acgs_lite.policygen.context.PreContext

::: acgs_lite.policygen.context.DomainRiskLevel

## Researcher Reference

::: acgs_lite.policygen.research.PolicyResearcher
    options:
      members:
        - research

::: acgs_lite.policygen.research.PolicyRequirement

::: acgs_lite.policygen.research.ResearchReport

## Generator Reference

::: acgs_lite.policygen.generator.AdaptivePolicyGenerator
    options:
      members:
        - generate
        - generate_yaml
        - write_yaml

::: acgs_lite.policygen.generator.GeneratedPolicy

## Example

```python
from acgs_lite.policygen import AdaptivePolicyGenerator, PreContextBuilder

precontext = (
    PreContextBuilder(
        "ACME Health Assistant",
        description="An AI agent handling patient PII and clinical notes; HIPAA and GDPR scope.",
        environment="production",
    )
    .add_risk_area("pii", "secrets", "code-execution")
    .add_framework("hipaa", "gdpr")
    .add_custom_requirement("Agents must never fabricate clinical diagnoses.")
    .infer()       # detects extra risk areas/frameworks and classifies risk level
    .build()
)

policy = AdaptivePolicyGenerator().generate(precontext)
print(policy.summary)          # {'rule_count': 8, 'permission_ceiling': 'strict', ...}
policy.write("acme-health.constitution.yaml")

# The artifact is a normal constitution and loads straight back:
from acgs_lite import Constitution
constitution = Constitution.from_yaml_str(policy.yaml)
```

The generated YAML is a standard constitution — load it with
`Constitution.from_yaml` / `from_yaml_str` and enforce it with `GovernanceEngine`.
Each rule carries `provenance` (e.g. `risk-area:pii`, `framework:gdpr`) so the
generated policy is auditable back to the research signal that produced it.
