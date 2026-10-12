# Govern an agent action before it runs

ACGS-Lite is a Python library for checking proposed actions against a constitution,
recording decisions, and enforcing authorization at a governed execution boundary.
Your application supplies the policy and connects the boundary to the actual tool call.

**Start small:** prove that one allowed action executes and one denied action does not.
Then add the integration and audit storage your application needs.

[Install ACGS-Lite](installation.md){ .md-button .md-button--primary }
[Try the 5-minute membrane](guides/five-minute-membrane.md){ .md-button }

!!! note "Published package and source candidate"
    The published PyPI package is **3.0.1**. This checkout also documents unreleased
    execution-grant, trusted-context, durable-audit, and recovery hardening that is
    **not in the published 3.0.1 wheel**. Match examples to the artifact you installed.
    A source checkout reporting the same version does not prove identical contents.

## Find your next step

<div class="grid cards" markdown>

- **Install and run**

    Choose a package, optional dependencies, or a source checkout.

    [Installation and distributions](installation.md) · [Quickstart](quickstart.md)

- **Connect your stack**

    Locate the adapter and understand the checks it actually performs.

    [Integration decision guide](integration-decision-guide.md) · [Adapter catalog](integrations.md)

- **Understand the execution boundary**

    Follow decisions, receipt checks, MACI roles, and audit evidence.

    [Architecture](architecture.md) · [Runtime legitimacy API](api/legitimacy.md)

- **Contribute a reproducible result**

    Ask a focused question, improve a guide, or share a tested integration.

    [Community hub](community.md) · [Write a walkthrough](community/share-a-walkthrough.md)

</div>

## What the checks establish

A `GovernanceEngine` check evaluates text against the supplied rules. A
`GovernedAgent` adds input/output validation and audit logging around its wrapped
agent. Receipt-enforced execution paths add authorization checks at the executor.
Choose the path that matches the action you must control; a model-client wrapper
alone does not establish that a later external tool call is authorized.

```text
Proposed action → policy check → decision and receipt → governed executor
```

The [5-minute membrane](guides/five-minute-membrane.md) demonstrates ALLOW,
TRANSFORM, DENY, and missing-receipt refusal. It also explains what the local demo
does not establish. `pip install` does not ship the repository's `examples/` folder.

## Build confidence in your integration

1. Name the side effect and the function that performs it.
2. Put the check on that function's real call path.
3. Demonstrate denial with a counter that proves the function did not run.
4. Check the audit record and document storage, restart, and concurrency limits.

Use [Testing Governance](testing-governance.md), the
[MACI architecture](maci.md), and the [audit API](api/audit.md) for the next layer
of detail. Local examples and passing tests are not proof of production readiness
or independent adoption.

## Compliance Mapping Examples

ACGS can map governance constraints to global regulatory frameworks to support
audits and risk assessments. The ratios below are SELF-ASSESSED mapping
coverage only; they are not certification, regulatory approval, adoption proof,
or a substitute for legal review.

| Framework | Mapping Coverage | Review Context |
|---|---|---|
| **EU AI Act** | SELF-ASSESSED mapping coverage: 5/9 | Risk classification, transparency, human oversight, and documentation mapping |
| **NIST AI RMF** | SELF-ASSESSED mapping coverage: 7/16 | Governance, mapping, measurement, and management functions |
| **ISO/IEC 42001** | SELF-ASSESSED mapping coverage: 9/18 | AI management-system controls and audit-preparation evidence |
| **SOC 2 + AI** | SELF-ASSESSED mapping coverage: 10/16 | Security, availability, processing integrity, confidentiality, and privacy mappings |
| **HIPAA + AI** | SELF-ASSESSED mapping coverage: 9/15 | Privacy, security, breach-notification, and PHI-handling safeguards; penalty exposure is tiered and inflation-adjusted, so verify current HHS/OCR amounts with legal review |
| **GDPR Art. 22** | SELF-ASSESSED mapping coverage: 10/12 | Automated decision-making, explanation, and data-protection mapping |
| **ECOA/FCRA** | SELF-ASSESSED mapping coverage: 6/12 | Fair-lending, adverse-action, and model-documentation mapping |
| **NYC LL 144** | SELF-ASSESSED mapping coverage: 6/12 | Bias-audit, candidate-notice, and public-reporting mapping |
| **OECD AI** | SELF-ASSESSED mapping coverage: 10/15 | Transparency, accountability, robustness, and human-oversight mapping |

**Run `acgs assess` to see self-assessed mapping coverage for your jurisdiction and domain.**

## Reference and project resources

- [CLI reference](cli.md) and [constitution lifecycle API](api/lifecycle.md)
- [Security reporting](security.md) and [changelog](changelog.md)
- [Frequently asked questions](community/faq.md)
- [Contribution guide](contributing.md)

!!! info "Constitutional Hash"
    `608508a9bd224290` -- documented constitutional hash for this release line. `acgs verify` currently validates license key integrity only.
