# ACGS - Constitutional AI Governance
# Copyright (C) 2024-2026 ACGS Contributors
# Licensed under Apache-2.0. See LICENSE for details.

"""Automated, adaptive policy (constitution) generation.

Run::

    python examples/adaptive_policy_generation.py

Builds a research pre-context for a governance domain, automatically researches
the applicable requirements, and adaptively generates a constitution YAML whose
severity, enforcement, and permission ceiling scale with the domain's risk level
and environment. The generated YAML is a standard acgs-lite constitution and is
loaded straight back to prove the round-trip.
"""

from __future__ import annotations

from acgs_lite import Constitution
from acgs_lite.policygen import AdaptivePolicyGenerator, PreContextBuilder


def main() -> None:
    precontext = (
        PreContextBuilder(
            "ACME Health Assistant",
            description=(
                "An AI agent handling patient PII and clinical notes, deploying to "
                "production, in scope for HIPAA and GDPR."
            ),
            environment="production",
        )
        .with_objectives("Protect patient data", "Keep a human in the loop")
        .add_risk_area("pii", "secrets", "code-execution")
        .add_framework("hipaa", "gdpr")
        .add_custom_requirement("Agents must never fabricate clinical diagnoses.")
        .infer()
        .build()
    )

    print(f"Domain        : {precontext.domain}")
    print(f"Risk level    : {precontext.risk_level.value}")
    print(f"Risk areas    : {', '.join(precontext.risk_areas)}")
    print(f"Frameworks    : {', '.join(precontext.frameworks)}")

    policy = AdaptivePolicyGenerator().generate(precontext)

    print("\n=== Summary ===")
    for key, value in policy.summary.items():
        print(f"  {key}: {value}")

    print("\n=== Rule provenance ===")
    for line in policy.rationale:
        print(f"  {line}")

    # The generated artifact is a normal constitution: load it back.
    reloaded = Constitution.from_yaml_str(policy.yaml)
    assert reloaded.hash == policy.constitution.hash
    print(f"\nRound-trip OK — constitutional hash {reloaded.hash}")
    print(f"Generated {len(reloaded.rules)} rules.")


if __name__ == "__main__":
    main()
