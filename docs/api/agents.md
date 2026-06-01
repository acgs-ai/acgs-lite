# Agent Discovery — Registry & Governed Selection

**Stability: beta.**

Answers the question *"which agent should take this task?"* as a **governed**
decision. Two coordinated pieces:

- **`AgentRegistry`** — discovery. A process-local registry of
  `AgentCapabilityProfile` records, ranked against a task by a deterministic,
  dependency-free lexical scorer.
- **`GovernedAgentSelector`** — decision. Picks the most suitable agent only after
  a **fail-closed**, **receipted**, **MACI-respecting** constitutional decision,
  reusing the [Runtime Legitimacy Kernel](legitimacy.md) rather than a parallel
  decision path.

The selector does not run the chosen agent — it returns a decision and a
`DecisionReceipt` bound to that agent. It does not touch the governance hot-path
matcher; ranking is independent.

## Profile Reference

::: acgs_lite.agents.capability.AgentCapabilityProfile
    options:
      members:
        - from_dict
        - to_dict
        - match_score
        - handles_domain

## Registry Reference

::: acgs_lite.agents.registry.AgentRegistry
    options:
      members:
        - register
        - get
        - list_profiles
        - candidates_for
        - from_manifest
        - reset

## Selector Reference

::: acgs_lite.agents.selector.GovernedAgentSelector
    options:
      members:
        - select

::: acgs_lite.agents.selector.AgentSelection

## Decision & Fail-Closed Behavior

Selection runs as a sequence of fail-closed gates. Each denial raises a typed
error carrying the denied `DecisionReceipt` — there is no silent "best guess".

| Condition | Outcome | Receipt decision |
|-----------|---------|------------------|
| No governance engine / policy version | `SelectionDeniedError` | `HARD_DENY` |
| Task violates the constitution | `SelectionDeniedError` | `HARD_DENY` |
| No registered agent matches the task | `NoEligibleAgentError` | `DENY_OPERATION_WITH_ALTERNATIVE` |
| Required MACI role, no enforcer configured | `SelectionDeniedError` | `STRUCTURED_REVIEW_REQUIRED` |
| No candidate passes MACI checks | `NoEligibleAgentError` | `DENY_OPERATION_WITH_ALTERNATIVE` |
| Authorized | `AgentSelection` | `ALLOW` |

## Receipt Binding

An authorized selection emits a `DecisionReceipt` bound to the chosen agent:

| Receipt field | Value |
|---------------|-------|
| `goal` | the task |
| `proposed_method` | `delegate:<agent_id>` |
| `execution_boundary.allowed_method` | `delegate:<agent_id>` |
| `execution_boundary.allowed_subjects` | `(<agent_id>,)` |
| `execution_boundary.allowed_scope` | the requested `domain` (or `None`) |

When a signer is supplied, the receipt is Ed25519-signed (`crypto` extra) and is
[replay-verifiable](legitimacy.md): an independent party holding the public key can
re-derive the `ALLOW` verdict.

## MACI Constraints

When `required_role` is supplied, MACI is **never bypassed**:

- the chosen agent's assigned role must permit the role's canonical action verb
  (`propose` / `validate` / `execute` / `read`); and
- when selecting a **validator**, the requester can never be selected as its own
  validator (`check_no_self_validation`).

A `required_role` with no `MACIEnforcer` fails closed. See [MACI](maci.md).

## Example

```python
from acgs_lite import (
    AgentCapabilityProfile,
    AgentRegistry,
    Constitution,
    GovernedAgentSelector,
)
from acgs_lite.engine.core import GovernanceEngine
from acgs_lite.maci import MACIEnforcer, MACIRole

registry = AgentRegistry(profiles=[])
registry.register(
    AgentCapabilityProfile(
        agent_id="governance-branch-review",
        name="Governance Branch Reviewer",
        description="adaptive governance-aware review of a branch",
        capabilities=("review", "governance", "audit"),
        domains=("governance",),
        skills=("branch-review",),
    )
)

engine = GovernanceEngine(Constitution.from_yaml("rules.yaml"), strict=True)
maci = MACIEnforcer()
maci.assign_role("governance-branch-review", MACIRole.VALIDATOR)

selector = GovernedAgentSelector(registry=registry, engine=engine, maci_enforcer=maci)
selection = selector.select(
    "review this branch for governance regressions",
    requester_id="orchestrator",
    required_role=MACIRole.VALIDATOR,
    domain="governance",
)
print(selection.selected_agent_id, selection.decision)  # governance-branch-review ALLOW
assert selection.receipt.verify_hash()
```

## Repo Agent Index

This repository's own coding agents/skills are catalogued in `agent-index.json`
(repo root), authored in the exact `AgentCapabilityProfile` schema above and
loadable via `AgentRegistry.from_manifest("agent-index.json")`. See the
**Agent Discovery** section of `AGENTS.md`.
