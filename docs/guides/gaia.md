# Govern AMD GAIA tool calls with ACGS-Lite

GAIA (AMD's local agent runtime) already has confirmation UX and a
`PolicyEngine` Protocol. The in-repo `RuleBasedPolicyEngine` is a tag stub
for demos. This adapter is the production-shaped swap they documented.

It does **not** import `gaia`. Types are duck-typed so AMD can depend on
`acgs-lite` optionally, and we do not take a dependency on their runtime.

## Install

```bash
pip install acgs-lite
```

## Wire into GAIA

```python
from acgs_lite import Constitution
from acgs_lite.integrations.gaia import build_gaia_components
from gaia.governance import GaiaGovernanceAdapter, GovernedAgentMixin

engine, checkpoints, receipts, binding = build_gaia_components(Constitution.default())
adapter = GaiaGovernanceAdapter(engine, checkpoints, receipts, binding)

class MyAgent(GovernedAgentMixin, MyGaiaAgent):
    pass

agent = MyAgent(governance_adapter=adapter, governance_actor_id="alice")
```

If you are on a GAIA build that includes `GaiaGovernanceAdapter.from_acgs_lite()`,
that factory is equivalent.

## What is enforced

- Constitution decisions map to GAIA's `ALLOW` / `REVIEW` / `BLOCK`.
- GAIA `@govern(risk="blocked"|"review")` tags remain a **floor**. A
  constitution may only tighten a decision.
- `GAIA_AUTO_APPROVE_TOOLS` is ignored. Missing tool names, non-mapping
  args, and engine exceptions are `BLOCK`.
- Checkpoints bind `workflow_id`. Unknown or already-resolved checkpoints
  terminate rather than execute.

This is a local, tested integration. It is not a claim that AMD ships ACGS
as a default, or that the combination is compliance-certified.
