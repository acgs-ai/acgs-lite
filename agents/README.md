# Agent Manifests (generated)

Each `*.agent.yaml` file in this directory is a per-agent manifest: a human-browsable,
machine-readable description of one agent's purpose, allowed scope, required tools,
input/output contract, safety constraints, execution command, validation checks, and
expected artifacts.

## Source of truth

These files are **generated** from [`../agent-index.json`](../agent-index.json) — the
canonical registry loaded at runtime by `acgs_lite.agents.AgentRegistry` and the governed
`GovernedAgentSelector`. Do **not** edit `*.agent.yaml` by hand.

```bash
# Add or change an agent: edit agent-index.json, then regenerate this directory.
make agents-sync                       # writes agents/*.agent.yaml
python3 scripts/sync_agents.py --check  # fails if anything drifted (also run by make validate)
```

The `--check` mode is wired into `make validate` and the `scripts/agent_ready.py`
readiness summary, so a manifest that drifts from `agent-index.json` fails CI rather
than going unnoticed. This keeps the two discovery layers — the runtime registry and
the on-disk manifests — provably in lockstep.

## Why one canonical registry

The codebase deliberately avoids a second, independently-editable registry that could drift
from the runtime one (see the docstring in `src/acgs_lite/agents/capability.py`). The manifests
here are a *projection* of `agent-index.json`, not a parallel source of truth.

## Selecting an agent at runtime

```python
from acgs_lite.agents import AgentRegistry

registry = AgentRegistry.from_manifest("agent-index.json")
for profile, score in registry.candidates_for("review this branch for governance regressions"):
    print(profile.agent_id, score)   # governance-branch-review ranks first
```

For governed, fail-closed, receipted selection use `GovernedAgentSelector` — see
[`../docs/api/agents.md`](../docs/api/agents.md).
