# Runbook: Agent Onboarding

Goal: a fresh coding/review/QA/workflow agent enters the repo and completes a task with
zero human clarification. This is the acceptance flow from the project goal.

## The flow

```text
1. Understand   →  Read README.md and AGENTS.md (start here).
2. Install      →  make setup   (alias of dev-setup; no real API keys needed)
3. Discover     →  tools/registry.yaml + TOOLS.md (every executable surface)
4. Register     →  pick an agent from agent-index.json / agents/*.agent.yaml
5. Plan         →  /ce-plan (or the researcher agent for context first)
6. Execute      →  do the work within the chosen agent's declared scope
7. Validate     →  make verify   (lint, typecheck, tests, validate, agent-check)
8. Report       →  emit the task report (template in AGENTS.md)
```

## Selecting the right agent

```python
from acgs_lite.agents import AgentRegistry
registry = AgentRegistry.from_manifest("agent-index.json")
for profile, score in registry.candidates_for("<your task description>"):
    print(profile.agent_id, score)   # highest score = best-matched agent
```

Then read `agents/<agent_id>.agent.yaml` for that agent's scope, required tools,
execution command, validation checks, and expected artifacts before acting.

## Self-check (machine-readable)

```bash
python3 scripts/agent_ready.py --json --run-tests
# {"status": "passed", "checks": [...]}  → the workspace understood and executed cleanly
```

## Hard rules

- Stay inside the selected agent's `scope` and honor its `safety_constraints`.
- Never skip the verification ladder before marking a task complete (`make verify`).
- Never weaken governance defaults or bypass MACI (see `AGENTS.md` anti-patterns).
- If blocked, record it in `BLOCKERS.md` with owner, impact, and next action.
