# Tasks

Current agent-executable roadmap for this repository.

## Done

- Governed agent capability registry and selector are implemented and tested.
- `agent-index.json` is the canonical runtime/discovery manifest.
- `agents/*.agent.yaml` are generated projections of `agent-index.json`.
- `tools/registry.yaml` catalogs executable surfaces and is validated for live commands.
- `scripts/agent_ready.py` provides a make-free readiness check.

## Next

- Keep new agents registered in `agent-index.json`, then run `make agents-sync`.
- Keep tool additions synchronized with `tools/registry.yaml`, then run `make validate`.
- Before handoff, run `make verify` in a prepared environment or the direct script fallbacks in `TOOLS.md`.
