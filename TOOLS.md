# Tools

ACGS-Lite keeps executable surfaces in two places:

- `Makefile` and `scripts/*.py` are the executable source of truth.
- `tools/registry.yaml` is the machine-readable discovery index for agents.

Validate the index any time a command is added, renamed, or removed:

```bash
python3 scripts/validate_tools.py
python3 scripts/agent_ready.py --json --run-tests
```

## Primary commands

| Command | Purpose |
| --- | --- |
| `make setup` | Alias for `make dev-setup`; creates `.venv` and installs dev extras. |
| `make agent-check` | Agent readiness gate; wraps `python3 scripts/agent_ready.py --run-tests`. |
| `make agents-sync` | Regenerate `agents/*.agent.yaml` from `agent-index.json`. |
| `make validate` | Check generated agent manifests, tool registry liveness, and readiness summary. |
| `make verify` | Pre-handoff gate: lint, typecheck, quick tests, validate, agent-check. |
| `make smoke` | Run bundled examples plus a package import check. |
| `make build` | Build wheel and source distribution into `dist/`. |

When `make` is unavailable, use the direct script path:

```bash
python3 scripts/agent_ready.py --json --run-tests
python3 scripts/sync_agents.py --check
python3 scripts/validate_tools.py
```

See `tools/runbooks/` for setup, verification, governance-review, onboarding, and release runbooks.
