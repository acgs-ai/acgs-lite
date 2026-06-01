# Runbook: Verify (pre-handoff gate)

Goal: prove a change is correct and the workspace is still agent-executable before
handing off, opening a PR, or marking a task complete.

## One command

```bash
make verify
```

`make verify` runs, in order:

1. `make lint` — Ruff over `src/`, `tests/`, and `scripts/`
2. `make typecheck` — MyPy (strict)
3. `make test-quick` — suite minus slow/benchmark, fail-fast
4. `make validate` — workspace integrity (manifests ↔ index, tool registry, readiness)
5. `make agent-check` — agent readiness self-check (runs the focused registry tests)

## Make-free fallback

When `make` or the venv is unavailable:

```bash
python3 scripts/agent_ready.py --json --run-tests   # status must be "passed"
python3 scripts/sync_agents.py --check              # agents/ in sync with agent-index.json
python3 scripts/validate_tools.py                   # no dead tool references
```

## Interpreting failures

- **manifest drift** → `make agents-sync`, then re-run.
- **dead tool reference** → fix `tools/registry.yaml` or add the missing make target.
- **test/lint/type failure** → fix the code; never mark complete while red.
