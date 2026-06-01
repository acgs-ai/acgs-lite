# Runbook: Setup

Goal: a working, test-passing ACGS-Lite environment from a fresh clone.

## Steps

```bash
make setup            # creates .venv + installs all dev extras (alias of dev-setup)
source .venv/bin/activate
make agent-check      # confirm the workspace is agent-executable
```

No real API keys are required — tests use `InMemory*` stubs. Placeholder keys silence
import-time validation:

```bash
export OPENAI_API_KEY=test-key-for-unit-tests
export ANTHROPIC_API_KEY=test-key-for-unit-tests
```

`.env.example` lists the full (placeholder) set. `make setup` is an alias for
`dev-setup`, which copies `.env.example` to `.env.test` only when `.env.test` does not
already exist.

## Verify

```bash
make test-quick       # fast suite
python3 scripts/agent_ready.py --json   # machine-readable readiness, status: passed
```

## Failure modes

| Symptom | Cause | Fix |
| --- | --- | --- |
| `python3.11 not found` | CI-pinned interpreter absent | `make setup` falls back to 3.12/3.10; any 3.10+ works |
| crewai/autogen install fails | those extras require Python ≤3.13 | excluded by `make setup`; use `uv sync --all-extras` on ≤3.13 for the full env |
| import-time `*_API_KEY` error | missing placeholder key | export the placeholder keys above |
