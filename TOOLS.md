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
| `make test-optional` | Require optional dependencies and test solver, adapters, Rust, and real Lean. |

When `make` is unavailable, use the direct script path:

```bash
python3 scripts/agent_ready.py --json --run-tests
python3 scripts/sync_agents.py --check
python3 scripts/validate_tools.py
```

See `tools/runbooks/` for setup, verification, governance-review, onboarding, and release runbooks.

## Optional integration qualification

Use a dedicated Python 3.12 environment so the minimal Python-fallback CI lane
continues to prove behavior without Rust and Z3. The test dependencies are pinned
in `requirements-test-optional.txt`; they do not become base runtime dependencies.

```bash
python -m pip install -e ".[dev,mcp,autonoma,anthropic,otel]" httpx
python -m pip install -r requirements-test-optional.txt "maturin==1.12.6"
maturin build --release --locked --manifest-path rust/pyo3/Cargo.toml --out /tmp/acgs-rust-wheels
python -m pip install /tmp/acgs-rust-wheels/acgs_lite_rust-*.whl
```

Install Lean **4.34.0** from the checksum-verified archive used in
`.github/workflows/release-candidate.yml`, and put its `bin/` directory on `PATH`.
Then run `make test-optional PYTHON=python`. The target requires the real optional
imports and compiler before testing; it enables the real Lean smoke test itself.
The `optional-integrations` CI job also rejects skipped tests in this focused lane.

For complete qualification, keep the pinned Lean `bin/` directory on `PATH`, then
run `LEAN_INTEGRATION=1 make verify PYTHON=python` and
`LEAN_INTEGRATION=1 make test PYTHON=python 'PYTEST=python -m pytest -o addopts='`.
The latter clears the default end-to-end exclusion and includes benchmarks.
Minimal developer and fallback environments intentionally omit optional
dependencies; validate those separately from this fully provisioned run.
