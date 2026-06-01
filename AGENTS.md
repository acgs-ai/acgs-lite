# ACGS-Lite Agent Guide

> **Language**: Python | **Line Length**: 100

AI governance library for constitutional rule enforcement, lifecycle management, and audit-backed validation.

## Structure

```text
packages/acgs-lite/
├── src/acgs_lite/
│   ├── constitution/        # Rules, lifecycle, bundle store, HTTP router
│   ├── engine/              # Validation engine and bundle binding
│   ├── compliance/          # Regulatory mapping and assessments
│   ├── integrations/        # External adapters
│   ├── audit.py             # Tamper-evident audit trail
│   ├── governed.py          # Governed wrappers
│   ├── maci.py              # MACI role enforcement
│   └── server.py            # FastAPI wrapper
├── docs/                    # MkDocs documentation
├── examples/                # Smoke-test examples and quickstarts
├── rust/                    # Optional Rust workspace
└── tests/                   # Python tests
```

## Commands

```bash
# Setup
pip install -e ".[dev]"

# Testing
make test
make test-quick
python -m pytest tests/ -v --import-mode=importlib

# Linting
make lint
ruff check .
ruff format --check .

# Type check
make typecheck
mypy src/acgs_lite

# Build
make build
python -m mkdocs build
```

## Where to Look

| Task | Location |
| --- | --- |
| Entry point | `src/acgs_lite/cli.py` |
| HTTP API | `src/acgs_lite/server.py`, `src/acgs_lite/constitution/lifecycle_router.py` |
| Lifecycle logic | `src/acgs_lite/constitution/lifecycle_service.py` |
| Bundle store | `src/acgs_lite/constitution/bundle_store.py`, `sqlite_bundle_store.py` |
| Engine binding | `src/acgs_lite/engine/bundle_binding.py` |
| Rules / constitution | `src/acgs_lite/constitution/` |
| Docs | `docs/`, especially `docs/api/` |
| Tests | `tests/` |
| Shared utilities | `src/acgs_lite/audit.py`, `src/acgs_lite/maci.py` |
| Agent discovery | `agent-index.json`, `src/acgs_lite/agents/`, `docs/api/agents.md` |

## Agent Discovery

When a task needs a specialist, route it to the right agent rather than improvising.
`agent-index.json` (repo root, companion to this file) is the canonical,
machine-readable index of this repo's coding agents/skills. It is authored in the
**same `AgentCapabilityProfile` schema** the library's `AgentRegistry` consumes
(`src/acgs_lite/agents/`), so the index is both human-browsable and loadable at
runtime:

```python
from acgs_lite.agents import AgentRegistry

registry = AgentRegistry.from_manifest("agent-index.json")
for profile, score in registry.candidates_for("review this branch for governance regressions"):
    print(profile.agent_id, score)   # governance-branch-review ranks first
```

Rules:

- **Every new coding agent or skill must be added to `agent-index.json`.**
  A specialist that is not in the index cannot be discovered or routed to. The
  drift guard `tests/test_agent_index.py` loads the index through the registry and
  fails if any entry is malformed — keep entries schema-valid.
- For *governed runtime* selection (fail-closed, receipted, MACI-respecting), use
  `GovernedAgentSelector` instead of the bare registry. See `docs/api/agents.md`.
- Each entry's `agent_id` should match the invocable skill/agent name so a ranked
  candidate maps directly to something callable.

## Conventions

- Python 3.10+.
- For file search / grep in this git-indexed repo, prefer the **`fff` MCP tools**
  (`ffgrep`, `fffind`, `fff-multi-grep`) over the default search tools — they share
  a warm frecency-ranked index and are far faster for repeated queries. Fall back to
  the built-in tools if the `fff` MCP server is not connected.
- Keep integrations optional through extras and lazy imports.
- Do not import optional SDKs at module import time.
- Constitutional hash `608508a9bd224290` is part of the validation flow.
- Use `_make_*` helpers in tests for fixture creation when available.

## Anti-Patterns (Forbidden)

| Pattern | Alternative |
| --- | --- |
| Importing optional SDKs at module import time | Guarded imports inside functions |
| Changing `matcher.py` hot-path behavior without tests | Add targeted benchmarks or regression tests |
| Bypassing MACI enforcement | Keep role checks in the flow |
| Relying on raw `cargo test` alone | Run the Python test surface too |
| Skipping verification before marking complete | Run `make lint && make typecheck && make test` |

## Coverage Thresholds

- System-wide: 80%
- Critical paths: 90%

## Notes

- Existing repo docs already cover the broader product story. Use this file for navigation and commands.
- Add subdirectory `AGENTS.md` files later if a sub-area grows large enough to need its own guide.
