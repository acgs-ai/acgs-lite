# Project Map

A folder-by-folder guide so an agent can locate anything without guessing. For the system
design see [`ARCHITECTURE.md`](ARCHITECTURE.md); for commands see [`TOOLS.md`](TOOLS.md).

## Top level

| Path | What it is |
| --- | --- |
| [`README.md`](README.md) | Product purpose, quick start, install, run, test |
| [`AGENTS.md`](AGENTS.md) | Instructions + execution contract for AI agents |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | System design, modules, runtime flow |
| [`PROJECT_MAP.md`](PROJECT_MAP.md) | This file |
| [`TOOLS.md`](TOOLS.md) | Every script, command, CLI, and workflow |
| [`TASKS.md`](TASKS.md) | Roadmap, completed work, next tasks |
| [`DECISIONS.md`](DECISIONS.md) | Architecture/product decision log |
| [`BLOCKERS.md`](BLOCKERS.md) | Known blockers with owner, impact, next action |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Coding, testing, review, PR standards |
| [`GOAL.md`](GOAL.md) | Product goal, core invariant, success criteria |
| [`GOVERNANCE.md`](GOVERNANCE.md) / [`SECURITY.md`](SECURITY.md) | Project governance / disclosure |
| [`CHANGELOG.md`](CHANGELOG.md) / [`ROADMAP.md`](ROADMAP.md) | History / direction |
| [`CLAUDE.md`](CLAUDE.md) | Repo-specific agent rules (compounding knowledge) |
| [`Makefile`](Makefile) | One-command execution surface |
| `pyproject.toml` | Package metadata, dependencies, ruff/mypy config |
| `.env.example` / `.env.test` | Placeholder environment (no real keys needed) |

## Source — `src/acgs_lite/`

| Path | Responsibility |
| --- | --- |
| `constitution/` | Rules, lifecycle service + router, bundle stores |
| `engine/` | Validation engine, bundle binding |
| `agents/` | Capability profiles, `AgentRegistry`, `GovernedAgentSelector` |
| `compliance/` | Regulatory mapping and assessments |
| `integrations/` | Optional external adapters (lazy imports) |
| `commands/` | CLI subcommands (`acgs ...`) |
| `observability/` | Observation and reporting helpers |
| `arckit/` | Arckit bridge code and templates |
| `audit.py` | Tamper-evident audit trail |
| `maci.py` | MACI role enforcement |
| `governed.py` | Governed wrappers |
| `server.py` | FastAPI app factory `create_governance_app` |
| `cli.py` | CLI entry point |

## Agent & tool registries

| Path | Role |
| --- | --- |
| [`agent-index.json`](agent-index.json) | Canonical, runtime-loaded agent registry (source of truth) |
| [`agents/`](agents/README.md) | Generated per-agent manifests (`*.agent.yaml`) + how-to |
| [`tools/registry.yaml`](tools/registry.yaml) | Machine-readable catalog of executable surfaces |
| `tools/schemas/` | JSON Schemas for the agent + tool registries |
| `tools/runbooks/` | Step-by-step runbooks (setup, verify, governance-review, release, onboarding) |

## Scripts — `scripts/`

| Path | Purpose |
| --- | --- |
| [`agent_ready.py`](scripts/agent_ready.py) | Stdlib-only agent-readiness self-check (`--json`) |
| `sync_agents.py` | Generate/validate `agents/*.agent.yaml` from the index |
| `validate_tools.py` | Assert the tool registry references only live targets/scripts |
| `run_governance_regression.py` | Governance-regression gate |
| `build_evolution_corpus.py`, `si_benchmark.py`, `visualizer.py` | Research/utility tooling |

## Other directories

| Path | What it is |
| --- | --- |
| `tests/` | Python tests (InMemory* stubs, no real keys) |
| `docs/` | MkDocs site (`docs/api/` for API surfaces) |
| `examples/` | Runnable smoke-test examples / quickstarts |
| `rust/` | Optional Rust workspace (Python fallback always exists) |
| `planning/` | Roadmaps, TODOs, growth + execution plans |
| `integrations/` | Integration assets |
| `.github/workflows/` | CI (`ci.yml`), publish, wheels |
