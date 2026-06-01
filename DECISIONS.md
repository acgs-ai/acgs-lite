# Decisions

Concise architecture/product decisions that future agents should preserve.

## D-001: Keep `agent-index.json` canonical

`agent-index.json` is the single source of truth for repo agent discovery. Runtime loading uses `AgentRegistry.from_manifest("agent-index.json")`; `agents/*.agent.yaml` are generated projections for human browsing and must not be edited by hand.

## D-002: Keep readiness tooling repo-local

`scripts/agent_ready.py` is repo-readiness tooling, not an installed `acgs` product command. It intentionally has a make-free/source-checkout path so agents can inspect the registry even when the local venv or `make` is unavailable.

## D-003: Tool registry is a catalog, not authority

`tools/registry.yaml` indexes executable surfaces for agents. The Makefile and scripts remain the executable source of truth; `scripts/validate_tools.py` keeps the catalog schema-compatible and rejects dead command references.
