# ACGS-Lite

For repo-wide rules, see the parent repo guide at `../../CLAUDE.md` and `.claude/rules/`.
Claude Code auto-loads parent `CLAUDE.md` files; this file should stay package-specific.
AGENTS.md serves Codex/OMX.

## Project Overview

| Key | Value |
| --- | --- |
| **Project** | ACGS-Lite |
| **Language** | Python |
| **Framework** | FastAPI, MkDocs |
| **Package Mgr** | pip / Make |
| **Line Length** | 100 |
| **Target** | Python 3.10+ |

AI governance library for constitutional rule enforcement, lifecycle management, and audit-backed validation.

## Pre-Implementation Checks

- Before creating new config/diagram/schema files (`.dsl`, `workspace.*`, `schema.*`, `AGENTS.md`) **search the repo first** with `find . -name <filename>` to avoid duplicates
- Before calling agent methods or SDK functions, read the actual source to verify the API (method name, signature, return type)
- Before marking a task complete, verify all gates actually ran — never substitute static or remembered outputs for a fresh run

---

## Repo Boundary

- `packages/acgs-lite` is a nested git repo inside the parent ACGS monorepo.
- Before staging, committing, or pushing, check git state both here and in the parent repo.

---

## CI/Deployment Fix Protocol

- When fixing a CI failure, check **all** job matrices and workflow files for the same pattern — not just the job that surfaced the error
- For gh-pages/docs-deploy failures, verify both remote URL correctness **and** push semantics (fast-forward vs. force push)
- Before any commit/push operation, confirm `git rev-parse --git-dir` succeeds (repo is initialized)

---

## Skill Invocation

- If a skill or slash-command is invoked without a required task description or scope, **stop and ask** — do not proceed with a guess
- After any failed skill invocation, run `/oh-my-claudecode:cancel` to clean up session state before retrying

---

## Quick Commands

```bash
# Verify (required before marking complete)
bash .claude/commands/test-and-verify.sh
# or step by step:
make lint && make typecheck && make test && make build

# Single test
python -m pytest tests/test_lifecycle_router.py -v --import-mode=importlib
python -m pytest tests/test_lifecycle_router.py -k test_create_draft_200 -v --import-mode=importlib

# Format
ruff format .
```

**Test notes:** Tests use `InMemory*` stubs. Set `OPENAI_API_KEY=test-key-for-unit-tests` and `ANTHROPIC_API_KEY=test-key-for-unit-tests` when needed.

---

## Repo Boundary

`packages/acgs-lite` is a nested git repo inside the parent ACGS monorepo.
Before staging, committing, or pushing, check git state both here and in the parent repo.

---

## Architecture & Conventions

- Keep integrations optional through extras and lazy imports.
- Keep Python fallbacks when optional Rust or third-party acceleration exists.
- CLI command wiring lives in `src/acgs_lite/commands/`; `acgs arckit` is routed through that surface.
- Arckit bridge code and templates live in `src/acgs_lite/arckit/`.
- Observation and reporting helpers live in `src/acgs_lite/observability/`.
- Constitution lifecycle code lives in `src/acgs_lite/constitution/`.
- HTTP surfaces live in `src/acgs_lite/server.py` and `src/acgs_lite/constitution/lifecycle_router.py`.
- Docs for API surfaces live under `docs/api/`.
- Use `_make_*` helpers in tests for fixture creation when available.

---

## Environment Variables

| Variable | Default | Description |
| --- | --- | --- |
| `OPENAI_API_KEY` | `test-key-for-unit-tests` | Placeholder to silence import-time validation |
| `ANTHROPIC_API_KEY` | `test-key-for-unit-tests` | Placeholder to silence import-time validation |
| `ACGS_LIFECYCLE_ENABLED` | unset | Enables the lifecycle router in `server.py` |
| `ACGS_LIFECYCLE_API_KEY` | unset | API key required by lifecycle mutation endpoints |

---

## What NOT to Do

- Never import optional platform SDKs at module import time.
- Never bypass MACI enforcement in wrappers or integrations.
- Never change `matcher.py` hot-path behavior without targeted tests.
- Never rely on raw `cargo test` as the only verification for Python-facing Rust changes.
- Never skip the verification sequence before marking a task complete.

---

## Git Workflow

- Branch naming: `feature/`, `fix/`, `refactor/`, `docs/`, `test/`, `chore/`.
- Commits must follow the repo Lore commit protocol from the parent `AGENTS.md`.
- Keep commits atomic and bisectable.
- Never force push to shared branches.

---


## Compounding Knowledge

Update this section whenever a mistake is made so it never happens again.

| ID | Lesson | Detail |
| --- | --- | --- |
| CK-001 | Optional integrations stay lazy | Import optional SDKs only inside guarded code paths. |
| CK-002 | Validation failures raise | `GovernanceEngine.validate()` raises `ConstitutionalViolationError` instead of returning `valid=False`. |
| CK-003 | Bundle hashes are derived | `ConstitutionBundle.constitutional_hash` is populated from `constitution.hash`. |

---

## Skill Routing

Package-local workflow routing should stay minimal here.
Prefer the parent repo `CLAUDE.md` and `.claude/rules/` as the authoritative routing source so package guidance does not drift from installed skills.

## GBrain Configuration (configured by /setup-gbrain)
- Engine: pglite
- Config file: ~/.gbrain/config.json (mode 0600)
- Brain database: ~/.gbrain/brain.pglite (123 pages imported on init)
- Setup date: 2026-04-30
- MCP registered: yes (user scope, `/home/martin/.bun/bin/gbrain serve`)
- Memory sync: off (gstack-brain-sync declined — local-only)
- Current repo policy: read-write (origin: github.com/acgs-ai/acgs-lite)
