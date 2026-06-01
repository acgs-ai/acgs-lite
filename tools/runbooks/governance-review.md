# Runbook: Governance Review

Goal: catch governance regressions and optional-integration risks in a branch before a PR.

Agent: `governance-branch-review` (see `agents/governance-branch-review.agent.yaml`).

## Steps

```bash
# 1. Run the governance-regression safety gate (must stay green).
make test-governance

# 2. Adaptive, governance-aware review of the branch vs a base ref.
/governance-branch-review main          # skill invocation in Claude Code
```

## What it checks

- Constitutional invariants (hash `608508a9bd224290`) are not silently changed.
- Fail-closed defaults (MACI enforcement, receipt binding, audit verifiability) are not
  weakened — see `GOAL.md` "Core Invariant".
- Optional integrations stay lazy (no SDK imports at module import time).

## After fixes

Verify the fixes actually hold, not just that tests pass:

```bash
/verify-governance-fixes                # writes + executes real bypass attempts
```

## Hard rules (never violate)

- Never weaken a fail-closed default to make a test pass.
- Never bypass MACI enforcement in wrappers or integrations.
- Never change `matcher.py` hot-path behavior without targeted tests.
- A reopened bypass vector is a hard failure (`make test-governance`).
