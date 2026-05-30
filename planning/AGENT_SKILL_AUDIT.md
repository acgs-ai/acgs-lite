# Agent & Skill Audit

Audit date: 2026-04-24  
Scope: `.claude/` directory — settings, hooks, commands, rules

---

## Skills

No `.claude/skills/` directory exists in this repo. Skill routing is delegated to the
parent repo's `.claude/rules/skill-routing.md` and the user's global OMC plugin.

**Decision:** No skills to audit or remove.

---

## Subagents

No `.claude/agents/` directory. Agent dispatch happens via the parent monorepo.

---

## Slash Commands

### `.claude/commands/test-and-verify.sh`

| Field | Value |
|-------|-------|
| Trigger | `bash .claude/commands/test-and-verify.sh [--quick]` |
| Purpose | Run lint → typecheck → tests → build in sequence |
| Input | Optional `--quick` flag (skips tests and build) |
| Output | Exit 0 on all pass, exit 1 on any failure with summary |
| Status | **Kept** |

No other slash commands.

---

## Hooks

### `PreToolUse` — `.claude/hooks/pre_tool_use.py`

| Field | Value |
|-------|-------|
| Matcher | `Bash` |
| Purpose | Block dangerous shell patterns before execution |
| Patterns blocked | `rm -rf`, `git push --force`, `git push -f`, `git reset --hard`, `git clean -fd`, `mkfs.`, fork-bomb |
| Timeout | 5000ms |
| Fail behavior | Silent pass (exception caught) |
| Status | **Kept** — minimal, correct |

### `PostToolUse` — `.claude/hooks/post_tool_use.py`

| Field | Value |
|-------|-------|
| Matcher | `Bash` |
| Purpose | Truncate output > 120 lines (head 60 + tail 60) |
| Timeout | 5000ms |
| Fail behavior | Silent pass |
| Status | **Kept** — reduces context bloat on large test output |

### `Stop` — `.claude/hooks/stop.py`

| Field | Value |
|-------|-------|
| Matcher | (all) |
| Purpose | Emit JSON summary on session end |
| Output | `{"session_ended": "<ISO>", "stop_reason": "<reason>"}` to stdout |
| Timeout | 5000ms |
| Fail behavior | Silent pass |
| Status | **Kept** — low cost, useful for OMC session tracking |

---

## Rules (`.claude/rules/`)

All four rules files are auto-loaded every session. Each is short (9–12 lines) and
repo-specific. No overlap with each other.

| File | Lines | Content | Status |
|------|-------|---------|--------|
| `coding-style.md` | 11 | Python 3.10+, line length, ruff, import order, naming | **Kept** |
| `git-workflow.md` | 9 | Branch naming, conventional commits, never force-push | **Kept** |
| `security.md` | 12 | No secrets, parameterized queries, no eval/exec | **Kept** |
| `testing.md` | 11 | Verification gates, pytest invocation, mock strategy | **Kept** |

**Note:** `CLAUDE.md` previously duplicated these rules (Coding Standards, Testing Standards,
Security, Git Workflow, What NOT to Do sections — ~80 lines). Those sections were removed in
this audit; the rules files are the canonical source.

---

## Settings (`.claude/settings.json`)

| Change | Before | After | Reason |
|--------|--------|-------|--------|
| Consolidated `allow` patterns | 4 separate `make test*` entries | 1 `Bash(make test*)` | Glob already covers all variants |

Remaining `allow` list covers all safe development operations. `deny` list unchanged
(destructive git ops remain blocked).

---

## `CLAUDE.md` Summary

| Metric | Before | After |
|--------|--------|-------|
| Lines | 216 | 87 |
| Sections removed | Coding Standards, Testing Standards, Security, Git Workflow, What NOT to Do, verbose Autonomous Verification | — |
| Sections kept | Project Overview, Quick Commands, Repo Boundary, Architecture, Environment Variables, Compounding Knowledge, Skill Routing | — |
| Reason | Removed sections duplicated `.claude/rules/` content loaded every session | — |
