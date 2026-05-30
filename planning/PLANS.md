<!-- /autoplan restore point: /home/martin/.gstack/projects/dislovelhl-acgs-lite/main-autoplan-restore-20260423-195049.md -->
# ACGS-Lite Plans

## Purpose / Big Picture

Stabilize `packages/acgs-lite/` as a publishable governance library with:
- explicit MACI semantics
- predictable wrapper validation for structured inputs/outputs
- consistent audit behavior in API surfaces
- packaging/docs that match the shipped wheel

## Active Remediation Plan

### Phase 1 — Close correctness gaps in public wrappers
Status: completed on 2026-04-02

Goals:
- validate keyword arguments in `GovernedCallable`
- validate structured outputs in `GovernedAgent` / `GovernedCallable`
- ensure `/stats` reflects the real engine audit log
- ship both `acgs` and `acgs-lite` console scripts

Verification:
- targeted regression tests added in `tests/test_core.py`, `tests/test_server.py`, `tests/test_cli_governance.py`
- full package pytest run passes
- wheel build exports both console script aliases

### Phase 2 — Make MACI enforcement explicit without breaking compatibility
Status: completed on 2026-04-02

Decision:
- `maci_role` remains metadata by default
- explicit enforcement now requires opt-in via `enforce_maci=True`
- enforced runs must also provide `governance_action=...`

Rationale:
- existing callers and tests treat `maci_role` as descriptive metadata
- automatic enforcement on all governed runs would be a breaking semantic change
- explicit opt-in preserves compatibility while enabling real separation-of-duties checks

Verification targets:
- proposer + `governance_action="propose"` passes
- proposer + `governance_action="validate"` fails with `MACIViolationError`
- enforced agent with no `governance_action` fails fast with `GovernanceError`

### Phase 3 — Consolidate governance serialization
Status: completed on 2026-04-02

Goals:
- move wrapper-side payload normalization into a shared helper/module
- support dataclasses, pydantic models, and bounded serialization
- centralize truncation / fallback behavior for large or unserializable objects

Verification:
- shared helper added at `src/acgs_lite/serialization.py`
- wrappers now consume the shared helper instead of private local helpers
- targeted tests cover dataclass, pydantic, and truncation behavior

### Phase 4 — Clarify audit modes
Status: completed on 2026-04-02

Goals:
- document and formalize `fast` vs `full` audit behavior in `GovernanceEngine`
- keep server/API surfaces on full audit by default
- keep benchmark/hot-path usage allowed to use fast audit intentionally

Verification:
- `GovernanceEngine` now exposes explicit `audit_mode`
- stats now report `audit_mode` and `audit_entry_count`
- fast mode rejects an explicit durable `audit_log` to avoid ambiguous semantics
- server and governed wrappers now opt into `audit_mode="full"` explicitly

## Decision Log

- 2026-04-02: preserve backward compatibility by making MACI enforcement opt-in instead of implicit.
- 2026-04-02: wrapper governance must treat structured outputs as first-class validation payloads, not string-only payloads.
- 2026-04-02: package metadata must match actual wheel entry points.

## Active Remediation Plan

### Phase 5 — Harden Leanstral verifier theorem construction
Status: completed on 2026-04-06

Goals:
- lock `lean_verify.py` behavior with targeted regression tests before refactoring
- stop guessing Lean predicate names from rule IDs; derive theorem references from generated declarations
- encode available action/context assumptions into the theorem statement so kernel verification matches runtime inputs more closely
- make the documented `leanstral` → `codestral-latest` fallback real when the preferred model is unavailable

Verification targets:
- targeted regressions in `tests/test_lean_verify.py` cover predicate-name derivation, context assumptions, and model fallback
- `python -m pytest tests/test_lean_verify.py -q --import-mode=importlib` passes
- `python -m ruff check src/acgs_lite/lean_verify.py tests/test_lean_verify.py` passes
- `python -m mypy src/acgs_lite/lean_verify.py` passes

### Phase 6 — Harden the real Lean execution environment
Status: completed on 2026-04-06

Goals:
- make the Lean kernel command configurable for real deployments without code changes
- support running verification inside an explicit Lean/Lake working directory when provided
- tighten subprocess isolation and diagnostics for kernel failures and missing toolchains
- preserve existing mocked verifier behavior while adding runtime-specific regression coverage

Verification targets:
- targeted regressions cover command override, working-directory override, and stdout-only diagnostics
- `python -m pytest tests/test_lean_verify.py -q --import-mode=importlib` passes
- `python -m ruff check src/acgs_lite/lean_verify.py tests/test_lean_verify.py` passes
- `python -m mypy src/acgs_lite/lean_verify.py` passes

### Phase 7 — Add Lean runtime smoke-check CLI
Status: completed on 2026-04-06

Goals:
- add a small CLI command to validate `ACGS_LEAN_CMD` / `ACGS_LEAN_WORKDIR` against a real Lean toolchain
- keep the command dependency-light and reuse `lean_verify` runtime helpers instead of duplicating subprocess logic
- support human-readable and JSON output for scripting
- preserve existing CLI behavior and parser compatibility

Verification targets:
- targeted CLI regressions cover parser registration, success output, and failure output
- `python -m pytest tests/test_cli_governance.py -q --import-mode=importlib -k lean_smoke` passes
- `python -m pytest tests/test_lean_verify.py -q --import-mode=importlib` passes
- `python -m ruff check src/acgs_lite/cli.py src/acgs_lite/commands/lean_smoke.py src/acgs_lite/lean_verify.py tests/test_cli_governance.py tests/test_lean_verify.py` passes
- `python -m mypy src/acgs_lite/cli.py src/acgs_lite/commands/lean_smoke.py src/acgs_lite/lean_verify.py` passes

### Phase 8 — Close remaining Lean runtime risks
Status: completed on 2026-04-06

Goals:
- exercise the Lean runtime path with a real subprocess in tests instead of mocks only
- make `ACGS_LEAN_CMD` parsing more robust and script-friendly
- fail fast on unsupported shell syntax with actionable remediation guidance
- preserve backwards compatibility for existing command-string configuration

Verification targets:
- targeted regressions cover JSON-array command parsing, shell-syntax rejection, and fake-binary live subprocess execution
- `python -m pytest tests/test_lean_verify.py -q --import-mode=importlib -k "fake_runtime or json_command or shell_syntax"` passes
- `python -m pytest tests/test_cli_governance.py -q --import-mode=importlib -k lean_smoke` passes
- `python -m ruff check src/acgs_lite/cli.py src/acgs_lite/commands/lean_smoke.py src/acgs_lite/lean_verify.py tests/test_cli_governance.py tests/test_lean_verify.py` passes
- `python -m mypy src/acgs_lite/cli.py src/acgs_lite/commands/lean_smoke.py src/acgs_lite/lean_verify.py` passes

### Phase 9 — Document wrapper-script setup and optional Lean integration coverage
Status: completed on 2026-04-06

Goals:
- provide a sample wrapper script for Lean/Lake project execution
- document the preferred JSON-array `ACGS_LEAN_CMD` form and wrapper-script fallback
- add a real-toolchain pytest integration test that auto-runs only when `LEAN_INTEGRATION=1`
- keep the optional integration test skipped by default for normal package CI

Verification targets:
- `python -m pytest tests/test_lean_verify.py -q --import-mode=importlib -k real_toolchain` is skipped by default and ready to run when `LEAN_INTEGRATION=1`
- docs/examples mention `acgs lean-smoke`, wrapper scripts, and `LEAN_INTEGRATION=1`
- `python -m ruff check tests/test_lean_verify.py` passes

### Phase 10 — Unify ValidationResult and clear package mypy debt
Status: completed on 2026-04-06

### Phase 11 — Promote acgs-lite mypy to a real CI gate
Status: completed on 2026-04-06

Goals:
- remove failure suppression from the existing `mypy (acgs-lite)` workflow step
- run the step from `packages/acgs-lite` with the verified package-local mypy path
- enable merge-blocking type regression detection for `packages/acgs-lite`

Verification targets:
- `.github/workflows/ci.yml` no longer contains `|| true` in `mypy (acgs-lite)`
- `.github/workflows/ci.yml` runs `mypy (acgs-lite)` with `working-directory: packages/acgs-lite`
- `cd packages/acgs-lite && uv run mypy src/acgs_lite --ignore-missing-imports --no-error-summary` passes

### Phase 12 — Harden optional Z3 coverage for package CI
Status: completed on 2026-04-06

Goals:
- stop assuming `z3-solver` is always installed in `acgs-lite` test environments
- keep real-Z3 coverage when the optional solver is present
- preserve the graceful no-Z3 runtime contract while keeping the not-slow suite green

Verification targets:
- `python -m pytest tests/test_z3_verify_coverage.py -q --import-mode=importlib` passes
- `uv run pytest packages/acgs-lite/tests/ --import-mode=importlib -m "not slow" -x -q --timeout=120 --tb=short` passes
- `python -m ruff check src/acgs_lite/z3_verify.py tests/test_z3_verify_coverage.py` passes

### Phase 13 — Clean up acgs-lite test warnings
Status: completed on 2026-04-06

Goals:
- remove `PytestCollectionWarning` noise caused by imported `Test*` helper types in `test_rule_metrics.py`
- remove `InsecureKeyLengthWarning` noise from the invalid JWT test in `test_autonoma.py`
- keep the not-slow suite green without changing production behavior

Verification targets:
- `uv run pytest packages/acgs-lite/tests/test_rule_metrics.py packages/acgs-lite/tests/test_autonoma.py --import-mode=importlib -q --tb=short` passes without those warnings
- `uv run pytest packages/acgs-lite/tests/ --import-mode=importlib -m "not slow" -x -q --timeout=120 --tb=short` passes

Goals:
- collapse `engine.types.ValidationResult` and `engine.models.ValidationResult` onto one canonical class
- preserve public import compatibility while removing nominal-type divergence
- clean remaining package mypy errors in small, focused batches
- keep Lean/runtime regressions green while refactoring shared engine types

Verification targets:
- canonical `ValidationResult` regression passes
- `python -m pytest tests/test_lean_verify.py -q --import-mode=importlib` passes
- `python -m mypy src/acgs_lite` passes
- `python -m ruff check src/acgs_lite tests/test_acgs_namespace.py tests/test_lean_verify.py` passes

## Outcomes & Retrospective

- Public wrapper behavior is now protected by regression tests.
- API stats wiring now reports the actual audit trail used by the engine.
- Remaining work is mostly contract/documentation consolidation rather than emergency bug fixing.

## Surprises & Discoveries

- Full-package tests were already strong enough to safely tighten wrapper behavior once targeted regressions were added.
- `maci_role` had become a semantic trap: documented enough to imply enforcement, but not actually enforced.
- Whole-package `ruff check` still has substantial legacy debt outside the touched files.

---

<!-- /autoplan Phase 1 CEO Review — 2026-04-23 -->

## Phase 1 CEO Review (2026-04-23)

### PRE-REVIEW SYSTEM AUDIT

- **Branch:** main | **Commit:** 40b12e4 | **Stash:** 1 entry (ci/fix-fpdf2-types branch, not in flight on main)
- **TODO/FIXME:** 1 file — `src/acgs_lite/constitution/bundle.py:52` (ROLLED_BACK→DRAFT transition removed, intentional)
- **Hot files (30d):** server.py, engine/core.py, trajectory.py, __init__.py, mcp_server.py, lifecycle_service.py
- **Test count:** 163 test files
- **Open TODOs:** T-08, T-09, T-11, T-12 (T-04..T-07, T-10 resolved in recent commits)
- **Blocking:** PyPI token expired — v2.10.0 cannot publish

### 0A. Premise Challenge

| # | Premise | Status | Risk |
|---|---------|--------|------|
| P1 | "Publishable governance library" is the right product wedge | **WEAK** — both review voices challenge this; buyers want audit evidence + blocked bad actions, not governance primitives | HIGH |
| P2 | require_auth=True is the right default | **VALID** — security-correct; CHANGELOG migration path is present | LOW |
| P3 | PostgresBundleStore is appropriately scoped (optional extra) | **WEAK** — premature without documented production demand; also not exported from top-level namespace | MEDIUM |
| P4 | API stability tiers are complete and user-visible | **INCOMPLETE** — classification exists in code but not linked from docs; users can't discover `acgs_lite.stability()` | MEDIUM |
| P5 | Rust wheel is distribution-ready | **INCOMPLETE** — cibuildwheel workflow exists but `rust-v*` tag never pushed; no CI job testing Python fallback | MEDIUM |
| P6 | T-08/T-09 are medium/low priority | **WRONG** — both review voices flag these as undermining governance promise; T-08 silently drops violations | HIGH |

### 0B. Existing Code Leverage

- `PostgresBundleStore` correctly mirrors `SQLiteBundleStore` design (same protocol, same error wrapping) but shares no base class — DRY risk if BundleStore protocol changes
- `API_STABILITY` dict exists in code; user-facing documentation does not reference it
- `fail_closed`, `GovernanceCircuitBreaker` are well-designed and stable — these are differentiators
- 163 test files provide strong regression safety; CI coverage gate at 85% is solid

### 0C. Dream State

```
CURRENT STATE              THIS PLAN              12-MONTH IDEAL
─────────────────────      ──────────────────     ──────────────────────────
Phases 1-13 done           API stability tiers    Published stable v3.0
T-04..T-07/T-10 closed     PostgresBundleStore    Clear "evidence plane" positioning
Rust fast path (no wheel)  Rust wheel pipeline    Star History growth
require_auth=True          WAL hooks              Hosted docs (acgs.ai/docs)
API stability in code      CI/CodeQL hardening    One indispensable workflow published
```

**Gap:** The plan moves toward stability (good) but the product positioning ("governance primitives") is the wrong framing. The 12-month ideal requires re-centering around the audit/evidence story before building more infrastructure.

### 0C-bis. Implementation Alternatives

**APPROACH A: Current trajectory (incremental patches)**
- Summary: Continue adding infrastructure, ship v2.10.0 when PyPI token renewed
- Effort: S | Risk: Medium (distribution discipline gap, positioning drift)
- Pros: No disruption, momentum preserved
- Cons: Stability story incoherent to new users; no adoption forcing function

**APPROACH B: Stability sprint + positioning fix (RECOMMENDED)**
- Summary: Fix PyPI token (10 min), close T-08/T-09 (1hr CC), write `docs/stability.md` (15min CC), write upgrade guide (15min CC), export PostgresBundleStore from __init__.py (5min CC), add Rust fallback CI job (15min CC)
- Effort: M (~2hr CC total) | Risk: Low
- Pros: Users can adopt with confidence; governance promise is whole; clear "evidence plane" story
- Cons: Minor delay

**APPROACH C: v3.0 major rewrite with positioning pivot**
- Summary: Define new "evidence plane" positioning, redesign public API around audit/evidence primitives, full SemVer policy
- Effort: XL | Risk: Medium
- Pros: Clean story
- Cons: Premature — current user base doesn't justify the cost

**RECOMMENDATION:** Choose B — A leaves T-08 (governance promise hole) and stability incoherence; C is an ocean.

### 0D. Mode-Specific Analysis (SELECTIVE EXPANSION)

Complexity check: 47-file diff is large but architecturally coherent (3 independent features: PostgresBundleStore, Rust wheel, API stability). No artificial complexity.

**Cherry-pick candidates (expansion opportunities):**

| # | Opportunity | Effort | Decision |
|---|------------|--------|----------|
| E1 | `docs/stability.md` — user-facing stability tier explanation | ~15min CC | **ACCEPTED (P1+P5)** — in blast radius; makes stability tiers discoverable |
| E2 | Export `PostgresBundleStore` + `SQLiteBundleStore` from `acgs_lite.__init__` | ~5min CC | **ACCEPTED (P1)** — PostgresBundleStore is invisible without this |
| E3 | Rust fallback CI job (matrix entry: no `acgs-lite-rust` installed) | ~15min CC | **ACCEPTED (P1)** — CLAUDE.md requires Python fallback testing |
| E4 | v2.10.0 upgrade guide in `docs/` | ~15min CC | **ACCEPTED (P5)** — breaking change needs discoverable migration guide |
| E5 | Close T-08: fix `explain_violation` outer except scope | ~30min CC | **ACCEPTED (P2+P3)** — governance promise hole, not polish |
| E6 | Close T-09: document engine-sharing invariant for MCP+Telegram | ~15min CC | **ACCEPTED (P5)** — correctness documentation gap |

### 0E. Temporal Interrogation

- HOUR 1: Fix PyPI token (10min), run test suite to confirm baseline green
- HOUR 2-3: Close T-08, T-09; write docs/stability.md; export PostgresBundleStore from __init__.py
- HOUR 4-5: Write upgrade guide; add Rust fallback CI job; push rust-v* tag for wheel build
- HOUR 6+: Publish v2.10.0 to PyPI; update README with "evidence plane" positioning

### 0.5 CEO Dual Voices

**CLAUDE SUBAGENT (CEO — strategic independence):**
1. [CRITICAL] Wrong problem frame — model providers eating the middleware wrapper; pivot to audit trail + MACI separation-of-duties as the defensible core
2. [HIGH] Lean verification (phases 5-9) solves a problem the target audience doesn't have; no evidence of adoption
3. [HIGH] PostgresBundleStore premature — infrastructure-for-scale before one confirmed production user
4. [HIGH] PyPI token expiry = distribution discipline failure; T-04/T-05 must ship before/with v2.10.0
5. [MEDIUM] Competitive risk: Guardrails AI, LlamaGuard, NeMo, model-provider native guardrails

**CODEX SAYS (CEO — strategy challenge):**
1. "Publishable governance library" wedge is unproven — buyers want audit evidence, blocked bad actions, procurement confidence
2. PyPI token expiry signals distribution discipline gap
3. PostgresBundleStore/Rust/WAL/Lean premature without production demand — expands maintenance surface
4. require_auth=True = "secure by default, unused by default" risk
5. Stability story incoherent: stable core + Beta classifier + breaking changes
6. T-08/T-09/T-11/T-12 misprioritized — they undermine the central governance promise
7. Competitive risk: OPA, Cedar, Guardrails, LangChain/LlamaIndex, cloud AI safety
8. 10x reframe: "evidence plane" — policy decisions, human approvals, immutable audit, release gates, incident replay
9. Six-month regret: breadth without one indispensable workflow

**CEO DUAL VOICES — CONSENSUS TABLE:**
```
═══════════════════════════════════════════════════════════════════════
  Dimension                              Claude  Codex  Consensus
  ──────────────────────────────────────────── ─────── ─────────
  1. Premises valid?                     NO      NO     CONFIRMED: both challenge core premise
  2. Right problem to solve?             PARTIAL PARTIAL CONFIRMED: framing too broad
  3. Scope calibration correct?          NO      NO     CONFIRMED: infrastructure over-invested
  4. Alternatives sufficiently explored? NO      NO     CONFIRMED: OPA/Cedar/OTEL unexplored
  5. Competitive/market risks covered?   NO      NO     CONFIRMED: under-addressed
  6. 6-month trajectory sound?           RISKY   RISKY  CONFIRMED: course correction needed
═══════════════════════════════════════════════════════════════════════
Consensus: 6/6 CONFIRMED. Zero disagreements between voices.
USER CHALLENGE: Both models agree the "governance primitives" positioning should shift to "evidence plane" framing.
```

### CEO Sections 1-10

**Section 1: Value Proposition**
Issue: `acgs_lite.stability()` and `API_STABILITY` exist in code but no user-facing documentation references them. A developer seeing PyPI classifier "4 - Beta" can't know which parts are stable without reading source.
Decision: [ACCEPTED E1] Write docs/stability.md + README link. (P1+P5)

**Section 2: User/Market Fit**
Issue: require_auth=True breaking change: helpful error message but hidden in CHANGELOG only.
Decision: [ACCEPTED E4] Write upgrade guide in docs/. (P5)

**Section 3: Competitive Positioning**
MACI primitive is the most defensible asset — not in any competitor. T-08/T-09 keeping MCP integration broken undermines the governance story exactly where enterprise evaluators look.
Decision: [ACCEPTED E5+E6] Close T-08 and T-09. (P2)

**Section 4: Distribution**
PyPI token expired — v2.10.0 cannot publish. This is the highest-urgency blocking item.
No plan issue to file: it's an operational task (10-minute fix). Flagged in TODOS.md HIGH PRIORITY.

**Section 5: Strategic Risks**
1. [P1 HIGH] PostgresBundleStore not exported from `acgs_lite` namespace — users who `pip install 'acgs-lite[postgres]'` don't know how to import it.
2. [P1 MEDIUM] Rust wheel: `rust-v*` tag never pushed; `acgs-lite-rust` package doesn't exist on PyPI yet.
3. [P1 MEDIUM] T-08: `explain_violation` outer except swallows post-validate errors — MCP callers get generic error even when governance ran successfully.

**Section 6: Execution Risk**
Low. 163 tests, 85% coverage gate, CodeQL, dependabot. CI discipline is strong. Engineering throughput outpaces distribution discipline — the gap to close.

**Section 7: Timeline**
v2.10.0: ready to publish, blocked on PyPI token only.
Rust wheels: need `rust-v*` tag push after confirming wheel.yml is correct.

**Section 8: NOT in Scope**
- v3.0 positioning redesign (ocean, not lake)
- OPA/Cedar integration (separate decision)
- Hosted docs deployment (mkdocs configured, deploy separate concern)
- Lean phase extensions

**Section 9: What Already Exists**
- `acgs_lite.stability(name)` and `acgs_lite.API_STABILITY` — just needs docs
- CHANGELOG v2.10.0 breaking change section — needs docs/ mirror
- `examples/agent_quickstart/run.py` — excellent DX anchor, underused in marketing
- `fail_closed` + circuit breaker — strong positioning asset

**Section 10: Failure Modes Registry**

| ID | Failure | Trigger | Catch | User sees | Tested |
|----|---------|---------|-------|-----------|--------|
| FM-1 | require_auth=True + no key | app startup | ValueError | Clear error + remediation | YES |
| FM-2 | PostgresBundleStore import without psycopg | import | ImportError | Module not found | UNKNOWN |
| FM-3 | Rust wheel missing | no acgs-lite-rust installed | graceful? | Python fallback | NOT IN CI |
| FM-4 | T-08: explain_violation outer except | post-validate error | outer Exception | Generic error, governance ran but result lost | NO |
| FM-5 | T-09: engine sharing MCP+Telegram concurrent | concurrent validate() + Telegram call | none | engine.strict race | NO |

**Error & Rescue Registry:**
FM-1: ✅ handled. FM-2: needs test. FM-3: needs CI job. FM-4: needs T-08 fix. FM-5: needs T-09 doc + test.

### CEO Completion Summary

| Item | Status | Owner |
|------|--------|-------|
| Premise challenge | CHALLENGED — "evidence plane" framing stronger than "governance primitives" | USER CHALLENGE (see gate below) |
| Scope: 6 expansion items accepted | ACCEPTED | Autoplan auto-decided |
| T-08/T-09 reprioritized HIGH | ACCEPTED | Phase 3 will plan implementation |
| PostgresBundleStore export gap | IDENTIFIED | Phase 3 + E2 |
| Rust fallback CI gap | IDENTIFIED | E3 |
| PyPI token | OPERATIONAL — renew immediately | HIGH PRIORITY TODO |
| Stability docs | ACCEPTED (E1) | Phase 3 will plan |

---

## Decision Audit Trail

| # | Phase | Decision | Classification | Principle | Rationale | Rejected |
|---|-------|----------|----------------|-----------|-----------|---------|
| 1 | CEO | Mode: SELECTIVE EXPANSION | Mechanical | P6 | Plan has completed phases + new work; expansion candidates to surface | — |
| 2 | CEO | E1 Accept: docs/stability.md | Mechanical | P1+P5 | In blast radius, ~15min CC, fixes discoverability of stable API tiers | Skip |
| 3 | CEO | E2 Accept: export PostgresBundleStore from __init__ | Mechanical | P1 | Users can't find it via normal import; in blast radius | Skip |
| 4 | CEO | E3 Accept: Rust fallback CI job | Mechanical | P1 | CLAUDE.md requires Python fallback testing when optional Rust exists | Defer |
| 5 | CEO | E4 Accept: v2.10.0 upgrade guide | Mechanical | P5 | Breaking change needs discoverable migration path | Skip |
| 6 | CEO | E5 Accept: T-08 close | Mechanical | P2+P3 | Governance promise hole — not polish; ~30min CC | Defer |
| 7 | CEO | E6 Accept: T-09 close | Mechanical | P5 | Engine sharing correctness doc gap; ~15min CC | Skip |
| 8 | CEO | T-08/T-09 priority upgrade to HIGH | Mechanical | P2 | Both review voices flag these as undermining governance guarantee | Stay Medium |
| 9 | CEO | PyPI token: flag as P0 operational task | Mechanical | P6 | Everything else is blocked by this | — |


---

## Phase 3 Eng Review (2026-04-23)

### Step 0: Scope Challenge

47 files changed, 2222 insertions. Touches: PostgresBundleStore (411 LOC), __init__.py (519 LOC), server.py, engine/core.py, sqlite_bundle_store.py, trajectory.py, 12 integration files, rust/pyo3, CI workflows.

Three distinct feature areas (not scope creep): PostgresBundleStore, API stability tiers, Rust wheel. Independent concerns that happen to ship together.

**What exists:** 163 test files, 85% coverage gate, CodeQL, dependabot. CI discipline is strong.
**What's missing:** PostgresBundleStore concurrency tests, Rust fallback CI job, __init__ optional-dep crash tests, docs/examples sync after require_auth=True.

**TODOS cross-reference:** T-08 and T-09 still open. Both now escalated to HIGH after two independent eng voices confirmed they undermine governance promise.

**Completeness check:** Distribution architecture is present (wheels.yml + maturin), but `acgs-lite-rust` package doesn't exist on PyPI yet (no `rust-v*` tag pushed). Distribution is incomplete.

### 0.5 Eng Dual Voices

**CLAUDE SUBAGENT (Eng — independent review):**
- [P1] `__init__.py` 519 lines eager imports Redis, z3, lean — `ImportError` on missing optional dep crashes entire `acgs_lite` import
- [P1] `list_bundles(limit=None)` passes None to SQL LIMIT — PostgreSQL syntax error
- [P1] T-08 / T-09 governance holes (unchanged from CEO phase)
- [P2] `_ensure_schema` INSERT missing `ON CONFLICT DO NOTHING` — concurrent cold-starts raise UniqueViolation → LifecycleError at startup
- [P2] `_utcnow()` return type diverges between stores (datetime vs str)
- [P2] PostgresBundleStore has no context-manager protocol (`__enter__`/`__exit__`)
- [P2] Test gaps: `save_bundle_transactional`, pool teardown, require_auth regression, Rust fallback

**CODEX SAYS (Eng — architecture challenge):**
- [P1] CAS race on new tenants: `SELECT ... FOR UPDATE` doesn't lock absent rows → two concurrent `expected=0` callers both succeed at version 1 (`postgres_bundle_store.py:370-387`)
- [P1] `save_bundle_transactional()` not in `BundleStore` protocol, no production caller — `activate()` still does separate writes that can leave half-applied state (`lifecycle_service.py:617-648`)
- [P1] T-09 NOT closed: `non_strict()` still mutates `self.strict`; tests prove restoration but not concurrent overlap (`mcp_server.py:393-395`, `engine/core.py:1197-1205`)
- [P1] T-08 dangerous: `explain_violation` outer except returns normal payload, hiding programmer/audit failures (`mcp_server.py:564-575`)
- [P1] Docs lie after require_auth=True: `create_governance_app()` examples in `docs/api/lifecycle.md:16-19` and `docs/telegram-webhook.md:20-25` call without api_key → startup raises

**ENG DUAL VOICES — CONSENSUS TABLE:**
```
═══════════════════════════════════════════════════════════════════════
  Dimension                              Claude  Codex  Consensus
  ─────────────────────────────────────── ─────── ─────── ─────────
  1. Architecture sound?                 PARTIAL NO      CONFIRMED: save_bundle_transactional unused; activate() separate writes
  2. Test coverage sufficient?           NO      NO      CONFIRMED: Postgres concurrency, transactional, Rust fallback all missing
  3. Performance risks addressed?        NO      N/A     CONFIRMED: __init__ eager import cold-start risk
  4. Security threats covered?           PARTIAL PARTIAL CONFIRMED: docs/examples out of sync post require_auth flip
  5. Error paths handled?                NO      NO      CONFIRMED: T-08 P1, LIMIT None P1, CAS race P1
  6. Deployment risk manageable?         MEDIUM  HIGH    CONFIRMED: multi-replica CAS race, docs lie
═══════════════════════════════════════════════════════════════════════
Consensus: 6/6 CONFIRMED. Cross-phase theme: T-08/T-09 flagged in both CEO and Eng phases.
```

### Section 1: Architecture

**ASCII Dependency Diagram:**
```
acgs_lite/__init__.py (519 LOC)
├── EAGER: engine/core.py → GovernanceEngine ✓
├── EAGER: governed.py → GovernedAgent ✓
├── EAGER: openshell/*.py → RedisGovernanceStateBackend ⚠️ (requires redis at import time)
├── EAGER: lean_verify.py → LeanstralVerifier ⚠️ (probe at import time)
├── EAGER: z3_verify.py / formal/smt_gate.py ⚠️ (requires z3 at import time)
└── LAZY: constitution/postgres_bundle_store.py ✓ (not in __init__, psycopg imported on use)

PostgresBundleStore (411 LOC)
├── BundleStore [Protocol] ←── NOT a class inheritance, duck-typed
├── SQLiteBundleStore ←── parallel impl, no shared base
└── _ensure_schema() ←── INSERT without ON CONFLICT (concurrent startup bug)

lifecycle_service.activate()
├── supersede_active()    ─┐
├── save_bundle()          ├── separate writes, no savepoint
└── save_activation()     ─┘ ← half-applied if crash between writes
    save_bundle_transactional() (exists but unused here)
```

Issues auto-decided:
1. [P1] `__init__.py` eager Redis/lean/z3 imports → ACCEPTED for Phase 14 plan: add lazy `__getattr__` for experimental symbols (P5, ~30min CC)
2. [P1] `postgres_bundle_store.py:370-387` CAS race on new tenants → ACCEPTED for Phase 14: add `INSERT ... ON CONFLICT DO NOTHING` before the FOR UPDATE select, or use advisory lock (P1, ~1hr CC)
3. [P1] `list_bundles(limit=None)` → PostgreSQL LIMIT NULL syntax error → ACCEPTED for immediate fix (P2, ~5min CC)
4. [P2] `_ensure_schema` INSERT missing `ON CONFLICT DO NOTHING` → ACCEPTED for immediate fix with P1 CAS fix (P2, ~5min CC)
5. [P2] `save_bundle_transactional` not in BundleStore protocol and not called by `activate()` → ACCEPTED: wire it in or document as optional extension (P3, ~2hr CC)

### Section 2: Code Quality

1. [P2] `_utcnow()` return type diverges: `postgres_bundle_store.py:77` returns `datetime`, `sqlite_bundle_store.py:54` returns `str`. Fix: unify to `datetime`, let each serialize.
2. [P2] `PostgresBundleStore` has no `__enter__`/`__exit__` — `with PostgresBundleStore(...) as store:` raises `AttributeError`. Standard Python context manager protocol expected for connection-holding objects.
3. [P2] T-08 still open: `mcp_server.py:564-575` outer except is too broad.
4. [P2] T-09 still open: `non_strict()` mutates shared `self.strict` — per-call strict (T-04 fix) is the safe path but `non_strict()` still exists as a trap for new callers.

All auto-decided: accept all fixes (P5 + P3).

### Section 3: Test Review — Coverage Diagram

```
CODE PATHS                                                      TEST STATUS
════════════════════════════════════════════════════════════════════════════
PostgresBundleStore
  ├── _ensure_schema() happy path                               [★★  TESTED] test_postgres_bundle_store.py
  │   └── concurrent cold-start: INSERT race                   [GAP] → unit test with mock concurrent call
  ├── save_bundle() happy path                                  [★★  TESTED]
  ├── save_bundle_transactional()                               [GAP] NO TEST — no production caller either
  ├── list_bundles(limit=None)                                  [GAP] P1 BUG — LIMIT NULL syntax error
  ├── cas_tenant_version() — new tenant SELECT FOR UPDATE race  [GAP] P1 BUG — tests avoid real concurrency
  └── close() / pool ownership teardown                         [GAP]

__init__.py optional dep crashes
  ├── import acgs_lite (no redis installed)                     [GAP] P1 — would crash entire import
  ├── import acgs_lite (no z3 installed)                        [GAP]
  └── import acgs_lite (no lean installed)                      [GAP]

server.py require_auth=True
  ├── auth required → 401                                       [★★★ TESTED] test_server_api_key_auth.py
  └── old open-path regression: call without api_key now raises [GAP] → P1 regression test needed

mcp_server.py T-08
  └── explain_violation outer except swallows violations        [GAP] P1 — no test exercises this path

trajectory.py lock release
  └── lock released before rule eval (T-07/T-10)               [★★★ TESTED] test_trajectory_thread_safety.py

engine split init (T-06 fix)
  └── warmup / gc.freeze behind explicit kwargs                 [★★★ TESTED] test_engine_split_init.py

Rust wheel fallback
  └── Python fallback when acgs-lite-rust absent               [GAP] NO CI JOB — # pragma: no cover

docs/examples post require_auth=True
  ├── docs/api/lifecycle.md:16-19 (no api_key example)         [GAP] P1 DOCS LIE
  └── docs/telegram-webhook.md:20-25 (no api_key example)      [GAP] P1 DOCS LIE

COVERAGE: ~10/18 paths tested (56%)
CRITICAL GAPS: CAS race (P1), save_bundle_transactional (P2), __init__ import crash (P1),
               T-08 (P1), docs post-require_auth (P1), Rust fallback (P2)
```

**REGRESSION RULE triggers:**
- `list_bundles(limit=None)` — existing behavior (accepted None) broken by psycopg None→LIMIT NULL. Regression test required.
- `require_auth=True` default flip — existing callers without api_key now raise at startup. Regression test: call `create_governance_app()` without key, confirm raises `ValueError`.

### Section 4: Performance

1. [P1] `import acgs_lite` cold-start in serverless: eagerly imports Redis, Z3, Lean. Estimated +100-300ms cold start in Lambda/Cloud Run with these probes. Fix: `__getattr__` lazy loading for experimental symbols.
2. [P3] `gc.freeze()` moved behind explicit kwargs — GOOD, removes GC-freeze side effect from import.
3. [P3] `warmup()` moved behind explicit kwargs — GOOD, avoids JIT warmup cost for users who don't need it.

No N+1 query concerns in the new code.

### Failure Modes Registry

| ID | File | Line | Failure | Severity | Fix |
|----|------|------|---------|----------|-----|
| FM-1 | postgres_bundle_store.py | 370-387 | CAS race new tenant | P1 | INSERT ... ON CONFLICT or advisory lock |
| FM-2 | postgres_bundle_store.py | 242,248 | list_bundles(None) LIMIT NULL | P1 | Omit LIMIT clause when None |
| FM-3 | __init__.py | 131 | redis not installed → import acgs_lite crashes | P1 | Lazy __getattr__ for experimental |
| FM-4 | mcp_server.py | 564-575 | T-08: outer except swallows violations | P1 | Narrow except scope to post-validate only |
| FM-5 | mcp_server.py | 393-395 | T-09: non_strict() concurrent race | P1 | Document or add concurrent overlap test |
| FM-6 | docs/api/lifecycle.md | 16-19 | require_auth example calls without api_key | P1 | Update docs examples |
| FM-7 | docs/telegram-webhook.md | 20-25 | Same | P1 | Update docs examples |
| FM-8 | postgres_bundle_store.py | 145-161 | _ensure_schema INSERT without ON CONFLICT | P2 | Add ON CONFLICT DO NOTHING |
| FM-9 | postgres_bundle_store.py | — | save_bundle_transactional not used by activate() | P2 | Wire in or document |
| FM-10 | postgres_bundle_store.py | — | No __enter__/__exit__ | P2 | Add context manager protocol |

### Eng Completion Summary

All Phase 3 sections evaluated at full depth.
5 P1 issues found (auto-decided: all accepted).
5 P2 issues found (auto-decided: all accepted).

**NOT in scope:**
- OPA/Cedar underneath PostgresBundleStore
- Full PostgresBundleStore async rewrite
- __init__.py full restructure (ocean, not lake — Phase 14 plan item)


---

## Phase 3.5 DX Review (2026-04-23)

Product type: **Library/SDK** — developer library for Python agents

### PRE-REVIEW AUDIT
- README hero: `python examples/basic_governance/main.py` — requires cloned repo
- README line 20: "Stable core (v2.9.0)" — stale after v2.10.0 release today
- First quickstart code block uses `from acgs import ...` (not `acgs_lite`)
- CHANGELOG v2.10.0 breaking change entry: thorough, but only in CHANGELOG
- `examples/agent_quickstart/run.py`: excellent but assumes cloned repo

### Developer Persona: Backend dev integrating governance into AI agent
Context: discovered via PyPI / Awesome LLM Security, runs `pip install acgs-lite`, expects 5-minute path to working code.

### Empathy Narrative
"I pip install acgs-lite. I open the README. First code block says `from acgs import Constitution, GovernedAgent`. I copy it. `ModuleNotFoundError: No module named 'acgs'`. I check the package name — it's `acgs_lite`. I fix it. Now the hero demo: `python examples/basic_governance/main.py`. `No such file or directory`. Right, I need to clone the repo first. I didn't know that. So this isn't actually a pip-install quickstart. I clone, try the hero demo — it works! 8 minutes in. Not 20 seconds."

### 0.5 DX Dual Voices

**CLAUDE SUBAGENT (DX — independent review):**
- [P1] Hero path fails after cold pip install — `examples/` not shipped in wheel
- [P1] `from acgs import ...` in README quickstart → `ModuleNotFoundError` (should be `acgs_lite`)
- [P1] require_auth=True breaking change invisible in README; version badge says v2.9.0
- [P2] TTHW ~12 min for cold pip-install user; target is 5 min
- [P2] GovernedAgent.decorate buried; GovernedAgent vs GovernedCallable unexplained at first touch
- [P3] No ImportError hint for missing optional extras (openai, langchain, etc.)

**CODEX SAYS (DX — developer experience challenge):**
- README:20 "Stable core (v2.9.0)" stale — breaking change shipped today as v2.10.0
- README:38-40 hero demo requires cloned repo — fails cold
- Breaking change in CHANGELOG only — a dev running `pip install --upgrade acgs-lite` gets no signal
- Both models confirm: first two interactions a cold pip-install user has (import + hero demo) both fail

**DX DUAL VOICES — CONSENSUS TABLE:**
```
═══════════════════════════════════════════════════════════════════════
  Dimension                              Claude  Codex  Consensus
  ─────────────────────────────────────── ─────── ─────── ─────────
  1. Getting started < 5 min?            NO      NO     CONFIRMED: hero path broken cold
  2. API/CLI naming guessable?           NO      N/A    CONFIRMED: import name mismatch
  3. Error messages actionable?          PARTIAL N/A    CONFIRMED: require_auth error good in code, invisible in README
  4. Docs findable & complete?           PARTIAL PARTIAL CONFIRMED: GovernedAgent buried, version stale
  5. Upgrade path safe?                  NO      NO     CONFIRMED: breaking change not surfaced at upgrade time
  6. Dev environment friction-free?      PARTIAL N/A    CONFIRMED: examples assume cloned repo
═══════════════════════════════════════════════════════════════════════
Consensus: 6/6 CONFIRMED.
```

### DX Review Passes 1-8

**Pass 1 — Getting Started (3/10 → 7/10 after fixes)**
- TTHW current: ~12 min (cold pip install user hits 2 broken steps before any code runs)
- Blocker 1: `from acgs import` → fix to `from acgs_lite import` in README hero (5 min CC)
- Blocker 2: `python examples/...` hero requires cloned repo → replace with inline pip-install-friendly code block (10 min CC)
- `agent_quickstart/run.py` is excellent — promote it in README with explicit note that it requires cloned repo OR add an inline version

**Pass 2 — API Ergonomics (6/10 → 7/10 after fixes)**
- `Constitution`, `GovernedAgent`, `GovernanceEngine` — names are guessable ✓
- `GovernedAgent` vs `GovernedCallable` unexplained at first touch — add one-liner distinction in quickstart
- `acgs_lite.stability(name)` API is clean but invisible — no mention in README or docs index

**Pass 3 — Error Messages (6/10 → 8/10 after fixes)**
- `require_auth=True` error text is excellent (actionable, names the env var)
- Missing: README callout that this changed in v2.10
- Optional extras: no `ImportError` hint pointing to `pip install "acgs-lite[openai]"`

**Pass 4 — Documentation (5/10 → 7/10 after fixes)**
- README structure: hero → community favorites → install → 5-line quickstart → MACI → audit → ...
- `GovernedAgent.decorate` is the primary use case for AI agent developers but is buried after MACI and audit sections
- `docs/stability.md` doesn't exist yet (T-21) — critical for developer confidence

**Pass 5 — Upgrade Safety (4/10 → 8/10 after fixes)**
- CHANGELOG v2.10.0 entry is thorough ✓
- README version badge stale: "Stable core (v2.9.0)" → update to v2.10.0
- No `> Upgrading from v2.9.x?` callout in README Installation section

**Pass 6 — Dev Environment (7/10)**
- `make test`, `make lint`, `make build` — clean commands ✓
- `python -m pytest tests/ -v --import-mode=importlib --rootdir=.` documented in CLAUDE.md ✓
- Optional: `acgs lean-smoke` for Lean toolchain validation ✓

**Pass 7 — Competitive Position (5/10)**
- TTHW after fixes: ~4 min → competitive tier
- Stripe tier (<2 min) would require hosted playground — out of scope now
- `agent_quickstart/run.py` is a genuine differentiator for AI coding agent users (Codex, Claude Code)

**Pass 8 — Desirable (6/10)**
- Audit trail + MACI positioning is differentiated from Guardrails/OPA/Cedar ✓
- "4 - Beta" PyPI classifier hurts trust for production evaluators
- Star History badge (T-TODO from TODOS.md HIGH PRIORITY) would help social proof

### DX Scorecard

| Pass | Dimension | Current | After Fixes |
|------|-----------|---------|-------------|
| 1 | Getting Started | 3/10 | 7/10 |
| 2 | API Ergonomics | 6/10 | 7/10 |
| 3 | Error Messages | 6/10 | 8/10 |
| 4 | Documentation | 5/10 | 7/10 |
| 5 | Upgrade Safety | 4/10 | 8/10 |
| 6 | Dev Environment | 7/10 | 7/10 |
| 7 | Competitive | 5/10 | 7/10 |
| 8 | Desirable | 6/10 | 7/10 |
| **Overall** | | **5.3/10** | **7.3/10** |

TTHW: 12 min → 4 min (after fixes)

### DX Implementation Checklist

- [ ] T-26: Fix README quickstart import (`from acgs import` → `from acgs_lite import`)
- [ ] T-27: Replace hero demo command with inline pip-install-friendly code block
- [ ] T-28: Update README version badge to v2.10.0; add upgrading callout in Installation section
- [ ] T-29: Add `> Upgrading from v2.9.x?` callout pointing to CHANGELOG breaking change
- [ ] T-30: Move GovernedAgent.decorate example before MACI/audit sections
- [ ] T-21: Write docs/stability.md (already in TODOS)
- [ ] T-24: Write v2.10.0 upgrade guide (already in TODOS)

**PHASE 3.5 COMPLETE.**
> DX overall: 5.3/10 → 7.3/10. TTHW: 12 min → 4 min target.
> Codex: 3 concerns. Claude subagent: 6 issues. Consensus: 6/6 confirmed.
> Key: both cold-install first interactions (import + hero demo) fail — highest-priority DX fix.
> Passing to Phase 4 (Final Gate).


| 10 | DX | T-26: Fix README import name | Mechanical | P1 | First interaction for pip-install user fails; 5min fix | Skip |
| 11 | DX | T-27: Fix hero demo to work cold | Mechanical | P1 | Second interaction also fails; hero path requires clone | Defer |
| 12 | DX | T-28: Update README version badge | Mechanical | P3 | Stale badge erodes trust; trivial fix | Skip |
| 13 | DX | T-29: Upgrading callout in README | Mechanical | P5 | Breaking change not surfaced to pip-upgrade users | Defer |
| 14 | DX | T-30: Move GovernedAgent example | Taste | P5 | Plausible to keep structure; but subagent evidence says 2+ min to find primary use case | Keep current |

